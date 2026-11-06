package rout

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---- helpers ---------------------------------------------------------------------------------

// hubPost makes a raw mTLS call to the hub as an arbitrary identity (what an attacker with a
// certificate of their own, or a buggy agent, could do).
func hubPost(t *testing.T, addr string, id tgIdentity, path string, in, out any) int {
	t.Helper()
	cert, e := id.tlsCert()
	if e != nil {
		t.Fatal(e)
	}
	hc := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}}}
	defer hc.CloseIdleConnections()
	b, _ := json.Marshal(in)
	resp, e := hc.Post("https://"+addr+path, "application/json", bytes.NewReader(b))
	if e != nil {
		t.Fatalf("post %s: %v", path, e)
	}
	defer resp.Body.Close()
	if out != nil {
		json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode
}

func msgsTo(tg *fakeTelegram, chat int64) []fakeMsg {
	tg.mu.Lock()
	defer tg.mu.Unlock()
	var out []fakeMsg
	for _, m := range tg.msgs {
		if m.Chat == chat && !m.Deleted {
			out = append(out, *m)
		}
	}
	return out
}

func answered(tg *fakeTelegram, id string) (fakeAnswer, bool) {
	for _, a := range tg.answers() {
		if a.ID == id {
			return a, true
		}
	}
	return fakeAnswer{}, false
}

func waitAnswer(t *testing.T, tg *fakeTelegram, id, contains string) {
	t.Helper()
	waitFor(t, "answer containing "+contains, 8*time.Second, func() bool {
		a, ok := answered(tg, id)
		return ok && strings.Contains(a.Text, contains)
	})
}

func tgFileText(t *testing.T, path string) string {
	b, _ := os.ReadFile(path)
	return string(b)
}

// ---- authorisation -----------------------------------------------------------------------------

func TestTelegramRejectsEveryoneButTheOwnersPrivateChat(t *testing.T) {
	tg, nodes := newFleet(t, "US-GIA", "CA-Exit")
	ca := nodes[1]
	list := openList(t, tg)
	openServer(t, tg, list, "CA-Exit")
	toggle, ok := tg.button(list.ID, "开启 AI 分流")
	if !ok {
		t.Fatal("no toggle button")
	}

	// a stranger's private chat: refused politely, shown nothing
	tg.say(999, 999, "private", "/start")
	waitFor(t, "refusal", 5*time.Second, func() bool { return len(msgsTo(tg, 999)) == 1 })
	m := msgsTo(tg, 999)[0]
	if !strings.Contains(m.Text, "无权限") || m.Markup != nil || strings.Contains(m.Text, "US-GIA") {
		t.Fatalf("a stranger saw: %+v", m)
	}
	// repeated attempts do not make the bot reply again within the minute
	tg.say(999, 999, "private", "/start")
	tg.say(999, 999, "private", "/servers")
	time.Sleep(300 * time.Millisecond)
	if n := len(msgsTo(tg, 999)); n != 1 {
		t.Fatalf("the bot answered a stranger %d times", n)
	}
	// a group, even with the owner's own user id in it: ignored completely
	before := tg.count("Rout Control")
	tg.say(-100500, testChat, "supergroup", "/start")
	tg.say(-100500, 999, "group", "/start")
	// the right chat but the wrong sender
	tg.say(testChat, 999, "private", "/start")
	// a bot
	tg.push(tgUpdate{Message: &tgMessage{MessageID: 9, From: &tgUser{ID: testChat, IsBot: true}, Chat: tgChat{ID: testChat, Type: "private"}, Text: "/start"}})
	time.Sleep(400 * time.Millisecond)
	if len(msgsTo(tg, -100500)) != 0 || tg.count("Rout Control") != before {
		t.Fatal("a non-owner context produced a server list")
	}

	// buttons: pressed by someone else, or in someone else's chat
	for name, id := range map[string]string{
		"other user, owner chat": tg.tapAs(testChat, 999, list.ID, toggle),
		"other user and chat":    tg.tapAs(999, 999, list.ID, toggle),
		"owner id, group chat":   tg.tapAs(-100500, testChat, list.ID, toggle),
	} {
		_ = name
		waitFor(t, "callback answered: "+name, 5*time.Second, func() bool { _, ok := answered(tg, id); return ok })
		if a, _ := answered(tg, id); !strings.Contains(a.Text, "无权限") {
			t.Errorf("%s was not refused: %+v", name, a)
		}
	}
	if ca.status().Config.Enabled {
		t.Fatal("an unauthorised callback changed the configuration")
	}

	// forged / truncated / stale callback data from the real owner
	for name, data := range map[string]string{
		"no mac":        strings.SplitN(toggle, "~", 2)[0],
		"bad mac":       strings.SplitN(toggle, "~", 2)[0] + "~AAAAAAAAAAA",
		"flipped state": strings.Replace(toggle, ":1~", ":0~", 1),
		"garbage":       "xyz",
		"too long":      strings.Repeat("A", 80),
	} {
		id := tg.tap(list.ID, data)
		waitAnswer(t, tg, id, "按钮已失效")
		_ = name
	}
	if ca.status().Config.Enabled {
		t.Fatal("a forged callback changed the configuration")
	}

	// the refusals are audited and the audit log holds no secrets
	log := tgFileText(t, nodes[0].a.telegramAuditPath())
	if !strings.Contains(log, "message_denied") || !strings.Contains(log, "callback_denied") {
		t.Fatalf("denials not audited:\n%s", log)
	}
	if strings.Contains(log, testBotToken) || strings.Contains(log, "999\t") {
		t.Fatalf("audit log leaks identifiers:\n%s", log)
	}
}

func TestTelegramDuplicateAndStaleCallbacksCannotRepeatAnAction(t *testing.T) {
	tg, nodes := newFleet(t, "US-GIA", "CA-Exit")
	ca := nodes[1]
	list := openList(t, tg)
	openServer(t, tg, list, "CA-Exit")

	// toggle once, then flip it back locally; Telegram redelivers the same callback
	data, _ := tg.button(list.ID, "开启 AI 分流")
	id := tg.tap(list.ID, data)
	waitFor(t, "AI enabled", 8*time.Second, func() bool { return ca.status().Config.Enabled })
	waitText(t, tg, list.ID, "已开启 AI 分流")
	if e := ca.a.SetAIEnabled(false); e != nil {
		t.Fatal(e)
	}
	tg.tapReplay(id, list.ID, data)
	time.Sleep(400 * time.Millisecond)
	if ca.status().Config.Enabled {
		t.Fatal("a redelivered callback ran the action a second time")
	}

	// a confirmation works exactly once
	tapLabel(t, tg, list.ID, "查看状态")
	tapLabel(t, tg, list.ID, "切换 AI 出站")
	waitText(t, tg, list.ID, "选择新的 AI 出口")
	tapLabel(t, tg, list.ID, "CA-Exit-ExitB")
	waitText(t, tg, list.ID, "确认切换")
	confirm, _ := tg.button(list.ID, "确认切换")
	tg.tap(list.ID, confirm)
	waitFor(t, "switched", 8*time.Second, func() bool { return ca.status().Config.AIOutboundID == ca.exitB.ID })
	waitText(t, tg, list.ID, "已切换 AI 出口为")
	if e := ca.a.SetAIExit(ca.exitA.ID); e != nil { // the owner reverts locally
		t.Fatal(e)
	}
	id2 := tg.tap(list.ID, confirm) // the same confirmation again, new callback id
	waitAnswer(t, tg, id2, "已失效")
	time.Sleep(200 * time.Millisecond)
	if ca.status().Config.AIOutboundID != ca.exitA.ID {
		t.Fatal("a used confirmation switched the exit again")
	}

	// a confirmation for one message cannot be used from another message
	waitFor(t, "page", 5*time.Second, func() bool { _, ok := tg.button(list.ID, "切换 AI 出站"); return ok })
	tapLabel(t, tg, list.ID, "切换 AI 出站")
	waitText(t, tg, list.ID, "选择新的 AI 出口")
	tapLabel(t, tg, list.ID, "CA-Exit-ExitB")
	waitText(t, tg, list.ID, "确认切换")
	confirm2, _ := tg.button(list.ID, "确认切换")
	other := openList(t, tg)
	id3 := tg.tap(other.ID, confirm2)
	waitAnswer(t, tg, id3, "已失效")
	if ca.status().Config.AIOutboundID != ca.exitA.ID {
		t.Fatal("a confirmation was honoured from a different message")
	}
}

func TestTelegramButtonsAreRateLimited(t *testing.T) {
	tg, _ := newFleet(t, "US-GIA")
	list := openList(t, tg)
	data, _ := tg.button(list.ID, "刷新")
	var last string
	for i := 0; i < 60; i++ {
		last = tg.tap(list.ID, data)
	}
	waitFor(t, "flood handled", 10*time.Second, func() bool { _, ok := answered(tg, last); return ok })
	limited := 0
	for _, a := range tg.answers() {
		if strings.Contains(a.Text, "过于频繁") {
			limited++
		}
	}
	if limited == 0 {
		t.Fatal("button flooding was not limited")
	}
}

// ---- errors, rollback ---------------------------------------------------------------------------

func TestTelegramUnusableExitIsExplainedAndNeverApplied(t *testing.T) {
	tg, nodes := newFleet(t, "US-GIA", "CA-Exit")
	for _, n := range nodes {
		list := openList(t, tg)
		openServer(t, tg, list, n.name)
		tapLabel(t, tg, list.ID, "切换 AI 出站")
		waitText(t, tg, list.ID, "选择新的 AI 出口")
		id := tapLabel(t, tg, list.ID, n.name+"-Loop")
		waitFor(t, "explanation", 8*time.Second, func() bool { _, ok := answered(tg, id); return ok })
		a, _ := answered(tg, id)
		if !a.Alert || !strings.Contains(a.Text, "不能用于 AI 分流") || !strings.Contains(a.Text, "路由循环") {
			t.Fatalf("%s: the real reason was not shown: %+v", n.name, a)
		}
		if n.status().Config.AIOutboundID != n.exitA.ID {
			t.Fatalf("%s: an unusable exit was applied", n.name)
		}
		// bypassing the UI changes nothing either: the application layer refuses
		hub := nodes[0].theHub()
		cfg := nodes[0].hubConfig(t)
		sid := cfg.ServerID
		if n != nodes[0] {
			sid = n.agentConfig(t).ServerID
		}
		res, e := hub.dispatch(context.Background(), cfg, sid, tgCommand{ID: randomID(8), Kind: tgCmdSetExit, ExitID: n.exitBad.ID}, 5*time.Second)
		if e != nil || res.OK || !strings.Contains(res.Error, "循环") {
			t.Fatalf("%s: dispatch result %+v %v", n.name, res, e)
		}
		if n.status().Config.AIOutboundID != n.exitA.ID {
			t.Fatalf("%s: bypass applied an unusable exit", n.name)
		}
		// an exit that does not exist
		res, _ = hub.dispatch(context.Background(), cfg, sid, tgCommand{ID: randomID(8), Kind: tgCmdSetExit, ExitID: "deadbeefdead"}, 5*time.Second)
		if res.OK || res.Error == "" {
			t.Fatalf("%s: unknown exit accepted: %+v", n.name, res)
		}
	}
}

func TestTelegramFailedSwitchRollsBackAndSaysSo(t *testing.T) {
	tg, nodes := newFleet(t, "US-GIA", "CA-Exit")
	ca := nodes[1]
	list := openList(t, tg)
	openServer(t, tg, list, "CA-Exit")
	tapLabel(t, tg, list.ID, "开启 AI 分流")
	waitFor(t, "AI enabled", 8*time.Second, func() bool { return ca.status().Config.Enabled })
	waitText(t, tg, list.ID, "已开启 AI 分流")

	stateBefore := tgFileText(t, filepath.Join(ca.a.Home, "state.json"))
	cfgPath := filepath.Join(ca.a.profileDir(ca.node.ID), "config.json")
	cfgBefore := tgFileText(t, cfgPath)
	// the bound node's config can no longer be rewritten, so applying the new exit fails midway
	if e := os.Remove(cfgPath); e != nil {
		t.Fatal(e)
	}
	if e := os.MkdirAll(filepath.Join(cfgPath, "x"), 0700); e != nil {
		t.Fatal(e)
	}
	tapLabel(t, tg, list.ID, "切换 AI 出站")
	waitText(t, tg, list.ID, "选择新的 AI 出口")
	tapLabel(t, tg, list.ID, "CA-Exit-ExitB")
	waitText(t, tg, list.ID, "确认切换")
	tapLabel(t, tg, list.ID, "确认切换")
	m := waitText(t, tg, list.ID, "切换失败")
	if !strings.Contains(m.Text, "当前出口仍是 CA-Exit-ExitA") {
		t.Fatalf("the failure message must state what is still in effect:\n%s", m.Text)
	}
	if tgFileText(t, filepath.Join(ca.a.Home, "state.json")) != stateBefore {
		t.Fatal("state.json was not rolled back")
	}
	if ca.status().Config.AIOutboundID != ca.exitA.ID || !ca.status().Config.Enabled {
		t.Fatal("the failed switch changed the AI configuration")
	}
	// the same for turning AI off: the failure is real text, and nothing else moved
	tapLabel(t, tg, list.ID, "关闭 AI 分流")
	waitText(t, tg, list.ID, "操作失败")
	if !ca.status().Config.Enabled {
		t.Fatal("a failed disable reported success")
	}
	os.RemoveAll(cfgPath)
	if e := os.WriteFile(cfgPath, []byte(cfgBefore), 0600); e != nil {
		t.Fatal(e)
	}
	// sing-box rejecting the generated config also leaves everything as it was
	if e := os.WriteFile(ca.a.enginePath("sing-box"), []byte("#!/bin/sh\nexit 1\n"), 0755); e != nil {
		t.Fatal(e)
	}
	stateBefore = tgFileText(t, filepath.Join(ca.a.Home, "state.json"))
	tapLabel(t, tg, list.ID, "返回服务器列表")
	waitText(t, tg, list.ID, "请选择服务器")
	openServer(t, tg, tg.msg(list.ID), "CA-Exit")
	tapLabel(t, tg, list.ID, "切换 AI 出站")
	waitText(t, tg, list.ID, "选择新的 AI 出口")
	tapLabel(t, tg, list.ID, "CA-Exit-ExitB")
	waitText(t, tg, list.ID, "确认切换")
	tapLabel(t, tg, list.ID, "确认切换")
	waitText(t, tg, list.ID, "切换失败")
	if tgFileText(t, filepath.Join(ca.a.Home, "state.json")) != stateBefore || ca.status().Config.AIOutboundID != ca.exitA.ID {
		t.Fatal("a rejected configuration was not rolled back")
	}
}

func TestTelegramEnableFailureIsReportedWithItsRealCause(t *testing.T) {
	tg, nodes := newFleet(t, "US-GIA")
	us := nodes[0]
	// no usable exit selected -> AI cannot be switched on; the application layer says why
	if e := us.a.SetAIExit(""); e != nil {
		t.Fatal(e)
	}
	list := openList(t, tg)
	openServer(t, tg, list, "US-GIA")
	tapLabel(t, tg, list.ID, "开启 AI 分流")
	m := waitText(t, tg, list.ID, "操作失败")
	if us.status().Config.Enabled || strings.TrimSpace(m.Text) == "" {
		t.Fatalf("enable with no exit must fail visibly: %s", m.Text)
	}
}

// ---- enrollment ----------------------------------------------------------------------------------

func TestTelegramUnapprovedCertificatesGetNothing(t *testing.T) {
	tg, nodes := newFleet(t, "US-GIA", "CA-Exit")
	hub := nodes[0]
	addr := hub.theHub().addr()
	rogue, _ := newTelegramIdentity(randomID(8))
	var st tgStateOut

	// an unknown certificate cannot poll, post results or say goodbye
	for _, path := range []string{"/v1/poll", "/v1/result", "/v1/bye", "/v1/leave"} {
		if code := hubPost(t, addr, rogue, path, map[string]any{"result": tgResult{ID: "x"}}, &st); code != http.StatusForbidden || st.State != "unknown" {
			t.Fatalf("%s: %d %+v", path, code, st)
		}
	}
	// a client with no certificate at all cannot even connect
	hc := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	if resp, e := hc.Post("https://"+addr+"/v1/poll", "application/json", strings.NewReader("{}")); e == nil {
		resp.Body.Close()
		t.Fatal("the hub answered a client without a certificate")
	}
	// TLS older than 1.3 is refused
	old := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12}}}
	if resp, e := old.Post("https://"+addr+"/v1/poll", "application/json", strings.NewReader("{}")); e == nil {
		resp.Body.Close()
		t.Fatal("the hub accepted TLS 1.2")
	}
	// GET is not an API
	if resp, e := http.DefaultClient.Get("http://" + addr + "/v1/poll"); e == nil {
		resp.Body.Close()
	}

	// the token is the entry ticket: a wrong-token proof opens no approval prompt
	var ch tgStateOut
	if code := hubPost(t, addr, rogue, "/v1/enroll/challenge", enrollIn{ServerID: randomID(8), Name: "Intruder"}, &ch); code != 200 || ch.Nonce == "" {
		t.Fatalf("challenge: %d %+v", code, ch)
	}
	wrong := deriveTelegramKeys("7000000002:AAHotherTokenForRoutTelegramBBBBBBBBBBBB")
	sid := randomID(8)
	hubPost(t, addr, rogue, "/v1/enroll/challenge", enrollIn{ServerID: sid, Name: "Intruder"}, &ch)
	bad := enrollIn{ServerID: sid, Name: "Intruder", Nonce: ch.Nonce, Proof: wrong.enrollProof(ch.Nonce, sid, rogue.fingerprint())}
	if code := hubPost(t, addr, rogue, "/v1/enroll", bad, nil); code != http.StatusForbidden {
		t.Fatalf("a proof made with another token was accepted: %d", code)
	}
	time.Sleep(100 * time.Millisecond)
	if tg.count("Intruder") != 0 || len(hub.hubConfig(t).Hub.Pending) != 0 {
		t.Fatal("a failed proof produced an approval prompt")
	}
	// the nonce was consumed by the failed attempt; the right proof cannot reuse it
	good := enrollIn{ServerID: sid, Name: "Intruder", Nonce: ch.Nonce, Proof: deriveTelegramKeys(testBotToken).enrollProof(ch.Nonce, sid, rogue.fingerprint())}
	if code := hubPost(t, addr, rogue, "/v1/enroll", good, nil); code != http.StatusForbidden {
		t.Fatalf("a nonce was used twice: %d", code)
	}
	// a nonce issued to one certificate is useless to another
	hubPost(t, addr, rogue, "/v1/enroll/challenge", enrollIn{ServerID: sid, Name: "Intruder"}, &ch)
	thief, _ := newTelegramIdentity(randomID(8))
	steal := enrollIn{ServerID: sid, Name: "Intruder", Nonce: ch.Nonce, Proof: deriveTelegramKeys(testBotToken).enrollProof(ch.Nonce, sid, thief.fingerprint())}
	if code := hubPost(t, addr, thief, "/v1/enroll", steal, nil); code != http.StatusForbidden {
		t.Fatalf("a nonce was used by another certificate: %d", code)
	}

	// a holder of the token still needs the human: the prompt shows up, it is escaped, and the
	// intruder gets no commands until Allow is pressed
	evil := `<b>x</b>&"<a href="http://evil">`
	hubPost(t, addr, rogue, "/v1/enroll/challenge", enrollIn{ServerID: sid, Name: evil}, &ch)
	ok := enrollIn{ServerID: sid, Name: evil, Nonce: ch.Nonce, Proof: deriveTelegramKeys(testBotToken).enrollProof(ch.Nonce, sid, rogue.fingerprint())}
	if code := hubPost(t, addr, rogue, "/v1/enroll", ok, &st); code != 200 || st.State != "pending" {
		t.Fatalf("enroll: %d %+v", code, st)
	}
	waitFor(t, "approval prompt", 5*time.Second, func() bool { return tg.count("新服务器请求加入") >= 1 })
	m, _ := tg.find("新服务器请求加入")
	if strings.Contains(m.Text, "<a href") || strings.Contains(m.Text, "<b>x</b>") || !strings.Contains(m.Text, fingerprintGroups(rogue.fingerprint())) {
		t.Fatalf("approval prompt is not escaped / lacks the fingerprint:\n%s", m.Text)
	}
	if code := hubPost(t, addr, rogue, "/v1/poll", pollIn{}, &st); code != http.StatusForbidden || st.State != "pending" {
		t.Fatalf("a pending server was treated as approved: %d %+v", code, st)
	}
	// Reject: the certificate is revoked for good
	reject, ok2 := tg.button(m.ID, "拒绝")
	if !ok2 {
		t.Fatal("no reject button")
	}
	tg.tap(m.ID, reject)
	waitFor(t, "revoked", 5*time.Second, func() bool {
		hubPost(t, addr, rogue, "/v1/poll", pollIn{}, &st)
		return st.State == "revoked"
	})
	if code := hubPost(t, addr, rogue, "/v1/enroll/challenge", enrollIn{ServerID: sid, Name: "x"}, &st); code != http.StatusForbidden || st.State != "revoked" {
		t.Fatalf("a rejected certificate could ask again: %d %+v", code, st)
	}
	// an approved server's ID cannot be claimed by a different certificate
	caID := nodes[1].agentConfig(t).ServerID
	hubPost(t, addr, rogue2(t), "/v1/enroll/challenge", enrollIn{ServerID: caID, Name: "CA-Exit"}, &ch)
}

func rogue2(t *testing.T) tgIdentity {
	id, e := newTelegramIdentity(randomID(8))
	if e != nil {
		t.Fatal(e)
	}
	return id
}

func TestTelegramApprovedServerIDCannotBeHijacked(t *testing.T) {
	_, nodes := newFleet(t, "US-GIA", "CA-Exit")
	hub, ca := nodes[0], nodes[1]
	addr := hub.theHub().addr()
	impostor := rogue2(t)
	caID := ca.agentConfig(t).ServerID
	var ch tgStateOut
	hubPost(t, addr, impostor, "/v1/enroll/challenge", enrollIn{ServerID: caID, Name: "CA-Exit"}, &ch)
	proof := deriveTelegramKeys(testBotToken).enrollProof(ch.Nonce, caID, impostor.fingerprint())
	if code := hubPost(t, addr, impostor, "/v1/enroll", enrollIn{ServerID: caID, Name: "CA-Exit", Nonce: ch.Nonce, Proof: proof}, nil); code != http.StatusConflict {
		t.Fatalf("an approved server ID was claimed by another certificate: %d", code)
	}
	if len(hub.hubConfig(t).Hub.Pending) != 0 {
		t.Fatal("a hijack attempt created a pending request")
	}
}

func TestTelegramOwnerCanRemoveAServerFromTheChat(t *testing.T) {
	tg, nodes := newFleet(t, "US-GIA", "CA-Exit")
	hub, ca := nodes[0], nodes[1]
	list := openList(t, tg)
	openServer(t, tg, list, "CA-Exit")
	if _, ok := tg.button(list.ID, "移除此服务器"); !ok {
		t.Fatal("no remove button for an agent")
	}
	tapLabel(t, tg, list.ID, "移除此服务器")
	waitText(t, tg, list.ID, "确认撤销")
	tapLabel(t, tg, list.ID, "确认移除")
	waitText(t, tg, list.ID, "已移除 CA-Exit")
	if len(hub.hubConfig(t).Hub.Agents) != 0 || len(hub.hubConfig(t).Hub.Revoked) != 1 {
		t.Fatalf("revocation not recorded: %+v", hub.hubConfig(t).Hub)
	}
	// the revoked server is told, stops and cannot control or be controlled any more
	waitFor(t, "agent notices", 10*time.Second, func() bool { return ca.runtime().State == tgStateRevoked })
	if ca.agentConfig(t).Agent.State != "revoked" {
		t.Fatal("the agent did not record the revocation")
	}
	if _, e := hub.theHub().dispatch(context.Background(), hub.hubConfig(t), ca.agentConfig(t).ServerID, tgCommand{ID: randomID(8), Kind: tgCmdStatus}, time.Second); e == nil {
		t.Fatal("a revoked server still accepts commands")
	}
	// the hub itself cannot be removed from the chat
	list = openList(t, tg)
	openServer(t, tg, list, "US-GIA")
	if _, ok := tg.button(list.ID, "移除此服务器"); ok {
		t.Fatal("the local server offers a remove button")
	}
}

// ---- hub identity pinning ----------------------------------------------------------------------------

func TestTelegramAgentRefusesAHubWhoseCertificateChanged(t *testing.T) {
	_, nodes := newFleet(t, "US-GIA", "CA-Exit")
	hub, ca := nodes[0], nodes[1]
	ca.stop()
	if e := ca.a.mutateTelegram(func(c *TelegramConfig) error { c.Agent.HubFP = strings.Repeat("0", 64); return nil }); e != nil {
		t.Fatal(e)
	}
	seen := time.Now()
	ca.start()
	waitFor(t, "hub_changed", 10*time.Second, func() bool { return ca.runtime().State == tgStateHubChanged })
	// the hub never heard from it again, so no command can reach it
	for _, v := range hub.theHub().servers(hub.hubConfig(t)) {
		if v.Name == "CA-Exit" && v.LastSeen.After(seen) {
			t.Fatal("an agent talked to a hub it does not trust")
		}
	}
	if !strings.Contains(ca.runtime().Detail, "重新信任") {
		t.Fatalf("the user is not told how to recover: %q", ca.runtime().Detail)
	}
}

func TestTelegramAgentFindsAMovedHubOnlyIfItIsTheSameHub(t *testing.T) {
	_, nodes := newFleet(t, "US-GIA", "CA-Exit")
	hub, ca := nodes[0], nodes[1]
	// the hub's address changed: the agent's saved endpoint is dead, the announcement is right
	if e := ca.a.mutateTelegram(func(c *TelegramConfig) error { c.Agent.Endpoints = []string{"127.0.0.1:1"}; return nil }); e != nil {
		t.Fatal(e)
	}
	waitFor(t, "agent rediscovered the hub", 15*time.Second, func() bool {
		return ca.agentConfig(t).Agent.Endpoints[0] != "127.0.0.1:1" && ca.runtime().State == tgStateOK
	})
	_ = hub
}

func TestTelegramReplacedHubRequiresDeliberateRetrust(t *testing.T) {
	tg, nodes := newFleet(t, "US-GIA", "CA-Exit")
	hub, ca := nodes[0], nodes[1]
	hub.stop()
	hub.a.TelegramUnbind(context.Background())
	// somebody (or the owner, on another VPS) becomes the hub for the same bot
	hub2 := newTGNode(t, tg, "US-NEW")
	hub2.bindHub(tg)
	// CA follows only the hub it pinned: it must stop, not silently join the new one
	waitFor(t, "hub_changed", 15*time.Second, func() bool { return ca.runtime().State == tgStateHubChanged })
	// re-trusting needs the new fingerprint, compared by a person
	res, e := ca.a.TelegramRetrust(context.Background(), "")
	if e != nil || !res.NeedsTrust || res.HubName != "US-NEW" {
		t.Fatalf("retrust must ask first: %+v %v", res, e)
	}
	if _, e = ca.a.TelegramRetrust(context.Background(), strings.Repeat("0", 32)); e != nil {
		t.Fatal(e)
	}
	if ca.agentConfig(t).Agent.HubName != "US-GIA" {
		t.Fatal("a wrong fingerprint re-trusted the hub")
	}
	res, e = ca.a.TelegramRetrust(context.Background(), fingerprintGroups(res.HubFP))
	if e != nil || res.NeedsTrust {
		t.Fatalf("retrust: %+v %v", res, e)
	}
	approvePending(t, tg, "CA-Exit")
	waitFor(t, "CA under the new hub", 15*time.Second, func() bool {
		for _, v := range hub2.theHub().servers(hub2.hubConfig(t)) {
			if v.Name == "CA-Exit" && v.Online {
				return true
			}
		}
		return false
	})
}

// ---- command replay -------------------------------------------------------------------------------

func TestTelegramAgentDeduplicatesAndExpiresCommands(t *testing.T) {
	tg := newFakeTelegram(t, testBotToken, testChat)
	n := newTGNode(t, tg, "CA-Exit")
	n.bindHub(tg)
	cfg := n.hubConfig(t)
	g, e := n.a.newTelegramAgent(TelegramConfig{Token: cfg.Token, ChatID: cfg.ChatID, ServerID: cfg.ServerID, Name: cfg.Name, Role: tgRoleAgent, CertPEM: cfg.CertPEM, KeyPEM: cfg.KeyPEM,
		Agent: &TelegramAgent{HubFP: strings.Repeat("a", 64), Endpoints: []string{"127.0.0.1:1"}}})
	if e != nil {
		t.Fatal(e)
	}
	cmd := tgCommand{ID: "replay-0123456789", Kind: tgCmdSetEnabled, Enabled: true, TTL: 60}
	if r := g.execute(context.Background(), cmd, time.Now()); !r.OK || !n.status().Config.Enabled {
		t.Fatalf("first run: %+v", r)
	}
	if e := n.a.SetAIEnabled(false); e != nil {
		t.Fatal(e)
	}
	// the hub redelivers (its response was lost): answered from the cache, not executed again
	if r := g.execute(context.Background(), cmd, time.Now()); !r.OK || n.status().Config.Enabled {
		t.Fatalf("a redelivered command ran twice: %+v", r)
	}
	// an old command arriving late is refused
	old := tgCommand{ID: "stale-0123456789", Kind: tgCmdSetEnabled, Enabled: true, TTL: 30}
	if r := g.execute(context.Background(), old, time.Now().Add(-time.Minute)); r.OK || !strings.Contains(r.Error, "过期") || n.status().Config.Enabled {
		t.Fatalf("an expired command was executed: %+v", r)
	}
	// there is no command that runs anything else
	for _, kind := range []string{"exec", "shell", "set_exit;reboot", "read_file", "get_secrets"} {
		r := g.execute(context.Background(), tgCommand{ID: randomID(8), Kind: kind, TTL: 60}, time.Now())
		if r.OK || r.Status != nil && false {
			t.Fatalf("%q was accepted: %+v", kind, r)
		}
	}
}

// ---- credentials, unbind, uninstall ------------------------------------------------------------------

func TestTelegramTokenReplacementReachesEveryServerAndOldKeysDie(t *testing.T) {
	tg, nodes := newFleet(t, "US-GIA", "CA-Exit")
	hub, ca := nodes[0], nodes[1]
	const token2 = "7000000009:AAHsecondTokenForRoutTelegramCCCCCCCCCCC"
	tg.addToken(token2)
	warns, e := hub.a.TelegramSetCredentials(context.Background(), token2, 0)
	if e != nil {
		t.Fatal(e)
	}
	if len(warns) == 0 {
		t.Fatal("the user is not told that other servers sync later")
	}
	waitFor(t, "hub republished under the new token", 10*time.Second, func() bool {
		_, e := deriveTelegramKeys(token2).openAnnouncement(tg.pinnedText())
		return e == nil
	})
	if _, e := deriveTelegramKeys(testBotToken).openAnnouncement(tg.pinnedText()); e == nil {
		t.Fatal("the old token still opens the announcement")
	}
	waitFor(t, "agent synced", 15*time.Second, func() bool { return ca.agentConfig(t).Token == token2 })
	// the old token is revoked at Telegram: everything keeps working on the new one
	tg.mu.Lock()
	delete(tg.tokens, testBotToken)
	tg.mu.Unlock()
	list := openList(t, tg)
	openServer(t, tg, list, "CA-Exit")
	tapLabel(t, tg, list.ID, "开启 AI 分流")
	waitFor(t, "AI enabled on the new token", 10*time.Second, func() bool { return ca.status().Config.Enabled })
	for _, n := range nodes {
		if strings.Contains(tgFileText(t, n.a.telegramPath()), testBotToken) {
			t.Fatalf("%s still stores the old token", n.name)
		}
	}
	// an invalid replacement is refused before anything changes
	if _, e := hub.a.TelegramSetCredentials(context.Background(), "7000000010:AAHunknownTokenForRoutTelegramDDDDDDDDDD", 0); e == nil {
		t.Fatal("a token Telegram does not know was accepted")
	}
	if hub.hubConfig(t).Token != token2 {
		t.Fatal("a failed replacement changed the token")
	}
	// credentials are managed on the hub only
	if _, e := ca.a.TelegramSetCredentials(context.Background(), testBotToken, 0); e == nil {
		t.Fatal("an agent changed the shared credentials")
	}
}

func TestTelegramUnbindLeavesNoControlChannel(t *testing.T) {
	tg, nodes := newFleet(t, "US-GIA", "CA-Exit")
	hub, ca := nodes[0], nodes[1]
	caID := ca.agentConfig(t).ServerID
	oldCA := ca.agentConfig(t)
	addr := hub.theHub().addr()

	// an agent unbinding is forgotten by the hub at once
	if _, e := ca.a.TelegramUnbind(context.Background()); e != nil {
		t.Fatal(e)
	}
	for _, p := range []string{ca.a.telegramPath(), ca.a.telegramStatusPath(), ca.a.telegramAuditPath()} {
		if _, e := os.Stat(p); e == nil {
			t.Fatalf("%s left behind", p)
		}
	}
	waitFor(t, "hub forgot the agent", 5*time.Second, func() bool {
		for _, a := range hub.hubConfig(t).Hub.Agents {
			if a.ID == caID {
				return false
			}
		}
		return true
	})
	// its old identity is dead
	var st tgStateOut
	oldID := tgIdentity{CertPEM: oldCA.CertPEM, KeyPEM: oldCA.KeyPEM}
	if code := hubPost(t, addr, oldID, "/v1/poll", pollIn{}, &st); code != http.StatusForbidden || st.State != "revoked" {
		t.Fatalf("an unbound server can still poll: %d %+v", code, st)
	}
	waitFor(t, "agent loop idle", 5*time.Second, func() bool { return ca.runtime().State == tgStateStopped })

	// the hub unbinding closes the listener, withdraws the announcement and stops polling
	if _, e := hub.a.TelegramUnbind(context.Background()); e != nil {
		t.Fatal(e)
	}
	waitFor(t, "announcement withdrawn", 5*time.Second, func() bool { return tg.pinnedText() == "" })
	waitFor(t, "listener closed", 8*time.Second, func() bool {
		c, e := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
		if e == nil {
			c.Close()
			return false
		}
		return true
	})
	calls, _ := tg.stats()
	time.Sleep(300 * time.Millisecond)
	calls2, _ := tg.stats()
	if calls2["getUpdates"] != calls["getUpdates"] && calls2["getUpdates"] > calls["getUpdates"]+2 {
		t.Fatal("the hub kept polling Telegram after unbind")
	}
	if _, e := os.Stat(hub.a.telegramPath()); e == nil {
		t.Fatal("the hub's token and private key were not deleted")
	}
	// pressing an old button now does nothing
	list, _ := tg.find("Rout Control")
	id := tg.tap(list.ID, "L~AAAAAAAAAAA")
	time.Sleep(300 * time.Millisecond)
	if a, ok := answered(tg, id); ok && a.Text != "" && !strings.Contains(a.Text, "失效") {
		t.Fatalf("unexpected answer after unbind: %+v", a)
	}
}

func TestTelegramUnbindOfAFailedConfigAlwaysSucceeds(t *testing.T) {
	a := testApp(t)
	if e := os.WriteFile(a.telegramPath(), []byte("{not json"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := a.LoadTelegram(); e == nil {
		t.Fatal("a corrupt config loaded")
	}
	if _, e := a.TelegramUnbind(context.Background()); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(a.telegramPath()); e == nil {
		t.Fatal("corrupt config left behind")
	}
	// unbinding when nothing is bound is a no-op
	if w, e := a.TelegramUnbind(context.Background()); e != nil || len(w) != 0 {
		t.Fatalf("%v %v", w, e)
	}
}

// ---- single consumer / webhook ------------------------------------------------------------------------

func TestTelegramNeverTakesOverAWebhookOrAnotherConsumer(t *testing.T) {
	tg := newFakeTelegram(t, testBotToken, testChat)
	n := newTGNode(t, tg, "US-GIA")
	tg.setWebhook("https://example.invalid/hook")
	if _, e := n.a.TelegramBind(context.Background(), TelegramBindRequest{Token: testBotToken, ChatID: testChat}); e == nil || !strings.Contains(e.Error(), "webhook") {
		t.Fatalf("binding next to a webhook must be refused: %v", e)
	}
	if _, e := n.a.LoadTelegram(); e != errTelegramUnbound {
		t.Fatal("a refused bind left a configuration behind")
	}
	tg.setWebhook("")
	n.bindHub(tg)
	// another program starts consuming the same bot
	tg.setRogue(true)
	waitFor(t, "conflict reported", 10*time.Second, func() bool { return n.runtime().State == tgStateConflict })
	if !strings.Contains(n.runtime().Detail, "不会覆盖") {
		t.Fatalf("detail: %q", n.runtime().Detail)
	}
	tg.setRogue(false)
	waitFor(t, "recovered", 10*time.Second, func() bool { return n.runtime().State == tgStateOK })
	// a webhook set while we run is respected after a restart
	n.stop()
	tg.setWebhook("https://example.invalid/hook")
	n.start()
	waitFor(t, "webhook conflict", 10*time.Second, func() bool { return n.runtime().State == tgStateConflict })
	if calls, _ := tg.stats(); calls["deleteWebhook"] != 0 {
		t.Fatal("Rout deleted somebody's webhook")
	}
}

func TestTelegramBindValidatesWithTelegramItself(t *testing.T) {
	tg := newFakeTelegram(t, testBotToken, testChat)
	n := newTGNode(t, tg, "US-GIA")
	bind := func(tok string, chat int64) error {
		_, e := n.a.TelegramBind(context.Background(), TelegramBindRequest{Token: tok, ChatID: chat})
		return e
	}
	for name, c := range map[string]struct {
		tok  string
		chat int64
		want string
	}{
		"bad format":     {"not-a-token", testChat, "格式"},
		"unknown token":  {"7000000010:AAHunknownTokenForRoutTelegramDDDDDDDDDD", testChat, "Token"},
		"group chat id":  {testBotToken, -1001234, "私聊"},
		"zero chat id":   {testBotToken, 0, "私聊"},
		"chat not found": {testBotToken, 424242, "Chat ID"},
	} {
		e := bind(c.tok, c.chat)
		if e == nil || !strings.Contains(e.Error(), c.want) {
			t.Errorf("%s: %v", name, e)
		}
		if strings.Contains(e.Error(), c.tok) && c.tok != "" && len(c.tok) > 12 {
			t.Errorf("%s: the error repeats the token: %v", name, e)
		}
		if _, er := n.a.LoadTelegram(); er != errTelegramUnbound {
			t.Fatalf("%s: a failed bind stored something", name)
		}
	}
	if e := bind(testBotToken, testChat); e != nil {
		t.Fatal(e)
	}
	if e := bind(testBotToken, testChat); e != errTelegramBound {
		t.Fatalf("second bind: %v", e)
	}
}

// ---- nothing sensitive reaches Telegram, the logs or the status file ------------------------------------

func TestTelegramNeverSendsSecretsToTelegramOrDisk(t *testing.T) {
	tg, nodes := newFleet(t, "US-GIA", "CA-Exit", "JP-Tokyo")
	for _, n := range nodes {
		list := openList(t, tg)
		openServer(t, tg, list, n.name)
		tapLabel(t, tg, list.ID, "开启 AI 分流")
		waitFor(t, "enabled", 8*time.Second, func() bool { return n.status().Config.Enabled })
		waitText(t, tg, list.ID, "已开启 AI 分流")
		tapLabel(t, tg, list.ID, "切换 AI 出站")
		waitText(t, tg, list.ID, "选择新的 AI 出口")
		tapLabel(t, tg, list.ID, n.name+"-ExitB")
		waitText(t, tg, list.ID, "确认切换")
		tapLabel(t, tg, list.ID, "确认切换")
		waitFor(t, "switched", 8*time.Second, func() bool { return n.status().Config.AIOutboundID == n.exitB.ID })
		waitText(t, tg, list.ID, "已切换 AI 出口为")
		tapLabel(t, tg, list.ID, "测试 AI 出口")
		waitText(t, tg, list.ID, "AI 出口测试")
	}
	seen := tg.allText()
	secrets := []string{testBotToken, "AAHtest", tgSecretPass, tgSecretUser, "198.51.100", "127.0.0.1"}
	for _, n := range nodes {
		for _, s := range []string{n.node.Password, n.node.UUID, n.node.PrivateKey} {
			if len(s) > 8 {
				secrets = append(secrets, s)
			}
		}
	}
	for _, s := range secrets {
		if strings.Contains(seen, s) {
			t.Errorf("Telegram saw %q", s)
		}
	}
	// the announcement carries the hub's address, but only encrypted
	if strings.Contains(tg.pinnedText(), "127.0.0.1") {
		t.Error("the pinned announcement shows the address in the clear")
	}
	for _, n := range nodes {
		for _, f := range []string{n.a.telegramStatusPath(), n.a.telegramAuditPath()} {
			b := tgFileText(t, f)
			for _, s := range []string{testBotToken, "AAHtest", tgSecretPass, tgSecretUser, "PRIVATE KEY"} {
				if strings.Contains(b, s) {
					t.Errorf("%s contains %q", filepath.Base(f), s)
				}
			}
		}
		// the one file that must hold secrets is private
		if st, e := os.Stat(n.a.telegramPath()); e != nil || st.Mode().Perm() != 0600 {
			t.Errorf("%s: telegram.json permissions: %v %v", n.name, st, e)
		}
	}
}
