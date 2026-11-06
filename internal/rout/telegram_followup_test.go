package rout

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Regression tests for the review of PR #13 and the audit that followed: diagnostics that name
// the configured exit by host name or bare IPv6, agent renames, heartbeat during long commands,
// the cost of the status that is reported every few seconds, clock-skewed certificates and a
// short Bot API rate limit.

func (n *tgNode) addExit(name string, p Proxy) Exit {
	n.t.Helper()
	s, e := n.a.Load()
	if e != nil {
		n.t.Fatal(e)
	}
	ex := Exit{ID: RandomHex(6), Name: name, Proxy: p}
	if e = n.a.Commit(s, UpsertExit(s, ex), false); e != nil {
		n.t.Fatal(e)
	}
	return ex
}

// scriptedDiag makes the AI exit test deterministic: names resolve from the table and every
// connection is refused immediately, with the address in the error like the real dialer.
func scriptedDiag(records map[string][]string) *webTestHooks {
	env := diagEnvFor(records, func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, fmt.Errorf("dial %s: connection refused", addr)
	})
	return &webTestHooks{diag: &env}
}

// ---- scrubbing ---------------------------------------------------------------------------------

func TestTelegramScrubberRemovesWhatTheConfigurationNames(t *testing.T) {
	s := State{
		Exits: []Exit{
			{ID: "aaaaaaaaaaaa", Name: "Canada", Proxy: Proxy{Protocol: "socks5", Host: "private-exit.example.com", Port: 1080, Username: "exit-user-xyz", Password: "ExitPassw0rd-SECRET"}},
			{ID: "bbbbbbbbbbbb", Name: "v6", Proxy: Proxy{Protocol: "http", Host: "2001:db8::20", Port: 8080}},
			{ID: "cccccccccccc", Name: "chain", Kind: "chain", ViaAddress: "hop.example.net:4443", Proxy: Proxy{Protocol: "socks5", Host: "end.example.org", Port: 1080}},
		},
		Profiles: []Profile{{ID: "dddddddddddd", Kind: "relay", Name: "CA-hop", Target: "relay-target.example.net:443"}},
	}
	x := newTGScrubber(s)
	for _, text := range []string{
		"域名 private-exit.example.com 解析为 IPv4: 203.0.113.9；IPv6: 2001:db8::20",
		"域名解析失败：private-exit.example.com — no such host",
		"连接超时：PRIVATE-EXIT.EXAMPLE.COM:1080",
		"目标连通 [2001:db8::20]:8080 失败",
		"地址 2001:db8::20: failed",
		"hop hop.example.net:4443 then end.example.org",
		"relay target relay-target.example.net:443 unreachable",
		"login exit-user-xyz / ExitPassw0rd-SECRET rejected",
	} {
		out := x.clean(text, 300)
		for _, bad := range []string{"private-exit", "PRIVATE-EXIT", "203.0.113.9", "2001:db8", "hop.example.net", "end.example.org", "relay-target", "exit-user-xyz", "ExitPassw0rd"} {
			if strings.Contains(out, bad) {
				t.Errorf("%q still contains %q after scrubbing: %q", text, bad, out)
			}
		}
		if !strings.Contains(out, tgRedacted) {
			t.Errorf("%q was not changed: %q", text, out)
		}
	}
	// what is not configured stays readable: public AI domains, times, MAC addresses, versions
	keep := "解析 api.openai.com 用时 12:30:45，网卡 aa:bb:cc:dd:ee:ff，版本 1:2:3"
	if got := x.clean(keep, 300); got != keep {
		t.Errorf("ordinary text was damaged: %q", got)
	}
	// the generic scrub alone still handles literals it can recognise
	if got := tgScrub("v6 ::1 and fe80::1 and [2001:db8::1]:443 and 10.0.0.1:80", 200); strings.ContainsAny(got, "0123456789") && strings.Contains(got, "::") {
		t.Errorf("generic scrub left an address: %q", got)
	}
	// an empty configuration is fine
	if got := newTGScrubber(State{}).clean("hello 1.2.3.4", 50); got != "hello "+tgRedacted {
		t.Errorf("empty configuration: %q", got)
	}
}

func TestTelegramRedactIPv6OnlyRealAddresses(t *testing.T) {
	for in, want := range map[string]string{
		"2001:db8::20":                               tgRedacted,
		"addr 2001:db8::20: failed":                  "addr " + tgRedacted + ": failed",
		"loopback ::1.":                              "loopback " + tgRedacted + ".",
		"2001:0db8:0000:0000:0000:0000:0000:0020 ok": tgRedacted + " ok",
		"::ffff:192.0.2.1":                           tgRedacted,
		"time 10:12:33":                              "time 10:12:33",
		"mac aa:bb:cc:dd:ee:ff":                      "mac aa:bb:cc:dd:ee:ff",
		"ratio 1:2:3":                                "ratio 1:2:3",
		"no colons here":                             "no colons here",
	} {
		if got := tgRedactIPv6(in); got != want {
			t.Errorf("tgRedactIPv6(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTelegramTestStepsNeverRevealExitHostnamesOrIPv6(t *testing.T) {
	records := map[string][]string{"private-exit.example.com": {"203.0.113.9", "2001:db8::20"}}
	tg, nodes := newFleet(t, "US-GIA", "CA-Exit")
	secrets := []string{"private-exit.example.com", "PRIVATE-EXIT", "203.0.113.9", "2001:db8::20", "2001:db8:"}
	for _, n := range nodes {
		n.a.webHooks = scriptedDiag(records)
		hostExit := n.addExit(n.name+"-HostExit", Proxy{Protocol: "socks5", Host: "private-exit.example.com", Port: 1080, Username: "u-" + tgSecretUser, Password: tgSecretPass})
		v6Exit := n.addExit(n.name+"-V6Exit", Proxy{Protocol: "socks5", Host: "2001:db8::20", Port: 1080, Username: "v6-user-abc", Password: "V6Passw0rd-xyz"})
		for _, ex := range []Exit{hostExit, v6Exit} {
			if e := n.a.SetAIExit(ex.ID); e != nil {
				t.Fatal(e)
			}
			// the unscrubbed local diagnosis does contain the address, so this test is not vacuous
			raw, e := n.a.TestAIExit(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			var all strings.Builder
			for _, st := range raw.Steps {
				all.WriteString(st.Text + "\n")
			}
			if !strings.Contains(all.String(), strings.TrimSuffix(strings.TrimPrefix(ex.Proxy.Host, "["), "]")) {
				t.Fatalf("%s: the local diagnosis no longer prints the host, the scenario is empty:\n%s", n.name, all.String())
			}
			list := openList(t, tg)
			openServer(t, tg, list, n.name)
			tapLabel(t, tg, list.ID, "测试 AI 出口")
			waitText(t, tg, list.ID, "AI 出口测试")
			// give any late edit a moment, then look at everything Telegram has seen
			time.Sleep(100 * time.Millisecond)
			seen := tg.allText()
			for _, bad := range secrets {
				if strings.Contains(seen, bad) {
					t.Fatalf("%s/%s: Telegram saw %q:\n%s", n.name, ex.Name, bad, seen)
				}
			}
			if strings.Contains(seen, tgSecretPass) || strings.Contains(seen, "u-"+tgSecretUser) {
				t.Fatalf("%s: Telegram saw exit credentials", n.name)
			}
		}
	}
}

// ---- agent rename -------------------------------------------------------------------------------

func hubServerNames(hub *tgNode, t *testing.T) []string {
	var names []string
	for _, v := range hub.theHub().servers(hub.hubConfig(t)) {
		names = append(names, v.Name)
	}
	return names
}

func TestTelegramAgentRenameReachesTheHubAndEveryView(t *testing.T) {
	tg, nodes := newFleet(t, "US-GIA", "CA-Exit")
	hub, ca := nodes[0], nodes[1]
	_, c := telegramEnv(t, tg, hub)
	c.reauth()
	idBefore, fpBefore := ca.agentConfig(t).ServerID, ca.agentConfig(t).identity().fingerprint()

	if e := ca.a.TelegramRename("CA-Canada"); e != nil {
		t.Fatal(e)
	}
	waitFor(t, "hub adopted the name", 10*time.Second, func() bool {
		for _, n := range hubServerNames(hub, t) {
			if n == "CA-Canada" {
				return true
			}
		}
		return false
	})
	for _, n := range hubServerNames(hub, t) {
		if n == "CA-Exit" {
			t.Fatal("the old name is still listed")
		}
	}
	if got := hub.hubConfig(t).Hub.Agents[0]; got.Name != "CA-Canada" || got.ID != idBefore || got.FP != ca.agentConfig(t).identity().fingerprint() || got.FP != fpBefore {
		t.Fatalf("a rename must change the label only: %+v", got)
	}
	// Telegram's list and the server page use the new name, and the server is still controllable
	list := openList(t, tg)
	if _, ok := tg.button(list.ID, "CA-Canada"); !ok {
		t.Fatalf("the list lacks the new name: %+v", list.Markup)
	}
	if _, ok := tg.button(list.ID, "CA-Exit"); ok {
		t.Fatal("the list still shows the old name")
	}
	openServer(t, tg, list, "CA-Canada")
	tapLabel(t, tg, list.ID, "开启 AI 分流")
	waitFor(t, "AI enabled after the rename", 8*time.Second, func() bool { return ca.status().Config.Enabled })
	// the hub's panel shows it too (after the service's next fleet refresh)
	waitFor(t, "panel shows the new name", 10*time.Second, func() bool {
		for _, sv := range listOf(t, jsonOf(t, c.get("/api/telegram")), "servers") {
			if sv["name"] == "CA-Canada" {
				return true
			}
		}
		return false
	})
	if !strings.Contains(tgFileText(t, hub.a.telegramAuditPath()), "renamed") {
		t.Fatal("the rename is not in the audit log")
	}
	// the new name survives a restart of both sides
	ca.stop()
	hub.stop()
	hub.start()
	ca.start()
	waitFor(t, "fleet back", 10*time.Second, func() bool {
		if hub.theHub() == nil {
			return false
		}
		for _, v := range hub.theHub().servers(hub.hubConfig(t)) {
			if v.Name == "CA-Canada" && v.Online && v.Status != nil {
				return true
			}
		}
		return false
	})
}

func TestTelegramRenameGuards(t *testing.T) {
	_, nodes := newFleet(t, "US-GIA", "CA-Exit", "JP-Tokyo")
	hub, ca, jp := nodes[0], nodes[1], nodes[2]
	h := hub.theHub()
	cfg := hub.hubConfig(t)
	var caRec, jpRec TelegramAgentRecord
	for _, a := range cfg.Hub.Agents {
		switch a.ID {
		case ca.agentConfig(t).ServerID:
			caRec = a
		case jp.agentConfig(t).ServerID:
			jpRec = a
		}
	}
	// names that are empty, invalid, unchanged or already taken are not adopted
	for name, reported := range map[string]string{
		"empty":            "",
		"control":          "bad\nname",
		"too long":         strings.Repeat("x", 61),
		"same":             jpRec.Name,
		"taken by agent":   caRec.Name,
		"taken, any case":  strings.ToUpper(caRec.Name),
		"taken by the hub": "us-gia",
	} {
		if got := h.adoptName(cfg, jpRec, reported); got != jpRec.Name {
			t.Errorf("%s: adopted %q", name, got)
		}
	}
	if !strings.Contains(tgFileText(t, hub.a.telegramAuditPath()), "rename_refused") {
		t.Error("a refused rename is not audited")
	}
	// a valid change is adopted once, a second one within 30 s is held back
	if got := h.adoptName(cfg, jpRec, "JP-Osaka"); got != "JP-Osaka" {
		t.Fatalf("valid rename refused: %q", got)
	}
	cfg = hub.hubConfig(t)
	for _, a := range cfg.Hub.Agents {
		if a.ID == jpRec.ID {
			jpRec = a
		}
	}
	if got := h.adoptName(cfg, jpRec, "JP-Kyoto"); got != "JP-Osaka" {
		t.Fatalf("rapid renames must be rate limited, got %q", got)
	}
	// only the record with the same certificate is touched: a stale record cannot rename another
	other := jpRec
	other.FP = strings.Repeat("0", 64)
	h.names = map[string]*tgNameState{}
	if got := h.adoptName(cfg, other, "JP-Elsewhere"); got != other.Name {
		t.Fatalf("a record with a different certificate was renamed: %q", got)
	}
}

// ---- data from other servers is limited like local data ------------------------------------------------

func TestTelegramReceivedStatusAndResultsAreSanitised(t *testing.T) {
	tg, nodes := newFleet(t, "US-GIA", "CA-Exit")
	hub, ca := nodes[0], nodes[1]
	caCfg := ca.agentConfig(t)
	caID := tgIdentity{CertPEM: caCfg.CertPEM, KeyPEM: caCfg.KeyPEM}
	addr := hub.theHub().addr()
	ca.stop() // from here on "CA" is played by the test, with the same approved certificate

	var exits []tgExitInfo
	for i := 0; i < 100; i++ {
		exits = append(exits, tgExitInfo{ID: fmt.Sprintf("%012d", i), Name: "exit<script>" + strings.Repeat("N", 200), Kind: "SOCKS5", Usable: true})
	}
	evil := &tgServerStatus{ServerID: caCfg.ServerID, Name: "CA-Exit", ExitName: "<b>boom</b>" + strings.Repeat("A", 300), Exits: exits, Version: strings.Repeat("v", 100), Bound: -7,
		Problems: []string{"password=hunter2 at 198.51.100.7", "p2", "p3", "p4", "p5", "p6", "p7", "p8", "p9", "p10"}}
	var out pollOut
	go hubPostErr(addr, caID, "/v1/poll", pollIn{Status: evil}, &out) // holds the long poll open
	waitFor(t, "status stored", 5*time.Second, func() bool {
		for _, v := range hub.theHub().servers(hub.hubConfig(t)) {
			if v.Name == "CA-Exit" && v.Status != nil && v.Online && len(v.Status.Exits) == 40 {
				return true
			}
		}
		return false
	})
	var st tgServerStatus
	for _, v := range hub.theHub().servers(hub.hubConfig(t)) {
		if v.Name == "CA-Exit" {
			st = *v.Status
		}
	}
	if len(st.Exits) != 40 || len(st.Problems) != 8 || st.Bound != 0 || len([]rune(st.ExitName)) > 61 || len(st.Version) > 25 {
		t.Fatalf("status not bounded: exits=%d problems=%d bound=%d exitname=%d version=%d", len(st.Exits), len(st.Problems), st.Bound, len([]rune(st.ExitName)), len(st.Version))
	}
	if strings.Contains(strings.Join(st.Problems, " "), "hunter2") || strings.Contains(strings.Join(st.Problems, " "), "198.51.100.7") {
		t.Fatalf("problems not scrubbed: %v", st.Problems)
	}
	if st.Name != "CA-Exit" {
		t.Fatalf("a status must not choose its own name here: %q", st.Name)
	}
	// the page shows it escaped
	list := openList(t, tg)
	page := openServer(t, tg, list, "CA-Exit")
	if strings.Contains(page.Text, "<b>boom</b>") || !strings.Contains(page.Text, "&lt;b&gt;boom&lt;/b&gt;") {
		t.Fatalf("server-supplied text is not escaped:\n%s", page.Text)
	}

	// a result carrying secrets, too many steps and a made-up level
	cfg := hub.hubConfig(t)
	type dres struct {
		res tgResult
		err error
	}
	done := make(chan dres, 1)
	go func() {
		r, e := hub.theHub().dispatch(context.Background(), cfg, caCfg.ServerID, tgCommand{ID: randomID(8), Kind: tgCmdTest}, 10*time.Second)
		done <- dres{r, e}
	}()
	var job pollOut
	waitFor(t, "job delivered", 5*time.Second, func() bool {
		job = pollOut{}
		hubPost(t, addr, caID, "/v1/poll", pollIn{Status: evil}, &job)
		return len(job.Commands) == 1
	})
	var steps []tgStep
	for i := 0; i < 30; i++ {
		steps = append(steps, tgStep{Level: "<script>", Text: "key " + strings.Repeat("Q", 64) + " at 203.0.113.50 password=hunter2"})
	}
	hubPost(t, addr, caID, "/v1/result", resultIn{Result: tgResult{ID: job.Commands[0].ID, OK: true, Error: "http://evil.example/x?token=abc", Steps: steps}}, nil)
	r := <-done
	if r.err != nil || len(r.res.Steps) != 12 {
		t.Fatalf("result: %+v %v", r.res, r.err)
	}
	for _, s := range r.res.Steps {
		if s.Level != "info" || strings.Contains(s.Text, "hunter2") || strings.Contains(s.Text, "203.0.113.50") || strings.Contains(s.Text, strings.Repeat("Q", 64)) {
			t.Fatalf("step not sanitised: %+v", s)
		}
	}
	if strings.Contains(r.res.Error, "evil.example") {
		t.Fatalf("error not scrubbed: %q", r.res.Error)
	}
}

// ---- liveness during a long command ----------------------------------------------------------------------

func TestTelegramHeartbeatKeepsABusyServerOnlineAndPagesResponsive(t *testing.T) {
	tg, nodes := newFleet(t, "US-GIA", "CA-Exit")
	hub, ca := nodes[0], nodes[1]
	entered := make(chan struct{}, 16)
	release := make(chan struct{})
	env := diagEnvFor(map[string][]string{}, func(ctx context.Context, network, addr string) (net.Conn, error) {
		select {
		case entered <- struct{}{}:
		default:
		}
		// deliberately ignores ctx: the command must stay running until the test releases it,
		// whatever deadlines the diagnosis applies to its own steps
		select {
		case <-release:
		case <-time.After(30 * time.Second):
		}
		return nil, errors.New("connection refused")
	})
	ca.a.webHooks = &webTestHooks{diag: &env}

	list := openList(t, tg)
	openServer(t, tg, list, "CA-Exit")
	tapLabel(t, tg, list.ID, "测试 AI 出口") // the agent is now busy in the test
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the test never reached the agent")
	}
	// a long time passes at the hub; only the agent's heartbeat can keep the server online
	hub.clock.advance(10 * time.Minute)
	waitFor(t, "busy server still online", 5*time.Second, func() bool {
		for _, v := range hub.theHub().servers(hub.hubConfig(t)) {
			if v.Name == "CA-Exit" {
				return v.Online
			}
		}
		return false
	})
	// and opening its page in a new message does not wait for a status the busy agent cannot give
	// (it would otherwise time out after 8 s and show the cached one)
	began := time.Now()
	list2 := openList(t, tg)
	page := openServer(t, tg, list2, "CA-Exit")
	if d := time.Since(began); d > 3*time.Second {
		t.Fatalf("the page waited %v for a busy server", d)
	}
	if !strings.Contains(page.Text, "在线") {
		t.Fatalf("a busy server must still be shown as online:\n%s", page.Text)
	}
	close(release)
	waitFor(t, "test finished", 30*time.Second, func() bool {
		m := tg.msg(list.ID)
		return strings.Contains(m.Text, "AI 出口测试")
	})
}

// ---- cost of the periodic status --------------------------------------------------------------------------

func TestTelegramSummaryMatchesAIStatus(t *testing.T) {
	sc := newAIScene(t)
	a := sc.a
	if e := a.SetAIExit(sc.exit.ID); e != nil {
		t.Fatal(e)
	}
	if e := a.SetAIBindings([]string{sc.reality.ID, sc.anytls.ID}); e != nil {
		t.Fatal(e)
	}
	for _, enabled := range []bool{false, true} {
		if e := a.SetAIEnabled(enabled); e != nil {
			t.Fatal(e)
		}
		full, e := a.AIStatus()
		if e != nil {
			t.Fatal(e)
		}
		s, _ := a.Load()
		sum := a.aiSummary(s)
		if sum.Config.Enabled != full.Config.Enabled || sum.Config.AIOutboundID != full.Config.AIOutboundID || sum.ExitName != full.ExitName || sum.ExitProtocol != full.ExitProtocol ||
			sum.ExitChain != full.ExitChain || sum.BoundCount != full.BoundCount || sum.RuleSetAvailable != full.RuleSetAvailable || strings.Join(sum.Problems, "|") != strings.Join(full.Problems, "|") {
			t.Fatalf("summary differs from AIStatus (enabled=%v):\n%+v\n%+v", enabled, sum, full)
		}
		if len(sum.Nodes) != 0 || len(full.Nodes) != 4 || full.BoundCount != 2 {
			t.Fatalf("summary must not carry node runtime facts: summary %d nodes, status %d nodes, bound %d", len(sum.Nodes), len(full.Nodes), full.BoundCount)
		}
	}
	// the control plane reports the same facts
	cfg := TelegramConfig{ServerID: "0123456789abcdef", Name: "x", Token: testBotToken, ChatID: 1}
	st, e := a.tgStatus(cfg)
	if e != nil || !st.Enabled || st.ExitID != sc.exit.ID || st.Bound != 2 || st.ExitName != sc.exit.Name {
		t.Fatalf("tgStatus: %+v %v", st, e)
	}
}

func TestWebTelegramViewNeverLooksUpAddressesOrQueriesNodes(t *testing.T) {
	tg := newFakeTelegram(t, testBotToken, testChat)
	n := newTGNode(t, tg, "US-GIA")
	var lookups atomic.Int32
	n.a.telegram.addresses = func() Addresses { lookups.Add(1); return Addresses{IPv4: "127.0.0.1"} }
	_, c := telegramEnv(t, tg, n)
	c.reauth()
	mustOK(t, c.do("POST", "/api/telegram/bind", map[string]any{"token": testBotToken, "chat_id": "111", "role": "hub", "multi_server": true}).Code, "")
	waitFor(t, "endpoints announced", 8*time.Second, func() bool { return len(n.runtime().Endpoints) > 0 })
	n.stop() // the service's own announcements are not what is measured here
	lookups.Store(0)
	var first map[string]any
	for i := 0; i < 20; i++ {
		w := c.get("/api/telegram")
		mustOK(t, w.Code, w.Body.String())
		if i == 0 {
			first = jsonOf(t, w)
		}
	}
	if lookups.Load() != 0 {
		t.Fatalf("the panel looked up this server's address %d times while polling", lookups.Load())
	}
	hub := first["hub"].(map[string]any)
	eps := hub["endpoints"].([]any)
	if len(eps) != 1 || !strings.HasPrefix(eps[0].(string), "127.0.0.1:") || hub["multi_server"] != true {
		t.Fatalf("hub view: %v", hub)
	}
	// with multi-server off there is nothing to announce
	mustOK(t, c.do("PATCH", "/api/telegram", map[string]any{"multi_server": false}).Code, "")
	if eps := jsonOf(t, c.get("/api/telegram"))["hub"].(map[string]any)["endpoints"].([]any); len(eps) != 0 {
		t.Fatalf("endpoints with multi-server off: %v", eps)
	}
}

// ---- clock skew, rate limit, service definition ---------------------------------------------------------------------

func TestTelegramHubAcceptsAgentsWhoseClocksAreWrong(t *testing.T) {
	tg := newFakeTelegram(t, testBotToken, testChat)
	hub := newTGNode(t, tg, "US-GIA")
	hub.bindHub(tg)
	for name, shift := range map[string]time.Duration{"ahead": 72 * time.Hour, "behind": -40 * 365 * 24 * time.Hour} {
		old := tgIdentityClock
		tgIdentityClock = func() time.Time { return time.Now().Add(shift) }
		n := newTGNode(t, tg, "CA-"+name)
		n.bindAgent(tg)
		tgIdentityClock = old
		approvePending(t, tg, "CA-"+name)
		waitFor(t, name+" agent online", 10*time.Second, func() bool {
			for _, v := range hub.theHub().servers(hub.hubConfig(t)) {
				if v.Name == "CA-"+name && v.Online && v.Status != nil {
					return true
				}
			}
			return false
		})
		// and commands work: the TTL is relative, so a skewed clock cannot expire them
		list := openList(t, tg)
		openServer(t, tg, list, "CA-"+name)
		tapLabel(t, tg, list.ID, "开启 AI 分流")
		waitFor(t, name+" agent obeys", 8*time.Second, func() bool { return n.status().Config.Enabled })
	}
}

func TestTelegramClientRetriesAShortRateLimitOnce(t *testing.T) {
	tg := newFakeTelegram(t, testBotToken, testChat)
	a := testApp(t)
	a.telegram = &telegramHooks{base: tg.URL()}
	cl := a.tgClient(testBotToken)
	defer cl.close()

	tg.mu.Lock()
	tg.failNext["sendMessage"] = &tgAPIError{Code: 429, Desc: "Too Many Requests: retry after 1", RetryAfter: 1}
	tg.mu.Unlock()
	began := time.Now()
	if _, e := cl.sendMessage(context.Background(), testChat, "hello", nil); e != nil {
		t.Fatalf("a short rate limit should be waited out: %v", e)
	}
	if d := time.Since(began); d < 900*time.Millisecond || d > 5*time.Second {
		t.Fatalf("waited %v", d)
	}
	if calls, _ := tg.stats(); calls["sendMessage"] != 2 {
		t.Fatalf("sendMessage calls: %d", calls["sendMessage"])
	}
	// a long wait is reported, not slept through
	tg.mu.Lock()
	tg.failNext["sendMessage"] = &tgAPIError{Code: 429, Desc: "Too Many Requests", RetryAfter: 60}
	tg.mu.Unlock()
	began = time.Now()
	_, e := cl.sendMessage(context.Background(), testChat, "again", nil)
	var ae *tgAPIError
	if !errors.As(e, &ae) || ae.Code != 429 || time.Since(began) > 3*time.Second {
		t.Fatalf("long rate limit: %v after %v", e, time.Since(began))
	}
	// the update poll has its own back-off and is never retried inside the client
	tg.mu.Lock()
	tg.failNext["getUpdates"] = &tgAPIError{Code: 429, Desc: "Too Many Requests", RetryAfter: 1}
	tg.mu.Unlock()
	began = time.Now()
	if _, e = cl.getUpdates(context.Background(), 0, 0); !errors.As(e, &ae) || time.Since(began) > 900*time.Millisecond {
		t.Fatalf("getUpdates: %v after %v", e, time.Since(began))
	}
	// cancellation interrupts the wait
	tg.mu.Lock()
	tg.failNext["sendMessage"] = &tgAPIError{Code: 429, Desc: "Too Many Requests", RetryAfter: 5}
	tg.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	began = time.Now()
	if _, e = cl.sendMessage(ctx, testChat, "cancel", nil); e == nil || time.Since(began) > 2*time.Second {
		t.Fatalf("cancel: %v after %v", e, time.Since(began))
	}
}

func TestTelegramOpenRCServiceDoesNotHardRequireTheNetwork(t *testing.T) {
	a := testApp(t)
	rc := a.telegramOpenRC()
	if !strings.Contains(rc, "depend() { use net; }") || strings.Contains(rc, "need net") {
		t.Fatalf("OpenRC dependency must be soft, like the panel's:\n%s", rc)
	}
}

func TestTelegramAgentSkipsAHubAddressThatSwallowsConnections(t *testing.T) {
	_, nodes := newFleet(t, "US-GIA", "CA-Exit")
	hub, ca := nodes[0], nodes[1]
	// a first address that accepts the TCP connection and then never answers the TLS handshake
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	var held []net.Conn
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			held = append(held, c)
		}
	}()
	t.Cleanup(func() {
		l.Close()
		for _, c := range held {
			c.Close()
		}
	})
	ca.stop()
	real := ca.agentConfig(t).Agent.Endpoints
	if e = ca.a.mutateTelegram(func(c *TelegramConfig) error {
		c.Agent.Endpoints = append([]string{l.Addr().String()}, real...)
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	ca.a.telegram.connect = 300 * time.Millisecond
	began := time.Now()
	ca.start()
	waitFor(t, "agent online through the second address", 8*time.Second, func() bool { return ca.runtime().State == tgStateOK })
	if d := time.Since(began); d > 6*time.Second {
		t.Fatalf("took %v to skip a dead address", d)
	}
	waitFor(t, "hub sees the agent", 5*time.Second, func() bool {
		for _, v := range hub.theHub().servers(hub.hubConfig(t)) {
			if v.Name == "CA-Exit" && v.Online {
				return true
			}
		}
		return false
	})
}

// The real init tools parse the generated definitions where they exist on the machine running the
// tests (CI has them). The negative control proves the tools would have said something.
func TestTelegramServiceDefinitionsAreAcceptedByTheRealInitTools(t *testing.T) {
	a := testApp(t)
	if e := os.WriteFile(filepath.Join(a.BinDir, "rout-telegram-v1"), []byte("#!/bin/sh\nexit 0\n"), 0755); e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	if p, e := exec.LookPath("systemd-analyze"); e == nil {
		verify := func(name, body string) string {
			f := filepath.Join(dir, name)
			if e := os.WriteFile(f, []byte(body), 0644); e != nil {
				t.Fatal(e)
			}
			out, _ := exec.Command(p, "verify", "--man=no", f).CombinedOutput()
			return strings.TrimSpace(string(out))
		}
		if out := verify("rout-bogus.service", "[Service]\nExecStart=/bin/true\nBogusKey=1\n"); out == "" {
			t.Skip("this systemd-analyze does not report problems on this machine; nothing to learn from it")
		}
		if out := verify("rout-telegram.service", a.telegramUnit()); out != "" {
			t.Fatalf("systemd-analyze objects to the unit:\n%s\n\n%s", out, a.telegramUnit())
		}
	} else {
		t.Log("systemd-analyze not available: the unit was not parsed by systemd on this machine")
	}
	script := filepath.Join(dir, "rout-telegram")
	if e := os.WriteFile(script, []byte(a.telegramOpenRC()), 0755); e != nil {
		t.Fatal(e)
	}
	if out, e := exec.Command("sh", "-n", script).CombinedOutput(); e != nil {
		t.Fatalf("the OpenRC script does not parse: %v\n%s", e, out)
	}
	if p, e := exec.LookPath("shellcheck"); e == nil {
		// SC2034: the openrc-run variables are read by openrc-run, not by the script.
		if out, e := exec.Command(p, "-s", "sh", "-e", "SC2034", script).CombinedOutput(); e != nil {
			t.Fatalf("shellcheck objects to the OpenRC script:\n%s", out)
		}
	}
}

func TestTelegramStaleRuntimeStatusIsNotShownAsConnected(t *testing.T) {
	tg := newFakeTelegram(t, testBotToken, testChat)
	n := newTGNode(t, tg, "US-GIA")
	if _, e := n.a.TelegramBind(context.Background(), TelegramBindRequest{Token: testBotToken, ChatID: testChat}); e != nil {
		t.Fatal(e)
	}
	// a service wrote "connected" and then died
	n.a.writeTelegramRuntime(TelegramRuntime{Role: tgRoleHub, State: tgStateOK})
	if s, _ := n.a.TelegramSummary(); s.Runtime == nil || s.Runtime.State != tgStateOK {
		t.Fatalf("a fresh status must be shown as it is: %+v", s.Runtime)
	}
	n.clock.advance(10 * time.Minute)
	s, _ := n.a.TelegramSummary()
	if s.Runtime == nil || s.Runtime.State != tgStateStopped || !strings.Contains(s.Runtime.Detail, "没有更新") {
		t.Fatalf("a status nobody has refreshed for 10 minutes must read as stopped: %+v", s.Runtime)
	}
	// and the panel agrees
	_, c := telegramEnv(t, tg, n)
	if got := jsonOf(t, c.get("/api/telegram"))["connection"].(map[string]any)["state"]; got != "stopped" {
		t.Fatalf("panel connection state: %v", got)
	}
}

// A press that sat in Telegram's backlog while the hub was down must not be carried out hours
// later: Telegram refuses an answer for it, and that is how the hub recognises it.
func TestTelegramPressesTelegramNoLongerAcceptsAreDropped(t *testing.T) {
	tg, nodes := newFleet(t, "US-GIA", "CA-Exit")
	hub, ca := nodes[0], nodes[1]
	list := openList(t, tg)
	openServer(t, tg, list, "CA-Exit")

	// a toggle from the backlog does nothing
	tg.makeNextPressesStale(1)
	tapLabel(t, tg, list.ID, "开启 AI 分流")
	waitFor(t, "stale press noticed", 5*time.Second, func() bool {
		return strings.Contains(tgFileText(t, hub.a.telegramAuditPath()), "stale_press_ignored")
	})
	time.Sleep(300 * time.Millisecond)
	if ca.status().Config.Enabled {
		t.Fatal("a stale press changed the configuration")
	}
	// a current one works
	tapLabel(t, tg, list.ID, "开启 AI 分流")
	waitFor(t, "fresh press obeyed", 8*time.Second, func() bool { return ca.status().Config.Enabled })
	waitText(t, tg, list.ID, "已开启 AI 分流")

	// a stale confirmation does not switch the exit, and the confirmation is used up
	tapLabel(t, tg, list.ID, "切换 AI 出站")
	waitText(t, tg, list.ID, "选择新的 AI 出口")
	tapLabel(t, tg, list.ID, "CA-Exit-ExitB")
	waitText(t, tg, list.ID, "确认切换")
	confirm, _ := tg.button(list.ID, "确认切换")
	tg.makeNextPressesStale(1)
	tg.tap(list.ID, confirm)
	waitFor(t, "second stale press noticed", 5*time.Second, func() bool {
		return strings.Count(tgFileText(t, hub.a.telegramAuditPath()), "stale_press_ignored") >= 2
	})
	time.Sleep(300 * time.Millisecond)
	if ca.status().Config.AIOutboundID != ca.exitA.ID {
		t.Fatal("a stale confirmation switched the exit")
	}
	id := tg.tap(list.ID, confirm)
	waitAnswer(t, tg, id, "已失效")

	// a stale Allow leaves the request pending for a current press
	jp := newTGNode(t, tg, "JP-Tokyo")
	jp.bindAgent(tg)
	var m fakeMsg
	var allow string
	waitFor(t, "join prompt", 5*time.Second, func() bool {
		var ok bool
		if m, ok = tg.find("<b>JP-Tokyo</b>"); !ok {
			return false
		}
		allow, ok = tg.button(m.ID, "允许")
		return ok
	})
	tg.makeNextPressesStale(1)
	tg.tap(m.ID, allow)
	waitFor(t, "third stale press noticed", 5*time.Second, func() bool {
		return strings.Count(tgFileText(t, hub.a.telegramAuditPath()), "stale_press_ignored") >= 3
	})
	if len(hub.hubConfig(t).Hub.Pending) != 1 || len(hub.hubConfig(t).Hub.Agents) != 1 {
		t.Fatalf("a stale Allow decided the request: %+v", hub.hubConfig(t).Hub)
	}
	tg.tap(m.ID, allow)
	waitFor(t, "current Allow obeyed", 5*time.Second, func() bool { return len(hub.hubConfig(t).Hub.Agents) == 2 })
}

// Two hubs for one bot (two servers bound at the same moment, or a hub forced while the old one
// still runs) must not fight over the update stream: the one whose announcement is not pinned
// gives way.
func TestTelegramOnlyOneHubKeepsTheUpdateStream(t *testing.T) {
	tg := newFakeTelegram(t, testBotToken, testChat)
	first := newTGNode(t, tg, "US-GIA")
	first.bindHub(tg)
	second := newTGNode(t, tg, "US-NEW")
	res, e := second.a.TelegramBind(context.Background(), TelegramBindRequest{Token: testBotToken, ChatID: testChat, ForceHub: true})
	if e != nil || res.Role != tgRoleHub {
		t.Fatalf("forced hub: %+v %v", res, e)
	}
	second.start()
	waitFor(t, "the old hub gives way", 15*time.Second, func() bool { return first.runtime().State == tgStateConflict })
	if !strings.Contains(first.runtime().Detail, "另一个控制中心") {
		t.Fatalf("the old hub does not say why: %q", first.runtime().Detail)
	}
	waitFor(t, "the new hub works", 10*time.Second, func() bool { return second.runtime().State == tgStateOK })
	// from here on exactly one consumer polls: no further conflicts accumulate
	time.Sleep(500 * time.Millisecond)
	_, before := tg.stats()
	time.Sleep(1500 * time.Millisecond)
	if _, after := tg.stats(); after != before {
		t.Fatalf("two hubs are still fighting: %d new conflicts", after-before)
	}
	// and the surviving hub answers the owner
	list := openList(t, tg)
	if !strings.Contains(list.Text, "US-NEW") && tgButtonText(list, "🟢 US-NEW") == "" {
		t.Fatalf("the new hub did not answer: %+v", list)
	}
}
