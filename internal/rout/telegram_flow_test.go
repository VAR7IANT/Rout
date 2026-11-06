package rout

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These tests drive the real hub, bot and agents against fakeTelegram. Servers talk to each
// other over real mutually authenticated TLS 1.3 on the loopback interface; only Telegram is
// simulated. They are automated end to end: the "user" presses buttons by their visible label.

const testChat int64 = 111

func openList(t *testing.T, tg *fakeTelegram) fakeMsg {
	t.Helper()
	before := tg.count("Rout Control")
	tg.say(testChat, testChat, "private", "/start")
	waitFor(t, "server list", 8*time.Second, func() bool { return tg.count("Rout Control") > before })
	m, _ := tg.find("Rout Control")
	return m
}

func tapLabel(t *testing.T, tg *fakeTelegram, msg int64, label string) string {
	t.Helper()
	var data string
	waitFor(t, "button "+label, 8*time.Second, func() bool {
		var ok bool
		data, ok = tg.button(msg, label)
		return ok
	})
	return tg.tap(msg, data)
}

func waitText(t *testing.T, tg *fakeTelegram, msg int64, substr string) fakeMsg {
	t.Helper()
	var m fakeMsg
	waitFor(t, "message text containing "+substr+"\n--- current text:\n"+tg.msg(msg).Text, 10*time.Second, func() bool {
		m = tg.msg(msg)
		return strings.Contains(m.Text, substr)
	})
	return m
}

// openServer taps the server's button in the list message and waits for its page.
func openServer(t *testing.T, tg *fakeTelegram, list fakeMsg, name string) fakeMsg {
	t.Helper()
	tapLabel(t, tg, list.ID, name)
	return waitText(t, tg, list.ID, "🌐 <b>"+name+"</b>")
}

// newFleet starts a hub (names[0]) and approved agents for the remaining names.
func newFleet(t *testing.T, names ...string) (*fakeTelegram, []*tgNode) {
	t.Helper()
	tg := newFakeTelegram(t, testBotToken, testChat)
	var nodes []*tgNode
	hub := newTGNode(t, tg, names[0])
	hub.bindHub(tg)
	nodes = append(nodes, hub)
	for _, name := range names[1:] {
		n := newTGNode(t, tg, name)
		n.bindAgent(tg)
		approvePending(t, tg, name)
		nodes = append(nodes, n)
	}
	waitFor(t, "all servers online", 10*time.Second, func() bool {
		cfg, e := hub.a.LoadTelegram()
		if e != nil || hub.theHub() == nil {
			return false
		}
		for _, v := range hub.theHub().servers(cfg) {
			if !v.Online || v.Status == nil {
				return false
			}
		}
		return len(hub.theHub().servers(cfg)) == len(names)
	})
	return tg, nodes
}

func TestTelegramSingleServerToggleSwitchAndTest(t *testing.T) {
	tg := newFakeTelegram(t, testBotToken, testChat)
	n := newTGNode(t, tg, "US-GIA")
	res, e := n.a.TelegramBind(context.Background(), TelegramBindRequest{Token: testBotToken, ChatID: testChat})
	if e != nil || res.Role != tgRoleHub || res.BotUser != "rout_test_bot" {
		t.Fatalf("bind: %+v %v", res, e)
	}
	n.start()
	waitFor(t, "service running", 5*time.Second, func() bool { return n.runtime().State == tgStateOK })
	// Single-server mode opens no listening port at all.
	if rt := n.runtime(); rt.Listen != "" || n.theHub() != nil {
		t.Fatalf("a single server must not listen: %+v", rt)
	}

	list := openList(t, tg)
	if !strings.Contains(list.Text, "已连接服务器：1") || !strings.Contains(list.Text, "请选择服务器") {
		t.Fatalf("list: %s", list.Text)
	}
	page := openServer(t, tg, list, "US-GIA")
	for _, want := range []string{"服务器状态", "在线", "AI 分流", "已关闭", "US-GIA-ExitA", "已绑定入站", "1"} {
		if !strings.Contains(page.Text, want) {
			t.Errorf("server page lacks %q:\n%s", want, page.Text)
		}
	}
	for _, label := range []string{"开启 AI 分流", "切换 AI 出站", "测试 AI 出口", "查看状态", "返回服务器列表"} {
		if _, ok := tg.button(list.ID, label); !ok {
			t.Errorf("button %q missing", label)
		}
	}

	// toggle on
	tapLabel(t, tg, list.ID, "开启 AI 分流")
	waitFor(t, "AI enabled", 8*time.Second, func() bool { return n.status().Config.Enabled })
	waitText(t, tg, list.ID, "已开启 AI 分流")
	if _, ok := tg.button(list.ID, "关闭 AI 分流"); !ok {
		t.Fatal("the button should now offer to turn AI routing off")
	}

	// switch exit: pick, see the confirm screen, nothing changed yet, confirm
	tapLabel(t, tg, list.ID, "切换 AI 出站")
	m := waitText(t, tg, list.ID, "选择新的 AI 出口")
	if !strings.Contains(m.Text, "") || tgButtonText(m, "✅ US-GIA-ExitA") == "" || tgButtonText(m, "⛔ US-GIA-Loop") == "" {
		t.Fatalf("exit list should mark the current and the unusable exit: %+v", m.Markup)
	}
	tapLabel(t, tg, list.ID, "US-GIA-ExitB")
	waitText(t, tg, list.ID, "确认切换 AI 出口")
	if got := n.status().Config.AIOutboundID; got != n.exitA.ID {
		t.Fatal("the exit must not change before confirmation")
	}
	tapLabel(t, tg, list.ID, "确认切换")
	waitFor(t, "exit switched", 8*time.Second, func() bool { return n.status().Config.AIOutboundID == n.exitB.ID })
	page = waitText(t, tg, list.ID, "已切换 AI 出口为 US-GIA-ExitB")
	if !strings.Contains(page.Text, "当前 AI 出口") || !strings.Contains(page.Text, "US-GIA-ExitB") {
		t.Fatalf("page not refreshed after the switch: %s", page.Text)
	}
	// the AI setting and the binding survived
	if st := n.status(); !st.Config.Enabled || st.BoundCount != 1 {
		t.Fatalf("switching must keep AI on and the binding: %+v", st)
	}

	// test the exit (the AI exit points at a TEST-NET address, so the layered check reports it)
	tapLabel(t, tg, list.ID, "测试 AI 出口")
	waitFor(t, "test result", 90*time.Second, func() bool {
		m := tg.msg(list.ID)
		return strings.Contains(m.Text, "AI 出口测试")
	})

	// toggle off keeps the exit
	tapLabel(t, tg, list.ID, "关闭 AI 分流")
	waitFor(t, "AI disabled", 8*time.Second, func() bool { return !n.status().Config.Enabled })
	if n.status().Config.AIOutboundID != n.exitB.ID {
		t.Fatal("disabling must keep the selected exit")
	}
	// back to the list
	tapLabel(t, tg, list.ID, "返回服务器列表")
	waitText(t, tg, list.ID, "请选择服务器")
}

func tgButtonText(m fakeMsg, prefix string) string {
	if m.Markup == nil {
		return ""
	}
	for _, r := range m.Markup.Keyboard {
		for _, b := range r {
			if strings.HasPrefix(b.Text, prefix) {
				return b.Text
			}
		}
	}
	return ""
}

func TestTelegramThreeServersShareOneBotAndStayIndependent(t *testing.T) {
	tg, nodes := newFleet(t, "US-GIA", "CA-Exit", "JP-Tokyo")
	us, ca, jp := nodes[0], nodes[1], nodes[2]

	// exactly ONE consumer of getUpdates for the token: never a conflict
	calls, conflicts := tg.stats()
	if calls["getUpdates"] == 0 || conflicts != 0 || calls["deleteWebhook"] != 0 {
		t.Fatalf("hub must be the only getUpdates consumer and must not touch webhooks: %v conflicts=%d", calls, conflicts)
	}

	list := openList(t, tg)
	if !strings.Contains(list.Text, "已连接服务器：3") {
		t.Fatalf("list: %s", list.Text)
	}
	for _, name := range []string{"US-GIA", "CA-Exit", "JP-Tokyo"} {
		if _, ok := tg.button(list.ID, name); !ok {
			t.Fatalf("server %s missing from the list", name)
		}
	}

	// turn AI ON for CA only
	page := openServer(t, tg, list, "CA-Exit")
	if !strings.Contains(page.Text, "CA-Exit-ExitA") || strings.Contains(page.Text, "US-GIA-Exit") || strings.Contains(page.Text, "JP-Tokyo-Exit") {
		t.Fatalf("a server page must show only that server: %s", page.Text)
	}
	tapLabel(t, tg, list.ID, "开启 AI 分流")
	waitFor(t, "CA AI enabled", 8*time.Second, func() bool { return ca.status().Config.Enabled })
	waitText(t, tg, list.ID, "已开启 AI 分流")
	if us.status().Config.Enabled || jp.status().Config.Enabled {
		t.Fatal("operating on CA changed another server")
	}

	// switch JP's exit; US and CA keep theirs
	tapLabel(t, tg, list.ID, "返回服务器列表")
	waitText(t, tg, list.ID, "请选择服务器")
	openServer(t, tg, tg.msg(list.ID), "JP-Tokyo")
	tapLabel(t, tg, list.ID, "切换 AI 出站")
	waitText(t, tg, list.ID, "选择新的 AI 出口")
	if _, ok := tg.button(list.ID, "CA-Exit-Exit"); ok {
		t.Fatal("JP's exit list contains another server's exits")
	}
	tapLabel(t, tg, list.ID, "JP-Tokyo-ExitB")
	waitText(t, tg, list.ID, "确认切换")
	tapLabel(t, tg, list.ID, "确认切换")
	waitFor(t, "JP exit switched", 8*time.Second, func() bool { return jp.status().Config.AIOutboundID == jp.exitB.ID })
	if us.status().Config.AIOutboundID != us.exitA.ID || ca.status().Config.AIOutboundID != ca.exitA.ID {
		t.Fatal("switching JP changed another server's exit")
	}
	if !ca.status().Config.Enabled || jp.status().Config.Enabled || us.status().Config.Enabled {
		t.Fatal("unexpected AI enable state after JP switch")
	}

	// the hub itself (US) is controlled the same way
	tapLabel(t, tg, list.ID, "返回服务器列表")
	waitText(t, tg, list.ID, "请选择服务器")
	openServer(t, tg, tg.msg(list.ID), "US-GIA")
	tapLabel(t, tg, list.ID, "开启 AI 分流")
	waitFor(t, "US AI enabled", 8*time.Second, func() bool { return us.status().Config.Enabled })

	// a callback minted for one server can never be re-aimed at another
	waitText(t, tg, list.ID, "已开启 AI 分流")
	data, _ := tg.button(list.ID, "关闭 AI 分流")
	forged := strings.Replace(data, us.hubConfig(t).ServerID, ca.agentConfig(t).ServerID, 1)
	if forged == data {
		t.Fatal("test could not forge the callback")
	}
	tg.tap(list.ID, forged)
	waitFor(t, "forged button refused", 5*time.Second, func() bool {
		for _, a := range tg.answers() {
			if strings.Contains(a.Text, "按钮已失效") {
				return true
			}
		}
		return false
	})
	if !ca.status().Config.Enabled || !us.status().Config.Enabled {
		t.Fatal("a forged cross-server callback changed a server")
	}
}

func (n *tgNode) hubConfig(t *testing.T) TelegramConfig {
	t.Helper()
	c, e := n.a.LoadTelegram()
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func (n *tgNode) agentConfig(t *testing.T) TelegramConfig { return n.hubConfig(t) }

func TestTelegramAgentOfflineThenReconnect(t *testing.T) {
	tg, nodes := newFleet(t, "US-GIA", "CA-Exit")
	hub, ca := nodes[0], nodes[1]

	ca.stop() // the agent's service goes away (reboot, outage)
	hub.clock.advance(2 * time.Minute)

	list := openList(t, tg)
	if !strings.Contains(list.Text, "已连接服务器：1") {
		t.Fatalf("an offline server must not count as connected: %s", list.Text)
	}
	if tgButtonText(list, "🔴 CA-Exit") == "" {
		t.Fatalf("an offline server must show as offline: %+v", list.Markup)
	}
	page := openServer(t, tg, list, "CA-Exit")
	if !strings.Contains(page.Text, "离线") {
		t.Fatalf("page: %s", page.Text)
	}
	for _, label := range []string{"开启 AI 分流", "切换 AI 出站", "测试 AI 出口"} {
		if _, ok := tg.button(list.ID, label); ok {
			t.Errorf("offline server still offers %q", label)
		}
	}
	// a stale button from before the outage cannot act on an offline server
	hubCfg := hub.hubConfig(t)
	cb := hub.theHub()
	if _, e := cb.dispatch(context.Background(), hubCfg, ca.agentConfig(t).ServerID, tgCommand{ID: randomID(8), Kind: tgCmdSetEnabled, Enabled: true}, time.Second); e != errTgOffline {
		t.Fatalf("dispatch to an offline server must fail fast, got %v", e)
	}
	if ca.status().Config.Enabled {
		t.Fatal("an offline server was changed")
	}

	// the outage ends: the agent reconnects by itself, without a new approval
	ca.start()
	waitFor(t, "CA back online", 10*time.Second, func() bool {
		for _, v := range hub.theHub().servers(hub.hubConfig(t)) {
			if v.Name == "CA-Exit" && v.Online {
				return true
			}
		}
		return false
	})
	tapLabel(t, tg, list.ID, "查看状态")
	waitText(t, tg, list.ID, "🟢 在线")
	tapLabel(t, tg, list.ID, "开启 AI 分流")
	waitFor(t, "CA AI enabled after reconnect", 8*time.Second, func() bool { return ca.status().Config.Enabled })
}

func TestTelegramRestartKeepsBindingAndControl(t *testing.T) {
	tg, nodes := newFleet(t, "US-GIA", "CA-Exit")
	hub, ca := nodes[0], nodes[1]
	list := openList(t, tg)
	openServer(t, tg, list, "CA-Exit")
	tapLabel(t, tg, list.ID, "开启 AI 分流")
	waitFor(t, "CA AI enabled", 8*time.Second, func() bool { return ca.status().Config.Enabled })
	joinsBefore := tg.count("新服务器请求加入") + tg.count("已允许 CA-Exit")
	offsetBefore := hub.hubConfig(t).Offset
	if offsetBefore == 0 {
		t.Fatal("the update offset must be persisted")
	}

	// restart everything: hub first, then the agent
	ca.stop()
	hub.stop()
	hub.start()
	ca.start()
	waitFor(t, "fleet back", 10*time.Second, func() bool {
		if hub.theHub() == nil {
			return false
		}
		cfg, e := hub.a.LoadTelegram()
		if e != nil {
			return false
		}
		for _, v := range hub.theHub().servers(cfg) {
			if !v.Online || v.Status == nil {
				return false
			}
		}
		return true
	})
	// still controllable with no re-binding and no second approval prompt
	if tgButtonCount(tg, "允许") != 0 || tg.count("新服务器请求加入")+tg.count("已允许 CA-Exit") != joinsBefore {
		t.Fatal("a restart must not ask for approval again")
	}
	list2 := openList(t, tg)
	openServer(t, tg, list2, "CA-Exit")
	tapLabel(t, tg, list2.ID, "关闭 AI 分流")
	waitFor(t, "CA AI disabled after restart", 8*time.Second, func() bool { return !ca.status().Config.Enabled })
	if hub.hubConfig(t).Offset < offsetBefore {
		t.Fatal("offset went backwards")
	}
	// settings of the proxy services were never touched by the restarts
	if ca.status().Config.AIOutboundID != ca.exitA.ID || ca.status().BoundCount != 1 {
		t.Fatal("restart changed the AI configuration")
	}
}

func tgButtonCount(tg *fakeTelegram, label string) int {
	tg.mu.Lock()
	defer tg.mu.Unlock()
	n := 0
	for _, m := range tg.msgs {
		if m.Markup == nil || m.Deleted {
			continue
		}
		for _, r := range m.Markup.Keyboard {
			for _, b := range r {
				if strings.Contains(b.Text, label) {
					n++
				}
			}
		}
	}
	return n
}

func TestTelegramProxyServicesUntouchedByTheControlPlane(t *testing.T) {
	tg, nodes := newFleet(t, "US-GIA", "CA-Exit")
	hub, ca := nodes[0], nodes[1]
	read := func(n *tgNode) ([]byte, []byte) {
		st, _ := os.ReadFile(filepath.Join(n.a.Home, "state.json"))
		cfg, _ := os.ReadFile(filepath.Join(n.a.profileDir(n.node.ID), "config.json"))
		return st, cfg
	}
	st1, cfg1 := read(ca)
	// pure observation: opening pages, refreshing, listing exits changes nothing
	list := openList(t, tg)
	openServer(t, tg, list, "CA-Exit")
	tapLabel(t, tg, list.ID, "查看状态")
	tapLabel(t, tg, list.ID, "切换 AI 出站")
	waitText(t, tg, list.ID, "选择新的 AI 出口")
	time.Sleep(200 * time.Millisecond)
	st2, cfg2 := read(ca)
	if string(st1) != string(st2) || string(cfg1) != string(cfg2) {
		t.Fatal("browsing the bot changed state or node configuration")
	}
	// the control plane going away does not touch the proxy configuration either
	hub.stop()
	ca.stop()
	st3, cfg3 := read(ca)
	if string(st1) != string(st3) || string(cfg1) != string(cfg3) {
		t.Fatal("stopping the Telegram services changed state or node configuration")
	}
	if _, e := ca.a.Load(); e != nil {
		t.Fatal(e)
	}
}
