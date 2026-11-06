package rout

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestTelegramMenuBindsFirstServerAsHubWithOnlyTokenAndChat(t *testing.T) {
	tg := newFakeTelegram(t, testBotToken, testChat)
	n := newTGNode(t, tg, "US-GIA")
	installed := 0
	// menu: 1 = bind; then Bot Token, Chat ID; then 0 = back
	u, out := testUI(n.a, "1\n"+testBotToken+"\n111\n0\n")
	u.telegramSvc = func(action string) error {
		if action == "install" {
			installed++
			n.start()
		}
		return nil
	}
	if e := u.telegramMenu(); e != nil {
		t.Fatal(e)
	}
	text := out.String()
	if installed != 1 {
		t.Fatalf("service not installed: %d", installed)
	}
	for _, want := range []string{"Bot Token", "Chat ID", "@rout_test_bot", "US-GIA", "/start"} {
		if !strings.Contains(text, want) {
			t.Errorf("output lacks %q:\n%s", want, text)
		}
	}
	// only token + chat id were asked; the name defaulted to the hostname
	if strings.Contains(text, "Server name") || strings.Contains(text, "服务器名称:") {
		t.Errorf("the first bind must not ask for a server name:\n%s", text)
	}
	if strings.Contains(text, testBotToken) || strings.Contains(text, "AAHtest") {
		t.Fatal("the menu printed the Bot Token")
	}
	cfg := n.hubConfig(t)
	if cfg.Role != tgRoleHub || cfg.Name != "US-GIA" || cfg.ChatID != testChat || cfg.Hub.MultiServer {
		t.Fatalf("unexpected config: %+v", cfg)
	}
	waitFor(t, "service up", 5*time.Second, func() bool { return n.runtime().State == tgStateOK })

	// status view: token masked, chat id masked
	u, out = testUI(n.a, "2\n0\n")
	if e := u.telegramMenu(); e != nil {
		t.Fatal(e)
	}
	text = out.String()
	if strings.Contains(text, testBotToken) || strings.Contains(text, "111\n") || !strings.Contains(text, "••••") || !strings.Contains(text, fingerprintGroups(cfg.identity().fingerprint())) {
		t.Fatalf("status view:\n%s", text)
	}
}

func TestTelegramMenuTestsAndUnbinds(t *testing.T) {
	tg := newFakeTelegram(t, testBotToken, testChat)
	n := newTGNode(t, tg, "US-GIA")
	n.bindHub(tg)

	u, out := testUI(n.a, "4\n0\n") // test the connection
	if e := u.telegramMenu(); e != nil {
		t.Fatal(e)
	}
	if text := out.String(); !strings.Contains(text, "rout_test_bot") || strings.Contains(text, testBotToken) {
		t.Fatalf("test output:\n%s", text)
	}

	// unbind needs a yes; "n" keeps everything
	u, _ = testUI(n.a, "5\nn\n0\n")
	if e := u.telegramMenu(); e != nil {
		t.Fatal(e)
	}
	if _, e := n.a.LoadTelegram(); e != nil {
		t.Fatal("declining the confirmation unbound the server")
	}
	u, out = testUI(n.a, "5\ny\n0\n")
	if e := u.telegramMenu(); e != nil {
		t.Fatal(e)
	}
	if _, e := n.a.LoadTelegram(); e != errTelegramUnbound {
		t.Fatal("not unbound")
	}
	if _, e := os.Stat(n.a.telegramPath()); e == nil {
		t.Fatal("secrets left on disk")
	}
	waitFor(t, "announcement withdrawn", 5*time.Second, func() bool { return tg.pinnedText() == "" })
	// the proxy configuration is untouched
	if n.status().Config.AIOutboundID != n.exitA.ID || n.status().BoundCount != 1 {
		t.Fatal("unbinding changed the AI configuration")
	}
}

func TestTelegramMenuJoinsAnExistingHubAfterFingerprintCheck(t *testing.T) {
	tg := newFakeTelegram(t, testBotToken, testChat)
	hub := newTGNode(t, tg, "US-GIA")
	hub.bindHub(tg)
	hubFP := hub.hubConfig(t).identity().fingerprint()

	// declining the fingerprint binds nothing
	ca := newTGNode(t, tg, "CA-Exit")
	u, out := testUI(ca.a, "1\n"+testBotToken+"\n111\n0\n0\n")
	if e := u.telegramMenu(); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(out.String(), fingerprintGroups(hubFP)) || !strings.Contains(out.String(), "US-GIA") {
		t.Fatalf("the hub fingerprint was not shown:\n%s", out.String())
	}
	if _, e := ca.a.LoadTelegram(); e != errTelegramUnbound {
		t.Fatal("bound without the user confirming the fingerprint")
	}

	// confirming joins as an agent and starts the service; the owner then approves in Telegram
	u, out = testUI(ca.a, "1\n"+testBotToken+"\n111\n1\n0\n")
	u.telegramSvc = func(action string) error {
		if action == "install" {
			ca.start()
		}
		return nil
	}
	if e := u.telegramMenu(); e != nil {
		t.Fatal(e)
	}
	if cfg := ca.agentConfig(t); cfg.Role != tgRoleAgent || cfg.Name != "CA-Exit" || cfg.Agent.HubFP != hubFP {
		t.Fatalf("agent config: %+v", cfg)
	}
	approvePending(t, tg, "CA-Exit")
	waitFor(t, "agent online", 10*time.Second, func() bool { return ca.runtime().State == tgStateOK })
	if strings.Contains(out.String(), testBotToken) {
		t.Fatal("token printed")
	}

	// an agent's menu explains that credentials live on the hub
	u, out = testUI(ca.a, "3\n0\n")
	if e := u.telegramMenu(); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(out.String(), "控制中心") && !strings.Contains(out.String(), "hub") {
		t.Fatalf("no explanation:\n%s", out.String())
	}
}

func TestTelegramMenuHubAdministration(t *testing.T) {
	tg, nodes := newFleet(t, "US-GIA", "CA-Exit")
	hub := nodes[0]
	// a third server asks to join; the owner decides from the hub's menu this time
	jp := newTGNode(t, tg, "JP-Tokyo")
	jp.bindAgent(tg)
	waitFor(t, "pending recorded", 5*time.Second, func() bool { return len(hub.hubConfig(t).Hub.Pending) == 1 })

	sum, _ := hub.a.TelegramSummary()
	if len(sum.Pending) != 1 || len(sum.Agents) != 1 || sum.Pending[0].Name != "JP-Tokyo" {
		t.Fatalf("summary: %+v", sum)
	}
	// choose the pending item (menu item 1) and allow it
	u, out := testUI(hub.a, "1\n1\n")
	if e := u.telegramServers(sum); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(out.String(), "JP-Tokyo") {
		t.Fatalf("output:\n%s", out.String())
	}
	waitFor(t, "JP online", 10*time.Second, func() bool { return jp.runtime().State == tgStateOK })

	// revoke CA from the menu: needs a yes
	sum, _ = hub.a.TelegramSummary()
	idx := 1
	for i, ag := range sum.Agents {
		if ag.Name == "CA-Exit" {
			idx = len(sum.Pending) + i + 1
		}
	}
	u, _ = testUI(hub.a, strings.Repeat("", 0)+itoa(idx)+"\ny\n")
	if e := u.telegramServers(sum); e != nil {
		t.Fatal(e)
	}
	waitFor(t, "CA revoked", 10*time.Second, func() bool { return nodes[1].runtime().State == tgStateRevoked })
	if len(hub.hubConfig(t).Hub.Agents) != 1 {
		t.Fatalf("agents: %+v", hub.hubConfig(t).Hub.Agents)
	}
}

func TestTelegramMultiServerSwitchOpensAndClosesTheListener(t *testing.T) {
	tg := newFakeTelegram(t, testBotToken, testChat)
	n := newTGNode(t, tg, "US-GIA")
	res, e := n.a.TelegramBind(context.Background(), TelegramBindRequest{Token: testBotToken, ChatID: testChat})
	if e != nil || res.Role != tgRoleHub {
		t.Fatal(e)
	}
	n.start()
	waitFor(t, "single mode", 5*time.Second, func() bool { return n.runtime().State == tgStateOK })
	if n.theHub() != nil {
		t.Fatal("a listener exists in single-server mode")
	}
	// a second server cannot join a hub that has not enabled multi-server mode, and is told so
	other := newTGNode(t, tg, "CA-Exit")
	if _, e := other.a.TelegramBind(context.Background(), TelegramBindRequest{Token: testBotToken, ChatID: testChat}); e == nil || !strings.Contains(e.Error(), "多服务器") {
		t.Fatalf("expected the multi-server explanation, got %v", e)
	}
	if e := n.a.TelegramSetMultiServer(true, 0, nil); e != nil {
		t.Fatal(e)
	}
	waitFor(t, "listener", 5*time.Second, func() bool { return n.theHub() != nil && n.runtime().Listen != "" })
	addr := n.runtime().Listen
	if e := n.a.TelegramSetMultiServer(false, 0, nil); e != nil {
		t.Fatal(e)
	}
	waitFor(t, "listener closed", 8*time.Second, func() bool { return n.runtime().Listen == "" })
	_ = addr
	// invalid ports are refused and change nothing
	if e := n.a.TelegramSetMultiServer(true, 80, nil); e == nil {
		t.Fatal("port 80 accepted")
	}
	if n.hubConfig(t).Hub.MultiServer {
		t.Fatal("a refused change was applied")
	}
}

func TestTelegramCLIBindStatusAndUnbind(t *testing.T) {
	tg := newFakeTelegram(t, testBotToken, testChat)
	n := newTGNode(t, tg, "US-GIA")
	t.Setenv("ROUT_TELEGRAM_TOKEN", testBotToken)
	u, out := testUI(n.a, "")
	u.telegramSvc = func(string) error { return nil }
	if e := u.telegramCommand([]string{"telegram", "bind", "--chat-id", "111", "--name", "US-GIA"}); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(out.String(), testBotToken) {
		t.Fatal("bind printed the token")
	}
	u, out = testUI(n.a, "")
	if e := u.telegramCommand([]string{"telegram", "status"}); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(out.String(), testBotToken) || !strings.Contains(out.String(), "US-GIA") {
		t.Fatalf("status:\n%s", out.String())
	}
	if e := u.telegramCommand([]string{"telegram", "multi", "on", "--port", "28999", "--advertise", "203.0.113.5:28999"}); e != nil {
		t.Fatal(e)
	}
	if cfg := n.hubConfig(t); !cfg.Hub.MultiServer || cfg.Hub.Port != 28999 || cfg.Hub.Advertise[0] != "203.0.113.5:28999" {
		t.Fatalf("%+v", cfg.Hub)
	}
	if e := u.telegramCommand([]string{"telegram", "rename", "US-Main"}); e != nil || n.hubConfig(t).Name != "US-Main" {
		t.Fatalf("rename: %v", e)
	}
	if e := u.telegramCommand([]string{"telegram", "rename", "bad\nname"}); e == nil {
		t.Fatal("invalid name accepted")
	}
	for _, bad := range [][]string{{"telegram", "multi"}, {"telegram", "approve"}, {"telegram", "frobnicate"}, {"telegram", "bind", "--chat-id", "-5"}} {
		if e := u.telegramCommand(bad); e == nil {
			t.Errorf("%v should fail", bad)
		}
	}
	if e := u.telegramCommand([]string{"telegram", "unbind", "--yes"}); e != nil {
		t.Fatal(e)
	}
	if _, e := n.a.LoadTelegram(); e != errTelegramUnbound {
		t.Fatal("not unbound")
	}
}

func TestTelegramServiceDefinitions(t *testing.T) {
	a := testApp(t)
	a.Home, a.BinDir = "/etc/rout", "/opt/rout/bin"
	if a.telegramService() != "rout-telegram" {
		t.Fatalf("name: %s", a.telegramService())
	}
	unit := a.telegramUnit()
	for _, want := range []string{`ExecStart="/opt/rout/bin/rout-telegram-v1" "--home" "/etc/rout" "--bin-dir" "/opt/rout/bin" "telegram" "serve"`, "Restart=always", "WantedBy=multi-user.target", "After=network-online.target",
		"NoNewPrivileges=true", "ProtectHome=true", "PrivateTmp=true", "UMask=0077", "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK"} {
		if !strings.Contains(unit, want) {
			t.Errorf("systemd unit lacks %q:\n%s", want, unit)
		}
	}
	rc := a.telegramOpenRC()
	for _, want := range []string{"#!/sbin/openrc-run", "supervisor=supervise-daemon", "command='/opt/rout/bin/rout-telegram-v1'", "telegram", "serve", "respawn_delay=5", "output_log='/var/log/rout-telegram.log'", "chmod 600"} {
		if !strings.Contains(rc, want) {
			t.Errorf("OpenRC script lacks %q:\n%s", want, rc)
		}
	}
	// the definitions never contain credentials
	for _, s := range []string{unit, rc} {
		if strings.Contains(s, "AAH") || strings.Contains(s, "token") && !strings.Contains(s, "Token") && false {
			t.Error("service definition contains credentials")
		}
	}
	if a.telegramUnitPath("systemd") != "/etc/systemd/system/rout-telegram.service" || a.telegramUnitPath("openrc") != "/etc/init.d/rout-telegram" {
		t.Fatal("unit paths")
	}
	// a side-by-side install does not collide
	b := testApp(t)
	if b.telegramService() == "rout-telegram" || !strings.HasPrefix(b.telegramService(), "rout-telegram-") || a.telegramHelper() == b.telegramHelper() {
		t.Fatalf("custom home name: %s", b.telegramService())
	}
	// no service manager: installing says so instead of pretending
	if e := b.InstallTelegramService(); e == nil {
		t.Fatal("install without a service manager succeeded")
	}
	if st := b.TelegramServiceState(); st.Managed || st.Installed || st.Running {
		t.Fatalf("state: %+v", st)
	}
	// refresh on a host without a binding is a no-op
	if e := b.RefreshTelegramService(); e != nil {
		t.Fatal(e)
	}
}

func TestTelegramFilesAreCoveredByPermissionChecksAndLogs(t *testing.T) {
	a := testApp(t)
	id, _ := newTelegramIdentity("0123456789abcdef")
	cfg := TelegramConfig{Token: testBotToken, ChatID: 111, ServerID: "0123456789abcdef", Name: "x", Role: tgRoleHub, CertPEM: id.CertPEM, KeyPEM: id.KeyPEM, Hub: &TelegramHub{}}
	if e := a.saveTelegram(cfg); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(a.telegramPath(), 0644); e != nil {
		t.Fatal(e)
	}
	found := false
	for _, c := range a.CheckPermissions() {
		if c.Path == "telegram.json" && !c.OK {
			found = true
		}
	}
	if !found {
		t.Fatal("an over-permissive telegram.json is not flagged")
	}
	if a.FixPermissions() == 0 {
		t.Fatal("nothing fixed")
	}
	if st, _ := os.Stat(a.telegramPath()); st.Mode().Perm() != 0600 {
		t.Fatalf("mode after fix: %v", st.Mode())
	}
	// the panel's log viewer knows the unit (and reports there is no service here)
	s, _ := a.Load()
	if _, e := a.serviceLog(s, "telegram", 50); e == nil || strings.Contains(e.Error(), "未知") {
		t.Fatalf("log unit not recognised: %v", e)
	}
}
