package rout

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Phase 1 menu tests: structure, navigation, Quick Create, node detail, cancellation,
// confirmation, Chinese rendering and narrow terminals. All run against a temporary
// directory with a stub engine; they drive the real menu code through scripted input.

func mainMenuItems(t *testing.T, a *App) []string {
	t.Helper()
	u, out := testUI(a, "0\n")
	if e := u.mainMenu(); e != nil {
		t.Fatal(e)
	}
	var items []string
	for _, line := range strings.Split(out.String(), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && len(f[0]) == 1 && f[0] >= "1" && f[0] <= "9" {
			items = append(items, strings.Join(f[1:], " "))
		}
	}
	return items
}

func TestMainMenuIsCompactAndHasNoDuplicates(t *testing.T) {
	a := testApp(t)
	items := mainMenuItems(t, a)
	want := []string{"Quick create node", "Manage nodes", "AI Smart Routing", "Port forwarding", "Outbound proxies", "Service & system", "Subscriptions"}
	if strings.Join(items, "|") != strings.Join(want, "|") {
		t.Fatalf("main menu %v, want %v", items, want)
	}
	seen := map[string]bool{}
	for _, it := range items {
		if seen[it] {
			t.Fatalf("duplicate entry %q", it)
		}
		seen[it] = true
	}
	// Operational menus moved under one entry instead of three top-level ones.
	for _, moved := range []string{"Diagnostics", "Updates", "Settings", "Traffic and limits"} {
		if seen[moved] {
			t.Fatalf("%q must not be a top-level entry any more", moved)
		}
	}
	keys := map[string]bool{}
	for _, it := range (&UI{a: a}).menu0() {
		if keys[it.key] {
			t.Fatalf("duplicate key %s", it.key)
		}
		keys[it.key] = true
	}
}

func TestMainMenuShowsStatusFromRealState(t *testing.T) {
	sc := newAIScene(t)
	u, out := testUI(sc.a, "0\n")
	_ = u.mainMenu()
	if !strings.Contains(out.String(), "Nodes: 4") || !strings.Contains(out.String(), "AI routing: disabled") {
		t.Fatalf("status line:\n%s", out.String())
	}
	_ = sc.a.SetAIExit(sc.exit.ID)
	_ = sc.a.SetAIBindings([]string{sc.reality.ID, sc.anytls.ID})
	_ = sc.a.SetAIEnabled(true)
	u, out = testUI(sc.a, "0\n")
	_ = u.mainMenu()
	if !strings.Contains(out.String(), "AI routing: enabled (2 inbounds)") {
		t.Fatalf("AI status not taken from the saved configuration:\n%s", out.String())
	}
}

func TestEveryPreviousFunctionStaysReachable(t *testing.T) {
	a := testApp(t)
	cases := []struct {
		name, input string
		want        []string
	}{
		{"service management", "6\n1\n0\n0\n0\n", []string{"Service status", "Restart a node or relay", "View logs", "Re-apply all configuration", "Install or update the traffic monitor service"}},
		{"diagnostics, updates, settings", "6\n0\n0\n", []string{"Diagnostics", "Updates", "Settings"}},
		{"settings submenu", "6\n4\n0\n0\n0\n", []string{"Language", "Server address", "Backup and restore", "Uninstall"}},
		{"node management extras", "2\n0\n0\n", []string{"New node", "All links", "Traffic and limits"}},
		{"traffic overview from node management", "2\nt\n0\n0\n", []string{"Traffic and limits"}},
		{"port forwarding", "4\n0\n0\n", []string{"Create relay", "Delete relay"}},
		{"outbound proxies", "5\n0\n0\n", []string{"Create outbound proxy", "Assign to nodes"}},
	}
	for _, c := range cases {
		u, out := testUI(a, c.input)
		if e := u.mainMenu(); e != nil {
			t.Fatalf("%s: %v", c.name, e)
		}
		for _, want := range c.want {
			if !strings.Contains(out.String(), want) {
				t.Errorf("%s: missing %q in\n%s", c.name, want, out.String())
			}
		}
	}
}

func createdNodes(t *testing.T, a *App) []Profile {
	t.Helper()
	s, e := a.Load()
	if e != nil {
		t.Fatal(e)
	}
	return s.Profiles
}

func TestQuickCreateAndNodeManagementShareOneImplementation(t *testing.T) {
	quick := testApp(t)
	// Quick create → base name → protocol → confirm.
	u, qOut := testUI(quick, "1\nEdge\n1\n\n0\n")
	if e := u.mainMenu(); e != nil {
		t.Fatal(e)
	}
	viaMenu := testApp(t)
	// Node Management → n → the same questions.
	u, mOut := testUI(viaMenu, "2\nn\nEdge\n1\n\n0\n0\n")
	if e := u.mainMenu(); e != nil {
		t.Fatal(e)
	}
	q, m := createdNodes(t, quick), createdNodes(t, viaMenu)
	if len(q) != 1 || len(m) != 1 {
		t.Fatalf("quick created %d, management created %d", len(q), len(m))
	}
	a, b := q[0], m[0]
	if a.Name != "Edge-VLESS" || a.Name != b.Name || a.Protocol != b.Protocol || a.SNI != b.SNI || a.Listen != b.Listen || a.Kind != b.Kind || a.Enabled != b.Enabled {
		t.Fatalf("different defaults: %+v vs %+v", a, b)
	}
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	}
	// Connection information is shown immediately after creation, in both paths.
	for _, out := range []string{qOut.String(), mOut.String()} {
		if !strings.Contains(out, "Nodes created successfully") || !strings.Contains(out, "vless://") {
			t.Fatalf("no connection info after creation:\n%s", out)
		}
	}
	if _, e := os.Stat(filepath.Join(quick.profileDir(a.ID), "config.json")); e != nil {
		t.Fatal("quick-created node has no service configuration")
	}
}

func TestQuickCreateCanBeCancelled(t *testing.T) {
	for name, input := range map[string]string{
		"at the name":      "1\n0\n0\n",
		"at the protocols": "1\nEdge\n0\n0\n",
		"at confirmation":  "1\nEdge\n1\n4\n0\n",
	} {
		a := testApp(t)
		u, out := testUI(a, input)
		if e := u.mainMenu(); e != nil {
			t.Fatalf("%s: %v", name, e)
		}
		if n := len(createdNodes(t, a)); n != 0 {
			t.Fatalf("%s: created %d nodes after cancelling", name, n)
		}
		if !strings.Contains(out.String(), "Cancelled") {
			t.Fatalf("%s: no cancellation message:\n%s", name, out.String())
		}
	}
}

func TestQuickCreateRejectsConflictingPortBeforeCreating(t *testing.T) {
	a := testApp(t)
	u, _ := testUI(a, "Edge\n1\n\n")
	if e := u.create(); e != nil {
		t.Fatal(e)
	}
	taken := createdNodes(t, a)[0]
	// "Change ports" → the port of the existing node is refused, a free one accepted.
	free, _ := freePort()
	u, out := testUI(a, "Edge2\n1\n2\n"+itoa(taken.Port)+"\n"+itoa(free)+"\n1\n")
	if e := u.create(); e != nil {
		t.Fatalf("%v\n%s", e, out.String())
	}
	if !strings.Contains(out.String(), "use the same TCP port") {
		t.Fatalf("conflict not reported:\n%s", out.String())
	}
	if n := len(createdNodes(t, a)); n != 2 {
		t.Fatalf("expected 2 nodes, got %d", n)
	}
}

func TestNodeSelectionShowsConnectionLinkDirectly(t *testing.T) {
	a := testApp(t)
	u, _ := testUI(a, "Edge\n1 3\n\n")
	if e := u.create(); e != nil {
		t.Fatal(e)
	}
	nodes := createdNodes(t, a)
	vless := nodes[0]
	link, _ := vless.URI()
	// List first: no links, no secrets.
	u, listOut := testUI(a, "2\n0\n0\n")
	_ = u.mainMenu()
	if strings.Contains(listOut.String(), "vless://") || strings.Contains(listOut.String(), vless.UUID) {
		t.Fatal("credentials shown in the node list")
	}
	// Selecting a node shows its link at once, before any further choice.
	u, out := testUI(a, "2\n1\n0\n0\n0\n")
	if e := u.mainMenu(); e != nil {
		t.Fatal(e)
	}
	text := out.String()
	detail := text[strings.Index(text, "Edge-VLESS\n"):]
	for _, want := range []string{"Protocol", "VLESS", "Address", "203.0.113.10", "Status", "Connection", link, "Edit", "Delete"} {
		if !strings.Contains(detail, want) {
			t.Fatalf("detail misses %q:\n%s", want, detail)
		}
	}
	if strings.Index(detail, link) > strings.Index(detail, "Edit") {
		t.Fatal("the link must appear before the action menu")
	}
	// A different protocol shows only its own fields.
	u, ssOut := testUI(a, "2\n2\n0\n0\n0\n")
	_ = u.mainMenu()
	if !strings.Contains(ssOut.String(), "ss://") || strings.Contains(ssOut.String(), "pbk=") {
		t.Fatalf("Shadowsocks detail wrong:\n%s", ssOut.String())
	}
}

func TestNodeDeleteNeedsConfirmationAndDefaultsToNo(t *testing.T) {
	a := testApp(t)
	u, _ := testUI(a, "Edge\n1\n\n")
	_ = u.create()
	for name, answer := range map[string]string{"empty answer": "\n", "n": "n\n"} {
		u, out := testUI(a, "2\n1\n2\n"+answer+"0\n0\n0\n")
		if e := u.mainMenu(); e != nil {
			t.Fatal(e)
		}
		if len(createdNodes(t, a)) != 1 {
			t.Fatalf("%s deleted the node", name)
		}
		if !strings.Contains(out.String(), "[y/N]") {
			t.Fatal("destructive prompt must default to No")
		}
	}
	u, out := testUI(a, "2\n1\n2\ny\n0\n0\n")
	if e := u.mainMenu(); e != nil {
		t.Fatal(e)
	}
	if len(createdNodes(t, a)) != 0 || !strings.Contains(out.String(), "Node deleted") {
		t.Fatalf("confirmed delete failed:\n%s", out.String())
	}
}

func TestNodeDetailActionsToggleAndEdit(t *testing.T) {
	a := testApp(t)
	u, _ := testUI(a, "Edge\n1\n\n")
	_ = u.create()
	// 4 = disable (confirm), then enable again without confirmation, then edit → rename.
	u, _ = testUI(a, "2\n1\n4\ny\n4\n0\n0\n0\n")
	if e := u.mainMenu(); e != nil {
		t.Fatal(e)
	}
	if !createdNodes(t, a)[0].Enabled {
		t.Fatal("node should be enabled again")
	}
	u, _ = testUI(a, "2\n1\n1\n1\nRenamed\n0\n0\n0\n0\n")
	if e := u.mainMenu(); e != nil {
		t.Fatal(e)
	}
	if got := createdNodes(t, a)[0].Name; got != "Renamed" {
		t.Fatalf("rename: %q", got)
	}
	// The link is not duplicated inside the edit menu.
	u, out := testUI(a, "2\n1\n1\n0\n0\n0\n0\n")
	_ = u.mainMenu()
	if strings.Contains(out.String(), "View or copy connection link") {
		t.Fatal("edit menu still carries the old link entry")
	}
}

func TestNavigationInvalidInputBackAndQuit(t *testing.T) {
	a := testApp(t)
	// Invalid input never exits or loops forever: it asks again.
	u, out := testUI(a, "9\nabc\n\n")
	if e := u.mainMenu(); e != nil {
		t.Fatal(e)
	}
	if strings.Count(out.String(), "Choose one of the menu numbers") != 2 {
		t.Fatalf("invalid input handling:\n%s", out.String())
	}
	// q quits from any depth; b goes back one level only.
	for _, input := range []string{"q\n", "2\nq\n", "3\nq\n", "6\n1\nq\n", "4\nq\n", "2\nn\nq\n"} {
		u, _ := testUI(a, input)
		if e := u.mainMenu(); e != nil {
			t.Fatalf("%q: %v", input, e)
		}
	}
	u, out = testUI(a, "2\nb\nb\n")
	_ = u.mainMenu()
	if strings.Count(out.String(), "Quick create node") != 2 {
		t.Fatalf("b did not return exactly one level:\n%s", out.String())
	}
	// End of input is a clean exit.
	u, _ = testUI(a, "")
	if e := u.mainMenu(); e != nil {
		t.Fatalf("EOF: %v", e)
	}
}

func TestChineseMenusRenderWithCorrectWidth(t *testing.T) {
	a := testApp(t)
	a.Language = "zh-CN"
	u, out := testUI(a, "0\n")
	_ = u.mainMenu()
	for _, want := range []string{"快速创建节点", "节点管理", "AI 智能分流", "端口转发", "出站代理", "服务与系统", "AI 分流：未启用"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q:\n%s", want, out.String())
		}
	}
	// The heading underline is as wide as the text in terminal columns (2 per Chinese character).
	lines := strings.Split(out.String(), "\n")
	for i, l := range lines {
		if strings.HasPrefix(l, "Rout ") && i+1 < len(lines) {
			if displayWidth(lines[i+1]) != displayWidth(l) {
				t.Fatalf("underline %d vs title %d", displayWidth(lines[i+1]), displayWidth(l))
			}
		}
	}
	if displayWidth("快速创建") != 8 || displayWidth("AI 智能") != 7 || displayWidth(pad("节点", 8)) != 8 {
		t.Fatal("CJK width miscounted")
	}
	// UTF-8 survives untouched in node names.
	u, _ = testUI(a, "东京测试\n1\n\n")
	if e := u.create(); e != nil {
		t.Fatal(e)
	}
	if got := createdNodes(t, a)[0].Name; got != "东京测试-VLESS" {
		t.Fatalf("name %q", got)
	}
	u, detail := testUI(a, "2\n1\n0\n0\n0\n")
	_ = u.mainMenu()
	for _, want := range []string{"东京测试-VLESS", "协议", "连接"} {
		if !strings.Contains(detail.String(), want) {
			t.Fatalf("zh detail misses %q:\n%s", want, detail.String())
		}
	}
}

func TestNarrowTerminalNeverOverflows(t *testing.T) {
	for _, lang := range []string{"en", "zh-CN"} {
		a := testApp(t)
		a.Language = lang
		u, _ := testUI(a, "Edge\n1\n\n")
		_ = u.create()
		for _, width := range []int{40, 30} {
			u, out := testUI(a, "2\n0\n0\n")
			u.termWidth = width
			if e := u.mainMenu(); e != nil {
				t.Fatal(e)
			}
			card := out.String()
			card = card[strings.Index(card, "Edge-VLESS"):]
			if lang == "zh-CN" {
				card = out.String()[strings.Index(out.String(), "Edge-VLESS"):]
			}
			for _, line := range strings.Split(card, "\n") {
				if strings.Contains(line, "·") && strings.HasPrefix(line, "      ") && displayWidth(line) > width {
					t.Fatalf("%s width %d: line too wide (%d): %q", lang, width, displayWidth(line), line)
				}
			}
		}
	}
}

func TestAccentColorOnlyWithColorTerminalAndAlwaysReset(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("TERM", "xterm-256color")
	a := testApp(t)
	u, out := testUI(a, "0\n")
	u.forceColor = true
	_ = u.mainMenu()
	if !strings.Contains(out.String(), "\033["+accent+"m") {
		t.Fatal("blue accent missing")
	}
	for _, line := range strings.Split(out.String(), "\n") {
		if strings.Count(line, "\033[") != strings.Count(line, "\033[0m")*2 {
			t.Fatalf("unterminated color sequence: %q", line)
		}
	}
	plain, pout := testUI(a, "0\n")
	_ = plain.mainMenu()
	if strings.Contains(pout.String(), "\033") {
		t.Fatal("escape codes without a color terminal")
	}
}

// --- AI Smart Routing menu ---------------------------------------------------------

func aiUI(sc *aiScene, input string) (*UI, *strings.Builder) {
	u, out := testUI(sc.a, input)
	u.probeProxy = func(Proxy) (string, error) { return "198.51.100.77", nil }
	sb := &strings.Builder{}
	u.out = writerFunc(func(p []byte) (int, error) { sb.Write(p); return out.Write(p) })
	return u, sb
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

func TestAIMenuFullFlow(t *testing.T) {
	sc := newAIScene(t)
	// Select exit #1 · confirm · bind nodes 1 and 2 · save · confirm · enable · confirm · back
	u, out := aiUI(sc, "3\n1\n\n2\n1 2\ns\n\n1\n\n0\n")
	if e := u.aiMenu(); e != nil {
		t.Fatal(e)
	}
	text := out.String()
	for _, want := range []string{"AI Smart Routing", "Enable AI Smart Routing", "Select inbound nodes", "Select AI exit", "View AI rules", "Test configuration", "Status and diagnostics", "Apply changes", "Outbound IP: 198.51.100.77", "AI exit updated", "Inbound binding saved", "AI Smart Routing enabled"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in\n%s", want, text)
		}
	}
	s, _ := sc.a.Load()
	if !s.AI.Enabled || len(s.AI.BoundInboundIDs) != 2 || s.AI.AIOutboundID != sc.exit.ID {
		t.Fatalf("saved state %+v", s.AI)
	}
	for _, p := range s.Profiles {
		bound := p.ID == sc.reality.ID || p.ID == sc.anytls.ID
		if (p.AIRoute != nil) != bound {
			t.Fatalf("%s routed=%v, want %v", p.Name, p.AIRoute != nil, bound)
		}
	}
	// Status screen reflects persisted state; a second menu run shows "Disable".
	u, out = aiUI(sc, "6\n0\n0\n")
	if e := u.aiMenu(); e != nil {
		t.Fatal(e)
	}
	for _, want := range []string{"Enabled", "Canada (SOCKS5)", "Bound inbounds  2", "US-Reality-01", "Bound", "Unbound", "In sync", "Disable AI Smart Routing"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("status misses %q:\n%s", want, out.String())
		}
	}
}

func TestAIChecklistDefaultsEmptyAndCancelsCleanly(t *testing.T) {
	sc := newAIScene(t)
	_ = sc.a.SetAIExit(sc.exit.ID)
	u, out := aiUI(sc, "2\n0\n0\n")
	if e := u.aiMenu(); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(out.String(), "[x]") {
		t.Fatalf("a node is pre-selected:\n%s", out.String())
	}
	// Saving the untouched (empty) selection changes nothing and binds nothing.
	u, out = aiUI(sc, "2\ns\n0\n")
	if e := u.aiMenu(); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(out.String(), "Binding unchanged") {
		t.Fatalf("empty save:\n%s", out.String())
	}
	// Toggling then cancelling saves nothing; toggling twice removes the mark again.
	u, _ = aiUI(sc, "2\n1\n0\n0\n")
	_ = u.aiMenu()
	if s, _ := sc.a.Load(); s.AI != nil && len(s.AI.BoundInboundIDs) != 0 {
		t.Fatal("cancel saved a selection")
	}
	u, out = aiUI(sc, "2\n1\n1\n0\n0\n")
	_ = u.aiMenu()
	if strings.Count(out.String(), "[x]") != 1 {
		t.Fatalf("second toggle did not clear the mark:\n%s", out.String())
	}
	// Bad numbers are reported and nothing is lost.
	u, out = aiUI(sc, "2\n9\n0\n0\n")
	_ = u.aiMenu()
	if !strings.Contains(out.String(), "Invalid selection") {
		t.Fatalf("bad number:\n%s", out.String())
	}
}

func TestAIEnableWithoutExitIsRefusedClearly(t *testing.T) {
	sc := newAIScene(t)
	u, out := aiUI(sc, "1\n0\n")
	if e := u.aiMenu(); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(out.String(), "Select an AI exit first") {
		t.Fatalf("no explanation:\n%s", out.String())
	}
	if s, _ := sc.a.Load(); s.AI != nil && s.AI.Enabled {
		t.Fatal("enabled without an exit")
	}
}

func TestAIDisableAskesConfirmationAndKeepsSettings(t *testing.T) {
	sc := newAIScene(t)
	_ = sc.a.SetAIExit(sc.exit.ID)
	_ = sc.a.SetAIBindings([]string{sc.reality.ID})
	_ = sc.a.SetAIEnabled(true)
	u, _ := aiUI(sc, "1\nn\n0\n")
	_ = u.aiMenu()
	if s, _ := sc.a.Load(); !s.AI.Enabled {
		t.Fatal("declining the confirmation still disabled AI routing")
	}
	u, out := aiUI(sc, "1\n\n0\n")
	_ = u.aiMenu()
	s, _ := sc.a.Load()
	if s.AI.Enabled || len(s.AI.BoundInboundIDs) != 1 || s.AI.AIOutboundID != sc.exit.ID {
		t.Fatalf("after disable: %+v\n%s", s.AI, out.String())
	}
}

func TestAISelectExitRefusesUnusableAndWarnsWhenUnreachable(t *testing.T) {
	sc := newAIScene(t)
	loop := aiTestExit(t, sc.a, "Loop", "127.0.0.1", sc.reality.Port)
	// Exits are listed in order: Canada (1), Loop (2). The looping one is marked and refused.
	u, out := aiUI(sc, "3\n2\n0\n")
	if e := u.aiMenu(); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(out.String(), "routing loop") || !strings.Contains(out.String(), "cannot be used as the AI exit") {
		t.Fatalf("loop not refused:\n%s", out.String())
	}
	if s, _ := sc.a.Load(); s.AI != nil && s.AI.AIOutboundID == loop.ID {
		t.Fatal("selected a looping exit")
	}
	// An unreachable exit needs an explicit second confirmation (default: no).
	u, out = aiUI(sc, "3\n1\n\n0\n")
	u.probeProxy = func(Proxy) (string, error) { return "", os.ErrDeadlineExceeded }
	_ = u.aiMenu()
	if s, _ := sc.a.Load(); s.AI != nil && s.AI.AIOutboundID != "" {
		t.Fatalf("unreachable exit selected without confirmation:\n%s", out.String())
	}
}

func TestAIRulesTestAndDiagnosticsScreens(t *testing.T) {
	sc := newAIScene(t)
	_ = sc.a.SetAIExit(sc.exit.ID)
	_ = sc.a.SetAIBindings([]string{sc.reality.ID})
	_ = sc.a.SetAIEnabled(true)
	u, out := aiUI(sc, "4\n0\n")
	_ = u.aiMenu()
	for _, want := range []string{"OpenAI / ChatGPT", "Claude / Anthropic", "Gemini", "Google AI Studio", "Hugging Face", "GitHub Copilot", "Cursor", "never whole-site domains", "ECH"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("rules screen misses %q", want)
		}
	}
	// Test configuration + simulation: bound node → AI exit, unbound node → original.
	u, out = aiUI(sc, "5\nclaude.ai\n0\n")
	if e := u.aiMenu(); e != nil {
		t.Fatal(e)
	}
	text := out.String()
	sim := text[strings.Index(text, "Routing simulation"):]
	var reality, other string
	for _, line := range strings.Split(sim, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "US-Reality-01") {
			reality = line
		}
		if strings.HasPrefix(strings.TrimSpace(line), "US-SS-03") {
			other = line
		}
	}
	if !strings.Contains(reality, "AI exit") || !strings.Contains(other, "Original route") {
		t.Fatalf("simulation wrong:\n%s", sim)
	}
	if !strings.Contains(text, "rule simulation") && !strings.Contains(text, "simulates the rules only") {
		t.Fatal("the simulation is not labelled as such")
	}
	// Apply updates the rule set version and reports success.
	u, out = aiUI(sc, "7\n\n0\n")
	_ = u.aiMenu()
	if !strings.Contains(out.String(), "Applied") {
		t.Fatalf("apply:\n%s", out.String())
	}
}

func TestAICommandStatusIsReadOnly(t *testing.T) {
	sc := newAIScene(t)
	_ = sc.a.SetAIExit(sc.exit.ID)
	_ = sc.a.SetAIBindings([]string{sc.reality.ID})
	before, _ := os.ReadFile(filepath.Join(sc.a.Home, "state.json"))
	u, out := testUI(sc.a, "")
	if e := u.aiCommand([]string{"ai", "status"}); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(out.String(), "Bound inbounds") || !strings.Contains(out.String(), "US-Reality-01") {
		t.Fatalf("status output:\n%s", out.String())
	}
	after, _ := os.ReadFile(filepath.Join(sc.a.Home, "state.json"))
	if string(before) != string(after) {
		t.Fatal("status modified the configuration")
	}
	if e := u.aiCommand([]string{"ai", "bogus"}); e == nil {
		t.Fatal("unknown subcommand accepted")
	}
}

func TestEnglishAIMenusHaveNoChinese(t *testing.T) {
	sc := newAIScene(t)
	_ = sc.a.SetAIExit(sc.exit.ID)
	u, out := aiUI(sc, "2\n1\ns\n\n4\n5\nchat.openai.com\n6\n7\n\n1\n\n1\n\n0\n")
	_ = u.aiMenu()
	for _, line := range strings.Split(out.String(), "\n") {
		if hasHan(line) {
			t.Errorf("untranslated: %q", line)
		}
	}
}

func TestDisplayWidthIgnoresColorSequencesAndCountsCJK(t *testing.T) {
	if displayWidth("\033[94m节点\033[0m") != 4 || displayWidth("\033[2mabc\033[0m") != 3 || displayWidth("[x]") != 3 {
		t.Fatal("display width wrong")
	}
}
