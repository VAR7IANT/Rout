package rout

import (
	"path/filepath"
	"strings"
	"testing"
)

// Visual-layer tests: main menu grouping and badges, the Enter guard, short hints,
// breadcrumbs, status dots, usage bars and the adaptive banner. Menu numbers and every
// command stay as documented.

// mainMenuLayout returns the main menu as an ordered list of "G:<group>" and "<n>:<label>".
func mainMenuLayout(out string) []string {
	var layout []string
	started := false
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		f := strings.Fields(t)
		switch {
		case strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "   ") && len(f) == 1 && (t == "Nodes" || t == "Network" || t == "Services" || t == "节点" || t == "网络" || t == "服务"):
			layout = append(layout, "G:"+t)
			started = true
		case started && len(f) >= 2 && len(f[0]) == 1 && f[0] >= "1" && f[0] <= "9":
			layout = append(layout, f[0])
		}
	}
	return layout
}

func TestMainMenuGroupsKeepTheDocumentedNumbers(t *testing.T) {
	for _, lang := range []string{"en", "zh-CN"} {
		a := testApp(t)
		a.Language = lang
		u, out := testUI(a, "0\n")
		_ = u.mainMenu()
		got := strings.Join(mainMenuLayout(out.String()), " ")
		want := "G:Nodes 1 2 G:Network 3 4 5 G:Services 6 7"
		if lang == "zh-CN" {
			want = "G:节点 1 2 G:网络 3 4 5 G:服务 6 7"
		}
		if got != want {
			t.Fatalf("%s layout %q, want %q\n%s", lang, got, want, out.String())
		}
	}
}

func TestMainMenuBadgesShowLiveCounts(t *testing.T) {
	sc := newAIScene(t)
	line := func(out, label string) string {
		for _, l := range strings.Split(out, "\n") {
			if strings.Contains(l, label) {
				return strings.TrimRight(l, " ")
			}
		}
		return ""
	}
	u, out := testUI(sc.a, "0\n")
	_ = u.mainMenu()
	if l := line(out.String(), "Manage nodes"); !strings.HasSuffix(l, "  4") {
		t.Fatalf("node badge: %q", l)
	}
	if l := line(out.String(), "AI Smart Routing"); !strings.HasSuffix(l, "  Disabled") {
		t.Fatalf("AI badge: %q", l)
	}
	if l := line(out.String(), "Port forwarding"); strings.TrimSpace(strings.SplitN(l, "forwarding", 2)[1]) != "" {
		t.Fatalf("an empty category must not show a badge: %q", l)
	}
	_ = sc.a.SetAIExit(sc.exit.ID)
	_ = sc.a.SetAIBindings([]string{sc.reality.ID})
	_ = sc.a.SetAIEnabled(true)
	sc.a.Language = "zh-CN"
	u, out = testUI(sc.a, "0\n")
	_ = u.mainMenu()
	if l := line(out.String(), "节点管理"); !strings.HasSuffix(l, "  4 个") {
		t.Fatalf("zh node badge: %q", l)
	}
	if l := line(out.String(), "AI 智能分流"); !strings.HasSuffix(l, "  已启用") {
		t.Fatalf("zh AI badge: %q", l)
	}
	// Narrow terminals keep the badge on the line, separated by two spaces.
	u, out = testUI(sc.a, "0\n")
	u.termWidth = 30
	_ = u.mainMenu()
	if l := line(out.String(), "节点管理"); !strings.HasSuffix(l, "节点管理  4 个") {
		t.Fatalf("narrow badge: %q", l)
	}
}

func TestEnterDoesNotQuitTheMainMenu(t *testing.T) {
	a := testApp(t)
	u, out := testUI(a, "\n\n  \n0\n")
	if e := u.mainMenu(); e != nil {
		t.Fatal(e)
	}
	if n := strings.Count(out.String(), "Quick create node"); n != 1 {
		// An empty answer asks again without redrawing the whole menu.
		t.Fatalf("menu drawn %d times:\n%s", n, out.String())
	}
	if strings.Contains(out.String(), "Choose one of the menu numbers") {
		t.Fatal("an empty answer must not be reported as an error")
	}
	// The other menus still go back on Enter.
	u, out = testUI(a, "6\n\n0\n")
	if e := u.mainMenu(); e != nil {
		t.Fatal(e)
	}
	if n := strings.Count(out.String(), "Quick create node"); n != 2 {
		t.Fatalf("Enter did not go back from a sub-menu:\n%s", out.String())
	}
}

func TestNavigationHintIsFullOnceThenShort(t *testing.T) {
	a := testApp(t)
	full := Translate("en", "输入编号 · 0 或 q 退出 Rout")
	fullBack := Translate("en", "输入编号 · 0 或 b 返回 · q 退出 Rout")
	short := Translate("en", "0 返回 · q 退出")
	shortTop := Translate("en", "0 或 q 退出")
	u, out := testUI(a, "6\n0\n0\n")
	_ = u.mainMenu()
	text := out.String()
	if strings.Count(text, full) != 1 || strings.Contains(text, fullBack) {
		t.Fatalf("full hint must appear once:\n%s", text)
	}
	if strings.Count(text, short) != 1 || strings.Count(text, shortTop) != 1 {
		t.Fatalf("short hints missing:\n%s", text)
	}
	// A session that starts in a sub-menu gets the full "back" hint first.
	u, out = testUI(a, "0\n")
	_ = u.system()
	if !strings.Contains(out.String(), fullBack) {
		t.Fatalf("first hint:\n%s", out.String())
	}
}

func TestHeadingsShowTheBreadcrumb(t *testing.T) {
	a := testApp(t)
	u, out := testUI(a, "6\n1\n0\n0\n0\n")
	_ = u.mainMenu()
	if !strings.Contains(out.String(), "Rout › Service & system › Services\n") {
		t.Fatalf("breadcrumb:\n%s", out.String())
	}
	// The path is popped again: back at the top level there is no stale trail.
	if strings.Count(out.String(), "Rout 0.") != 2 {
		t.Fatalf("main heading after returning:\n%s", out.String())
	}
	a.Language = "zh-CN"
	u, out = testUI(a, "6\n4\n0\n0\n0\n")
	_ = u.mainMenu()
	if !strings.Contains(out.String(), "Rout › 服务与系统 › 设置\n") {
		t.Fatalf("zh breadcrumb:\n%s", out.String())
	}
}

func TestBreadcrumbNamesTheNodeAndStaysWithinNarrowWidth(t *testing.T) {
	a := testApp(t)
	u, _ := testUI(a, "Edge\n1\n\n")
	_ = u.create()
	u, out := testUI(a, "2\n1\n0\n0\n0\n")
	_ = u.mainMenu()
	if !strings.Contains(out.String(), "Rout › Manage nodes › Edge-VLESS\n") {
		t.Fatalf("node breadcrumb:\n%s", out.String())
	}
	u, out = testUI(a, "2\n1\n1\n0\n0\n0\n0\n")
	_ = u.mainMenu()
	if !strings.Contains(out.String(), "Rout › Manage nodes › Edge-VLESS › Edit\n") {
		t.Fatalf("edit breadcrumb:\n%s", out.String())
	}
	for _, width := range []int{30, 24} {
		u, out = testUI(a, "2\n1\n1\n0\n0\n0\n0\n")
		u.termWidth = width
		_ = u.mainMenu()
		lines := strings.Split(out.String(), "\n")
		for i, l := range lines {
			if strings.Contains(l, "›") && displayWidth(l) > width-1 && !strings.HasPrefix(l, "  ") {
				t.Fatalf("width %d: breadcrumb too wide (%d): %q", width, displayWidth(l), l)
			}
			if strings.HasPrefix(l, "─") && displayWidth(l) > width-1 {
				t.Fatalf("width %d: rule too wide (line %d)", width, i)
			}
		}
		if !strings.Contains(out.String(), "… › ") {
			t.Fatalf("width %d: long path was not shortened:\n%s", width, out.String())
		}
	}
}

func TestStatusDotsAndUsageBarOnlyOnFancyTerminals(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("TERM", "xterm-256color")
	a := testApp(t)
	u, _ := testUI(a, "")
	u.forceColor = true
	on := Profile{Enabled: true}
	off := Profile{Enabled: false}
	if got := u.nodeStatusStyled(off); !strings.Contains(got, "○") || !strings.Contains(got, u.nodeStatus(off)) {
		t.Fatalf("disabled status %q", got)
	}
	if got := u.nodeStatusStyled(on); !strings.Contains(got, "●") || !strings.Contains(got, u.nodeStatus(on)) {
		t.Fatalf("enabled status %q", got)
	}
	u.termWidth = 80
	if bar := u.usageBar(31, 50); !strings.Contains(bar, "▓▓▓▓▓") || !strings.Contains(bar, "░░░") || !strings.HasSuffix(bar, " 62%") {
		t.Fatalf("bar %q", bar)
	}
	for used, color := range map[uint64]string{10: colorOK, 36: colorWarn, 49: colorErr} {
		if bar := u.usageBar(used, 50); !strings.Contains(bar, "\033["+color+"m") {
			t.Fatalf("used %d: expected color %s in %q", used, color, bar)
		}
	}
	if bar := u.usageBar(1, 1000000); !strings.Contains(bar, "▓") {
		t.Fatalf("a little usage must still show: %q", bar)
	}
	if bar := u.usageBar(2000, 1000); !strings.HasSuffix(bar, " 100%") {
		t.Fatalf("over-limit bar %q", bar)
	}
	u.termWidth = 40
	if u.usageBar(31, 50) != "" {
		t.Fatal("no bar on a very narrow terminal")
	}
	// Plain output (captured, piped, NO_COLOR) has no glyphs or escape codes.
	plain, _ := testUI(a, "")
	plain.termWidth = 80
	if plain.dot(levelOK) != "" || plain.usageBar(31, 50) != "" || plain.nodeStatusStyled(on) != plain.nodeStatus(on) {
		t.Fatal("plain output must not change")
	}
	t.Setenv("NO_COLOR", "1")
	u.forceColor = true
	if u.dot(levelOK) != "" {
		t.Fatal("NO_COLOR with a captured writer must stay plain")
	}
}

func TestAlertsStayInTheStatusPanelAndAreCapped(t *testing.T) {
	a := testApp(t)
	u, _ := testUI(a, "Edge\n1 3 4\n\n")
	if e := u.create(); e != nil {
		t.Fatal(e)
	}
	s, _ := a.Load()
	s.Schema = 2
	s.Profiles[0].Traffic = &TrafficPolicy{LimitBytes: 1000, BillingDay: 1}
	data, _ := JSON(s)
	if e := AtomicWrite(filepath.Join(a.Home, "state.json"), data, 0600); e != nil {
		t.Fatal(e)
	}
	warning := Translate("en", "流量监控未启用：有限额节点保持暂停，请运行 rout traffic install")
	u, out := testUI(a, "x\n\n0\n")
	if e := u.mainMenu(); e != nil {
		t.Fatal(e)
	}
	// Redrawn on every main-menu visit instead of printed once before the loop.
	if n := strings.Count(out.String(), warning); n != 1 {
		t.Fatalf("alert printed %d times for one drawing:\n%s", n, out.String())
	}
	u, out = testUI(a, "6\n0\n0\n")
	_ = u.mainMenu()
	if n := strings.Count(out.String(), warning); n != 2 {
		t.Fatalf("alert not repeated after returning to the main menu (%d):\n%s", n, out.String())
	}
	// More than maxPanelAlerts conditions collapse into one line.
	u, out = testUI(a, "")
	var list []alert
	for i := 0; i < maxPanelAlerts+2; i++ {
		list = append(list, alert{levelWarn, "problem " + itoa(i)})
	}
	list = append(list[:1], append([]alert{{levelErr, "broken"}}, list[1:]...)...)
	u.printAlerts(list)
	text := out.String()
	if strings.Count(text, "\n") != maxPanelAlerts+1 || !strings.Contains(text, "✗ broken") || !strings.Contains(text, "! 3 more notices; run rout doctor to see them") {
		t.Fatalf("alert cap:\n%s", text)
	}
}

func TestCompactBannerWhenTheTerminalIsShort(t *testing.T) {
	a := testApp(t)
	tall, tallOut := testUI(a, "0\n")
	tall.forceLogo, tall.termWidth, tall.termHeight = true, 100, 50
	_ = tall.mainMenu()
	short, shortOut := testUI(a, "0\n")
	short.forceLogo, short.termWidth, short.termHeight = true, 100, 24
	_ = short.mainMenu()
	if !strings.Contains(tallOut.String(), "██████╗") {
		t.Fatalf("tall terminals keep the big logo:\n%s", tallOut.String())
	}
	if strings.Contains(shortOut.String(), "██████╗") {
		t.Fatalf("short terminals must get the compact banner:\n%s", shortOut.String())
	}
	if !strings.Contains(shortOut.String(), "ROUT v"+Version) || !strings.Contains(shortOut.String(), "Support by VAR7IANT") {
		t.Fatalf("compact banner lost the title or credit:\n%s", shortOut.String())
	}
	// Unknown height (captured output, no window) never changes the banner.
	unknown, unknownOut := testUI(a, "0\n")
	unknown.forceLogo, unknown.termWidth = true, 100
	_ = unknown.mainMenu()
	if !strings.Contains(unknownOut.String(), "██████╗") {
		t.Fatal("unknown height must keep the big logo")
	}
}
