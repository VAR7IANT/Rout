package rout

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode"
)

// relayTestApp has a saved server setup so relay flows skip the first-run questions.
func relayTestApp(t *testing.T, setup ServerSetup) *App {
	t.Helper()
	a := testApp(t)
	if e := os.WriteFile(a.enginePath("gost"), []byte("#!/bin/sh\nexit 0\n"), 0755); e != nil {
		t.Fatal(e)
	}
	if e := a.SaveSettings(Settings{Language: "en", Server: &setup}); e != nil {
		t.Fatal(e)
	}
	return a
}
func onlyRelay(t *testing.T, a *App) Profile {
	t.Helper()
	s, e := a.Load()
	if e != nil {
		t.Fatal(e)
	}
	var out []Profile
	for _, p := range s.Profiles {
		if p.Kind == "relay" {
			out = append(out, p)
		}
	}
	if len(out) != 1 {
		t.Fatalf("expected one relay, got %d", len(out))
	}
	return out[0]
}
func hasHan(s string) bool {
	for _, r := range s {
		if unicode.Is(unicode.Han, r) {
			return true
		}
	}
	return false
}

func TestRelayCreateLocalDestination(t *testing.T) {
	a := relayTestApp(t, ServerSetup{PublicHost: "203.0.113.10", Listen: "0.0.0.0", Network: "both"})
	listen, _ := freePort()
	target, _ := freePort()
	// local · override planned entry · listen port · target port · TCP · name · confirm
	// (the saved server address is reused silently; no listen-address or target-host question)
	u, out := testUI(a, "1\nn\n"+itoa(listen)+"\n"+itoa(target)+"\n1\n\n\n")
	if e := u.relayCreate(); e != nil {
		t.Fatal(e, out.String())
	}
	p := onlyRelay(t, a)
	if p.RelayMode != relayLocal || p.Target != "127.0.0.1:"+itoa(target) || p.Protocol != "tcp" {
		t.Fatalf("local relay %+v", p)
	}
	if p.Port != listen || p.PublicPort != listen || p.PublicHost != "203.0.113.10" {
		t.Fatalf("VPS public port must equal listening port: %+v", p)
	}
	text := out.String()
	for _, want := range []string{"Local machine", "203.0.113.10:" + itoa(listen), "127.0.0.1:" + itoa(target), "Client endpoint"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in\n%s", want, text)
		}
	}
	if hasHan(text) {
		t.Fatalf("untranslated text in English relay flow:\n%s", text)
	}
	if st, _ := a.LoadSettings(); st.RelayMode != relayLocal {
		t.Fatal("relay destination type not remembered")
	}
	// The remembered type becomes the default: an empty answer picks "local" again.
	u, out = testUI(a, "\n\n")
	_ = u.relayCreate()
	if !strings.Contains(out.String(), "Local machine") {
		t.Fatal("flow did not run")
	}
}

func TestRelayCreateRemoteNATUDP(t *testing.T) {
	a := relayTestApp(t, ServerSetup{NAT: true, PublicHost: "203.0.113.10", Listen: "0.0.0.0", LocalStart: 20000, LocalEnd: 20019, PublicStart: 40000, Network: "both"})
	internal := 0
	for port := 20000; port <= 20019; port++ {
		if CheckAvailable(Profile{Kind: "relay", Protocol: "both", Listen: "0.0.0.0", Port: port}) == nil {
			internal = port
			break
		}
	}
	if internal == 0 {
		t.Skip("no free port in the test NAT range")
	}
	// remote · planned entry accepted (first free internal port, mapped public port) ·
	// empty host (refused, never filled in) · host · port · UDP · name · confirm (uppercase)
	u, out := testUI(a, "2\n\n\n198.51.100.7\n8443\n2\n\nYES\n")
	if e := u.relayCreate(); e != nil {
		t.Fatal(e, out.String())
	}
	p := onlyRelay(t, a)
	public := 40000 + internal - 20000
	if p.RelayMode != relayRemote || p.Target != "198.51.100.7:8443" || p.Protocol != "udp" || p.Port != internal || p.PublicPort != public || !p.NAT {
		t.Fatalf("remote NAT relay %+v", p)
	}
	if p.Name != "Relay-198.51.100.7" {
		t.Fatal("default name", p.Name)
	}
	text := out.String()
	if !strings.Contains(text, "203.0.113.10:"+itoa(public)) || !strings.Contains(text, "0.0.0.0:"+itoa(internal)) {
		t.Fatalf("diagram must show public and internal ports separately:\n%s", text)
	}
	if !strings.Contains(text, "address is required") {
		t.Fatal("empty remote host was not refused")
	}
	// UDP is never reported as verified.
	if !strings.Contains(text, "UDP has no connection handshake") || strings.Contains(strings.ToLower(text), "udp reachable") {
		t.Fatalf("UDP check wording:\n%s", text)
	}
	if hasHan(text) {
		t.Fatalf("untranslated text:\n%s", text)
	}
}

func TestRelayEntryReusesSavedDefaults(t *testing.T) {
	a := relayTestApp(t, ServerSetup{PublicHost: "203.0.113.10", Listen: "::", Network: "both"})
	// remote · planned entry accepted · host · port · TCP · name · confirm
	u, out := testUI(a, "2\n\n198.51.100.7\n443\n1\n\n\n")
	if e := u.relayCreate(); e != nil {
		t.Fatal(e, out.String())
	}
	p := onlyRelay(t, a)
	if p.Listen != "::" || p.Port == 0 || p.PublicPort != p.Port || p.Target != "198.51.100.7:443" || p.RelayMode != relayRemote {
		t.Fatalf("saved defaults not reused: %+v", p)
	}
	text := out.String()
	if strings.Contains(text, "Listening address on this server") || strings.Contains(text, "Use the saved server settings") {
		t.Fatalf("redundant entry prompts:\n%s", text)
	}
	if !strings.Contains(text, "Use this listening address and port") || !strings.Contains(text, "[::]:"+itoa(p.Port)) {
		t.Fatalf("planned entry not shown:\n%s", text)
	}
	// Editing the entry asks for each value, with the current ones as defaults: keep the
	// address, move the port.
	port, _ := freePort()
	u, out = testUI(a, "2\n"+itoa(port)+"\n\n")
	if e := u.relayEdit(p.ID); e != nil {
		t.Fatal(e, out.String())
	}
	q := onlyRelay(t, a)
	if q.Listen != "::" || q.Port != port || q.PublicPort != port || q.Target != p.Target || q.ID != p.ID {
		t.Fatalf("entry edit: %+v", q)
	}
}

func TestRelayRemoteTCPReachabilityIsReal(t *testing.T) {
	var host string
	for ip := range localIPs() {
		if x := net.ParseIP(ip); x != nil && x.To4() != nil && !x.IsLoopback() {
			host = ip
			break
		}
	}
	if host == "" {
		t.Skip("no non-loopback IPv4 interface")
	}
	l, e := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if e != nil {
		t.Skip(e)
	}
	port := l.Addr().(*net.TCPAddr).Port
	p := Profile{Kind: "relay", RelayMode: relayRemote, Protocol: "tcp", Target: net.JoinHostPort(host, itoa(port))}
	if c := checkRelayDestination(p); len(c) != 1 || !c[0].ok || !strings.Contains(c[0].text, "不代表代理协议可用") {
		t.Fatalf("open port %+v", c)
	}
	l.Close()
	if c := checkRelayDestination(p); len(c) != 1 || c[0].ok || !c[0].warning {
		t.Fatalf("closed port must warn, not pass: %+v", c)
	}
	p.Protocol = "both"
	c := checkRelayDestination(p)
	var udp bool
	for _, x := range c {
		if strings.Contains(x.text, "UDP") {
			udp = true
			if x.ok {
				t.Fatal("UDP claimed as verified")
			}
		}
	}
	if !udp {
		t.Fatal("UDP check missing")
	}
}

func TestRelayLoopDetection(t *testing.T) {
	local := map[string]bool{"10.0.0.5": true}
	base := func(id string, port int, target string) Profile {
		return Profile{ID: id, Name: id, Kind: "relay", Enabled: true, Protocol: "tcp", Listen: "0.0.0.0", Port: port, PublicHost: "203.0.113.10", PublicPort: port, Target: target}
	}
	for _, tc := range []struct {
		name   string
		target string
		loop   bool
	}{
		{"same host, other port", "127.0.0.1:8443", false},
		{"same host via interface IP, other port", "10.0.0.5:8443", false},
		{"own listening port on loopback", "127.0.0.1:1000", true},
		{"own listening port on interface IP", "10.0.0.5:1000", true},
		{"own listening port via 0.0.0.0", "0.0.0.0:1000", true},
		{"own public endpoint", "203.0.113.10:1000", true},
		{"same public IP, other port (not proof of a loop)", "203.0.113.10:2000", false},
		{"remote server", "198.51.100.7:1000", false},
		{"localhost name", "LOCALHOST:1000", true},
	} {
		p := base("a", 1000, tc.target)
		e := relayLoop(State{Profiles: []Profile{p}}, p, local)
		if (e != nil) != tc.loop {
			t.Errorf("%s: loop=%v err=%v", tc.name, tc.loop, e)
		}
	}
	// A TCP relay may target the same port number of a UDP-only service: no loop.
	udp := base("u", 1000, "127.0.0.1:1000")
	udp.Protocol = "udp"
	if e := relayLoop(State{Profiles: []Profile{udp}}, udp, local); e == nil {
		t.Error("udp self loop accepted")
	}
	tcp := base("t", 1000, "127.0.0.1:1000")
	other := base("o", 1000, "198.51.100.7:53")
	other.Protocol = "udp"
	tcp.Target = "127.0.0.1:2000"
	other.Port = 2000
	other.Target = "127.0.0.1:1000"
	if e := relayLoop(State{Profiles: []Profile{tcp, other}}, tcp, local); e != nil {
		t.Error("UDP relay on the target port cannot carry TCP back:", e)
	}
	// Chains of local relays: A -> B -> A loops, A -> B -> node does not.
	a := base("A", 1000, "127.0.0.1:2000")
	b := base("B", 2000, "127.0.0.1:1000")
	e := relayLoop(State{Profiles: []Profile{a, b}}, a, local)
	if e == nil || !strings.Contains(e.Error(), "B") {
		t.Fatal("chain loop", e)
	}
	b.Target = "127.0.0.1:3000"
	if e = relayLoop(State{Profiles: []Profile{a, b}}, a, local); e != nil {
		t.Fatal("chain to a service flagged", e)
	}
	b.Enabled = false
	b.Target = "127.0.0.1:1000"
	if e = relayLoop(State{Profiles: []Profile{a, b}}, a, local); e != nil {
		t.Fatal("disabled relay cannot loop", e)
	}
}

func TestCommitRejectsRelayLoopAndKeepsState(t *testing.T) {
	a := relayTestApp(t, ServerSetup{PublicHost: "203.0.113.10", Listen: "0.0.0.0"})
	port, _ := freePort()
	old, _ := a.Load()
	p := Profile{ID: RandomHex(6), Name: "self", Kind: "relay", Enabled: true, Protocol: "tcp", Listen: "127.0.0.1", Port: port, PublicHost: "203.0.113.10", PublicPort: port, Target: "127.0.0.1:" + itoa(port)}
	if e := a.Commit(old, replace(old, p), false); e == nil {
		t.Fatal("self-forwarding relay committed")
	}
	if s, _ := a.Load(); len(s.Profiles) != 0 {
		t.Fatal("rejected relay was written")
	}
	// Forwarding to another port on the same host is legitimate.
	other, _ := freePort()
	p.Target = "127.0.0.1:" + itoa(other)
	if e := a.Commit(old, replace(old, p), false); e != nil {
		t.Fatal("same-host forwarding rejected:", e)
	}
}

func TestPreferLocalForOwnPublicEndpoint(t *testing.T) {
	a := testApp(t)
	node := fixture(t, "vless")
	node.PublicHost, node.PublicPort, node.Port = "203.0.113.10", 443, 8443
	s := State{Profiles: []Profile{node}}
	p := Profile{ID: "r", Kind: "relay", RelayMode: relayRemote, PublicHost: "203.0.113.10", Target: "203.0.113.10:443"}
	u, out := testUI(a, "y\n")
	u.preferLocal(s, &p)
	if p.RelayMode != relayLocal || p.Target != "127.0.0.1:8443" || p.Protocol != "tcp" || p.TargetURI == "" {
		t.Fatalf("switch to local %+v\n%s", p, out.String())
	}
	// Declining keeps the remote target exactly as typed.
	p = Profile{ID: "r", Kind: "relay", RelayMode: relayRemote, PublicHost: "203.0.113.10", Target: "203.0.113.10:443"}
	u, _ = testUI(a, "N\n")
	u.preferLocal(s, &p)
	if p.RelayMode != relayRemote || p.Target != "203.0.113.10:443" {
		t.Fatal("declined switch changed target")
	}
	// Our own public IP at an unmanaged port only warns: on NAT the IP is shared.
	p = Profile{ID: "r", Kind: "relay", RelayMode: relayRemote, PublicHost: "203.0.113.10", Target: "203.0.113.10:9999"}
	u, out = testUI(a, "")
	u.preferLocal(s, &p)
	if p.RelayMode != relayRemote || p.Target != "203.0.113.10:9999" || !strings.Contains(out.String(), "hairpin") && !strings.Contains(out.String(), "loopback") {
		t.Fatalf("own IP: %+v\n%s", p, out.String())
	}
}

func TestInputNormalization(t *testing.T) {
	for in, want := range map[string]string{"  YES ": "yes", "ＹＥＳ": "yes", "Ｑ": "q", "　ReSeT　": "reset", "１００": "100"} {
		if got := normalizeInput(in); got != want {
			t.Errorf("normalize %q = %q", in, got)
		}
	}
	for in, want := range map[string]bool{"y": true, "Y": true, "yes": true, "YeS": true, "是": true, "ｙ": true, "n": false, "N": false, "No": false, "否": false} {
		if v, ok := parseYesNo(in); !ok || v != want {
			t.Errorf("parseYesNo %q", in)
		}
	}
	for _, in := range []string{"", "maybe", "yy", "1"} {
		if _, ok := parseYesNo(in); ok {
			t.Errorf("parseYesNo accepted %q", in)
		}
	}
	if !matchesKeyword("UNINSTALL", "uninstall") || matchesKeyword("", "") || matchesKeyword("y", "reset") {
		t.Error("matchesKeyword")
	}
	for in, want := range map[string]string{"Q": "quit", "Exit": "quit", "退出": "quit", "B": "back", "返回": "back", "3": ""} {
		if menuShortcut(in) != want {
			t.Errorf("shortcut %q", in)
		}
	}
	a := testApp(t)
	for input, want := range map[string]bool{"\n": true, "N\n": false, "maybe\nYES\n": true} {
		u, _ := testUI(a, input)
		if u.yes("Continue", true) != want {
			t.Errorf("yes(default Y) with %q", input)
		}
	}
	u, _ := testUI(a, "\n")
	if u.yes("Delete", false) {
		t.Error("destructive default must be no")
	}
	u, out := testUI(a, "Reset\n")
	if !u.confirmWord("Wipe", "reset") || !strings.Contains(out.String(), "Type reset to confirm") {
		t.Error("typed confirmation is case-insensitive")
	}
	u, _ = testUI(a, "y\n")
	if u.confirmWord("Wipe", "reset") {
		t.Error("y must not confirm a destructive action")
	}
	// q quits from any menu; numbers still work.
	u, _ = testUI(a, "Q\n")
	if v := u.menu("Menu", []menuItem{item("a", "A")}, "返回"); v != "" || u.err != errQuit {
		t.Fatal("q did not quit", v, u.err)
	}
	u, _ = testUI(a, "b\n")
	if v := u.menu("Menu", []menuItem{item("a", "A")}, "返回"); v != "" || u.err != nil {
		t.Fatal("b did not go back", v, u.err)
	}
	u, _ = testUI(a, "1\n")
	if v := u.menu("Menu", []menuItem{item("a", "A")}, "返回"); v != "a" {
		t.Fatal("numeric choice", v)
	}
	u, _ = testUI(a, "q\n")
	if e := u.mainMenu(); e != nil {
		t.Fatal("quit from main menu is not an error:", e)
	}
}

func TestQuotaInputInGB(t *testing.T) {
	for in, want := range map[string]uint64{
		"": 0, "0": 0, "Unlimited": 0, "NONE": 0, "不限": 0,
		"100": 100_000_000_000, "1.5": 1_500_000_000, " 100 GB ": 100_000_000_000, "100g": 100_000_000_000,
		"500 MB": 500_000_000, "500m": 500_000_000, "2tb": 2_000_000_000_000, "2 T": 2_000_000_000_000, "１００": 100_000_000_000,
	} {
		got, e := parseLimitInput(in)
		if e != nil || got != want {
			t.Errorf("parseLimitInput(%q) = %d, %v", in, got, e)
		}
	}
	for _, in := range []string{"abc", "-5", "1 GiB", "1e3", "5 PB"} {
		if _, e := parseLimitInput(in); e == nil {
			t.Errorf("accepted %q", in)
		}
	}
	for n, want := range map[uint64]string{0: "", 100_000_000_000: "100", 1_500_000_000: "1.5", 500_000_000: "0.5"} {
		if limitInput(n) != want {
			t.Errorf("limitInput(%d) = %q", n, limitInput(n))
		}
	}
	if FormatTraffic(100_000_000_000) != "100 GB" {
		t.Error(FormatTraffic(100_000_000_000))
	}
}

func TestQuotaMenuSetsLimitWithoutResetWord(t *testing.T) {
	a, m, p := trafficTestApp(t)
	snap := m.values[p.ID]
	snap.Up, snap.Down, snap.Consumed = 3_000_000_000, 1_000_000_000, 4_000_000_000
	m.values[p.ID] = snap
	if e := a.TrafficSync(time.Now(), false); e != nil {
		t.Fatal(e)
	}
	// Menu item 1 = limit; "100" means 100 GB. No RESET typing is involved.
	u, out := testUI(a, "1\n100\n")
	s, _ := a.Load()
	if e := u.trafficManage(s.Profiles[0]); e != nil {
		t.Fatal(e, out.String())
	}
	r := record(t, a, p.ID)
	if _, _, total, _ := r.totals(); total != 4_000_000_000 {
		t.Fatal("setting a limit changed usage", total)
	}
	s, _ = a.Load()
	if s.Profiles[0].trafficPolicy().LimitBytes != 100_000_000_000 {
		t.Fatal("limit", s.Profiles[0].trafficPolicy().LimitBytes)
	}
	text := out.String()
	for _, want := range []string{"Upload", "Download", "Total", "Limit", "Next reset", "1 GB = 1,000,000,000 bytes"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "Type reset") || strings.Contains(text, "RESET") {
		t.Fatal("ordinary limit change asked for a reset word")
	}
	u, out = testUI(a, "")
	s, _ = a.Load()
	_ = u.showTraffic(s.Profiles[0])
	if !strings.Contains(out.String(), "Remaining") || !strings.Contains(out.String(), "96 GB") {
		t.Fatalf("remaining:\n%s", out.String())
	}
	// Back to unlimited with 0.
	u, _ = testUI(a, "1\n0\n")
	if e := u.trafficManage(s.Profiles[0]); e != nil {
		t.Fatal(e)
	}
	s, _ = a.Load()
	if s.Profiles[0].trafficPolicy().LimitBytes != 0 {
		t.Fatal("0 must mean unlimited")
	}
}

func TestOutboundAssignmentTouchesOnlyChosenNodes(t *testing.T) {
	a := testApp(t)
	base, _ := a.Load()
	old := base
	var nodes []Profile
	for i, proto := range []string{"vless", "anytls", "ss"} {
		p := fixture(t, proto)
		p.Name = "N" + itoa(i)
		p.Port, _ = freePort()
		p.PublicPort = p.Port
		if proto == "ss" {
			p.Network = "udp"
		}
		nodes = append(nodes, p)
		old = replace(old, p)
	}
	ex := Exit{ID: RandomHex(6), Name: "US", Proxy: Proxy{Protocol: "socks5", Host: "192.0.2.10", Port: 1080, Username: "u", Password: "p"}}
	old.Exits = append(old.Exits, ex)
	if e := a.Commit(base, old, false); e != nil {
		t.Fatal(e)
	}
	old, _ = a.Load()
	u, out := testUI(a, "\n")
	probes := 0
	u.probeProxy = func(Proxy) (string, error) { probes++; return "192.0.2.10", nil }
	// N0 and the UDP-only SS node are chosen; N1 is not.
	if e := u.assignOutbound(old, []Profile{nodes[0], nodes[2]}, ex.ID); e != nil {
		t.Fatal(e, out.String())
	}
	s, _ := a.Load()
	got := map[string]string{}
	for _, p := range s.Profiles {
		got[p.Name] = p.ExitID
	}
	if got["N0"] != ex.ID || got["N1"] != "" || got["N2"] != "" || probes != 1 {
		t.Fatalf("assignment %+v probes=%d\n%s", got, probes, out.String())
	}
	if !strings.Contains(out.String(), "N2") || !strings.Contains(out.String(), "UDP-only") {
		t.Fatalf("UDP-only SS node must be skipped with a reason:\n%s", out.String())
	}
	if s.Exits[0].ID != ex.ID {
		t.Fatal("outbound ID changed")
	}
	// Back to direct connection without a proxy test.
	old = s
	u, _ = testUI(a, "y\n")
	u.probeProxy = func(Proxy) (string, error) { t.Fatal("direct needs no proxy test"); return "", nil }
	if e := u.assignOutbound(old, []Profile{s.Profiles[0]}, ""); e != nil {
		t.Fatal(e)
	}
	s, _ = a.Load()
	for _, p := range s.Profiles {
		if p.ExitID != "" {
			t.Fatal("direct connection not applied", p.Name)
		}
	}
}

func TestLogoRendering(t *testing.T) {
	plain := renderLogo(100, false, false)
	if strings.Contains(plain, "\033") || !strings.Contains(plain, logoLines[0]) || !strings.Contains(plain, "v"+Version) {
		t.Fatalf("plain logo:\n%s", plain)
	}
	// Credit, then version, each on its own line, centered under the 35-column logo.
	lines := strings.Split(strings.TrimSuffix(plain, "\n"), "\n")
	credit, version := lines[len(lines)-2], lines[len(lines)-1]
	if strings.TrimSpace(credit) != "Support by VAR7IANT" || strings.TrimSpace(version) != "v"+Version || strings.Contains(plain, "proxy nodes") {
		t.Fatalf("banner text:\n%s", plain)
	}
	for _, line := range []string{credit, version} {
		text := strings.TrimSpace(line)
		left := len(line) - len(strings.TrimLeft(line, " ")) - 2
		if right := logoWidth - left - len(text); left < 0 || right-left > 1 || left-right > 1 {
			t.Fatalf("not centered under the logo: %q", line)
		}
	}
	rich := renderLogo(100, true, true)
	if !strings.Contains(rich, "\033[38;5;39m") || !strings.Contains(rich, "\033[38;5;26m") {
		t.Fatal("gradient missing")
	}
	basic := renderLogo(100, true, false)
	if strings.Contains(basic, "38;5;") || !strings.Contains(basic, "\033[34m") {
		t.Fatal("16-color fallback")
	}
	// Every line that opens a color closes it, so the terminal is left untouched.
	for _, s := range []string{rich, basic, renderLogo(20, true, true)} {
		for _, line := range strings.Split(strings.TrimSuffix(s, "\n"), "\n") {
			if strings.Contains(line, "\033[") && !strings.HasSuffix(line, "\033[0m") && !strings.Contains(line, "\033[0m ") {
				t.Fatalf("unterminated color: %q", line)
			}
		}
	}
	for _, w := range []int{20, 38} {
		narrow := renderLogo(w, false, false)
		if strings.Count(narrow, "\n") != 1 || narrow != "ROUT v"+Version+"\n" {
			t.Fatalf("narrow %d: %q", w, narrow)
		}
	}
	for _, line := range strings.Split(renderLogo(39, false, false), "\n") {
		if displayWidth(line) > 39 {
			t.Fatalf("logo wider than terminal: %q", line)
		}
	}
}

func TestLogoOncePerSessionAndNeverWhenScripted(t *testing.T) {
	a := testApp(t)
	u, out := testUI(a, "0\n0\n")
	if e := u.mainMenu(); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(out.String(), "██") {
		t.Fatal("logo printed for non-interactive output")
	}
	u, out = testUI(a, "1\n0\n0\n")
	u.forceLogo, u.termWidth = true, 100
	if e := u.mainMenu(); e != nil {
		t.Fatal(e)
	}
	u.showLogo()
	if strings.Count(out.String(), logoLines[0]) != 1 {
		t.Fatal("logo must appear exactly once per session")
	}
}

func TestNoColor(t *testing.T) {
	t.Setenv("TERM", "xterm-256color")
	t.Setenv("NO_COLOR", "")
	if !colorEnabled(true) || colorEnabled(false) {
		t.Fatal("tty color")
	}
	t.Setenv("NO_COLOR", "1")
	if colorEnabled(true) {
		t.Fatal("NO_COLOR ignored")
	}
	a := testApp(t)
	u, out := testUI(a, "0\n")
	u.forceColor, u.forceLogo, u.termWidth = true, true, 100
	_ = u.mainMenu()
	if strings.Contains(out.String(), "\033") {
		t.Fatal("escape codes with NO_COLOR")
	}
	t.Setenv("NO_COLOR", "")
	t.Setenv("TERM", "dumb")
	if colorEnabled(true) {
		t.Fatal("TERM=dumb")
	}
}

func TestEnglishMenusHaveNoChinese(t *testing.T) {
	a := testApp(t)
	p := fixture(t, "vless")
	p.Port, _ = freePort()
	p.PublicPort = p.Port
	s, _ := a.Load()
	if e := a.Commit(s, replace(s, p), false); e != nil {
		t.Fatal(e)
	}
	// main menu: every top-level section entered and left with 0.
	in := ""
	// Quick create is cancelled with 0 at its first question; every other section is left with 0.
	for i := 1; i <= 6; i++ {
		in += itoa(i) + "\n0\n"
	}
	u, out := testUI(a, in+"0\n")
	if e := u.mainMenu(); e != nil {
		t.Fatal(e)
	}
	text := out.String()
	for _, want := range []string{"Quick create node", "Manage nodes", "AI Smart Routing", "Port forwarding", "Outbound proxies", "Service & system", "Traffic", "Settings", "Diagnostics", "Updates", "Quit", "Direct connection"} {
		if !strings.Contains(text, want) {
			t.Errorf("menu misses %q", want)
		}
	}
	if strings.Contains(text, "Exits") || strings.Contains(text, "Exit IP") {
		t.Error("old \"exit\" terminology")
	}
	for _, line := range strings.Split(text, "\n") {
		if hasHan(line) {
			t.Errorf("untranslated: %q", line)
		}
	}
}

func TestOldConfigurationsStayReadable(t *testing.T) {
	a := testApp(t)
	// A v0.2.x state: relays without relay_mode, nodes and exits as before.
	node := fixture(t, "ss")
	node.Port, _ = freePort()
	node.PublicPort = node.Port
	lport, _ := freePort()
	rport, _ := freePort()
	local := Profile{ID: "aaaaaaaaaaaa", Name: "old-local", Kind: "relay", Enabled: true, Protocol: "tcp", Listen: "0.0.0.0", Port: lport, PublicHost: "203.0.113.10", PublicPort: lport, Target: "127.0.0.1:" + itoa(node.Port)}
	remote := Profile{ID: "bbbbbbbbbbbb", Name: "old-remote", Kind: "relay", Enabled: true, Protocol: "both", Listen: "0.0.0.0", Port: rport, PublicHost: "203.0.113.10", PublicPort: rport, Target: "198.51.100.7:443"}
	b, _ := json.Marshal(State{Schema: 1, Profiles: []Profile{node, local, remote}})
	if strings.Contains(string(b), "relay_mode") {
		t.Fatal("empty relay mode must not be written")
	}
	if e := AtomicWrite(filepath.Join(a.Home, "state.json"), b, 0600); e != nil {
		t.Fatal(e)
	}
	if e := AtomicWrite(filepath.Join(a.Home, "settings.json"), []byte(`{"language":"en","server":{"nat":false,"public_host":"203.0.113.10","listen":"0.0.0.0"}}`), 0600); e != nil {
		t.Fatal(e)
	}
	s, e := a.Load()
	if e != nil {
		t.Fatal(e)
	}
	if st, e := a.LoadSettings(); e != nil || st.RelayMode != "" || st.Server == nil {
		t.Fatal("old settings", e)
	}
	got := map[string]string{}
	for _, p := range s.Profiles {
		if e := p.Validate(); e != nil {
			t.Fatal(p.Name, e)
		}
		got[p.Name] = p.relayMode()
	}
	if got["old-local"] != relayLocal || got["old-remote"] != relayRemote {
		t.Fatal("relay mode inference", got)
	}
	// Recording the mode alone is not a runtime change (no restart).
	r, _ := Find(s, "aaaaaaaaaaaa")
	r2 := r
	r2.RelayMode = relayLocal
	if !runtimeEqual(r, r2) {
		t.Fatal("relay mode must not restart a relay")
	}
	r2.RelayMode = "bogus"
	if r2.Validate() == nil {
		t.Fatal("invalid relay mode accepted")
	}
	// The views still render old entries.
	u, out := testUI(a, "1\n0\n0\n")
	if e := u.relays(); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(out.String(), "old-remote") || !strings.Contains(out.String(), "198.51.100.7:443") {
		t.Fatalf("relay view:\n%s", out.String())
	}
}

func TestRelayLinkKeepsSIP002Encoding(t *testing.T) {
	raw := "ss://2022-blake3-aes-128-gcm:" + "AbC%2Bd%2Fe%3D%3D" + "@198.51.100.7:443#x"
	out, e := RewriteURI(raw, "203.0.113.10", 40001, "relay")
	if e != nil {
		t.Fatal(e)
	}
	if !strings.HasPrefix(out, "ss://2022-blake3-aes-128-gcm:AbC%2Bd%2Fe%3D%3D@203.0.113.10:40001") || !strings.HasSuffix(out, "#relay") {
		t.Fatal(out)
	}
	// IPv6 targets and links without userinfo are unaffected.
	if v := withRawUserinfo("vless://u@[2001:db8::1]:443", "vless://u@[2001:db8::2]:8443"); v != "vless://u@[2001:db8::1]:443" {
		t.Fatal(v)
	}
}

// TestIntegrationRelayFlowEndToEnd builds relays with the interactive flow and pushes
// real TCP and UDP traffic through GOST on this machine (loopback and interface
// addresses only; this is simulated networking, not a VPS test).
func TestIntegrationRelayFlowEndToEnd(t *testing.T) {
	a := integrationApp(t)
	a.Language = "en"
	if e := a.SaveSettings(Settings{Language: "en", Server: &ServerSetup{PublicHost: "203.0.113.10", Listen: "127.0.0.1", Network: "both"}}); e != nil {
		t.Fatal(e)
	}
	echo := func(host string) int {
		tl, e := net.Listen("tcp", net.JoinHostPort(host, "0"))
		if e != nil {
			t.Fatal(e)
		}
		port := tl.Addr().(*net.TCPAddr).Port
		ul, e := net.ListenPacket("udp", net.JoinHostPort(host, itoa(port)))
		if e != nil {
			t.Skip("UDP port taken:", e)
		}
		t.Cleanup(func() { tl.Close(); ul.Close() })
		go func() {
			for {
				c, e := tl.Accept()
				if e != nil {
					return
				}
				go func() { defer c.Close(); b := make([]byte, 64); n, _ := c.Read(b); c.Write(b[:n]) }()
			}
		}()
		go func() {
			b := make([]byte, 64)
			for {
				n, addr, e := ul.ReadFrom(b)
				if e != nil {
					return
				}
				ul.WriteTo(b[:n], addr)
			}
		}()
		return port
	}
	through := func(network string, port int) {
		t.Helper()
		c, e := net.DialTimeout(network, net.JoinHostPort("127.0.0.1", itoa(port)), time.Second)
		if e != nil {
			t.Fatal(e)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		c.Write([]byte("ping"))
		b := make([]byte, 4)
		if _, e = c.Read(b); e != nil || string(b) != "ping" {
			t.Fatalf("%s through relay: %v", network, e)
		}
	}
	run := func(input string) Profile {
		t.Helper()
		before, _ := a.Load()
		u, out := testUI(a, input)
		if e := u.relayCreate(); e != nil {
			t.Fatal(e, out.String())
		}
		after, _ := a.Load()
		for _, p := range after.Profiles {
			if _, e := Find(before, p.ID); e != nil {
				c, e := serverConfig(p, a.profileDir(p.ID))
				if e != nil {
					t.Fatal(e)
				}
				startEngine(t, profileSockets(p), a.enginePath("gost"), "-C", configFile(t, c))
				return p
			}
		}
		t.Fatal("no relay created")
		return Profile{}
	}
	// Local machine, TCP+UDP: client -> 127.0.0.1:listen -> 127.0.0.1:service.
	service := echo("127.0.0.1")
	listen, _ := freePort()
	p := run("1\nn\n" + itoa(listen) + "\n" + itoa(service) + "\n3\n\n\n")
	through("tcp", p.Port)
	through("udp", p.Port)
	// Remote relay server (an interface address stands in for the remote host), TCP only.
	var host string
	for ip := range localIPs() {
		if x := net.ParseIP(ip); x != nil && x.To4() != nil && !x.IsLoopback() {
			host = ip
		}
	}
	if host == "" {
		t.Skip("no non-loopback IPv4 interface for the remote case")
	}
	remote := echo(host)
	// Planned entry accepted: saved listening address, automatically chosen port.
	p = run("2\n\n" + host + "\n" + itoa(remote) + "\n1\n\n\n")
	if p.RelayMode != relayRemote || p.Protocol != "tcp" {
		t.Fatalf("%+v", p)
	}
	through("tcp", p.Port)
}

func TestFormatTrafficTruncates(t *testing.T) {
	for n, want := range map[uint64]string{
		100_000_000_000: "100 GB", 38_250_000_000: "38.25 GB", 99_999_999_999: "99.99 GB", 290_000_000: "290 MB",
		1_500_000_000_000: "1.5 TB", 1_000_000: "1 MB", 999_999: "999999 B", 10_200_000_000: "10.2 GB", 18_446_744_073_709_551_615: "18446744.07 TB",
	} {
		if got := FormatTraffic(n); got != want {
			t.Errorf("FormatTraffic(%d) = %q, want %q", n, got, want)
		}
	}
}
