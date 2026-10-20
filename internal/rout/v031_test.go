package rout

import (
	"net"
	"os"
	"reflect"
	"strings"
	"testing"
)

// v0.3.1: regular-VPS defaults, legacy NAT compatibility, port allocation, UI defaults.

// legacyNATApp builds a host as v0.3.0 left it after a NAT setup: saved NAT settings, a NAT
// node and a NAT relay already running from the provider-mapped range.
func legacyNATApp(t *testing.T) (*App, ServerSetup, State) {
	t.Helper()
	start, end := freeRange(t, 6)
	setup := ServerSetup{NAT: true, PublicHost: "198.51.100.1", Listen: "127.0.0.1", LocalStart: start, LocalEnd: end, PublicStart: 40000, Network: "both"}
	a := relayTestApp(t, setup)
	node := fixture(t, "vless")
	node.Name, node.NAT = "Old-NAT-VLESS", true
	node.Port, node.PublicHost, node.PublicPort = start, setup.PublicHost, 40000
	relay := Profile{ID: RandomHex(6), Name: "Old-NAT-Relay", Kind: "relay", Enabled: true, Protocol: "udp", NAT: true, Listen: "127.0.0.1", Port: start + 1, PublicHost: setup.PublicHost, PublicPort: 40001, Target: "198.51.100.7:8443", RelayMode: relayRemote}
	old, _ := a.Load()
	next := replace(replace(old, node), relay)
	if e := a.Commit(old, next, false); e != nil {
		t.Fatal(e)
	}
	s, _ := a.Load()
	return a, setup, s
}
func fileBytes(t *testing.T, path string) []byte {
	t.Helper()
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func TestLegacyNATConfigurationStaysIntactAndWorks(t *testing.T) {
	a, setup, before := legacyNATApp(t)
	settingsBefore := fileBytes(t, a.Home+"/settings.json")
	configs := map[string][]byte{}
	for _, p := range before.Profiles {
		configs[p.ID] = fileBytes(t, a.profileDir(p.ID)+"/config.json")
	}
	// A fresh App instance (the upgraded binary) reads everything unchanged.
	b := &App{Home: a.Home, BinDir: a.BinDir, ServiceMode: "none", Language: "en"}
	again, e := b.Load()
	if e != nil || !reflect.DeepEqual(again, before) {
		t.Fatalf("legacy state changed on load: %v", e)
	}
	if st, e := b.LoadSettings(); e != nil || st.Server == nil || *st.Server != setup {
		t.Fatalf("legacy settings changed: %+v %v", st.Server, e)
	}
	// Creating a node on a legacy NAT host: no NAT question, the saved mapping is followed,
	// existing entries are untouched byte for byte.
	u, out := testUI(b, "New\n1\n\n")
	if e = u.create(); e != nil {
		t.Fatal(e, out.String())
	}
	for _, banned := range []string{"Server type", "Regular VPS", "port range", "Internal port range"} {
		if strings.Contains(out.String(), banned) {
			t.Fatalf("NAT question %q is still asked:\n%s", banned, out)
		}
	}
	if !strings.Contains(out.String(), "legacy NAT") {
		t.Fatalf("legacy mode is not explained:\n%s", out)
	}
	after, _ := b.Load()
	if len(after.Profiles) != len(before.Profiles)+1 {
		t.Fatal("new node missing")
	}
	for _, p := range before.Profiles {
		q, e := Find(after, p.ID)
		if e != nil || !reflect.DeepEqual(p, q) {
			t.Fatalf("existing entry %s changed: %+v", p.Name, q)
		}
		if got := fileBytes(t, b.profileDir(p.ID)+"/config.json"); string(got) != string(configs[p.ID]) {
			t.Fatalf("existing %s config rewritten", p.Name)
		}
	}
	added := after.Profiles[len(after.Profiles)-1]
	if !added.NAT || added.Port < setup.LocalStart || added.Port > setup.LocalEnd || added.PublicPort != setup.PublicStart+added.Port-setup.LocalStart {
		t.Fatalf("new entry does not follow the saved NAT mapping: %+v", added)
	}
	if st, _ := b.LoadSettings(); *st.Server != setup {
		t.Fatalf("creating a node rewrote the saved NAT mapping: %+v", st.Server)
	}
	_ = settingsBefore
}

func TestLegacyNATEntriesStillAskForTheProviderMapping(t *testing.T) {
	a, setup, s := legacyNATApp(t)
	var node, relay Profile
	for _, p := range s.Profiles {
		if p.Kind == "relay" {
			relay = p
		} else {
			node = p
		}
	}
	// Node: moving the listening port asks for the provider's public port, defaulting to the saved mapping.
	moved := setup.LocalStart + 3
	u, out := testUI(a, "1\n"+itoa(moved)+"\n\n")
	if e := u.nodeAddress(&node); e != nil {
		t.Fatal(e, out.String())
	}
	if node.Port != moved || node.PublicPort != setup.PublicStart+3 || !node.NAT {
		t.Fatalf("%+v", node)
	}
	if !strings.Contains(out.String(), "Public port the provider maps to internal port") {
		t.Fatalf("mapping not asked:\n%s", out)
	}
	// Relay: editing the entry keeps its mapped public port and asks no NAT/VPS question.
	u, out = testUI(a, "2\n\n\n\n\n")
	if e := u.relayEdit(relay.ID); e != nil {
		t.Fatal(e, out.String())
	}
	got, _ := Find(mustLoad(t, a), relay.ID)
	if got.PublicPort != relay.PublicPort || got.Port != relay.Port || !got.NAT {
		t.Fatalf("relay mapping rewritten: %+v", got)
	}
	if strings.Contains(out.String(), "Server type") {
		t.Fatal("server type asked while editing")
	}
}
func mustLoad(t *testing.T, a *App) State {
	t.Helper()
	s, e := a.Load()
	if e != nil {
		t.Fatal(e)
	}
	return s
}

func TestSwitchingLegacyHostToRegularVPSIsExplicitAndTouchesNothingElse(t *testing.T) {
	a, setup, before := legacyNATApp(t)
	// Declined: nothing changes.
	u, out := testUI(a, "3\nn\n")
	if e := u.serverMenu(); e != nil {
		t.Fatal(e, out.String())
	}
	if st, _ := a.LoadSettings(); st.Server == nil || *st.Server != setup {
		t.Fatal("settings changed without confirmation")
	}
	for _, want := range []string{"Switch to a regular VPS", "not rewritten"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q:\n%s", want, out)
		}
	}
	// Confirmed: new entries become regular; existing NAT entries are not migrated.
	u, out = testUI(a, "3\ny\n")
	u.detectAddrs = func() Addresses { return Addresses{IPv4: v4Addr} }
	u.caps = func() listenCaps { return listenCaps{V4: true} }
	if e := u.serverMenu(); e != nil {
		t.Fatal(e, out.String())
	}
	st, _ := a.LoadSettings()
	if st.Server == nil || st.Server.NAT || st.Server.PublicHost != v4Addr || st.Server.LocalStart != 0 || st.Server.PublicStart != 0 {
		t.Fatalf("not a clean regular setup: %+v", st.Server)
	}
	if after := mustLoad(t, a); !reflect.DeepEqual(after, before) {
		t.Fatal("switching the default migrated or rewrote existing NAT entries")
	}
	u, out = testUI(a, "Reg\n1\n\n")
	if e := u.create(); e != nil {
		t.Fatal(e, out.String())
	}
	final := mustLoad(t, a)
	n := final.Profiles[len(final.Profiles)-1]
	if n.NAT || n.PublicPort != n.Port || n.PublicHost != v4Addr {
		t.Fatalf("%+v", n)
	}
}

func TestNoNATOrServerTypeQuestionOnARegularHost(t *testing.T) {
	a := relayTestApp(t, ServerSetup{PublicHost: v4Addr, Listen: "0.0.0.0", Network: "both"})
	os.Remove(a.Home + "/settings.json") // fresh install: nothing saved, nothing to reuse
	if e := a.SaveSettings(Settings{Language: "en"}); e != nil {
		t.Fatal(e)
	}
	var all strings.Builder
	run := func(input string, fn func(*UI) error) {
		t.Helper()
		u, out := testUI(a, input)
		u.detectAddrs = func() Addresses { return Addresses{IPv4: v4Addr} }
		u.caps = func() listenCaps { return listenCaps{V4: true} }
		if e := fn(u); e != nil {
			t.Fatal(e, out.String())
		}
		all.WriteString(out.String())
	}
	run("Fresh\n1 2\n\n", func(u *UI) error { return u.create() })
	run("2\n\n198.51.100.7\n443\n1\n\n\n", func(u *UI) error { return u.relayCreate() })
	run("2\n1\n0\n", func(u *UI) error { return u.settings() }) // Settings → Server address → detect again
	text := all.String()
	for _, banned := range []string{"NAT", "Regular VPS", "port range", "mapping", "Server type"} {
		if strings.Contains(text, banned) {
			t.Fatalf("%q appears in the normal flow:\n%s", banned, text)
		}
	}
	if hasHan(text) {
		t.Fatalf("untranslated text:\n%s", text)
	}
	for _, p := range mustLoad(t, a).Profiles {
		if p.NAT || p.PublicPort != p.Port {
			t.Fatalf("regular VPS behavior expected: %+v", p)
		}
	}
}

func TestExistingRegularEntriesSurviveCreation(t *testing.T) {
	a := relayTestApp(t, ServerSetup{PublicHost: v4Addr, Listen: "0.0.0.0", Network: "both"})
	u, out := testUI(a, "First\n1 3\n\n")
	if e := u.create(); e != nil {
		t.Fatal(e, out.String())
	}
	u, out = testUI(a, "2\n\n198.51.100.7\n443\n1\n\n\n")
	if e := u.relayCreate(); e != nil {
		t.Fatal(e, out.String())
	}
	before := mustLoad(t, a)
	configs := map[string][]byte{}
	for _, p := range before.Profiles {
		configs[p.ID] = fileBytes(t, a.profileDir(p.ID)+"/config.json")
	}
	u, out = testUI(a, "Second\n1\n\n")
	if e := u.create(); e != nil {
		t.Fatal(e, out.String())
	}
	after := mustLoad(t, a)
	for _, p := range before.Profiles {
		q, _ := Find(after, p.ID)
		if !reflect.DeepEqual(p, q) || string(fileBytes(t, a.profileDir(p.ID)+"/config.json")) != string(configs[p.ID]) {
			t.Fatalf("existing %s %s was modified", p.Kind, p.Name)
		}
	}
	if len(after.Profiles) != len(before.Profiles)+1 {
		t.Fatal("expected exactly one new node")
	}
}

// ---- Ports ----

func TestAutomaticPortsAreFreeDistinctAndPublicEqualsListening(t *testing.T) {
	setup := ServerSetup{PublicHost: v4Addr, Listen: "127.0.0.1", Network: "both"}
	s := State{Schema: 1}
	seen := map[int]bool{}
	for _, protocol := range []string{"vless", "anytls", "ss", "hy2", "tuic"} {
		p := fixture(t, protocol)
		p, e := PlanPort(p, setup, s)
		if e != nil {
			t.Fatal(e)
		}
		if p.PublicPort != p.Port || p.NAT || seen[p.Port] {
			t.Fatalf("%s: %+v", protocol, p)
		}
		if e = CheckAvailable(p); e != nil {
			t.Fatalf("planned port is not free: %v", e)
		}
		seen[p.Port] = true
		s = replace(s, p)
	}
}

func busyPorts(t *testing.T) (tcpOnly, udpOnly int) {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { l.Close() })
	tcpOnly = l.Addr().(*net.TCPAddr).Port
	pc, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { pc.Close() })
	return tcpOnly, pc.LocalAddr().(*net.UDPAddr).Port
}

func TestPortConflictsCoverTCPAndUDPSeparately(t *testing.T) {
	tcpBusy, udpBusy := busyPorts(t)
	with := func(protocol string, port int) Profile {
		p := fixture(t, protocol)
		p.Port, p.PublicPort = port, port
		return p
	}
	// A bound TCP port blocks TCP users only; a bound UDP port blocks UDP users only; SS needs both.
	for _, tc := range []struct {
		protocol string
		port     int
		blocked  bool
	}{
		{"vless", tcpBusy, true}, {"hy2", tcpBusy, false}, {"ss", tcpBusy, true},
		{"hy2", udpBusy, true}, {"vless", udpBusy, false}, {"ss", udpBusy, true}, {"tuic", udpBusy, true},
	} {
		if e := portConflict(State{Schema: 1}, with(tc.protocol, tc.port)); (e != nil) != tc.blocked {
			t.Errorf("%s on port %d: blocked=%v err=%v", tc.protocol, tc.port, tc.blocked, e)
		}
	}
	// Entries in the saved state reserve their networks the same way.
	free, _ := freePort()
	existing := with("vless", free) // TCP only
	s := replace(State{Schema: 1}, existing)
	if e := portConflict(s, with("hy2", free)); e != nil {
		t.Errorf("UDP user refused on a TCP-only port: %v", e)
	}
	for _, protocol := range []string{"vless", "ss", "anytls"} {
		if e := portConflict(s, with(protocol, free)); e == nil || !strings.Contains(e.Error(), "TCP") {
			t.Errorf("%s accepted on a port already used for TCP: %v", protocol, e)
		}
	}
	relay := Profile{ID: RandomHex(6), Name: "R", Kind: "relay", Protocol: "both", Listen: "127.0.0.1", Port: free}
	if e := portConflict(s, relay); e == nil {
		t.Error("TCP+UDP relay accepted on a port with a TCP node")
	}
}

func TestCreateFlowManualPortSelectionIsCheckedBeforeSaving(t *testing.T) {
	tcpBusy, _ := busyPorts(t)
	free, _ := freePort()
	a := relayTestApp(t, ServerSetup{PublicHost: v4Addr, Listen: "127.0.0.1", Network: "both"})
	// name · VLESS · change ports · busy TCP port (refused) · free port · create
	u, out := testUI(a, "Manual\n1\n2\n"+itoa(tcpBusy)+"\n"+itoa(free)+"\n1\n")
	if e := u.create(); e != nil {
		t.Fatal(e, out.String())
	}
	if !strings.Contains(out.String(), "TCP port "+itoa(tcpBusy)+" is unavailable") {
		t.Fatalf("busy port was not refused:\n%s", out)
	}
	p := mustLoad(t, a).Profiles[0]
	if p.Port != free || p.PublicPort != free {
		t.Fatalf("%+v", p)
	}
}

func TestCreateFlowDefaultsAndCancel(t *testing.T) {
	a := relayTestApp(t, ServerSetup{PublicHost: v4Addr, Listen: "127.0.0.1", Network: "both"})
	// Enter-only: default name, VLESS, create.
	u, out := testUI(a, "\n\n\n")
	if e := u.create(); e != nil {
		t.Fatal(e, out.String())
	}
	s := mustLoad(t, a)
	if len(s.Profiles) != 1 || s.Profiles[0].Name != "Rout-VLESS" || s.Profiles[0].Protocol != "vless" {
		t.Fatalf("%+v", s.Profiles)
	}
	for _, banned := range []string{"Manually specify", "Generate credentials automatically", "Server type", "Public IP or domain"} {
		if strings.Contains(out.String(), banned) {
			t.Fatalf("%q is asked in the default flow:\n%s", banned, out)
		}
	}
	// The summary lists the generated port and address; the default answer creates.
	if !strings.Contains(out.String(), "Rout-VLESS") || !strings.Contains(out.String(), v4Addr+":") || !strings.Contains(out.String(), "vless://") {
		t.Fatalf("summary or link missing:\n%s", out)
	}
	// Cancel changes nothing.
	before := mustLoad(t, a)
	u, out = testUI(a, "Nope\n1 2\n4\n")
	if e := u.create(); e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(before, mustLoad(t, a)) || !strings.Contains(out.String(), "Cancelled") {
		t.Fatal("cancel changed state")
	}
}

func TestCreateFailureRollsBackEverything(t *testing.T) {
	a := relayTestApp(t, ServerSetup{PublicHost: v4Addr, Listen: "127.0.0.1", Network: "both"})
	// sing-box rejects the generated configuration: nothing may remain.
	if e := os.WriteFile(a.enginePath("sing-box"), []byte("#!/bin/sh\nexit 1\n"), 0755); e != nil {
		t.Fatal(e)
	}
	u, out := testUI(a, "Bad\n1 3\n\n")
	if e := u.create(); e == nil {
		t.Fatal("create succeeded although the engine rejected the configuration")
	}
	if s := mustLoad(t, a); len(s.Profiles) != 0 {
		t.Fatalf("partial state saved: %+v", s.Profiles)
	}
	if _, e := os.Stat(a.Home + "/profiles"); !os.IsNotExist(e) {
		t.Fatalf("runtime files left behind:\n%s", out)
	}
}
