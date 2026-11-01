package rout

import (
	"strings"
	"testing"
	"time"
)

// Scripted tests of the relay screens: inbound mode, outbound policy, transport
// capability, link recognition, migration of legacy relays. The host's address families are
// injected (caps / routes), so every host type is covered on any machine.

func dualStackHost(u *UI) *UI {
	u.caps = func() listenCaps { return listenCaps{V4: true, V6: true, DualStack: true} }
	u.routes = func() familyRoutes { return familyRoutes{V4: true, V6: true} }
	return u
}

// fakeBinds stands in for the real port probe, recording every socket the flows ask about,
// so the IPv6 and dual-stack flows run on a host that has no IPv6.
func fakeBinds(t *testing.T) *[]listenSpec {
	t.Helper()
	var asked []listenSpec
	old := nativeBindProbe
	nativeBindProbe = func(p Profile) error {
		asked = append(asked, p.bindSpecs()...)
		return nil
	}
	t.Cleanup(func() { nativeBindProbe = old })
	return &asked
}

func fastDestinationChecks(t *testing.T) {
	t.Helper()
	old := relayDialTimeout
	relayDialTimeout = 150 * time.Millisecond
	t.Cleanup(func() { relayDialTimeout = old })
}

const testVLESS = "vless://11111111-1111-4111-8111-111111111111@198.51.100.7:44275?encryption=none&flow=xtls-rprx-vision&fp=chrome&pbk=PUBLICKEY&security=reality&sid=ab12&sni=addons.mozilla.org&type=tcp#orig"

func TestInboundMenuOffersOnlyWhatTheHostCanServe(t *testing.T) {
	setup := ServerSetup{PublicHost: v4Addr, IPv4: v4Addr, IPv6: v6Addr, Listen: "::"}
	for _, tc := range []struct {
		name  string
		caps  listenCaps
		input string
		mode  string
		host  string
		menu  bool
	}{
		{"IPv4-only host", listenCaps{V4: true}, "", inIPv4, v4Addr, false},
		{"IPv6-only host", listenCaps{V6: true}, "", inIPv6, v6Addr, false},
		{"dual host, Enter = IPv4", listenCaps{V4: true, V6: true}, "\n", inIPv4, v4Addr, true},
		{"dual host, IPv4", listenCaps{V4: true, V6: true}, "1\n", inIPv4, v4Addr, true},
		{"dual host, IPv6", listenCaps{V4: true, V6: true}, "2\n", inIPv6, v6Addr, true},
		{"dual host, dual stack", listenCaps{V4: true, V6: true}, "3\n", inDual, v4Addr, true},
		{"dual wildcard, IPv6", listenCaps{V4: true, V6: true, DualStack: true}, "2\n", inIPv6, v6Addr, true},
		{"IPv4/IPv6 sockets conflict on one port", listenCaps{V4: true, V6: true, SplitConflict: true}, "2\n", inIPv6, v6Addr, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u, out := testUI(testApp(t), tc.input)
			u.caps = func() listenCaps { return tc.caps }
			var p Profile
			got, e := u.relayInbound(&p, setup, "")
			if e != nil {
				t.Fatal(e)
			}
			if p.InboundMode != tc.mode || p.Engine != engineNative || got.PublicHost != tc.host || p.PublicHost != tc.host {
				t.Fatalf("mode=%q engine=%q public=%q\n%s", p.InboundMode, p.Engine, got.PublicHost, out.String())
			}
			if want := listenAddrFor(tc.mode, ""); p.Listen != want {
				t.Fatalf("listen %q, want %q", p.Listen, want)
			}
			if (strings.Contains(out.String(), "Inbound network (")) != tc.menu {
				t.Fatalf("menu shown=%v, want %v:\n%s", !tc.menu, tc.menu, out.String())
			}
			if tc.caps.SplitConflict && strings.Contains(out.String(), "Dual stack") {
				t.Fatal("dual stack offered although an IPv4 and an IPv6 socket cannot share a port")
			}
			noHan(t, out.String())
			// The saved server defaults are not modified by a per-relay choice.
			if setup.PublicHost != v4Addr || setup.Listen != "::" {
				t.Fatal("saved defaults were mutated")
			}
			// The result is a valid profile.
			p.ID, p.Name, p.Kind, p.Enabled, p.Protocol, p.Port, p.PublicPort, p.Target = RandomHex(6), "r", "relay", true, "tcp", 7400, 7400, "198.51.100.7:443"
			if e = p.Validate(); e != nil {
				t.Fatalf("invalid profile: %v", e)
			}
		})
	}
}

func TestInboundMenuDefaultFollowsTheLastChoice(t *testing.T) {
	u, out := testUI(testApp(t), "\n")
	u.caps = func() listenCaps { return listenCaps{V4: true, V6: true} }
	var p Profile
	if _, e := u.relayInbound(&p, ServerSetup{PublicHost: v4Addr, IPv4: v4Addr, IPv6: v6Addr}, inIPv6); e != nil {
		t.Fatal(e)
	}
	if p.InboundMode != inIPv6 || !strings.Contains(out.String(), "Choose [2]") {
		t.Fatalf("the remembered choice is not the default:\n%s", out.String())
	}
}

func TestInboundPublicAddressIsAskedOnlyWhenNoMatchingOneIsKnown(t *testing.T) {
	// IPv6 chosen, only an IPv4 public address is known: the user must supply an IPv6 one;
	// a mismatching answer is refused and asked again.
	u, out := testUI(testApp(t), "2001:db8::77\n")
	u.caps = func() listenCaps { return listenCaps{V6: true} }
	var p Profile
	got, e := u.relayInbound(&p, ServerSetup{PublicHost: v4Addr, IPv4: v4Addr}, "")
	if e != nil || got.PublicHost != "2001:db8::77" || p.PublicHost != "2001:db8::77" {
		t.Fatalf("%+v %v\n%s", got, e, out.String())
	}
	u, out = testUI(testApp(t), "198.51.100.1\nfe80::1\nrelay.example.net\n")
	u.caps = func() listenCaps { return listenCaps{V6: true} }
	p = Profile{}
	got, e = u.relayInbound(&p, ServerSetup{PublicHost: v4Addr, IPv4: v4Addr}, "")
	if e != nil || got.PublicHost != "relay.example.net" {
		t.Fatalf("%+v %v\n%s", got, e, out.String())
	}
	if strings.Count(out.String(), "does not match the selected listening mode") != 2 {
		t.Fatalf("mismatching answers were not refused:\n%s", out.String())
	}
}

func TestOutboundMenuAndPolicy(t *testing.T) {
	keys := func(items []menuItem) string {
		var k []string
		for _, it := range items {
			k = append(k, it.key)
		}
		return strings.Join(k, ",")
	}
	both := familyRoutes{V4: true, V6: true}
	items, ok := outboundMenu(both, "relay-target.example:443")
	if !ok || keys(items) != "ipv4_first,ipv6_first,ipv4_only,ipv6_only,auto" {
		t.Fatalf("%v", keys(items))
	}
	// A literal address can never satisfy the opposite "only" policy: it is not offered.
	if items, _ = outboundMenu(both, "198.51.100.7:443"); keys(items) != "ipv4_first,ipv6_first,ipv4_only,auto" {
		t.Fatalf("IPv4 literal: %v", keys(items))
	}
	if items, _ = outboundMenu(both, "[2001:db8::7]:443"); keys(items) != "ipv4_first,ipv6_first,ipv6_only,auto" {
		t.Fatalf("IPv6 literal: %v", keys(items))
	}
	for _, r := range []familyRoutes{{V4: true}, {V6: true}, {}} {
		if _, ok := outboundMenu(r, "relay-target.example:443"); ok {
			t.Errorf("a menu was offered on a host with routes %+v", r)
		}
	}
	for input, want := range map[string]string{"\n": outIPv4First, "1\n": outIPv4First, "2\n": outIPv6First, "3\n": outIPv4Only, "4\n": outIPv6Only, "5\n": outAuto} {
		u, _ := testUI(testApp(t), input)
		u.routes = func() familyRoutes { return both }
		p := Profile{Kind: "relay", RelayMode: relayRemote, Target: "relay-target.example:443"}
		u.relayOutbound(&p, "")
		if p.OutboundPolicy != want {
			t.Errorf("input %q: %q, want %q", input, p.OutboundPolicy, want)
		}
	}
	// No choice on a single-family host or for a local destination: "auto", said plainly.
	u, out := testUI(testApp(t), "")
	p := Profile{Kind: "relay", RelayMode: relayRemote, Target: "relay-target.example:443"}
	u.relayOutbound(&p, "")
	if p.OutboundPolicy != outAuto || !strings.Contains(out.String(), "Outbound policy: auto (this machine only has an IPv4 route)") {
		t.Fatalf("%q\n%s", p.OutboundPolicy, out.String())
	}
	u, out = testUI(testApp(t), "")
	u.routes = func() familyRoutes { return both }
	local := Profile{Kind: "relay", RelayMode: relayLocal, Target: "127.0.0.1:8443"}
	u.relayOutbound(&local, "")
	if local.OutboundPolicy != outAuto || out.Len() != 0 {
		t.Fatalf("a local relay was asked about outbound families: %q", out.String())
	}
}

func TestRelayCreateNativeIPv4DefaultOnADualStackHost(t *testing.T) {
	fastDestinationChecks(t)
	a := relayTestApp(t, ServerSetup{PublicHost: "203.0.113.10", IPv4: "203.0.113.10", IPv6: v6Addr, Listen: "::", Network: "both"})
	// remote · inbound (Enter = IPv4) · planned entry · host · port · TCP · outbound (Enter =
	// IPv4 first) · name · confirm
	u, out := testUI(a, "2\n\n\n198.51.100.7\n443\n1\n\n\n\n")
	dualStackHost(u)
	if e := u.relayCreate(); e != nil {
		t.Fatal(e, out.String())
	}
	p := onlyRelay(t, a)
	if p.Engine != engineNative || p.InboundMode != inIPv4 || p.Listen != "0.0.0.0" || p.OutboundPolicy != outIPv4First || p.PublicHost != "203.0.113.10" || p.Target != "198.51.100.7:443" {
		t.Fatalf("%+v", p)
	}
	if len(p.bindSpecs()) != 1 || p.bindSpecs()[0].Network != "tcp4" {
		t.Fatalf("an IPv4 relay must bind IPv4 only, got %v", p.bindSpecs())
	}
	text := out.String()
	for _, want := range []string{"Inbound network", "Outbound policy", "IPv4 first", "Inbound IPv4 · Outbound IPv4 first"} {
		if !strings.Contains(text, want) {
			t.Errorf("output misses %q:\n%s", want, text)
		}
	}
	noHan(t, text)
	if st, _ := a.LoadSettings(); st.RelayInbound != inIPv4 || st.RelayOutbound != outIPv4First {
		t.Fatalf("choices not remembered: %+v", st)
	}
	// The saved server defaults still carry the original wildcard; the relay did not change them.
	if st, _ := a.LoadSettings(); st.Server == nil || st.Server.Listen != "::" {
		t.Fatalf("server defaults changed: %+v", st.Server)
	}
}

func TestRelayCreateOnDualStackHostUsesTwoSockets(t *testing.T) {
	asked := fakeBinds(t)
	fastDestinationChecks(t)
	a := relayTestApp(t, ServerSetup{PublicHost: "203.0.113.10", IPv4: "203.0.113.10", IPv6: v6Addr, Listen: "0.0.0.0", Network: "both"})
	// remote · dual stack (3) · planned entry · link (identifies VLESS/TCP) · outbound IPv6 first · name · confirm
	u, out := testUI(a, "2\n3\n\n"+testVLESS+"\n2\n\n\n")
	dualStackHost(u)
	if e := u.relayCreate(); e != nil {
		t.Fatal(e, out.String())
	}
	p := onlyRelay(t, a)
	if p.InboundMode != inDual || p.Listen != "::" || p.OutboundPolicy != outIPv6First || p.PublicHost != "203.0.113.10" {
		t.Fatalf("%+v", p)
	}
	if got := len(p.bindSpecs()); got != 2 {
		t.Fatalf("dual stack must be two sockets, got %v", p.bindSpecs())
	}
	// The port was checked on BOTH families before saving.
	var fams string
	for _, s := range *asked {
		fams += s.Network[3:] + " "
	}
	if !strings.Contains(fams, "4") || !strings.Contains(fams, "6") {
		t.Fatalf("the free-port check covered %q only", fams)
	}
	text := out.String()
	if !strings.Contains(text, "The same relay at its other address: IPv6") || !strings.Contains(text, "["+v6Addr+"]:"+itoa(p.PublicPort)) {
		t.Fatalf("the alternate IPv6 link is missing:\n%s", text)
	}
	// Both links keep the original authentication and TLS parameters.
	for _, want := range []string{"11111111-1111-4111-8111-111111111111@", "pbk=PUBLICKEY", "sid=ab12", "sni=addons.mozilla.org", "flow=xtls-rprx-vision"} {
		if strings.Count(text, want) < 2 {
			t.Errorf("%q should appear in both links:\n%s", want, text)
		}
	}
	noHan(t, text)
}

func TestRelayCreateIPv6OnlyEntryToAnIPv4Destination(t *testing.T) {
	asked := fakeBinds(t)
	fastDestinationChecks(t)
	a := relayTestApp(t, ServerSetup{PublicHost: "203.0.113.10", IPv4: "203.0.113.10", IPv6: v6Addr, Listen: "0.0.0.0", Network: "both"})
	// IPv6 inbound (2), IPv4-only outbound (the IPv4-literal destination removes "IPv6 only": 1 ipv4_first, 2 ipv6_first, 3 ipv4_only).
	u, out := testUI(a, "2\n2\n\n"+testVLESS+"\n3\n\n\n")
	dualStackHost(u)
	if e := u.relayCreate(); e != nil {
		t.Fatal(e, out.String())
	}
	p := onlyRelay(t, a)
	if p.InboundMode != inIPv6 || p.OutboundPolicy != outIPv4Only || p.PublicHost != v6Addr || !strings.HasPrefix(p.Target, "198.51.100.7:") {
		t.Fatalf("%+v", p)
	}
	if specs := p.bindSpecs(); len(specs) != 1 || specs[0].Network != "tcp6" {
		t.Fatalf("%v", specs)
	}
	for _, s := range *asked {
		if s.Network[3] == '4' {
			t.Fatalf("an IPv6-only relay checked an IPv4 socket: %v", *asked)
		}
	}
	// The client link points at the IPv6 entry and keeps the IPv4 destination's identity.
	uri, e := p.URI()
	if e != nil || !strings.Contains(uri, "@["+v6Addr+"]:"+itoa(p.PublicPort)) || !strings.Contains(uri, "pbk=PUBLICKEY") {
		t.Fatalf("%s %v", uri, e)
	}
}

func TestVLESSLinkIsRecognizedAndAnswersTheTransportQuestion(t *testing.T) {
	fastDestinationChecks(t)
	a := relayTestApp(t, ServerSetup{PublicHost: "203.0.113.10", Listen: "0.0.0.0", Network: "both"})
	// remote · planned entry · link · (no transport question) · name · confirm
	u, out := testUI(a, "2\n\n"+testVLESS+"\n\n\n")
	if e := u.relayCreate(); e != nil {
		t.Fatal(e, out.String())
	}
	text := out.String()
	if !strings.Contains(text, "Recognized: TCP / VLESS Reality (destination 198.51.100.7:44275)") {
		t.Fatalf("recognition line missing:\n%s", text)
	}
	if strings.Contains(text, "Transport (must match") || !strings.Contains(text, "Transport: TCP (determined by the node link)") {
		t.Fatalf("the transport was asked although the link settles it:\n%s", text)
	}
	if p := onlyRelay(t, a); p.Protocol != "tcp" || p.TargetURI != testVLESS {
		t.Fatalf("%+v", p)
	}
}

func TestTCPOnlyTargetRefusesUDPProtocols(t *testing.T) {
	fastDestinationChecks(t)
	const hy2 = "hysteria2://secret@198.51.100.9:27001?sni=x.example#h"
	const wantTCPOnly = "The destination currently supports TCP only. Hysteria2 needs UDP transport and cannot be used through a plain TCP port relay. Choose a UDP relay, or use a compatible tunnel that can encapsulate UDP"

	// Hysteria2 link, user says the NAT maps TCP only.
	a := relayTestApp(t, ServerSetup{PublicHost: "203.0.113.10", Listen: "0.0.0.0", Network: "both"})
	u, out := testUI(a, "2\n\n"+hy2+"\n2\n")
	e := u.relayCreate()
	if e == nil || a.Error(e) != wantTCPOnly {
		t.Fatalf("got %v\n%s", e, out.String())
	}
	if s := mustLoad(t, a); len(s.Profiles) != 0 {
		t.Fatal("a relay that cannot work was stored")
	}
	noHan(t, out.String())

	// Same link, UDP declared available: the transport is taken from the link (UDP) and saved.
	a = relayTestApp(t, ServerSetup{PublicHost: "203.0.113.10", Listen: "0.0.0.0", Network: "both"})
	u, out = testUI(a, "2\n\n"+hy2+"\n1\n\n\n")
	if e = u.relayCreate(); e != nil {
		t.Fatal(e, out.String())
	}
	if p := onlyRelay(t, a); p.Protocol != "udp" || p.TargetNetwork != "" {
		t.Fatalf("%+v", p)
	}

	// A manual host:port with UDP chosen, on a TCP-only NAT.
	a = relayTestApp(t, ServerSetup{PublicHost: "203.0.113.10", Listen: "0.0.0.0", Network: "both"})
	u, out = testUI(a, "2\n\n198.51.100.9\n27001\n2\n2\n")
	e = u.relayCreate()
	if e == nil || !strings.Contains(a.Error(e), "TCP only") {
		t.Fatalf("manual UDP target on a TCP-only NAT: %v\n%s", e, out.String())
	}

	// TCP+UDP chosen with a TCP-only destination: the same refusal (a relay is all or nothing).
	a = relayTestApp(t, ServerSetup{PublicHost: "203.0.113.10", Listen: "0.0.0.0", Network: "both"})
	u, _ = testUI(a, "2\n\n198.51.100.9\n8388\n3\n2\n")
	if e = u.relayCreate(); e == nil {
		t.Fatal("TCP+UDP accepted for a TCP-only destination")
	}

	// A plain TCP relay to a TCP-only NAT is exactly what such a NAT supports.
	a = relayTestApp(t, ServerSetup{PublicHost: "203.0.113.10", Listen: "0.0.0.0", Network: "both"})
	u, out = testUI(a, "2\n\n198.51.100.9\n27001\n1\n\n\n")
	if e = u.relayCreate(); e != nil {
		t.Fatal(e, out.String())
	}
}

func TestLinkAndTransportMismatchesExplainThemselves(t *testing.T) {
	hy2 := Profile{ID: "aaaaaaaaaaaa", Name: "r", Kind: "relay", Enabled: true, Protocol: "tcp", Listen: "0.0.0.0", Port: 7500, PublicHost: v4Addr, PublicPort: 7500, Target: "198.51.100.9:27001", TargetURI: "hysteria2://pw@198.51.100.9:27001?sni=x.example#h"}
	e := hy2.Validate()
	if e == nil || !strings.Contains(e.Error(), "Hysteria2 需要 UDP 传输，TCP 中转无法使用") {
		t.Fatalf("TCP relay for a Hysteria2 link: %v", e)
	}
	tuic := hy2
	tuic.TargetURI = "tuic://11111111-1111-4111-8111-111111111111:pw@198.51.100.9:27001?sni=x.example#t"
	if e = tuic.Validate(); e == nil || !strings.Contains(e.Error(), "TUIC 需要 UDP 传输") {
		t.Fatalf("TCP relay for a TUIC link: %v", e)
	}
	vless := hy2
	vless.Protocol, vless.Target, vless.TargetURI = "udp", "198.51.100.7:44275", testVLESS
	if e = vless.Validate(); e == nil || !strings.Contains(e.Error(), "VLESS 使用 TCP") {
		t.Fatalf("UDP relay for a VLESS link: %v", e)
	}
	// Correct pairings are valid.
	hy2.Protocol = "udp"
	if e = hy2.Validate(); e != nil {
		t.Fatal(e)
	}
	// Declared TCP-only target with a UDP relay is refused on stored state as well.
	hy2.TargetNetwork = "tcp"
	if e = hy2.Validate(); e == nil || !strings.Contains(e.Error(), "目前目标仅支持 TCP") {
		t.Fatalf("declared TCP-only: %v", e)
	}
}

func TestLegacyRelayMigratesOnlyWhenTheUserChangesItsNetwork(t *testing.T) {
	fastDestinationChecks(t)
	a := relayTestApp(t, ServerSetup{PublicHost: "203.0.113.10", Listen: "0.0.0.0", Network: "both"})
	legacy := legacyRelayFixture(t)
	legacy.Target, legacy.TargetURI = "198.51.100.7:44275", testVLESS
	s := mustLoad(t, a)
	if e := a.Commit(s, replace(s, legacy), false); e != nil {
		t.Fatal(e)
	}

	// Renaming and disabling/enabling leave the engine alone.
	u, out := testUI(a, "4\nNewName\n")
	if e := u.relayEdit(legacy.ID); e != nil {
		t.Fatal(e, out.String())
	}
	u, _ = testUI(a, "5\n")
	if e := u.relayEdit(legacy.ID); e != nil {
		t.Fatal(e)
	}
	u, _ = testUI(a, "5\n")
	if e := u.relayEdit(legacy.ID); e != nil {
		t.Fatal(e)
	}
	got, _ := Find(mustLoad(t, a), legacy.ID)
	if got.Name != "NewName" || got.Engine != "" || got.InboundMode != "" || got.OutboundPolicy != "" || !got.Enabled {
		t.Fatalf("a rename or toggle migrated the relay: %+v", got)
	}

	// Changing the network moves it to the native forwarder, keeping everything else.
	u, out = testUI(a, "6\ny\n")
	if e := u.relayEdit(legacy.ID); e != nil {
		t.Fatal(e, out.String())
	}
	after, _ := Find(mustLoad(t, a), legacy.ID)
	if after.Engine != engineNative || after.InboundMode != inIPv4 || after.Listen != "0.0.0.0" {
		t.Fatalf("not migrated: %+v", after)
	}
	if after.Port != got.Port || after.PublicPort != got.PublicPort || after.PublicHost != got.PublicHost || after.Target != got.Target || after.TargetURI != got.TargetURI || after.Name != got.Name || after.Protocol != got.Protocol {
		t.Fatalf("migration changed more than the engine:\nbefore %+v\nafter  %+v", got, after)
	}
	old, _ := got.URI()
	now, _ := after.URI()
	if old != now {
		t.Fatalf("the share link changed:\n%s\n%s", old, now)
	}
	if !strings.Contains(out.String(), "legacy GOST engine") {
		t.Fatalf("the user was not told:\n%s", out.String())
	}
	noHan(t, out.String())
}

func TestRelayListShowsTheNetworkOfEveryRelay(t *testing.T) {
	a := relayTestApp(t, ServerSetup{PublicHost: "203.0.113.10", Listen: "0.0.0.0", Network: "both"})
	s := mustLoad(t, a)
	legacy := legacyRelayFixture(t)
	native := nativeFixture(t, inIPv4, outIPv6First, "198.51.100.8:443")
	native.PublicHost, native.Name = "203.0.113.10", "native"
	s = replace(replace(s, legacy), native)
	if e := a.Commit(mustLoad(t, a), s, false); e != nil {
		t.Fatal(e)
	}
	u, out := testUI(a, "")
	for i, p := range relaysOf(mustLoad(t, a)) {
		u.relayCard(i+1, p)
	}
	text := out.String()
	for _, want := range []string{"Inbound IPv4 · Outbound IPv6 first", "Legacy engine (GOST)"} {
		if !strings.Contains(text, want) {
			t.Errorf("list misses %q:\n%s", want, text)
		}
	}
	noHan(t, text)
}
