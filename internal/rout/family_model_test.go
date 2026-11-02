package rout

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

// Unit tests for the address-family model, configuration generation, persistence and
// backward compatibility. No network and no engines are involved.

func nativeFixture(t *testing.T, mode, policy, target string) Profile {
	t.Helper()
	port, _ := freePort()
	p := nativeRelayProfile(mode, policy, target, port)
	p.ID = RandomHex(6)
	p.Name = "native-" + mode
	return p
}

func legacyRelayFixture(t *testing.T) Profile {
	t.Helper()
	port, _ := freePort()
	return Profile{ID: RandomHex(6), Name: "legacy", Kind: "relay", Enabled: true, Protocol: "tcp", Listen: "0.0.0.0", Port: port, PublicHost: "203.0.113.10", PublicPort: port, Target: "198.51.100.7:443", RelayMode: relayRemote}
}

func TestLegacyProfilesSerializeWithoutNewFields(t *testing.T) {
	// A profile that never saw the new settings must serialize exactly as before: an older
	// Rout reading a state file written after an upgrade sees nothing it does not know.
	b, e := json.Marshal(legacyRelayFixture(t))
	if e != nil {
		t.Fatal(e)
	}
	for _, field := range []string{"inbound_mode", "outbound_policy", "engine", "target_network", "link"} {
		if strings.Contains(string(b), field) {
			t.Errorf("legacy relay serialized %q: %s", field, b)
		}
	}
	node := fixture(t, "vless")
	nb, _ := json.Marshal(node)
	if strings.Contains(string(nb), "inbound_mode") || strings.Contains(string(nb), "engine") {
		t.Errorf("legacy node serialized new fields: %s", nb)
	}
	ex, _ := json.Marshal(Exit{ID: "aaaaaaaaaaaa", Name: "x", Proxy: Proxy{Protocol: "socks5", Host: "h.example", Port: 1080, Username: "u", Password: "p"}})
	if strings.Contains(string(ex), "kind") || strings.Contains(string(ex), "remote_network") || strings.Contains(string(ex), "link") {
		t.Errorf("legacy exit serialized new fields: %s", ex)
	}
}

func TestLegacyRelayConfigurationIsUnchanged(t *testing.T) {
	// The GOST configuration of a relay that does not opt in is byte-for-byte what earlier
	// versions generated: services, addresses, handlers and forwarder.
	p := legacyRelayFixture(t)
	p.Protocol = "both"
	c, e := serverConfig(p, t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(c)
	want := `{"log":{"format":"json","level":"warn"},"services":[` +
		`{"addr":"0.0.0.0:` + itoa(p.Port) + `","forwarder":{"nodes":[{"addr":"198.51.100.7:443","name":"target"}]},"handler":{"type":"tcp"},"listener":{"type":"tcp"},"name":"` + p.ID + `-tcp"},` +
		`{"addr":"0.0.0.0:` + itoa(p.Port) + `","forwarder":{"nodes":[{"addr":"198.51.100.7:443","name":"target"}]},"handler":{"type":"udp"},"listener":{"metadata":{"keepAlive":true,"ttl":"60s"},"type":"udp"},"name":"` + p.ID + `-udp"}]}`
	if string(b) != want {
		t.Fatalf("legacy relay configuration changed\n got %s\nwant %s", b, want)
	}
	a := &App{Home: t.TempDir(), BinDir: t.TempDir()}
	if a.engineName(p) != "gost" {
		t.Fatal("legacy relay must stay on GOST")
	}
	exe, args := a.serviceCommand(p)
	if exe != a.enginePath("gost") || !reflect.DeepEqual(args, []string{"-C", filepath.Join(a.profileDir(p.ID), "config.json")}) {
		t.Fatalf("legacy command %s %v", exe, args)
	}
	// Nodes: sing-box, unchanged command line.
	n := fixture(t, "ss")
	exe, args = a.serviceCommand(n)
	if exe != a.enginePath("sing-box") || len(args) != 3 || args[0] != "run" {
		t.Fatalf("node command %s %v", exe, args)
	}
}

func TestNativeRelayServiceDefinition(t *testing.T) {
	a := &App{Home: "/etc/rout", BinDir: "/opt/rout/bin"}
	p := nativeFixture(t, inDual, outAuto, "198.51.100.7:443")
	if a.engineName(p) != "" {
		t.Fatal("a native relay needs no downloaded engine")
	}
	exe, args := a.serviceCommand(p)
	if exe != "/opt/rout/bin/rout-relay-v1" || len(args) != 2 || args[0] != "relay-serve" || args[1] != "/etc/rout/profiles/"+p.ID+"/config.json" {
		t.Fatalf("native command %s %v", exe, args)
	}
	unit := a.systemdUnit(p)
	for _, want := range []string{"ExecStart=\"/opt/rout/bin/rout-relay-v1\" \"relay-serve\"", "NoNewPrivileges=true", "ProtectSystem=strict", "CapabilityBoundingSet=CAP_NET_BIND_SERVICE\n", "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK"} {
		if !strings.Contains(unit, want) {
			t.Errorf("unit misses %q:\n%s", want, unit)
		}
	}
	if strings.Contains(unit, "CAP_NET_ADMIN") {
		t.Error("a relay must not receive CAP_NET_ADMIN")
	}
	if rc := a.openrcScript(p); !strings.Contains(rc, "rout-relay-v1") || !strings.Contains(rc, "relay-serve") {
		t.Errorf("openrc script:\n%s", rc)
	}
}

func TestNativeRelayConfigurationFile(t *testing.T) {
	for _, tc := range []struct {
		mode, protocol string
		want           []nativeListen
	}{
		{inIPv4, "tcp", []nativeListen{{"tcp4", "0.0.0.0:%d"}}},
		{inIPv6, "tcp", []nativeListen{{"tcp6", "[::]:%d"}}},
		{inDual, "both", []nativeListen{{"tcp4", "0.0.0.0:%d"}, {"tcp6", "[::]:%d"}, {"udp4", "0.0.0.0:%d"}, {"udp6", "[::]:%d"}}},
	} {
		p := nativeFixture(t, tc.mode, outIPv6First, "relay-target.example:443")
		p.Protocol = tc.protocol
		dir := t.TempDir()
		if e := writeProfileIn(p, dir); e != nil {
			t.Fatal(e)
		}
		b, _ := os.ReadFile(filepath.Join(dir, "config.json"))
		var cfg nativeRelayConfig
		if e := json.Unmarshal(b, &cfg); e != nil {
			t.Fatal(e)
		}
		if e := cfg.validate(); e != nil {
			t.Fatal(e)
		}
		for i := range tc.want {
			tc.want[i].Addr = strings.Replace(tc.want[i].Addr, "%d", itoa(p.Port), 1)
		}
		if !reflect.DeepEqual(cfg.Listen, tc.want) || cfg.Target != "relay-target.example:443" || cfg.Outbound != outIPv6First || cfg.ID != p.ID {
			t.Errorf("%s: %+v", tc.mode, cfg)
		}
	}
	// The file holds no credentials at all: a relay only forwards bytes.
	p := nativeFixture(t, inIPv4, outAuto, "198.51.100.7:443")
	p.TargetURI = "vless://11111111-1111-4111-8111-111111111111@198.51.100.7:443?security=reality&pbk=k&sid=ab&sni=x.example#r"
	c, _ := serverConfig(p, t.TempDir())
	b, _ := json.Marshal(c)
	if strings.Contains(string(b), "11111111") || strings.Contains(string(b), "pbk") {
		t.Fatalf("relay configuration carries node credentials: %s", b)
	}
}

func TestNativeConfigRejectsMalformedFiles(t *testing.T) {
	good := nativeRelayConfig{Version: 1, Engine: "rout-relay", ID: "x", Listen: []nativeListen{{"tcp4", "0.0.0.0:1"}}, Target: "h.example:1", Outbound: outAuto}
	if e := good.validate(); e != nil {
		t.Fatal(e)
	}
	for name, f := range map[string]func(*nativeRelayConfig){
		"version":  func(c *nativeRelayConfig) { c.Version = 2 },
		"engine":   func(c *nativeRelayConfig) { c.Engine = "gost" },
		"no sock":  func(c *nativeRelayConfig) { c.Listen = nil },
		"network":  func(c *nativeRelayConfig) { c.Listen = []nativeListen{{"tcp", "0.0.0.0:1"}} },
		"address":  func(c *nativeRelayConfig) { c.Listen = []nativeListen{{"tcp4", "nope"}} },
		"target":   func(c *nativeRelayConfig) { c.Target = "no-port" },
		"policy":   func(c *nativeRelayConfig) { c.Outbound = "fastest" },
		"bad port": func(c *nativeRelayConfig) { c.Target = "h.example:70000" },
	} {
		c := good
		f(&c)
		if c.validate() == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestStateRoundTripKeepsFamilySettings(t *testing.T) {
	a := testApp(t)
	s, _ := a.Load()
	p := nativeFixture(t, inIPv4, outIPv4Only, "relay-target.example:443")
	p.Protocol = "both"
	next := replace(s, p)
	if e := a.Commit(s, next, false); e != nil {
		t.Fatal(e)
	}
	loaded, e := a.Load()
	if e != nil {
		t.Fatal(e)
	}
	got, e := Find(loaded, p.ID)
	if e != nil {
		t.Fatal(e)
	}
	if got.InboundMode != inIPv4 || got.OutboundPolicy != outIPv4Only || got.Engine != engineNative || got.Listen != "0.0.0.0" {
		t.Fatalf("settings lost on reload: %+v", got)
	}
	// "Restart recovery": a fresh App on the same directory reads the same thing, and the
	// generated service definition is identical.
	b := &App{Home: a.Home, BinDir: a.BinDir, ServiceMode: "none"}
	again, e := b.Load()
	if e != nil {
		t.Fatal(e)
	}
	got2, _ := Find(again, p.ID)
	if !reflect.DeepEqual(got, got2) || a.systemdUnit(got) != b.systemdUnit(got2) {
		t.Fatal("restart changed the relay")
	}
	cfgA, _ := os.ReadFile(filepath.Join(a.profileDir(p.ID), "config.json"))
	var cfg nativeRelayConfig
	if e = json.Unmarshal(cfgA, &cfg); e != nil || cfg.Outbound != outIPv4Only || len(cfg.Listen) != 2 {
		t.Fatalf("written config %s %v", cfgA, e)
	}
}

func TestOldStateWithRelaysAndNodesStillLoadsAndIsUntouched(t *testing.T) {
	a := testApp(t)
	node := fixture(t, "ss")
	node.Port, _ = freePort()
	node.PublicPort = node.Port
	legacy := legacyRelayFixture(t)
	old := State{Schema: 1, Profiles: []Profile{node, legacy}}
	b, _ := json.Marshal(old)
	if e := AtomicWrite(filepath.Join(a.Home, "state.json"), b, 0600); e != nil {
		t.Fatal(e)
	}
	s, e := a.Load()
	if e != nil {
		t.Fatal(e)
	}
	r, _ := Find(s, legacy.ID)
	if r.nativeRelay() || r.inboundMode() != inIPv4 || r.outboundPolicy() != outAuto {
		t.Fatalf("legacy relay reinterpreted: %+v", r)
	}
	// Re-applying everything rewrites the same GOST configuration.
	before, _ := serverConfig(legacy, a.profileDir(legacy.ID))
	after, _ := serverConfig(r, a.profileDir(r.ID))
	if !reflect.DeepEqual(before, after) {
		t.Fatal("loading changed the legacy relay's configuration")
	}
}

func TestRelayShareLinksAreIdenticalForLegacyAndNativeRelays(t *testing.T) {
	// Switching engine must never change what clients are given.
	uri := "vless://11111111-1111-4111-8111-111111111111@ft.example.net:44275?encryption=none&flow=xtls-rprx-vision&fp=chrome&pbk=PUBLICKEY&security=reality&sid=ab12&sni=addons.mozilla.org&type=tcp#orig"
	legacy := legacyRelayFixture(t)
	legacy.Target, legacy.TargetURI = "ft.example.net:44275", uri
	native := legacy
	native.Engine, native.InboundMode, native.OutboundPolicy, native.Listen = engineNative, inIPv4, outIPv4First, "0.0.0.0"
	a, e1 := legacy.URI()
	b, e2 := native.URI()
	if e1 != nil || e2 != nil || a != b {
		t.Fatalf("links differ:\n%s\n%s", a, b)
	}
	for _, want := range []string{"pbk=PUBLICKEY", "sid=ab12", "sni=addons.mozilla.org", "flow=xtls-rprx-vision", "fp=chrome", "11111111-1111-4111-8111-111111111111@203.0.113.10:" + itoa(legacy.PublicPort)} {
		if !strings.Contains(a, want) {
			t.Errorf("link lost %q: %s", want, a)
		}
	}
	// And the subscription built from both states is byte-identical.
	sub := Subscription{ID: "aaaaaaaaaaaa", Name: "s", Enabled: true, NodeIDs: []string{legacy.ID}}
	s1 := State{Schema: 1, Profiles: []Profile{legacy}, Subscriptions: []Subscription{sub}}
	s2 := State{Schema: 1, Profiles: []Profile{native}, Subscriptions: []Subscription{sub}}
	if renderSubscription(s1.exportSubscription(sub).URIs) != renderSubscription(s2.exportSubscription(sub).URIs) {
		t.Fatal("subscription output changed with the relay engine")
	}
}

func TestAltLinkOnlyForDualStackEntries(t *testing.T) {
	setup := ServerSetup{PublicHost: v4Addr, IPv4: v4Addr, IPv6: v6Addr, Listen: "::"}
	uri := "vless://11111111-1111-4111-8111-111111111111@ft.example.net:44275?security=reality&pbk=k&sid=ab&sni=x.example#o"
	mk := func(mode string) Profile {
		p := nativeFixture(t, mode, outAuto, "ft.example.net:44275")
		p.TargetURI, p.PublicHost = uri, v4Addr
		if mode == inIPv6 {
			p.PublicHost = v6Addr
		}
		return p
	}
	if _, _, ok := setup.AltAddress(mk(inDual)); !ok {
		t.Error("a dual-stack relay should offer the other address")
	}
	for _, mode := range []string{inIPv4, inIPv6} {
		if _, _, ok := setup.AltAddress(mk(mode)); ok {
			t.Errorf("%s-only entry offered an address it does not serve", mode)
		}
	}
	// A node explicitly set to IPv6 on a dual-stack-capable host: no IPv4 link.
	n := fixture(t, "ss")
	n.Listen, n.InboundMode, n.PublicHost = "::", inIPv6, v6Addr
	yes := true
	n.IPv4Mapped = &yes // even if the wildcard could accept IPv4, the explicit mode wins
	if _, _, ok := setup.AltAddress(n); ok {
		t.Error("explicit IPv6 node must not offer an IPv4 link")
	}
}

func TestNodeInboundModeIsKeptNotUpgraded(t *testing.T) {
	// Choosing IPv4 on a dual-stack host stays IPv4; choosing IPv6 is not silently dual.
	for _, tc := range []struct {
		input string
		want  string
	}{{"1\n", inIPv4}, {"2\n", inDual}, {"3\n", inIPv6}} {
		t.Run(tc.want, func(t *testing.T) {
			if tc.want != inIPv4 {
				requireIPv6(t) // planning a "::" port binds a real IPv6 socket
			}
			u, _ := testUI(testApp(t), tc.input)
			u.caps = func() listenCaps { return listenCaps{V4: true, V6: true, DualStack: true} }
			setup, e := u.nodeListeningSetup(ServerSetup{PublicHost: "vpn.example.com", Listen: "::", Family: "custom", IPv4: v4Addr, IPv6: v6Addr})
			if e != nil {
				t.Fatal(e)
			}
			p := fixture(t, "ss")
			p, e = PlanPort(p, setup, State{})
			if e != nil {
				t.Fatal(e)
			}
			if p.InboundMode != tc.want {
				t.Errorf("mode %q, want %q", p.InboundMode, tc.want)
			}
			if (tc.want == inIPv4) != (p.Listen == "0.0.0.0") {
				t.Errorf("listen %q", p.Listen)
			}
			if tc.want == inIPv6 && (p.IPv4Mapped == nil || *p.IPv4Mapped) {
				t.Errorf("explicit IPv6 recorded as serving IPv4: %v", p.IPv4Mapped)
			}
			if e = p.Validate(); e != nil {
				t.Error(e)
			}
		})
	}
}

func TestIPv6OnlyNodeConfigurationRejectsIPv4Sources(t *testing.T) {
	p := fixture(t, "ss")
	p.Listen, p.InboundMode = "::", inIPv6
	c, e := serverConfig(p, t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	rules := c["route"].(M)["rules"].([]any)
	first, _ := rules[0].(M)
	if first["action"] != "reject" || !reflect.DeepEqual(first["source_ip_cidr"], []string{"0.0.0.0/0"}) {
		t.Fatalf("first rule %v", rules[0])
	}
	// Nothing changes for the other modes or for a node with no explicit mode.
	for _, mode := range []string{"", inIPv4, inDual} {
		q := fixture(t, "ss")
		q.Listen = "::"
		if mode == inIPv4 {
			q.Listen = "0.0.0.0"
		}
		q.InboundMode = mode
		cc, _ := serverConfig(q, t.TempDir())
		if r := cc["route"].(M)["rules"].([]any); len(r) != 1 {
			t.Errorf("mode %q has extra rules: %v", mode, r)
		}
	}
	// With AI routing the reject rule still comes first.
	p.AIRoute = &AIRoute{Outbound: &Proxy{Protocol: "http", Host: "198.51.100.9", Port: 3128, Username: "u", Password: "p"}, RuleSet: AIRuleSetCurrent}
	c, _ = serverConfig(p, t.TempDir())
	if r := c["route"].(M)["rules"].([]any); r[0].(M)["action"] != "reject" {
		t.Fatalf("AI rules ahead of the IPv6-only guard: %v", r[0])
	}
}

func TestIPv6OnlyMeterDoesNotCountIPv4(t *testing.T) {
	p := fixture(t, "ss")
	p.Listen, p.InboundMode = "::", inIPv6
	text := nftMeter{}.tableRules(p, TrafficRecord{})
	if !strings.Contains(text, "meta nfproto ipv6 ") {
		t.Errorf("IPv6-only entry is metered without a family match:\n%s", text)
	}
	p.InboundMode = inDual
	if strings.Contains(nftMeter{}.tableRules(p, TrafficRecord{}), "meta nfproto") {
		t.Error("a dual-stack entry must be metered for both families")
	}
	legacy := fixture(t, "ss")
	legacy.Listen = "::"
	if strings.Contains(nftMeter{}.tableRules(legacy, TrafficRecord{}), "meta nfproto") {
		t.Error("a legacy :: entry changed its meter")
	}
	// The traffic fingerprint of legacy entries is unchanged; an explicit IPv6 entry differs.
	l := fixture(t, "ss")
	l.Listen = "::"
	e := l
	e.InboundMode = inIPv6
	d := l
	d.InboundMode = inDual
	if trafficShape(l) != trafficShape(d) || trafficShape(l) == trafficShape(e) {
		t.Error("traffic shape fingerprints")
	}
}

func TestSettingsRejectInvalidRelayDefaults(t *testing.T) {
	a := testApp(t)
	if e := a.SaveSettings(Settings{Language: "en", RelayInbound: "triple"}); e == nil {
		t.Error("invalid inbound default saved")
	}
	if e := a.SaveSettings(Settings{Language: "en", RelayOutbound: "fast"}); e == nil {
		t.Error("invalid outbound default saved")
	}
	if e := a.SaveSettings(Settings{Language: "en", RelayInbound: inDual, RelayOutbound: outIPv6First}); e != nil {
		t.Error(e)
	}
}

func TestSplitDualProbeRequiresBothFamiliesOnOnePort(t *testing.T) {
	// Fake sockets: a stack where the second (IPv6) bind on the same port conflicts.
	var tcpCalls []string
	listen := func(network, addr string) (net.Listener, error) {
		tcpCalls = append(tcpCalls, network+" "+addr)
		if network == "tcp6" {
			return nil, syscall.EADDRINUSE
		}
		return net.Listen("tcp4", "127.0.0.1:0")
	}
	packet := func(network, addr string) (net.PacketConn, error) { return net.ListenPacket("udp4", "127.0.0.1:0") }
	if splitBindWorks(listen, packet, []string{"tcp"}) {
		t.Fatal("conflict not detected")
	}
	if len(tcpCalls) != 2 || !strings.HasPrefix(tcpCalls[0], "tcp4 0.0.0.0:") || !strings.HasPrefix(tcpCalls[1], "tcp6 [::]:") {
		t.Fatalf("the probe must bind explicit families on one port: %v", tcpCalls)
	}
	// The conflict removes the dual choice; IPv4 and IPv6 stay.
	items := relayInboundOptions(listenCaps{V4: true, V6: true, SplitConflict: true})
	if len(items) != 2 || items[0].key != inIPv4 || items[1].key != inIPv6 {
		t.Fatalf("%v", items)
	}
	items = relayInboundOptions(listenCaps{V4: true, V6: true})
	if len(items) != 3 || items[2].key != inDual {
		t.Fatalf("%v", items)
	}
	if got := relayInboundOptions(listenCaps{V4: true}); len(got) != 1 || got[0].key != inIPv4 {
		t.Fatalf("IPv4-only host: %v", got)
	}
	if got := relayInboundOptions(listenCaps{V6: true}); len(got) != 1 || got[0].key != inIPv6 {
		t.Fatalf("IPv6-only host: %v", got)
	}
	if len(relayInboundOptions(listenCaps{})) != 0 {
		t.Fatal("a host with no family offers nothing")
	}
}

func TestDualStackRelayCommitBindsBothFamilies(t *testing.T) {
	requireIPv6(t)
	a := testApp(t)
	s, _ := a.Load()
	p := nativeFixture(t, inDual, outAuto, "relay-target.example:443")
	if e := a.Commit(s, replace(s, p), false); e != nil {
		t.Fatal(e)
	}
	got, _ := a.Load()
	r, _ := Find(got, p.ID)
	if r.inboundMode() != inDual || r.Listen != "::" || len(r.bindSpecs()) != 2 {
		t.Fatalf("%+v", r)
	}
}

func TestCommitRejectsAnIPv6RelayOnAHostWithoutIPv6(t *testing.T) {
	if ipv6Available() {
		t.Skip("this host has IPv6")
	}
	// The bind check is real: a mode the host cannot serve is refused at save time, with the
	// failing family named, and nothing is written.
	a := testApp(t)
	s, _ := a.Load()
	p := nativeFixture(t, inIPv6, outAuto, "relay-target.example:443")
	p.PublicHost = v6Addr
	e := a.Commit(s, replace(s, p), false)
	if e == nil || !strings.Contains(e.Error(), "IPv6") {
		t.Fatalf("got %v", e)
	}
	if after, _ := a.Load(); len(after.Profiles) != 0 {
		t.Fatal("rejected relay was written")
	}
}

func TestNodeListeningSetupRecordsTheExplicitModeWithoutSockets(t *testing.T) {
	// The same selection as above, checked without binding anything, so it runs on hosts
	// that have no IPv6 at all.
	for _, tc := range []struct {
		input, mode, listen string
		mapped              bool
	}{{"1\n", inIPv4, "0.0.0.0", false}, {"2\n", inDual, "::", true}, {"3\n", inIPv6, "::", false}} {
		u, _ := testUI(testApp(t), tc.input)
		u.caps = func() listenCaps { return listenCaps{V4: true, V6: true, DualStack: true} }
		setup, e := u.nodeListeningSetup(ServerSetup{PublicHost: "vpn.example.com", Listen: "::", Family: "custom", IPv4: v4Addr, IPv6: v6Addr})
		if e != nil {
			t.Fatal(e)
		}
		if setup.inbound != tc.mode || setup.Listen != tc.listen {
			t.Errorf("%q: %+v", tc.input, setup)
		}
		if tc.listen == "::" && (setup.ipv4Mapped == nil || *setup.ipv4Mapped != tc.mapped) {
			t.Errorf("%q: ipv4Mapped %v, want %v", tc.input, setup.ipv4Mapped, tc.mapped)
		}
		if tc.listen == "0.0.0.0" && setup.ipv4Mapped != nil {
			t.Errorf("%q: IPv4 listener carries a mapped flag", tc.input)
		}
	}
}
