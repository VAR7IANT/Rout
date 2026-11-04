package rout

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf8"
)

func saveTestServer(t *testing.T, a *App) {
	t.Helper()
	s, _ := a.LoadSettings()
	s.Language = "en"
	s.Server = &ServerSetup{PublicHost: "203.0.113.10", Listen: "0.0.0.0", Network: "both", Family: "ipv4", IPv4: "203.0.113.10"}
	if e := a.SaveSettings(s); e != nil {
		t.Fatal(e)
	}
}

func TestAIExitThroughExistingRelayFromTheMenu(t *testing.T) {
	sc := newAIScene(t)
	old, _ := sc.a.Load()
	relay := chainRelayProfileIn(t, old, "198.51.100.20:1080")
	if e := sc.a.Commit(old, replace(old, relay), false); e != nil {
		t.Fatal(e)
	}
	// Select AI exit · through an existing forward · relay 1 · SOCKS5 · user · password ·
	// default name · confirm · back.
	u, out := aiUI(sc, "3\n2\n1\n\nca-user\nca-pass\n\n\n0\n")
	var dialed Proxy
	u.probeProxy = func(p Proxy) (string, error) { dialed = p; return "198.51.100.20", nil }
	if e := u.aiMenu(); e != nil {
		t.Fatal(e)
	}
	s, _ := sc.a.Load()
	ex, e := FindExit(s, s.AI.AIOutboundID)
	if e != nil || !ex.isChain() || ex.ViaRelay != relay.ID || ex.Proxy.Host != "198.51.100.20" || ex.Proxy.Username != "ca-user" {
		t.Fatalf("exit %+v %v\n%s", ex, e, out.String())
	}
	// The test dialed the relay's loopback entry, not the proxy directly.
	if dialed.Host != "127.0.0.1" || dialed.Port != relay.Port || dialed.Password != "ca-pass" {
		t.Fatalf("dialed %+v", dialed)
	}
	text := out.String()
	for _, want := range []string{"Through an existing port forward", "What service is at the end of the chain?", "plaintext", "Outbound IP: 198.51.100.20", "AI exit updated"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in\n%s", want, text)
		}
	}
	if strings.Contains(text, "ca-pass") {
		t.Fatal("password echoed")
	}
}

func TestAIExitNewChainCreatesALoopbackRelayAndRollsBackWhenDeclined(t *testing.T) {
	sc := newAIScene(t)
	saveTestServer(t, sc.a)
	before, _ := sc.a.Load()
	// New chain · relay on this server · SOCKS5 · address · user · password · policy auto.
	// The test fails, and the default answer to "select it anyway" is no.
	u, _ := aiUI(sc, "3\n4\n1\n\n198.51.100.30:1080\nu\np\n\n\n0\n0\n")
	u.probeProxy = func(Proxy) (string, error) { return "", errors.New("proxy unreachable") }
	_ = u.aiMenu()
	after, _ := sc.a.Load()
	if len(after.Exits) != len(before.Exits) || len(after.Profiles) != len(before.Profiles) {
		t.Fatalf("declined chain left pieces behind: %d exits, %d profiles", len(after.Exits), len(after.Profiles))
	}
	// Accepted: the relay listens on loopback only and the chain becomes the AI exit.
	u, out := aiUI(sc, "3\n4\n1\n\n198.51.100.30:1080\nu\np\n\n\n0\n")
	if e := u.aiMenu(); e != nil {
		t.Fatal(e)
	}
	s, _ := sc.a.Load()
	ex, e := FindExit(s, s.AI.AIOutboundID)
	if e != nil || !ex.isChain() {
		t.Fatalf("no chain exit: %v\n%s", e, out.String())
	}
	r, e := Find(s, ex.ViaRelay)
	if e != nil || r.Kind != "relay" || r.Listen != "127.0.0.1" || r.Target != "198.51.100.30:1080" || r.Engine != engineNative {
		t.Fatalf("relay %+v %v", r, e)
	}
}

func TestAIExitFromARemoteNodeLink(t *testing.T) {
	sc := newAIScene(t)
	n, e := NewProfile("vless")
	if e != nil {
		t.Fatal(e)
	}
	n.PublicHost, n.PublicPort = "198.51.100.40", 443
	link, _ := n.URI()
	u, out := aiUI(sc, "3\n3\n"+link+"\n\n0\n")
	if e := u.aiMenu(); e != nil {
		t.Fatal(e)
	}
	s, _ := sc.a.Load()
	ex, e := FindExit(s, s.AI.AIOutboundID)
	if e != nil || ex.Kind != exitRemote || ex.Proxy.Protocol != proxyNode {
		t.Fatalf("exit %+v %v\n%s", ex, e, out.String())
	}
	if strings.Contains(out.String(), link) {
		t.Fatal("share link echoed")
	}
}

// A relay that forwards UDP only is the hop of a Hysteria2/TUIC chain: the menu must list it as
// usable, offer only QUIC node ends, and dial it on loopback.
func TestAIExitThroughAUDPOnlyRelayFromTheMenu(t *testing.T) {
	sc := newAIScene(t)
	node := quicNode(t, "hy2", "hy2.example.net", 8443)
	old, _ := sc.a.Load()
	relay := chainRelayProfileIn(t, old, node.hostPort())
	relay.Protocol = "udp"
	if e := sc.a.Commit(old, replace(old, relay), false); e != nil {
		t.Fatal(e)
	}
	// Select AI exit · through an existing forward · relay 1 · end service: default (node) ·
	// share link · default name · confirm · back.
	u, out := aiUI(sc, "3\n2\n1\n\n"+node.Link+"\n\n\n0\n")
	var dialed Proxy
	u.probeProxy = func(p Proxy) (string, error) { dialed = p; return "203.0.113.55", nil }
	if e := u.aiMenu(); e != nil {
		t.Fatal(e)
	}
	text := out.String()
	if strings.Contains(text, "This relay cannot be used") || !strings.Contains(text, "forwards UDP only") {
		t.Fatalf("a UDP relay was refused or its ends were not narrowed:\n%s", text)
	}
	if strings.Contains(text, "SOCKS5 proxy") && strings.Contains(text, "What service is at the end of the chain?\n   1  SOCKS5") {
		t.Fatalf("TCP proxies were offered for a UDP-only relay:\n%s", text)
	}
	s, _ := sc.a.Load()
	ex, e := FindExit(s, s.AI.AIOutboundID)
	if e != nil || !ex.isChain() || ex.ViaRelay != relay.ID || ex.Proxy.Protocol != proxyNode {
		t.Fatalf("exit %+v %v\n%s", ex, e, text)
	}
	if dialed.Host != "127.0.0.1" || dialed.Port != relay.Port {
		t.Fatalf("the test did not go through the relay: %+v", dialed)
	}
	if strings.Contains(text, node.Link) {
		t.Fatal("share link echoed")
	}
}


func TestChainGeneratedNamesBoundedAndStable(t *testing.T) {
	host := "ca-" + strings.Repeat("x", 48) + ".example.net"
	spec := ChainSpec{
		ViaAddress: "[2001:db8:1234:5678:9abc:def0:1234:5678]:34443",
		Protocol:   "socks5",
		Host:       host,
		Port:       1080,
		Username:   "u",
		Password:   "p",
	}
	ex, err := buildChainExit(State{}, spec)
	if err != nil {
		t.Fatal(err)
	}
	if got := utf8.RuneCountInString(ex.Name); got > 60 {
		t.Fatalf("auto name has %d runes: %q", got, ex.Name)
	}
	if err := validDisplayName(ex.Name); err != nil {
		t.Fatalf("auto name rejected: %v", err)
	}
	again, err := buildChainExit(State{}, spec)
	if err != nil || again.Name != ex.Name {
		t.Fatalf("auto name changed across calls: %q / %q, %v", ex.Name, again.Name, err)
	}
	other := spec
	other.Host = "ca-" + strings.Repeat("x", 48) + ".example.org"
	different, err := buildChainExit(State{}, other)
	if err != nil || different.Name == ex.Name {
		t.Fatalf("different endpoints collided: %q / %q, %v", ex.Name, different.Name, err)
	}
	if got := boundedChainName("Chain", "CA-hop", "ca.example.net"); got != "Chain-CA-hop-ca.example.net" {
		t.Fatalf("short auto name changed: %q", got)
	}
	unicodeName := boundedChainName("Chain", strings.Repeat("加", 55), "加拿大出口")
	if utf8.RuneCountInString(unicodeName) > 60 || validDisplayName(unicodeName) != nil {
		t.Fatalf("Unicode auto name invalid: %q", unicodeName)
	}
	custom := spec
	custom.Name = "自定义出口"
	named, err := buildChainExit(State{}, custom)
	if err != nil || named.Name != custom.Name {
		t.Fatalf("custom name changed: %q, %v", named.Name, err)
	}
	custom.Name = strings.Repeat("中", 61)
	if _, err := buildChainExit(State{}, custom); err == nil {
		t.Fatal("overlong explicit name was silently shortened")
	}
}

func TestAIExitNewChainWithLongHostUsesBoundedNames(t *testing.T) {
	sc := newAIScene(t)
	saveTestServer(t, sc.a)
	host := "ca-" + strings.Repeat("x", 48) + ".example.net"
	// New chain -> local relay -> SOCKS5 -> long endpoint -> credentials -> auto policy.
	// The menu has no custom-name prompt; both generated names must be valid automatically.
	u, out := aiUI(sc, "3\n4\n1\n\n"+host+":1080\nu\np\n\n\n0\n")
	u.probeProxy = func(Proxy) (string, error) { return "203.0.113.55", nil }
	if err := u.aiMenu(); err != nil {
		t.Fatalf("long-host menu failed: %v\n%s", err, out.String())
	}
	s, err := sc.a.Load()
	if err != nil || s.AI == nil {
		t.Fatalf("AI exit not saved: %v\n%s", err, out.String())
	}
	ex, err := FindExit(s, s.AI.AIOutboundID)
	if err != nil || !ex.isChain() || ex.Proxy.Host != host {
		t.Fatalf("exit invalid: %+v, %v\n%s", ex, err, out.String())
	}
	relay, err := Find(s, ex.ViaRelay)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{ex.Name, relay.Name} {
		if utf8.RuneCountInString(name) > 60 || validDisplayName(name) != nil {
			t.Fatalf("invalid generated name %q", name)
		}
	}
}
