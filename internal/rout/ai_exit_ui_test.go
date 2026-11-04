package rout

import (
	"errors"
	"strings"
	"testing"
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
	relay := chainRelayProfile(t, "198.51.100.20:1080")
	old, _ := sc.a.Load()
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
