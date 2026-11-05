package rout

import (
	"net/url"
	"strings"
	"testing"
)

// IPv6 in relay chains. These are deterministic unit checks (no IPv6 stack needed). The real
// sockets run in CI, whose runners have IPv6 loopback; hosts without it skip those tests.

func TestRelayDialHostFollowsTheListenAddress(t *testing.T) {
	for listen, want := range map[string]string{
		"0.0.0.0":     "127.0.0.1", // an IPv4 wildcard accepts IPv4 loopback
		"127.0.0.1":   "127.0.0.1",
		"::":          "::1", // an IPv6 wildcard (IPv6-only or dual) accepts ::1
		"::1":         "::1",
		"2001:db8::5": "2001:db8::5", // a specific address is dialed as itself
		"192.0.2.9":   "192.0.2.9",
	} {
		if got := relayDialHost(Profile{Listen: listen}); got != want {
			t.Errorf("listen %s: dial %s, want %s", listen, got, want)
		}
	}
}

// An IPv6 entry does not imply an IPv6 exit: the relay may accept on [::1] and forward to an
// IPv4 proxy (and the other way round); the chain only needs both ends to be consistent.
func TestChainWithAnIPv6HopAndEitherFamilyOfProxy(t *testing.T) {
	for _, proxyHost := range []string{"203.0.113.20", "2001:db8::20"} {
		t.Run(proxyHost, func(t *testing.T) {
			target := proxyHost
			if strings.Contains(proxyHost, ":") {
				target = "[" + proxyHost + "]"
			}
			relay := chainRelayProfile(t, target+":1080")
			relay.Listen, relay.InboundMode = "::", inIPv6
			s := State{Schema: 1, Profiles: []Profile{relay}}
			ex := Exit{ID: RandomHex(6), Name: "v6-hop", Kind: exitChain, ViaRelay: relay.ID, Proxy: Proxy{Protocol: "socks5", Host: proxyHost, Port: 1080, Username: "u", Password: "p"}}
			if e := chainProblem(s, ex, map[string]bool{}); e != nil {
				t.Fatal(e)
			}
			dial, e := chainDialProxy(s, ex)
			if e != nil || dial.Host != "::1" || dial.Port != relay.Port {
				t.Fatalf("dial %+v %v", dial, e)
			}
			out := proxyConfig(dial)
			if out["server"] != "::1" || out["server_port"] != relay.Port {
				t.Fatalf("rendered outbound %v", out)
			}
		})
	}
}

// The same IPv6 address written differently is one host (relay target vs exit proxy).
func TestChainTargetComparisonIgnoresIPv6Notation(t *testing.T) {
	relay := chainRelayProfile(t, "[2001:DB8:0:0:0:0:0:20]:1080")
	s := State{Schema: 1, Profiles: []Profile{relay}}
	ex := Exit{ID: RandomHex(6), Name: "v6", Kind: exitChain, ViaRelay: relay.ID, Proxy: Proxy{Protocol: "socks5", Host: "2001:db8::20", Port: 1080, Username: "u", Password: "p"}}
	if e := chainProblem(s, ex, map[string]bool{}); e != nil {
		t.Fatalf("equal IPv6 addresses in different notation were refused: %v", e)
	}
}

// A node link whose server is an IPv6 literal is rewritten to the hop with brackets intact and
// keeps the TLS identity of the original server.
func TestChainRewritesAnIPv6NodeLinkToTheHop(t *testing.T) {
	p, e := NewProfile("vless")
	if e != nil {
		t.Fatal(e)
	}
	p.PublicHost, p.PublicPort = "2001:db8::30", 443
	link, e := p.URI()
	if e != nil || !strings.Contains(link, "@[2001:db8::30]:443") {
		t.Fatalf("link %q %v", link, e)
	}
	node, e := ParseRemoteNode(link)
	if e != nil || node.Host != "2001:db8::30" {
		t.Fatalf("node %+v %v", node, e)
	}
	relay := chainRelayProfile(t, node.hostPort())
	relay.Listen, relay.InboundMode = "::", inIPv6
	s := State{Schema: 1, Profiles: []Profile{relay}}
	ex := Exit{ID: RandomHex(6), Name: "v6-vless", Kind: exitChain, ViaRelay: relay.ID, Proxy: *node}
	dial, e := resolveExit(s, ex, map[string]bool{})
	if e != nil {
		t.Fatal(e)
	}
	u, e := url.Parse(dial.Link)
	if e != nil || u.Hostname() != "::1" || u.Port() != itoa(relay.Port) || !strings.Contains(dial.Link, "@[::1]:") {
		t.Fatalf("rewritten link %q (%v)", dial.Link, e)
	}
	out, e := URIOutbound(dial.Link)
	if e != nil || out["server"] != "::1" {
		t.Fatalf("outbound %v %v", out, e)
	}
	b, _ := JSON(out)
	if !strings.Contains(string(b), p.SNI) || !strings.Contains(string(b), p.PublicKey) {
		t.Fatalf("Reality identity lost:\n%s", b)
	}
}

// A subscription with an IPv6-only node keeps the bracketed endpoint in both formats. The state
// is served from memory, so no IPv6 socket is needed.
func TestSubscriptionKeepsIPv6OnlyNodesInBase64AndMihomo(t *testing.T) {
	sc := newSubScene(t)
	_, token := sc.create(t, "v6", 0, 1)
	s := sc.state(t)
	p, _ := Find(s, sc.nodes[0].ID)
	p.PublicHost, p.Listen, p.InboundMode = "2001:db8::77", "::", inIPv6
	s = replace(s, p)
	h := newSubscriptionHandler(func() (State, error) { return s, nil }, func(string, ...any) {})
	links := decodeBody(t, get(h, "GET", "/s/"+token).Body.String())
	if !strings.Contains(links[0], "@[2001:db8::77]:") {
		t.Fatalf("IPv6 endpoint lost in the Base64 list: %q", links[0])
	}
	w := get(h, "GET", "/s/"+token+"?format=mihomo")
	yaml := w.Body.String()
	// The proxies are written as JSON flow mappings: an IPv6 server is the bare address (Mihomo
	// wants no brackets there) and never the bracketed link form.
	if w.Code != 200 || !strings.Contains(yaml, `"server":"2001:db8::77"`) || strings.Contains(yaml, "[2001:db8::77]") {
		t.Fatalf("IPv6 server missing or bracketed in the Mihomo YAML (%d):\n%s", w.Code, yaml)
	}
}
