package rout

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Real sing-box runs of the node outbound IP family.
//
// The node configuration under test is the one Rout generates (serverConfig). Two deviations are
// needed to run it offline, and nothing else is touched:
//
//   - the inbound is replaced by a SOCKS inbound tagged "entry", so a test can ask for any
//     destination (a name, an IPv4 literal, an IPv6 literal) without a Reality client;
//   - the resolver named in dial.domain_resolver (the system resolver in production) is replaced
//     by a "hosts" server with fixed answers, so A-only / AAAA-only / dual-stack / missing names
//     exist without a network.
//
// The outbound's domain_resolver, the route rules and the rule order are exactly what ships.
// TestIntegrationNodeEgressRealReality below runs the unmodified generated configuration behind a
// real VLESS Reality client.
//
// Every origin counts the connections it receives per IP family, so "no fallback" is proved by a
// counter that stays at zero, not by an error message. Tests that need the host's IPv6 loopback
// skip where it is absent; the CI runners have it.

type egressLab struct {
	t              *testing.T
	a              *App
	v6             bool
	both, v4, v6o  int // origin ports: listens on both families / IPv4 only / IPv6 only
	hits4, hits6   atomic.Int32
	hosts          map[string][]string
	started        int
	proxyDestAddr  string
	proxyDestAddr6 string
}

var egressHosts = map[string][]string{
	"a-only.test":    {"127.0.0.1"},
	"aaaa-only.test": {"::1"},
	"dual.test":      {"127.0.0.1", "::1"},
}

func newEgressLab(t *testing.T) *egressLab {
	t.Helper()
	if os.Getenv("ROUT_SKIP_SINGBOX_RUNTIME") == "1" {
		t.Skip("runtime explicitly disabled; node egress NOT verified")
	}
	l := &egressLab{t: t, a: integrationApp(t), v6: ipv6LoopbackWorks(), hosts: egressHosts}
	var e error
	for _, port := range []*int{&l.both, &l.v4, &l.v6o} {
		if *port, e = freePort(); e != nil {
			t.Fatal(e)
		}
	}
	serve := func(network, address, body string, counter *atomic.Int32) {
		ln, e := net.Listen(network, address)
		if e != nil {
			t.Fatalf("origin %s: %v", address, e)
		}
		srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { counter.Add(1); fmt.Fprint(w, body) })}
		go srv.Serve(ln)
		t.Cleanup(func() { srv.Close() })
	}
	serve("tcp4", fmt.Sprintf("127.0.0.1:%d", l.both), "203.0.113.4", &l.hits4)
	serve("tcp4", fmt.Sprintf("127.0.0.1:%d", l.v4), "203.0.113.4", &l.hits4)
	if l.v6 {
		serve("tcp6", fmt.Sprintf("[::1]:%d", l.both), "2001:db8::6", &l.hits6)
		serve("tcp6", fmt.Sprintf("[::1]:%d", l.v6o), "2001:db8::6", &l.hits6)
	}
	return l
}

func (l *egressLab) port(which string) int {
	switch which {
	case "v4":
		return l.v4
	case "v6":
		return l.v6o
	}
	return l.both
}

// node runs one node with the given policy (and optional outbound proxy) and returns the port of
// its SOCKS entry.
func (l *egressLab) node(policy string, proxy *Proxy) int {
	t := l.t
	t.Helper()
	p := fixture(t, "vless")
	p.OutboundPolicy = policy
	p.Outbound = proxy
	cfg, e := serverConfig(p, t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	entry, e := freePort()
	if e != nil {
		t.Fatal(e)
	}
	cfg["inbounds"] = []any{M{"type": "socks", "tag": "entry", "listen": "127.0.0.1", "listen_port": entry}}
	if dns, ok := cfg["dns"].(M); ok {
		dns["servers"] = []any{M{"type": "hosts", "tag": egressDNSTag, "predefined": l.hosts}}
	}
	path := configFile(t, cfg)
	if e = l.a.checkConfig(path); e != nil {
		t.Fatalf("sing-box rejected the generated configuration: %v", e)
	}
	aiProcess(t, l.a.enginePath("sing-box"), path, entry)
	return entry
}

type egressOutcome struct {
	OK     bool
	Body   string
	Err    string
	V4, V6 int32 // connections the origins received during this request
}

// socksGet asks the node's SOCKS entry for host:port and performs an HTTP GET through it.
func (l *egressLab) socksGet(entry int, host string, port int) egressOutcome {
	t := l.t
	t.Helper()
	b4, b6 := l.hits4.Load(), l.hits6.Load()
	finish := func(o egressOutcome) egressOutcome {
		time.Sleep(60 * time.Millisecond) // a late connection from a fallback would show up here
		o.V4, o.V6 = l.hits4.Load()-b4, l.hits6.Load()-b6
		return o
	}
	c, e := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", entry), 3*time.Second)
	if e != nil {
		t.Fatalf("node entry: %v", e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(15 * time.Second))
	if _, e = c.Write([]byte{5, 1, 0}); e != nil {
		return finish(egressOutcome{Err: e.Error()})
	}
	greeting := make([]byte, 2)
	if _, e = io.ReadFull(c, greeting); e != nil || greeting[1] != 0 {
		return finish(egressOutcome{Err: fmt.Sprintf("socks greeting %v %v", greeting, e)})
	}
	req := []byte{5, 1, 0}
	switch ip := net.ParseIP(host); {
	case ip != nil && strings.Contains(host, ":"):
		req = append(append(req, 4), ip.To16()...)
	case ip != nil:
		req = append(append(req, 1), ip.To4()...)
	default:
		req = append(append(req, 3, byte(len(host))), host...)
	}
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, e = c.Write(req); e != nil {
		return finish(egressOutcome{Err: e.Error()})
	}
	head := make([]byte, 4)
	if _, e = io.ReadFull(c, head); e != nil {
		return finish(egressOutcome{Err: "no socks reply: " + e.Error()})
	}
	if head[1] != 0 {
		return finish(egressOutcome{Err: fmt.Sprintf("socks reply code %d", head[1])})
	}
	rest := map[byte]int{1: 4 + 2, 4: 16 + 2}[head[3]]
	if head[3] == 3 {
		n := make([]byte, 1)
		io.ReadFull(c, n)
		rest = int(n[0]) + 2
	}
	io.ReadFull(c, make([]byte, rest))
	fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: origin.test\r\nConnection: close\r\n\r\n")
	res, e := http.ReadResponse(bufio.NewReader(c), nil)
	if e != nil {
		return finish(egressOutcome{Err: "no http response: " + e.Error()})
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 128))
	return finish(egressOutcome{OK: true, Body: strings.TrimSpace(string(body))})
}

type egressCase struct {
	host, origin string // origin: both / v4 / v6
	want         string // v4, v6 (reaches an origin of that family) or fail
	needV6       bool
	// forbid names a family whose origins must receive nothing: the proof that no fallback happened.
	forbid string
}

func (l *egressLab) run(entry int, cases []egressCase) {
	t := l.t
	t.Helper()
	for _, c := range cases {
		if c.needV6 && !l.v6 {
			t.Logf("SKIP %s via %s origin: needs IPv6 loopback", c.host, c.origin)
			continue
		}
		o := l.socksGet(entry, c.host, l.port(c.origin))
		label := fmt.Sprintf("%s -> %s origin", c.host, c.origin)
		switch c.want {
		case "fail":
			if o.OK {
				t.Errorf("%s: connected (%q) but the policy forbids it", label, o.Body)
			}
		case "v4":
			if !o.OK || o.Body != "203.0.113.4" {
				t.Errorf("%s: want an IPv4 origin, got ok=%v body=%q err=%q", label, o.OK, o.Body, o.Err)
			}
		case "v6":
			if !o.OK || o.Body != "2001:db8::6" {
				t.Errorf("%s: want an IPv6 origin, got ok=%v body=%q err=%q", label, o.OK, o.Body, o.Err)
			}
		}
		if c.forbid == "4" && o.V4 != 0 {
			t.Errorf("%s: the IPv4 origin received %d connection(s); IPv4 must not be used", label, o.V4)
		}
		if c.forbid == "6" && o.V6 != 0 {
			t.Errorf("%s: the IPv6 origin received %d connection(s); IPv6 must not be used", label, o.V6)
		}
	}
}

// IPv6 Only is a real restriction: IPv4 literals, IPv4-mapped literals, A-only names and the IPv4
// half of a dual-stack name are all refused, and an unresolvable name fails. This is also the
// answer to "is domain_resolver.strategy = ipv6_only enough": the first two cases are exactly the
// ones the resolver alone does not cover (see TestIntegrationNodeEgressResolverAloneIsNotEnough).
func TestIntegrationNodeEgressIPv6Only(t *testing.T) {
	l := newEgressLab(t)
	entry := l.node(outIPv6Only, nil)
	l.run(entry, []egressCase{
		{host: "127.0.0.1", origin: "both", want: "fail", forbid: "4"},                  // IPv4 literal
		{host: "::ffff:127.0.0.1", origin: "both", want: "fail", forbid: "4"},           // IPv4-mapped literal
		{host: "a-only.test", origin: "both", want: "fail", forbid: "4"},                // A-only domain
		{host: "dual.test", origin: "v4", want: "fail", forbid: "4"},                    // no IPv4 fallback
		{host: "nx.test", origin: "both", want: "fail", forbid: "4"},                    // DNS failure: no IPv4 attempt
		{host: "::1", origin: "both", want: "v6", needV6: true, forbid: "4"},            // IPv6 literal
		{host: "aaaa-only.test", origin: "both", want: "v6", needV6: true, forbid: "4"}, // AAAA-only domain
		{host: "dual.test", origin: "both", want: "v6", needV6: true, forbid: "4"},      // dual-stack goes over IPv6
	})
}

func TestIntegrationNodeEgressIPv4Only(t *testing.T) {
	l := newEgressLab(t)
	entry := l.node(outIPv4Only, nil)
	l.run(entry, []egressCase{
		{host: "127.0.0.1", origin: "both", want: "v4", forbid: "6"},
		{host: "a-only.test", origin: "both", want: "v4", forbid: "6"},
		{host: "dual.test", origin: "both", want: "v4", forbid: "6"},
		{host: "::1", origin: "both", want: "fail", forbid: "6"}, // IPv6 literal
		{host: "::1", origin: "v6", want: "fail", forbid: "6"},
		{host: "aaaa-only.test", origin: "both", want: "fail", forbid: "6"}, // AAAA-only domain
		{host: "dual.test", origin: "v6", want: "fail", forbid: "6"},        // no IPv6 fallback
		{host: "nx.test", origin: "both", want: "fail", forbid: "6"},
	})
}

// IPv6 First is a preference with fallback; it is not IPv6 Only.
func TestIntegrationNodeEgressIPv6FirstFallsBack(t *testing.T) {
	l := newEgressLab(t)
	entry := l.node(outIPv6First, nil)
	l.run(entry, []egressCase{
		{host: "dual.test", origin: "v4", want: "v4"}, // IPv6 unreachable: falls back to IPv4
		{host: "a-only.test", origin: "both", want: "v4"},
		{host: "127.0.0.1", origin: "both", want: "v4"}, // literals are not blocked
		{host: "nx.test", origin: "both", want: "fail"},
		{host: "dual.test", origin: "both", want: "v6", needV6: true, forbid: "4"}, // prefers IPv6
		{host: "::1", origin: "both", want: "v6", needV6: true},
		{host: "aaaa-only.test", origin: "both", want: "v6", needV6: true},
	})
}

func TestIntegrationNodeEgressIPv4FirstFallsBack(t *testing.T) {
	l := newEgressLab(t)
	entry := l.node(outIPv4First, nil)
	l.run(entry, []egressCase{
		{host: "dual.test", origin: "both", want: "v4", forbid: "6"}, // prefers IPv4
		{host: "a-only.test", origin: "both", want: "v4"},
		{host: "127.0.0.1", origin: "both", want: "v4"},
		{host: "nx.test", origin: "both", want: "fail"},
		{host: "dual.test", origin: "v6", want: "v6", needV6: true}, // IPv4 unreachable: falls back to IPv6
		{host: "::1", origin: "both", want: "v6", needV6: true},
		{host: "aaaa-only.test", origin: "both", want: "v6", needV6: true},
	})
}

// Auto renders no egress options, so it behaves exactly as nodes did before this feature.
func TestIntegrationNodeEgressAutoIsUnrestricted(t *testing.T) {
	l := newEgressLab(t)
	entry := l.node("", nil)
	l.run(entry, []egressCase{
		{host: "127.0.0.1", origin: "both", want: "v4"},
		{host: "::1", origin: "both", want: "v6", needV6: true},
	})
}

// The question the task asked: does the resolver strategy alone stop a client from reaching an IPv4
// address? It does not, which is why the ip_version rule exists. Removing the rule from a real
// configuration lets the IPv4 literal through; with the rule it is refused.
func TestIntegrationNodeEgressResolverAloneIsNotEnough(t *testing.T) {
	l := newEgressLab(t)
	p := fixture(t, "vless")
	p.OutboundPolicy = outIPv6Only
	cfg, e := serverConfig(p, t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	entry, _ := freePort()
	cfg["inbounds"] = []any{M{"type": "socks", "tag": "entry", "listen": "127.0.0.1", "listen_port": entry}}
	cfg["dns"].(M)["servers"] = []any{M{"type": "hosts", "tag": egressDNSTag, "predefined": l.hosts}}
	route := cfg["route"].(M)
	var kept []any
	for _, r := range route["rules"].([]any) {
		if r.(M)["ip_version"] == nil {
			kept = append(kept, r)
		}
	}
	if len(kept) != len(route["rules"].([]any))-1 {
		t.Fatal("expected exactly one family rule to remove")
	}
	route["rules"] = kept
	aiProcess(t, l.a.enginePath("sing-box"), configFile(t, cfg), entry)
	o := l.socksGet(entry, "127.0.0.1", l.both)
	if !o.OK || o.V4 != 1 {
		t.Fatalf("expected the resolver strategy alone to let an IPv4 literal through (that is why the rule exists): %+v", o)
	}
	// ... while the resolver strategy does still govern names, rule or no rule.
	if o = l.socksGet(entry, "a-only.test", l.both); o.OK || o.V4 != 0 {
		t.Fatalf("an A-only name must fail under ipv6_only: %+v", o)
	}
}

// An outbound proxy changes what the policy can mean: it governs how Rout reaches the PROXY SERVER.
func TestIntegrationNodeEgressWithAnOutboundProxy(t *testing.T) {
	l := newEgressLab(t)
	origin := fmt.Sprintf("127.0.0.1:%d", l.v4)
	proxyFor := func(host string) (*Proxy, *atomic.Int32) {
		px, count, _, _ := aiProxyFixture(t, origin, "tcp4", false)
		px.Host = host // reached by name, resolved under the node's policy
		return &px, count
	}
	t.Run("IPv6 Only cannot reach an IPv4-only proxy and does not fall back to Direct", func(t *testing.T) {
		l.t = t
		px, count := proxyFor("a-only.test")
		entry := l.node(outIPv6Only, px)
		o := l.socksGet(entry, "127.0.0.1", l.v4)
		if o.OK || count.Load() != 0 || o.V4 != 0 {
			t.Fatalf("the node must fail closed: %+v proxy=%d", o, count.Load())
		}
	})
	t.Run("IPv4 Only reaches an IPv4 proxy", func(t *testing.T) {
		l.t = t
		px, count := proxyFor("a-only.test")
		entry := l.node(outIPv4Only, px)
		o := l.socksGet(entry, "127.0.0.1", l.v4)
		if !o.OK || count.Load() != 1 || o.V4 != 1 {
			t.Fatalf("expected the request through the proxy: %+v proxy=%d", o, count.Load())
		}
	})
	t.Run("IPv4 Only cannot reach an AAAA-only proxy name", func(t *testing.T) {
		l.t = t
		px, count := proxyFor("aaaa-only.test")
		entry := l.node(outIPv4Only, px)
		o := l.socksGet(entry, "127.0.0.1", l.v4)
		if o.OK || count.Load() != 0 || o.V4 != 0 {
			t.Fatalf("the node must fail closed: %+v proxy=%d", o, count.Load())
		}
	})
	t.Run("the destination's family is the proxy's business, and is reported as not enforced", func(t *testing.T) {
		l.t = t
		if !l.v6 {
			t.Skip("needs IPv6 loopback for an IPv6-reachable proxy")
		}
		px, count, _, _ := aiProxyFixture(t, origin, "tcp6", false)
		px.Host = "aaaa-only.test"
		entry := l.node(outIPv6Only, &px)
		// IPv6 only governs the connection to the proxy; the IPv4 destination travels through it.
		o := l.socksGet(entry, "127.0.0.1", l.v4)
		if !o.OK || count.Load() != 1 {
			t.Fatalf("an IPv4 destination through an IPv6-reachable proxy should work: %+v", o)
		}
		p := Profile{Kind: "node", OutboundPolicy: outIPv6Only, Outbound: &px}
		if p.egressInfo().Enforced {
			t.Fatal("must not claim to enforce the website-side family behind a proxy")
		}
	})
	l.t = t
}

// Changing the policy of a stored node regenerates its configuration, and the regenerated
// configuration behaves accordingly under the real engine. Auto and the old config format agree.
func TestIntegrationNodeEgressSwitchingPolicyOnAStoredNode(t *testing.T) {
	if os.Getenv("ROUT_SKIP_SINGBOX_RUNTIME") == "1" {
		t.Skip("runtime explicitly disabled")
	}
	withHostRoutes(t, familyRoutes{V4: true, V6: true})
	a := integrationApp(t)
	l := &egressLab{t: t, a: a, v6: ipv6LoopbackWorks()}
	var e error
	if l.v4, e = freePort(); e != nil {
		t.Fatal(e)
	}
	ln, e := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", l.v4))
	if e != nil {
		t.Fatal(e)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { l.hits4.Add(1); fmt.Fprint(w, "203.0.113.4") })}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	_, _, camouflage := tlsFixture(t)
	camHost, camPort, _ := ParseEndpoint(strings.TrimPrefix(camouflage.URL, "https://"))
	node := aiTestNode(t, a, "vless", "Turkey-VLESS")
	read := func() string {
		b, e := os.ReadFile(filepath.Join(a.profileDir(node.ID), "config.json"))
		if e != nil {
			t.Fatal(e)
		}
		return string(b)
	}
	legacy := read()

	// run the stored configuration as is, behind a real VLESS Reality client
	request := func() (string, error) {
		state := mustLoad(t, a)
		p, _ := Find(state, node.ID)
		// The stored file, except that Reality's camouflage destination (outside the egress policy)
		// is a local TLS server, since the production SNI is not reachable from a test host.
		var stored M
		if e := json.Unmarshal([]byte(read()), &stored); e != nil {
			t.Fatal(e)
		}
		stored["inbounds"].([]any)[0].(map[string]any)["tls"].(map[string]any)["reality"].(map[string]any)["handshake"] = M{"server": camHost, "server_port": camPort}
		stop := aiProcess(t, a.enginePath("sing-box"), configFile(t, stored), p.Port)
		defer stop()
		local, _ := freePort()
		client, e := ClientConfig(p, "127.0.0.1", p.Port, local)
		if e != nil {
			t.Fatal(e)
		}
		var body string
		e = a.withClient(client, local, func(proxy string) error {
			var err error
			body, err = fetchIP(proxy, fmt.Sprintf("http://127.0.0.1:%d/", l.v4))
			return err
		})
		return body, e
	}

	if body, e := request(); e != nil || body != "203.0.113.4" {
		t.Fatalf("Auto: the legacy node must reach an IPv4 destination: %q %v", body, e)
	}
	if e = a.SetNodeOutboundPolicy(node.ID, outIPv6Only, false); e != nil {
		t.Fatal(e)
	}
	if read() == legacy {
		t.Fatal("configuration was not regenerated")
	}
	before := l.hits4.Load()
	if body, e := request(); e == nil {
		t.Fatalf("IPv6 Only: an IPv4 destination must fail through a real Reality client, got %q", body)
	}
	if l.hits4.Load() != before {
		t.Fatal("IPv6 Only: the IPv4 origin was contacted")
	}
	// `rout apply` regenerates every configuration from the saved state and must keep the policy
	s := mustLoad(t, a)
	if e = a.Commit(s, s, true); e != nil {
		t.Fatal(e)
	}
	if p, _ := Find(mustLoad(t, a), node.ID); p.OutboundPolicy != outIPv6Only {
		t.Fatalf("apply lost the policy: %q", p.OutboundPolicy)
	}
	if p, _ := Find(mustLoad(t, a), node.ID); !a.configInSync(p) {
		t.Fatal("apply left the configuration out of sync with the saved state")
	}
	if body, e := request(); e == nil {
		t.Fatalf("IPv6 Only after apply: an IPv4 destination must still fail, got %q", body)
	}
	if e = a.SetNodeOutboundPolicy(node.ID, outIPv4Only, false); e != nil {
		t.Fatal(e)
	}
	if body, e := request(); e != nil || body != "203.0.113.4" {
		t.Fatalf("IPv4 Only: %q %v", body, e)
	}
	if e = a.SetNodeOutboundPolicy(node.ID, outAuto, false); e != nil {
		t.Fatal(e)
	}
	if read() != legacy {
		t.Fatal("going back to Auto must restore the exact legacy configuration")
	}
	if body, e := request(); e != nil || body != "203.0.113.4" {
		t.Fatalf("Auto again: %q %v", body, e)
	}
}

// runStoredNode runs a stored node's own configuration under the real engine. Reality's
// camouflage destination (outside the egress policy) is a local TLS server, since the production
// SNI is not reachable from a test host. mutate may alter the rendered configuration, to build a
// node that leaks.
func runStoredNode(t *testing.T, a *App, p Profile, mutate func(M)) {
	t.Helper()
	_, _, camouflage := tlsFixture(t)
	camHost, camPort, _ := ParseEndpoint(strings.TrimPrefix(camouflage.URL, "https://"))
	var stored M
	if e := json.Unmarshal(fileBytes(t, filepath.Join(a.profileDir(p.ID), "config.json")), &stored); e != nil {
		t.Fatal(e)
	}
	stored["inbounds"].([]any)[0].(map[string]any)["tls"].(map[string]any)["reality"].(map[string]any)["handshake"] = M{"server": camHost, "server_port": camPort}
	if mutate != nil {
		mutate(stored)
	}
	aiProcess(t, a.enginePath("sing-box"), configFile(t, stored), p.Port)
}

// The egress test, end to end: a real node, a real Reality client, real requests, controls taken
// from the host with the same kind of request. Its verdicts must match what the node really does,
// including when the node leaks.
func TestIntegrationNodeEgressTestEndToEnd(t *testing.T) {
	if os.Getenv("ROUT_SKIP_SINGBOX_RUNTIME") == "1" {
		t.Skip("runtime explicitly disabled")
	}
	withHostRoutes(t, familyRoutes{V4: true, V6: ipv6LoopbackWorks()})
	v6 := ipv6LoopbackWorks()
	// the measurement endpoints are local origins (bare addresses), one per family
	l := newEgressLab(t)
	old := ipEndpoints
	ipEndpoints = map[string][]string{"tcp4": {fmt.Sprintf("http://127.0.0.1:%d/", l.both)}, "tcp6": {fmt.Sprintf("http://[::1]:%d/", l.both)}}
	t.Cleanup(func() { ipEndpoints = old })
	literals := func() map[string]literalTarget {
		out := map[string]literalTarget{"tcp4": {IP: "127.0.0.1", Host: "origin.test", Port: itoa(l.both)}}
		if v6 {
			out["tcp6"] = literalTarget{IP: "::1", Host: "origin.test", Port: itoa(l.both)}
		}
		return out
	}
	env := defaultEgressEnv()
	env.literals = literals
	env.hostDNS = func(string) bool { return true }

	run := func(t *testing.T, policy string, mutate func(M)) EgressReport {
		t.Helper()
		a := l.a
		n := aiTestNode(t, a, "vless", "Turkey-"+policy)
		if policy != "" {
			s := mustLoad(t, a)
			n.OutboundPolicy = policy
			if e := a.Commit(s, replace(s, n), false); e != nil {
				t.Fatal(e)
			}
		}
		n, _ = Find(mustLoad(t, a), n.ID)
		runStoredNode(t, a, n, mutate)
		rep, e := a.nodeEgressTest(n.ID, false, env)
		if e != nil {
			t.Fatal(e)
		}
		return rep
	}
	status := func(rep EgressReport, key string) string {
		c, ok := checkOf(rep, key)
		if !ok {
			return "absent"
		}
		return c.Status
	}

	t.Run("IPv6 only holds", func(t *testing.T) {
		rep := run(t, outIPv6Only, nil)
		if rep.Node.V4.IP != "" || rep.Node.V4.LiteralOK {
			t.Fatalf("IPv4 must be refused through the node: %+v", rep.Node.V4)
		}
		if rep.Host.V4.IP == "" {
			t.Fatalf("the control (host over IPv4) failed: %+v", rep.Host)
		}
		if s := status(rep, "denied_name"); s != egressPass {
			t.Errorf("denied_name %s", s)
		}
		if s := status(rep, "denied_literal"); s != egressPass {
			t.Errorf("denied_literal %s", s)
		}
		if v6 {
			if rep.Result != egressPass || status(rep, "allowed") != egressPass || rep.Node.V6.IP != "2001:db8::6" {
				t.Errorf("with IPv6 available the policy must verify: %s %+v", rep.Result, rep.Checks)
			}
		} else if rep.Result != egressFail || status(rep, "allowed") != egressFail {
			// no IPv6 on this host: the allowed family cannot work, and that is reported, not hidden
			t.Errorf("without IPv6 the allowed family must be reported as failing: %s %+v", rep.Result, rep.Checks)
		}
	})

	t.Run("a node that leaks IPv4 is caught", func(t *testing.T) {
		// the stored policy says IPv6 only, but the running configuration has no family rule
		rep := run(t, outIPv6Only, func(cfg M) {
			route := cfg["route"].(map[string]any)
			var kept []any
			for _, r := range route["rules"].([]any) {
				if r.(map[string]any)["ip_version"] == nil {
					kept = append(kept, r)
				}
			}
			route["rules"] = kept
			// the resolver is also replaced by a permissive one: the node now behaves like Auto
			delete(cfg["outbounds"].([]any)[0].(map[string]any), "domain_resolver")
			delete(cfg, "dns")
		})
		if rep.Result != egressFail {
			t.Fatalf("a leaking node must fail the test: %s %+v", rep.Result, rep.Checks)
		}
		if s := status(rep, "denied_literal"); s != egressFail {
			t.Errorf("the literal leak was not detected: %s", s)
		}
		if rep.Node.V4.IP == "" {
			t.Errorf("the leak should be visible as a working IPv4 exit: %+v", rep.Node.V4)
		}
	})

	t.Run("auto only measures", func(t *testing.T) {
		rep := run(t, "", nil)
		if rep.Result != egressPass || rep.Node.V4.IP != "203.0.113.4" {
			t.Fatalf("%s %+v", rep.Result, rep.Checks)
		}
		if status(rep, "denied_name") != "absent" {
			t.Fatal("Auto must not claim any exclusion")
		}
	})

	t.Run("IPv4 only", func(t *testing.T) {
		rep := run(t, outIPv4Only, nil)
		if rep.Result == egressFail || status(rep, "allowed") != egressPass || rep.Node.V6.IP != "" || rep.Node.V6.LiteralOK {
			t.Fatalf("IPv4 only: %s %+v", rep.Result, rep.Checks)
		}
		if v6 {
			if rep.Result != egressPass {
				t.Fatalf("with IPv6 available the exclusion is provable: %s %+v", rep.Result, rep.Checks)
			}
		} else if rep.Result != egressInconclusive {
			// no IPv6 on this host: the host cannot prove that IPv6 is being blocked; never a pass
			t.Fatalf("without IPv6 the exclusion is unprovable and must say so: %s %+v", rep.Result, rep.Checks)
		}
	})
}

// Every generated configuration must be accepted by the pinned engine: all node protocols × all
// policies × direct and every kind of outbound proxy, including a remote node link of each
// protocol. A deprecated or misplaced field would be fatal at start-up, so this runs the real
// `sing-box check`, not a JSON comparison.
func TestIntegrationNodeEgressConfigsPassSingBoxCheck(t *testing.T) {
	if os.Getenv("ROUT_SKIP_SINGBOX_RUNTIME") == "1" {
		t.Skip("runtime explicitly disabled")
	}
	a := integrationApp(t)
	exits := map[string]*Proxy{
		"direct": nil,
		"socks5": {Protocol: "socks5", Host: "proxy.example.net", Port: 1080, Username: "u", Password: "p"},
		"http":   {Protocol: "http", Host: "198.51.100.7", Port: 8080, Username: "u", Password: "p"},
		"https":  {Protocol: "https", Host: "proxy.example.net", Port: 443, Username: "u", Password: "p"},
	}
	for _, proto := range []string{"vless", "anytls", "ss", "hy2", "tuic"} {
		remote := fixture(t, proto)
		link, e := remote.URI()
		if e != nil {
			t.Fatalf("%s link: %v", proto, e)
		}
		exits["node-"+proto] = &Proxy{Protocol: proxyNode, Host: remote.PublicHost, Port: remote.PublicPort, Link: link}
	}
	checked := 0
	for _, proto := range []string{"vless", "anytls", "ss", "hy2", "tuic"} {
		for exitName, exit := range exits {
			for _, policy := range []string{"", outIPv4First, outIPv6First, outIPv4Only, outIPv6Only} {
				p := fixture(t, proto)
				p.OutboundPolicy = policy
				p.Outbound = exit
				if e := p.Validate(); e != nil {
					continue // e.g. a literal proxy of the forbidden family; refused at save time, tested elsewhere
				}
				cfg, e := serverConfig(p, t.TempDir())
				if e != nil {
					continue // a combination Rout itself does not offer (e.g. UDP-only protocol with a proxy)
				}
				path := configFile(t, cfg)
				if e = a.checkConfig(path); e != nil {
					out, _ := runOutput(5*time.Second, a.enginePath("sing-box"), "check", "-c", path)
					t.Errorf("%s via %s policy %q rejected by sing-box: %v\n%s", proto, exitName, policy, e, out)
				}
				checked++
			}
		}
	}
	if checked < 80 {
		t.Fatalf("only %d combinations were checked; the matrix did not run", checked)
	}
	t.Logf("sing-box accepted %d configurations", checked)
}
