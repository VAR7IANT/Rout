package rout

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ---- fixtures ------------------------------------------------------------------------------

// exitOrigin is a controlled HTTP server that answers with the source address it observed:
// what an IP-echo service on the Internet reports as the exit IP.
func exitOrigin(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	hits := &atomic.Int32{}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		fmt.Fprint(w, host)
	})}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return l.Addr().String(), hits
}

// canadaSOCKS is an authenticated SOCKS5 server that egresses from 127.0.0.2, a different
// source address than anything else in the test, so the origin can tell which exit was used.
// Every CONNECT goes to the controlled origin; it never dials the public Internet.
func canadaSOCKS(t *testing.T, origin, user, password string) (Proxy, *atomic.Int32, func()) {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	count := &atomic.Int32{}
	stopped := &atomic.Bool{}
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(15 * time.Second))
				head := make([]byte, 2)
				if _, e := io.ReadFull(c, head); e != nil || head[0] != 5 {
					return
				}
				methods := make([]byte, int(head[1]))
				if _, e := io.ReadFull(c, methods); e != nil {
					return
				}
				c.Write([]byte{5, 2})
				if _, e := io.ReadFull(c, head); e != nil {
					return
				}
				u := make([]byte, int(head[1]))
				io.ReadFull(c, u)
				io.ReadFull(c, head[:1])
				pw := make([]byte, int(head[0]))
				io.ReadFull(c, pw)
				if string(u) != user || string(pw) != password {
					c.Write([]byte{1, 1})
					return
				}
				c.Write([]byte{1, 0})
				req := make([]byte, 4)
				if _, e := io.ReadFull(c, req); e != nil || req[1] != 1 {
					return
				}
				switch req[3] {
				case 1:
					io.ReadFull(c, make([]byte, 4))
				case 4:
					io.ReadFull(c, make([]byte, 16))
				case 3:
					n := make([]byte, 1)
					io.ReadFull(c, n)
					io.ReadFull(c, make([]byte, int(n[0])))
				default:
					return
				}
				port := make([]byte, 2)
				io.ReadFull(c, port)
				_ = binary.BigEndian.Uint16(port)
				d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}, Timeout: 3 * time.Second}
				up, e := d.Dial("tcp", origin)
				if e != nil {
					c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				count.Add(1)
				c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
				_ = c.SetDeadline(time.Time{})
				copyTunnel(c, up)
			}(c)
		}
	}()
	stop := func() {
		if stopped.CompareAndSwap(false, true) {
			l.Close()
		}
	}
	t.Cleanup(stop)
	h, p, _ := ParseEndpoint(l.Addr().String())
	return Proxy{Protocol: "socks5", Host: h, Port: p, Username: user, Password: password}, count, stop
}

// distinctFreePort is freePort that never returns one of the ports already taken.
func distinctFreePort(t *testing.T, taken ...int) int {
	t.Helper()
	for i := 0; i < 100; i++ {
		port, e := freePort()
		if e != nil {
			t.Fatal(e)
		}
		clash := false
		for _, other := range taken {
			clash = clash || other == port
		}
		if !clash {
			return port
		}
	}
	t.Fatal("no distinct free port")
	return 0
}

// chainRelayProfileIn is chainRelayProfile with a port that no profile of s already uses.
func chainRelayProfileIn(t *testing.T, s State, target string) Profile {
	t.Helper()
	var taken []int
	for _, p := range s.Profiles {
		taken = append(taken, p.Port)
	}
	r := chainRelayProfile(t, target)
	r.Port = distinctFreePort(t, taken...)
	r.PublicPort = r.Port
	return r
}

func chainRelayProfile(t *testing.T, target string) Profile {
	t.Helper()
	port, e := freePort()
	if e != nil {
		t.Fatal(e)
	}
	return Profile{ID: RandomHex(6), Name: "CA-hop", Kind: "relay", Enabled: true, Protocol: "tcp", Listen: "127.0.0.1", Port: port,
		PublicHost: "127.0.0.1", PublicPort: port, Target: target, RelayMode: relayRemote, InboundMode: inIPv4, OutboundPolicy: outAuto, Engine: engineNative}
}

// chainScene stores a relay to proxy and a chain exit through it, with node A bound.
type chainScene struct {
	a           *App
	relay       Profile
	exit        Exit
	nodeA, node Profile
}

func newChainScene(t *testing.T, a *App, proxy Proxy) chainScene {
	return newChainSceneProto(t, a, proxy, "tcp")
}

// newChainSceneProto is newChainScene with the transport the relay forwards ("udp" for a
// Hysteria2/TUIC end).
func newChainSceneProto(t *testing.T, a *App, proxy Proxy, protocol string) chainScene {
	t.Helper()
	sc := chainScene{a: a}
	sc.relay = chainRelayProfile(t, proxy.hostPort())
	sc.relay.Protocol = protocol
	sc.nodeA, sc.node = fixture(t, "ss"), fixture(t, "ss")
	sc.nodeA.Name, sc.node.Name = "US-A", "US-B"
	// freePort closes its probe socket before returning, so the kernel can hand the same port
	// out again: the relay and the two nodes must be given distinct ports explicitly, or
	// State.Validate rightly refuses "same udp/tcp port" now and then.
	sc.nodeA.Port = distinctFreePort(t, sc.relay.Port)
	sc.node.Port = distinctFreePort(t, sc.relay.Port, sc.nodeA.Port)
	sc.nodeA.PublicPort, sc.node.PublicPort = sc.nodeA.Port, sc.node.Port
	sc.exit = Exit{ID: RandomHex(6), Name: "CA-chain", Kind: exitChain, ViaRelay: sc.relay.ID, Proxy: proxy}
	if exitTransport(proxy) == "udp" {
		sc.exit.RemoteNetwork = "both"
	}
	old, e := a.Load()
	if e != nil {
		t.Fatal(e)
	}
	next := replace(replace(replace(old, sc.relay), sc.nodeA), sc.node)
	next = UpsertExit(next, sc.exit)
	next.AI = &AIRouting{Enabled: true, BoundInboundIDs: []string{sc.nodeA.ID}, AIOutboundID: sc.exit.ID, RuleSetVersion: AIRuleSetCurrent}
	if e = a.Commit(old, next, false); e != nil {
		t.Fatal(e)
	}
	return sc
}

func runChainRelay(t *testing.T, p Profile) context.CancelFunc {
	t.Helper()
	cfg, e := nativeRelayConfigOf(p)
	if e != nil {
		t.Fatal(e)
	}
	r := newRelayRuntime(cfg, io.Discard)
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- r.Serve(ctx, ready) }()
	select {
	case <-ready:
	case e := <-done:
		cancel()
		t.Fatalf("relay did not start: %v", e)
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("relay start timeout")
	}
	stop := func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
		}
	}
	t.Cleanup(stop)
	return stop
}

// goProxyProbe performs the real request of layer 6 with Go's own SOCKS5/HTTP client
// instead of sing-box: the bytes still travel through the relay and the proxy, and the
// address comes from the origin's observation, not from the configuration.
func goProxyProbe(originURL string) func(*App, Proxy) fullProbe {
	return func(_ *App, p Proxy) fullProbe {
		scheme := map[string]string{"socks5": "socks5", "http": "http"}[p.Protocol]
		u := &url.URL{Scheme: scheme, Host: net.JoinHostPort(p.Host, itoa(p.Port)), User: url.UserPassword(p.Username, p.Password)}
		ip, e := fetchIP(u.String(), originURL)
		return fullProbe{V4: ip, ErrV4: e, ErrV6: errors.New("IPv6 not tested here")}
	}
}

func chainEnv(originURL string) diagEnv {
	env := defaultDiagEnv()
	env.fullProxy = goProxyProbe(originURL)
	return env
}

// ---- model --------------------------------------------------------------------------------

func TestChainExitRendersThroughRelayAndKeepsTLSIdentity(t *testing.T) {
	a := testApp(t)
	sc := newChainScene(t, a, Proxy{Protocol: "https", Host: "ca.example.net", Port: 8443, Username: "u", Password: "p"})
	s, _ := a.Load()
	eff := s.withAIRoutes()
	A, _ := Find(eff, sc.nodeA.ID)
	B, _ := Find(eff, sc.node.ID)
	if A.AIRoute == nil || A.AIRoute.Outbound == nil || B.AIRoute != nil {
		t.Fatalf("binding: A=%+v B=%+v", A.AIRoute, B.AIRoute)
	}
	c, e := serverConfig(A, t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	b, _ := JSON(c)
	text := string(b)
	for _, want := range []string{`"tag": "ai-egress"`, `"server": "127.0.0.1"`, fmt.Sprintf(`"server_port": %d`, sc.relay.Port), `"server_name": "ca.example.net"`} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %s in\n%s", want, text)
		}
	}
	// The unbound node is byte-identical to a node without AI routing.
	cb, _ := serverConfig(B, t.TempDir())
	plain := B
	plain.AIRoute = nil
	cp, _ := serverConfig(plain, t.TempDir())
	x, _ := JSON(cb)
	y, _ := JSON(cp)
	if string(x) != string(y) {
		t.Fatal("unbound node changed")
	}
	// Editing the relay's port follows automatically: no stale loopback port remains.
	old, _ := a.Load()
	r, _ := Find(old, sc.relay.ID)
	r.Port, _ = freePort()
	r.PublicPort = r.Port
	if e = a.Commit(old, replace(old, r), false); e != nil {
		t.Fatal(e)
	}
	s, _ = a.Load()
	A, _ = Find(s.withAIRoutes(), sc.nodeA.ID)
	if A.AIRoute.Outbound.Port != r.Port {
		t.Fatalf("dial port %d, want %d", A.AIRoute.Outbound.Port, r.Port)
	}
}

func TestChainExitNodeLinkIsRewrittenToTheHopKeepingSNI(t *testing.T) {
	p, e := NewProfile("vless")
	if e != nil {
		t.Fatal(e)
	}
	p.PublicHost, p.PublicPort = "ca.example.net", 443
	link, _ := p.URI()
	node, e := ParseRemoteNode(link)
	if e != nil {
		t.Fatal(e)
	}
	r := chainRelayProfile(t, node.hostPort())
	s := State{Schema: 1, Profiles: []Profile{r}}
	ex := Exit{ID: RandomHex(6), Name: "CA", Kind: exitChain, ViaRelay: r.ID, Proxy: *node}
	dial, e := resolveExit(s, ex, map[string]bool{})
	if e != nil {
		t.Fatal(e)
	}
	out, e := URIOutbound(dial.Link)
	if e != nil {
		t.Fatal(e)
	}
	b, _ := JSON(out)
	if out["server"] != "127.0.0.1" || !strings.Contains(string(b), p.SNI) {
		t.Fatalf("rewritten outbound %s", b)
	}
}

func TestChainExitRefusesLoopsBareForwardsAndBrokenReferences(t *testing.T) {
	a := testApp(t)
	sc := newChainScene(t, a, Proxy{Protocol: "socks5", Host: "198.51.100.20", Port: 1080, Username: "u", Password: "p"})
	s, _ := a.Load()
	// A port forward without a proxy at its end is refused.
	if _, e := buildChainExit(s, ChainSpec{ViaRelay: sc.relay.ID, Protocol: "forward"}); e == nil {
		t.Fatal("bare forward accepted as an exit")
	}
	// A relay that targets one of this server's own nodes would leave from this server.
	loop := chainRelayProfile(t, net.JoinHostPort("127.0.0.1", itoa(sc.nodeA.Port)))
	next := replace(s, loop)
	ex := Exit{ID: RandomHex(6), Name: "loop", Kind: exitChain, ViaRelay: loop.ID, Proxy: Proxy{Protocol: "socks5", Host: "127.0.0.1", Port: sc.nodeA.Port, Username: "u", Password: "p"}}
	if e := chainProblem(next, ex, localIPs()); e == nil || !strings.Contains(e.Error(), "US-A") {
		t.Fatalf("loop not refused: %v", e)
	}
	// A proxy that does not match the relay target is refused.
	bad := sc.exit
	bad.Proxy.Port = 1081
	if e := chainProblem(s, bad, localIPs()); e == nil {
		t.Fatal("mismatched target accepted")
	}
	// Deleting the relay that the AI exit depends on is refused, naming both.
	e := a.DeleteProfiles([]string{sc.relay.ID})
	if e == nil || !strings.Contains(e.Error(), "CA-hop") {
		t.Fatalf("delete of a used relay: %v", e)
	}
	if !strings.Contains(Translate("en", e.Error()), "CA-chain") {
		t.Fatalf("message does not name the exit: %s", Translate("en", e.Error()))
	}
	// Retargeting it away from the proxy is refused too.
	old, _ := a.Load()
	r, _ := Find(old, sc.relay.ID)
	r.Target = "198.51.100.21:1080"
	if e = a.Commit(old, replace(old, r), false); e == nil {
		t.Fatal("retarget broke the chain silently")
	}
	// A chain exit cannot be a node's ordinary outbound.
	if _, e = BindExit(old, sc.node.ID, sc.exit.ID); e == nil {
		t.Fatal("chain bound as node outbound")
	}
	// Disabling the relay is refused while the AI exit uses it.
	r, _ = Find(old, sc.relay.ID)
	r.Enabled = false
	if e = a.Commit(old, replace(old, r), false); e == nil {
		t.Fatal("disable broke the chain silently")
	}
}

func TestChainExitFailsClosedWhenTheRelayIsGone(t *testing.T) {
	a := testApp(t)
	sc := newChainScene(t, a, Proxy{Protocol: "socks5", Host: "198.51.100.20", Port: 1080, Username: "u", Password: "p"})
	s, _ := a.Load()
	// Simulate a state edited outside Rout (or restored) where the relay disappeared.
	broken := removeProfile(s, sc.relay.ID)
	A, _ := Find(broken.withAIRoutes(), sc.nodeA.ID)
	if A.AIRoute == nil || A.AIRoute.Outbound != nil {
		t.Fatal("missing relay must keep the route and reject, not fall back")
	}
	c, _ := serverConfig(A, t.TempDir())
	b, _ := JSON(c)
	if strings.Contains(string(b), "ai-egress") || !strings.Contains(string(b), `"reject"`) {
		t.Fatalf("fail-closed rules missing:\n%s", b)
	}
	if route, _ := AIDecision(broken, sc.nodeA.ID, "api.openai.com"); route != "blocked" {
		t.Fatalf("decision %q", route)
	}
	if route, _ := AIDecision(broken, sc.node.ID, "api.openai.com"); route != "original" {
		t.Fatalf("unbound decision %q", route)
	}
}

func TestChainExitSurvivesStateRoundTripAndHidesSecrets(t *testing.T) {
	a := testApp(t)
	sc := newChainScene(t, a, Proxy{Protocol: "socks5", Host: "198.51.100.20", Port: 1080, Username: "ca-user", Password: "ca-secret-pw"})
	s, e := a.Load()
	if e != nil {
		t.Fatal(e)
	}
	got, _ := FindExit(s, sc.exit.ID)
	if got.ViaRelay != sc.relay.ID || got.Kind != exitChain {
		t.Fatalf("round trip %+v", got)
	}
	v := exitView(a, s, got)
	b, _ := JSON(v)
	if strings.Contains(string(b), "ca-secret-pw") || strings.Contains(string(b), "ca-user") {
		t.Fatalf("view leaks credentials: %s", b)
	}
	if v.Kind != "chain" || v.ViaRelayName != "CA-hop" || len(v.Path) < 4 {
		t.Fatalf("view %+v", v)
	}
}

// ---- real data path (no sing-box needed) ----------------------------------------------

func TestChainDiagnosisRealTrafficThroughRelayAndSOCKS5(t *testing.T) {
	origin, hits := exitOrigin(t)
	ca, caHits, stopCA := canadaSOCKS(t, origin, "ca-user", "ca-pass")
	a := testApp(t)
	sc := newChainScene(t, a, ca)
	runChainRelay(t, sc.relay)
	env := chainEnv("http://" + origin + "/ip")
	rep, e := a.diagnoseAI(context.Background(), env, diagOpts{Full: true})
	if e != nil {
		t.Fatal(e)
	}
	text := rep.Text()
	if _, failed := rep.Failed(); failed {
		t.Fatalf("chain failed:\n%s", text)
	}
	for _, want := range []string{"CA-hop", "127.0.0.2", "SOCKS5"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in\n%s", want, text)
		}
	}
	if !rep.Has(4, diagOK) || !rep.Has(5, diagOK) || !rep.Has(6, diagOK) {
		t.Fatalf("layers not proved:\n%s", text)
	}
	if caHits.Load() == 0 || hits.Load() == 0 {
		t.Fatal("no real traffic crossed the chain")
	}
	// Wrong credentials are reported at the protocol layer.
	old, _ := a.Load()
	ex, _ := FindExit(old, sc.exit.ID)
	ex.Proxy.Password = "wrong"
	if e = a.Commit(old, UpsertExit(old, ex), false); e != nil {
		t.Fatal(e)
	}
	rep, _ = a.diagnoseAI(context.Background(), env, diagOpts{Full: true})
	if layer, failed := rep.Failed(); !failed || layer != 5 {
		t.Fatalf("bad credentials not reported at layer 5:\n%s", rep.Text())
	}
	// The proxy is down: the failure names the layer and nothing reaches the origin.
	stopCA()
	before := hits.Load()
	rep, _ = a.diagnoseAI(context.Background(), env, diagOpts{Full: true})
	if _, failed := rep.Failed(); !failed {
		t.Fatalf("down proxy not reported:\n%s", rep.Text())
	}
	if hits.Load() != before {
		t.Fatal("request reached the origin without the proxy")
	}
}

func TestChainDiagnosisReportsAStoppedRelay(t *testing.T) {
	origin, _ := exitOrigin(t)
	ca, _, _ := canadaSOCKS(t, origin, "u", "p")
	a := testApp(t)
	sc := newChainScene(t, a, ca)
	// Relay not running: the hop's entry refuses connections.
	_ = sc
	rep, e := a.diagnoseAI(context.Background(), chainEnv("http://"+origin+"/ip"), diagOpts{Full: true})
	if e != nil {
		t.Fatal(e)
	}
	if _, failed := rep.Failed(); !failed {
		t.Fatalf("stopped relay not reported:\n%s", rep.Text())
	}
	if rep.Has(6, diagOK) {
		t.Fatal("exit claimed without a relay")
	}
}

// ---- full integration: real sing-box nodes, AI routing, relay, SOCKS5 ------------------

func TestIntegrationAIRelayChain(t *testing.T) {
	a := integrationApp(t)
	origin, hits := exitOrigin(t)
	ca, caHits, stopCA := canadaSOCKS(t, origin, "ca-user", "ca-pass")
	sc := newChainScene(t, a, ca)
	stopRelay := runChainRelay(t, sc.relay)
	ports := map[string]int{}
	for _, p := range []Profile{sc.nodeA, sc.node} {
		aiProcess(t, a.enginePath("sing-box"), filepath.Join(a.profileDir(p.ID), "config.json"), p.Port)
		port, _ := freePort()
		client, e := ClientConfig(p, "127.0.0.1", p.Port, port)
		if e != nil {
			t.Fatal(e)
		}
		aiProcess(t, a.enginePath("sing-box"), configFile(t, client), port)
		ports[p.ID] = port
	}
	get := func(p Profile, host string) (string, error) {
		proxy, _ := url.Parse("socks5://127.0.0.1:" + itoa(ports[p.ID]))
		tr := &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}
		defer tr.CloseIdleConnections()
		req, _ := http.NewRequest("GET", "http://"+origin+"/", nil)
		req.Host = host
		res, e := (&http.Client{Transport: tr, Timeout: 5 * time.Second}).Do(req)
		if e != nil {
			return "", e
		}
		defer res.Body.Close()
		b, e := io.ReadAll(io.LimitReader(res.Body, 64))
		return string(b), e
	}
	expect := func(p Profile, host, ip string) {
		t.Helper()
		got, e := get(p, host)
		if e != nil || got != ip {
			t.Fatalf("%s Host %s: got %q %v, want exit %s", p.Name, host, got, e, ip)
		}
	}
	// AI traffic of the bound node leaves from the "Canada" proxy (127.0.0.2); everything
	// else, and every connection of the unbound node, keeps the original route (127.0.0.1).
	n := caHits.Load()
	expect(sc.nodeA, "api.openai.com", "127.0.0.2")
	if caHits.Load() != n+1 {
		t.Fatal("AI request did not cross the chain")
	}
	expect(sc.nodeA, "www.example.com", "127.0.0.1")
	expect(sc.node, "api.openai.com", "127.0.0.1")
	expect(sc.node, "www.example.com", "127.0.0.1")
	if caHits.Load() != n+1 {
		t.Fatal("ordinary or unbound traffic used the AI exit")
	}
	// The layered test observes the same exit through the generated outbound.
	rep, e := a.diagnoseAI(context.Background(), chainEnv("http://"+origin+"/ip"), diagOpts{Full: true})
	if e != nil || !strings.Contains(rep.Text(), "127.0.0.2") {
		t.Fatalf("diagnosis: %v\n%s", e, rep.Text())
	}
	// Fail closed: with the relay down the AI request fails and never takes the original exit.
	stopRelay()
	before := hits.Load()
	if _, e = get(sc.nodeA, "api.openai.com"); e == nil {
		t.Fatal("AI request succeeded without the relay")
	}
	if hits.Load() != before {
		t.Fatal("AI request leaked through the original route")
	}
	expect(sc.nodeA, "www.example.com", "127.0.0.1")
	stopCA()
}
