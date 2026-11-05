package rout

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Relay chains whose end is a UDP/QUIC node (Hysteria2, TUIC).
//
// Three layers of evidence are kept apart on purpose:
//
//   - unit tests (TestChainQUIC*): the layered diagnosis with a scripted dialer, QUIC probe and
//     exit probe. They prove which transport is used and how each failure is classified; they
//     prove nothing about a network;
//   - loopback tests with real sockets (TestChainQUICRealClosedUDPPort);
//   - loopback integration with real sing-box engines (TestIntegrationAIRelayChainQUIC): a real
//     Hysteria2/TUIC server, Rout's native UDP relay and real bound nodes. It is still a single
//     machine: not a provider NAT, a real IPv6 path or a cross-border route.

func quicNode(t *testing.T, protocol, host string, port int) Proxy {
	t.Helper()
	p, e := NewProfile(protocol)
	if e != nil {
		t.Fatal(e)
	}
	p.PublicHost, p.PublicPort = host, port
	link, e := p.URI()
	if e != nil {
		t.Fatal(e)
	}
	node, e := ParseRemoteNode(link)
	if e != nil {
		t.Fatal(e)
	}
	return *node
}

// quicScript scripts everything the chain diagnosis touches outside plain computation.
type quicScript struct {
	mu       sync.Mutex
	networks []string // every network the hop and entry dialers used
	probes   []string // addresses given to the QUIC probe, in order
	proxies  []Proxy  // proxies handed to the real-exit probe
	// probe returns the QUIC probe result for the n-th call (0 = the relay target).
	probe func(n int) error
	// exit is the real-exit probe result.
	exit    fullProbe
	managed func(p Profile) (bool, bool)
	local   map[string]bool
}

func (q *quicScript) env() diagEnv {
	env := diagEnvFor(map[string][]string{"hy2.example.net": {"192.0.2.44"}, "tuic.example.net": {"192.0.2.45"}}, func(ctx context.Context, network, addr string) (net.Conn, error) {
		q.mu.Lock()
		q.networks = append(q.networks, network)
		q.mu.Unlock()
		c, _ := net.Pipe()
		return c, nil
	})
	env.quicProbe = func(ctx context.Context, network, addr string) error {
		q.mu.Lock()
		n := len(q.probes)
		q.probes = append(q.probes, addr)
		q.mu.Unlock()
		if q.probe != nil {
			return q.probe(n)
		}
		return nil
	}
	env.fullProxy = func(a *App, p Proxy) fullProbe {
		q.mu.Lock()
		q.proxies = append(q.proxies, p)
		q.mu.Unlock()
		return q.exit
	}
	if q.managed != nil {
		env.managed = func(a *App, p Profile) (bool, bool) { return q.managed(p) }
	}
	if q.local != nil {
		env.local = func() map[string]bool { return q.local }
	}
	return env
}

func (q *quicScript) onlyUDP(t *testing.T) {
	t.Helper()
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.networks) == 0 {
		t.Fatal("no connection was attempted")
	}
	for _, n := range q.networks {
		if !strings.HasPrefix(n, "udp") {
			t.Fatalf("a UDP exit was tested over %s (all: %v)", n, q.networks)
		}
	}
}

func goodExit(ip string) fullProbe {
	return fullProbe{V4: ip, ErrV6: errors.New("no IPv6 route")}
}

func TestChainQUICHopIsTestedWithTheTransportOfTheExit(t *testing.T) {
	for _, tc := range []struct{ proto, host string }{{"hy2", "hy2.example.net"}, {"tuic", "tuic.example.net"}} {
		t.Run(tc.proto, func(t *testing.T) {
			a := testApp(t)
			sc := newChainSceneProto(t, a, quicNode(t, tc.proto, tc.host, 8443), "udp")
			q := &quicScript{exit: goodExit("203.0.113.55")}
			rep, e := a.diagnoseAI(context.Background(), q.env(), diagOpts{Full: true})
			if e != nil {
				t.Fatal(e)
			}
			text := rep.Text()
			if _, failed := rep.Failed(); failed {
				t.Fatalf("a healthy QUIC chain was reported as failed:\n%s", text)
			}
			q.onlyUDP(t)
			if len(q.probes) != 2 {
				t.Fatalf("want a QUIC probe of the relay target and one through the relay entry, got %v", q.probes)
			}
			// The exit probe dials the relay's loopback entry and keeps the real node's TLS name.
			if len(q.proxies) != 1 || q.proxies[0].Host != "127.0.0.1" || q.proxies[0].Port != sc.relay.Port {
				t.Fatalf("exit probe proxies %+v", q.proxies)
			}
			out, err := URIOutbound(q.proxies[0].Link)
			if err != nil {
				t.Fatal(err)
			}
			b, _ := JSON(out)
			if out["server"] != "127.0.0.1" || !strings.Contains(string(b), "addons.mozilla.org") {
				t.Fatalf("rewritten outbound %s", b)
			}
			for _, want := range []string{"answered QUIC version negotiation", "203.0.113.55", "AI exit chain is working"} {
				if !strings.Contains(text, want) {
					t.Errorf("missing %q in\n%s", want, text)
				}
			}
			if !rep.Has(4, diagOK) || !rep.Has(3, diagOK) || !rep.Has(6, diagOK) {
				t.Fatalf("layers not proved:\n%s", text)
			}
		})
	}
}

func TestChainQUICSilentTargetIsInconclusiveNotAFailure(t *testing.T) {
	a := testApp(t)
	newChainSceneProto(t, a, quicNode(t, "hy2", "hy2.example.net", 8443), "udp")
	q := &quicScript{exit: goodExit("203.0.113.55"), probe: func(n int) error {
		if n == 0 {
			return errNoQUICAnswer // filtering or obfuscation looks like silence
		}
		return nil
	}}
	rep, _ := a.diagnoseAI(context.Background(), q.env(), diagOpts{Full: true})
	if _, failed := rep.Failed(); failed {
		t.Fatalf("silence was treated as a failure:\n%s", rep.Text())
	}
	if !rep.Has(3, diagWarn) || !strings.Contains(rep.Text(), "did not answer the QUIC probe") {
		t.Fatalf("silence not reported as inconclusive:\n%s", rep.Text())
	}
	// A warning never stands in for the real exit: the observed IP still has to arrive.
	if !rep.Has(6, diagOK) {
		t.Fatalf("no observed exit:\n%s", rep.Text())
	}
}

func TestChainQUICFailuresAreClassifiedByLayerAndNeverClaimAnExit(t *testing.T) {
	cases := []struct {
		name      string
		script    func() *quicScript
		layer     int
		want      string
		exitProbe bool // whether the real-exit probe may have run
	}{
		{"relay target refuses UDP (ICMP)", func() *quicScript {
			return &quicScript{probe: func(n int) error {
				if n == 0 {
					return syscall.ECONNREFUSED
				}
				return nil
			}, exit: goodExit("203.0.113.55")}
		}, 3, "ICMP port unreachable", false},
		{"relay entry does not forward UDP", func() *quicScript {
			return &quicScript{probe: func(n int) error {
				if n == 1 {
					return syscall.ECONNREFUSED
				}
				return nil
			}, exit: goodExit("203.0.113.55")}
		}, 3, "did not receive UDP", false},
		{"QUIC handshake or authentication fails", func() *quicScript {
			return &quicScript{exit: fullProbe{ErrV4: errors.New("handshake failed"), ErrV6: errors.New("handshake failed")}}
		}, 5, "handshake", true},
		{"relay service is stopped", func() *quicScript {
			return &quicScript{managed: func(p Profile) (bool, bool) { return true, p.Kind != "relay" }, exit: goodExit("203.0.113.55")}
		}, 4, "is not running", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := testApp(t)
			newChainSceneProto(t, a, quicNode(t, "hy2", "hy2.example.net", 8443), "udp")
			q := tc.script()
			rep, e := a.diagnoseAI(context.Background(), q.env(), diagOpts{Full: true})
			if e != nil {
				t.Fatal(e)
			}
			layer, failed := rep.Failed()
			if !failed || layer != tc.layer {
				t.Fatalf("want a failure at layer %d, got %d/%v:\n%s", tc.layer, layer, failed, rep.Text())
			}
			if !strings.Contains(rep.Text(), tc.want) {
				t.Errorf("missing %q in\n%s", tc.want, rep.Text())
			}
			if strings.Contains(rep.Text(), "AI exit chain is working") || (!tc.exitProbe && len(q.proxies) != 0) {
				t.Fatalf("an exit was claimed or probed after a failed layer:\n%s", rep.Text())
			}
		})
	}
}

func TestChainQUICExitAddressEqualToThisServerIsFlagged(t *testing.T) {
	a := testApp(t)
	newChainSceneProto(t, a, quicNode(t, "hy2", "hy2.example.net", 8443), "udp")
	local := map[string]bool{"198.51.100.77": true}
	// Different from this server: no warning.
	q := &quicScript{exit: goodExit("203.0.113.55"), local: local}
	rep, _ := a.diagnoseAI(context.Background(), q.env(), diagOpts{Full: true})
	if rep.Has(6, diagWarn) || !strings.Contains(rep.Text(), "203.0.113.55") {
		t.Fatalf("a remote exit address was flagged:\n%s", rep.Text())
	}
	// Equal to this server's own address: the chain did not leave from the remote side.
	q = &quicScript{exit: goodExit("198.51.100.77"), local: local}
	rep, _ = a.diagnoseAI(context.Background(), q.env(), diagOpts{Full: true})
	if !rep.Has(6, diagWarn) || !strings.Contains(rep.Text(), "is an address of this server") {
		t.Fatalf("this server's own address was accepted as a remote exit:\n%s", rep.Text())
	}
}

func TestChainQUICNeedsARelayThatForwardsUDP(t *testing.T) {
	node := quicNode(t, "tuic", "tuic.example.net", 8443)
	r := chainRelayProfile(t, node.hostPort()) // a TCP relay
	s := State{Schema: 1, Profiles: []Profile{r}}
	ex := Exit{ID: RandomHex(6), Name: "tuic-chain", Kind: exitChain, ViaRelay: r.ID, Proxy: node, RemoteNetwork: "both"}
	if e := chainProblem(s, ex, map[string]bool{}); e == nil || !strings.Contains(Translate("en", e.Error()), "does not forward UDP") {
		t.Fatalf("a TCP relay was accepted for a UDP exit: %v", e)
	}
	// A UDP relay in front of a TCP-only NAT mapping cannot reach a QUIC node either.
	r.Protocol, r.TargetNetwork = "udp", "tcp"
	s.Profiles[0] = r
	if e := chainProblem(s, ex, map[string]bool{}); e == nil || !strings.Contains(Translate("en", e.Error()), "maps TCP only") {
		t.Fatalf("a TCP-only target was accepted for a UDP exit: %v", e)
	}
}

// TCP chains are unchanged: SOCKS5 through the relay is tested over TCP, never with QUIC.
func TestChainTCPExitNeverUsesTheQUICProbe(t *testing.T) {
	origin, hits := exitOrigin(t)
	ca, _, _ := canadaSOCKS(t, origin, "u", "p")
	a := testApp(t)
	sc := newChainScene(t, a, ca)
	runChainRelay(t, sc.relay)
	env := chainEnv("http://" + origin + "/ip")
	env.quicProbe = func(context.Context, string, string) error {
		t.Error("the QUIC probe was used for a TCP exit")
		return nil
	}
	rep, _ := a.diagnoseAI(context.Background(), env, diagOpts{Full: true})
	if _, failed := rep.Failed(); failed || !rep.Has(6, diagOK) || hits.Load() == 0 {
		t.Fatalf("TCP chain diagnosis regressed:\n%s", rep.Text())
	}
	if !strings.Contains(rep.Text(), "is reachable") {
		t.Fatalf("relay target not tested over TCP:\n%s", rep.Text())
	}
}

// Real sockets, no scripted dialer: a closed UDP port behind the relay is a definite failure
// found by the hop probe, and no exit is claimed.
func TestChainQUICRealClosedUDPPort(t *testing.T) {
	pc, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	_, port, _ := ParseEndpoint(pc.LocalAddr().String())
	pc.Close()
	a := testApp(t)
	newChainSceneProto(t, a, quicNode(t, "hy2", "127.0.0.1", port), "udp")
	env := defaultDiagEnv()
	env.fullProxy = func(*App, Proxy) fullProbe {
		t.Error("the exit probe ran although the hop was dead")
		return fullProbe{}
	}
	rep, _ := a.diagnoseAI(context.Background(), env, diagOpts{Full: true})
	if layer, failed := rep.Failed(); !failed || layer != 3 || !strings.Contains(rep.Text(), "ICMP port unreachable") {
		t.Fatalf("a closed UDP port was not reported at layer 3:\n%s", rep.Text())
	}
	if rep.Has(6, diagOK) {
		t.Fatal("an exit was claimed")
	}
}

// Fail closed for UDP chains: when the relay is gone the bound node rejects AI domains; it
// never keeps the node's UDP/QUIC outbound or falls back to the original exit.
func TestChainQUICFailsClosedWhenTheRelayIsGone(t *testing.T) {
	a := testApp(t)
	sc := newChainSceneProto(t, a, quicNode(t, "tuic", "tuic.example.net", 8443), "udp")
	s, _ := a.Load()
	broken := removeProfile(s, sc.relay.ID)
	A, _ := Find(broken.withAIRoutes(), sc.nodeA.ID)
	if A.AIRoute == nil || A.AIRoute.Outbound != nil {
		t.Fatal("a missing relay must keep the route and reject, not fall back")
	}
	c, _ := serverConfig(A, t.TempDir())
	b, _ := JSON(c)
	if strings.Contains(string(b), "ai-egress") || strings.Contains(string(b), "tuic.example.net") || !strings.Contains(string(b), `"reject"`) {
		t.Fatalf("fail-closed rules missing:\n%s", b)
	}
	if route, _ := AIDecision(broken, sc.nodeA.ID, "api.openai.com"); route != "blocked" {
		t.Fatalf("decision %q", route)
	}
	// And a working chain cannot lose its relay silently.
	if e := a.DeleteProfiles([]string{sc.relay.ID}); e == nil || !strings.Contains(e.Error(), "CA-hop") {
		t.Fatalf("the relay of a UDP chain was deletable: %v", e)
	}
}

// engineExitProbe is fullProbeProxy with the observation point replaced by a controlled
// origin that answers with the source address it saw: a real engine client, a real
// Hysteria2/TUIC handshake, the relay and the remote server in between.
func engineExitProbe(originURL string) func(*App, Proxy) fullProbe {
	return func(a *App, p Proxy) fullProbe {
		var out fullProbe
		port, e := freePort()
		if e != nil {
			out.ClientErr = e
			return out
		}
		conf := M{"log": M{"level": "error"}, "inbounds": []any{M{"type": "mixed", "listen": "127.0.0.1", "listen_port": port}}, "outbounds": []any{proxyConfig(p)}, "route": M{"final": "egress"}}
		out.ClientErr = a.withClientLog(conf, port, func(proxy string, logs func() string) error {
			out.V4, out.ErrV4 = fetchIP(proxy, originURL)
			out.ErrV6 = errors.New("IPv6 not tested here")
			out.LogHint = classifyClientLog(logs())
			return nil
		})
		return out
	}
}

// TestIntegrationAIRelayChainRemoteNodes is the real-engine proof that every node protocol a
// chain can end in carries AI traffic through a relay: VLESS Reality, AnyTLS and Shadowsocks
// 2022 over a TCP relay, Hysteria2 and TUIC over a UDP relay. The "remote server" is a real
// sing-box node of that protocol; its own egress leaves from 127.0.0.2.
func TestIntegrationAIRelayChainRemoteNodes(t *testing.T) {
	if os.Getenv("ROUT_SKIP_SINGBOX_RUNTIME") == "1" {
		t.Skip("runtime explicitly disabled; node chains NOT verified")
	}
	for _, tc := range []struct{ protocol, relay string }{{"vless", "tcp"}, {"anytls", "tcp"}, {"ss", "tcp"}, {"hy2", "udp"}, {"tuic", "udp"}} {
		protocol, relayProtocol := tc.protocol, tc.relay
		t.Run(protocol, func(t *testing.T) {
			a := integrationApp(t)
			cert, key, camouflage := tlsFixture(t)
			camHost, camPort, _ := ParseEndpoint(strings.TrimPrefix(camouflage.URL, "https://"))
			origin, hits := exitOrigin(t)
			// The "remote server": a real sing-box node whose own egress is an authenticated
			// SOCKS5 leaving from 127.0.0.2, so the origin can tell its traffic from anything
			// that leaves this server (127.0.0.1).
			ca, caHits, _ := canadaSOCKS(t, origin, "ca-user", "ca-pass")
			remote := &App{Home: t.TempDir(), BinDir: a.BinDir, ServiceMode: "none"}
			srv := fixture(t, protocol)
			srv.Port, _ = freePort()
			srv.PublicHost, srv.PublicPort = "127.0.0.1", srv.Port
			srv.SNI, srv.CertPEM, srv.KeyPEM = "example.test", cert, key
			srv.Outbound = &ca
			if e := srv.Validate(); e != nil {
				t.Fatal(e)
			}
			if e := remote.writeProfile(srv); e != nil {
				t.Fatal(e)
			}
			conf, e := serverConfig(srv, remote.profileDir(srv.ID))
			if e != nil {
				t.Fatal(e)
			}
			if protocol == "vless" || protocol == "anytls" {
				// Reality borrows a real TLS site; use the local camouflage server.
				conf["inbounds"].([]any)[0].(M)["tls"].(M)["reality"].(M)["handshake"] = M{"server": camHost, "server_port": camPort}
			}
			startEngine(t, profileSockets(srv), a.enginePath("sing-box"), "run", "-c", configFile(t, conf))
			link, _ := srv.URI()
			if protocol == "hy2" || protocol == "tuic" {
				u, _ := url.Parse(link)
				q := u.Query()
				q.Set("insecure", "1") // the test server's certificate is self-signed
				u.RawQuery = q.Encode()
				link = u.String()
			}
			node, e := ParseRemoteNode(link)
			if e != nil {
				t.Fatal(e)
			}
			sc := newChainSceneProto(t, a, *node, relayProtocol)
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
				res, e := (&http.Client{Transport: tr, Timeout: 8 * time.Second}).Do(req)
				if e != nil {
					return "", e
				}
				defer res.Body.Close()
				b, e := io.ReadAll(io.LimitReader(res.Body, 64))
				return string(b), e
			}
			expect := func(p Profile, host, ip string) {
				t.Helper()
				if got, e := get(p, host); e != nil || got != ip {
					t.Fatalf("%s Host %s: got %q %v, want exit %s", p.Name, host, got, e, ip)
				}
			}
			// AI traffic of the bound node: node → relay (UDP) → remote Hysteria2/TUIC server →
			// its SOCKS5 egress, so the origin sees 127.0.0.2. Everything else leaves from here.
			n := caHits.Load()
			expect(sc.nodeA, "api.openai.com", "127.0.0.2")
			if caHits.Load() != n+1 {
				t.Fatal("the AI request did not cross the remote server")
			}
			expect(sc.nodeA, "www.example.com", "127.0.0.1")
			expect(sc.node, "api.openai.com", "127.0.0.1")
			expect(sc.node, "www.example.com", "127.0.0.1")
			if caHits.Load() != n+1 {
				t.Fatal("ordinary or unbound traffic used the AI exit")
			}
			// The AI exit test: real QUIC probes, a real engine client and the observed address.
			env := defaultDiagEnv()
			env.fullProxy = engineExitProbe("http://" + origin + "/ip")
			rep, e := a.diagnoseAI(context.Background(), env, diagOpts{Full: true})
			if e != nil {
				t.Fatal(e)
			}
			if _, failed := rep.Failed(); failed || !rep.Has(6, diagOK) || !strings.Contains(rep.Text(), "127.0.0.2") {
				t.Fatalf("diagnosis:\n%s", rep.Text())
			}
			t.Logf("%s over a %s relay: AI exit test (loopback, real engines):\n%s", protocol, relayProtocol, rep.Text())
			// Fail closed: with the relay gone the AI request fails and never takes the
			// original route; ordinary traffic still works.
			stopRelay()
			before := hits.Load()
			if got, e := get(sc.nodeA, "api.openai.com"); e == nil {
				t.Fatalf("the AI request succeeded without the relay: %q", got)
			}
			if hits.Load() != before {
				t.Fatal("the AI request leaked through the original route")
			}
			expect(sc.nodeA, "www.example.com", "127.0.0.1")
			// And the diagnosis names the broken layer instead of claiming an exit.
			rep, _ = a.diagnoseAI(context.Background(), env, diagOpts{Full: true})
			if _, failed := rep.Failed(); !failed || rep.Has(6, diagOK) {
				t.Fatalf("a dead relay was not reported:\n%s", rep.Text())
			}
		})
	}
}
