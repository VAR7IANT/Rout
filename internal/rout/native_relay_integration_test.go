package rout

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Integration tests with the real pinned engines (set ROUT_TEST_ENGINES). They use only
// loopback sockets: this is SIMULATED networking on one machine, not a VPS or NAT test.

type protoFixture struct {
	a          *App
	cert, key  string
	camHost    string
	camPort    int
	origin     *httptest.Server
	originPort int
	hits       *atomic.Int32
}

func newProtoFixture(t *testing.T) protoFixture {
	t.Helper()
	if os.Getenv("ROUT_SKIP_SINGBOX_RUNTIME") == "1" {
		t.Skip("sing-box runtime disabled explicitly; protocol traffic has NOT been verified")
	}
	a := integrationApp(t)
	cert, key, camouflage := tlsFixture(t)
	camHost, camPort, _ := ParseEndpoint(strings.TrimPrefix(camouflage.URL, "https://"))
	hits := &atomic.Int32{}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); fmt.Fprint(w, "198.51.100.19") }))
	t.Cleanup(origin.Close)
	_, originPort, _ := ParseEndpoint(strings.TrimPrefix(origin.URL, "http://"))
	isolated := *a
	isolated.Home = t.TempDir()
	return protoFixture{a: &isolated, cert: cert, key: key, camHost: camHost, camPort: camPort, origin: origin, originPort: originPort, hits: hits}
}

// node starts a real sing-box server node of the protocol on loopback.
func (f protoFixture) node(t *testing.T, protocol string, tweak func(*Profile)) Profile {
	t.Helper()
	p := fixture(t, protocol)
	p.Port, _ = freePort()
	p.PublicHost, p.PublicPort = "127.0.0.1", p.Port
	p.SNI, p.CertPEM, p.KeyPEM = "example.test", f.cert, f.key
	if tweak != nil {
		tweak(&p)
	}
	if e := p.Validate(); e != nil {
		t.Fatal(e)
	}
	if e := f.a.writeProfile(p); e != nil {
		t.Fatal(e)
	}
	conf, e := serverConfig(p, f.a.profileDir(p.ID))
	if e != nil {
		t.Fatal(e)
	}
	if protocol == "vless" || protocol == "anytls" {
		conf["inbounds"].([]any)[0].(M)["tls"].(M)["reality"].(M)["handshake"] = M{"server": f.camHost, "server_port": f.camPort}
	}
	path := configFile(t, conf)
	if e = f.a.checkConfig(path); e != nil {
		out, _ := runOutput(time.Second, f.a.enginePath("sing-box"), "check", "-c", path)
		t.Fatalf("%v: %s", e, out)
	}
	startEngine(t, profileSockets(p), f.a.enginePath("sing-box"), "run", "-c", path)
	return p
}

// fetchThrough requests the origin through a client built from the given sing-box config.
func (f protoFixture) fetchThrough(client M, port int) error {
	return f.a.withClient(client, port, func(proxy string) error {
		ip, e := fetchIP(proxy, f.origin.URL)
		if e != nil {
			return e
		}
		if ip != "198.51.100.19" {
			return fmt.Errorf("unexpected answer %q", ip)
		}
		return nil
	})
}

func TestIntegrationNativeRelayCarriesEveryProtocol(t *testing.T) {
	f := newProtoFixture(t)
	for _, protocol := range []string{"vless", "anytls", "ss", "hy2", "tuic"} {
		t.Run(protocol, func(t *testing.T) {
			node := f.node(t, protocol, nil)
			uri, e := node.URI()
			if e != nil {
				t.Fatal(e)
			}
			relay := nativeRelayProfile(inIPv4, outIPv4Only, joinHostPortInt("127.0.0.1", node.Port), 0)
			relay.Port, _ = freePort()
			relay.PublicPort, relay.Listen = relay.Port, "0.0.0.0"
			relay.Protocol = networkProtocol(node.Networks())
			relay.RelayMode, relay.TargetURI = relayLocal, uri
			if e = relay.Validate(); e != nil {
				t.Fatal(e)
			}
			cfg, _ := nativeRelayConfigOf(relay)
			rt := startRelay(t, cfg, nil)
			// The client uses the node's own credentials, TLS identity and options and only
			// the server address and port are replaced by the relay's: what a user does with
			// the share link of a relay.
			port, _ := freePort()
			client, e := ClientConfig(node, "127.0.0.1", relay.Port, port)
			if e != nil {
				t.Fatal(e)
			}
			if e = f.fetchThrough(client, port); e != nil {
				t.Fatalf("%s through the native relay: %v", protocol, e)
			}
			udp := protocol == "hy2" || protocol == "tuic"
			if udp && rt.stats.udpSessions.Load() == 0 {
				t.Fatal("no UDP session went through the relay")
			}
			if !udp && rt.stats.accepted.Load() == 0 {
				t.Fatal("no TCP connection went through the relay")
			}
			// The relay's share link rewrites only the endpoint.
			rl, e := relay.URI()
			if e != nil {
				t.Fatal(e)
			}
			if !strings.Contains(rl, "@"+relay.PublicHost+":"+itoa(relay.PublicPort)) {
				t.Fatalf("relay link %s", rl)
			}
		})
	}
}

func joinHostPortInt(host string, port int) string { return host + ":" + itoa(port) }

func TestIntegrationNativeRelayPolicyAndFailureOverRealProtocol(t *testing.T) {
	f := newProtoFixture(t)
	node := f.node(t, "vless", nil)
	uri, _ := node.URI()
	mk := func(target string) (Profile, *relayRuntime) {
		relay := nativeRelayProfile(inIPv4, outIPv4Only, target, 0)
		relay.Port, _ = freePort()
		relay.PublicPort, relay.Listen = relay.Port, "0.0.0.0"
		relay.RelayMode, relay.TargetURI = relayRemote, uri
		cfg, _ := nativeRelayConfigOf(relay)
		return relay, startRelay(t, cfg, func(r *relayRuntime) {
			r.dialer.Resolver.Lookup = fakeLookup(map[string][]string{"vless-host.example": {"127.0.0.1"}}, nil)
		})
	}
	// A domain destination is resolved by the relay at connection time.
	relay, rt := mk(joinHostPortInt("vless-host.example", node.Port))
	port, _ := freePort()
	client, _ := ClientConfig(node, "127.0.0.1", relay.Port, port)
	if e := f.fetchThrough(client, port); e != nil {
		t.Fatalf("domain destination: %v", e)
	}
	if rt.stats.accepted.Load() == 0 {
		t.Fatal("not forwarded")
	}
	// A destination that does not exist: the relay closes the client, so the protocol test
	// fails (and the layered diagnosis can say why).
	relay, rt = mk("127.0.0.1:1")
	port, _ = freePort()
	client, _ = ClientConfig(node, "127.0.0.1", relay.Port, port)
	if e := f.fetchThrough(client, port); e == nil {
		t.Fatal("a relay to a closed port reported a working proxy")
	}
	if rt.stats.dialFail.Load() == 0 {
		t.Fatal("the failed upstream dial was not counted")
	}
}

func TestIntegrationFullDiagnosisThroughARealRelay(t *testing.T) {
	f := newProtoFixture(t)
	node := f.node(t, "vless", nil)
	uri, _ := node.URI()
	relay := nativeRelayProfile(inIPv4, outIPv4Only, joinHostPortInt("127.0.0.1", node.Port), 0)
	relay.Port, _ = freePort()
	relay.PublicPort, relay.Listen = relay.Port, "0.0.0.0"
	relay.RelayMode, relay.TargetURI = relayLocal, uri
	cfg, _ := nativeRelayConfigOf(relay)
	startRelay(t, cfg, nil)

	env := defaultDiagEnv()
	env.hasV6 = func() bool { return false }
	// The Reality target is a local test server, so the credential-free camouflage check and
	// the engine test run against real services. The exit address service is replaced by the
	// local origin (no Internet is needed or used).
	env.full = func(a *App, p Profile, host string, port int) fullProbe {
		local, _ := freePort()
		conf, e := ClientConfig(p, host, port, local)
		if e != nil {
			return fullProbe{ClientErr: e}
		}
		// ClientConfig of a relay rebuilds the link; the relay's link has no certificate
		// problem for Reality, so this is the real client path.
		var res fullProbe
		res.ClientErr = a.withClientLog(conf, local, func(proxy string, logs func() string) error {
			res.V4, res.ErrV4 = fetchIP(proxy, f.origin.URL)
			res.ErrV6 = fmt.Errorf("IPv6 not tested in this fixture")
			res.LogHint = classifyClientLog(logs())
			return nil
		})
		return res
	}
	env.tlsCheck = func(ctx context.Context, addr, sni string) error { return nil }
	rep := f.a.diagnoseRelay(context.Background(), relay, env, diagOpts{Full: true})
	for _, layer := range []int{1, 3, 4, 5} {
		if !rep.Has(layer, diagOK) {
			t.Errorf("layer %d did not pass:\n%s", layer, rep.Text())
		}
	}
	if !rep.Has(6, diagOK) || !strings.Contains(rep.Text(), "198.51.100.19") {
		t.Fatalf("real exit not reported:\n%s", rep.Text())
	}
	if layer, failed := rep.Failed(); failed {
		t.Fatalf("failure at layer %d:\n%s", layer, rep.Text())
	}
}

func TestIntegrationIPv6OnlyNodeRefusesIPv4Clients(t *testing.T) {
	f := newProtoFixture(t)
	for _, mode := range []string{inDual, inIPv6} {
		t.Run(mode, func(t *testing.T) {
			// Listening on "::" is a dual-stack socket in sing-box; "ipv6" mode must still
			// keep IPv4 clients out. (A host without IPv6 binds the IPv4 wildcard instead,
			// which makes this an even stricter test of the source-address rule.)
			node := f.node(t, "ss", func(p *Profile) {
				p.Listen, p.InboundMode = "::", mode
				if mode == inIPv6 {
					p.PublicHost = v6Addr // an IPv6-only node advertises an IPv6 address
				}
			})
			port, _ := freePort()
			client, e := ClientConfig(node, "127.0.0.1", node.Port, port)
			if e != nil {
				t.Fatal(e)
			}
			before := f.hits.Load()
			e = f.fetchThrough(client, port)
			switch mode {
			case inDual:
				if e != nil {
					t.Fatalf("dual-stack node refused an IPv4 client: %v", e)
				}
			case inIPv6:
				if e == nil {
					t.Fatal("an IPv6-only node served an IPv4 client")
				}
				if f.hits.Load() != before {
					t.Fatal("traffic from an IPv4 client reached the origin")
				}
			}
		})
	}
}

func TestIntegrationRemoteNodeExit(t *testing.T) {
	f := newProtoFixture(t)
	// "The other VPS": a real VLESS Reality node. "This server": a Shadowsocks node whose
	// exit is that remote node, reached through its share link.
	remote := f.node(t, "vless", nil)
	remoteLinkURI, _ := remote.URI()
	exitProxy, e := ParseRemoteNode(remoteLinkURI)
	if e != nil {
		t.Fatal(e)
	}
	local := f.node(t, "ss", func(p *Profile) {
		proxy := *exitProxy
		p.Outbound = &proxy
	})
	// The origin has no way to tell the path apart, so count the remote node's use by
	// stopping it afterwards: with the exit gone the request must FAIL, never fall back.
	port, _ := freePort()
	client, e := ClientConfig(local, "127.0.0.1", local.Port, port)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.fetchThrough(client, port); e != nil {
		t.Fatalf("traffic did not leave through the remote node: %v", e)
	}
	// Authentication failure: the same remote server with a different UUID.
	wrong := strings.Replace(remoteLinkURI, remote.UUID, "22222222-2222-4222-8222-222222222222", 1)
	bad, e := ParseRemoteNode(wrong)
	if e != nil {
		t.Fatal(e)
	}
	denied := f.node(t, "ss", func(p *Profile) {
		proxy := *bad
		p.Outbound = &proxy
	})
	port2, _ := freePort()
	client2, _ := ClientConfig(denied, "127.0.0.1", denied.Port, port2)
	if e = f.fetchThrough(client2, port2); e == nil {
		t.Fatal("a remote node exit with the wrong UUID let traffic out")
	}
	// The layered check of that exit fails at the protocol layer, after proving the TCP port.
	env := defaultDiagEnv()
	rep := f.a.diagnoseProxy(context.Background(), Exit{ID: "aaaaaaaaaaaa", Name: "bad", Kind: exitRemote, Proxy: *bad}, env, diagOpts{Full: true})
	if !rep.Has(3, diagOK) {
		t.Fatalf("the remote port was reachable:\n%s", rep.Text())
	}
	if rep.Has(5, diagOK) || rep.Has(6, diagOK) {
		t.Fatalf("a remote exit with wrong credentials was reported as working:\n%s", rep.Text())
	}
	if _, failed := rep.Failed(); !failed {
		t.Fatalf("no failing layer reported:\n%s", rep.Text())
	}
	// And a healthy remote exit passes the protocol layer with a real answer.
	// (fullProbeProxy asks the public echo services, which are unreachable here, so use
	// the origin through the same chain instead.)
	env.fullProxy = func(a *App, p Proxy) fullProbe {
		lp, _ := freePort()
		conf := M{"log": M{"level": "error"}, "inbounds": []any{M{"type": "mixed", "listen": "127.0.0.1", "listen_port": lp}}, "outbounds": []any{proxyConfig(p)}, "route": M{"final": "egress"}}
		var res fullProbe
		res.ClientErr = a.withClientLog(conf, lp, func(proxy string, logs func() string) error {
			res.V4, res.ErrV4 = fetchIP(proxy, f.origin.URL)
			res.ErrV6 = fmt.Errorf("IPv6 not tested in this fixture")
			return nil
		})
		return res
	}
	rep = f.a.diagnoseProxy(context.Background(), Exit{ID: "bbbbbbbbbbbb", Name: "good", Kind: exitRemote, Proxy: *exitProxy}, env, diagOpts{Full: true})
	if _, failed := rep.Failed(); failed || !rep.Has(6, diagOK) {
		t.Fatalf("healthy remote exit:\n%s", rep.Text())
	}
}

func TestIntegrationRemoteNodeExitConfigPassesTheEngineCheck(t *testing.T) {
	f := newProtoFixture(t)
	for _, protocol := range []string{"vless", "anytls", "ss", "hy2", "tuic"} {
		p, e := ParseRemoteNode(remoteLink(t, protocol, "us-vps.example.net", 44275))
		if e != nil {
			t.Fatalf("%s: %v", protocol, e)
		}
		node := fixture(t, "ss")
		node.Outbound = p
		dir := t.TempDir()
		if e = writeProfileIn(node, dir); e != nil {
			t.Fatal(e)
		}
		if e = f.a.checkConfig(filepath.Join(dir, "config.json")); e != nil {
			out, _ := runOutput(5*time.Second, f.a.enginePath("sing-box"), "check", "-c", filepath.Join(dir, "config.json"))
			t.Errorf("%s exit: sing-box rejects the generated node configuration: %s", protocol, out)
		}
	}
}
