package rout

import (
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// This proxy never dials the public internet. Every CONNECT goes to the controlled
// origin, while separate counters prove which exit actually carried each request.
func aiProxyFixture(t *testing.T, origin, network string, encrypted bool, expired ...bool) (Proxy, *atomic.Int32, *atomic.Bool, string) {
	t.Helper()
	count, broken := &atomic.Int32{}, &atomic.Bool{}
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" || r.Header.Get("Proxy-Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte("fixture-user:fixture-password")) {
			w.WriteHeader(407)
			return
		}
		if broken.Load() {
			w.WriteHeader(502)
			return
		}
		up, err := net.DialTimeout("tcp", origin, time.Second)
		if err != nil {
			w.WriteHeader(502)
			return
		}
		down, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			up.Close()
			return
		}
		count.Add(1)
		fmt.Fprint(buf, "HTTP/1.1 200 Connection Established\r\n\r\n")
		buf.Flush()
		copyTunnel(down, up)
	}))
	s.Listener.Close()
	address := "127.0.0.1:0"
	if network == "tcp6" {
		address = "[::1]:0"
	}
	l, err := net.Listen(network, address)
	if err != nil {
		t.Skipf("%s loopback unavailable: %v", network, err)
	}
	s.Listener = l
	cert := ""
	protocol := "http"
	if encrypted {
		host, _, _ := net.SplitHostPort(l.Addr().String())
		var key string
		cert, key, err = GenerateCertificate(host)
		if err != nil {
			t.Fatal(err)
		}
		pair, err := tls.X509KeyPair([]byte(cert), []byte(key))
		if err != nil {
			t.Fatal(err)
		}
		if len(expired) > 0 && expired[0] {
			leaf, err := x509.ParseCertificate(pair.Certificate[0])
			if err != nil {
				t.Fatal(err)
			}
			leaf.NotBefore, leaf.NotAfter = time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour)
			der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, pair.PrivateKey.(crypto.Signer).Public(), pair.PrivateKey)
			if err != nil {
				t.Fatal(err)
			}
			cert = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
			pair.Certificate = [][]byte{der}
		}
		s.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
		s.StartTLS()
		protocol = "https"
	} else {
		s.Start()
	}
	t.Cleanup(s.Close)
	h, p, err := ParseEndpoint(l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return Proxy{protocol, h, p, "fixture-user", "fixture-password"}, count, broken, cert
}

// Unlike service tests, these processes need no root or init system. Explicit stop
// permits checking enable/disable against real, freshly loaded generated configs.
func aiProcess(t *testing.T, binary, path string, port int) func() {
	t.Helper()
	logPath := filepath.Join(t.TempDir(), "engine.log")
	log, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "run", "-c", path)
	cmd.Stdout, cmd.Stderr = log, log
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var once sync.Once
	stop := func() { once.Do(func() { cmd.Process.Kill(); <-done; log.Close() }) }
	t.Cleanup(func() {
		stop()
		if t.Failed() {
			b, _ := os.ReadFile(logPath)
			t.Log(string(b))
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, e := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(port)), 50*time.Millisecond)
		if e == nil {
			c.Close()
			return stop
		}
		time.Sleep(25 * time.Millisecond)
	}
	stop()
	t.Fatal("sing-box did not listen")
	return stop
}

func aiRequest(port int, endpoint, host string, tlsConfig *tls.Config) error {
	proxy, _ := url.Parse("socks5://127.0.0.1:" + itoa(port))
	transport := &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true, TLSClientConfig: tlsConfig}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 4 * time.Second}
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return err
	}
	if host != "" {
		req.Host = host
	}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 64))
	if err != nil {
		return err
	}
	if string(b) != "controlled-origin" {
		return fmt.Errorf("unexpected response %q", b)
	}
	return nil
}

func TestIntegrationAINetwork(t *testing.T) {
	if os.Getenv("ROUT_SKIP_SINGBOX_RUNTIME") == "1" {
		t.Skip("runtime explicitly disabled; AI traffic NOT verified")
	}
	for _, network := range []string{"tcp4", "tcp6"} {
		t.Run(network, func(t *testing.T) {
			a := integrationApp(t)
			originHits := &atomic.Int32{}
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { originHits.Add(1); fmt.Fprint(w, "controlled-origin") }))
			defer origin.Close()
			original, originalCount, _, _ := aiProxyFixture(t, strings.TrimPrefix(origin.URL, "http://"), network, false)
			canada, canadaCount, broken, _ := aiProxyFixture(t, strings.TrimPrefix(origin.URL, "http://"), network, false)
			ca := Exit{ID: RandomHex(6), Name: "Canada", Proxy: canada}
			old, err := a.Load()
			if err != nil {
				t.Fatal(err)
			}
			next := UpsertExit(old, ca)
			var nodes []Profile
			for i := 0; i < 3; i++ {
				p := fixture(t, "ss")
				p.Name = fmt.Sprintf("node-%d", i)
				p.Port, _ = freePort()
				p.PublicPort = p.Port
				p.Outbound = &original
				nodes = append(nodes, p)
				next = replace(next, p)
			}
			next.AI = &AIRouting{Enabled: true, BoundInboundIDs: []string{nodes[0].ID, nodes[2].ID}, AIOutboundID: ca.ID, RuleSetVersion: AIRuleSetCurrent}
			if err = a.Commit(old, next, false); err != nil {
				t.Fatal(err)
			}
			stops := map[string]func(){}
			ports := map[string]int{}
			for _, p := range nodes {
				stops[p.ID] = aiProcess(t, a.enginePath("sing-box"), filepath.Join(a.profileDir(p.ID), "config.json"), p.Port)
				port, _ := freePort()
				client, err := ClientConfig(p, "127.0.0.1", p.Port, port)
				if err != nil {
					t.Fatal(err)
				}
				aiProcess(t, a.enginePath("sing-box"), configFile(t, client), port)
				ports[p.ID] = port
			}
			check := func(p Profile, endpoint, host, route string, success bool) {
				t.Helper()
				us, ca, hits := originalCount.Load(), canadaCount.Load(), originHits.Load()
				err := aiRequest(ports[p.ID], endpoint, host, nil)
				if (err == nil) != success {
					t.Fatalf("%s %s expected success=%t: %v", p.Name, route, success, err)
				}
				if !success {
					if originHits.Load() != hits || originalCount.Load() != us {
						t.Fatal("failed AI connection leaked to original exit/origin")
					}
					return
				}
				if originHits.Load() != hits+1 {
					t.Fatal("request did not reach controlled origin exactly once")
				}
				if route == "ai" {
					if canadaCount.Load() != ca+1 || originalCount.Load() != us {
						t.Fatal("AI request used wrong exit")
					}
				} else if originalCount.Load() != us+1 || canadaCount.Load() != ca {
					t.Fatal("ordinary/unbound traffic changed exit")
				}
			}
			for _, p := range []Profile{nodes[0], nodes[2]} {
				check(p, "http://chat.openai.com/", "", "ai", true) // explicit domain, resolved at exit
				check(p, "http://CHAT.OPENAI.COM./", "", "ai", true)
				check(p, "http://CHAT.OPENAI.COM/", "", "ai", true)
				check(p, "http://chat.openai.com./", "", "ai", true)
				check(p, origin.URL, "chat.openai.com", "ai", true)                // IP destination + HTTP sniff
				check(p, "http://chat.openai.com/", "www.example.com", "ai", true) // sniff must not hide explicit AI destination
				check(p, "http://www.example.com/", "", "original", true)
				check(p, "http://notopenai.com/", "", "original", true)
				check(p, "http://openai.com.evil.invalid/", "", "original", true)
				check(p, origin.URL, "", "original", true) // pure IP, no AI Host: documented limitation
			}
			check(nodes[1], "http://chat.openai.com/", "", "original", true)
			check(nodes[1], "http://www.example.com/", "", "original", true)
			broken.Store(true)
			check(nodes[0], "http://chat.openai.com/", "", "ai", false)
			check(nodes[0], "http://CHAT.OPENAI.COM./", "", "ai", false)
			check(nodes[0], origin.URL, "chat.openai.com", "ai", false)
			check(nodes[0], "http://www.example.com/", "", "original", true)
			check(nodes[1], "http://chat.openai.com/", "", "original", true)
			_, unboundBefore := readConfigFile(t, a, nodes[1])
			if err = a.SetAIEnabled(false); err != nil {
				t.Fatal(err)
			}
			for _, p := range []Profile{nodes[0], nodes[2]} {
				stops[p.ID]()
				stops[p.ID] = aiProcess(t, a.enginePath("sing-box"), filepath.Join(a.profileDir(p.ID), "config.json"), p.Port)
				check(p, "http://chat.openai.com/", "", "original", true)
			}
			_, unboundAfter := readConfigFile(t, a, nodes[1])
			before, _ := JSON(unboundBefore)
			after, _ := JSON(unboundAfter)
			if string(before) != string(after) {
				t.Fatal("disable rewrote unbound node")
			}
			state, err := a.Load()
			if err != nil || state.AI.Enabled || len(state.AI.BoundInboundIDs) != 2 {
				t.Fatal("disable lost bindings", err)
			}
		})
	}
}

func TestIntegrationHTTPSConnect(t *testing.T) {
	if os.Getenv("ROUT_SKIP_SINGBOX_RUNTIME") == "1" {
		t.Skip("runtime explicitly disabled; HTTPS CONNECT NOT verified")
	}
	a := integrationApp(t)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "controlled-origin") }))
	defer origin.Close()
	proxy, count, _, cert := aiProxyFixture(t, strings.TrimPrefix(origin.URL, "http://"), "tcp4", true)
	for _, mode := range []string{"trusted", "untrusted", "expired", "wrong-name", "wrong-auth", "plaintext-peer"} {
		t.Run(mode, func(t *testing.T) {
			p := proxy
			trust := cert
			if mode == "expired" {
				p, _, _, trust = aiProxyFixture(t, strings.TrimPrefix(origin.URL, "http://"), "tcp4", true, true)
			}
			if mode == "wrong-auth" {
				p.Password = "incorrect"
			}
			if mode == "plaintext-peer" {
				p, _, _, _ = aiProxyFixture(t, strings.TrimPrefix(origin.URL, "http://"), "tcp4", false)
				p.Protocol = "https"
			}
			out := proxyConfig(p)
			if mode != "untrusted" {
				out["tls"].(M)["certificate"] = []string{trust}
			} // isolated test trust, production uses system roots
			if mode == "wrong-name" {
				out["tls"].(M)["server_name"] = "wrong.invalid"
			}
			port, _ := freePort()
			cfg := M{"inbounds": []any{M{"type": "mixed", "listen": "127.0.0.1", "listen_port": port}}, "outbounds": []any{out}, "route": M{"final": "egress"}, "log": M{"level": "warn"}}
			path := configFile(t, cfg)
			if err := a.checkConfig(path); err != nil {
				t.Fatal(err)
			}
			aiProcess(t, a.enginePath("sing-box"), path, port)
			before := count.Load()
			err := aiRequest(port, "http://chat.openai.com/", "", nil)
			if mode == "trusted" {
				if err != nil || count.Load() != before+1 {
					t.Fatal("verified HTTPS CONNECT failed", err)
				}
			} else if err == nil || count.Load() != before {
				t.Fatal("invalid HTTPS proxy was used or fell back to plaintext", err)
			}
		})
	}
}

func TestIntegrationAIUDP(t *testing.T) {
	if os.Getenv("ROUT_SKIP_SINGBOX_RUNTIME") == "1" {
		t.Skip("runtime explicitly disabled; UDP NOT verified")
	}
	a := integrationApp(t)
	sink, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	go func() {
		b := make([]byte, 2048)
		for {
			n, peer, err := sink.ReadFrom(b)
			if err != nil {
				return
			}
			sink.WriteTo(b[:n], peer)
		}
	}()
	_, sinkPort, err := ParseEndpoint(sink.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	for _, bound := range []bool{true, false} {
		t.Run(fmt.Sprint("bound=", bound), func(t *testing.T) {
			p := fixture(t, "ss")
			p.Port, _ = freePort()
			p.PublicPort = p.Port
			if bound {
				p.AIRoute = &AIRoute{Outbound: &Proxy{"http", "127.0.0.1", 1, "u", "p"}, RuleSet: AIRuleSetCurrent}
			}
			cfg, err := serverConfig(p, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			// Controlled DNS ensures a missing reject rule would really reach the sink.
			cfg["dns"] = M{"servers": []any{M{"type": "hosts", "tag": "test-hosts", "predefined": M{"chat.openai.com": []string{"127.0.0.1"}}}}}
			cfg["route"].(M)["default_domain_resolver"] = "test-hosts"
			path := configFile(t, cfg)
			if err = a.checkConfig(path); err != nil {
				t.Fatal(err)
			}
			aiProcess(t, a.enginePath("sing-box"), path, p.Port)
			for _, domain := range []string{"127.0.0.1", "chat.openai.com"} {
				tcpPort, _ := freePort()
				udpPort, _ := freePort()
				client, err := ClientConfig(p, "127.0.0.1", p.Port, tcpPort)
				if err != nil {
					t.Fatal(err)
				}
				client["inbounds"] = append(client["inbounds"].([]any), M{"type": "direct", "listen": "127.0.0.1", "listen_port": udpPort, "network": "udp", "override_address": domain, "override_port": sinkPort})
				path := configFile(t, client)
				if err = a.checkConfig(path); err != nil {
					t.Fatal(err)
				}
				aiProcess(t, a.enginePath("sing-box"), path, tcpPort)
				conn, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", itoa(udpPort)))
				if err != nil {
					t.Fatal(err)
				}
				conn.SetDeadline(time.Now().Add(time.Second))
				conn.Write([]byte("controlled-udp"))
				b := make([]byte, 64)
				n, err := conn.Read(b)
				conn.Close()
				rejected := bound && domain == "chat.openai.com"
				if rejected {
					if err == nil {
						t.Fatal("AI UDP escaped to original exit")
					}
				} else if err != nil || string(b[:n]) != "controlled-udp" {
					t.Fatal("ordinary or unbound UDP failed", err)
				}
			}
		})
	}
}

func TestIntegrationAITLSSNI(t *testing.T) {
	if os.Getenv("ROUT_SKIP_SINGBOX_RUNTIME") == "1" {
		t.Skip("runtime explicitly disabled; TLS SNI NOT verified")
	}
	a := integrationApp(t)
	cert, key, err := GenerateCertificate("chat.openai.com")
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair([]byte(cert), []byte(key))
	if err != nil {
		t.Fatal(err)
	}
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "controlled-origin") }))
	origin.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
	origin.StartTLS()
	defer origin.Close()
	ca, count, broken, _ := aiProxyFixture(t, strings.TrimPrefix(origin.URL, "https://"), "tcp4", false)
	p := fixture(t, "ss")
	p.Port, _ = freePort()
	p.PublicPort = p.Port
	p.AIRoute = &AIRoute{Outbound: &ca, RuleSet: AIRuleSetCurrent}
	cfg, err := serverConfig(p, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := configFile(t, cfg)
	if err = a.checkConfig(path); err != nil {
		t.Fatal(err)
	}
	aiProcess(t, a.enginePath("sing-box"), path, p.Port)
	port, _ := freePort()
	client, err := ClientConfig(p, "127.0.0.1", p.Port, port)
	if err != nil {
		t.Fatal(err)
	}
	aiProcess(t, a.enginePath("sing-box"), configFile(t, client), port)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(cert)) {
		t.Fatal("test root invalid")
	}
	targetTLS := &tls.Config{RootCAs: roots, ServerName: "chat.openai.com", MinVersion: tls.VersionTLS12}
	if err = aiRequest(port, origin.URL, "", targetTLS); err != nil || count.Load() != 1 {
		t.Fatal("IP + TLS SNI not routed through AI exit", err)
	}
	broken.Store(true)
	if err = aiRequest(port, origin.URL, "", targetTLS); err == nil || count.Load() != 1 {
		t.Fatal("TLS SNI AI request fell back after exit failed", err)
	}
}
