package rout

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func integrationApp(t *testing.T) *App {
	t.Helper()
	dir := os.Getenv("ROUT_TEST_ENGINES")
	if dir == "" {
		t.Skip("set ROUT_TEST_ENGINES to verified engine directory for integration tests")
	}
	a := &App{Home: t.TempDir(), BinDir: dir, ServiceMode: "none"}
	for _, n := range []string{"sing-box", "gost"} {
		if _, e := os.Stat(a.enginePath(n)); e != nil {
			t.Fatal(e)
		}
	}
	return a
}

func TestIntegrationAutomaticHY2NativeURI(t *testing.T) {
	if os.Getenv("ROUT_SKIP_SINGBOX_RUNTIME") == "1" {
		t.Skip("runtime explicitly disabled")
	}
	binary := os.Getenv("ROUT_TEST_HYSTERIA")
	if binary == "" {
		t.Skip("set ROUT_TEST_HYSTERIA for native Hysteria URI and certificate-pin tests")
	}
	a := integrationApp(t)
	u, out := testUI(a, "1\n127.0.0.1\n127.0.0.1\nAuto\n4\nn\ny\n1\nexample.test\n")
	if e := u.create(); e != nil {
		t.Fatalf("HY2 creation failed: %v %s", e, out.String())
	}
	state, e := a.Load()
	if e != nil {
		t.Fatal(e)
	}
	p := state.Profiles[0]
	startEngine(t, profileSockets(p), a.enginePath("sing-box"), "run", "-c", filepath.Join(a.profileDir(p.ID), "config.json"))
	hits := &atomic.Int32{}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); fmt.Fprint(w, "198.51.100.19") }))
	defer origin.Close()
	uri, e := p.URI()
	if e != nil {
		t.Fatal(e)
	}
	port, _ := freePort()
	conf := configFile(t, M{"server": uri, "socks5": M{"listen": net.JoinHostPort("127.0.0.1", itoa(port))}})
	startEngine(t, []engineSocket{{"tcp", port}}, binary, "client", "-c", conf)
	if _, e = fetchIP("socks5://127.0.0.1:"+itoa(port), origin.URL); e != nil {
		t.Fatalf("native HY2 URI request failed: %v", e)
	}
	// Reject a wrong pin. Never allow a client importer to silently discard pinSHA256.
	bad, _ := url.Parse(uri)
	q := bad.Query()
	q.Set("pinSHA256", strings.Repeat("0", 64))
	bad.RawQuery = q.Encode()
	badPort, _ := freePort()
	badConf := configFile(t, M{"server": bad.String(), "socks5": M{"listen": net.JoinHostPort("127.0.0.1", itoa(badPort))}})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "client", "-c", badConf)
	var log strings.Builder
	cmd.Stdout = &log
	cmd.Stderr = &log
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	before := hits.Load()
	err := cmd.Wait()
	if err == nil {
		t.Fatal("client with wrong certificate pin started successfully")
	}
	if hits.Load() != before {
		t.Fatal("wrong pin reached origin")
	}
	if !strings.Contains(strings.ToLower(log.String()), "certificate") {
		t.Fatalf("expected a certificate error: %s", log.String())
	}
}
func tlsFixture(t *testing.T) (string, string, *httptest.Server) {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "example.test"}, DNSNames: []string{"example.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	pk, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	cert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	secret := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}))
	pair, e := tls.X509KeyPair([]byte(cert), []byte(secret))
	if e != nil {
		t.Fatal(e)
	}
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "camouflage") }))
	s.EnableHTTP2 = true
	s.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13}
	s.StartTLS()
	t.Cleanup(s.Close)
	return cert, secret, s
}

// engineSocket is a listener an engine must bind before a test may use it.
type engineSocket struct {
	network string
	port    int
}

func profileSockets(p Profile) []engineSocket {
	var out []engineSocket
	for _, n := range p.Networks() {
		out = append(out, engineSocket{n, p.Port})
	}
	return out
}

const (
	engineReadyTimeout = 5 * time.Second
	engineReadyPoll    = 100 * time.Millisecond
)

// startEngine runs an engine for the rest of the test and returns as soon as every
// ready socket is bound. An engine that exits early, or is not ready within
// engineReadyTimeout, fails the test with its log; the process is always reaped.
func startEngine(t *testing.T, ready []engineSocket, path string, args ...string) {
	t.Helper()
	logPath := filepath.Join(t.TempDir(), "engine.log")
	log, e := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(path, args...)
	cmd.Stdout = log
	cmd.Stderr = log
	if e = cmd.Start(); e != nil {
		log.Close()
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	exited, logged := false, false
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		if !exited {
			select {
			case <-done:
			case <-time.After(2 * time.Second):
			}
		}
		log.Close()
		if t.Failed() && !logged {
			b, _ := os.ReadFile(logPath)
			t.Log(string(b))
		}
	})
	missing := func() []string {
		var out []string
		for _, s := range ready {
			if !socketBound(s.network, s.port) {
				out = append(out, fmt.Sprintf("%s/%d", s.network, s.port))
			}
		}
		return out
	}
	started := time.Now()
	deadline := started.Add(engineReadyTimeout)
	for {
		select {
		case e := <-done:
			exited, logged = true, true
			b, _ := os.ReadFile(logPath)
			t.Fatalf("%s exited after %v before it was ready: %v\n%s", filepath.Base(path), time.Since(started).Round(time.Millisecond), e, b)
		default:
		}
		wait := missing()
		if len(wait) == 0 {
			return
		}
		if time.Now().After(deadline) {
			logged = true
			b, _ := os.ReadFile(logPath)
			t.Fatalf("%s not ready after %v; not listening on %s\n%s", filepath.Base(path), engineReadyTimeout, strings.Join(wait, ", "), b)
		}
		time.Sleep(engineReadyPoll)
	}
}
func configFile(t *testing.T, c M) string {
	t.Helper()
	b, e := JSON(c)
	if e != nil {
		t.Fatal(e)
	}
	p := filepath.Join(t.TempDir(), "config.json")
	if e = AtomicWrite(p, b, 0600); e != nil {
		t.Fatal(e)
	}
	return p
}
func copyTunnel(a, b net.Conn) {
	defer a.Close()
	defer b.Close()
	done := make(chan struct{}, 1)
	go func() { _, _ = io.Copy(a, b); done <- struct{}{} }()
	_, _ = io.Copy(b, a)
	a.Close()
	b.Close()
	<-done
}
func mapFixtureAddress(addr string) string {
	h, p, e := net.SplitHostPort(addr)
	if e == nil && h == "origin.rout.invalid" {
		return net.JoinHostPort("127.0.0.1", p)
	}
	return addr
}
func httpProxyFixture(t *testing.T) (*Proxy, *atomic.Int32) {
	t.Helper()
	count := &atomic.Int32{}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" || r.Header.Get("Proxy-Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte("test-user:p:a@ss%$")) {
			w.WriteHeader(407)
			return
		}
		up, e := net.Dial("tcp", mapFixtureAddress(r.Host))
		if e != nil {
			w.WriteHeader(502)
			return
		}
		down, buf, e := w.(http.Hijacker).Hijack()
		if e != nil {
			up.Close()
			return
		}
		count.Add(1)
		fmt.Fprint(buf, "HTTP/1.1 200 Connection Established\r\n\r\n")
		buf.Flush()
		copyTunnel(down, up)
	}))
	t.Cleanup(s.Close)
	h, p, _ := ParseEndpoint(strings.TrimPrefix(s.URL, "http://"))
	return &Proxy{"http", h, p, "test-user", "p:a@ss%$"}, count
}
func socksFixture(t *testing.T) (*Proxy, *atomic.Int32) {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { l.Close() })
	count := &atomic.Int32{}
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
				user := make([]byte, int(head[1]))
				io.ReadFull(c, user)
				io.ReadFull(c, head[:1])
				password := make([]byte, int(head[0]))
				io.ReadFull(c, password)
				if string(user) != "test-user" || string(password) != "p:a@ss%$" {
					c.Write([]byte{1, 1})
					return
				}
				c.Write([]byte{1, 0})
				req := make([]byte, 4)
				if _, e := io.ReadFull(c, req); e != nil || req[1] != 1 {
					return
				}
				var host string
				switch req[3] {
				case 1:
					b := make([]byte, 4)
					io.ReadFull(c, b)
					host = net.IP(b).String()
				case 4:
					b := make([]byte, 16)
					io.ReadFull(c, b)
					host = net.IP(b).String()
				case 3:
					b := make([]byte, 1)
					io.ReadFull(c, b)
					name := make([]byte, int(b[0]))
					io.ReadFull(c, name)
					host = string(name)
				default:
					return
				}
				port := make([]byte, 2)
				if _, e := io.ReadFull(c, port); e != nil {
					return
				}
				addr := net.JoinHostPort(host, itoa(int(binary.BigEndian.Uint16(port))))
				up, e := net.Dial("tcp", mapFixtureAddress(addr))
				if e != nil {
					c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				count.Add(1)
				c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
				copyTunnel(c, up)
			}(c)
		}
	}()
	h, p, _ := ParseEndpoint(l.Addr().String())
	return &Proxy{"socks5", h, p, "test-user", "p:a@ss%$"}, count
}
func TestIntegrationProtocolsAndProxyExit(t *testing.T) {
	if os.Getenv("ROUT_SKIP_SINGBOX_RUNTIME") == "1" {
		t.Skip("sing-box runtime disabled explicitly; protocol traffic has NOT been verified")
	}
	a := integrationApp(t)
	cert, key, camouflage := tlsFixture(t)
	camHost, camPort, _ := ParseEndpoint(strings.TrimPrefix(camouflage.URL, "https://"))
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "198.51.100.19") }))
	defer origin.Close()
	_, originPort, _ := ParseEndpoint(strings.TrimPrefix(origin.URL, "http://"))
	for _, protocol := range []string{"vless", "anytls", "ss", "hy2", "tuic"} {
		for _, mode := range []string{"direct", "socks5", "http"} {
			t.Run(protocol+"/"+mode, func(t *testing.T) {
				isolated := *a
				isolated.Home = t.TempDir()
				a := &isolated
				p := fixture(t, protocol)
				p.Port, _ = freePort()
				p.PublicHost = "127.0.0.1"
				p.PublicPort = p.Port
				p.SNI = "example.test"
				p.CertPEM = cert
				p.KeyPEM = key
				var count *atomic.Int32
				if mode == "http" {
					p.Outbound, count = httpProxyFixture(t)
				}
				if mode == "socks5" {
					p.Outbound, count = socksFixture(t)
				}
				if e := p.Validate(); e != nil {
					t.Fatal(e)
				}
				attachProtocolMeter(t, a, p)
				if e := a.writeProfile(p); e != nil {
					t.Fatal(e)
				}
				conf, e := serverConfig(p, a.profileDir(p.ID))
				if e != nil {
					t.Fatal(e)
				}
				if protocol == "vless" || protocol == "anytls" {
					conf["inbounds"].([]any)[0].(M)["tls"].(M)["reality"].(M)["handshake"] = M{"server": camHost, "server_port": camPort}
				}
				path := configFile(t, conf)
				if e = a.checkConfig(path); e != nil {
					out, _ := runOutput(time.Second, a.enginePath("sing-box"), "check", "-c", path)
					t.Fatalf("%v: %s", e, out)
				}
				startEngine(t, profileSockets(p), a.enginePath("sing-box"), "run", "-c", path)
				port, _ := freePort()
				client, e := ClientConfig(p, "127.0.0.1", p.Port, port)
				if e != nil {
					t.Fatal(e)
				}
				endpoint := origin.URL
				if mode != "direct" {
					endpoint = "http://origin.rout.invalid:" + itoa(originPort)
				}
				e = a.withClient(client, port, func(proxy string) error {
					ip, e := fetchIP(proxy, endpoint)
					if e != nil {
						return e
					}
					if ip != "198.51.100.19" {
						return fmt.Errorf("unexpected response")
					}
					return assertProtocolQuota(t, a, p, proxy, endpoint)
				})
				if e != nil {
					t.Fatal(e)
				}
				if count != nil && count.Load() == 0 {
					t.Fatal("request bypassed selected proxy")
				}
			})
		}
	}
}
func TestIntegrationGOSTTCPAndUDP(t *testing.T) {
	a := integrationApp(t)
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			var target string
			if network == "tcp" {
				l, e := net.Listen("tcp", "127.0.0.1:0")
				if e != nil {
					t.Fatal(e)
				}
				defer l.Close()
				target = l.Addr().String()
				go func() {
					for {
						c, e := l.Accept()
						if e != nil {
							return
						}
						go func() { defer c.Close(); io.Copy(c, c) }()
					}
				}()
			} else {
				l, e := net.ListenPacket("udp", "127.0.0.1:0")
				if e != nil {
					t.Fatal(e)
				}
				defer l.Close()
				target = l.LocalAddr().String()
				go func() {
					buf := make([]byte, 512)
					for {
						n, addr, e := l.ReadFrom(buf)
						if e != nil {
							return
						}
						l.WriteTo(buf[:n], addr)
					}
				}()
			}
			port, _ := freePort()
			p := Profile{ID: RandomHex(6), Name: "relay-test", Kind: "relay", Enabled: true, Protocol: network, Listen: "127.0.0.1", Port: port, PublicHost: "203.0.113.1", PublicPort: port, Target: target}
			if e := p.Validate(); e != nil {
				t.Fatal(e)
			}
			c, e := serverConfig(p, t.TempDir())
			if e != nil {
				t.Fatal(e)
			}
			startEngine(t, profileSockets(p), a.enginePath("gost"), "-C", configFile(t, c))
			conn, e := net.DialTimeout(network, net.JoinHostPort("127.0.0.1", itoa(port)), time.Second)
			if e != nil {
				t.Fatal(e)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			conn.Write([]byte("ping"))
			b := make([]byte, 4)
			if _, e = io.ReadFull(conn, b); e != nil || string(b) != "ping" {
				t.Fatalf("relay failed: %v", e)
			}
		})
	}
}
func TestIntegrationExportedURIs(t *testing.T) {
	a := integrationApp(t)
	for _, protocol := range []string{"vless", "anytls", "ss"} {
		t.Run(protocol, func(t *testing.T) {
			p := fixture(t, protocol)
			raw, e := p.URI()
			if e != nil {
				t.Fatal(e)
			}
			out, e := URIOutbound(raw)
			if e != nil {
				t.Fatal(e)
			}
			path := configFile(t, M{"outbounds": []any{out}})
			if e = a.checkConfig(path); e != nil {
				t.Fatal(e)
			}
		})
	}
}

func TestIntegrationConfigSchema(t *testing.T) {
	a := integrationApp(t)
	cert, key, _ := tlsFixture(t)
	for _, protocol := range []string{"vless", "anytls", "ss", "hy2", "tuic"} {
		for _, mode := range []string{"direct", "socks5", "http"} {
			t.Run(protocol+"/"+mode, func(t *testing.T) {
				p := fixture(t, protocol)
				p.SNI = "example.test"
				p.CertPEM = cert
				p.KeyPEM = key
				if mode != "direct" {
					p.Outbound = &Proxy{mode, "proxy.example", 1080, "user", "special:p@ss%$"}
				}
				if e := a.writeProfile(p); e != nil {
					t.Fatal(e)
				}
				for _, path := range []string{filepath.Join(a.profileDir(p.ID), "config.json")} {
					if e := a.checkConfig(path); e != nil {
						out, _ := runOutput(time.Second, a.enginePath("sing-box"), "check", "-c", path)
						t.Fatalf("%v: %s", e, out)
					}
				}
				client, e := ClientConfig(p, p.PublicHost, p.PublicPort, 2080)
				if e != nil {
					t.Fatal(e)
				}
				path := configFile(t, client)
				if e = a.checkConfig(path); e != nil {
					out, _ := runOutput(time.Second, a.enginePath("sing-box"), "check", "-c", path)
					t.Fatalf("%v: %s", e, out)
				}
			})
		}
	}
}

func TestIntegrationServiceLifecycle(t *testing.T) {
	if os.Getenv("ROUT_TEST_SYSTEMD") != "1" {
		t.Skip("set ROUT_TEST_SYSTEMD=1 on a disposable root/systemd test host")
	}
	if os.Geteuid() != 0 {
		t.Fatal("systemd lifecycle test requires root")
	}
	verified := integrationApp(t)
	root, e := os.MkdirTemp("/var/lib", "rout-ci-")
	if e != nil {
		t.Fatal(e)
	}
	a := &App{Home: filepath.Join(root, "config"), BinDir: filepath.Join(root, "bin"), ServiceMode: "auto"}
	if e = os.MkdirAll(a.BinDir, 0755); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(verified.enginePath("sing-box"))
	if e != nil {
		t.Fatal(e)
	}
	if e = AtomicWrite(a.enginePath("sing-box"), b, 0755); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		s, e := a.Load()
		if e == nil {
			if e = a.Commit(s, State{Schema: 1, Profiles: []Profile{}}, false); e != nil {
				t.Errorf("service cleanup failed: %v", e)
			}
		}
		os.RemoveAll(root)
	})
	p := fixture(t, "ss")
	p.Port, _ = freePort()
	p.PublicPort = p.Port
	old, _ := a.Load()
	if e = a.Commit(old, replace(old, p), false); e != nil {
		t.Fatal(e)
	}
	if a.Running(p) != "运行中" {
		t.Fatal("service did not start")
	}
	pid := func(node Profile) string {
		b, e := runOutput(5*time.Second, "systemctl", "show", "--property=MainPID", "--value", serviceName(node)+".service")
		if e != nil {
			t.Fatal(e)
		}
		return strings.TrimSpace(string(b))
	}
	firstPID := pid(p)
	other := fixture(t, "ss")
	other.Port, _ = freePort()
	other.PublicPort = other.Port
	old, _ = a.Load()
	if e = a.Commit(old, replace(old, other), false); e != nil {
		t.Fatal(e)
	}
	if pid(p) != firstPID {
		t.Fatal("creating a node restarted an existing node")
	}
	otherPID := pid(other)
	old, _ = a.Load()
	metadata := p
	metadata.Name = "Renamed"
	metadata.PublicPort++
	if e = a.Commit(old, replace(old, metadata), false); e != nil {
		t.Fatal(e)
	}
	if pid(p) != firstPID || pid(other) != otherPID {
		t.Fatal("metadata edit restarted a node")
	}
	old, _ = a.Load()
	registry := UpsertExit(old, Exit{ID: RandomHex(6), Name: "Independent", Proxy: Proxy{"http", "192.0.2.1", 80, "u", "p"}})
	if e = a.Commit(old, registry, false); e != nil {
		t.Fatal(e)
	}
	if pid(p) != firstPID || pid(other) != otherPID {
		t.Fatal("adding an independent exit restarted nodes")
	}
	if e = a.Restart(p.ID); e != nil {
		t.Fatal(e)
	}
	if pid(p) == firstPID || pid(other) != otherPID {
		t.Fatal("restart affected the wrong nodes")
	}
	hits := &atomic.Int32{}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); fmt.Fprint(w, "198.51.100.19") }))
	defer origin.Close()
	request := func() error {
		port, _ := freePort()
		client, e := ClientConfig(p, "127.0.0.1", p.Port, port)
		if e != nil {
			return e
		}
		return a.withClient(client, port, func(proxy string) error { _, e := fetchIP(proxy, origin.URL); return e })
	}
	if e = request(); e != nil {
		t.Fatal(e)
	}
	if pid(other) != otherPID {
		t.Fatal("rollback restarted an unrelated node")
	}
	// Verify live fail-closed behavior with an unavailable proxy endpoint.
	old, _ = a.Load()
	deadPort, _ := freePort()
	p.Outbound = &Proxy{"http", "127.0.0.1", deadPort, "u", "p"}
	if e = a.Commit(old, replace(old, p), false); e != nil {
		t.Fatal(e)
	}
	before := hits.Load()
	if e = request(); e == nil {
		t.Fatal("unavailable exit unexpectedly succeeded")
	}
	if hits.Load() != before {
		t.Fatal("proxy failure fell back to direct")
	}
	old, _ = a.Load()
	p.Outbound = nil
	if e = a.Commit(old, replace(old, p), false); e != nil {
		t.Fatal(e)
	}
	// A new engine exits after config generation: the previous service must recover.
	if e = AtomicWrite(a.enginePath("gost"), []byte("#!/bin/sh\nexit 42\n"), 0755); e != nil {
		t.Fatal(e)
	}
	old, _ = a.Load()
	broken := p
	broken.Kind = "relay"
	broken.Protocol = "both"
	broken.Target = strings.TrimPrefix(origin.URL, "http://")
	if e = a.Commit(old, replace(old, broken), false); e == nil {
		t.Fatal("expected failed service start")
	}
	restored, e := a.Load()
	if e != nil {
		t.Fatal(e)
	}
	actual, e := Find(restored, p.ID)
	if e != nil || actual.Kind != "node" || a.Running(p) != "运行中" {
		t.Fatal("service rollback failed")
	}
	if e = request(); e != nil {
		t.Fatal(e)
	}
	if pid(other) != otherPID {
		t.Fatal("startup rollback restarted an unrelated node")
	}
	for _, enabled := range []bool{false, true} {
		old, _ = a.Load()
		p.Enabled = enabled
		if e = a.Commit(old, replace(old, p), false); e != nil {
			t.Fatal(e)
		}
		if (a.Running(p) == "运行中") != enabled {
			t.Fatal("service enable/disable mismatch")
		}
	}
}
