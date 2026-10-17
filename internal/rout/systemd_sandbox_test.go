package rout

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Every protocol must keep working under the systemd sandbox, and the engine process
// must really hold only the capabilities Rout grants. Disposable root/systemd host only.
func TestIntegrationSystemdSandboxProtocols(t *testing.T) {
	if os.Getenv("ROUT_TEST_SYSTEMD") != "1" {
		t.Skip("set ROUT_TEST_SYSTEMD=1 on a disposable root/systemd test host")
	}
	verified := integrationApp(t)
	root, e := os.MkdirTemp("/var/lib", "rout-sandbox-")
	if e != nil {
		t.Fatal(e)
	}
	a := &App{Home: filepath.Join(root, "config"), BinDir: filepath.Join(root, "bin"), ServiceMode: "auto"}
	for _, n := range []string{"sing-box", "gost"} {
		b, e := os.ReadFile(verified.enginePath(n))
		if e != nil {
			t.Fatal(e)
		}
		if e = AtomicWrite(a.enginePath(n), b, 0755); e != nil {
			t.Fatal(e)
		}
	}
	t.Cleanup(func() {
		if s, e := a.Load(); e == nil {
			_ = a.Commit(s, State{Schema: 1, Profiles: []Profile{}}, false)
		}
		_ = os.RemoveAll(root)
	})
	// Reality borrows a real TLS 1.3 handshake from SNI:443; serve it locally.
	cert, key, camouflage := tlsFixture(t)
	camHost, camPort, _ := ParseEndpoint(strings.TrimPrefix(camouflage.URL, "https://"))
	l, e := net.Listen("tcp", "127.0.0.1:443")
	if e != nil {
		t.Skip("port 443 unavailable for the Reality handshake target", e)
	}
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			go func() {
				up, e := net.Dial("tcp", net.JoinHostPort(camHost, strconv.Itoa(camPort)))
				if e != nil {
					c.Close()
					return
				}
				copyTunnel(c, up)
			}()
		}
	}()
	t.Cleanup(func() { l.Close() })
	hosts, _ := os.ReadFile("/etc/hosts")
	if e = os.WriteFile("/etc/hosts", append(append([]byte{}, hosts...), []byte("\n127.0.0.1 example.test\n")...), 0644); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = os.WriteFile("/etc/hosts", hosts, 0644) })
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "198.51.100.19") }))
	defer origin.Close()
	capabilities := func(p Profile) string {
		pid := servicePID("systemd", serviceName(p))
		b, e := os.ReadFile("/proc/" + pid + "/status")
		if e != nil {
			t.Fatal(e)
		}
		for _, line := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(line, "CapBnd:"); ok {
				return strings.TrimSpace(v)
			}
		}
		return ""
	}
	for _, protocol := range []string{"vless", "anytls", "ss", "hy2", "tuic"} {
		t.Run(protocol, func(t *testing.T) {
			p := fixture(t, protocol)
			p.Port, _ = freePort()
			p.PublicPort = p.Port
			p.SNI = "example.test"
			p.CertPEM, p.KeyPEM = cert, key
			s, _ := a.Load()
			if e := a.Commit(s, replace(s, p), false); e != nil {
				t.Fatal(e)
			}
			want := "0000000000000400" // CAP_NET_BIND_SERVICE
			if protocol == "hy2" || protocol == "tuic" {
				want = "0000000000001400" // + CAP_NET_ADMIN for QUIC socket buffers
			}
			if got := capabilities(p); got != want {
				t.Fatal("unexpected engine capability bounding set", got)
			}
			port, _ := freePort()
			client, e := ClientConfig(p, "127.0.0.1", p.Port, port)
			if e != nil {
				t.Fatal(e)
			}
			e = a.withClient(client, port, func(proxy string) error {
				ip, e := fetchIP(proxy, origin.URL)
				if e == nil && ip != "198.51.100.19" {
					e = fmt.Errorf("unexpected response %q", ip)
				}
				return e
			})
			if e != nil {
				t.Fatal("sandboxed engine failed to carry traffic", e)
			}
		})
	}
	for _, network := range []string{"tcp", "udp"} {
		t.Run("relay-"+network, func(t *testing.T) {
			var target string
			if network == "tcp" {
				echo, _ := net.Listen("tcp", "127.0.0.1:0")
				defer echo.Close()
				go func() {
					for {
						c, e := echo.Accept()
						if e != nil {
							return
						}
						go func() { defer c.Close(); io.Copy(c, c) }()
					}
				}()
				target = echo.Addr().String()
			} else {
				echo, _ := net.ListenPacket("udp", "127.0.0.1:0")
				defer echo.Close()
				go func() {
					b := make([]byte, 512)
					for {
						n, addr, e := echo.ReadFrom(b)
						if e != nil {
							return
						}
						echo.WriteTo(b[:n], addr)
					}
				}()
				target = echo.LocalAddr().String()
			}
			port, _ := freePort()
			p := Profile{ID: RandomHex(6), Name: "relay-" + network, Kind: "relay", Enabled: true, Protocol: network, Listen: "127.0.0.1", Port: port, PublicHost: "203.0.113.1", PublicPort: port, Target: target}
			s, _ := a.Load()
			if e := a.Commit(s, replace(s, p), false); e != nil {
				t.Fatal(e)
			}
			if got := capabilities(p); got != "0000000000000400" {
				t.Fatal("unexpected relay capability bounding set", got)
			}
			c, e := net.DialTimeout(network, net.JoinHostPort("127.0.0.1", itoa(port)), time.Second)
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(3 * time.Second))
			c.Write([]byte("ping"))
			b := make([]byte, 4)
			if _, e = io.ReadFull(c, b); e != nil || string(b) != "ping" {
				t.Fatal("sandboxed relay failed", e)
			}
		})
	}
}
