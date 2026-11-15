package rout

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestIntegrationSnellRealEngineAcceptsRoutConfiguration runs the real, pinned official
// snell-server (set ROUT_TEST_ENGINES; needs network the first time) on the configuration
// Rout writes, for both versions and every listening / outbound-family variant Rout can
// produce, and proves that the engine really listens where the configuration says.
//
// This is the only check that the INI keys and the version flag Rout relies on are accepted
// by the official binaries; the unit tests can only prove what Rout writes. There are no
// official Snell builds for macOS/arm64 of v5 or for non-Linux platforms, so it runs on Linux.
func TestIntegrationSnellRealEngineAcceptsRoutConfiguration(t *testing.T) {
	dir := os.Getenv("ROUT_TEST_ENGINES")
	if dir == "" {
		t.Skip("set ROUT_TEST_ENGINES to run the real Snell engines")
	}
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		t.Skip("official Snell servers are published for Linux amd64/arm64 only")
	}
	type variant struct {
		name, listen, policy string
		inbound              string
	}
	variants := []variant{
		{"ipv4 wildcard", "0.0.0.0", "", inIPv4},
		{"ipv4 loopback address", "127.0.0.1", "", inIPv4},
		{"ipv4 only egress", "0.0.0.0", outIPv4Only, inIPv4},
	}
	if ipv6LoopbackWorks() {
		variants = append(variants,
			variant{"dual stack wildcard", "::", "", inDual},
			variant{"ipv6 loopback address", "::1", "", inIPv6})
	}
	for _, version := range []string{snellV5, snellV6} {
		version := version
		t.Run("v"+version, func(t *testing.T) {
			a := &App{Home: t.TempDir(), BinDir: dir, ServiceMode: "none", Language: "en"}
			if version == snellV6 && hostLibc() != "glibc" {
				t.Skip("the official Snell v6 build needs glibc")
			}
			engine := snellEngine(version)
			if e := a.EnsureEngine(engine); e != nil {
				t.Fatal(e)
			}
			path := a.enginePath(engine)
			out, e := runOutput(10*time.Second, path, "--version")
			if e != nil || !strings.Contains(strings.ToLower(string(out)), "snell") {
				t.Fatalf("--version: %v %q", e, out)
			}
			t.Logf("engine: %s", strings.TrimSpace(string(out)))

			policies := []variant{}
			if version == snellV6 {
				for _, pol := range []string{outIPv4First, outIPv6First, outIPv4Only, outIPv6Only, outAuto} {
					policies = append(policies, variant{"policy " + pol, "0.0.0.0", pol, inIPv4})
				}
			}
			for _, v := range append(append([]variant{}, variants...), policies...) {
				v := v
				t.Run(v.name, func(t *testing.T) {
					port, e := freePort()
					if e != nil {
						t.Fatal(e)
					}
					p, e := NewProfile(map[string]string{snellV5: "snell", snellV6: "snell6"}[version])
					if e != nil {
						t.Fatal(e)
					}
					p.Name, p.Listen, p.InboundMode, p.OutboundPolicy = "it", v.listen, v.inbound, v.policy
					p.Port, p.PublicPort, p.PublicHost = port, port, "127.0.0.1"
					if v.inbound == inIPv6 {
						p.PublicHost = "::1"
					}
					if e = p.Validate(); e != nil {
						t.Fatal(e)
					}
					profile := filepath.Join(a.Home, "p-"+RandomHex(3))
					if e = writeProfileIn(p, profile); e != nil {
						t.Fatal(e)
					}
					startSnell(t, path, filepath.Join(profile, snellConf), v.listen, port)
				})
			}
		})
	}
}

// startSnell runs the engine and waits until it accepts TCP connections on its address. The
// process is stopped at the end; if it exits early its output is part of the failure.
func startSnell(t *testing.T, engine, conf, listen string, port int) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, engine, "-c", conf)
	var logs bytes.Buffer
	cmd.Stdout, cmd.Stderr = &logs, &logs
	if e := cmd.Start(); e != nil {
		t.Fatal(e)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	defer func() {
		cancel()
		select {
		case <-exited:
		case <-time.After(3 * time.Second):
		}
	}()
	host := listen
	if host == "0.0.0.0" {
		host = "127.0.0.1"
	} else if host == "::" {
		host = "::1"
	}
	addr := net.JoinHostPort(host, itoa(port))
	deadline := time.Now().Add(8 * time.Second)
	for {
		select {
		case e := <-exited:
			t.Fatalf("snell-server exited early (%v) for %s:\n%s", e, filepath.Base(conf), redactPSK(logs.String()))
		default:
		}
		if c, e := net.DialTimeout("tcp", addr, 300*time.Millisecond); e == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("snell-server is not listening on %s:\n%s", addr, redactPSK(logs.String()))
		}
		time.Sleep(100 * time.Millisecond)
	}
	// Listening is not enough: the engine must keep running.
	time.Sleep(500 * time.Millisecond)
	select {
	case e := <-exited:
		t.Fatalf("snell-server stopped after starting (%v):\n%s", e, redactPSK(logs.String()))
	default:
	}
}

func redactPSK(s string) string {
	out := []string{}
	for _, l := range strings.Split(s, "\n") {
		if strings.Contains(strings.ToLower(l), "psk") {
			l = "[line mentioning psk redacted]"
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

// TestIntegrationSnellOnSingBoxThroughAnExit runs a Snell node bound to an exit the way Rout
// runs it then: on sing-box's built-in Snell, with the exit as its outbound. A sing-box Snell
// client fetches a page through it, so the request must cross the node and leave by the exit.
// For v5 the client speaks version 4, which is what Rout tells Surge to use for such a node.
func TestIntegrationSnellOnSingBoxThroughAnExit(t *testing.T) {
	if os.Getenv("ROUT_SKIP_SINGBOX_RUNTIME") == "1" {
		t.Skip("sing-box runtime disabled explicitly; Snell on sing-box has NOT been verified")
	}
	a := integrationApp(t)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "198.51.100.23") }))
	defer origin.Close()
	_, originPort, _ := ParseEndpoint(strings.TrimPrefix(origin.URL, "http://"))
	for _, protocol := range []string{"snell", "snell6"} {
		t.Run(protocol, func(t *testing.T) {
			isolated := *a
			isolated.Home = t.TempDir()
			a := &isolated
			p, e := NewProfile(protocol)
			if e != nil {
				t.Fatal(e)
			}
			p.Name, p.Listen, p.InboundMode = "it", "127.0.0.1", inIPv4
			p.Port, _ = freePort()
			p.PublicHost, p.PublicPort = "127.0.0.1", p.Port
			var count *atomic.Int32
			p.Outbound, count = socksFixture(t)
			if e = p.Validate(); e != nil {
				t.Fatal(e)
			}
			if !p.snellOnSingBox() || a.engineName(p) != "sing-box" {
				t.Fatal("a Snell node with an exit is not run by sing-box")
			}
			if e = a.writeProfile(p); e != nil {
				t.Fatal(e)
			}
			conf, e := serverConfig(p, a.profileDir(p.ID))
			if e != nil {
				t.Fatal(e)
			}
			path := configFile(t, conf)
			if e = a.checkConfig(path); e != nil {
				out, _ := runOutput(time.Second, a.enginePath("sing-box"), "check", "-c", path)
				t.Fatalf("%v: %s", e, redactPSK(string(out)))
			}
			startEngine(t, profileSockets(p), a.enginePath("sing-box"), "run", "-c", path)

			version := 4
			if p.snellSurgeVersion() == snellV6 {
				version = 6
			}
			if line, _ := p.SnellSurgeLine(p.PublicHost, p.PublicPort); !strings.HasSuffix(line, "version="+itoa(version)) {
				t.Fatalf("the Surge line does not match the version the engine speaks: %s", line)
			}
			local, _ := freePort()
			client := M{
				"log":       M{"level": "warn"},
				"inbounds":  []any{M{"type": "mixed", "listen": "127.0.0.1", "listen_port": local}},
				"outbounds": []any{M{"type": "snell", "tag": "node", "server": "127.0.0.1", "server_port": p.Port, "version": version, "psk": p.Password}},
				"route":     M{"final": "node"},
			}
			e = a.withClient(client, local, func(proxy string) error {
				ip, e := fetchIP(proxy, "http://origin.rout.invalid:"+itoa(originPort))
				if e != nil {
					return e
				}
				if ip != "198.51.100.23" {
					return fmt.Errorf("unexpected response")
				}
				return nil
			})
			if e != nil {
				t.Fatal(e)
			}
			if count.Load() == 0 {
				t.Fatal("the request did not leave by the exit")
			}
		})
	}
}

// TestIntegrationSnellRemoteExitReachesOfficialServer checks the remote Snell exit against the
// real official servers: the Surge line Rout prints for a Snell node is pasted as an exit, and
// the sing-box outbound Rout builds from it fetches a page through snell-server v5 (spoken to
// as v4) and v6.
func TestIntegrationSnellRemoteExitReachesOfficialServer(t *testing.T) {
	if os.Getenv("ROUT_SKIP_SINGBOX_RUNTIME") == "1" {
		t.Skip("sing-box runtime disabled explicitly")
	}
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		t.Skip("official Snell servers are published for Linux amd64/arm64 only")
	}
	a := integrationApp(t)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "198.51.100.29") }))
	defer origin.Close()
	for _, protocol := range []string{"snell", "snell6"} {
		t.Run(protocol, func(t *testing.T) {
			if protocol == "snell6" && hostLibc() != "glibc" {
				t.Skip("the official Snell v6 build needs glibc")
			}
			p, e := NewProfile(protocol)
			if e != nil {
				t.Fatal(e)
			}
			if e = a.EnsureEngine(snellEngine(p.snellVersion())); e != nil {
				t.Fatal(e)
			}
			p.Name, p.Listen, p.InboundMode = "far", "127.0.0.1", inIPv4
			p.Port, _ = freePort()
			p.PublicHost, p.PublicPort = "127.0.0.1", p.Port
			if e = p.Validate(); e != nil {
				t.Fatal(e)
			}
			dir := filepath.Join(t.TempDir(), "p")
			if e = writeProfileIn(p, dir); e != nil {
				t.Fatal(e)
			}
			startEngine(t, profileSockets(p), a.enginePath(snellEngine(p.snellVersion())), "-c", filepath.Join(dir, snellConf))

			line, e := p.SnellSurgeLine(p.PublicHost, p.PublicPort)
			if e != nil {
				t.Fatal(e)
			}
			exit, e := ParseRemoteNode(line)
			if e != nil {
				t.Fatal(e)
			}
			out := proxyConfig(*exit)
			out["tag"] = "node"
			local, _ := freePort()
			client := M{
				"log":       M{"level": "warn"},
				"inbounds":  []any{M{"type": "mixed", "listen": "127.0.0.1", "listen_port": local}},
				"outbounds": []any{out},
				"route":     M{"final": "node"},
			}
			e = a.withClient(client, local, func(proxy string) error {
				ip, e := fetchIP(proxy, origin.URL)
				if e != nil {
					return e
				}
				if ip != "198.51.100.29" {
					return fmt.Errorf("unexpected response")
				}
				return nil
			})
			if e != nil {
				t.Fatal(e)
			}
		})
	}
}
