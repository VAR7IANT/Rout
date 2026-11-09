package rout

import (
	"bytes"
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
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
