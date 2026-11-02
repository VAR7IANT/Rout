package rout

import (
	"bytes"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// syncBuffer is a bytes.Buffer that can be written by the exec goroutine and read by the test.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }
func (s *syncBuffer) Len() int       { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Len() }

// buildManager compiles the real CLI once per test binary.
func buildManager(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("ROUT_TEST_MANAGER"); p != "" {
		return p
	}
	goBin, e := exec.LookPath("go")
	if e != nil {
		t.Skip("no Go toolchain to build the CLI")
	}
	out := filepath.Join(t.TempDir(), "rout")
	cmd := exec.Command(goBin, "build", "-o", out, "../../cmd/rout")
	if b, e := cmd.CombinedOutput(); e != nil {
		t.Skipf("cannot build the CLI here: %v\n%s", e, b)
	}
	return out
}

func TestRelayServeCommandRunsAsAServiceProcess(t *testing.T) {
	manager := buildManager(t)
	_, echoPort := echoTCP(t, "tcp4", "127.0.0.1:0")
	port, _ := freePort()
	p := nativeRelayProfile(inIPv4, outIPv4Only, "127.0.0.1:"+itoa(echoPort), port)
	p.Listen = "0.0.0.0"
	dir := t.TempDir()
	if e := writeProfileIn(p, dir); e != nil {
		t.Fatal(e)
	}
	log := &syncBuffer{}
	cmd := exec.Command(manager, "relay-serve", filepath.Join(dir, "config.json"))
	cmd.Stderr = log
	if e := cmd.Start(); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	deadline := time.Now().Add(5 * time.Second)
	for {
		if c, e := net.DialTimeout("tcp4", "127.0.0.1:"+itoa(port), 100*time.Millisecond); e == nil {
			c.Close()
			break
		}
		select {
		case e := <-done:
			t.Fatalf("relay-serve exited early: %v\n%s", e, log.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("relay-serve never listened\n%s", log.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	if e := roundTrip(t, "tcp4", "127.0.0.1:"+itoa(port), "through the real process"); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(log.String(), "listening tcp4 0.0.0.0:"+itoa(port)) {
		t.Fatalf("log: %q", log.String())
	}
	// SIGTERM is a clean stop: exit status 0 and the port is released.
	_ = cmd.Process.Signal(syscall.SIGTERM)
	select {
	case e := <-done:
		if e != nil {
			t.Fatalf("not a clean exit: %v\n%s", e, log.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("relay-serve ignored SIGTERM")
	}
	if c, e := net.DialTimeout("tcp4", "127.0.0.1:"+itoa(port), 200*time.Millisecond); e == nil {
		c.Close()
		t.Fatal("the port is still open after the service stopped")
	}
}

func TestRelayServeCommandRefusesBadInput(t *testing.T) {
	manager := buildManager(t)
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	os.WriteFile(bad, []byte(`{"version":9}`), 0600)
	for name, args := range map[string][]string{
		"no argument":   {"relay-serve"},
		"missing file":  {"relay-serve", filepath.Join(dir, "nope.json")},
		"bad version":   {"relay-serve", bad},
		"extra argment": {"relay-serve", bad, "extra"},
	} {
		cmd := exec.Command(manager, args...)
		stderr := &syncBuffer{}
		cmd.Stderr = stderr
		cmd.Stdout = io.Discard
		if e := cmd.Run(); e == nil {
			t.Errorf("%s: exit status 0", name)
		}
		if stderr.Len() == 0 {
			t.Errorf("%s: no error message", name)
		}
	}
	// Port already taken: the service fails at once and names the family (so systemd restarts
	// it and the journal explains why), instead of running half bound.
	l, _ := net.Listen("tcp4", "0.0.0.0:0")
	defer l.Close()
	busy := nativeRelayProfile(inIPv4, outAuto, "198.51.100.7:443", l.Addr().(*net.TCPAddr).Port)
	busy.Listen = "0.0.0.0"
	if e := writeProfileIn(busy, dir); e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(manager, "relay-serve", filepath.Join(dir, "config.json"))
	stderr := &syncBuffer{}
	cmd.Stderr = stderr
	if e := cmd.Run(); e == nil || !strings.Contains(stderr.String(), "cannot listen on tcp4") {
		t.Fatalf("busy port: %v %q", e, stderr.String())
	}
}
