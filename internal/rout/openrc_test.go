package rout

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Real OpenRC (supervise-daemon) lifecycle test. Run only inside a disposable
// container or VM where OpenRC manages services: ROUT_TEST_OPENRC=1.
func TestIntegrationOpenRCLifecycle(t *testing.T) {
	if os.Getenv("ROUT_TEST_OPENRC") != "1" {
		t.Skip("set ROUT_TEST_OPENRC=1 on a disposable OpenRC host")
	}
	verified := integrationApp(t)
	root := t.TempDir()
	a := &App{Home: filepath.Join(root, "config"), BinDir: filepath.Join(root, "bin"), ServiceMode: "auto"}
	if m, e := a.serviceManager(); e != nil || m != "openrc" {
		t.Fatal("OpenRC not detected", m, e)
	}
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
	})
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "198.51.100.19") }))
	defer origin.Close()
	node := func() Profile {
		p := fixture(t, "ss")
		p.Port, _ = freePort()
		p.PublicPort = p.Port
		s, _ := a.Load()
		if e := a.Commit(s, replace(s, p), false); e != nil {
			t.Fatal(e)
		}
		return p
	}
	request := func(p Profile) error {
		port, _ := freePort()
		c, e := ClientConfig(p, "127.0.0.1", p.Port, port)
		if e != nil {
			return e
		}
		return a.withClient(c, port, func(proxy string) error { _, e := fetchIP(proxy, origin.URL); return e })
	}
	p := node()
	if a.Running(p) != "运行中" || !listening(p) {
		t.Fatal("OpenRC service not healthy after start")
	}
	if e := request(p); e != nil {
		t.Fatal("traffic through OpenRC-managed node failed", e)
	}
	firstPID := servicePID("openrc", serviceName(p))
	other := node()
	if servicePID("openrc", serviceName(p)) != firstPID {
		t.Fatal("adding a node restarted an existing OpenRC service")
	}
	// Manual disable/enable.
	for _, enabled := range []bool{false, true} {
		s, _ := a.Load()
		current, _ := Find(s, p.ID)
		current.Enabled = enabled
		if e := a.Commit(s, replace(s, current), false); e != nil {
			t.Fatal(e)
		}
		if (a.Running(p) == "运行中") != enabled {
			t.Fatal("OpenRC enable/disable mismatch", enabled)
		}
	}
	// A replacement whose engine exits immediately must fail health checks and roll back.
	if e := AtomicWrite(a.enginePath("gost"), []byte("#!/bin/sh\nexit 42\n"), 0755); e != nil {
		t.Fatal(e)
	}
	s, _ := a.Load()
	broken, _ := Find(s, other.ID)
	broken.Kind, broken.Protocol, broken.Target = "relay", "tcp", strings.TrimPrefix(origin.URL, "http://")
	if e := a.Commit(s, replace(s, broken), false); e == nil {
		t.Fatal("crashing engine passed the OpenRC health check")
	}
	restored, _ := a.Load()
	if again, _ := Find(restored, other.ID); again.Kind != "node" || a.Running(other) != "运行中" {
		t.Fatal("OpenRC rollback did not restore the previous service")
	}
	// The private log stays bounded both at start and while running.
	logPath := "/var/log/" + serviceName(p) + ".log"
	if st, e := os.Stat(logPath); e != nil || st.Mode().Perm() != 0600 {
		t.Fatal("OpenRC log missing or not private", e)
	}
	if e := os.WriteFile(logPath, make([]byte, openrcLogLimit+1), 0600); e != nil {
		t.Fatal(e)
	}
	if e := rotateLog(logPath, openrcLogLimit); e != nil {
		t.Fatal(e)
	}
	if st, _ := os.Stat(logPath); st.Size() != 0 {
		t.Fatal("running log not truncated")
	}
	if st, e := os.Stat(logPath + ".1"); e != nil || st.Size() <= openrcLogLimit {
		t.Fatal("rotated log not kept", e)
	}
	if e := a.Restart(p.ID); e != nil {
		t.Fatal(e)
	}
	time.Sleep(200 * time.Millisecond)
	if e := request(p); e != nil {
		t.Fatal("restarted OpenRC node failed", e)
	}
	s, _ = a.Load()
	if e := a.Commit(s, removeProfile(s, p.ID), false); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat("/etc/init.d/" + serviceName(p)); !os.IsNotExist(e) {
		t.Fatal("deleted node left its OpenRC script")
	}
}
