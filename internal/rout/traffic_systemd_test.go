package rout

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIntegrationTrafficServiceGuard(t *testing.T) {
	if os.Getenv("ROUT_TEST_TRAFFIC_SYSTEMD") != "1" {
		t.Skip("disposable root/systemd host required")
	}
	verified := integrationApp(t)
	manager := os.Getenv("ROUT_TEST_MANAGER")
	if manager == "" {
		t.Fatal("compiled manager required")
	}
	root, e := os.MkdirTemp("/var/lib", "rout-quota-ci-")
	if e != nil {
		t.Fatal(e)
	}
	a := &App{Home: filepath.Join(root, "config"), BinDir: filepath.Join(root, "bin"), ServiceMode: "auto"}
	b, e := os.ReadFile(verified.enginePath("sing-box"))
	if e != nil {
		t.Fatal(e)
	}
	if e = AtomicWrite(a.enginePath("sing-box"), b, 0755); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		_ = a.removeTrafficMonitor()
		s, e := a.Load()
		if e == nil {
			if e = a.Commit(s, State{Schema: 1, Profiles: []Profile{}}, false); e != nil {
				t.Error(e)
			}
		}
		_ = os.RemoveAll(root)
	})
	var nodes []Profile
	for i := 0; i < 2; i++ {
		p := fixture(t, "ss")
		p.Port, _ = freePort()
		p.PublicPort = p.Port
		s, _ := a.Load()
		if e = a.Commit(s, replace(s, p), false); e != nil {
			t.Fatal(e)
		}
		nodes = append(nodes, p)
	}
	pid := func(p Profile) string {
		b, e := runOutput(5*time.Second, "systemctl", "show", "--property=MainPID", "--value", serviceName(p)+".service")
		if e != nil {
			t.Fatal(e)
		}
		return strings.TrimSpace(string(b))
	}
	first, other := pid(nodes[0]), pid(nodes[1])
	args := append([]string{"--home", a.Home, "--bin-dir", a.BinDir}, "traffic", "install")
	if out, e := runOutput(30*time.Second, manager, args...); e != nil {
		t.Fatalf("monitor installation failed: %v %s", e, out)
	}
	if pid(nodes[0]) != first || pid(nodes[1]) != other {
		t.Fatal("monitor installation restarted existing nodes")
	}
	// A 1-byte kernel budget cannot admit even the first TCP SYN.
	if e = a.ConfigureTraffic(nodes[0].ID, TrafficPolicy{LimitBytes: 1, BillingDay: 1}, false, time.Now()); e != nil {
		t.Fatal(e)
	}
	if e = a.TrafficGuard(nodes[0].ID); e != nil {
		t.Fatal("healthy guarded node did not start", e)
	}
	confPath := filepath.Join(a.profileDir(nodes[0].ID), "config.json")
	current, e := os.ReadFile(confPath)
	if e != nil {
		t.Fatal(e)
	}
	if e = AtomicWrite(confPath, []byte("{}"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = a.TrafficGuard(nodes[0].ID); e == nil {
		t.Fatal("guard accepted a config not matching metered listener")
	}
	if e = AtomicWrite(confPath, current, 0600); e != nil {
		t.Fatal(e)
	}
	// Force an entry packet through the actual engine listener to deplete the kernel quota.
	port, _ := freePort()
	client, e := ClientConfig(nodes[0], "127.0.0.1", nodes[0].Port, port)
	if e != nil {
		t.Fatal(e)
	}
	_ = a.withClient(client, port, func(proxy string) error { _, e := fetchIP(proxy, "http://127.0.0.1:9"); return e })
	if e = a.TrafficSync(time.Now(), false); e != nil {
		t.Fatal(e)
	}
	if a.Running(nodes[0]) == "运行中" {
		t.Fatal("quota did not stop the actual node service")
	}
	if e = a.Restart(nodes[0].ID); e == nil {
		t.Fatal("CLI restart bypassed quota")
	}
	if _, e = runOutput(5*time.Second, "systemctl", "start", serviceName(nodes[0])+".service"); e == nil {
		t.Fatal("systemctl start bypassed persistent quota")
	}
	if pid(nodes[1]) != other {
		t.Fatal("quota changed an unrelated node PID")
	}
	// Move the durable cycle to the previous month, then exercise the real reset/start path.
	unlock, e := a.lock()
	if e != nil {
		t.Fatal(e)
	}
	meterUnlock, e := a.trafficLock()
	if e != nil {
		unlock()
		t.Fatal(e)
	}
	db, e := a.loadTraffic()
	if e != nil {
		meterUnlock()
		unlock()
		t.Fatal(e)
	}
	r := db.Records[nodes[0].ID]
	now := time.Now()
	r.Start = now.AddDate(0, -1, 0)
	r.Next = now.Add(-time.Hour)
	r.Seen = now.Add(-time.Hour)
	db.Records[nodes[0].ID] = r
	e = a.saveTraffic(db)
	meterUnlock()
	unlock()
	if e != nil {
		t.Fatal(e)
	}
	if e = a.TrafficSync(now, false); e != nil {
		t.Fatal(e)
	}
	if a.Running(nodes[0]) != "运行中" {
		t.Fatal("new cycle failed to restore quota-stopped node")
	}
	if pid(nodes[1]) != other {
		t.Fatal("monthly reset changed unrelated PID")
	}
}
