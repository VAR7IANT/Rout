package rout

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Simulated (fake-meter) regression tests for v0.2.2 recovery, locking and lifecycle
// separation. Real kernel behavior is covered by traffic_kernel_test.go.
func limitedTestApp(t *testing.T, limit uint64) (*App, *fakeMeter, Profile) {
	t.Helper()
	a, m, p := trafficTestApp(t)
	a.bootID = func() (string, error) { return "boot-1", nil }
	if e := a.TrafficSync(time.Now(), false); e != nil {
		t.Fatal(e)
	}
	if e := a.ConfigureTraffic(p.ID, TrafficPolicy{LimitBytes: limit, BillingDay: 1}, true, time.Now()); e != nil {
		t.Fatal(e)
	}
	return a, m, p
}
func record(t *testing.T, a *App, id string) TrafficRecord {
	t.Helper()
	db, e := a.loadTraffic()
	if e != nil {
		t.Fatal(e)
	}
	return db.Records[id]
}

func TestTrafficGracefulRestartSealsAndResumes(t *testing.T) {
	a, m, p := limitedTestApp(t, 1000)
	started := 0
	a.trafficStart = func(Profile) error { started++; return nil }
	a.trafficStop = func(Profile) error { return nil }
	snap := m.values[p.ID]
	snap.Up, snap.Down, snap.Consumed = 300, 100, 400
	m.values[p.ID] = snap
	a.monitorMode = true
	if e := a.TrafficSync(time.Now(), true); e != nil {
		t.Fatal(e)
	}
	r := record(t, a, p.ID)
	if r.Blocked != "sealed" || r.Incomplete || r.Consumed != 400 {
		t.Fatal("graceful shutdown did not seal an exact checkpoint", r)
	}
	// The CLI (not the monitor) never reopens a sealed node.
	a.monitorMode = false
	if e := a.TrafficSync(time.Now(), false); e != nil {
		t.Fatal(e)
	}
	if record(t, a, p.ID).Blocked != "sealed" || started != 0 {
		t.Fatal("CLI reopened a sealed checkpoint without a monitor")
	}
	if e := a.TrafficGuard(p.ID); e == nil {
		t.Fatal("guard admitted a sealed node")
	}
	a.monitorMode = true
	if e := a.TrafficSync(time.Now(), false); e != nil {
		t.Fatal(e)
	}
	r = record(t, a, p.ID)
	if _, _, total, _ := r.totals(); r.Blocked != "" || r.Incomplete || total != 400 || r.Consumed != 400 || started != 1 {
		t.Fatal("monitor restart did not resume with preserved usage", r, started)
	}
	if e := a.TrafficGuard(p.ID); e != nil {
		t.Fatal("resumed node cannot start", e)
	}
}

func TestTrafficSealedCheckpointRequiresVerification(t *testing.T) {
	a, m, p := limitedTestApp(t, 1000)
	a.trafficStop = func(Profile) error { return nil }
	a.monitorMode = true
	if e := a.TrafficSync(time.Now(), true); e != nil {
		t.Fatal(e)
	}
	// Same boot but the kernel admitted bytes after the seal: not provably complete.
	snap := m.values[p.ID]
	snap.Up += 50
	m.values[p.ID] = snap
	_ = a.TrafficSync(time.Now(), false)
	if r := record(t, a, p.ID); r.Blocked != "fault" || !r.Incomplete {
		t.Fatal("unverifiable seal was trusted", r)
	}
	// Fresh boot with a surviving (possibly stale) table is also not trusted.
	a2, m2, p2 := limitedTestApp(t, 1000)
	a2.trafficStop = func(Profile) error { return nil }
	a2.monitorMode = true
	if e := a2.TrafficSync(time.Now(), true); e != nil {
		t.Fatal(e)
	}
	a2.bootID = func() (string, error) { return "boot-2", nil }
	_ = m2
	_ = a2.TrafficSync(time.Now(), false)
	if r := record(t, a2, p2.ID); r.Blocked != "fault" {
		t.Fatal("reboot with a surviving table was trusted", r)
	}
}

func TestTrafficLegacyGracefulShutdownUpgrade(t *testing.T) {
	a, _, p := limitedTestApp(t, 1000)
	a.trafficStop = func(Profile) error { return nil }
	a.trafficStart = func(Profile) error { return nil }
	// Exactly what v0.2.1 wrote at graceful shutdown: fault, complete, not pending.
	write := func() {
		unlock, _ := a.trafficLock()
		defer unlock()
		db, _ := a.loadTraffic()
		r := db.Records[p.ID]
		r.Blocked = "fault"
		db.Records[p.ID] = r
		if e := a.saveTraffic(db); e != nil {
			t.Fatal(e)
		}
	}
	write()
	a.monitorMode = true
	if e := a.TrafficSync(time.Now(), false); e != nil {
		t.Fatal(e)
	}
	if r := record(t, a, p.ID); r.Blocked != "" {
		t.Fatal("same-boot v0.2.1 shutdown checkpoint not recovered", r)
	}
	write()
	a.bootID = func() (string, error) { return "boot-2", nil }
	_ = a.TrafficSync(time.Now(), false)
	if r := record(t, a, p.ID); r.Blocked != "fault" || !r.Incomplete {
		t.Fatal("legacy checkpoint across a reboot was trusted", r)
	}
}

func TestTrafficUnlimitedNeverBlockedByMeterFaults(t *testing.T) {
	a, m, p := trafficTestApp(t)
	stopped := 0
	a.trafficStop = func(Profile) error { stopped++; return nil }
	// Force a rebuild (shape change) whose replacement fails.
	s, _ := a.Load()
	p.Port, _ = freePort()
	p.PublicPort = p.Port
	m.failReplace = true
	if e := a.Commit(s, replace(s, p), false); e != nil {
		t.Fatal(e)
	}
	if m.frozen[p.ID] || stopped != 0 || record(t, a, p.ID).Blocked != "" {
		t.Fatal("unlimited node was frozen or stopped by a meter failure")
	}
	m.failReplace = false
	if e := a.TrafficSync(time.Now(), false); e != nil {
		t.Fatal(e)
	}
	if _, ok := m.values[p.ID]; !ok || m.frozen[p.ID] {
		t.Fatal("unlimited meter not rebuilt")
	}
}

func TestTrafficRenewFailureIsNotPermanent(t *testing.T) {
	a, m, p := limitedTestApp(t, 1000)
	m.failRenew = true
	if e := a.TrafficSync(time.Now(), false); e == nil {
		t.Fatal("renewal failure not reported")
	}
	m.failRenew = false
	m.renewed = map[string]int{}
	if e := a.TrafficSync(time.Now(), false); e != nil {
		t.Fatal(e)
	}
	if r := record(t, a, p.ID); r.Blocked != "" || m.renewed[p.ID] != 1 {
		t.Fatal("transient lease error became a permanent fault", r)
	}
}

func TestTrafficLockContentionWaits(t *testing.T) {
	a, _, _ := trafficTestApp(t)
	// A monitor heartbeat holding the traffic lock briefly must delay, not roll back, a Commit.
	unlock, e := a.trafficLock()
	if e != nil {
		t.Fatal(e)
	}
	go func() { time.Sleep(300 * time.Millisecond); unlock() }()
	s, _ := a.Load()
	q := fixture(t, "vless")
	q.Port, _ = freePort()
	q.PublicPort = q.Port
	if e := a.Commit(s, replace(s, q), false); e != nil {
		t.Fatal("commit failed under short lock contention", e)
	}
	// Concurrent CLI operations and monitor polls: no lock errors, no lost state.
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for i := 0; i < 4; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 5; j++ {
				if e := a.TrafficSync(time.Now(), false); e != nil {
					errs <- e
				}
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 3; j++ {
				unlock, e := a.lock()
				if e != nil {
					errs <- e
					return
				}
				time.Sleep(10 * time.Millisecond)
				unlock()
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal("concurrent operation failed", e)
	}
	// A holder that never releases produces a bounded, explicit timeout.
	hold, _ := lockFile(filepath.Join(a.Home, ".lock"), time.Second)
	defer hold()
	start := time.Now()
	if _, e := a.lockWait(200 * time.Millisecond); e != errLockBusy || time.Since(start) > 2*time.Second {
		t.Fatal("lock wait not bounded", e)
	}
}

func TestTrafficSlowServiceCommandsRunOutsideLocks(t *testing.T) {
	a, m, p := limitedTestApp(t, 100)
	q := fixture(t, "ss")
	q.Port, _ = freePort()
	q.PublicPort = q.Port
	s, _ := a.Load()
	if e := a.Commit(s, replace(s, q), false); e != nil {
		t.Fatal(e)
	}
	if e := a.ConfigureTraffic(q.ID, TrafficPolicy{LimitBytes: 1000, BillingDay: 1}, true, time.Now()); e != nil {
		t.Fatal(e)
	}
	m.renewed = map[string]int{}
	heartbeat := make(chan error, 1)
	a.trafficStop = func(Profile) error {
		// While the init system is slow, another node's lease must still be renewable.
		m.renewed = map[string]int{}
		go func() { _, e := a.trafficHeartbeat(time.Now(), false); heartbeat <- e }()
		select {
		case e := <-heartbeat:
			heartbeat <- e
		case <-time.After(3 * time.Second):
			heartbeat <- errLockBusy
		}
		return nil
	}
	snap := m.values[p.ID]
	snap.Consumed = 100
	m.values[p.ID] = snap
	if e := a.TrafficSync(time.Now(), false); e != nil {
		t.Fatal(e)
	}
	if e := <-heartbeat; e != nil || m.renewed[q.ID] == 0 {
		t.Fatal("service stop held the traffic lock and starved other leases", e)
	}
	if record(t, a, p.ID).Blocked != "quota" || record(t, a, q.ID).Blocked != "" {
		t.Fatal("quota isolation failed")
	}
}

func TestTrafficSkipsRedundantWrites(t *testing.T) {
	a, _, _ := trafficTestApp(t)
	path := filepath.Join(a.Home, "traffic.json")
	now := time.Now()
	if e := a.TrafficSync(now, false); e != nil {
		t.Fatal(e)
	}
	before, _ := os.Stat(path)
	if e := a.TrafficSync(now.Add(time.Second), false); e != nil {
		t.Fatal(e)
	}
	after, _ := os.Stat(path)
	if !os.SameFile(before, after) {
		t.Fatal("unchanged counters were rewritten")
	}
	if e := a.TrafficSync(now.Add(trafficRefresh+time.Second), false); e != nil {
		t.Fatal(e)
	}
	refreshed, _ := os.Stat(path)
	if os.SameFile(before, refreshed) {
		t.Fatal("liveness checkpoint was never refreshed")
	}
}

func TestTrafficNewLimitOnIncompleteCycleNeedsConsent(t *testing.T) {
	a, _, p := trafficTestApp(t)
	a.bootID = func() (string, error) { return "boot-1", nil }
	_ = a.TrafficSync(time.Now(), false) // boot differs from the setup record: a gap
	if !record(t, a, p.ID).Incomplete {
		t.Fatal("expected an incomplete cycle")
	}
	if e := a.ConfigureTraffic(p.ID, TrafficPolicy{LimitBytes: 1 << 40, BillingDay: 1}, false, time.Now()); e != nil {
		t.Fatal(e)
	}
	if record(t, a, p.ID).Blocked != "fault" {
		t.Fatal("new cap on a gapped cycle was enabled silently")
	}
	if e := a.RecoverTraffic(p.ID, time.Now()); e != nil {
		t.Fatal(e)
	}
	r := record(t, a, p.ID)
	if r.Blocked != "" || !r.Incomplete {
		t.Fatal("accepting the gap must resume and keep the gap marker", r)
	}
	// Later edits of an already limited node do not re-block it.
	if e := a.ConfigureTraffic(p.ID, TrafficPolicy{LimitBytes: 2 << 40, BillingDay: 5}, false, time.Now()); e != nil {
		t.Fatal(e)
	}
	if record(t, a, p.ID).Blocked != "" {
		t.Fatal("editing a limit re-blocked an accepted cycle")
	}
}

func TestTrafficMissingJournalPreservesSurvivingCounters(t *testing.T) {
	for _, limited := range []bool{false, true} {
		label := "unlimited"
		if limited {
			label = "limited"
		}
		t.Run(label, func(t *testing.T) {
			a, m, p := trafficTestApp(t)
			if limited {
				if e := a.ConfigureTraffic(p.ID, TrafficPolicy{LimitBytes: 10000, BillingDay: 1}, false, time.Now()); e != nil {
					t.Fatal(e)
				}
			}
			snap := m.values[p.ID]
			snap.Up, snap.Down, snap.Consumed = 300, 100, 0
			if limited {
				snap.Consumed = 400
			}
			m.values[p.ID] = snap
			if e := os.Remove(filepath.Join(a.Home, "traffic.json")); e != nil {
				t.Fatal(e)
			}
			if e := a.TrafficSync(time.Now(), false); e != nil {
				t.Fatal(e)
			}
			r := record(t, a, p.ID)
			if r.RawUp != 300 || r.RawDown != 100 || r.Consumed != snap.Consumed || !r.Incomplete {
				t.Fatal("surviving counters replaced with zero", r)
			}
			if limited && r.Blocked != blockFault {
				t.Fatal("missing journal reopened a finite allowance", r)
			}
		})
	}
}
