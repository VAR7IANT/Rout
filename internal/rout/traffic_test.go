package rout

import (
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeMeter struct {
	values map[string]MeterSnapshot
	fail   bool
	frozen map[string]bool
}

func (m *fakeMeter) Read(p Profile) (MeterSnapshot, error) {
	if m.fail {
		return MeterSnapshot{}, errors.New("meter failed")
	}
	s, ok := m.values[p.ID]
	if !ok {
		return s, errMeterMissing
	}
	return s, nil
}
func (m *fakeMeter) Replace(p Profile, r TrafficRecord) (string, error) {
	if m.fail {
		return "", errors.New("meter failed")
	}
	h := trafficShape(p) + r.Blocked
	m.values[p.ID] = MeterSnapshot{r.RawUp, r.RawDown, r.Consumed, h}
	m.frozen[p.ID] = r.Blocked != ""
	return h, nil
}
func (m *fakeMeter) Freeze(p Profile) error { m.frozen[p.ID] = true; return nil }
func (m *fakeMeter) Renew(p Profile) error {
	if m.fail {
		return errors.New("lease failed")
	}
	return nil
}
func (m *fakeMeter) Delete(p Profile) error { delete(m.values, p.ID); return nil }
func trafficTestApp(t *testing.T) (*App, *fakeMeter, Profile) {
	t.Helper()
	a := testApp(t)
	m := &fakeMeter{values: map[string]MeterSnapshot{}, frozen: map[string]bool{}}
	a.trafficMeter = m
	p := fixture(t, "ss")
	p.Port, _ = freePort()
	p.PublicPort = p.Port
	s, _ := a.Load()
	if e := a.Commit(s, replace(s, p), false); e != nil {
		t.Fatal(e)
	}
	if e := AtomicWrite(filepath.Join(a.Home, "traffic.enabled"), []byte("1"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := a.TrafficSync(time.Now(), false); e != nil {
		t.Fatal(e)
	}
	return a, m, p
}
func TestTrafficDecimalUnitsAndOverflow(t *testing.T) {
	for s, n := range map[string]uint64{"1 MB": 1_000_000, "1.25 GB": 1_250_000_000, "2tb": 2_000_000_000_000, "0.000001 MB": 1} {
		v, e := ParseTrafficLimit(s)
		if e != nil || v != n {
			t.Fatalf("%s %d %v", s, v, e)
		}
	}
	for _, s := range []string{"0 GB", "-1 GB", "1 GiB", "NaN GB", "1e10 TB", "9223372037 GB", "0.0000001 MB"} {
		if _, e := ParseTrafficLimit(s); e == nil {
			t.Fatal("accepted", s)
		}
	}
	r := TrafficRecord{RawUp: math.MaxUint64, RawDown: 1}
	if _, _, _, e := r.totals(); e == nil {
		t.Fatal("overflow undetected")
	}
	r = TrafficRecord{RawUp: 1, BaseUp: 2}
	if _, _, _, e := r.totals(); e == nil {
		t.Fatal("negative usage")
	}
}
func TestTrafficBillingBoundaries(t *testing.T) {
	for _, tc := range []struct {
		now, zone, start, next string
		day                    int
	}{
		{"2024-02-29T12:00:00Z", "UTC", "2024-02-29", "2024-03-31", 31},
		{"2025-02-28T12:00:00Z", "UTC", "2025-02-28", "2025-03-31", 31},
		{"2026-01-01T00:00:00Z", "UTC", "2026-01-01", "2026-02-01", 1},
		{"2025-12-15T12:00:00Z", "UTC", "2025-11-30", "2025-12-31", 31},
		{"2026-03-08T08:00:00Z", "America/New_York", "2026-03-08", "2026-04-08", 8},
		{"2026-10-31T17:00:00Z", "Asia/Hong_Kong", "2026-11-01", "2026-12-01", 1},
	} {
		now, _ := time.Parse(time.RFC3339, tc.now)
		s, n := trafficWindow(now, TrafficPolicy{BillingDay: tc.day, Timezone: tc.zone})
		if s.Format("2006-01-02") != tc.start || n.Format("2006-01-02") != tc.next {
			t.Fatalf("%+v %v %v", tc, s, n)
		}
	}
	p := TrafficPolicy{BillingDay: 1, Timezone: "UTC"}
	now := time.Date(2025, 12, 31, 12, 0, 0, 0, time.UTC)
	r := newTrafficRecord(Profile{Traffic: &p}, now, "boot")
	r.RawUp = 99
	r.RawDown = 1
	if !r.advance(now.Add(48*time.Hour), p) {
		t.Fatal("did not reset across year")
	}
	r.RawUp += 50
	if r.advance(now, p) {
		t.Fatal("backward clock reset usage")
	}
	if r.advance(now.Add(48*time.Hour), p) {
		t.Fatal("duplicate reset")
	}
	if _, _, total, _ := r.totals(); total != 50 {
		t.Fatal(total)
	}
	if !r.advance(now.AddDate(0, 4, 0), p) {
		t.Fatal("offline months not caught up")
	}
	r.RawUp += 20
	p.BillingDay = 31
	p.Timezone = "Pacific/Auckland"
	if r.advance(now.AddDate(0, 4, 1), p) {
		t.Fatal("schedule edit reset usage")
	}
}
func TestTrafficUnlimitedThresholdsAndRestartProtection(t *testing.T) {
	a, m, p := trafficTestApp(t)
	now := time.Now()
	stop := map[string]int{}
	a.trafficStop = func(p Profile) error { stop[p.ID]++; return nil }
	snap := m.values[p.ID]
	snap.Up = 60
	snap.Down = 39
	m.values[p.ID] = snap
	if e := a.TrafficSync(now, false); e != nil {
		t.Fatal(e)
	}
	if e := a.TrafficSync(now, false); e != nil {
		t.Fatal(e)
	}
	db, _ := a.loadTraffic()
	if _, _, n, _ := db.Records[p.ID].totals(); n != 99 {
		t.Fatal("duplicate billing", n)
	}
	if stop[p.ID] != 0 {
		t.Fatal("unlimited stopped")
	}
	policy := TrafficPolicy{LimitBytes: 100, BillingDay: 1}
	if e := a.ConfigureTraffic(p.ID, policy, false, now); e != nil {
		t.Fatal(e)
	}
	s, _ := a.Load()
	current, _ := Find(s, p.ID)
	if s.Schema != 2 || !current.Enabled {
		t.Fatal("manual state changed")
	}
	db, _ = a.loadTraffic()
	if db.Records[p.ID].Consumed != 99 {
		t.Fatal("enabling a quota ignored already-used traffic")
	}
	snap = m.values[p.ID]
	snap.Up++
	snap.Consumed = 100
	m.values[p.ID] = snap
	if e := a.TrafficSync(now, false); e != nil {
		t.Fatal(e)
	}
	db, _ = a.loadTraffic()
	if db.Records[p.ID].Blocked != "quota" || stop[p.ID] == 0 {
		t.Fatal("100% did not stop")
	}
	if e := a.TrafficGuard(p.ID); e == nil {
		t.Fatal("restart bypassed quota")
	}
	if e := a.Restart(p.ID); e == nil {
		t.Fatal("restart command bypassed quota")
	}
	// Ordinary edits/restoring old state keep the cap and counters.
	s, _ = a.Load()
	oldReader := s.Clone()
	oldReader.Schema = 1
	oldReader.Profiles[0].Traffic = nil
	if e := a.Commit(s, oldReader, false); e != nil {
		t.Fatal(e)
	}
	s, _ = a.Load()
	if s.Profiles[0].Traffic.LimitBytes != 100 {
		t.Fatal("apply removed quota")
	}
	// Manual off survives automatic reset; an enabled quota-stopped node is eligible for restore.
	s.Profiles[0].Enabled = false
	b, _ := JSON(s)
	if e := AtomicWrite(filepath.Join(a.Home, "state.json"), b, 0600); e != nil {
		t.Fatal(e)
	}
	resetAt := db.Records[p.ID].Next.Add(time.Second)
	if e := a.TrafficSync(resetAt, false); e != nil {
		t.Fatal(e)
	}
	db, _ = a.loadTraffic()
	r := db.Records[p.ID]
	if r.Blocked != "" {
		t.Fatal("monthly reset kept quota block")
	}
	if _, _, total, _ := r.totals(); total != 0 {
		t.Fatal("monthly reset failed")
	}
	s, _ = a.Load()
	if s.Profiles[0].Enabled {
		t.Fatal("manual pause auto resumed")
	}
}
func TestTrafficColdBootFaultAndUnlimitedIsolation(t *testing.T) {
	a, m, p := trafficTestApp(t)
	now := time.Now()
	if e := a.ConfigureTraffic(p.ID, TrafficPolicy{LimitBytes: 1000, BillingDay: 1}, false, now); e != nil {
		t.Fatal(e)
	}
	s, _ := a.Load()
	q := fixture(t, "vless")
	q.Port, _ = freePort()
	q.PublicPort = q.Port
	if e := a.Commit(s, replace(s, q), false); e != nil {
		t.Fatal(e)
	}
	db, _ := a.loadTraffic()
	r := db.Records[p.ID]
	r.Boot = "previous-boot"
	db.Records[p.ID] = r
	if e := a.saveTraffic(db); e != nil {
		t.Fatal(e)
	}
	delete(m.values, p.ID)
	stopped := map[string]bool{}
	a.trafficStop = func(p Profile) error { stopped[p.ID] = true; return nil }
	if e := a.TrafficSync(now, false); e != nil {
		t.Fatal(e)
	}
	db, _ = a.loadTraffic()
	if db.Records[p.ID].Blocked != "fault" || !stopped[p.ID] || stopped[q.ID] {
		t.Fatal("cold boot fail-closed/isolation failed")
	}
	if e := a.TrafficGuard(p.ID); e == nil {
		t.Fatal("cold reboot bypass")
	}
	if e := a.ConfigureTraffic(p.ID, TrafficPolicy{LimitBytes: 2000, BillingDay: 1}, false, now); e != nil {
		t.Fatal(e)
	}
	db, _ = a.loadTraffic()
	if db.Records[p.ID].Blocked != "fault" {
		t.Fatal("raising quota erased missing usage")
	}
	if e := a.ConfigureTraffic(p.ID, TrafficPolicy{LimitBytes: 2000, BillingDay: 1}, true, now); e != nil {
		t.Fatal(e)
	}
	db, _ = a.loadTraffic()
	if db.Records[p.ID].Blocked != "" {
		t.Fatal("explicit reset failed")
	}
	m.fail = true
	_ = a.TrafficSync(now, false)
	if stopped[q.ID] {
		t.Fatal("meter fault stopped unlimited node")
	}
}
func TestTrafficStateCorruptionDiskFailureAndUIConfirmation(t *testing.T) {
	a, m, p := trafficTestApp(t)
	now := time.Now()
	if e := a.ConfigureTraffic(p.ID, TrafficPolicy{LimitBytes: 1000, BillingDay: 1}, false, now); e != nil {
		t.Fatal(e)
	}
	u, _ := testUI(a, "5\ny\nNO\n")
	s, _ := a.Load()
	if e := u.trafficManage(s.Profiles[0]); e == nil {
		t.Fatal("reset lacked second confirmation")
	}
	path := filepath.Join(a.Home, "traffic.json")
	b, _ := os.ReadFile(path)
	var v map[string]any
	if e := json.Unmarshal(b, &v); e != nil {
		t.Fatal(e)
	}
	if e := AtomicWrite(path, []byte("broken"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := a.TrafficSync(now, false); e == nil {
		t.Fatal("corrupt state accepted")
	}
	if !m.frozen[p.ID] {
		t.Fatal("corrupt state did not freeze cap")
	}
	if e := AtomicWrite(path, b, 0600); e != nil {
		t.Fatal(e)
	}
	// A directory at the atomic-write target deterministically injects a persistence failure.
	if e := os.Rename(path, path+".saved"); e != nil {
		t.Fatal(e)
	}
	if e := os.Mkdir(path, 0700); e != nil {
		t.Fatal(e)
	}
	if e := a.TrafficSync(now, false); e == nil {
		t.Fatal("unwritable state accepted")
	}
	if e := os.Remove(path); e != nil {
		t.Fatal(e)
	}
	if e := os.Rename(path+".saved", path); e != nil {
		t.Fatal(e)
	}
	u, out := testUI(a, "")
	if e := u.showTraffic(s.Profiles[0]); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(out.String(), "Traffic limit") {
		t.Fatal("English UI missing")
	}
}
func TestTrafficLegacyPartialCycleAndIntegrityRecovery(t *testing.T) {
	a, m, p := trafficTestApp(t)
	legacy := p
	legacy.CreatedAt = nil
	r := newTrafficRecord(legacy, time.Now(), "boot")
	if !r.Incomplete {
		t.Fatal("legacy history was presented as complete")
	}
	if newTrafficRecord(p, time.Now(), "boot").Incomplete {
		t.Fatal("new monitored node unnecessarily incomplete")
	}
	path := filepath.Join(a.Home, "traffic.json")
	db, e := a.loadTraffic()
	if e != nil {
		t.Fatal(e)
	}
	// Structurally valid JSON with a modified number is still corrupt.
	r = db.Records[p.ID]
	r.RawUp = 123
	db.Records[p.ID] = r
	b, _ := JSON(db)
	if e = AtomicWrite(path, b, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = a.loadTraffic(); e == nil {
		t.Fatal("checksum did not detect altered usage")
	}
	if e = a.ConfigureTraffic(p.ID, TrafficPolicy{LimitBytes: 1000, BillingDay: 1}, true, time.Now()); e != nil {
		t.Fatal("explicit reset did not recover readable corrupt state", e)
	}
	db, e = a.loadTraffic()
	if e != nil || db.Records[p.ID].Incomplete || db.Records[p.ID].Blocked != "" {
		t.Fatal("explicit recovery failed", e)
	}
	files, _ := filepath.Glob(filepath.Join(a.Home, "backups", "traffic-corrupt-*.json"))
	if len(files) != 1 {
		t.Fatal("corrupt evidence not quarantined")
	}
	// A counter/consumed reset is a fault, not a fresh budget.
	s := m.values[p.ID]
	s.Consumed = 10
	m.values[p.ID] = s
	if e = a.TrafficSync(time.Now(), false); e != nil {
		t.Fatal(e)
	}
	s.Consumed = 0
	m.values[p.ID] = s
	_ = a.TrafficSync(time.Now(), false)
	db, _ = a.loadTraffic()
	if db.Records[p.ID].Blocked != "fault" {
		t.Fatal("quota counter rollback granted new allowance")
	}
}
