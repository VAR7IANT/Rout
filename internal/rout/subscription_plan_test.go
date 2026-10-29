package rout

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func enableTrafficMarker(t *testing.T, a *App) {
	t.Helper()
	if e := AtomicWrite(filepath.Join(a.Home, "traffic.enabled"), []byte("1"), 0600); e != nil {
		t.Fatal(e)
	}
}

// writeNodeCounters stores absolute kernel counters per node in the traffic journal,
// the way the per-node sync leaves them just before the pool step reads them.
func writeNodeCounters(t *testing.T, a *App, now time.Time, raw map[string][2]uint64) {
	t.Helper()
	db := TrafficState{Version: 1, Records: map[string]TrafficRecord{}, Updated: now}
	for id, v := range raw {
		db.Records[id] = TrafficRecord{RawUp: v[0], RawDown: v[1], Start: now.Add(-time.Hour), Next: now.Add(time.Hour), Seen: now, Observed: now}
	}
	if e := a.saveTraffic(db); e != nil {
		t.Fatal(e)
	}
}

func infoNames(t *testing.T, body string) []string {
	t.Helper()
	var out []string
	for _, line := range decodeBody(t, body) {
		if !strings.HasPrefix(line, "trojan://rout-info@127.0.0.1:1") {
			continue
		}
		u, e := url.Parse(line)
		if e != nil {
			t.Fatal(e)
		}
		out = append(out, u.Fragment)
	}
	return out
}

func TestPlanExpiryRenewsMonthlyAndNeverBlocks(t *testing.T) {
	loc := time.UTC
	for _, tc := range []struct{ expires, now, want string }{
		{"2026-11-27", "2026-10-29", "2026-11-27"},
		{"2026-11-27", "2026-11-27", "2026-11-27"}, // still shown on the day itself
		{"2026-11-27", "2026-11-28", "2026-12-27"},
		{"2026-11-27", "2027-03-01", "2027-03-27"},
		{"2026-01-31", "2026-02-15", "2026-02-28"}, // clamped, original day kept
		{"2026-01-31", "2026-03-01", "2026-03-31"},
		{"2024-02-29", "2026-02-10", "2026-02-28"},
		{"2020-05-15", "2026-10-29", "2026-11-15"},
	} {
		now, _ := time.ParseInLocation("2006-01-02", tc.now, loc)
		got, ok := SubscriptionPlan{Expires: tc.expires, Timezone: "UTC"}.nextExpiry(now.Add(9 * time.Hour))
		if !ok || got.Format(planDateLayout) != tc.want {
			t.Fatalf("%+v got %v", tc, got)
		}
	}
	if _, ok := (SubscriptionPlan{}).nextExpiry(time.Now()); ok {
		t.Fatal("no expiry set")
	}
	for _, bad := range []string{"2026-13-01", "27-11-2026", "2026/11/27", "tomorrow", "1999-01-01"} {
		if (SubscriptionPlan{Expires: bad}).Validate() == nil {
			t.Fatal("accepted", bad)
		}
	}
}

func TestPlanInfoNodesHeaderAndUnchangedOutput(t *testing.T) {
	sc := newSubScene(t)
	enableTrafficMarker(t, sc.a)
	plain, plainToken := sc.create(t, "plain", 0, 1)
	sub, token := sc.create(t, "airport", 0, 1)
	h := sc.a.subscriptionHTTPHandler(sc.a.Load, func(string, ...any) {})
	baseline := get(h, "GET", "/s/"+token)

	now := time.Now()
	_, next := trafficWindow(now, TrafficPolicy{BillingDay: 1})
	expires := now.AddDate(0, 0, 20).Format(planDateLayout)
	if e := sc.a.SetSubscriptionPlan(sub.ID, SubscriptionPlan{LimitBytes: 100_000_000_000, Expires: expires}); e != nil {
		t.Fatal(e)
	}
	rec := newPoolRecord(TrafficPolicy{BillingDay: 1}, now)
	rec.Up, rec.Down = 20_000_000_000, 48_730_000_000
	if e := sc.a.savePools(PoolState{Version: 1, Records: map[string]PoolRecord{sub.ID: rec}}); e != nil {
		t.Fatal(e)
	}

	w := get(h, "GET", "/s/"+token)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	names := infoNames(t, w.Body.String())
	days := daysUntil(next, time.Now())
	want := []string{"Remaining data: 31.27 GB", "Days until reset: " + itoa(days), "Plan expires: " + expires}
	if strings.Join(names, "|") != strings.Join(want, "|") {
		t.Fatalf("info nodes %q, want %q", names, want)
	}
	lines := decodeBody(t, w.Body.String())
	if len(lines) != len(decodeBody(t, baseline.Body.String()))+3 || !strings.HasPrefix(lines[0], "trojan://rout-info@") {
		t.Fatal("information entries must come first and the real nodes stay unchanged")
	}
	for i, line := range decodeBody(t, baseline.Body.String()) {
		if lines[i+3] != line {
			t.Fatal("real node links changed")
		}
	}
	info := w.Header().Get("Subscription-Userinfo")
	exp, _ := SubscriptionPlan{Expires: expires}.nextExpiry(time.Now())
	if info != "upload=20000000000; download=48730000000; total=100000000000; expire="+itoa(int(exp.Unix())) {
		t.Fatal(info)
	}
	if hd := get(h, "HEAD", "/s/"+token); hd.Header().Get("Subscription-Userinfo") != info {
		t.Fatal("HEAD differs")
	}

	// A subscription without a plan is byte-identical to before and has no header.
	p := get(h, "GET", "/s/"+plainToken)
	if p.Header().Get("Subscription-Userinfo") != "" || len(infoNames(t, p.Body.String())) != 0 || p.Body.String() != baseline.Body.String() && plain.NodeIDs[0] == "" {
		t.Fatal("plan-less subscription changed")
	}
	if p.Body.String() != baseline.Body.String() {
		t.Fatal("plan-less subscriptions with the same nodes must keep identical bytes")
	}

	// Mihomo: same lines, in a separate group that no automatic group references.
	y := get(h, "GET", "/s/"+token+"?format=mihomo").Body.String()
	for _, line := range want {
		if !strings.Contains(y, `"name":"`+line+`"`) {
			t.Fatalf("missing proxy %q in\n%s", line, y)
		}
	}
	if !strings.Contains(y, `"name":"📊 Info"`) || !strings.Contains(y, `"type":"select"`) {
		t.Fatalf("info group missing:\n%s", y)
	}
	for _, group := range []string{`"name":"🚀 Proxy"`, `"name":"⚡ Auto"`, `"name":"🛡️ Fallback"`} {
		i := strings.Index(y, group)
		j := strings.Index(y[i:], "\n")
		if i < 0 || strings.Contains(y[i:i+j], "Remaining data") {
			t.Fatalf("info node leaked into %s", group)
		}
	}
	if get(h, "GET", "/s/"+plainToken+"?format=mihomo").Body.String() != renderMihomo(mustMihomo(t, sc, plain), nil, mihomoDefaultTestURL) {
		t.Fatal("plan-less Mihomo output changed")
	}

	// Chinese manager language gives the names of the original screenshot.
	sc.a.Language = "zh-CN"
	zh := infoNames(t, get(h, "GET", "/s/"+token).Body.String())
	if zh[0] != "剩余流量：31.27 GB" || zh[1] != "距离下次重置剩余："+itoa(days)+" 天" || zh[2] != "套餐到期："+expires {
		t.Fatalf("%q", zh)
	}
}

func mustMihomo(t *testing.T, sc *subScene, sub Subscription) []M {
	t.Helper()
	proxies, _ := sc.state(t).exportMihomo(sub)
	return proxies
}

func TestPlanWithoutLimitShowsOnlyExpiry(t *testing.T) {
	sc := newSubScene(t)
	sub, token := sc.create(t, "dated", 0)
	if e := sc.a.SetSubscriptionPlan(sub.ID, SubscriptionPlan{Expires: "2099-05-17"}); e != nil {
		t.Fatal(e) // no traffic monitoring is required without a limit
	}
	h := sc.a.subscriptionHTTPHandler(sc.a.Load, func(string, ...any) {})
	w := get(h, "GET", "/s/"+token)
	if names := infoNames(t, w.Body.String()); len(names) != 1 || names[0] != "Plan expires: 2099-05-17" {
		t.Fatalf("%q", names)
	}
	if !strings.HasPrefix(w.Header().Get("Subscription-Userinfo"), "expire=") || strings.Contains(w.Header().Get("Subscription-Userinfo"), "total") {
		t.Fatal(w.Header().Get("Subscription-Userinfo"))
	}
}

func TestPlanSettingsValidationAndSchema(t *testing.T) {
	sc := newSubScene(t)
	sub, _ := sc.create(t, "p", 0)
	if e := sc.a.SetSubscriptionPlan(sub.ID, SubscriptionPlan{LimitBytes: 1_000_000_000}); e == nil {
		t.Fatal("a finite allowance needs traffic monitoring")
	}
	enableTrafficMarker(t, sc.a)
	for _, bad := range []SubscriptionPlan{{LimitBytes: 1, BillingDay: 32}, {BillingDay: -1}, {Timezone: "Mars/Base"}, {Expires: "soon"}} {
		if sc.a.SetSubscriptionPlan(sub.ID, bad) == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
	if e := sc.a.UpdateSubscriptionPlan(sub.ID, func(p *SubscriptionPlan) { p.LimitBytes = 50_000_000_000; p.BillingDay = 15 }); e != nil {
		t.Fatal(e)
	}
	s := sc.state(t)
	if s.Schema != 2 || s.Subscriptions[0].Plan.BillingDay != 15 {
		t.Fatalf("schema %d plan %+v", s.Schema, s.Subscriptions[0].Plan)
	}
	// A limit cannot be smuggled in through the unprotected schema.
	b, _ := json.Marshal(s)
	var raw map[string]any
	_ = json.Unmarshal(b, &raw)
	raw["schema"] = 1
	b, _ = json.Marshal(raw)
	if _, e := DecodeState(b); e == nil {
		t.Fatal("schema 1 with an allowance accepted")
	}
	// Only the monitor's marker is needed to *change* the limit, not to edit the date.
	_ = os.Remove(filepath.Join(sc.a.Home, "traffic.enabled"))
	if e := sc.a.UpdateSubscriptionPlan(sub.ID, func(p *SubscriptionPlan) { p.Expires = "2099-01-01" }); e != nil {
		t.Fatal(e)
	}
	if e := sc.a.SetSubscriptionPlan(sub.ID, SubscriptionPlan{}); e != nil {
		t.Fatal(e)
	}
	if sc.state(t).Subscriptions[0].Plan != nil {
		t.Fatal("empty plan must be removed")
	}
}

type poolHarness struct {
	t       *testing.T
	sc      *subScene
	sub     Subscription
	running map[string]bool
	now     time.Time
}

func newPoolHarness(t *testing.T, limit uint64) *poolHarness {
	sc := newSubScene(t)
	enableTrafficMarker(t, sc.a)
	sub, _ := sc.create(t, "pool", 0, 1)
	if e := sc.a.SetSubscriptionPlan(sub.ID, SubscriptionPlan{LimitBytes: limit, Timezone: "UTC"}); e != nil {
		t.Fatal(e)
	}
	h := &poolHarness{t: t, sc: sc, sub: sub, running: map[string]bool{}, now: time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)}
	for _, id := range sub.NodeIDs {
		h.running[id] = true
	}
	sc.a.poolRunning = func(p Profile) bool { return h.running[p.ID] }
	return h
}

func (h *poolHarness) poll(step time.Duration, counters map[string][2]uint64) poolOutcome {
	h.t.Helper()
	h.now = h.now.Add(step)
	writeNodeCounters(h.t, h.sc.a, h.now, counters)
	out, e := h.sc.a.syncPools(h.sc.state(h.t), h.now)
	if e != nil {
		h.t.Fatal(e)
	}
	return out
}

func (h *poolHarness) record() PoolRecord {
	h.t.Helper()
	pools, e := h.sc.a.loadPools()
	if e != nil {
		h.t.Fatal(e)
	}
	return pools.Records[h.sub.ID]
}

func stopped(acts trafficActions) []string {
	var ids []string
	for _, p := range acts.stop {
		ids = append(ids, p.ID)
	}
	return ids
}

func TestPoolSharesAllowanceAcrossNodesAndStopsThem(t *testing.T) {
	h := newPoolHarness(t, 100_000_000)
	a, b := h.sub.NodeIDs[0], h.sub.NodeIDs[1]
	// Earlier traffic of the nodes is not charged to a new allowance.
	h.poll(0, map[string][2]uint64{a: {7_000_000_000, 9_000_000_000}, b: {1_000, 2_000}})
	if r := h.record(); r.used() != 0 || len(r.Marks) != 2 {
		t.Fatalf("%+v", r)
	}
	out := h.poll(5*time.Second, map[string][2]uint64{a: {7_030_000_000, 9_030_000_000}, b: {1_000, 20_002_000}})
	if r := h.record(); r.Up != 30_000_000 || r.Down != 50_000_000 {
		t.Fatalf("upload/download are summed per direction across nodes: %+v", r)
	}
	if len(out.blocked) != 0 || len(out.acts.stop) != 0 {
		t.Fatal("80 MB of 100 MB must not stop anything")
	}
	// The second node pushes the SHARED total over the limit although neither node
	// reached 100 MB by itself.
	out = h.poll(5*time.Second, map[string][2]uint64{a: {7_030_000_000, 9_030_000_000}, b: {1_000, 40_002_000}})
	if !out.blocked[a] || !out.blocked[b] || len(stopped(out.acts)) != 2 {
		t.Fatalf("both nodes must be blocked and stopped: %+v %v", out.blocked, stopped(out.acts))
	}
	if r := h.record(); len(r.Paused) != 2 {
		t.Fatalf("stopped nodes must be remembered: %+v", r)
	}
	// Restarting a node by hand does not bypass the allowance: it is stopped again.
	h.running[a] = false
	h.running[b] = false
	out = h.poll(5*time.Second, map[string][2]uint64{a: {7_030_000_000, 9_030_000_000}, b: {1_000, 40_002_000}})
	if len(out.acts.stop) != 0 || len(out.acts.start) != 0 || !out.blocked[a] {
		t.Fatal("stays blocked, nothing to do while the nodes are down")
	}
	h.running[b] = true
	out = h.poll(5*time.Second, map[string][2]uint64{a: {7_030_000_000, 9_030_000_000}, b: {1_000, 40_002_000}})
	if got := stopped(out.acts); len(got) != 1 || got[0] != b {
		t.Fatalf("manual restart must be undone, got %v", got)
	}
	// The per-node resume of the quota engine cannot override the allowance.
	acts := out.apply(trafficActions{start: []Profile{{ID: a}, {ID: "unrelated"}}})
	if len(acts.start) != 1 || acts.start[0].ID != "unrelated" {
		t.Fatalf("a blocked node must not be resumed: %+v", acts.start)
	}
	// Raising the limit resumes exactly the nodes the allowance stopped, once.
	h.running[b] = false
	if e := h.sc.a.UpdateSubscriptionPlan(h.sub.ID, func(p *SubscriptionPlan) { p.LimitBytes = 10_000_000_000 }); e != nil {
		t.Fatal(e)
	}
	out = h.poll(5*time.Second, map[string][2]uint64{a: {7_030_000_000, 9_030_000_000}, b: {1_000, 40_002_000}})
	if len(out.blocked) != 0 || len(out.acts.start) != 2 {
		t.Fatalf("both nodes should be resumed: %+v", out.acts.start)
	}
	h.running[a], h.running[b] = true, true
	h.poll(5*time.Second, map[string][2]uint64{a: {7_030_000_000, 9_030_000_000}, b: {1_000, 40_002_000}})
	if r := h.record(); len(r.Paused) != 0 {
		t.Fatalf("resumed nodes are forgotten once running: %+v", r)
	}
}

// A member that is down for its own quota when the pool empties is remembered too: its
// resume is swallowed while the pool blocks it, and must happen once the pool clears.
func TestPoolResumesEnabledMembersButNeverDisabledOnes(t *testing.T) {
	h := newPoolHarness(t, 10_000_000_000)
	a, b := h.sub.NodeIDs[0], h.sub.NodeIDs[1]
	c := h.sc.nodes[2].ID
	s := h.sc.state(t)
	pc, _ := Find(s, c)
	pc.Enabled = false
	if e := h.sc.a.Commit(s, replace(s, pc), false); e != nil {
		t.Fatal(e)
	}
	if e := h.sc.a.SetSubscriptionNodes(h.sub.ID, []string{a, b, c}); e != nil {
		t.Fatal(e)
	}
	h.running[a] = false // down for its own quota
	h.running[c] = false
	h.poll(0, map[string][2]uint64{a: {0, 0}, b: {0, 0}, c: {0, 0}})
	out := h.poll(5*time.Second, map[string][2]uint64{a: {0, 0}, b: {0, 11_000_000_000}, c: {0, 0}})
	if got := stopped(out.acts); len(got) != 1 || got[0] != b {
		t.Fatalf("%v", got)
	}
	if r := h.record(); !contains(r.Paused, a) || !contains(r.Paused, b) || contains(r.Paused, c) {
		t.Fatalf("enabled members only: %v", r.Paused)
	}
	// The node's own resume is filtered while blocked; the pool remembers it.
	if acts := out.apply(trafficActions{start: []Profile{{ID: a}}}); len(acts.start) != 0 {
		t.Fatal("blocked resume must be filtered")
	}
	if e := h.sc.a.UpdateSubscriptionPlan(h.sub.ID, func(p *SubscriptionPlan) { p.LimitBytes = 0 }); e != nil {
		t.Fatal(e)
	}
	h.running[b] = false
	out = h.poll(5*time.Second, map[string][2]uint64{a: {0, 0}, b: {0, 11_000_000_000}, c: {0, 0}})
	var started []string
	for _, p := range out.acts.start {
		started = append(started, p.ID)
	}
	if len(started) != 2 || !contains(started, a) || !contains(started, b) {
		t.Fatalf("both enabled members resume and the disabled one stays down: %v", started)
	}
	h.running[a], h.running[b] = true, true
	h.poll(5*time.Second, map[string][2]uint64{a: {0, 0}, b: {0, 11_000_000_000}, c: {0, 0}})
	if pools, _ := h.sc.a.loadPools(); len(pools.Records) != 0 {
		t.Fatal("an unused record is removed")
	}
}

func TestPoolGivesUpOnNodesThatNeverStart(t *testing.T) {
	h := newPoolHarness(t, 10_000_000_000)
	a, b := h.sub.NodeIDs[0], h.sub.NodeIDs[1]
	h.poll(0, map[string][2]uint64{a: {0, 0}, b: {0, 0}})
	h.poll(5*time.Second, map[string][2]uint64{a: {0, 11_000_000_000}, b: {0, 0}})
	if e := h.sc.a.UpdateSubscriptionPlan(h.sub.ID, func(p *SubscriptionPlan) { p.LimitBytes = 0 }); e != nil {
		t.Fatal(e)
	}
	h.running[a], h.running[b] = false, false
	attempts := 0
	for i := 0; i < 40; i++ {
		out := h.poll(poolStartRetry, map[string][2]uint64{a: {0, 11_000_000_000}, b: {0, 0}})
		for _, p := range out.acts.start {
			if p.ID == a {
				attempts++
			}
		}
	}
	if attempts != poolStartAttempts {
		t.Fatalf("a node that cannot start is attempted %d times, want %d", attempts, poolStartAttempts)
	}
	if pools, _ := h.sc.a.loadPools(); len(pools.Records) != 0 {
		t.Fatal("given-up nodes must not keep the record alive")
	}
}

func TestRestoreCannotCancelSubscriptionAllowance(t *testing.T) {
	sc := newSubScene(t)
	enableTrafficMarker(t, sc.a)
	sub, _ := sc.create(t, "limited", 0)
	older := filepath.Join(t.TempDir(), "older.json")
	b, e := JSON(sc.state(t))
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(older, b, 0600); e != nil {
		t.Fatal(e)
	}
	if e = sc.a.SetSubscriptionPlan(sub.ID, SubscriptionPlan{LimitBytes: 5_000_000_000, Expires: "2099-01-01"}); e != nil {
		t.Fatal(e)
	}
	// A backup made before the allowance existed keeps the current plan.
	if e = sc.a.Restore(older); e != nil {
		t.Fatal(e)
	}
	s := sc.state(t)
	if s.Schema != 2 || len(s.Subscriptions) != 1 || s.Subscriptions[0].Plan == nil || s.Subscriptions[0].Plan.LimitBytes != 5_000_000_000 {
		t.Fatalf("allowance cancelled by restore: %+v", s.Subscriptions)
	}
	// A backup without the limited subscription is refused, leaving the state untouched.
	without := sc.state(t)
	without.Subscriptions = nil
	b, _ = JSON(without)
	missing := filepath.Join(t.TempDir(), "missing.json")
	if e = os.WriteFile(missing, b, 0600); e != nil {
		t.Fatal(e)
	}
	if e = sc.a.Restore(missing); e == nil {
		t.Fatal("restore silently dropped a subscription with an allowance")
	}
	if got := sc.state(t).Subscriptions; len(got) != 1 || got[0].Plan == nil {
		t.Fatal("state changed by a refused restore")
	}
}

func TestPoolCycleResetAndCounterAnomalies(t *testing.T) {
	h := newPoolHarness(t, 100_000_000)
	a, b := h.sub.NodeIDs[0], h.sub.NodeIDs[1]
	h.poll(0, map[string][2]uint64{a: {0, 0}, b: {0, 0}})
	h.poll(5*time.Second, map[string][2]uint64{a: {0, 150_000_000}, b: {0, 0}})
	r := h.record()
	if r.used() != 150_000_000 {
		t.Fatal(r.used())
	}
	// The next boundary (1st of the month) starts a new allowance and unblocks.
	h.now = time.Date(2026, 10, 31, 23, 59, 58, 0, time.UTC)
	h.poll(3*time.Second, map[string][2]uint64{a: {0, 160_000_000}, b: {0, 0}})
	r = h.record()
	if r.used() != 0 || r.Start.Format("2006-01-02") != "2026-11-01" || r.Incomplete {
		t.Fatalf("%+v", r)
	}
	out := h.poll(5*time.Second, map[string][2]uint64{a: {0, 170_000_000}, b: {0, 0}})
	if len(out.blocked) != 0 || h.record().used() != 10_000_000 {
		t.Fatalf("the new cycle counts only new traffic: %d", h.record().used())
	}
	// A clock set back cannot mint another cycle.
	before := h.record()
	h.now = h.now.Add(-48 * time.Hour)
	writeNodeCounters(t, h.sc.a, h.now, map[string][2]uint64{a: {0, 170_000_000}, b: {0, 0}})
	if _, e := h.sc.a.syncPools(h.sc.state(t), h.now); e != nil {
		t.Fatal(e)
	}
	if after := h.record(); after.Start != before.Start || after.used() != before.used() {
		t.Fatal("clock rollback changed the cycle")
	}
	// A counter that went backwards is charged in full and flagged, never negative.
	h.now = before.Seen.Add(time.Minute)
	writeNodeCounters(t, h.sc.a, h.now, map[string][2]uint64{a: {0, 5_000_000}, b: {0, 0}})
	if _, e := h.sc.a.syncPools(h.sc.state(t), h.now); e != nil {
		t.Fatal(e)
	}
	if r := h.record(); !r.Incomplete || r.used() != 15_000_000 {
		t.Fatalf("%+v", r)
	}
	// Nodes added later start from their current counters.
	c := h.sc.nodes[2].ID
	if e := h.sc.a.SetSubscriptionNodes(h.sub.ID, []string{a, b, c}); e != nil {
		t.Fatal(e)
	}
	h.poll(5*time.Second, map[string][2]uint64{a: {0, 5_000_000}, b: {0, 0}, c: {50_000_000_000, 50_000_000_000}})
	if r := h.record(); r.used() != 15_000_000 || len(r.Marks) != 3 {
		t.Fatalf("history of a joining node must not be charged: %+v", r)
	}
}

func TestPoolManualResetKeepsPausedNodesAndRebuildsCorruptJournal(t *testing.T) {
	h := newPoolHarness(t, 100_000_000)
	a, b := h.sub.NodeIDs[0], h.sub.NodeIDs[1]
	h.poll(0, map[string][2]uint64{a: {0, 0}, b: {0, 0}})
	h.poll(5*time.Second, map[string][2]uint64{a: {0, 200_000_000}, b: {0, 0}})
	if len(h.record().Paused) == 0 {
		t.Fatal("setup")
	}
	if e := h.sc.a.ResetSubscriptionUsage(h.sub.ID, h.now.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	r := h.record()
	if r.used() != 0 || len(r.Paused) == 0 {
		t.Fatalf("reset must zero usage but keep the nodes it has to resume: %+v", r)
	}
	// Tampered or truncated journals are errors, never an empty (fresh) allowance.
	path := h.sc.a.poolPath()
	b64, _ := os.ReadFile(path)
	if e := os.WriteFile(path, []byte(strings.Replace(string(b64), `"upload": 0`, `"upload": 1`, 1)), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := h.sc.a.loadPools(); e == nil {
		t.Fatal("checksum not enforced")
	}
	if _, e := h.sc.a.syncPools(h.sc.state(t), h.now); e == nil {
		t.Fatal("the monitor must not continue on a damaged journal")
	}
	if e := h.sc.a.ResetSubscriptionUsage(h.sub.ID, h.now.Add(2*time.Second)); e != nil {
		t.Fatal(e)
	}
	if _, e := h.sc.a.loadPools(); e != nil {
		t.Fatal("reset must rebuild a damaged journal:", e)
	}
	if m, _ := filepath.Glob(filepath.Join(h.sc.a.Home, "backups", "subscription-traffic-corrupt-*.json")); len(m) != 1 {
		t.Fatal("a private copy of the damaged journal must be kept")
	}
}

func TestSubscriptionPlanCommand(t *testing.T) {
	sc := newSubScene(t)
	enableTrafficMarker(t, sc.a)
	sub, _ := sc.create(t, "cli", 0)
	u, out := testUI(sc.a, "")
	for _, args := range [][]string{{sub.ID, "limit", "100"}, {sub.ID, "reset-day", "28"}, {sub.ID, "expires", "2099-02-03"}} {
		if e := u.subscriptionPlanCommand(args); e != nil {
			t.Fatal(args, e)
		}
	}
	p := *sc.state(t).Subscriptions[0].Plan
	if p.LimitBytes != 100_000_000_000 || p.BillingDay != 28 || p.Expires != "2099-02-03" {
		t.Fatalf("%+v", p)
	}
	out.Reset()
	if e := u.subscriptionPlanCommand([]string{sub.ID}); e != nil || !strings.Contains(out.String(), "100 GB") || !strings.Contains(out.String(), "2099-02-03") {
		t.Fatalf("%v\n%s", e, out.String())
	}
	for _, args := range [][]string{{sub.ID, "limit", "lots"}, {sub.ID, "reset-day", "0"}, {sub.ID, "expires", "later"}, {sub.ID, "frobnicate"}, {"000000000000", "show"}} {
		if u.subscriptionPlanCommand(args) == nil {
			t.Fatal("accepted", args)
		}
	}
	if e := u.subscriptionPlanCommand([]string{sub.ID, "expires", "none"}); e != nil {
		t.Fatal(e)
	}
	if sc.state(t).Subscriptions[0].Plan.Expires != "" {
		t.Fatal("expiry not cleared")
	}
	if e := u.subscriptionPlanCommand([]string{sub.ID, "clear"}); e != nil || sc.state(t).Subscriptions[0].Plan != nil {
		t.Fatal("clear failed", e)
	}
}

func TestSubscriptionPlanMenu(t *testing.T) {
	sc := newSubScene(t)
	enableTrafficMarker(t, sc.a)
	sub, _ := sc.create(t, "menu", 0)
	// 1 limit, 3 expiry date, then back.
	u, out := testUI(sc.a, "1\n250 GB\n3\n2099-12-31\n0\n")
	if e := u.subscriptionPlanMenu(sub.ID); e != nil {
		t.Fatal(e)
	}
	p := sc.state(t).Subscriptions[0].Plan
	if p == nil || p.LimitBytes != 250_000_000_000 || p.Expires != "2099-12-31" {
		t.Fatalf("%+v\n%s", p, out.String())
	}
}

func TestShadowrocketImportLinkCarriesSubscriptionName(t *testing.T) {
	link := shadowrocketImportURL("https://sub.example.com/s/TOKEN", "我的 订阅 &x")
	rest, ok := strings.CutPrefix(link, "shadowrocket://add/sub://")
	if !ok {
		t.Fatal(link)
	}
	enc, query, _ := strings.Cut(rest, "?")
	raw, e := base64.StdEncoding.DecodeString(enc)
	if e != nil || string(raw) != "https://sub.example.com/s/TOKEN" {
		t.Fatalf("%q %v", raw, e)
	}
	q, e := url.ParseQuery(query)
	if e != nil || q.Get("remark") != "我的 订阅 &x" || strings.Contains(link, "+") && !strings.Contains(enc, "+") {
		t.Fatalf("%q %v", query, e)
	}
	if strings.ContainsAny(query, " +&") && strings.Count(query, "&") > 0 {
		t.Fatal("name not escaped:", query)
	}
}
