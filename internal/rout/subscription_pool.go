package rout

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Shared subscription allowance. Every managed listener is already metered per node
// (traffic.go); the monitor adds each node's growth since its previous poll to the
// subscription's own cycle total here. This is a userspace budget enforced with the
// monitor's 5-second cadence by stopping the subscription's nodes, not a per-packet
// kernel gate like a node's own limit (which keeps working independently on top of it).
// It lives in its own journal so traffic.json stays readable by older monitors.

const poolFile = "subscription-traffic.json"

// PoolMark is a node's absolute kernel byte counters at the previous poll.
type PoolMark struct {
	Up   uint64 `json:"up"`
	Down uint64 `json:"down"`
}

type PoolRecord struct {
	Up         uint64              `json:"upload"`
	Down       uint64              `json:"download"`
	Start      time.Time           `json:"cycle_start"`
	Next       time.Time           `json:"next_reset"`
	Seen       time.Time           `json:"last_seen"`
	Schedule   string              `json:"schedule"`
	Marks      map[string]PoolMark `json:"marks"`
	Incomplete bool                `json:"incomplete,omitempty"`
	// Nodes this allowance stopped and must start again once it is available.
	Paused []string `json:"paused,omitempty"`
}

type PoolState struct {
	Version  int                   `json:"version"`
	Records  map[string]PoolRecord `json:"records"`
	Updated  time.Time             `json:"updated"`
	Checksum string                `json:"checksum,omitempty"`
}

func satAdd(a, b uint64) uint64 {
	if a > math.MaxUint64-b {
		return math.MaxUint64
	}
	return a + b
}

func (r PoolRecord) used() uint64 { return satAdd(r.Up, r.Down) }

func poolChecksum(s PoolState) string {
	s.Checksum = ""
	b, _ := json.Marshal(s)
	return fmt.Sprintf("%x", sha256.Sum256(b))
}

func (a *App) poolPath() string { return filepath.Join(a.Home, poolFile) }

// loadPools never fails on a missing file. A damaged one is an error and is never
// mistaken for an empty journal (which would hand out a fresh allowance).
func (a *App) loadPools() (PoolState, error) {
	s := PoolState{Version: 1, Records: map[string]PoolRecord{}}
	f, e := os.Open(a.poolPath())
	if os.IsNotExist(e) {
		return s, nil
	}
	if e != nil {
		return s, e
	}
	defer f.Close()
	bad := errors.New("订阅流量状态损坏；请运行 rout subscription plan ID reset 重建")
	var loaded PoolState
	decoder := json.NewDecoder(io.LimitReader(f, 4<<20))
	decoder.DisallowUnknownFields()
	if e = decoder.Decode(&loaded); e != nil || decoder.Decode(new(any)) != io.EOF {
		return s, bad
	}
	if loaded.Version != 1 || loaded.Records == nil || loaded.Checksum != poolChecksum(loaded) {
		return s, bad
	}
	for id, r := range loaded.Records {
		if !idPattern.MatchString(id) || r.Next.IsZero() || !r.Next.After(r.Start) {
			return s, bad
		}
		if r.Marks == nil {
			r.Marks = map[string]PoolMark{}
			loaded.Records[id] = r
		}
	}
	return loaded, nil
}

func (a *App) savePools(s PoolState) error {
	s.Checksum = poolChecksum(s)
	b, e := JSON(s)
	if e != nil {
		return e
	}
	return AtomicWrite(a.poolPath(), b, 0600)
}

func (a *App) poolLock() (func(), error) {
	return lockFile(filepath.Join(a.Home, ".subscription-traffic.lock"), heartbeatLockWait)
}

func newPoolRecord(policy TrafficPolicy, now time.Time) PoolRecord {
	s, n := trafficWindow(now, policy)
	return PoolRecord{Start: s, Next: n, Seen: now, Schedule: trafficSchedule(policy, now), Marks: map[string]PoolMark{}}
}

func (r *PoolRecord) reset(now time.Time, policy TrafficPolicy, manual bool) {
	r.Up, r.Down, r.Incomplete = 0, 0, false
	r.Start, r.Next = trafficWindow(now, policy)
	if manual {
		r.Start = now
	}
	r.Seen = now
}

// Same rules as a node's cycle: clock rollbacks cannot mint a cycle and a changed
// billing day only reschedules the next boundary.
func (r *PoolRecord) advance(now time.Time, policy TrafficPolicy) {
	if now.Before(r.Seen) {
		return
	}
	r.Seen = now
	if schedule := trafficSchedule(policy, now); schedule != r.Schedule {
		r.Schedule = schedule
		_, r.Next = trafficWindow(now, policy)
		return
	}
	if !now.Before(r.Next) {
		if start, _ := trafficWindow(now, policy); start.After(r.Start) {
			r.reset(now, policy, false)
		}
	}
}

// accumulate adds each member node's growth since the previous poll. A node new to the
// subscription starts at its current counters: earlier traffic is not charged. A counter
// that went backwards (observation restarted) is charged in full and flagged.
func (r *PoolRecord) accumulate(ids []string, db TrafficState) {
	keep := map[string]PoolMark{}
	for _, id := range ids {
		rec, ok := db.Records[id]
		if !ok {
			if mark, had := r.Marks[id]; had {
				keep[id] = mark
			}
			continue
		}
		now := PoolMark{rec.RawUp, rec.RawDown}
		mark, had := r.Marks[id]
		switch {
		case !had:
		case now.Up >= mark.Up && now.Down >= mark.Down:
			r.Up = satAdd(r.Up, now.Up-mark.Up)
			r.Down = satAdd(r.Down, now.Down-mark.Down)
		default:
			r.Up, r.Down = satAdd(r.Up, now.Up), satAdd(r.Down, now.Down)
			r.Incomplete = true
		}
		keep[id] = now
	}
	r.Marks = keep
}

func poolFingerprint(s PoolState) string {
	records := map[string]PoolRecord{}
	for id, r := range s.Records {
		r.Seen = time.Time{}
		records[id] = r
	}
	b, _ := json.Marshal(records)
	return fmt.Sprintf("%x", sha256.Sum256(b))
}

// poolOutcome is what one poll decided: the nodes that must not run now and the
// lifecycle actions to perform (after every lock is released).
type poolOutcome struct {
	blocked map[string]bool
	acts    trafficActions
}

// apply merges the allowance's decisions into the node accounting actions: a node the
// per-node accounting wants to resume stays down while any allowance blocks it.
func (o poolOutcome) apply(acts trafficActions) trafficActions {
	var start []Profile
	for _, p := range acts.start {
		if !o.blocked[p.ID] {
			start = append(start, p)
		}
	}
	acts.start = start
	acts.merge(o.acts)
	return acts
}

func (a *App) poolNodeRunning(p Profile) bool {
	if a.poolRunning != nil {
		return a.poolRunning(p)
	}
	m, e := a.serviceManager()
	return e == nil && m != "none" && serviceActive(m, serviceName(p))
}

// A start that keeps failing is retried at most twice a minute, and given up after
// poolStartAttempts tries: service commands run while the monitor holds the configuration
// lock, so a node that cannot start (broken certificate, port taken) must not be attempted
// every poll forever.
const (
	poolStartRetry    = 30 * time.Second
	poolStartAttempts = 10
)

type poolTry struct {
	last  time.Time
	count int
}

var (
	poolTriedMu sync.Mutex
	poolTried   = map[string]poolTry{}
)

// poolStartAttempt reports whether a start may be tried now, and whether to give up.
func (a *App) poolStartAttempt(id string, now time.Time) (try, giveUp bool) {
	key := a.Home + "\x00" + id
	poolTriedMu.Lock()
	defer poolTriedMu.Unlock()
	t := poolTried[key]
	if t.count >= poolStartAttempts {
		delete(poolTried, key)
		return false, true
	}
	if t.count > 0 && now.Sub(t.last) < poolStartRetry && !now.Before(t.last) {
		return false, false
	}
	poolTried[key] = poolTry{last: now, count: t.count + 1}
	return true, false
}

func (a *App) poolStartDone(id string) {
	poolTriedMu.Lock()
	delete(poolTried, a.Home+"\x00"+id)
	poolTriedMu.Unlock()
}

// syncPools runs after the per-node sync, with that sync's journal already written, so
// the raw counters it reads are those of the same poll. It never touches nodes, quotas
// or tables: it only reads node counters and starts/stops services outside any lock.
func (a *App) syncPools(state State, now time.Time) (poolOutcome, error) {
	out := poolOutcome{blocked: map[string]bool{}}
	limited := false
	for _, sub := range state.Subscriptions {
		limited = limited || (sub.Plan != nil && sub.Plan.LimitBytes > 0)
	}
	if _, e := os.Stat(a.poolPath()); !limited && os.IsNotExist(e) {
		return out, nil // nothing configured, nothing to read
	}
	unlock, e := a.poolLock()
	if e != nil {
		return out, e
	}
	defer unlock()
	pools, e := a.loadPools()
	if e != nil {
		return out, e
	}
	db, e := a.loadTraffic()
	if e != nil {
		return out, e
	}
	before := poolFingerprint(pools)
	subs := map[string]Subscription{}
	for _, sub := range state.Subscriptions {
		subs[sub.ID] = sub
	}
	// First account usage of every allowance, so that a node shared by several of
	// them is blocked by whichever is exhausted.
	exhausted := map[string]bool{}
	for _, sub := range state.Subscriptions {
		if sub.Plan == nil || sub.Plan.LimitBytes == 0 {
			continue
		}
		policy := sub.Plan.policy()
		rec, ok := pools.Records[sub.ID]
		if !ok {
			rec = newPoolRecord(policy, now)
		}
		rec.accumulate(sub.NodeIDs, db)
		rec.advance(now, policy)
		pools.Records[sub.ID] = rec
		if rec.used() >= policy.LimitBytes {
			exhausted[sub.ID] = true
			for _, id := range sub.NodeIDs {
				out.blocked[id] = true
			}
		}
	}
	ids := make([]string, 0, len(pools.Records))
	for id := range pools.Records {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		rec := pools.Records[id]
		sub, live := subs[id]
		active := live && sub.Plan != nil && sub.Plan.LimitBytes > 0
		members := map[string]bool{}
		if active {
			for _, n := range sub.NodeIDs {
				members[n] = true
			}
		}
		if exhausted[id] {
			for _, n := range sub.NodeIDs {
				p, er := Find(state, n)
				if er != nil || !p.Enabled {
					continue
				}
				if a.poolNodeRunning(p) {
					out.acts.stopNode(p)
				}
				// Every enabled member is remembered, running or not: one that is down
				// for its own quota may have its resume swallowed (see poolOutcome.apply)
				// while this allowance blocks it, and must be started when it clears.
				if !contains(rec.Paused, n) {
					rec.Paused = append(rec.Paused, n)
				}
			}
		}
		// Nodes this allowance stopped resume once it can serve them again: the cycle
		// rolled over, the limit was raised or removed, or the node left the subscription.
		var still []string
		for _, n := range rec.Paused {
			if members[n] && exhausted[id] {
				still = append(still, n)
				continue
			}
			p, er := Find(state, n)
			if er != nil || !p.Enabled || a.poolNodeRunning(p) {
				a.poolStartDone(n)
				continue
			}
			// Another exhausted allowance, or the node's own quota, still holds it down.
			if out.blocked[n] || db.Records[n].Blocked != "" {
				still = append(still, n)
				continue
			}
			try, giveUp := a.poolStartAttempt(n, now)
			if giveUp {
				continue
			}
			still = append(still, n) // kept until the node is observed running
			if try {
				out.acts.startNode(p)
			}
		}
		rec.Paused = still
		if !active && len(rec.Paused) == 0 {
			delete(pools.Records, id)
			continue
		}
		pools.Records[id] = rec
	}
	if poolFingerprint(pools) != before || now.Sub(pools.Updated) >= 30*time.Second || pools.Updated.After(now) {
		pools.Updated = now
		if e = a.savePools(pools); e != nil {
			return out, e
		}
	}
	return out, nil
}

// ResetSubscriptionUsage starts a new cycle of the shared allowance now. It rebuilds a
// damaged journal (keeping a private copy), which is the explicit recovery path.
func (a *App) ResetSubscriptionUsage(id string, now time.Time) error {
	state, e := a.Load()
	if e != nil {
		return e
	}
	i, e := findSubscription(state, id)
	if e != nil {
		return e
	}
	sub := state.Subscriptions[i]
	if sub.Plan == nil || sub.Plan.LimitBytes == 0 {
		return errors.New("此订阅没有设置流量额度")
	}
	unlock, e := a.poolLock()
	if e != nil {
		return e
	}
	defer unlock()
	pools, e := a.loadPools()
	if e != nil {
		b, er := os.ReadFile(a.poolPath())
		if er != nil {
			return er
		}
		backup := filepath.Join(a.Home, "backups", "subscription-traffic-corrupt-"+time.Now().UTC().Format("20060102T150405.000000000")+".json")
		if er = AtomicWrite(backup, b, 0600); er != nil {
			return er
		}
		pools = PoolState{Version: 1, Records: map[string]PoolRecord{}}
	}
	policy := sub.Plan.policy()
	rec, ok := pools.Records[id]
	if !ok {
		rec = newPoolRecord(policy, now)
	}
	if now.Before(rec.Seen) {
		now = rec.Seen
	}
	rec.reset(now, policy, true)
	rec.Schedule = trafficSchedule(policy, now)
	pools.Records[id] = rec
	pools.Updated = now
	return a.savePools(pools)
}
