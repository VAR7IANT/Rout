package rout

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata"
)

// A zero limit is ALWAYS unlimited. Enabled remains the user's manual switch.
type TrafficPolicy struct {
	LimitBytes uint64 `json:"limit_bytes"`
	BillingDay int    `json:"billing_day"`
	Timezone   string `json:"timezone,omitempty"`
}

func (p Profile) trafficPolicy() TrafficPolicy {
	if p.Traffic == nil {
		return TrafficPolicy{BillingDay: 1}
	}
	return *p.Traffic
}
func (p TrafficPolicy) location() (*time.Location, error) {
	if p.Timezone == "" {
		return time.Local, nil
	}
	return time.LoadLocation(p.Timezone)
}
func (p TrafficPolicy) Validate() error {
	if p.LimitBytes > math.MaxInt64 || p.BillingDay < 1 || p.BillingDay > 31 {
		return errors.New("流量限额或账单日无效")
	}
	if _, e := p.location(); e != nil {
		return errors.New("账单时区无效，请使用 IANA 时区名称")
	}
	return nil
}

var sizePattern = regexp.MustCompile(`(?i)^([0-9]+(?:\.[0-9]+)?)\s*(MB|GB|TB)$`)

func parseUint(s string) (uint64, error) { return strconv.ParseUint(s, 10, 64) }
func ParseTrafficLimit(s string) (uint64, error) {
	m := sizePattern.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return 0, errors.New("请输入正数和 MB、GB 或 TB，例如 100 GB")
	}
	v, ok := new(big.Rat).SetString(m[1])
	if !ok {
		return 0, errors.New("流量限额无效")
	}
	mult := map[string]int64{"MB": 1_000_000, "GB": 1_000_000_000, "TB": 1_000_000_000_000}[strings.ToUpper(m[2])]
	v.Mul(v, new(big.Rat).SetInt64(mult))
	if !v.IsInt() || v.Sign() <= 0 || !v.Num().IsInt64() {
		return 0, errors.New("流量限额无效")
	}
	return v.Num().Uint64(), nil
}

// FormatTraffic shows decimal units with at most two decimals (100 GB, 38.25 GB).
// It truncates rather than rounds, so usage never appears to reach a limit early.
func FormatTraffic(n uint64) string {
	for _, u := range []struct {
		name string
		n    uint64
	}{{"TB", 1_000_000_000_000}, {"GB", 1_000_000_000}, {"MB", 1_000_000}} {
		if n >= u.n {
			v := fmt.Sprintf("%d.%02d", n/u.n, n%u.n*100/u.n)
			return strings.TrimSuffix(strings.TrimRight(v, "0"), ".") + " " + u.name
		}
	}
	return fmt.Sprintf("%d B", n)
}

// Boundaries are civil midnights, clamped BEFORE constructing the date (not AddDate).
func trafficWindow(now time.Time, p TrafficPolicy) (time.Time, time.Time) {
	z, _ := p.location()
	t := now.In(z)
	boundary := func(y int, m time.Month) time.Time {
		last := time.Date(y, m+1, 0, 12, 0, 0, 0, z).Day()
		day := p.BillingDay
		if day > last {
			day = last
		}
		return time.Date(y, m, day, 0, 0, 0, 0, z)
	}
	start := boundary(t.Year(), t.Month())
	if now.Before(start) {
		start = boundary(t.Year(), t.Month()-1)
	}
	return start, boundary(start.Year(), start.Month()+1)
}

type TrafficRecord struct {
	RawUp      uint64    `json:"raw_upload"`
	RawDown    uint64    `json:"raw_download"`
	BaseUp     uint64    `json:"base_upload"`
	BaseDown   uint64    `json:"base_download"`
	Consumed   uint64    `json:"quota_consumed"`
	Start      time.Time `json:"cycle_start"`
	Next       time.Time `json:"next_reset"`
	Seen       time.Time `json:"last_seen"`
	Observed   time.Time `json:"observed_since"`
	Boot       string    `json:"boot_id"`
	Shape      string    `json:"shape"`
	Rules      string    `json:"rules_hash"`
	Schedule   string    `json:"schedule"`
	Blocked    string    `json:"blocked,omitempty"`
	Incomplete bool      `json:"incomplete,omitempty"`
	Pending    bool      `json:"pending,omitempty"`
}

func (r TrafficRecord) totals() (uint64, uint64, uint64, error) {
	if r.RawUp < r.BaseUp || r.RawDown < r.BaseDown {
		return 0, 0, 0, errors.New("流量计数器损坏或回退")
	}
	u, d := r.RawUp-r.BaseUp, r.RawDown-r.BaseDown
	if u > math.MaxInt64 || d > math.MaxInt64-u {
		return 0, 0, 0, errors.New("流量计数器溢出")
	}
	return u, d, u + d, nil
}

type TrafficState struct {
	Version  int                      `json:"version"`
	Records  map[string]TrafficRecord `json:"records"`
	Updated  time.Time                `json:"updated"`
	Checksum string                   `json:"checksum,omitempty"`
}

func trafficChecksum(s TrafficState) string {
	s.Checksum = ""
	b, _ := json.Marshal(s)
	return fmt.Sprintf("%x", sha256.Sum256(b))
}

func (a *App) loadTraffic() (TrafficState, error) {
	s := TrafficState{Version: 1, Records: map[string]TrafficRecord{}}
	f, e := os.Open(filepath.Join(a.Home, "traffic.json"))
	if os.IsNotExist(e) {
		return s, nil
	}
	if e != nil {
		return s, e
	}
	defer f.Close()
	decoder := json.NewDecoder(io.LimitReader(f, 16<<20))
	decoder.DisallowUnknownFields()
	if e = decoder.Decode(&s); e != nil {
		return s, errors.New("流量状态损坏，有限额节点保持保护暂停")
	}
	if s.Version != 1 || s.Records == nil || decoder.Decode(new(any)) != io.EOF {
		return s, errors.New("流量状态损坏，有限额节点保持保护暂停")
	}
	if s.Checksum != trafficChecksum(s) {
		return s, errors.New("流量状态损坏，有限额节点保持保护暂停")
	}
	for id, r := range s.Records {
		if !idPattern.MatchString(id) || r.Next.IsZero() || !r.Next.After(r.Start) {
			return s, errors.New("流量状态损坏，有限额节点保持保护暂停")
		}
		if _, _, _, e = r.totals(); e != nil {
			return s, e
		}
	}
	return s, nil
}
func (a *App) saveTraffic(s TrafficState) error {
	s.Checksum = trafficChecksum(s)
	b, e := JSON(s)
	if e != nil {
		return e
	}
	return AtomicWrite(filepath.Join(a.Home, "traffic.json"), b, 0600)
}
func bootID() (string, error) {
	b, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	return strings.TrimSpace(string(b)), e
}
func (a *App) trafficActive() bool {
	_, e := os.Stat(filepath.Join(a.Home, "traffic.enabled"))
	return e == nil
}
func trafficShape(p Profile) string {
	b, _ := json.Marshal([]any{p.Listen, p.Port, p.Networks(), p.trafficPolicy().LimitBytes})
	return fmt.Sprintf("%x", sha256.Sum256(b))
}
func trafficSchedule(p TrafficPolicy, now time.Time) string {
	z, _ := p.location()
	_, winter := time.Date(now.Year(), 1, 1, 0, 0, 0, 0, z).Zone()
	_, summer := time.Date(now.Year(), 7, 1, 0, 0, 0, 0, z).Zone()
	return fmt.Sprintf("%d/%s/%d/%d", p.BillingDay, z, winter, summer)
}
func newTrafficRecord(p Profile, now time.Time, boot string) TrafficRecord {
	s, n := trafficWindow(now, p.trafficPolicy())
	return TrafficRecord{Start: s, Next: n, Seen: now, Observed: now, Boot: boot, Schedule: trafficSchedule(p.trafficPolicy(), now), Incomplete: p.CreatedAt == nil}
}
func (r *TrafficRecord) reset(now time.Time, p TrafficPolicy, manual bool) {
	r.BaseUp = r.RawUp
	r.BaseDown = r.RawDown
	r.Consumed = 0
	r.Blocked = ""
	r.Incomplete = false
	r.Start, r.Next = trafficWindow(now, p)
	if manual {
		r.Start = now
	}
	r.Seen = now
}

// Rollbacks cannot mint another cycle. A forward jump is held until the clock catches up.
func (r *TrafficRecord) advance(now time.Time, p TrafficPolicy) bool {
	if now.Before(r.Seen) {
		return false
	}
	r.Seen = now
	if schedule := trafficSchedule(p, now); schedule != r.Schedule {
		_, r.Next = trafficWindow(now, p)
		r.Schedule = schedule
		return false
	}
	if !now.Before(r.Next) {
		start, _ := trafficWindow(now, p)
		if start.After(r.Start) {
			r.reset(now, p, false)
			return true
		}
	}
	return false
}

// Snapshot values are absolute kernel counters, not deltas added each poll.
type MeterSnapshot struct {
	Up, Down, Consumed uint64
	Hash               string
}
type TrafficMeter interface {
	Read(Profile) (MeterSnapshot, error)
	Replace(Profile, TrafficRecord) (string, error)
	Freeze(Profile) error
	Renew(Profile) error
	Delete(Profile) error
}

var errMeterMissing = errors.New("meter missing")

func (a *App) meter() TrafficMeter {
	if a.trafficMeter != nil {
		return a.trafficMeter
	}
	return nftMeter{home: a.Home}
}
func mergeTraffic(r *TrafficRecord, s MeterSnapshot) error {
	if s.Up < r.RawUp || s.Down < r.RawDown || s.Consumed < r.Consumed {
		return errors.New("流量计数器损坏或回退")
	}
	next := *r
	next.RawUp = s.Up
	next.RawDown = s.Down
	next.Consumed = s.Consumed
	if _, _, _, e := next.totals(); e != nil {
		return e
	}
	*r = next
	return nil
}

// Block reasons. "sealed" is a verified graceful-shutdown checkpoint: the kernel gate
// was closed BEFORE the final counters were read and persisted, so no admitted byte
// can be missing. Only a running monitor that re-verifies it may reopen the gate.
const (
	blockQuota  = "quota"
	blockFault  = "fault"
	blockSealed = "sealed"
)

const (
	heartbeatLockWait = 4 * time.Second
	monitorConfigWait = 250 * time.Millisecond
	// Unchanged counters are re-persisted at least this often; guards require < 30 s.
	trafficRefresh = 15 * time.Second
)

// v0.2.1 graceful shutdowns wrote "fault" without marking a gap. Within the SAME boot
// the frozen kernel generation can still prove that checkpoint exact, so it is treated
// as sealed. Across a reboot nothing can verify it and it stays a fault.
func (r *TrafficRecord) normalizeLegacySeal(boot string) {
	if r.Blocked == blockFault && !r.Incomplete && !r.Pending && r.Rules != "" && r.Boot == boot {
		r.Blocked = blockSealed
	}
}

// A closed checkpoint may be restored only when the kernel cannot have admitted bytes
// since it was written: same boot with identical frozen counters, or a fresh boot
// with no surviving (possibly stale) Rout table.
func verifyClosedCheckpoint(r TrafficRecord, snap MeterSnapshot, readErr error, boot string) bool {
	if r.Rules == "" || r.Pending {
		return false
	}
	if r.Boot == boot {
		return readErr == nil && snap.Hash == r.Rules && snap.Up == r.RawUp && snap.Down == r.RawDown && snap.Consumed == r.Consumed
	}
	return errors.Is(readErr, errMeterMissing)
}

// Service lifecycle work produced by a sync. It always runs after the traffic lock is
// released: the kernel gate enforces limits by itself, and a slow init system must
// never delay other nodes' lease renewals.
type trafficActions struct {
	stop, start []Profile
	// Per-node meter errors. Only journal (load/save) failures are fatal to a sync.
	warn []error
}

func addProfile(list []Profile, p Profile) []Profile {
	for _, v := range list {
		if v.ID == p.ID {
			return list
		}
	}
	return append(list, p)
}
func (x *trafficActions) stopNode(p Profile)  { x.stop = addProfile(x.stop, p) }
func (x *trafficActions) startNode(p Profile) { x.start = addProfile(x.start, p) }
func (x *trafficActions) merge(y trafficActions) {
	for _, p := range y.stop {
		x.stopNode(p)
	}
	for _, p := range y.start {
		x.startNode(p)
	}
	x.warn = append(x.warn, y.warn...)
}
func (x trafficActions) warning() error { return errors.Join(x.warn...) }

// Interactive operations report other nodes' meter errors without failing.
func (a *App) warnTraffic(x trafficActions) {
	if e := x.warning(); e != nil {
		a.printf("提示：部分节点流量计量异常，运行 rout doctor 查看：%s\n", a.Error(e))
	}
}
func (a *App) runTrafficActions(x trafficActions, shutdown bool) error {
	var errs []error
	for _, p := range x.stop {
		if e := a.stopTrafficNode(p, shutdown); e != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p.Name, e))
		}
	}
	for _, p := range x.start {
		if e := a.startTrafficNode(p); e != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p.Name, e))
		}
	}
	return errors.Join(errs...)
}
func (a *App) stopTrafficNode(p Profile, shutdown bool) error {
	if a.trafficStop != nil {
		return a.trafficStop(p)
	}
	return a.stopServiceOnly(p, shutdown)
}
func (a *App) startTrafficNode(p Profile) error {
	if a.trafficStart != nil {
		return a.trafficStart(p)
	}
	return a.startService(p)
}

type meterRead struct {
	snap MeterSnapshot
	err  error
}

// Optional batching: one nft transaction per poll instead of one per node.
type batchMeter interface {
	ReadAll([]Profile) (map[string]meterRead, []string)
	RenewAll([]Profile) error
	DeleteTables([]string) error
}

func readMeters(m TrafficMeter, ps []Profile) (map[string]meterRead, []string) {
	if b, ok := m.(batchMeter); ok {
		return b.ReadAll(ps)
	}
	out := map[string]meterRead{}
	for _, p := range ps {
		s, e := m.Read(p)
		out[p.ID] = meterRead{s, e}
	}
	return out, nil
}

// A failed batch falls back per node, so one broken table cannot block other leases.
func renewMeters(m TrafficMeter, ps []Profile) map[string]error {
	errs := map[string]error{}
	if len(ps) == 0 {
		return errs
	}
	if b, ok := m.(batchMeter); ok && b.RenewAll(ps) == nil {
		return errs
	}
	for _, p := range ps {
		if e := m.Renew(p); e != nil {
			errs[p.ID] = e
		}
	}
	return errs
}

// Seen/Updated move every poll; they alone do not justify an fsynced rewrite.
func trafficFingerprint(s TrafficState) string {
	records := map[string]TrafficRecord{}
	for id, r := range s.Records {
		r.Seen = time.Time{}
		records[id] = r
	}
	b, _ := json.Marshal(records)
	return fmt.Sprintf("%x", sha256.Sum256(b))
}
func needsTrafficSave(db TrafficState, before string, previous, now time.Time) bool {
	return trafficFingerprint(db) != before || now.Sub(previous) >= trafficRefresh || previous.After(now)
}
func (a *App) currentBoot() (string, error) {
	if a.bootID != nil {
		return a.bootID()
	}
	return bootID()
}
func (a *App) trafficLock() (func(), error) {
	return lockFile(filepath.Join(a.Home, ".traffic.lock"), trafficLockWait)
}
func (a *App) syncTraffic(state State, now time.Time, shutdown bool) (trafficActions, error) {
	unlock, e := a.trafficLock()
	if e != nil {
		return trafficActions{}, e
	}
	defer unlock()
	return a.syncTrafficInner(state, now, shutdown)
}

// Called with the traffic lock held. No HTTP calls and no init-system commands.
func (a *App) syncTrafficInner(state State, now time.Time, shutdown bool) (trafficActions, error) {
	var acts trafficActions
	m := a.meter()
	boot, e := a.currentBoot()
	if e != nil {
		return acts, e
	}
	db, e := a.loadTraffic()
	if e != nil {
		for _, p := range state.Profiles {
			if p.trafficPolicy().LimitBytes > 0 {
				_ = m.Freeze(p)
				acts.stopNode(p)
			}
		}
		return acts, e
	}
	before, previousUpdate := trafficFingerprint(db), db.Updated
	reads, _ := readMeters(m, state.Profiles)
	var errs []error
	for _, p := range state.Profiles {
		r, exists := db.Records[p.ID]
		policy := p.trafficPolicy()
		limited := policy.LimitBytes > 0
		if !exists {
			r = newTrafficRecord(p, now, boot)
			if limited {
				r.Blocked = blockFault
				r.Incomplete = true
			}
		}
		if !limited {
			r.Blocked = "" // Unlimited nodes are never paused by accounting state.
		}
		r.normalizeLegacySeal(boot)
		if r.Blocked == blockSealed && (!a.monitorMode || shutdown) {
			db.Records[p.ID] = r
			continue
		}
		previous := r.Blocked
		read := reads[p.ID]
		snap, readErr := read.snap, read.err
		restored := false
		if limited && r.Blocked != "" && !r.Pending && (r.Blocked == blockSealed || r.Boot != boot) {
			if verifyClosedCheckpoint(r, snap, readErr, boot) {
				restored = true
				if r.Blocked == blockSealed {
					r.Blocked = ""
				}
			} else {
				r.Blocked = blockFault
				r.Incomplete = true
			}
		}
		healthy := restored
		if !restored {
			healthy = readErr == nil && r.Rules != "" && snap.Hash == r.Rules && !r.Pending && r.Boot == boot
			if healthy {
				if e = mergeTraffic(&r, snap); e != nil {
					healthy = false
					readErr = e
				}
			}
			if !healthy && exists {
				r.Incomplete = true
				if limited {
					r.Blocked = blockFault
				}
			}
		}
		rollover := r.advance(now, policy)
		quotaNew := limited && r.Consumed >= policy.LimitBytes && r.Blocked != blockQuota
		if quotaNew {
			r.Blocked = blockQuota
		}
		rebuild := !healthy || restored || r.Shape != trafficShape(p) || (rollover && limited) || quotaNew
		if shutdown && limited {
			if r.Blocked == "" {
				r.Blocked = blockSealed // Confirmed below only if the freeze/read succeeds.
			}
			rebuild = true
		}
		froze := false
		// Seal before sampling and replacing a live counter generation.
		if rebuild && readErr == nil {
			if e = m.Freeze(p); e != nil {
				errs = append(errs, fmt.Errorf("%s: %w", p.Name, e))
				if limited {
					r.Blocked = blockFault
					r.Incomplete = true
					r.Pending = true
					acts.stopNode(p)
					db.Records[p.ID] = r
					continue
				}
			} else {
				froze = true
				sealed, er := m.Read(p)
				if er == nil && (healthy || !exists) {
					// A first installation may find a surviving owned counter generation.
					// Preserve those bytes rather than replacing it with a zero record. The
					// missing journal cannot prove cycle boundaries, so keep the gap/fault.
					if !exists {
						r.Incomplete = true
					}
					er = mergeTraffic(&r, sealed)
				}
				if er != nil {
					r.Incomplete = true
					if limited {
						r.Blocked = blockFault
					}
				}
			}
			if rollover {
				r.reset(now, policy, false)
			}
		}
		if limited && r.Consumed >= policy.LimitBytes {
			r.Blocked = blockQuota
		}
		if rebuild {
			r.Pending = true
			r.Boot = boot
			db.Records[p.ID] = r
			if e = a.saveTraffic(db); e != nil {
				if limited {
					_ = m.Freeze(p)
					acts.stopNode(p)
				} else if froze {
					_ = m.Delete(p) // Fail open: an unlimited node keeps serving.
				}
				return acts, e
			}
			if r.Rules, e = m.Replace(p, r); e != nil {
				errs = append(errs, fmt.Errorf("%s: %w", p.Name, e))
				if limited {
					acts.stopNode(p)
				} else {
					_ = m.Delete(p)
					r.Incomplete = true
				}
				db.Records[p.ID] = r
				continue
			}
			r.Shape = trafficShape(p)
			r.Pending = false
		}
		if limited && r.Blocked != "" && (previous == "" || rebuild) {
			acts.stopNode(p)
		}
		if previous != "" && r.Blocked == "" && p.Enabled && !shutdown {
			acts.startNode(p)
		}
		db.Records[p.ID] = r
	}
	// Historical probes and missing configurations used indistinguishable names.
	// Ownership is not proof that an orphan no longer enforces a live limit.
	// Leave every orphan in place; doctor reports them for administrator review.
	db.Updated = now
	if shutdown || needsTrafficSave(db, before, previousUpdate, now) {
		if e = a.saveTraffic(db); e != nil {
			for _, p := range state.Profiles {
				if p.trafficPolicy().LimitBytes > 0 {
					_ = m.Freeze(p)
					acts.stopNode(p)
				}
			}
			return acts, e
		}
	}
	if !shutdown {
		var renew []Profile
		for _, p := range state.Profiles {
			r := db.Records[p.ID]
			if p.trafficPolicy().LimitBytes > 0 && r.Blocked == "" && !r.Pending {
				renew = append(renew, p)
			}
		}
		// A failed renewal needs no freeze: the kernel lease expires by itself and the
		// counters stay exact, so a transient error does not become a permanent fault.
		failed := renewMeters(m, renew)
		for _, p := range renew {
			if e := failed[p.ID]; e != nil {
				errs = append(errs, fmt.Errorf("%s: %w", p.Name, e))
			}
		}
	}
	acts.warn = append(acts.warn, errs...)
	return acts, nil
}
func (a *App) TrafficSync(now time.Time, shutdown bool) error {
	return a.trafficSync(now, shutdown, nil)
}

// The full sync holds the configuration lock only briefly; when a long configuration
// transaction owns it, a heartbeat keeps verified leases alive instead.
func (a *App) trafficSync(now time.Time, shutdown bool, ready func()) error {
	unlock, e := a.lockWait(monitorConfigWait)
	if e != nil {
		if !errors.Is(e, errLockBusy) {
			return e
		}
		acts, e := a.trafficHeartbeat(now, shutdown)
		if ready != nil {
			ready()
		}
		return errors.Join(e, acts.warning(), a.runTrafficActions(acts, shutdown))
	}
	defer unlock()
	state, e := a.Load()
	if e != nil {
		if ready != nil {
			ready()
		}
		return e
	}
	acts, e := a.syncTraffic(state, now, shutdown)
	if ready != nil {
		ready()
	}
	return errors.Join(e, acts.warning(), a.runTrafficActions(acts, shutdown))
}

// A slow engine download/service operation must not expire OTHER nodes' leases.
// This path never changes policy/cycles. Except for an explicit shutdown it only
// checkpoints counters and renews permits. The meter lock serializes transactions.
func (a *App) trafficHeartbeat(now time.Time, shutdown bool) (trafficActions, error) {
	var acts trafficActions
	unlock, e := lockFile(filepath.Join(a.Home, ".traffic.lock"), heartbeatLockWait)
	if e != nil {
		return acts, e
	}
	defer unlock()
	state, e := a.Load()
	if e != nil {
		return acts, e
	}
	db, e := a.loadTraffic()
	if e != nil {
		return acts, e
	}
	boot, e := a.currentBoot()
	if e != nil {
		return acts, e
	}
	m := a.meter()
	before, previousUpdate := trafficFingerprint(db), db.Updated
	reads, _ := readMeters(m, state.Profiles)
	var renew []Profile
	for _, p := range state.Profiles {
		r, ok := db.Records[p.ID]
		if !ok || r.Pending || r.Boot != boot || r.Shape != trafficShape(p) || r.Blocked == blockSealed {
			continue
		}
		read := reads[p.ID]
		if read.err != nil || read.snap.Hash != r.Rules {
			continue
		}
		if e = mergeTraffic(&r, read.snap); e != nil {
			continue
		}
		if now.After(r.Seen) {
			r.Seen = now
		}
		limit := p.trafficPolicy().LimitBytes
		if limit > 0 {
			if shutdown {
				sealed := false
				if e = m.Freeze(p); e == nil {
					if s, er := m.Read(p); er == nil && mergeTraffic(&r, s) == nil {
						r.Rules = s.Hash
						sealed = true
					}
				}
				if sealed && r.Blocked == "" {
					r.Blocked = blockSealed
				} else if !sealed && r.Blocked != blockQuota {
					r.Blocked = blockFault
					r.Incomplete = true
				}
				acts.stopNode(p)
			} else if r.Consumed >= limit {
				if r.Blocked != blockQuota {
					r.Blocked = blockQuota
					acts.stopNode(p)
				}
			} else if r.Blocked == "" {
				renew = append(renew, p)
			}
		}
		db.Records[p.ID] = r
	}
	db.Updated = now
	if shutdown || needsTrafficSave(db, before, previousUpdate, now) {
		if e = a.saveTraffic(db); e != nil {
			return acts, e
		}
	}
	failed := renewMeters(m, renew)
	for _, p := range renew {
		if e := failed[p.ID]; e != nil {
			acts.warn = append(acts.warn, fmt.Errorf("%s: %w", p.Name, e))
		}
	}
	return acts, nil
}

type trafficMode int

const (
	trafficKeep      trafficMode = iota // Preserve usage; never clears a fault.
	trafficReset                        // Explicit, confirmed reset of this cycle.
	trafficAcceptGap                    // Resume with known usage as a lower bound.
)

// Only these explicit operations may weaken a policy or clear a block. Apply/restore cannot.
func (a *App) ConfigureTraffic(id string, policy TrafficPolicy, reset bool, now time.Time) error {
	mode := trafficKeep
	if reset {
		mode = trafficReset
	}
	return a.configureTraffic(id, &policy, mode, now)
}

// RecoverTraffic reopens a fault-paused node WITHOUT resetting usage. Bytes during the
// gap are unknown, so the cycle stays marked incomplete and its total is a lower bound.
func (a *App) RecoverTraffic(id string, now time.Time) error {
	return a.configureTraffic(id, nil, trafficAcceptGap, now)
}
func (a *App) configureTraffic(id string, requested *TrafficPolicy, mode trafficMode, now time.Time) error {
	if requested != nil {
		if e := requested.Validate(); e != nil {
			return e
		}
	}
	if !a.trafficActive() {
		return errors.New("请先运行 rout traffic install，未启用流量监控")
	}
	unlock, e := a.lock()
	if e != nil {
		return e
	}
	defer unlock()
	var acts trafficActions
	var previous, policy TrafficPolicy
	var p Profile
	var blocked string
	// The traffic lock covers only kernel and journal work, never service commands.
	e = func() error {
		meterUnlock, e := a.trafficLock()
		if e != nil {
			return e
		}
		defer meterUnlock()
		state, e := a.Load()
		if e != nil {
			return e
		}
		if p, e = Find(state, id); e != nil {
			return e
		}
		previous = p.trafficPolicy()
		policy = previous
		if requested != nil {
			policy = *requested
		}
		if mode == trafficAcceptGap && policy.LimitBytes == 0 {
			return errors.New("无限额节点不需要恢复")
		}
		x, e := a.syncTrafficInner(state, now, false)
		acts.merge(x)
		if e != nil {
			if mode != trafficReset && policy.LimitBytes > 0 {
				return e
			}
			if _, er := a.loadTraffic(); er == nil {
				return e
			}
			// Recovery is only permitted after explicit reset/unlimited confirmation.
			if e = a.recoverTraffic(state, now); e != nil {
				return e
			}
			if x, e = a.syncTrafficInner(state, now, false); e != nil {
				return e
			}
			acts.merge(x)
		}
		db, e := a.loadTraffic()
		if e != nil {
			return e
		}
		r := db.Records[id]
		m := a.meter()
		kernel := previous.LimitBytes > 0 || policy.LimitBytes > 0 || mode == trafficReset
		if kernel {
			if e = m.Freeze(p); e != nil {
				return e
			}
			snap, e := m.Read(p)
			if e != nil {
				return e
			}
			if e = mergeTraffic(&r, snap); e != nil {
				return e
			}
			r.Pending = true
			db.Records[id] = r
			if e = a.saveTraffic(db); e != nil {
				return e
			}
		}
		p.Traffic = &policy
		if policy.LimitBytes == 0 {
			r.Consumed = 0
			r.Blocked = ""
		}
		if now.Before(r.Seen) {
			now = r.Seen
		}
		switch mode {
		case trafficReset:
			r.reset(now, policy, true)
		case trafficKeep:
			_, r.Next = trafficWindow(now, policy)
			if r.Blocked == blockQuota && policy.LimitBytes > r.Consumed {
				r.Blocked = ""
			}
			// A NEW cap on a cycle with a metering gap needs explicit consent.
			if policy.LimitBytes > 0 && previous.LimitBytes == 0 && r.Incomplete {
				r.Blocked = blockFault
			}
		case trafficAcceptGap:
			_, r.Next = trafficWindow(now, policy)
			if r.Blocked == blockFault || r.Blocked == blockSealed || (r.Blocked == blockQuota && policy.LimitBytes > r.Consumed) {
				r.Blocked = ""
			}
		}
		r.Schedule = trafficSchedule(policy, now)
		if policy.LimitBytes > 0 {
			_, _, total, er := r.totals()
			if er != nil {
				return er
			}
			if total > r.Consumed {
				r.Consumed = total
			}
			if r.Consumed >= policy.LimitBytes {
				r.Blocked = blockQuota
				r.Consumed = policy.LimitBytes
			}
		}
		// Keep the journal closed until both policy and kernel generation are durable/installed.
		old := state.Clone()
		state = replace(state, p)
		if policy.LimitBytes > 0 || state.Schema == 2 {
			state.Schema = 2
		}
		if e = a.writeBackup(old); e != nil {
			return e
		}
		b, _ := JSON(state)
		if e = AtomicWrite(filepath.Join(a.Home, "state.json"), b, 0600); e != nil {
			return e
		}
		if kernel {
			if r.Rules, e = m.Replace(p, r); e != nil {
				return e
			}
			r.Shape = trafficShape(p)
			r.Pending = false
		}
		db.Records[id] = r
		db.Updated = now
		if e = a.saveTraffic(db); e != nil {
			return e
		}
		if policy.LimitBytes > 0 && r.Blocked == "" {
			if e = m.Renew(p); e != nil {
				return e
			}
		}
		blocked = r.Blocked
		return nil
	}()
	if e != nil {
		return e
	}
	ae := a.runTrafficActions(acts, false)
	// A limit adds a start guard; removing one removes only this node's guard.
	if previous.LimitBytes > 0 || policy.LimitBytes > 0 {
		if blocked == "" && p.Enabled {
			e = a.startService(p)
		} else {
			e = a.setService(p, false)
		}
	}
	a.warnTraffic(acts)
	return errors.Join(e, ae)
}
func (a *App) TrafficGuard(id string) error {
	state, e := a.Load()
	if e != nil {
		return e
	}
	p, e := Find(state, id)
	if e != nil {
		return e
	}
	if p.trafficPolicy().LimitBytes == 0 {
		return nil
	}
	db, e := a.loadTraffic()
	if e != nil {
		return e
	}
	r, ok := db.Records[id]
	boot, e := a.currentBoot()
	if e != nil {
		return e
	}
	if !ok || r.Boot != boot || r.Shape != trafficShape(p) || r.Blocked != "" || r.Pending || time.Since(db.Updated) > 30*time.Second || db.Updated.After(time.Now().Add(5*time.Second)) {
		return errors.New("流量保护暂停，不能通过重启绕过限额")
	}
	snap, e := a.meter().Read(p)
	if e != nil {
		return e
	}
	if snap.Hash != r.Rules || snap.Consumed >= p.trafficPolicy().LimitBytes {
		return errors.New("流量保护暂停，不能通过重启绕过限额")
	}
	config, e := serverConfig(p, a.profileDir(p.ID))
	if e != nil {
		return e
	}
	expected, e := JSON(config)
	if e != nil {
		return e
	}
	actual, e := os.ReadFile(filepath.Join(a.profileDir(p.ID), "config.json"))
	if e != nil {
		return e
	}
	if !bytes.Equal(expected, actual) {
		return errors.New("流量保护暂停，不能通过重启绕过限额")
	}
	return nil
}
func (a *App) removeTraffic(p Profile) error {
	db, e := a.loadTraffic()
	if e != nil {
		return e
	}
	r, ok := db.Records[p.ID]
	if !ok {
		return nil
	}
	s, e := a.meter().Read(p)
	if errors.Is(e, errMeterMissing) {
		return nil
	}
	if e != nil {
		return e
	}
	if e = mergeTraffic(&r, s); e != nil {
		return e
	}
	db.Records[p.ID] = r
	if e = a.saveTraffic(db); e != nil {
		return e
	}
	return a.meter().Delete(p)
}
func (a *App) recoverTraffic(state State, now time.Time) error {
	path := filepath.Join(a.Home, "traffic.json")
	b, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	if e = AtomicWrite(filepath.Join(a.Home, "backups", "traffic-corrupt-"+time.Now().UTC().Format("20060102T150405.000000000")+".json"), b, 0600); e != nil {
		return e
	}
	boot, e := a.currentBoot()
	if e != nil {
		return e
	}
	db := TrafficState{Version: 1, Records: map[string]TrafficRecord{}, Updated: now}
	for _, p := range state.Profiles {
		r := newTrafficRecord(p, now, boot)
		r.Incomplete = true
		s, e := a.meter().Read(p)
		if e != nil {
			return e
		}
		r.RawUp = s.Up
		r.RawDown = s.Down
		r.BaseUp = s.Up
		r.BaseDown = s.Down
		r.Consumed = s.Consumed
		r.Rules = s.Hash
		r.Shape = trafficShape(p)
		if p.trafficPolicy().LimitBytes > 0 {
			r.Blocked = blockFault
			if e = a.meter().Freeze(p); e != nil {
				return e
			}
		}
		db.Records[p.ID] = r
	}
	return a.saveTraffic(db)
}
