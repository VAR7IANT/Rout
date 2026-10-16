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
	"syscall"
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
func FormatTraffic(n uint64) string {
	for _, u := range []struct {
		name string
		n    uint64
	}{{"TB", 1_000_000_000_000}, {"GB", 1_000_000_000}, {"MB", 1_000_000}} {
		if n >= u.n {
			return fmt.Sprintf("%.3f %s", float64(n)/float64(u.n), u.name)
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
func (a *App) stopTrafficNode(p Profile) error {
	if a.trafficStop != nil {
		return a.trafficStop(p)
	}
	return a.stopServiceOnly(p)
}

// Called with the normal configuration lock held. No unbounded retries/HTTP calls.
func (a *App) trafficLock() (func(), error) {
	f, e := os.OpenFile(filepath.Join(a.Home, ".traffic.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		f.Close()
		return nil, errors.New("另一个 rout 正在修改配置，请稍后重试")
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }, nil
}
func (a *App) syncTraffic(state State, now time.Time, shutdown bool) error {
	unlock, e := a.trafficLock()
	if e != nil {
		return e
	}
	defer unlock()
	return a.syncTrafficInner(state, now, shutdown)
}
func (a *App) syncTrafficInner(state State, now time.Time, shutdown bool) error {
	m := a.meter()
	boot, e := bootID()
	if e != nil {
		return e
	}
	db, e := a.loadTraffic()
	if e != nil {
		for _, p := range state.Profiles {
			if p.trafficPolicy().LimitBytes > 0 {
				_ = m.Freeze(p)
				_ = a.stopTrafficNode(p)
			}
		}
		return e
	}
	var errs []error
	resume := map[string]bool{}
	for _, p := range state.Profiles {
		r, exists := db.Records[p.ID]
		policy := p.trafficPolicy()
		limited := policy.LimitBytes > 0
		if !exists {
			r = newTrafficRecord(p, now, boot)
			if limited {
				r.Blocked = "fault"
				r.Incomplete = true
			}
		}
		snap, readErr := m.Read(p)
		healthy := readErr == nil && r.Rules != "" && snap.Hash == r.Rules && !r.Pending && r.Boot == boot
		if healthy {
			if e = mergeTraffic(&r, snap); e != nil {
				healthy = false
				readErr = e
			}
		}
		if !healthy && exists {
			r.Incomplete = true
			if limited {
				r.Blocked = "fault"
			}
		}
		oldBlocked := r.Blocked
		rollover := r.advance(now, policy)
		shapeChanged := r.Shape != trafficShape(p)
		quotaNew := limited && r.Consumed >= policy.LimitBytes && r.Blocked != "quota"
		if quotaNew {
			r.Blocked = "quota"
		}
		rebuild := !healthy || shapeChanged || (rollover && limited) || quotaNew
		if shutdown && limited {
			r.Blocked = "fault"
			rebuild = true
		}
		// Seal before sampling and replacing a live counter generation.
		if rebuild && readErr == nil {
			if e = m.Freeze(p); e != nil {
				errs = append(errs, e)
				if limited {
					r.Blocked = "fault"
					r.Pending = true
					_ = a.stopTrafficNode(p)
				}
				db.Records[p.ID] = r
				continue
			}
			sealed, er := m.Read(p)
			if er == nil && healthy {
				er = mergeTraffic(&r, sealed)
			}
			if er != nil {
				r.Incomplete = true
				if limited {
					r.Blocked = "fault"
				}
			}
			if rollover {
				r.reset(now, policy, false)
			}
		}
		if limited && r.Consumed >= policy.LimitBytes {
			r.Blocked = "quota"
		}
		if rebuild {
			r.Pending = true
			r.Boot = boot
			db.Records[p.ID] = r
			if e = a.saveTraffic(db); e != nil {
				if limited {
					_ = m.Freeze(p)
					_ = a.stopTrafficNode(p)
				}
				return e
			}
			if readErr != nil && !errors.Is(readErr, errMeterMissing) {
				errs = append(errs, readErr)
				if limited {
					_ = a.stopTrafficNode(p)
				}
				continue
			}
			if r.Rules, e = m.Replace(p, r); e != nil {
				errs = append(errs, e)
				if limited {
					_ = a.stopTrafficNode(p)
				}
				continue
			}
			r.Shape = trafficShape(p)
			r.Pending = false
		}
		if limited && r.Blocked != "" {
			_ = a.stopTrafficNode(p)
		}
		if oldBlocked != "" && r.Blocked == "" && p.Enabled {
			resume[p.ID] = true
		}
		db.Records[p.ID] = r
	}
	db.Updated = now
	if e = a.saveTraffic(db); e != nil {
		for _, p := range state.Profiles {
			if p.trafficPolicy().LimitBytes > 0 {
				_ = m.Freeze(p)
				_ = a.stopTrafficNode(p)
			}
		}
		return e
	}
	for _, p := range state.Profiles {
		r := db.Records[p.ID]
		if p.trafficPolicy().LimitBytes > 0 && r.Blocked == "" && !r.Pending && !shutdown {
			if e = m.Renew(p); e != nil {
				errs = append(errs, e)
				_ = m.Freeze(p)
				_ = a.stopTrafficNode(p)
				continue
			}
		}
		if resume[p.ID] && !shutdown {
			if e = a.setService(p, true); e != nil {
				errs = append(errs, e)
			}
		}
	}
	return errors.Join(errs...)
}
func (a *App) TrafficSync(now time.Time, shutdown bool) error {
	unlock, e := a.lock()
	if e != nil {
		return a.trafficHeartbeat(now, shutdown)
	}
	defer unlock()
	state, e := a.Load()
	if e != nil {
		return e
	}
	return a.syncTraffic(state, now, shutdown)
}

// A slow engine download/service operation must not expire OTHER nodes' leases.
// This path never changes policy/cycles. Except for an explicit shutdown it only
// checkpoints counters and renews permits. The meter lock serializes transactions.
func (a *App) trafficHeartbeat(now time.Time, shutdown bool) error {
	unlock, e := a.trafficLock()
	if e != nil {
		return e
	}
	defer unlock()
	state, e := a.Load()
	if e != nil {
		return e
	}
	db, e := a.loadTraffic()
	if e != nil {
		return e
	}
	boot, e := bootID()
	if e != nil {
		return e
	}
	var renew []Profile
	for _, p := range state.Profiles {
		r, ok := db.Records[p.ID]
		if !ok || r.Pending || r.Boot != boot || r.Shape != trafficShape(p) {
			continue
		}
		s, e := a.meter().Read(p)
		if e != nil || s.Hash != r.Rules {
			continue
		}
		if e = mergeTraffic(&r, s); e != nil {
			continue
		}
		if now.After(r.Seen) {
			r.Seen = now
		}
		if p.trafficPolicy().LimitBytes > 0 {
			if shutdown {
				r.Blocked = "fault"
				if e = a.meter().Freeze(p); e == nil {
					if sealed, er := a.meter().Read(p); er == nil {
						_ = mergeTraffic(&r, sealed)
						r.Rules = sealed.Hash
					}
				}
			} else if r.Consumed >= p.trafficPolicy().LimitBytes {
				r.Blocked = "quota"
			} else if r.Blocked == "" {
				renew = append(renew, p)
			}
		}
		db.Records[p.ID] = r
	}
	db.Updated = now
	if e = a.saveTraffic(db); e != nil {
		return e
	}
	if shutdown {
		for _, p := range state.Profiles {
			if p.trafficPolicy().LimitBytes > 0 {
				_ = a.stopTrafficNode(p)
			}
		}
		return nil
	}
	for _, p := range renew {
		if e = a.meter().Renew(p); e != nil {
			return e
		}
	}
	return nil
}

// Only this explicit operation may weaken a policy or clear a quota. Normal apply/restore cannot.
func (a *App) ConfigureTraffic(id string, policy TrafficPolicy, reset bool, now time.Time) error {
	if e := policy.Validate(); e != nil {
		return e
	}
	if !a.trafficActive() {
		return errors.New("请先运行 rout traffic install，未启用流量监控")
	}
	unlock, e := a.lock()
	if e != nil {
		return e
	}
	defer unlock()
	meterUnlock, e := a.trafficLock()
	if e != nil {
		return e
	}
	defer meterUnlock()
	state, e := a.Load()
	if e != nil {
		return e
	}
	p, e := Find(state, id)
	if e != nil {
		return e
	}
	if e = a.syncTrafficInner(state, now, false); e != nil {
		if !reset && policy.LimitBytes > 0 {
			return e
		}
		// Recovery is only permitted after explicit reset/unlimited confirmation.
		if _, er := a.loadTraffic(); er == nil {
			return e
		}
		if e = a.recoverTraffic(state, now); e != nil {
			return e
		}
		if e = a.syncTrafficInner(state, now, false); e != nil {
			return e
		}
	}
	db, e := a.loadTraffic()
	if e != nil {
		return e
	}
	r := db.Records[id]
	m := a.meter()
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
	previousPolicy := p.trafficPolicy()
	p.Traffic = &policy
	if policy.LimitBytes == 0 {
		r.Consumed = 0
	}
	if now.Before(r.Seen) {
		now = r.Seen
	}
	if reset {
		r.reset(now, policy, true)
	} else {
		_, r.Next = trafficWindow(now, policy)
		if policy.LimitBytes == 0 || (r.Blocked == "quota" && policy.LimitBytes > r.Consumed) {
			r.Blocked = ""
		}
		if policy.LimitBytes > 0 && r.Incomplete {
			r.Blocked = "fault"
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
	}
	if policy.LimitBytes > 0 && r.Consumed >= policy.LimitBytes {
		r.Blocked = "quota"
		r.Consumed = policy.LimitBytes
	}
	// Keep the journal closed until both policy and kernel generation are durable/installed.
	state = replace(state, p)
	if policy.LimitBytes > 0 || state.Schema == 2 {
		state.Schema = 2
	}
	b, _ := JSON(state)
	if e = AtomicWrite(filepath.Join(a.Home, "state.json"), b, 0600); e != nil {
		return e
	}
	if r.Rules, e = m.Replace(p, r); e != nil {
		return e
	}
	r.Shape = trafficShape(p)
	r.Pending = false
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
	// A limit adds a boot guard; removing one removes only this node's guard.
	if previousPolicy.LimitBytes > 0 || policy.LimitBytes > 0 {
		return a.setService(p, p.Enabled && r.Blocked == "")
	}
	return nil
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
	boot, e := bootID()
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
	boot, e := bootID()
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
			r.Blocked = "fault"
			if e = a.meter().Freeze(p); e != nil {
				return e
			}
			_ = a.stopTrafficNode(p)
		}
		db.Records[p.ID] = r
	}
	return a.saveTraffic(db)
}
