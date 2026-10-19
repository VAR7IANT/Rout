package rout

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type App struct {
	Home, BinDir, ServiceMode string
	Language                  string
	BackupKeep                int
	trafficMeter              TrafficMeter
	trafficStop               func(Profile) error
	trafficStart              func(Profile) error
	bootID                    func() (string, error)
	// Only the running monitor reopens sealed checkpoints.
	monitorMode bool
}

func DefaultApp() *App                     { return &App{Home: "/etc/rout", BinDir: "/opt/rout/bin", ServiceMode: "auto"} }
func itoa(n int) string                    { return strconv.Itoa(n) }
func (a *App) profileDir(id string) string { return filepath.Join(a.Home, "profiles", id) }
func (a *App) engineName(p Profile) string {
	if p.Kind == "relay" {
		return "gost"
	}
	return "sing-box"
}
func AtomicWrite(path string, b []byte, mode os.FileMode) error {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".rout-*")
	if e != nil {
		return e
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if e = f.Chmod(mode); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e == nil {
		e = closeErr
	}
	if e != nil {
		return e
	}
	if e = os.Rename(tmp, path); e != nil {
		return e
	}
	d, e := os.Open(filepath.Dir(path))
	if e == nil {
		defer d.Close()
		e = d.Sync()
	}
	return e
}

const defaultBackupKeep = 20

func (a *App) backupKeep() int {
	if a.BackupKeep > 0 {
		return a.BackupKeep
	}
	return defaultBackupKeep
}

// Automatic pre-change backups (timestamp names only). Explicit `rout backup` files and
// corrupt-journal evidence are never pruned. The newest automatic backup always survives.
func (a *App) writeBackup(s State) error {
	b, e := JSON(s)
	if e != nil {
		return e
	}
	path := filepath.Join(a.Home, "backups", time.Now().UTC().Format("20060102T150405.000000000")+".json")
	e = AtomicWrite(path, b, 0600)
	for errors.Is(e, syscall.ENOSPC) && a.pruneOldestBackup() {
		e = AtomicWrite(path, b, 0600)
	}
	if errors.Is(e, syscall.ENOSPC) {
		return errors.New("磁盘空间不足，无法写入变更前备份；配置未修改")
	}
	if e != nil {
		return e
	}
	a.pruneBackups(a.backupKeep())
	return nil
}
func (a *App) automaticBackups() []string {
	files, _ := filepath.Glob(filepath.Join(a.Home, "backups", "[0-9]*T*.json"))
	sort.Strings(files) // UTC timestamp names sort chronologically.
	return files
}
func (a *App) pruneOldestBackup() bool {
	files := a.automaticBackups()
	if len(files) <= 1 {
		return false
	}
	return os.Remove(files[0]) == nil
}
func (a *App) pruneBackups(keep int) {
	if keep < 1 {
		keep = 1
	}
	files := a.automaticBackups()
	for len(files) > keep {
		_ = os.Remove(files[0])
		files = files[1:]
	}
}
func (a *App) Load() (State, error) {
	b, e := os.ReadFile(filepath.Join(a.Home, "state.json"))
	if os.IsNotExist(e) {
		return State{Schema: 1, Profiles: []Profile{}}, nil
	}
	if e != nil {
		return State{}, e
	}
	return DecodeState(b)
}
func DecodeState(b []byte) (State, error) {
	var s State
	if len(b) > 16<<20 {
		return s, errors.New("配置文件过大")
	}
	if e := json.Unmarshal(b, &s); e != nil {
		return s, errors.New("配置 JSON 无效")
	}
	s = s.MigrateLegacyExits()
	if e := s.Validate(); e != nil {
		return s, e
	}
	return s.withAIRoutes(), nil
}

// Bounded waits: user operations queue behind short monitor checkpoints instead of
// failing at random. A timeout (never an indefinite hang) reports a busy holder.
const (
	configLockWait  = 30 * time.Second
	trafficLockWait = 15 * time.Second
)

var errLockBusy = errors.New("另一个 rout 操作仍在进行，请稍后重试")

func lockFile(path string, wait time.Duration) (func(), error) {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return nil, e
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	deadline := time.Now().Add(wait)
	for {
		e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if e == nil {
			return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }, nil
		}
		if !errors.Is(e, syscall.EWOULDBLOCK) || !time.Now().Before(deadline) {
			f.Close()
			if errors.Is(e, syscall.EWOULDBLOCK) {
				return nil, errLockBusy
			}
			return nil, e
		}
		time.Sleep(25 * time.Millisecond)
	}
}
func (a *App) lock() (func(), error) { return a.lockWait(configLockWait) }
func (a *App) lockWait(wait time.Duration) (func(), error) {
	return lockFile(filepath.Join(a.Home, ".lock"), wait)
}
func Find(s State, id string) (Profile, error) {
	for _, p := range s.Profiles {
		if p.ID == id {
			return p, nil
		}
	}
	return Profile{}, errors.New("找不到节点 ID")
}
func replace(s State, p Profile) State {
	out := s.Clone()
	for i := range out.Profiles {
		if out.Profiles[i].ID == p.ID {
			out.Profiles[i] = p
			return out
		}
	}
	out.Profiles = append(out.Profiles, p)
	return out
}
func removeProfile(s State, id string) State {
	out := pruneAIBinding(s.Clone(), id)
	out.Profiles = []Profile{}
	for _, p := range s.Profiles {
		if p.ID != id {
			out.Profiles = append(out.Profiles, p)
		}
	}
	return out
}

func CheckAvailable(p Profile) error {
	for _, n := range p.Networks() {
		addr := net.JoinHostPort(p.Listen, itoa(p.Port))
		if n == "tcp" {
			l, e := net.Listen("tcp", addr)
			if e != nil {
				return fmt.Errorf("TCP %d 不可用：%w", p.Port, e)
			}
			l.Close()
		} else {
			l, e := net.ListenPacket("udp", addr)
			if e != nil {
				return fmt.Errorf("UDP %d 不可用：%w", p.Port, e)
			}
			l.Close()
		}
	}
	return nil
}
func (a *App) writeProfile(p Profile) error {
	dir := a.profileDir(p.ID)
	return writeProfileIn(p, dir)
}
func writeProfileIn(p Profile, dir string) error {
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	if p.CertPEM != "" {
		if e := AtomicWrite(filepath.Join(dir, "tls.crt"), []byte(p.CertPEM), 0600); e != nil {
			return e
		}
		if e := AtomicWrite(filepath.Join(dir, "tls.key"), []byte(p.KeyPEM), 0600); e != nil {
			return e
		}
	}
	c, e := serverConfig(p, dir)
	if e != nil {
		return e
	}
	b, e := JSON(c)
	if e != nil {
		return e
	}
	return AtomicWrite(filepath.Join(dir, "config.json"), b, 0600)
}

// Commit checks configuration first and rolls state, generated files and services back together.
func (a *App) Commit(old, next State, force bool) error { return a.commit(old, next, force, nil) }

// commit is Commit with an optional restriction: when only is non-nil, force applies to
// just those node IDs (used to re-apply AI routing without restarting every node).
func (a *App) commit(old, next State, force bool, only map[string]bool) error {
	// Effective AI routes are derived from the settings so that a settings-only change still
	// shows up as a change of the affected nodes, and of no others.
	old = old.withAIRoutes()
	next = next.withAIRoutes()
	if probs := newAIProblems(old, next); len(probs) > 0 {
		return errors.New(strings.Join(probs, "；"))
	}
	// Ordinary edits, apply and old backups cannot silently cancel a quota.
	for i, p := range next.Profiles {
		if prev, er := Find(old, p.ID); er == nil {
			next.Profiles[i].Traffic = prev.Traffic
		}
	}
	if old.Schema == 2 {
		next.Schema = 2
	}
	next = next.MigrateLegacyExits()
	if e := next.Validate(); e != nil {
		return e
	}
	unlock, e := a.lock()
	if e != nil {
		return e
	}
	defer unlock()
	current, e := a.Load()
	if e != nil {
		return e
	}
	if !reflect.DeepEqual(current, old) {
		return errors.New("配置已被其他操作修改，请重新打开菜单")
	}
	changed := map[string]bool{}
	edited := map[string]bool{}
	for _, p := range next.Profiles {
		if p.trafficPolicy().LimitBytes > 0 && !a.trafficActive() {
			return errors.New("请先运行 rout traffic install，未启用流量监控")
		}
		prev, err := Find(old, p.ID)
		edited[p.ID] = err != nil || !runtimeEqual(prev, p)
		if (force && (only == nil || only[p.ID])) || edited[p.ID] {
			changed[p.ID] = true
		}
		if edited[p.ID] {
			if e := p.CheckCompatibility(); e != nil {
				return fmt.Errorf("%s: %w", p.Name, e)
			}
			if p.Kind == "relay" && p.Enabled {
				if e := relayLoop(next, p, localIPs()); e != nil {
					return fmt.Errorf("%s: %w", p.Name, e)
				}
			}
		}
		if p.Enabled {
			for _, network := range p.Networks() {
				owned := false
				for _, active := range old.Profiles {
					if active.Enabled && active.Port == p.Port && (active.Listen == p.Listen || active.ID == p.ID) && sharesNetwork(active.Networks(), []string{network}) {
						if active.ID == p.ID {
							owned = true
						} else if after, er := Find(next, active.ID); er != nil || !after.Enabled {
							owned = true
						}
					}
				}
				if !owned {
					if e := checkNetworkAvailable(p, network); e != nil {
						return e
					}
				}
			}
		}
	}
	for _, p := range old.Profiles {
		if _, e := Find(next, p.ID); e != nil {
			changed[p.ID] = true
		}
	}
	if len(changed) > 0 {
		if _, e = a.serviceManager(); e != nil {
			return e
		}
	}
	var skipped []string
	for _, p := range next.Profiles {
		if changed[p.ID] {
			if e := p.Ready(); e != nil {
				// A forced re-apply leaves an unchanged node with an expired certificate
				// untouched instead of blocking every other node.
				if !edited[p.ID] {
					delete(changed, p.ID)
					skipped = append(skipped, fmt.Sprintf("%s (%s): %s", p.Name, p.Protocol, a.Error(e)))
					continue
				}
				return fmt.Errorf("%s (%s): %w", p.Name, p.Protocol, e)
			}
			if e := a.EnsureEngine(a.engineName(p)); e != nil {
				return e
			}
		}
	}
	// Validate entirely in private staging paths. Invalid edits never touch live files/services.
	stage, e := os.MkdirTemp(a.Home, ".staging-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(stage)
	for _, p := range next.Profiles {
		if !changed[p.ID] {
			continue
		}
		dir := filepath.Join(stage, p.ID)
		if e = writeProfileIn(p, dir); e != nil {
			return e
		}
		if p.Kind == "node" {
			if e = a.checkConfig(filepath.Join(dir, "config.json")); e != nil {
				return fmt.Errorf("%s (%s): %w", p.Name, p.Protocol, e)
			}
		}
	}
	oldBytes, _ := JSON(old)
	if !reflect.DeepEqual(old, next) || force {
		if e := a.writeBackup(old); e != nil {
			return e
		}
	}
	filesTouched := map[string]bool{}
	servicesTouched := map[string]bool{}
	rollback := func(cause error) error {
		var failures []error
		// Free ports held by newly-created services before recovering older services.
		for _, p := range next.Profiles {
			if _, err := Find(old, p.ID); err != nil && servicesTouched[p.ID] {
				if er := a.removeService(p); er != nil {
					failures = append(failures, er)
				} else {
					delete(servicesTouched, p.ID)
				}
			}
		}
		for _, p := range next.Profiles {
			if !filesTouched[p.ID] && !servicesTouched[p.ID] {
				continue
			}
			if prev, er := Find(old, p.ID); er == nil {
				if er = a.writeProfile(prev); er != nil {
					failures = append(failures, er)
				}
				if servicesTouched[p.ID] {
					if er = a.setService(prev, prev.Enabled); er != nil {
						failures = append(failures, er)
					}
				}
			} else {
				if servicesTouched[p.ID] {
					if er := a.removeService(p); er != nil {
						failures = append(failures, er)
					}
				}
				os.RemoveAll(a.profileDir(p.ID))
			}
		}
		for _, p := range old.Profiles {
			if servicesTouched[p.ID] {
				if _, er := Find(next, p.ID); er != nil {
					if er = a.writeProfile(p); er != nil {
						failures = append(failures, er)
					}
					if er = a.setService(p, p.Enabled); er != nil {
						failures = append(failures, er)
					}
				}
			}
		}
		if er := AtomicWrite(filepath.Join(a.Home, "state.json"), oldBytes, 0600); er != nil {
			failures = append(failures, er)
		}
		if a.trafficActive() {
			acts, er := a.syncTraffic(old, time.Now(), false)
			if er != nil {
				failures = append(failures, er)
			}
			if er = errors.Join(acts.warning(), a.runTrafficActions(acts, false)); er != nil {
				failures = append(failures, er)
			}
		}
		if len(failures) > 0 {
			return fmt.Errorf("操作失败：%w；恢复时还有错误：%v，请检查 rout status", cause, failures)
		}
		return fmt.Errorf("操作失败，已恢复原配置：%w", cause)
	}
	for _, p := range next.Profiles {
		if !changed[p.ID] {
			continue
		}
		filesTouched[p.ID] = true
		if e := a.writeProfile(p); e != nil {
			return rollback(e)
		}
	}
	// Stop removed entries before enabling replacements that may reuse their ports.
	for _, p := range old.Profiles {
		after, er := Find(next, p.ID)
		if er != nil {
			servicesTouched[p.ID] = true
			if e := a.removeService(p); e != nil {
				return rollback(e)
			}
		} else if p.Enabled && !after.Enabled {
			servicesTouched[p.ID] = true
			if e := a.setService(after, false); e != nil {
				return rollback(e)
			}
		}
	}
	b, e := JSON(next)
	if e != nil {
		return rollback(e)
	}
	if e = AtomicWrite(filepath.Join(a.Home, "state.json"), b, 0600); e != nil {
		return rollback(e)
	}
	var acts trafficActions
	if a.trafficActive() {
		if acts, e = a.syncTraffic(next, time.Now(), false); e != nil {
			return rollback(e)
		}
	}
	for _, p := range next.Profiles {
		if changed[p.ID] {
			if servicesTouched[p.ID] && !p.Enabled {
				continue
			}
			servicesTouched[p.ID] = true
			if e := a.setService(p, p.Enabled); e != nil {
				return rollback(e)
			}
		}
	}
	if e := a.runTrafficActions(acts, false); e != nil {
		acts.warn = append(acts.warn, e)
	}
	a.warnTraffic(acts)
	for _, line := range skipped {
		a.printf("已跳过（未修改，证书需更新）：%s\n", line)
	}
	for _, p := range old.Profiles {
		if _, er := Find(next, p.ID); er != nil {
			if a.trafficActive() {
				if e = a.removeTraffic(p); e != nil {
					return e
				}
			}
			if e := os.RemoveAll(a.profileDir(p.ID)); e != nil {
				return e
			}
		}
	}
	return nil
}

func runtimeEqual(a, b Profile) bool {
	a.CreatedAt = nil
	b.CreatedAt = nil
	a.Traffic = nil
	b.Traffic = nil
	a.Name = ""
	b.Name = ""
	a.PublicHost = ""
	b.PublicHost = ""
	a.PublicPort = 0
	b.PublicPort = 0
	a.NAT = false
	b.NAT = false
	a.ExitID = ""
	b.ExitID = ""
	a.TLSGenerated = false
	b.TLSGenerated = false
	a.RelayMode = ""
	b.RelayMode = ""
	return reflect.DeepEqual(a, b)
}
func checkNetworkAvailable(p Profile, network string) error {
	addr := net.JoinHostPort(p.Listen, itoa(p.Port))
	if network == "tcp" {
		l, e := net.Listen("tcp", addr)
		if e != nil {
			return fmt.Errorf("TCP %d 不可用：%w", p.Port, e)
		}
		return l.Close()
	}
	l, e := net.ListenPacket("udp", addr)
	if e != nil {
		return fmt.Errorf("UDP %d 不可用：%w", p.Port, e)
	}
	return l.Close()
}

func (a *App) Backup(path string) error {
	s, e := a.Load()
	if e != nil {
		return e
	}
	b, e := JSON(s)
	if e != nil {
		return e
	}
	return AtomicWrite(path, b, 0600)
}
func (a *App) Restore(path string) error {
	b, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	next, e := DecodeState(b)
	if e != nil {
		return e
	}
	old, e := a.Load()
	if e != nil {
		return e
	}
	for _, p := range old.Profiles {
		if p.trafficPolicy().LimitBytes > 0 {
			if _, er := Find(next, p.ID); er != nil {
				return errors.New("备份缺少有限额节点，请先显式取消限额或删除节点")
			}
		}
	}
	return a.Commit(old, next, true)
}
