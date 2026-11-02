package rout

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	backupFormat  = "rout-backup"
	backupVersion = 2
	backupMaxSize = 24 << 20
)

// BackupBundle is the full backup written by the panel (and `rout backup --full`): the state
// exactly as `rout backup` writes it, plus the third-party sources and their last good data.
//
// It contains the URLs of third-party subscriptions, which usually embed an access key, so the
// file is as sensitive as a password: it is created 0600 and the panel asks for the password
// before it hands one out. It never contains the panel password hash or any session.
type BackupBundle struct {
	Format      string          `json:"format"`
	Version     int             `json:"version"`
	RoutVersion string          `json:"rout_version"`
	CreatedAt   time.Time       `json:"created_at"`
	State       json.RawMessage `json:"state"`
	Remote      *RemoteBackup   `json:"remote,omitempty"`
}

type RemoteBackup struct {
	Sources   []RemoteSource             `json:"sources"`
	Snapshots map[string]*RemoteSnapshot `json:"snapshots,omitempty"`
}

// BackupBundle collects the current state and sources.
func (a *App) BackupBundle(now time.Time) (BackupBundle, error) {
	s, e := a.Load()
	if e != nil {
		return BackupBundle{}, e
	}
	sb, e := JSON(s)
	if e != nil {
		return BackupBundle{}, e
	}
	cfg, e := a.loadRemoteConfig()
	if e != nil {
		return BackupBundle{}, e
	}
	b := BackupBundle{Format: backupFormat, Version: backupVersion, RoutVersion: Version, CreatedAt: now.UTC(), State: sb}
	if len(cfg.Sources) > 0 {
		rb := &RemoteBackup{Sources: cfg.Sources, Snapshots: map[string]*RemoteSnapshot{}}
		for _, src := range cfg.Sources {
			if snap, er := a.loadRemoteSnapshot(src.ID); er == nil && snap != nil {
				rb.Snapshots[src.ID] = snap
			}
		}
		b.Remote = rb
	}
	return b, nil
}

// WriteBackupBundle writes the bundle to path with mode 0600.
func (a *App) WriteBackupBundle(path string, now time.Time) error {
	b, e := a.BackupBundle(now)
	if e != nil {
		return e
	}
	raw, e := json.MarshalIndent(b, "", "  ")
	if e != nil {
		return e
	}
	return AtomicWrite(path, append(raw, '\n'), 0600)
}

// parsedBackup is a decoded and validated backup, ready to compare or apply.
type parsedBackup struct {
	Full    bool
	State   State
	Remote  remoteConfig
	Snaps   map[string]*RemoteSnapshot
	Created time.Time
	Version string
}

// ParseBackup accepts both formats: a v0.5.0 bundle and the plain state file that every
// earlier version (and `rout backup`) writes.
func ParseBackup(raw []byte) (*parsedBackup, error) {
	if len(raw) == 0 || len(raw) > backupMaxSize {
		return nil, errors.New("备份文件为空或过大")
	}
	var probe struct {
		Format string `json:"format"`
	}
	_ = json.Unmarshal(raw, &probe)
	if probe.Format == "" {
		st, e := DecodeState(raw)
		if e != nil {
			return nil, e
		}
		return &parsedBackup{State: st}, nil
	}
	if probe.Format != backupFormat {
		return nil, errors.New("不是 Rout 备份文件")
	}
	var b BackupBundle
	dec := json.NewDecoder(bytes.NewReader(raw))
	if e := dec.Decode(&b); e != nil {
		return nil, errors.New("备份文件无效")
	}
	if b.Version < 1 || b.Version > backupVersion {
		return nil, errors.New("备份来自更新版本的 Rout，无法恢复")
	}
	st, e := DecodeState(b.State)
	if e != nil {
		return nil, e
	}
	out := &parsedBackup{Full: true, State: st, Created: b.CreatedAt, Version: b.RoutVersion, Remote: remoteConfig{Schema: remoteSchema, Sources: []RemoteSource{}}, Snaps: map[string]*RemoteSnapshot{}}
	if b.Remote != nil {
		out.Remote.Sources = b.Remote.Sources
		if e := out.Remote.validate(); e != nil {
			return nil, e
		}
		for id, snap := range b.Remote.Snapshots {
			if _, ok := out.Remote.find(id); !ok || snap == nil || snap.SourceID != id {
				return nil, errors.New("备份中的订阅源数据与来源不一致")
			}
			out.Snaps[id] = snap
		}
	}
	// Aggregates must not point at sources the backup does not contain.
	for _, sub := range st.Subscriptions {
		for _, it := range sub.Items {
			if it.Kind == itemRemote {
				if _, ok := out.Remote.find(it.SourceID); !ok {
					return nil, fmt.Errorf("聚合订阅「%s」引用了备份中不存在的订阅源", sub.Name)
				}
			}
		}
	}
	return out, nil
}

// RestorePlan summarises what restoring a backup would change.
type RestorePlan struct {
	Full     bool     `json:"full"`
	Created  string   `json:"created_at,omitempty"`
	Version  string   `json:"rout_version,omitempty"`
	Nodes    DiffSet  `json:"nodes"`
	Relays   DiffSet  `json:"relays"`
	Exits    DiffSet  `json:"exits"`
	Subs     DiffSet  `json:"subscriptions"`
	Sources  DiffSet  `json:"sources"`
	Warnings []string `json:"warnings"`
}

type DiffSet struct {
	Now     int      `json:"now"`
	Backup  int      `json:"backup"`
	Removed []string `json:"removed"` // names that exist now but not in the backup
	Added   []string `json:"added"`
}

func diffNames(now, then []string) DiffSet {
	have, want := map[string]bool{}, map[string]bool{}
	for _, n := range now {
		have[n] = true
	}
	for _, n := range then {
		want[n] = true
	}
	d := DiffSet{Now: len(now), Backup: len(then), Removed: []string{}, Added: []string{}}
	for _, n := range now {
		if !want[n] {
			d.Removed = append(d.Removed, n)
		}
	}
	for _, n := range then {
		if !have[n] {
			d.Added = append(d.Added, n)
		}
	}
	sort.Strings(d.Removed)
	sort.Strings(d.Added)
	return d
}

func profileNames(s State, kind string) []string {
	var out []string
	for _, p := range s.Profiles {
		if p.Kind == kind {
			out = append(out, p.ID+"|"+p.Name)
		}
	}
	return out
}

func stripIDs(names []string) []string {
	out := make([]string, len(names))
	for i, n := range names {
		if j := strings.IndexByte(n, '|'); j >= 0 {
			n = n[j+1:]
		}
		out[i] = n
	}
	return out
}

func idDiff(now, then []string) DiffSet {
	d := diffNames(now, then)
	d.Removed, d.Added = stripIDs(d.Removed), stripIDs(d.Added)
	return d
}

// PlanRestore compares a backup with the current configuration without changing anything.
func (a *App) PlanRestore(p *parsedBackup) (RestorePlan, error) {
	cur, e := a.Load()
	if e != nil {
		return RestorePlan{}, e
	}
	plan := RestorePlan{Full: p.Full, Version: p.Version, Warnings: []string{}}
	if !p.Created.IsZero() {
		plan.Created = p.Created.Format(time.RFC3339)
	}
	plan.Nodes = idDiff(profileNames(cur, "node"), profileNames(p.State, "node"))
	plan.Relays = idDiff(profileNames(cur, "relay"), profileNames(p.State, "relay"))
	var ce, pe []string
	for _, x := range cur.Exits {
		ce = append(ce, x.ID+"|"+x.Name)
	}
	for _, x := range p.State.Exits {
		pe = append(pe, x.ID+"|"+x.Name)
	}
	plan.Exits = idDiff(ce, pe)
	var cs, ps []string
	for _, x := range cur.Subscriptions {
		cs = append(cs, x.ID+"|"+x.Name)
	}
	for _, x := range p.State.Subscriptions {
		ps = append(ps, x.ID+"|"+x.Name)
	}
	plan.Subs = idDiff(cs, ps)
	var cr, pr []string
	if cfg, er := a.loadRemoteConfig(); er == nil {
		for _, x := range cfg.Sources {
			cr = append(cr, x.ID+"|"+x.Name)
		}
	}
	for _, x := range p.Remote.Sources {
		pr = append(pr, x.ID+"|"+x.Name)
	}
	plan.Sources = idDiff(cr, pr)
	if !p.Full {
		plan.Warnings = append(plan.Warnings, "plain_state_backup")
		if len(cr) > 0 {
			plan.Warnings = append(plan.Warnings, "sources_kept")
		}
	}
	for _, x := range p.State.Subscriptions {
		for _, it := range x.Items {
			if it.Kind == itemRemote && !p.Full {
				plan.Warnings = append(plan.Warnings, "aggregate_without_sources")
				return plan, nil
			}
		}
	}
	return plan, nil
}

// RestoreBackup applies a parsed backup. The configuration goes through the same checks as
// `rout restore` (a backup may not drop a node or subscription that carries a quota), and the
// sources are replaced only afterwards, so a refused restore changes nothing.
func (a *App) RestoreBackup(p *parsedBackup) error {
	old, e := a.Load()
	if e != nil {
		return e
	}
	next := p.State
	for _, pr := range old.Profiles {
		if pr.trafficPolicy().LimitBytes > 0 {
			if _, er := Find(next, pr.ID); er != nil {
				return errors.New("备份缺少有限额节点，请先显式取消限额或删除节点")
			}
		}
	}
	for _, sub := range old.Subscriptions {
		if sub.Plan != nil && sub.Plan.LimitBytes > 0 {
			if _, er := findSubscription(next, sub.ID); er != nil {
				return errors.New("备份缺少有流量额度的订阅，请先清除其额度或删除订阅")
			}
		}
	}
	if p.Full {
		// Keep the current sources next to the restore so it can be undone by hand.
		if cur, er := os.ReadFile(a.remoteConfigPath()); er == nil {
			_ = AtomicWrite(a.remotePath("sources.json.pre-restore"), cur, 0600)
		}
	}
	if e = a.Commit(old, next, true); e != nil {
		return e
	}
	if !p.Full {
		return nil
	}
	if e = a.mutateRemote(func(c *remoteConfig) error {
		*c = p.Remote
		c.Schema = remoteSchema
		return nil
	}); e != nil {
		return e
	}
	for _, src := range p.Remote.Sources {
		if snap := p.Snaps[src.ID]; snap != nil {
			if e = a.saveRemoteSnapshot(snap); e != nil {
				return e
			}
		}
	}
	// Snapshots of sources that no longer exist are removed on the next scheduler pass.
	a.gcRemoteSnapshots()
	return nil
}

// PermissionCheck is one path whose mode was verified.
type PermissionCheck struct {
	Path     string `json:"path"`
	Mode     string `json:"mode"`
	Expected string `json:"expected"`
	OK       bool   `json:"ok"`
}

// CheckPermissions verifies that Rout's private files are not readable by other users.
func (a *App) CheckPermissions() []PermissionCheck {
	var out []PermissionCheck
	check := func(path string, dir bool) {
		st, e := os.Stat(path)
		if e != nil {
			return
		}
		mode := st.Mode().Perm()
		want := os.FileMode(0600)
		if dir {
			want = 0700
		}
		rel, er := filepath.Rel(a.Home, path)
		if er != nil || strings.HasPrefix(rel, "..") {
			rel = filepath.Base(path)
		}
		if rel == "." {
			rel = "(home)"
		}
		out = append(out, PermissionCheck{Path: rel, Mode: fmt.Sprintf("%04o", mode), Expected: fmt.Sprintf("%04o", want), OK: mode&0o077 == 0})
	}
	check(a.Home, true)
	for _, f := range []string{"state.json", "web.json", "traffic.json", "settings.json"} {
		check(filepath.Join(a.Home, f), false)
	}
	check(filepath.Join(a.Home, "secrets"), true)
	check(a.subscriptionTokensPath(), false)
	check(a.remotePath(), true)
	check(a.remoteConfigPath(), false)
	check(a.remotePath("data"), true)
	if ents, e := os.ReadDir(a.remotePath("data")); e == nil {
		for _, ent := range ents {
			if strings.HasSuffix(ent.Name(), ".json") {
				check(filepath.Join(a.remotePath("data"), ent.Name()), false)
			}
		}
	}
	return out
}

// FixPermissions tightens anything CheckPermissions flagged.
func (a *App) FixPermissions() int {
	n := 0
	for _, c := range a.CheckPermissions() {
		if c.OK {
			continue
		}
		path := filepath.Join(a.Home, c.Path)
		if c.Path == "(home)" {
			path = a.Home
		}
		mode := os.FileMode(0600)
		if c.Expected == "0700" {
			mode = 0700
		}
		if os.Chmod(path, mode) == nil {
			n++
		}
	}
	return n
}
