package rout

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/VAR7IANT/Rout/internal/remote"
)

// Refreshing third-party sources.
//
// A refresh never touches proxies, forwarding or state.json: it downloads, parses and validates
// into memory, and only a complete, non-empty result replaces the stored snapshot (one atomic
// rename). Any failure — network, HTTP status, size, parse, "no usable node" — records the
// error and leaves the last good snapshot exactly as it was.

type remoteFetchFunc func(ctx context.Context, rawURL string, opt remote.FetchOptions) (*remote.Result, error)

var (
	errRefreshBusy = errors.New("该订阅源正在刷新，请稍后")
	// remoteInflight makes concurrent refreshes of one source in this process a no-op for
	// the second caller; the per-source file lock does the same across processes.
	remoteInflight sync.Map
	// remoteSem bounds how many sources download at once, manual and scheduled together.
	remoteSem     = make(chan struct{}, 3)
	defaultFetch  remoteFetchFunc
	defaultFetchO sync.Once
)

func (a *App) fetchRemote(ctx context.Context, rawURL string, opt remote.FetchOptions) (*remote.Result, error) {
	if a.remoteFetch != nil {
		return a.remoteFetch(ctx, rawURL, opt)
	}
	defaultFetchO.Do(func() { defaultFetch = remote.NewFetcher().Fetch })
	return defaultFetch(ctx, rawURL, opt)
}

var urlInText = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^\s"'<>]+`)

// redactError makes a failure safe to store and show: no URL (which may hold a token), no
// control characters, bounded length.
func redactError(err error) string {
	s := urlInText.ReplaceAllString(err.Error(), "<地址已隐藏>")
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if r := []rune(s); len(r) > 300 {
		s = string(r[:300]) + "…"
	}
	return s
}

// RemoteRefreshResult summarises one successful refresh.
type RemoteRefreshResult struct {
	Format  string `json:"format"`
	Valid   int    `json:"valid"`
	Errors  int    `json:"errors"`
	Skipped int    `json:"skipped"`
	Added   int    `json:"added"`
	Removed int    `json:"removed"`
}

// RefreshRemoteSource refreshes one source now (manual refresh). It returns errRefreshBusy
// when the same source is already being refreshed, and on any failure keeps the old data.
func (a *App) RefreshRemoteSource(ctx context.Context, id string) (RemoteRefreshResult, error) {
	var zero RemoteRefreshResult
	if !idPattern.MatchString(id) {
		return zero, errors.New("订阅源 ID 无效")
	}
	key := a.Home + "\x00" + id
	if _, busy := remoteInflight.LoadOrStore(key, true); busy {
		return zero, errRefreshBusy
	}
	defer remoteInflight.Delete(key)
	select {
	case remoteSem <- struct{}{}:
		defer func() { <-remoteSem }()
	case <-ctx.Done():
		return zero, ctx.Err()
	}
	unlock, e := lockFile(a.remotePath("data", id+".refresh"), 0)
	if e != nil {
		if errors.Is(e, errLockBusy) {
			return zero, errRefreshBusy
		}
		return zero, e
	}
	defer unlock()

	cfg, e := a.loadRemoteConfig()
	if e != nil {
		return zero, e
	}
	i, ok := cfg.find(id)
	if !ok {
		return zero, errors.New("找不到订阅源")
	}
	src := cfg.Sources[i]
	old, _ := a.loadRemoteSnapshot(id)
	now := time.Now().UTC()

	parsed, ui, title, e := a.downloadAndParse(ctx, src)
	if e != nil {
		a.recordRefreshFailure(id, old, now, e)
		return zero, e
	}
	// The source may have been edited or deleted while we were downloading; never write the
	// result of a request made with stale settings.
	if cur, e2 := a.loadRemoteConfig(); e2 != nil {
		return zero, e2
	} else if j, ok := cur.find(id); !ok {
		return zero, errors.New("订阅源在刷新期间被删除")
	} else if cur.Sources[j].URL != src.URL || cur.Sources[j].Content != src.Content {
		return zero, errors.New("订阅源在刷新期间被修改，请重新刷新")
	}
	snap := snapshotFrom(id, parsed, ui, title, now)
	if e = a.saveRemoteSnapshot(snap); e != nil {
		a.recordRefreshFailure(id, old, now, e)
		return zero, e
	}
	res := RemoteRefreshResult{Format: parsed.Format, Valid: len(snap.Nodes)}
	for _, is := range parsed.Issues {
		if is.Level == "skip" {
			res.Skipped++
		} else {
			res.Errors++
		}
	}
	before := map[string]bool{}
	if old != nil {
		for _, n := range old.Nodes {
			before[n.ID] = true
		}
	}
	after := map[string]bool{}
	for _, n := range snap.Nodes {
		after[n.ID] = true
		if !before[n.ID] {
			res.Added++
		}
	}
	for id := range before {
		if !after[id] {
			res.Removed++
		}
	}
	return res, nil
}

func (a *App) downloadAndParse(ctx context.Context, src RemoteSource) (remote.Parsed, *remote.UserInfo, string, error) {
	var body []byte
	var ui *remote.UserInfo
	var title string
	if src.Kind == sourceKindStatic {
		body = []byte(src.Content)
	} else {
		res, e := a.fetchRemote(ctx, src.URL, remote.FetchOptions{UserAgent: src.UserAgent})
		if e != nil {
			return remote.Parsed{}, nil, "", errors.New(redactError(e))
		}
		body, ui, title = res.Body, res.UserInfo, res.Title
	}
	p, e := remote.Parse(body)
	if e != nil {
		return remote.Parsed{}, nil, "", errors.New(redactError(e))
	}
	if len(p.Nodes) == 0 {
		return remote.Parsed{}, nil, "", errors.New("订阅中没有可用节点，已保留上一次成功的结果")
	}
	return p, ui, title, nil
}

// recordRefreshFailure stores the error next to the untouched last good snapshot.
func (a *App) recordRefreshFailure(id string, old *RemoteSnapshot, now time.Time, cause error) {
	var snap RemoteSnapshot
	if old != nil {
		snap = *old
	} else {
		snap = RemoteSnapshot{SourceID: id, Nodes: []remote.Node{}}
	}
	snap.Status.State = "error"
	snap.Status.LastAttempt = now
	snap.Status.LastError = redactError(cause)
	snap.Status.Failures++
	// Best effort: if even this cannot be written the old file is still intact.
	if cur, e := a.loadRemoteConfig(); e == nil {
		if _, ok := cur.find(id); !ok {
			return
		}
	}
	_ = a.saveRemoteSnapshot(&snap)
}

// nextRefresh is when a source is due again. It depends only on persisted data, so a restart
// resumes the schedule instead of refreshing everything at once. Failures back off from 15
// minutes up to the normal interval; a per-source offset spreads sources over time.
func nextRefresh(src RemoteSource, st RemoteStatus, now time.Time) time.Time {
	if st.LastAttempt.IsZero() {
		return now
	}
	interval := time.Duration(src.IntervalMin) * time.Minute
	delay := interval
	if st.State == "error" && st.Failures > 0 {
		shift := st.Failures - 1
		if shift > 6 {
			shift = 6
		}
		if back := 15 * time.Minute << uint(shift); back < delay {
			delay = back
		}
	}
	return st.LastAttempt.Add(delay + sourceJitter(src.ID, interval))
}

// sourceJitter is a stable offset of up to 10% of the interval (at most 10 minutes).
func sourceJitter(id string, interval time.Duration) time.Duration {
	h := sha256.Sum256([]byte(id))
	span := interval / 10
	if span > 10*time.Minute {
		span = 10 * time.Minute
	}
	if span <= 0 {
		return 0
	}
	return time.Duration(binary.BigEndian.Uint64(h[:8]) % uint64(span))
}

// DueRemoteSources lists the enabled URL sources whose refresh is due at now, oldest first.
func (a *App) DueRemoteSources(now time.Time) ([]string, error) {
	cfg, e := a.loadRemoteConfig()
	if e != nil {
		return nil, e
	}
	type due struct {
		id string
		at time.Time
	}
	var list []due
	for _, src := range cfg.Sources {
		if src.Kind != sourceKindURL || !src.Enabled || src.IntervalMin <= 0 {
			continue
		}
		var st RemoteStatus
		if snap, e := a.loadRemoteSnapshot(src.ID); e == nil && snap != nil {
			st = snap.Status
		}
		if at := nextRefresh(src, st, now); !at.After(now) {
			list = append(list, due{src.ID, at})
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].at.Before(list[j].at) })
	ids := make([]string, len(list))
	for i, d := range list {
		ids[i] = d.id
	}
	return ids, nil
}

// RunRemoteScheduler refreshes due sources until ctx ends. It returns immediately for each
// source that is already being refreshed. Failures are recorded per source and never stop
// the loop. A source that is not due costs one stat-sized read per tick.
func (a *App) RunRemoteScheduler(ctx context.Context, tick time.Duration, log func(string)) {
	if tick <= 0 {
		tick = time.Minute
	}
	if log == nil {
		log = func(string) {}
	}
	run := func() {
		a.gcRemoteSnapshots()
		ids, e := a.DueRemoteSources(time.Now())
		if e != nil {
			log("第三方订阅调度读取配置失败：" + redactError(e))
			return
		}
		var wg sync.WaitGroup
		for _, id := range ids {
			if ctx.Err() != nil {
				break
			}
			wg.Add(1)
			go func(id string) {
				defer wg.Done()
				rctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
				defer cancel()
				if _, e := a.RefreshRemoteSource(rctx, id); e != nil && !errors.Is(e, errRefreshBusy) {
					log("第三方订阅刷新失败 " + id + "：" + redactError(e))
				}
			}(id)
		}
		wg.Wait()
	}
	run()
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run()
		}
	}
}

// gcRemoteSnapshots removes snapshot files of sources that no longer exist.
func (a *App) gcRemoteSnapshots() {
	cfg, e := a.loadRemoteConfig()
	if e != nil {
		return
	}
	known := map[string]bool{}
	for _, s := range cfg.Sources {
		known[s.ID] = true
	}
	entries, e := os.ReadDir(a.remotePath("data"))
	if e != nil {
		return
	}
	for _, ent := range entries {
		name := ent.Name()
		base := strings.TrimSuffix(strings.TrimSuffix(name, ".json"), ".refresh")
		if base == name || !idPattern.MatchString(base) || known[base] {
			continue
		}
		// Recent files may belong to a source being added right now.
		if info, e := ent.Info(); e == nil && time.Since(info.ModTime()) > time.Minute {
			_ = os.Remove(filepath.Join(a.remotePath("data"), name))
		}
	}
}
