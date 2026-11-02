package rout

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// padSource is a static source whose size is dominated by Content.
func padSource(i int, n int) RemoteSource {
	return RemoteSource{
		ID: fmt.Sprintf("%012x", 0xabc000+i), Name: fmt.Sprintf("pad-%d", i), Kind: sourceKindStatic,
		Content: "# " + strings.Repeat("x", n), Enabled: true,
	}
}

func readSources(t *testing.T, a *App) []byte {
	t.Helper()
	b, e := os.ReadFile(a.remoteConfigPath())
	if e != nil && !os.IsNotExist(e) {
		t.Fatal(e)
	}
	return b
}

func noTempFiles(t *testing.T, a *App) {
	t.Helper()
	ents, _ := os.ReadDir(filepath.Dir(a.remoteConfigPath()))
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".rout-") {
			t.Fatalf("leftover temp file %s", e.Name())
		}
	}
}

// fillTo adds pad sources until the serialized file is exactly total bytes.
func fillTo(t *testing.T, a *App, total int) {
	t.Helper()
	var cfg remoteConfig
	cfg.Schema = remoteSchema
	for i := 0; ; i++ {
		base, e := JSON(cfg)
		if e != nil {
			t.Fatal(e)
		}
		room := total - len(base)
		next := padSource(i, 0)
		probe := cfg
		probe.Sources = append(append([]RemoteSource{}, cfg.Sources...), next)
		pb, _ := JSON(probe)
		overhead := len(pb) - len(base)
		need := total - len(base) - overhead
		if need < 0 {
			t.Fatalf("cannot hit %d (room %d)", total, room)
		}
		if need > maxRemoteContent-2 {
			need = maxRemoteContent - 2
		}
		cfg.Sources = append(cfg.Sources, padSource(i, need))
		if got, _ := JSON(cfg); len(got) == total {
			break
		}
	}
	b, _ := JSON(cfg)
	if len(b) != total {
		t.Fatalf("built %d want %d", len(b), total)
	}
	if e := os.MkdirAll(filepath.Dir(a.remoteConfigPath()), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(a.remoteConfigPath(), b, 0600); e != nil {
		t.Fatal(e)
	}
}

func TestRemoteConfigExactBoundary(t *testing.T) {
	for _, tc := range []struct {
		name  string
		total int
		ok    bool
	}{{"at limit", maxRemoteConfigBytes, true}, {"one byte over", maxRemoteConfigBytes + 1, false}} {
		t.Run(tc.name, func(t *testing.T) {
			var cfg remoteConfig
			cfg.Schema = remoteSchema
			for i := 0; i < 4; i++ {
				cfg.Sources = append(cfg.Sources, padSource(i, 1900_000))
			}
			base, _ := JSON(cfg)
			probe := cfg
			probe.Sources = append(append([]RemoteSource{}, cfg.Sources...), padSource(9, 0))
			pb, _ := JSON(probe)
			over := len(pb) - len(base)
			cfg.Sources = append(cfg.Sources, padSource(9, tc.total-len(base)-over))
			b, e := encodeRemoteConfig(cfg, 0)
			if got, _ := JSON(cfg); len(got) != tc.total {
				t.Fatalf("test setup: %d != %d", len(got), tc.total)
			}
			if tc.ok != (e == nil) {
				t.Fatalf("ok=%v err=%v", tc.ok, e)
			}
			if tc.ok && len(b) != maxRemoteConfigBytes {
				t.Fatalf("len=%d", len(b))
			}
			if !tc.ok && !strings.Contains(e.Error(), "上限") {
				t.Fatalf("unclear error: %v", e)
			}
		})
	}
}

// The scenario from the review: individually valid sources add up past what can be read back.
func TestRemoteConfigCumulativeSizeRefusedAndStaysReadable(t *testing.T) {
	a := testApp(t)
	accepted := 0
	var refused error
	for i := 0; i < 12; i++ {
		_, e := a.AddRemoteSource(RemoteSourceSpec{
			Name: fmt.Sprintf("S%d", i), Enabled: true,
			Content: linkVless + "\n# " + strings.Repeat("x", 950<<10),
		})
		if e != nil {
			refused = e
			break
		}
		accepted++
		if _, e := a.RemoteSources(); e != nil {
			t.Fatalf("source %d made the configuration unreadable: %v", i, e)
		}
	}
	if refused == nil || accepted == 0 {
		t.Fatalf("accepted=%d refused=%v", accepted, refused)
	}
	if !strings.Contains(refused.Error(), "上限") {
		t.Fatalf("refusal not explanatory: %v", refused)
	}
	if n := len(readSources(t, a)); n > maxRemoteConfigBytes {
		t.Fatalf("file is %d bytes", n)
	}
	list, e := a.RemoteSources()
	if e != nil || len(list) != accepted {
		t.Fatalf("list=%d accepted=%d err=%v", len(list), accepted, e)
	}
	noTempFiles(t, a)
	// Deleting still works and makes room again.
	if e = a.DeleteRemoteSource(list[0].ID, false); e != nil {
		t.Fatal(e)
	}
	if _, e = a.AddRemoteSource(RemoteSourceSpec{Name: "again", Enabled: true, Content: linkTrojan}); e != nil {
		t.Fatalf("add after delete: %v", e)
	}
}

func TestRemoteConfigEditPastLimitRefusedOriginalIntact(t *testing.T) {
	a := testApp(t)
	fillTo(t, a, maxRemoteConfigBytes-40)
	before := readSources(t, a)
	list, e := a.RemoteSources()
	if e != nil || len(list) == 0 {
		t.Fatalf("setup: %v", e)
	}
	note := strings.Repeat("n", 200)
	_, e = a.UpdateRemoteSource(list[0].ID, RemoteSourcePatch{Note: &note})
	if e == nil || !strings.Contains(e.Error(), "上限") {
		t.Fatalf("edit past the limit must be refused clearly, got %v", e)
	}
	if after := readSources(t, a); string(after) != string(before) {
		t.Fatal("refused edit changed the file")
	}
	if _, e = a.RemoteSources(); e != nil {
		t.Fatalf("configuration unreadable after refused edit: %v", e)
	}
	noTempFiles(t, a)
	// A small edit that still fits works.
	short := "ok"
	if _, e = a.UpdateRemoteSource(list[0].ID, RemoteSourcePatch{Note: &short}); e != nil {
		t.Fatal(e)
	}
}

func TestRemoteConfigFailedChangeKeepsOriginal(t *testing.T) {
	a := testApp(t)
	if _, e := a.AddRemoteSource(RemoteSourceSpec{Name: "keep", Enabled: true, Content: linkVless}); e != nil {
		t.Fatal(e)
	}
	before := readSources(t, a)
	boom := errors.New("boom")
	if e := a.mutateRemote(func(c *remoteConfig) error { c.Sources = nil; return boom }); !errors.Is(e, boom) {
		t.Fatalf("got %v", e)
	}
	// An invalid result is rejected before it is written.
	if e := a.mutateRemote(func(c *remoteConfig) error { c.Sources[0].Name = ""; return nil }); e == nil {
		t.Fatal("invalid configuration was accepted")
	}
	// A write that cannot create its temp file leaves the old file alone.
	dir := filepath.Dir(a.remoteConfigPath())
	if os.Geteuid() != 0 {
		_ = os.Chmod(dir, 0500)
		defer os.Chmod(dir, 0700)
		if e := a.mutateRemote(func(c *remoteConfig) error { c.Sources[0].Note = "x"; return nil }); e == nil {
			t.Fatal("write into a read-only directory succeeded")
		}
		_ = os.Chmod(dir, 0700)
	}
	if after := readSources(t, a); string(after) != string(before) {
		t.Fatal("failed change altered the file")
	}
	noTempFiles(t, a)
	if st, _ := os.Stat(a.remoteConfigPath()); st.Mode().Perm() != 0600 {
		t.Fatalf("mode %v", st.Mode())
	}
}

func TestRemoteConfigConcurrentWritersStayConsistent(t *testing.T) {
	a := testApp(t)
	var wg sync.WaitGroup
	var ok, refused atomic.Int32
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, e := a.AddRemoteSource(RemoteSourceSpec{
				Name: fmt.Sprintf("C%d", i), Enabled: true,
				Content: linkVless + "\n# " + strings.Repeat("y", 700<<10),
			})
			if e == nil {
				ok.Add(1)
			} else {
				refused.Add(1)
			}
		}(i)
	}
	wg.Wait()
	list, e := a.RemoteSources()
	if e != nil {
		t.Fatalf("unreadable after concurrent adds: %v", e)
	}
	if int32(len(list)) != ok.Load() || ok.Load() == 0 || refused.Load() == 0 {
		t.Fatalf("stored=%d ok=%d refused=%d", len(list), ok.Load(), refused.Load())
	}
	if n := len(readSources(t, a)); n > maxRemoteConfigBytes {
		t.Fatalf("file is %d bytes", n)
	}
	noTempFiles(t, a)
}

func TestRemoteConfigAlreadyOversizedDiagnosedAndRecoverable(t *testing.T) {
	a := testApp(t)
	fillTo(t, a, maxRemoteConfigBytes+3<<20) // as an earlier build could have written it
	_, e := a.loadRemoteConfig()
	if e == nil || !strings.Contains(e.Error(), "上限") || !strings.Contains(e.Error(), "字节") {
		t.Fatalf("diagnosis must state size and limit, got %v", e)
	}
	if _, e = a.RemoteSources(); e == nil {
		t.Fatal("listing an oversized configuration should report it")
	}
	cfg, e := a.readRemoteConfig(remoteRecoverBytes)
	if e != nil || len(cfg.Sources) < 3 {
		t.Fatalf("recovery read: %v", e)
	}
	// A change that makes the oversized file bigger is refused and leaves it untouched.
	before := readSources(t, a)
	note := strings.Repeat("n", 50)
	if _, e = a.UpdateRemoteSource(cfg.Sources[0].ID, RemoteSourcePatch{Note: &note}); e == nil {
		t.Fatal("growing an oversized configuration must be refused")
	}
	if string(readSources(t, a)) != string(before) {
		t.Fatal("refused change altered the file")
	}
	// Deleting shrinks it step by step until it is readable again.
	for _, s := range cfg.Sources {
		if e = a.DeleteRemoteSource(s.ID, false); e != nil {
			t.Fatalf("delete while oversized: %v", e)
		}
		if _, e2 := a.loadRemoteConfig(); e2 == nil {
			break
		}
	}
	if _, e = a.RemoteSources(); e != nil {
		t.Fatalf("not recovered: %v", e)
	}
	if n := len(readSources(t, a)); n > maxRemoteConfigBytes {
		t.Fatalf("still %d bytes", n)
	}
}

func TestRemoteConfigAbsurdlyLargeFileNotParsed(t *testing.T) {
	a := testApp(t)
	if e := os.MkdirAll(filepath.Dir(a.remoteConfigPath()), 0700); e != nil {
		t.Fatal(e)
	}
	f, _ := os.Create(a.remoteConfigPath())
	_ = f.Truncate(remoteRecoverBytes + 10)
	f.Close()
	if e := a.mutateRemote(func(*remoteConfig) error { return nil }); e == nil || !strings.Contains(e.Error(), "异常过大") {
		t.Fatalf("got %v", e)
	}
}

func TestRestoreRefusesOversizedSourcesBeforeCommitting(t *testing.T) {
	a := testApp(t)
	if _, e := a.AddRemoteSource(RemoteSourceSpec{Name: "orig", Enabled: true, Content: linkVless}); e != nil {
		t.Fatal(e)
	}
	st, e := a.Load()
	if e != nil {
		t.Fatal(e)
	}
	var big remoteConfig
	big.Schema = remoteSchema
	for i := 0; i < 6; i++ {
		big.Sources = append(big.Sources, padSource(i, 1900_000))
	}
	next := st
	next.Subscriptions = append([]Subscription{}, st.Subscriptions...)
	err := a.RestoreBackup(&parsedBackup{Full: true, State: next, Remote: big, Snaps: map[string]*RemoteSnapshot{}})
	if err == nil || !strings.Contains(err.Error(), "上限") {
		t.Fatalf("restore with unreadable sources must be refused, got %v", err)
	}
	list, e := a.RemoteSources()
	if e != nil || len(list) != 1 || list[0].Name != "orig" {
		t.Fatalf("restore changed the sources: %v %v", list, e)
	}
}

// A malicious provider must not hold a refresh slot or spin the CPU.
func TestRemoteRefreshMaliciousYAMLFailsFastAndFreesSlot(t *testing.T) {
	a, fs, src := remoteScene(t, linkList(linkVless))
	good := snapshotOf(t, a, src.ID)
	for _, evil := range []string{
		"proxies: [{<<: &loop [*loop]}]\n",
		"proxies:\n  - <<: &a\n      - *a\n",
	} {
		fs.set(evil, nil)
		done := make(chan error, 1)
		go func() { _, e := a.RefreshRemoteSource(context.Background(), src.ID); done <- e }()
		select {
		case e := <-done:
			if e == nil {
				t.Fatal("malicious document was accepted")
			}
			if strings.Contains(e.Error(), "panic") {
				t.Fatalf("unreadable diagnostic: %v", e)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("refresh did not finish: slot would stay occupied")
		}
	}
	if got := snapshotOf(t, a, src.ID); len(got.Nodes) != len(good.Nodes) {
		t.Fatalf("last good result lost: %d -> %d", len(good.Nodes), len(got.Nodes))
	}
	// All slots are free again: three sources can refresh at once.
	if len(remoteSem) != 0 {
		t.Fatalf("%d refresh slots still held", len(remoteSem))
	}
	fs.set(linkList(linkVless, linkTrojan), nil)
	if _, e := a.RefreshRemoteSource(context.Background(), src.ID); e != nil {
		t.Fatalf("source cannot refresh after the attack: %v", e)
	}
}

func TestRemoteRefreshCancelledParseReleasesSlot(t *testing.T) {
	var b strings.Builder
	b.WriteString("proxies:\n")
	for i := 0; i < 1800; i++ {
		fmt.Fprintf(&b, "  - {name: n%d, type: ss, server: h%d.example.org, port: 1, cipher: aes-128-gcm, password: p}\n", i, i)
	}
	a, fs, src := remoteScene(t, linkList(linkVless))
	fs.set(b.String(), nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := a.RefreshRemoteSource(ctx, src.ID); e == nil {
		t.Fatal("cancelled refresh reported success")
	}
	if len(remoteSem) != 0 {
		t.Fatalf("%d slots held after cancellation", len(remoteSem))
	}
}
