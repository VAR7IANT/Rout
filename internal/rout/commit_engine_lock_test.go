package rout

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// gatedEngine replaces ensureEngine for one test: the first install waits until release is
// closed, as a download on a slow link would.
type gatedEngine struct {
	mu      sync.Mutex
	calls   map[string]int
	held    chan struct{}
	release chan struct{}
	once    sync.Once
	fail    error
}

func installGatedEngine(t *testing.T) *gatedEngine {
	t.Helper()
	g := &gatedEngine{calls: map[string]int{}, held: make(chan struct{}), release: make(chan struct{})}
	prev := ensureEngine
	ensureEngine = func(a *App, name string) error {
		g.mu.Lock()
		g.calls[name]++
		first := g.calls[name] == 1
		g.mu.Unlock()
		if first {
			g.once.Do(func() { close(g.held) })
			<-g.release
		}
		return g.fail
	}
	t.Cleanup(func() { ensureEngine = prev })
	return g
}

func commitNewNode(t *testing.T, a *App) (State, chan error) {
	t.Helper()
	old, e := a.Load()
	if e != nil {
		t.Fatal(e)
	}
	p := fixture(t, "ss")
	p.Port = distinctFreePort(t)
	p.PublicPort = p.Port
	done := make(chan error, 1)
	go func() { done <- a.Commit(old, replace(old, p), false) }()
	return old, done
}

// While a commit is installing an engine, other rout operations must still be able to take
// the configuration lock. Before, the download ran under that lock, so the menu, the panel
// and the traffic monitor queued behind it and gave up with "another rout operation is
// still in progress".
func TestCommitDoesNotHoldConfigLockWhileInstallingEngine(t *testing.T) {
	a := testApp(t)
	g := installGatedEngine(t)
	_, done := commitNewNode(t, a)
	select {
	case <-g.held:
	case e := <-done:
		t.Fatalf("commit finished without installing an engine: %v", e)
	case <-time.After(5 * time.Second):
		t.Fatal("engine install never started")
	}
	unlock, e := a.lockWait(300 * time.Millisecond)
	if e != nil {
		close(g.release)
		<-done
		t.Fatalf("configuration lock held during the engine install: %v", e)
	}
	unlock()
	close(g.release)
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("commit did not finish")
	}
	s, _ := a.Load()
	if len(s.Profiles) != 1 {
		t.Fatalf("node not committed: %d profiles", len(s.Profiles))
	}
	if n := g.calls["sing-box"]; n != 1 {
		t.Fatalf("sing-box ensured %d times, want once", n)
	}
}

// A failed install still refuses the change and writes nothing.
func TestCommitEngineInstallFailureWritesNothing(t *testing.T) {
	a := testApp(t)
	g := installGatedEngine(t)
	g.fail = errors.New("download failed")
	close(g.release)
	_, done := commitNewNode(t, a)
	if e := <-done; e == nil || e.Error() != "download failed" {
		t.Fatalf("want the install error, got %v", e)
	}
	s, _ := a.Load()
	if len(s.Profiles) != 0 {
		t.Fatal("state written despite the failed install")
	}
}
