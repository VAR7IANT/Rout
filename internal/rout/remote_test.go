package rout

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/VAR7IANT/Rout/internal/remote"
)

const (
	pbk = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	linkVless  = "vless://11111111-1111-4111-8111-111111111111@198.51.100.10:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.example.org&fp=chrome&pbk=" + pbk + "&sid=0123abcd&type=tcp#HK%20Reality"
	linkTrojan = "trojan://trojanpw@203.0.113.20:443?security=tls&sni=t.example.net&type=ws&host=t.example.net&path=%2Fws#JP%20Trojan"
	linkHy2    = "hysteria2://hy2pw@203.0.113.30:8443?sni=h.example.net&alpn=h3&obfs=salamander&obfs-password=xyz#SG%20HY2"
	linkSS     = "ss://YWVzLTI1Ni1nY206cGFzcw@203.0.113.40:8388#US%20SS"
	linkSSPlug = "ss://YWVzLTI1Ni1nY206cGFzcw@203.0.113.41:8388/?plugin=obfs-local%3Bobfs%3Dhttp#SS%20Plugin"
	linkInsec  = "trojan://insecpw@203.0.113.21:443?security=tls&sni=i.example.net&allowInsecure=1#Insecure%20Trojan"

	secretURL = "https://sub.provider.test/api/v1/client/subscribe?token=SUPERSECRETTOKEN"
)

var clashFixture = `
port: 7890
proxies:
  - {name: "🇭🇰 Clash VLESS WS", type: vless, server: cdn.example.net, port: 443, uuid: 22222222-2222-4222-8222-222222222222, network: ws, tls: true, servername: cdn.example.net, ws-opts: {path: /vl, headers: {Host: cdn.example.net}}, client-fingerprint: chrome, alpn: [h2, http/1.1], udp: true}
  - {name: "Clash Hy2 Insecure", type: hysteria2, server: 203.0.113.50, port: 443, password: pw2, sni: h2.example.net, skip-cert-verify: true}
  - {name: "Clash SS", type: ss, server: 203.0.113.60, port: 8388, cipher: aes-256-gcm, password: pass}
proxy-groups:
  - {name: x, type: select, proxies: [a]}
rules:
  - MATCH,x
`

// fakeSource is a controllable subscription provider.
type fakeSource struct {
	mu    sync.Mutex
	body  string
	err   error
	calls atomic.Int32
	delay time.Duration
	ui    *remote.UserInfo
}

func (f *fakeSource) set(body string, err error) {
	f.mu.Lock()
	f.body, f.err = body, err
	f.mu.Unlock()
}
func (f *fakeSource) fetch(ctx context.Context, rawURL string, opt remote.FetchOptions) (*remote.Result, error) {
	f.calls.Add(1)
	f.mu.Lock()
	body, err, delay := f.body, f.err, f.delay
	f.mu.Unlock()
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if err != nil {
		return nil, err
	}
	return &remote.Result{Body: []byte(body), UserInfo: f.ui, Title: "Provider"}, nil
}

func linkList(links ...string) string { return strings.Join(links, "\n") }

func remoteScene(t *testing.T, body string) (*App, *fakeSource, RemoteSource) {
	t.Helper()
	a := testApp(t)
	fs := &fakeSource{body: body}
	a.remoteFetch = fs.fetch
	src, e := a.AddRemoteSource(RemoteSourceSpec{Name: "Provider A", URL: secretURL, Enabled: true, IntervalMin: 60})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.RefreshRemoteSource(context.Background(), src.ID); e != nil {
		t.Fatal(e)
	}
	return a, fs, src
}

func snapshotOf(t *testing.T, a *App, id string) *RemoteSnapshot {
	t.Helper()
	s, e := a.loadRemoteSnapshot(id)
	if e != nil || s == nil {
		t.Fatalf("snapshot: %v %v", s, e)
	}
	return s
}

func TestRemoteSourceStaticImportAndValidation(t *testing.T) {
	a := testApp(t)
	src, e := a.AddRemoteSource(RemoteSourceSpec{Name: "Pasted", Content: linkList(linkVless, linkTrojan, linkHy2, linkSS, "vmess://abc"), Enabled: true, Tags: []string{"hk", "HK", " ", "paid"}})
	if e != nil {
		t.Fatal(e)
	}
	if src.Kind != sourceKindStatic || len(src.Tags) != 2 {
		t.Fatalf("%+v", src)
	}
	snap := snapshotOf(t, a, src.ID)
	if len(snap.Nodes) != 4 || snap.Status.State != "ok" {
		t.Fatalf("nodes=%d status=%+v", len(snap.Nodes), snap.Status)
	}
	var unsupported int
	for _, is := range snap.Issues {
		if strings.Contains(is.Reason, "vmess") {
			unsupported++
		}
	}
	if unsupported != 1 {
		t.Fatalf("an unsupported vmess entry must be reported, not dropped silently: %+v", snap.Issues)
	}
	for name, spec := range map[string]RemoteSourceSpec{
		"empty name":      {Name: " ", Content: linkVless},
		"no nodes":        {Name: "x", Content: "hello world"},
		"bad scheme":      {Name: "x", URL: "ftp://a.example.net/x"},
		"loopback url":    {Name: "x", URL: "http://127.0.0.1/sub"},
		"interval low":    {Name: "x", URL: "https://a.example.net/x", IntervalMin: 5},
		"interval high":   {Name: "x", URL: "https://a.example.net/x", IntervalMin: 99999},
		"too many tags":   {Name: "x", Content: linkVless, Tags: []string{"1", "2", "3", "4", "5", "6", "7", "8", "9"}},
		"newline in note": {Name: "x", Content: linkVless, Note: strings.Repeat("a", 201)},
	} {
		if _, e := a.AddRemoteSource(spec); e == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, e := a.AddRemoteSource(RemoteSourceSpec{Name: "pasted", Content: linkVless}); e == nil {
		t.Error("duplicate (case-insensitive) name accepted")
	}
}

func TestRemoteSourceNeverExposesItsURL(t *testing.T) {
	a, _, src := remoteScene(t, linkList(linkVless, linkTrojan))
	views, e := a.RemoteSources()
	if e != nil || len(views) != 1 {
		t.Fatal(e, views)
	}
	b, _ := json.Marshal(views)
	for _, secret := range []string{"SUPERSECRETTOKEN", "/api/v1/client", "token="} {
		if strings.Contains(string(b), secret) {
			t.Fatalf("view leaks %q: %s", secret, b)
		}
	}
	if views[0].URLMasked != "https://sub.provider.test/…" {
		t.Fatalf("masked url %q", views[0].URLMasked)
	}
	got, e := a.RemoteSourceSecret(src.ID)
	if e != nil || got != secretURL {
		t.Fatalf("explicit reveal failed: %q %v", got, e)
	}
}

func TestRemoteStorePermissions(t *testing.T) {
	a, _, src := remoteScene(t, linkList(linkVless))
	for path, want := range map[string]os.FileMode{
		a.remotePath(): 0700,
		filepath.Dir(a.remoteSnapshotPath(src.ID)): 0700,
		a.remoteConfigPath():                       0600,
		a.remoteSnapshotPath(src.ID):               0600,
	} {
		fi, e := os.Stat(path)
		if e != nil {
			t.Fatal(path, e)
		}
		if fi.Mode().Perm() != want {
			t.Errorf("%s: %v, want %v", path, fi.Mode().Perm(), want)
		}
	}
}

func TestRemoteRefreshFailureKeepsLastGoodSnapshot(t *testing.T) {
	a, fs, src := remoteScene(t, linkList(linkVless, linkTrojan, linkHy2))
	before := snapshotOf(t, a, src.ID)
	if len(before.Nodes) != 3 {
		t.Fatal(len(before.Nodes))
	}
	cases := map[string]struct {
		body string
		err  error
	}{
		"network":    {err: errors.New("dial https://sub.provider.test/api?token=SUPERSECRETTOKEN: connection refused")},
		"garbage":    {body: "<html>Service unavailable</html>"},
		"empty":      {body: ""},
		"only error": {body: "vmess://AAAA"},
	}
	for name, c := range cases {
		fs.set(c.body, c.err)
		if _, e := a.RefreshRemoteSource(context.Background(), src.ID); e == nil {
			t.Fatalf("%s: refresh unexpectedly succeeded", name)
		}
		after := snapshotOf(t, a, src.ID)
		if len(after.Nodes) != 3 || after.Nodes[0].ID != before.Nodes[0].ID {
			t.Fatalf("%s: nodes were replaced by a failed refresh", name)
		}
		if after.Status.State != "error" || after.Status.LastError == "" || !after.Status.LastSuccess.Equal(before.Status.LastSuccess) {
			t.Fatalf("%s: status %+v", name, after.Status)
		}
		if strings.Contains(after.Status.LastError, "SUPERSECRETTOKEN") || strings.Contains(after.Status.LastError, "provider.test") {
			t.Fatalf("%s: stored error leaks the URL: %q", name, after.Status.LastError)
		}
	}
	if st := snapshotOf(t, a, src.ID).Status; st.Failures != len(cases) {
		t.Fatalf("failure count %d", st.Failures)
	}
	// Recovery: a good body replaces the snapshot and clears the error state.
	fs.set(linkList(linkVless, linkSS), nil)
	res, e := a.RefreshRemoteSource(context.Background(), src.ID)
	if e != nil {
		t.Fatal(e)
	}
	if res.Valid != 2 || res.Added != 1 || res.Removed != 2 {
		t.Fatalf("%+v", res)
	}
	if st := snapshotOf(t, a, src.ID).Status; st.State != "ok" || st.Failures != 0 || st.LastError != "" {
		t.Fatalf("%+v", st)
	}
}

func TestRemoteRefreshAtMostOncePerSourceAtATime(t *testing.T) {
	a, fs, src := remoteScene(t, linkList(linkVless))
	fs.mu.Lock()
	fs.delay = 300 * time.Millisecond
	fs.mu.Unlock()
	start := fs.calls.Load()
	var wg sync.WaitGroup
	var busy, ok atomic.Int32
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, e := a.RefreshRemoteSource(context.Background(), src.ID)
			switch {
			case e == nil:
				ok.Add(1)
			case errors.Is(e, errRefreshBusy):
				busy.Add(1)
			default:
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 1 || busy.Load() != 7 || fs.calls.Load()-start != 1 {
		t.Fatalf("ok=%d busy=%d downloads=%d", ok.Load(), busy.Load(), fs.calls.Load()-start)
	}
}

func TestRemoteRefreshDiscardsResultOfEditedSource(t *testing.T) {
	a, fs, src := remoteScene(t, linkList(linkVless))
	fs.mu.Lock()
	fs.delay = 200 * time.Millisecond
	fs.body = linkList(linkSS)
	fs.mu.Unlock()
	done := make(chan error, 1)
	go func() { _, e := a.RefreshRemoteSource(context.Background(), src.ID); done <- e }()
	time.Sleep(60 * time.Millisecond)
	newURL := "https://other.provider.test/sub"
	if _, e := a.UpdateRemoteSource(src.ID, RemoteSourcePatch{URL: &newURL}); e != nil {
		t.Fatal(e)
	}
	if e := <-done; e == nil {
		t.Fatal("a download started for the old URL was stored for the edited source")
	}
	if got := snapshotOf(t, a, src.ID); len(got.Nodes) != 1 || got.Nodes[0].Protocol != "vless" {
		t.Fatalf("snapshot changed: %+v", got.Nodes)
	}
}

func TestRemoteSchedulerDueAndResumeAfterRestart(t *testing.T) {
	a, fs, src := remoteScene(t, linkList(linkVless))
	now := time.Now()
	due, _ := a.DueRemoteSources(now)
	if len(due) != 0 {
		t.Fatalf("freshly refreshed source is due: %v", due)
	}
	// Interval is 60 minutes; the per-source offset is below 6 minutes.
	due, _ = a.DueRemoteSources(now.Add(70 * time.Minute))
	if len(due) != 1 || due[0] != src.ID {
		t.Fatalf("not due after the interval: %v", due)
	}
	// A new App over the same directory (a restart) sees the same schedule.
	b := &App{Home: a.Home, BinDir: a.BinDir, ServiceMode: "none", Language: "en", remoteFetch: fs.fetch}
	if due, _ = b.DueRemoteSources(now); len(due) != 0 {
		t.Fatalf("restart refreshes everything at once: %v", due)
	}
	if due, _ = b.DueRemoteSources(now.Add(70 * time.Minute)); len(due) != 1 {
		t.Fatalf("restart lost the schedule: %v", due)
	}
	// Failures back off but never beyond the normal interval.
	fs.set("", errors.New("boom"))
	_, _ = a.RefreshRemoteSource(context.Background(), src.ID)
	if due, _ = a.DueRemoteSources(time.Now()); len(due) != 0 {
		t.Fatal("failed source is retried immediately")
	}
	if due, _ = a.DueRemoteSources(time.Now().Add(25 * time.Minute)); len(due) != 1 {
		t.Fatal("failed source not retried after the first back-off")
	}
	// Disabled and manual-only sources are never scheduled.
	off := false
	if _, e := a.UpdateRemoteSource(src.ID, RemoteSourcePatch{Enabled: &off}); e != nil {
		t.Fatal(e)
	}
	if due, _ = a.DueRemoteSources(time.Now().Add(48 * time.Hour)); len(due) != 0 {
		t.Fatal("disabled source scheduled")
	}
	manual, e := a.AddRemoteSource(RemoteSourceSpec{Name: "Manual", URL: "https://m.provider.test/s", Enabled: true})
	if e != nil {
		t.Fatal(e)
	}
	if due, _ = a.DueRemoteSources(time.Now().Add(48 * time.Hour)); len(due) != 0 {
		t.Fatalf("manual-only source %s scheduled: %v", manual.ID, due)
	}
}

func TestRemoteSchedulerRunRefreshesDueSourcesAndSurvivesFailures(t *testing.T) {
	a := testApp(t)
	good, bad := &fakeSource{body: linkList(linkVless)}, &fakeSource{err: errors.New("down")}
	a.remoteFetch = func(ctx context.Context, rawURL string, opt remote.FetchOptions) (*remote.Result, error) {
		if strings.Contains(rawURL, "bad") {
			return bad.fetch(ctx, rawURL, opt)
		}
		return good.fetch(ctx, rawURL, opt)
	}
	g, e := a.AddRemoteSource(RemoteSourceSpec{Name: "good", URL: "https://good.provider.test/s", Enabled: true, IntervalMin: 30})
	if e != nil {
		t.Fatal(e)
	}
	b, e := a.AddRemoteSource(RemoteSourceSpec{Name: "bad", URL: "https://bad.provider.test/s", Enabled: true, IntervalMin: 30})
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var logs []string
	var mu sync.Mutex
	done := make(chan struct{})
	go func() {
		a.RunRemoteScheduler(ctx, 20*time.Millisecond, func(s string) { mu.Lock(); logs = append(logs, s); mu.Unlock() })
		close(done)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		gs, _ := a.loadRemoteSnapshot(g.ID)
		bs, _ := a.loadRemoteSnapshot(b.ID)
		if gs != nil && gs.Status.State == "ok" && bs != nil && bs.Status.State == "error" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
	if gs := snapshotOf(t, a, g.ID); gs.Status.State != "ok" || len(gs.Nodes) != 1 {
		t.Fatalf("good source %+v", gs.Status)
	}
	if bs := snapshotOf(t, a, b.ID); bs.Status.State != "error" {
		t.Fatalf("bad source %+v", bs.Status)
	}
	// Each source is attempted once per interval, not once per tick.
	if good.calls.Load() != 1 || bad.calls.Load() != 1 {
		t.Fatalf("calls good=%d bad=%d", good.calls.Load(), bad.calls.Load())
	}
	mu.Lock()
	defer mu.Unlock()
	for _, l := range logs {
		if strings.Contains(l, "bad.provider.test") {
			t.Fatalf("scheduler log leaks a URL: %s", l)
		}
	}
}

func TestRemoteSourceDeleteProtectionAndDetach(t *testing.T) {
	sc := newSubScene(t)
	a := sc.a
	fs := &fakeSource{body: linkList(linkVless, linkTrojan)}
	a.remoteFetch = fs.fetch
	src, e := a.AddRemoteSource(RemoteSourceSpec{Name: "P", URL: secretURL, Enabled: true})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.RefreshRemoteSource(context.Background(), src.ID); e != nil {
		t.Fatal(e)
	}
	snap := snapshotOf(t, a, src.ID)
	items := []SubItem{{Kind: itemLocal, NodeID: sc.nodes[0].ID}, {Kind: itemRemote, SourceID: src.ID, RemoteID: snap.Nodes[0].ID}}
	if _, _, e = a.CreateAggregateSubscription("Mix", AggregateSpec{Items: items}); e != nil {
		t.Fatal(e)
	}
	if e = a.DeleteRemoteSource(src.ID, false); e == nil || !strings.Contains(e.Error(), "Mix") {
		t.Fatalf("a referenced source was deleted or the error names nothing: %v", e)
	}
	if views, _ := a.RemoteSources(); len(views) != 1 || len(views[0].Refs) != 1 || views[0].Refs[0] != "Mix" {
		t.Fatalf("reference count: %+v", views)
	}
	if e = a.DeleteRemoteSource(src.ID, true); e != nil {
		t.Fatal(e)
	}
	s := sc.state(t)
	if len(s.Subscriptions[0].Items) != 1 || s.Subscriptions[0].Items[0].Kind != itemLocal {
		t.Fatalf("detach did not remove only the remote items: %+v", s.Subscriptions[0].Items)
	}
	if _, err := os.Stat(a.remoteSnapshotPath(src.ID)); !os.IsNotExist(err) {
		t.Fatal("snapshot not removed")
	}
}

func TestRemoteUserInfoAndDisabledNodes(t *testing.T) {
	a, fs, src := remoteScene(t, linkList(linkVless, linkTrojan, linkHy2))
	fs.ui = &remote.UserInfo{Upload: 1, Download: 2, Total: 100, Expire: 1900000000}
	if _, e := a.RefreshRemoteSource(context.Background(), src.ID); e != nil {
		t.Fatal(e)
	}
	snap := snapshotOf(t, a, src.ID)
	dis := []string{snap.Nodes[1].ID}
	if _, e := a.UpdateRemoteSource(src.ID, RemoteSourcePatch{DisabledNodes: &dis}); e != nil {
		t.Fatal(e)
	}
	v, _ := a.RemoteSources()
	if v[0].UserInfo == nil || v[0].UserInfo.Total != 100 || v[0].Valid != 3 || v[0].Active != 2 || v[0].Disabled != 1 {
		t.Fatalf("%+v", v[0])
	}
	foreign := []string{"abcdefabcdef"}
	if _, e := a.UpdateRemoteSource(src.ID, RemoteSourcePatch{DisabledNodes: &foreign}); e == nil {
		t.Fatal("a node that is not in the source was accepted")
	}
}
