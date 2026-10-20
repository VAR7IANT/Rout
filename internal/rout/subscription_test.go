package rout

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

type subScene struct {
	a     *App
	nodes []Profile
}

func newSubScene(t *testing.T) *subScene {
	t.Helper()
	a := testApp(t)
	return &subScene{a: a, nodes: []Profile{aiTestNode(t, a, "vless", "alpha"), aiTestNode(t, a, "ss", "bravo"), aiTestNode(t, a, "anytls", "charlie")}}
}
func (sc *subScene) ids(idx ...int) []string {
	var out []string
	for _, i := range idx {
		out = append(out, sc.nodes[i].ID)
	}
	return out
}
func (sc *subScene) create(t *testing.T, name string, idx ...int) (Subscription, string) {
	t.Helper()
	sub, token, e := sc.a.CreateSubscription(name, sc.ids(idx...))
	if e != nil {
		t.Fatal(e)
	}
	return sub, token
}
func (sc *subScene) state(t *testing.T) State {
	t.Helper()
	s, e := sc.a.Load()
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func (sc *subScene) handler() (*subscriptionHandler, *[]string) {
	var mu sync.Mutex
	var logs []string
	cache := &stateCache{a: sc.a}
	h := newSubscriptionHandler(cache.load, func(f string, args ...any) {
		mu.Lock()
		logs = append(logs, fmt.Sprintf(f, args...))
		mu.Unlock()
	})
	return h, &logs
}
func get(h http.Handler, method, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(method, path, nil))
	return w
}
func decodeBody(t *testing.T, body string) []string {
	t.Helper()
	b, e := base64.StdEncoding.DecodeString(strings.TrimSpace(body))
	if e != nil {
		t.Fatalf("body is not standard Base64: %v", e)
	}
	return strings.Split(string(b), "\n")
}

func TestSubscriptionLifecycleAndPersistence(t *testing.T) {
	sc := newSubScene(t)
	one, _ := sc.create(t, "Phone", 0, 1)
	two, _ := sc.create(t, "Laptop", 2)
	if one.ID == two.ID || one.TokenHash == two.TokenHash {
		t.Fatal("subscriptions are not independent")
	}
	if _, _, e := sc.a.CreateSubscription("phone", sc.ids(0)); e == nil {
		t.Fatal("duplicate name (case-insensitive) accepted")
	}
	if e := sc.a.RenameSubscription(two.ID, "Phone"); e == nil {
		t.Fatal("rename onto an existing name accepted")
	}
	if e := sc.a.RenameSubscription(one.ID, "Phone 2"); e != nil {
		t.Fatal(e)
	}
	if e := sc.a.SetSubscriptionNodes(one.ID, sc.ids(1, 0, 2)); e != nil { // add + reorder
		t.Fatal(e)
	}
	if e := sc.a.SetSubscriptionNodes(one.ID, sc.ids(2, 1)); e != nil { // remove
		t.Fatal(e)
	}
	if e := sc.a.SetSubscriptionEnabled(two.ID, false); e != nil {
		t.Fatal(e)
	}
	// A fresh App on the same directory (a restart) sees the same data.
	b := &App{Home: sc.a.Home, BinDir: sc.a.BinDir, ServiceMode: "none", Language: "en"}
	s, e := b.Load()
	if e != nil {
		t.Fatal(e)
	}
	if len(s.Subscriptions) != 2 || s.Subscriptions[0].Name != "Phone 2" || !reflect.DeepEqual(s.Subscriptions[0].NodeIDs, sc.ids(2, 1)) || s.Subscriptions[1].Enabled {
		t.Fatalf("not persisted: %+v", s.Subscriptions)
	}
	if e = sc.a.DeleteSubscription(one.ID); e != nil {
		t.Fatal(e)
	}
	if s = sc.state(t); len(s.Subscriptions) != 1 || s.Subscriptions[0].ID != two.ID {
		t.Fatal("delete removed the wrong subscription")
	}
	if e = sc.a.DeleteSubscription(one.ID); e == nil {
		t.Fatal("deleting twice succeeded")
	}
	info, e := os.Stat(filepath.Join(sc.a.Home, "state.json"))
	if e != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("state permissions changed: %v %v", info, e)
	}
}

func TestSubscriptionManualSelectionOnly(t *testing.T) {
	sc := newSubScene(t)
	sub, _ := sc.create(t, "Mine", 0)
	extra := aiTestNode(t, sc.a, "ss", "delta")
	s := sc.state(t)
	if got := s.Subscriptions[0].NodeIDs; !reflect.DeepEqual(got, []string{sc.nodes[0].ID}) {
		t.Fatalf("a new node was added automatically: %v (new %s)", got, extra.ID)
	}
	if _, _, e := sc.a.CreateSubscription("Empty", nil); e == nil {
		t.Fatal("empty selection accepted")
	}
	if _, _, e := sc.a.CreateSubscription("Ghost", []string{"abcdef012345"}); e == nil {
		t.Fatal("unknown node accepted")
	}
	if _, _, e := sc.a.CreateSubscription("Dup", append(sc.ids(0), sc.nodes[0].ID)); e == nil {
		t.Fatal("duplicate node accepted")
	}
	if e := sc.a.SetSubscriptionNodes(sub.ID, nil); e == nil {
		t.Fatal("edit to an empty selection accepted")
	}
	// The same node may be in several subscriptions.
	other, _ := sc.create(t, "Other", 0, 1)
	if !contains(sc.state(t).Subscriptions[1].NodeIDs, sc.nodes[0].ID) || other.ID == sub.ID {
		t.Fatal("shared node rejected")
	}
	for _, bad := range []string{"", "0", "4", "1 1", "a", "1,x", "-1"} {
		if _, e := parseSelection(bad, 3); e == nil {
			t.Errorf("selection %q accepted", bad)
		}
	}
	idx, e := parseSelection("３, 1　2", 3)
	if e != nil || !reflect.DeepEqual(idx, []int{2, 0, 1}) {
		t.Fatalf("typed order not preserved: %v %v", idx, e)
	}
}

func TestSubscriptionCandidatesExcludeRelayWithoutLink(t *testing.T) {
	sc := newSubScene(t)
	s := sc.state(t)
	uri, _ := sc.nodes[0].URI()
	withTarget := Profile{ID: RandomHex(6), Name: "relay-ok", Kind: "relay", Enabled: true, Protocol: "tcp", Listen: "0.0.0.0", Port: 31001, PublicHost: "203.0.113.10", PublicPort: 31001, Target: net.JoinHostPort("203.0.113.10", itoa(sc.nodes[0].PublicPort)), TargetURI: uri, RelayMode: relayRemote}
	bare := Profile{ID: RandomHex(6), Name: "relay-bare", Kind: "relay", Enabled: true, Protocol: "tcp", Listen: "0.0.0.0", Port: 31002, PublicHost: "203.0.113.10", PublicPort: 31002, Target: "198.51.100.7:443", RelayMode: relayRemote}
	for _, p := range []Profile{withTarget, bare} {
		if e := p.Validate(); e != nil {
			t.Fatal(e)
		}
		s.Profiles = append(s.Profiles, p)
	}
	ok, warnings := s.SubscriptionCandidates()
	if len(ok) != 4 || len(warnings) != 1 || !strings.Contains(warnings[0], "relay-bare") {
		t.Fatalf("candidates=%d warnings=%v", len(ok), warnings)
	}
	if e := checkSubscriptionNodes(s, []string{bare.ID}); e == nil {
		t.Fatal("link-less relay accepted")
	}
	if e := checkSubscriptionNodes(s, []string{withTarget.ID}); e != nil {
		t.Fatal(e)
	}
}

func TestSubscriptionTokenSecurity(t *testing.T) {
	sc := newSubScene(t)
	sub, token := sc.create(t, "Secure", 0)
	if !tokenPattern.MatchString(token) {
		t.Fatalf("unexpected token shape %q", token)
	}
	other, _ := sc.create(t, "Second", 1)
	_, token2, _ := newSubscriptionToken()
	if token == token2 {
		t.Fatal("tokens repeat")
	}
	// The plaintext token appears in neither the state nor any backup.
	files, _ := filepath.Glob(filepath.Join(sc.a.Home, "*.json"))
	backups, _ := filepath.Glob(filepath.Join(sc.a.Home, "backups", "*.json"))
	for _, f := range append(files, backups...) {
		if b, _ := os.ReadFile(f); bytes.Contains(b, []byte(token)) {
			t.Fatalf("plaintext token stored in %s", f)
		}
	}
	s := sc.state(t)
	if got, ok := s.matchSubscription(token); !ok || got.ID != sub.ID {
		t.Fatal("valid token rejected")
	}
	for _, bad := range []string{"", token[:42], token + "A", strings.ToUpper(token), strings.Repeat("A", 43)} {
		if _, ok := s.matchSubscription(bad); ok && bad != token {
			t.Errorf("token %q accepted", bad)
		}
	}
	// Edits keep the token; rotation replaces it and revokes the old one at once.
	if e := sc.a.RenameSubscription(sub.ID, "Secure 2"); e != nil {
		t.Fatal(e)
	}
	if _, ok := sc.state(t).matchSubscription(token); !ok {
		t.Fatal("an ordinary edit changed the token")
	}
	fresh, e := sc.a.RotateSubscriptionToken(sub.ID)
	if e != nil || fresh == token {
		t.Fatal("rotation failed", e)
	}
	s = sc.state(t)
	if _, ok := s.matchSubscription(token); ok {
		t.Fatal("old token still valid after rotation")
	}
	if got, ok := s.matchSubscription(fresh); !ok || got.ID != sub.ID {
		t.Fatal("new token rejected")
	}
	if got, ok := s.matchSubscription(fresh); ok && got.ID == other.ID {
		t.Fatal("tokens collide")
	}
	if _, e = sc.a.RotateSubscriptionToken("000000000000"); e == nil {
		t.Fatal("rotating a missing subscription succeeded")
	}
}

func TestSubscriptionBase64OutputAndOrder(t *testing.T) {
	sc := newSubScene(t)
	_, token := sc.create(t, "Order", 2, 0, 1)
	h, _ := sc.handler()
	w := get(h, "GET", "/s/"+token)
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Fatal(ct)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatal(cc)
	}
	lines := decodeBody(t, w.Body.String())
	for i, idx := range []int{2, 0, 1} {
		want, _ := sc.nodes[idx].URI()
		if lines[i] != want {
			t.Fatalf("line %d: %q != %q", i, lines[i], want)
		}
	}
	if len(lines) != 3 || strings.HasSuffix(w.Body.String(), "=\n\n") {
		t.Fatal("unexpected line count")
	}
	for _, p := range []string{"vless://", "anytls://", "ss://"} {
		if !strings.Contains(strings.Join(lines, "\n"), p) {
			t.Errorf("missing %s link", p)
		}
	}
}

func TestSubscriptionIPv6AndHysteria(t *testing.T) {
	a := testApp(t)
	var ids []string
	for _, tc := range []struct{ proto, host string }{{"ss", "2001:db8::7"}, {"hy2", "2001:db8::8"}, {"tuic", "vpn.example.com"}, {"vless", "198.51.100.9"}} {
		p := linkFixture(t, tc.proto, tc.host)
		p.Name = tc.proto + " " + tc.host
		p.Listen = "127.0.0.1"
		p.Port, _ = freePort()
		p.PublicPort = p.Port
		s, _ := a.Load()
		if e := a.Commit(s, replace(s, p), false); e != nil {
			t.Fatal(e)
		}
		ids = append(ids, p.ID)
	}
	_, token, e := a.CreateSubscription("Mixed", ids)
	if e != nil {
		t.Fatal(e)
	}
	cache := &stateCache{a: a}
	w := get(newSubscriptionHandler(cache.load, func(string, ...any) {}), "GET", "/s/"+token)
	lines := decodeBody(t, w.Body.String())
	s, _ := a.Load()
	for i, id := range ids {
		p, _ := Find(s, id)
		want, _ := p.URI()
		if lines[i] != want {
			t.Fatalf("%s: %q != %q", p.Name, lines[i], want)
		}
	}
	if !strings.Contains(lines[0], "@[2001:db8::7]:") || !strings.Contains(lines[1], "[2001:db8::8]") || !strings.Contains(lines[1], "pinSHA256=") {
		t.Fatalf("IPv6 or protocol parameters lost: %v", lines[:2])
	}
}

func TestSubscriptionReflectsNodeChanges(t *testing.T) {
	sc := newSubScene(t)
	_, token := sc.create(t, "Live", 0, 1, 2)
	h, logs := sc.handler()
	links := func() []string { return decodeBody(t, get(h, "GET", "/s/"+token).Body.String()) }
	if len(links()) != 3 {
		t.Fatal("expected 3 links")
	}
	// Rename + move: the next request carries the new data, no restart needed.
	s := sc.state(t)
	p := sc.nodes[1]
	p.Name, p.PublicHost = "bravo renamed", "198.51.100.77"
	if e := sc.a.Commit(s, replace(s, p), false); e != nil {
		t.Fatal(e)
	}
	want, _ := p.URI()
	if got := links(); got[1] != want || !strings.Contains(got[1], "198.51.100.77") || !strings.Contains(got[1], "bravo%20renamed") {
		t.Fatalf("stale link: %q", got[1])
	}
	// Disabled nodes disappear and return when re-enabled.
	s = sc.state(t)
	off := sc.nodes[0]
	off.Enabled = false
	if e := sc.a.Commit(s, replace(s, off), false); e != nil {
		t.Fatal(e)
	}
	if got := links(); len(got) != 2 || strings.Contains(strings.Join(got, "\n"), "alpha") {
		t.Fatalf("disabled node still exported: %v", got)
	}
	if !strings.Contains(strings.Join(*logs, "\n"), "alpha") {
		t.Fatalf("no diagnostic for disabled node: %v", *logs)
	}
	s = sc.state(t)
	if e := sc.a.Commit(s, replace(s, sc.nodes[0]), false); e != nil {
		t.Fatal(e)
	}
	if len(links()) != 3 {
		t.Fatal("re-enabled node missing")
	}
	// Deleting a node prunes it from the subscription: no stale link, order kept.
	s = sc.state(t)
	if e := sc.a.Commit(s, removeProfile(s, sc.nodes[1].ID), false); e != nil {
		t.Fatal(e)
	}
	if ids := sc.state(t).Subscriptions[0].NodeIDs; !reflect.DeepEqual(ids, sc.ids(0, 2)) {
		t.Fatalf("deleted node not pruned: %v", ids)
	}
	if got := links(); len(got) != 2 {
		t.Fatalf("got %d links", len(got))
	}
}

func TestSubscriptionNoValidNodesIsExplicitFailure(t *testing.T) {
	sc := newSubScene(t)
	_, token := sc.create(t, "Fragile", 0)
	h, _ := sc.handler()
	s := sc.state(t)
	off := sc.nodes[0]
	off.Enabled = false
	if e := sc.a.Commit(s, replace(s, off), false); e != nil {
		t.Fatal(e)
	}
	w := get(h, "GET", "/s/"+token)
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") == "" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("empty subscription answered %d", w.Code)
	}
	if strings.TrimSpace(w.Body.String()) == "" || w.Body.Len() > 64 {
		t.Fatal("unexpected body")
	}
	// A stored ghost ID (hand-edited state) is skipped, never exported.
	st := sc.state(t)
	sub := st.Subscriptions[0]
	sub.NodeIDs = []string{"0123456789ab"}
	if exp := st.exportSubscription(sub); len(exp.URIs) != 0 || len(exp.Warnings) != 1 {
		t.Fatalf("%+v", exp)
	}
}

func TestSubscriptionHTTPAuthAndMethods(t *testing.T) {
	sc := newSubScene(t)
	sub, token := sc.create(t, "Web", 0, 1)
	h, logs := sc.handler()
	uri0, _ := sc.nodes[0].URI()
	notFoundBody := get(h, "GET", "/s/"+strings.Repeat("A", 43)).Body.String()
	for _, path := range []string{"/", "/s", "/s/", "/s/" + token + "/", "/s/" + token + "/x", "/s/short", "/s/" + token + "A", "/s/../etc/passwd", "/s/%00", "/admin", "/state.json", "//s/" + token, "/S/" + token, "/s/" + strings.Repeat("A", 43)} {
		w := get(h, "GET", path)
		if w.Code != 404 {
			t.Errorf("%s -> %d", path, w.Code)
		}
		if w.Body.String() != notFoundBody || strings.Contains(w.Body.String(), "alpha") {
			t.Errorf("%s leaks or differs: %q", path, w.Body.String())
		}
	}
	for _, m := range []string{"POST", "PUT", "DELETE", "PATCH", "OPTIONS"} {
		if w := get(h, m, "/s/"+token); w.Code != 405 || w.Header().Get("Allow") != "GET, HEAD" || w.Body.String() == "" {
			t.Errorf("%s -> %d", m, w.Code)
		}
	}
	if w := get(h, "HEAD", "/s/"+token); w.Code != 200 || w.Body.Len() != 0 {
		t.Errorf("HEAD -> %d (%d bytes)", w.Code, w.Body.Len())
	}
	if w := get(h, "GET", "/s/"+token+"?x=1"); w.Code != 200 {
		t.Errorf("query string -> %d", w.Code)
	}
	// Disabled -> 404 identical to unknown; re-enabled works again.
	if e := sc.a.SetSubscriptionEnabled(sub.ID, false); e != nil {
		t.Fatal(e)
	}
	if w := get(h, "GET", "/s/"+token); w.Code != 404 || w.Body.String() != notFoundBody {
		t.Fatalf("disabled subscription -> %d", w.Code)
	}
	if e := sc.a.SetSubscriptionEnabled(sub.ID, true); e != nil {
		t.Fatal(e)
	}
	if w := get(h, "GET", "/s/"+token); w.Code != 200 {
		t.Fatal("re-enabled subscription unreachable")
	}
	// Rotation revokes immediately, even though the handler cached the old state.
	fresh, _ := sc.a.RotateSubscriptionToken(sub.ID)
	if w := get(h, "GET", "/s/"+token); w.Code != 404 {
		t.Fatalf("revoked token -> %d", w.Code)
	}
	if w := get(h, "GET", "/s/"+fresh); w.Code != 200 {
		t.Fatal("rotated token rejected")
	}
	// Deleted -> 404.
	if e := sc.a.DeleteSubscription(sub.ID); e != nil {
		t.Fatal(e)
	}
	if w := get(h, "GET", "/s/"+fresh); w.Code != 404 {
		t.Fatal("deleted subscription still served")
	}
	// Nothing sensitive reached the logs.
	for _, l := range *logs {
		for _, secret := range []string{token, fresh, uri0, sc.nodes[0].UUID, sc.nodes[1].Password} {
			if strings.Contains(l, secret) {
				t.Fatalf("log leaks a secret: %q", l)
			}
		}
	}
}

func TestSubscriptionServerStateErrorDoesNotLeak(t *testing.T) {
	sc := newSubScene(t)
	_, token := sc.create(t, "Broken", 0)
	h, logs := sc.handler()
	if e := os.WriteFile(filepath.Join(sc.a.Home, "state.json"), []byte("{not json, password=hunter2"), 0600); e != nil {
		t.Fatal(e)
	}
	w := get(h, "GET", "/s/"+token)
	if w.Code != 503 || strings.Contains(w.Body.String(), "hunter2") || strings.Contains(w.Body.String(), "json") {
		t.Fatalf("%d %q", w.Code, w.Body.String())
	}
	for _, l := range *logs {
		if strings.Contains(l, token) || strings.Contains(l, "hunter2") {
			t.Fatalf("log leaks: %q", l)
		}
	}
	// Recovery needs no restart.
	if e := AtomicWrite(filepath.Join(sc.a.Home, "state.json"), []byte(`{"schema":1,"profiles":[]}`), 0600); e != nil {
		t.Fatal(e)
	}
	if w = get(h, "GET", "/s/"+token); w.Code != 404 {
		t.Fatalf("after repair: %d", w.Code)
	}
}

func TestSubscriptionServerIsReadOnlyAndConcurrent(t *testing.T) {
	sc := newSubScene(t)
	sub, token := sc.create(t, "Busy", 0, 1, 2)
	before, _ := os.ReadFile(filepath.Join(sc.a.Home, "state.json"))
	entries := func() string {
		var names []string
		filepath.Walk(sc.a.Home, func(p string, _ os.FileInfo, _ error) error { names = append(names, p); return nil })
		return strings.Join(names, "\n")
	}
	tree := entries()
	h, _ := sc.handler()
	var wg sync.WaitGroup
	errs := make(chan string, 400)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				w := get(h, "GET", "/s/"+token)
				if w.Code != 200 {
					errs <- fmt.Sprintf("status %d", w.Code)
					return
				}
				if n := len(decodeBody(t, w.Body.String())); n != 3 {
					errs <- fmt.Sprintf("%d links", n)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
	if after, _ := os.ReadFile(filepath.Join(sc.a.Home, "state.json")); !bytes.Equal(before, after) || entries() != tree {
		t.Fatal("read-only requests modified the configuration directory")
	}
	// Concurrent CLI-style writes while readers run: every response is a complete,
	// valid snapshot and no write is lost.
	stop := make(chan struct{})
	var readers sync.WaitGroup
	bad := make(chan string, 10)
	for i := 0; i < 4; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if w := get(h, "GET", "/s/"+token); w.Code != 200 && w.Code != 404 {
					bad <- fmt.Sprintf("status %d", w.Code)
					return
				}
			}
		}()
	}
	for i := 0; i < 12; i++ {
		if e := sc.a.RenameSubscription(sub.ID, fmt.Sprintf("Busy %d", i)); e != nil {
			t.Fatal(e)
		}
		if e := sc.a.SetSubscriptionEnabled(sub.ID, i%2 == 0); e != nil {
			t.Fatal(e)
		}
	}
	close(stop)
	readers.Wait()
	close(bad)
	for e := range bad {
		t.Fatal(e)
	}
	if got := sc.state(t).Subscriptions[0]; got.Name != "Busy 11" || got.Enabled {
		t.Fatalf("lost update: %+v", got)
	}
}

func TestSubscriptionConcurrentWritersDoNotLoseUpdates(t *testing.T) {
	sc := newSubScene(t)
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, _, e := sc.a.CreateSubscription(fmt.Sprintf("S%d", i), sc.ids(i%3)); e != nil {
				t.Error(e)
			}
		}(i)
	}
	wg.Wait()
	if n := len(sc.state(t).Subscriptions); n != 6 {
		t.Fatalf("%d subscriptions, want 6", n)
	}
}

func TestSubscriptionRealServerLifecycle(t *testing.T) {
	sc := newSubScene(t)
	_, token := sc.create(t, "Live", 0)
	ctx, cancel := context.WithCancel(context.Background())
	addrCh := make(chan net.Addr, 1)
	done := make(chan error, 1)
	go func() {
		done <- sc.a.serveSubscriptions(ctx, "127.0.0.1:0", func(string, ...any) {}, func(a net.Addr) { addrCh <- a })
	}()
	var addr net.Addr
	select {
	case addr = <-addrCh:
	case e := <-done:
		t.Fatal(e)
	case <-time.After(5 * time.Second):
		t.Fatal("server did not start")
	}
	base := "http://" + addr.String()
	resp, e := http.Get(base + "/s/" + token)
	if e != nil {
		t.Fatal(e)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || len(decodeBody(t, string(body))) != 1 || resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("%d %q", resp.StatusCode, body)
	}
	if resp, e = http.Post(base+"/s/"+token, "text/plain", strings.NewReader("x")); e != nil || resp.StatusCode != 405 {
		t.Fatalf("POST: %v %v", resp, e)
	}
	resp.Body.Close()
	// The port is held, so a second server reports a clear bind error.
	if e = sc.a.serveSubscriptions(context.Background(), addr.String(), func(string, ...any) {}, nil); e == nil || !strings.Contains(e.Error(), "cannot listen") && !strings.Contains(e.Error(), "无法监听") {
		t.Fatalf("bind error: %v", e)
	}
	cancel()
	select {
	case e = <-done:
		if e != nil {
			t.Fatalf("shutdown: %v", e)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("no graceful shutdown")
	}
	if _, e = net.DialTimeout("tcp", addr.String(), time.Second); e == nil {
		t.Fatal("still listening after shutdown")
	}
}

func TestSubscriptionServerRefusesPublicBind(t *testing.T) {
	sc := newSubScene(t)
	for _, addr := range []string{"0.0.0.0:0", ":0", "[::]:0", "203.0.113.5:8787", "localhost:8787", "example.com:80"} {
		if e := sc.a.serveSubscriptions(context.Background(), addr, func(string, ...any) {}, nil); e == nil {
			t.Errorf("%s accepted", addr)
		}
	}
	if e := sc.a.ServeSubscriptions(context.Background()); e == nil {
		t.Fatal("server started although it is disabled by default")
	}
}

func TestSubscriptionServerSettings(t *testing.T) {
	sc := newSubScene(t)
	st, e := sc.a.SubscriptionServerStatus()
	if e != nil || st.Settings.Enabled || st.Settings.listenPort() != 8787 {
		t.Fatalf("not disabled by default: %+v %v", st, e)
	}
	if e = sc.a.SaveSettings(Settings{Language: "en"}); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{"http://sub.example.com", "ftp://x", "sub.example.com", "https://", "https://u:p@sub.example.com", "https://sub.example.com/?t=1", "https://sub.example.com/#x", "https://bad host"} {
		if e = sc.a.SetSubscriptionPublicURL(bad); e == nil {
			t.Errorf("public URL %q accepted", bad)
		}
	}
	if e = sc.a.SetSubscriptionPublicURL("https://sub.example.com/prefix/"); e != nil {
		t.Fatal(e)
	}
	for _, port := range []int{0, 80, 1023, 65536} {
		if e = sc.a.EnableSubscriptionServer(port); e == nil {
			t.Errorf("port %d accepted", port)
		}
	}
	busy := sc.nodes[0].Port
	if e = sc.a.EnableSubscriptionServer(busy); e == nil {
		t.Fatal("a node's port was accepted")
	}
	port, _ := freePort()
	if e = sc.a.EnableSubscriptionServer(port); e != nil {
		t.Fatal(e)
	}
	// Settings survive a restart, keep the language and the public URL, and build the URL.
	b := &App{Home: sc.a.Home, BinDir: sc.a.BinDir, ServiceMode: "none", Language: "en"}
	st, _ = b.SubscriptionServerStatus()
	if !st.Settings.Enabled || st.Settings.Port != port || st.Settings.PublicURL != "https://sub.example.com/prefix" {
		t.Fatalf("%+v", st)
	}
	if got := st.Settings.SubscriptionURL("TOKEN"); got != "https://sub.example.com/prefix/s/TOKEN" {
		t.Fatal(got)
	}
	if all, _ := b.LoadSettings(); all.Language != "en" {
		t.Fatal("language lost")
	}
	if e = b.DisableSubscriptionServer(); e != nil {
		t.Fatal(e)
	}
	if st, _ = b.SubscriptionServerStatus(); st.Settings.Enabled || st.Settings.PublicURL == "" {
		t.Fatalf("%+v", st)
	}
	if len(sc.state(t).Subscriptions) != 0 {
		t.Fatal("unexpected subscriptions")
	}
}

func TestSubscriptionServiceDefinitions(t *testing.T) {
	a := &App{Home: "/etc/rout", BinDir: "/opt/rout/bin", ServiceMode: "auto"}
	unit := a.subscriptionUnit()
	for _, want := range []string{"ExecStart='/opt/rout/bin/rout-subscription-v1' '--home' '/etc/rout' '--bin-dir' '/opt/rout/bin' 'subscription' 'serve'", "ProtectSystem=strict", "CapabilityBoundingSet=\n", "NoNewPrivileges=true", "RestrictAddressFamilies=AF_INET AF_INET6", "WantedBy=multi-user.target", "Restart=on-failure"} {
		if !strings.Contains(strings.ReplaceAll(unit, `"`, `'`), want) {
			t.Errorf("unit lacks %q:\n%s", want, unit)
		}
	}
	rc := a.subscriptionOpenRC()
	for _, want := range []string{"#!/sbin/openrc-run", "supervisor=supervise-daemon", "rout-subscription-v1", "subscription", "serve", "chmod 600"} {
		if !strings.Contains(rc, want) {
			t.Errorf("openrc script lacks %q", want)
		}
	}
	if a.subscriptionService() != "rout-subscription" || (&App{Home: "/tmp/x"}).subscriptionService() == "rout-subscription" {
		t.Fatal("service naming")
	}
	if strings.Contains(unit, "rout-traffic") || strings.Contains(unit, "sing-box") {
		t.Fatal("unit touches other services")
	}
}

// State written by v0.3.3 (no subscriptions) loads, keeps working, and gains subscriptions
// without disturbing nodes, AI routing, outbounds or traffic policy.
func TestSubscriptionCompatibilityWithPreviousState(t *testing.T) {
	sc := newAIScene(t)
	a := sc.a
	base, e := a.Load()
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := os.ReadFile(filepath.Join(a.Home, "state.json"))
	if bytes.Contains(raw, []byte("subscriptions")) {
		t.Fatal("empty state should omit the optional field")
	}
	// A state with exits and AI routing configured, as an older version wrote it.
	node := aiTestNode(t, a, "vless", "legacy")
	ex := aiTestExit(t, a, "exit", "198.51.100.1", 1080)
	if e = a.SetAIExit(ex.ID); e != nil {
		t.Fatal(e)
	}
	if e = a.SetAIBindings([]string{node.ID}); e != nil {
		t.Fatal(e)
	}
	before, _ := a.Load()
	cfgBefore, _ := os.ReadFile(filepath.Join(a.profileDir(node.ID), "config.json"))
	if _, _, e = a.CreateSubscription("Compat", []string{node.ID}); e != nil {
		t.Fatal(e)
	}
	after, _ := a.Load()
	if !reflect.DeepEqual(before.Profiles, after.Profiles) || !reflect.DeepEqual(before.Exits, after.Exits) || !reflect.DeepEqual(before.AI, after.AI) || before.Schema != after.Schema {
		t.Fatal("subscription change altered nodes, outbounds, AI routing or schema")
	}
	if cfgAfter, _ := os.ReadFile(filepath.Join(a.profileDir(node.ID), "config.json")); !bytes.Equal(cfgBefore, cfgAfter) {
		t.Fatal("node configuration rewritten")
	}
	// Node operations keep the subscription; AI routing still works with it present.
	if e = a.SetAIEnabled(true); e != nil {
		t.Fatal(e)
	}
	if e = a.ApplyAI(); e != nil {
		t.Fatal(e)
	}
	if s, _ := a.Load(); len(s.Subscriptions) != 1 || s.AI == nil || !s.AI.Enabled {
		t.Fatal("AI apply lost the subscription or settings")
	}
	// Old Rout files: no "subscriptions" key at all.
	legacy := []byte(`{"schema":1,"profiles":[]}`)
	s, e := DecodeState(legacy)
	if e != nil || len(s.Subscriptions) != 0 || len(base.Subscriptions) != 0 {
		t.Fatal("pre-v0.3.4 state rejected", e)
	}
	// Malformed subscription data is refused at load rather than crashing the server.
	for _, bad := range []string{
		`{"schema":1,"profiles":[],"subscriptions":[{"id":"x","name":"n","node_ids":[],"token_hash":"` + strings.Repeat("a", 64) + `","enabled":true}]}`,
		`{"schema":1,"profiles":[],"subscriptions":[{"id":"abcdef012345","name":"","node_ids":[],"token_hash":"` + strings.Repeat("a", 64) + `","enabled":true}]}`,
		`{"schema":1,"profiles":[],"subscriptions":[{"id":"abcdef012345","name":"n","node_ids":["../x"],"token_hash":"` + strings.Repeat("a", 64) + `","enabled":true}]}`,
		`{"schema":1,"profiles":[],"subscriptions":[{"id":"abcdef012345","name":"n","node_ids":[],"token_hash":"plain-token","enabled":true}]}`,
		`{"schema":1,"profiles":[],"subscriptions":[{"id":"abcdef012345","name":"n","node_ids":[],"token_hash":"` + strings.Repeat("a", 64) + `","enabled":true},{"id":"abcdef012345","name":"m","node_ids":[],"token_hash":"` + strings.Repeat("b", 64) + `","enabled":true}]}`,
	} {
		if _, e := DecodeState([]byte(bad)); e == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestSubscriptionMenuCreateEditRotateDelete(t *testing.T) {
	sc := newSubScene(t)
	// Create: name, nodes in typed order, default-yes confirmation.
	u, out := testUI(sc.a, "2\nMy Phone\n3 1\n\n0\n")
	if e := u.subscriptions(); e != nil {
		t.Fatal(e)
	}
	text := out.String()
	s := sc.state(t)
	if len(s.Subscriptions) != 1 || !reflect.DeepEqual(s.Subscriptions[0].NodeIDs, sc.ids(2, 0)) {
		t.Fatalf("menu did not create the chosen subscription: %+v\n%s", s.Subscriptions, text)
	}
	tokenLine := ""
	for _, l := range strings.Split(text, "\n") {
		if strings.Contains(l, "Access token") {
			tokenLine = l
		}
	}
	token := strings.Fields(tokenLine)[len(strings.Fields(tokenLine))-1]
	if _, ok := s.matchSubscription(token); !ok {
		t.Fatalf("displayed token invalid: %q", tokenLine)
	}
	if !strings.Contains(text, "https://YOUR-DOMAIN/s/"+token) || !strings.Contains(text, "No public HTTPS address") || !strings.Contains(text, "not enabled yet") {
		t.Fatalf("missing HTTPS/enable guidance:\n%s", text)
	}
	if strings.Contains(text, "Selected") && strings.Contains(text, "://") {
		t.Fatal("create review shows links")
	}
	// Public URL configured: the full HTTPS URL is shown.
	if e := sc.a.SaveSettings(Settings{Language: "en"}); e != nil {
		t.Fatal(e)
	}
	if e := sc.a.SetSubscriptionPublicURL("https://sub.example.com"); e != nil {
		t.Fatal(e)
	}
	// List shows names, never credentials, links or tokens.
	u, out = testUI(sc.a, "1\n0\n")
	if e := u.subscriptions(); e != nil {
		t.Fatal(e)
	}
	for _, secret := range []string{token, sc.nodes[0].UUID, sc.nodes[0].PublicKey, sc.nodes[2].Password} {
		if strings.Contains(out.String(), secret) {
			t.Fatalf("list view exposes %q", secret)
		}
	}
	if !strings.Contains(out.String(), "https://sub.example.com/s/{access_token}") {
		t.Fatal("missing safe URL template")
	}
	if !strings.Contains(out.String(), "My Phone") || !strings.Contains(out.String(), "charlie") || !strings.Contains(out.String(), "2/2 nodes available") {
		t.Fatalf("list view:\n%s", out.String())
	}
	// Edit: rename (3), add node 2 (2→ first remaining item), reorder, toggle.
	u, _ = testUI(sc.a, "3\n1\n1\nRenamed\n0\n0\n0\n")
	if e := u.subscriptions(); e != nil {
		t.Fatal(e)
	}
	if got := sc.state(t).Subscriptions[0]; got.Name != "Renamed" || got.TokenHash != s.Subscriptions[0].TokenHash {
		t.Fatalf("rename failed or token changed: %+v", got)
	}
	u, _ = testUI(sc.a, "3\n1\n2\n1\n0\n0\n0\n") // add: only "bravo" is left to pick
	if e := u.subscriptions(); e != nil {
		t.Fatal(e)
	}
	if ids := sc.state(t).Subscriptions[0].NodeIDs; !reflect.DeepEqual(ids, sc.ids(2, 0, 1)) {
		t.Fatalf("add failed: %v", ids)
	}
	u, _ = testUI(sc.a, "3\n1\n4\n3 1 2\n0\n0\n0\n") // reorder
	if e := u.subscriptions(); e != nil {
		t.Fatal(e)
	}
	if ids := sc.state(t).Subscriptions[0].NodeIDs; !reflect.DeepEqual(ids, sc.ids(1, 2, 0)) {
		t.Fatalf("reorder failed: %v", ids)
	}
	u, _ = testUI(sc.a, "3\n1\n3\n1\n0\n0\n0\n") // remove first listed
	if e := u.subscriptions(); e != nil {
		t.Fatal(e)
	}
	if ids := sc.state(t).Subscriptions[0].NodeIDs; !reflect.DeepEqual(ids, sc.ids(2, 0)) {
		t.Fatalf("remove failed: %v", ids)
	}
	u, _ = testUI(sc.a, "3\n1\n5\n0\n0\n0\n") // toggle
	if e := u.subscriptions(); e != nil {
		t.Fatal(e)
	}
	if sc.state(t).Subscriptions[0].Enabled {
		t.Fatal("toggle failed")
	}
	// Rotate: declining keeps the token; confirming prints a new URL with the public host.
	old := sc.state(t).Subscriptions[0].TokenHash
	u, _ = testUI(sc.a, "5\n1\nn\n0\n")
	_ = u.subscriptions()
	if sc.state(t).Subscriptions[0].TokenHash != old {
		t.Fatal("declined rotation changed the token")
	}
	u, out = testUI(sc.a, "5\n1\nY\n0\n")
	if e := u.subscriptions(); e != nil {
		t.Fatal(e)
	}
	if sc.state(t).Subscriptions[0].TokenHash == old || !strings.Contains(out.String(), "https://sub.example.com/s/") || !strings.Contains(out.String(), "needs the new link") {
		t.Fatalf("rotation output:\n%s", out.String())
	}
	// Delete: default answer cancels; "YES" (any case) confirms.
	u, _ = testUI(sc.a, "4\n1\n\n0\n")
	_ = u.subscriptions()
	if len(sc.state(t).Subscriptions) != 1 {
		t.Fatal("default answer deleted the subscription")
	}
	u, _ = testUI(sc.a, "4\n1\nYES\n0\n")
	if e := u.subscriptions(); e != nil {
		t.Fatal(e)
	}
	if len(sc.state(t).Subscriptions) != 0 {
		t.Fatal("confirmed delete did nothing")
	}
}

func TestSubscriptionMenuRejectsEmptyAndDuplicateInput(t *testing.T) {
	sc := newSubScene(t)
	sc.create(t, "Taken", 0)
	u, out := testUI(sc.a, "2\nTaken\n0\n")
	if e := u.subscriptions(); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(out.String(), "already exists") {
		t.Fatalf("duplicate not reported:\n%s", out.String())
	}
	u, _ = testUI(sc.a, "2\nFresh\n\n0\n") // empty selection cancels
	if e := u.subscriptions(); e != nil {
		t.Fatal(e)
	}
	u, _ = testUI(sc.a, "2\nFresh\n9\n1 1\n2\nn\n0\n") // invalid input is retried; "n" declines
	if e := u.subscriptions(); e != nil {
		t.Fatal(e)
	}
	if n := len(sc.state(t).Subscriptions); n != 1 {
		t.Fatalf("%d subscriptions after cancelled flows", n)
	}
	// No nodes at all: a helpful error, no subscription.
	empty := testApp(t)
	u, out = testUI(empty, "2\n0\n")
	if e := u.subscriptions(); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(out.String(), "create a node first") {
		t.Fatalf("missing guidance:\n%s", out.String())
	}
}

func TestSubscriptionChineseMenu(t *testing.T) {
	a := testApp(t)
	a.Language = "zh-CN"
	u, out := testUI(a, "0\n")
	if e := u.subscriptions(); e != nil {
		t.Fatal(e)
	}
	for _, want := range []string{"订阅管理", "创建订阅", "更换访问令牌", "订阅服务设置"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("Chinese menu lacks %q", want)
		}
	}
	a.Language = "en"
	u, out = testUI(a, "0\n")
	_ = u.subscriptions()
	if hasHan(out.String()) {
		t.Fatalf("untranslated text in English menu:\n%s", out.String())
	}
}

func TestSubscriptionCommandsAndHelp(t *testing.T) {
	a := testApp(t)
	u, out := testUI(a, "")
	if e := u.subscriptionCommand([]string{"subscription", "list"}); e != nil || !strings.Contains(out.String(), "No subscriptions") {
		t.Fatalf("%v %q", e, out.String())
	}
	if e := u.subscriptionCommand([]string{"subscription", "bogus"}); e == nil {
		t.Fatal("unknown subcommand accepted")
	}
	if e := u.subscriptionCommand([]string{"subscription", "serve"}); e == nil {
		t.Fatal("serve ran while disabled")
	}
	u, out = testUI(a, "")
	a.help()
	_ = out
	found := false
	for _, l := range helpLines {
		found = found || strings.HasPrefix(l[0], "rout subscription")
	}
	if !found {
		t.Fatal("help lacks the subscription command")
	}
	if Version != "0.3.5" {
		t.Fatalf("version %s", Version)
	}
}
