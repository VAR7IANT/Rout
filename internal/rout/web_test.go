package rout

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	webTestPassword = "correct horse battery staple"
	webTestHost     = "127.0.0.1:8790"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type webEnv struct {
	t     *testing.T
	a     *App
	ws    *WebServer
	clock *fakeClock
}

func newWebEnv(t *testing.T) *webEnv { t.Helper(); return newWebEnvFor(t, testApp(t)) }

// newWebEnvFor serves an existing App (for instance one that already has nodes and sources).
func newWebEnvFor(t *testing.T, a *App) *webEnv {
	t.Helper()
	old := webPBKDF2Iterations
	webPBKDF2Iterations = 1000
	t.Cleanup(func() { webPBKDF2Iterations = old })
	clock := &fakeClock{t: time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)}
	a.webHooks = &webTestHooks{
		now: clock.now,
		ui: func(u *UI) {
			u.detectAddrs = func() Addresses { return Addresses{IPv4: v4Addr, IPv6: v6Addr} }
			u.caps = func() listenCaps { return listenCaps{V4: true, V6: true, DualStack: true} }
			u.routes = func() familyRoutes { return familyRoutes{V4: true, V6: true} }
			u.detectIP = func() string { return v4Addr }
			u.checkReality = func(string) error { return nil }
		},
	}
	env := diagEnvFor(map[string][]string{}, nil)
	a.webHooks.diag = &env
	if e := a.SetWebPassword(webTestPassword); e != nil {
		t.Fatal(e)
	}
	ws := NewWebServer(a, t.Logf)
	ws.now = clock.now
	ws.sessions = newSessionStore(clock.now)
	ws.limiter = newLoginLimiter(clock.now)
	ws.detectIPs = func() (string, string) { return v4Addr, v6Addr }
	ws.lookupHost = func(context.Context, string) ([]string, error) { return []string{"192.0.2.1"}, nil }
	ws.fetchLatest = func(context.Context) (string, error) { return "v9.9.9", nil }
	return &webEnv{t: t, a: a, ws: ws, clock: clock}
}

type webClient struct {
	env    *webEnv
	cookie *http.Cookie
	csrf   string
}

type reqOpt func(*http.Request)

func withHeader(k, v string) reqOpt { return func(r *http.Request) { r.Header.Set(k, v) } }
func withoutHeader(k string) reqOpt { return func(r *http.Request) { r.Header.Del(k) } }
func withHost(h string) reqOpt {
	return func(r *http.Request) { r.Host = h }
}
func withPeer(addr string) reqOpt { return func(r *http.Request) { r.RemoteAddr = addr } }

// do sends a request as the browser would: same origin, JSON, with the session cookie and
// CSRF header when the client has them.
func (c *webClient) do(method, path string, body any, opts ...reqOpt) *httptest.ResponseRecorder {
	c.env.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case []byte:
		rd = bytes.NewReader(b)
	case string:
		rd = strings.NewReader(b)
	default:
		raw, e := json.Marshal(b)
		if e != nil {
			c.env.t.Fatal(e)
		}
		rd = bytes.NewReader(raw)
	}
	r := httptest.NewRequest(method, "http://"+webTestHost+path, rd)
	r.RemoteAddr = "127.0.0.1:50000"
	if method != http.MethodGet && method != http.MethodHead {
		r.Header.Set("Origin", "http://"+webTestHost)
		if rd != nil {
			r.Header.Set("Content-Type", "application/json")
		}
	}
	if c.cookie != nil {
		r.AddCookie(c.cookie)
	}
	if c.csrf != "" {
		r.Header.Set("X-CSRF-Token", c.csrf)
	}
	for _, o := range opts {
		o(r)
	}
	w := httptest.NewRecorder()
	c.env.ws.ServeHTTP(w, r)
	return w
}

func (c *webClient) get(path string) *httptest.ResponseRecorder {
	c.env.t.Helper()
	return c.do("GET", path, nil)
}

func jsonOf(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if e := json.Unmarshal(w.Body.Bytes(), &m); e != nil {
		t.Fatalf("not JSON (%d): %s", w.Code, w.Body.String())
	}
	return m
}

func errCode(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	m := jsonOf(t, w)
	e, _ := m["error"].(map[string]any)
	code, _ := e["code"].(string)
	return code
}

func (e *webEnv) anon() *webClient { return &webClient{env: e} }

func (e *webEnv) login() *webClient {
	e.t.Helper()
	c := e.anon()
	w := c.do("POST", "/api/login", map[string]string{"password": webTestPassword})
	if w.Code != 200 {
		e.t.Fatalf("login failed: %d %s", w.Code, w.Body.String())
	}
	for _, ck := range w.Result().Cookies() {
		if ck.Name == webCookie {
			c.cookie = ck
		}
	}
	c.csrf, _ = jsonOf(e.t, w)["csrf"].(string)
	if c.cookie == nil || c.csrf == "" {
		e.t.Fatal("login returned no session")
	}
	return c
}

func (c *webClient) reauth() {
	c.env.t.Helper()
	if w := c.do("POST", "/api/reauth", map[string]string{"password": webTestPassword}); w.Code != 200 {
		c.env.t.Fatalf("reauth: %d %s", w.Code, w.Body.String())
	}
}

// ---- authentication ----

func TestWebAuthenticationFlow(t *testing.T) {
	e := newWebEnv(t)
	anon := e.anon()
	if w := anon.get("/api/health"); w.Code != 200 {
		t.Fatal("health must be public")
	}
	for _, p := range []string{"/api/nodes", "/api/overview", "/api/subscriptions", "/api/sources", "/api/system", "/api/sessions", "/api/exits", "/api/relays"} {
		if w := anon.get(p); w.Code != 401 || errCode(t, w) != "unauthenticated" {
			t.Fatalf("%s without a session: %d %s", p, w.Code, w.Body.String())
		}
	}
	st := jsonOf(t, anon.get("/api/state"))
	if st["configured"] != true || st["authenticated"] != false || st["csrf"] != nil || st["version"] != nil {
		t.Fatalf("anonymous state leaks: %v", st)
	}
	if w := anon.do("POST", "/api/login", map[string]string{"password": "wrong password here"}); w.Code != 401 || errCode(t, w) != "invalid_credentials" {
		t.Fatalf("wrong password: %d %s", w.Code, w.Body.String())
	}
	c := e.login()
	if w := c.get("/api/nodes"); w.Code != 200 {
		t.Fatalf("after login: %d", w.Code)
	}
	if st := jsonOf(t, c.get("/api/state")); st["authenticated"] != true || st["csrf"] != c.csrf {
		t.Fatalf("state after login: %v", st)
	}
	if w := c.do("POST", "/api/logout", nil); w.Code != 200 {
		t.Fatalf("logout: %d", w.Code)
	}
	if w := c.get("/api/nodes"); w.Code != 401 {
		t.Fatal("session survived logout")
	}
}

func TestWebSessionCookieAttributes(t *testing.T) {
	e := newWebEnv(t)
	login := func(opts ...reqOpt) *http.Cookie {
		w := e.anon().do("POST", "/api/login", map[string]string{"password": webTestPassword}, opts...)
		if w.Code != 200 {
			t.Fatalf("login: %d", w.Code)
		}
		for _, ck := range w.Result().Cookies() {
			if ck.Name == webCookie {
				return ck
			}
		}
		t.Fatal("no cookie")
		return nil
	}
	plain := login()
	if !plain.HttpOnly || plain.SameSite != http.SameSiteStrictMode || plain.Path != "/" || plain.Secure {
		t.Fatalf("cookie over plain loopback: %+v", plain)
	}
	if len(plain.Value) < 40 {
		t.Fatalf("session token too short: %d", len(plain.Value))
	}
	proxied := login(withHeader("X-Forwarded-Proto", "https"))
	if !proxied.Secure || !proxied.HttpOnly || proxied.SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie behind the HTTPS proxy: %+v", proxied)
	}
	// A non-loopback peer cannot claim HTTPS through a header.
	spoof := e.anon().do("POST", "/api/login", map[string]string{"password": webTestPassword}, withPeer("203.0.113.9:4000"), withHeader("X-Forwarded-Proto", "https"))
	for _, ck := range spoof.Result().Cookies() {
		if ck.Name == webCookie && ck.Secure {
			t.Fatal("trusted X-Forwarded-Proto from a non-loopback peer")
		}
	}
	// SecureCookie in the configuration forces the attribute.
	if er := e.a.mutateWebConfig(func(c *WebConfig) error { c.SecureCookie = true; return nil }); er != nil {
		t.Fatal(er)
	}
	e.ws.invalidateConfig()
	if !login().Secure {
		t.Fatal("secure_cookie did not force Secure")
	}
}

func TestWebLoginNeedsAPasswordSetOnTheServer(t *testing.T) {
	old := webPBKDF2Iterations
	webPBKDF2Iterations = 1000
	defer func() { webPBKDF2Iterations = old }()
	a := testApp(t)
	ws := NewWebServer(a, t.Logf)
	e := &webEnv{t: t, a: a, ws: ws}
	w := e.anon().do("POST", "/api/login", map[string]string{"password": "anything at all 12"})
	if w.Code != 409 || errCode(t, w) != "not_configured" {
		t.Fatalf("login without a configured password: %d %s", w.Code, w.Body.String())
	}
	if st := jsonOf(t, e.anon().get("/api/state")); st["configured"] != false {
		t.Fatalf("state: %v", st)
	}
}

func TestWebLoginRateLimit(t *testing.T) {
	e := newWebEnv(t)
	c := e.anon()
	for i := 0; i < webLoginMaxFails; i++ {
		if w := c.do("POST", "/api/login", map[string]string{"password": "guess number " + string(rune('a'+i)) + " xx"}); w.Code != 401 {
			t.Fatalf("attempt %d: %d", i, w.Code)
		}
	}
	w := c.do("POST", "/api/login", map[string]string{"password": webTestPassword})
	if w.Code != 429 || w.Header().Get("Retry-After") == "" {
		t.Fatalf("not locked out: %d %s", w.Code, w.Body.String())
	}
	// Another client address is unaffected.
	if w := c.do("POST", "/api/login", map[string]string{"password": webTestPassword}, withPeer("203.0.113.7:1234")); w.Code != 200 {
		t.Fatalf("other address blocked: %d", w.Code)
	}
	// The lockout ends.
	e.clock.advance(2 * time.Minute)
	if w := c.do("POST", "/api/login", map[string]string{"password": webTestPassword}); w.Code != 200 {
		t.Fatalf("still locked after the delay: %d %s", w.Code, w.Body.String())
	}
}

func TestWebForwardedAddressOnlyTrustedFromLoopback(t *testing.T) {
	e := newWebEnv(t)
	c := e.anon()
	bad := func(peer, xff string) *httptest.ResponseRecorder {
		return c.do("POST", "/api/login", map[string]string{"password": "not the password 1"}, withPeer(peer), withHeader("X-Forwarded-For", xff))
	}
	// A remote peer cannot dodge the limiter by inventing addresses.
	for i := 0; i < webLoginMaxFails; i++ {
		bad("203.0.113.50:1111", "198.51.100."+string(rune('1'+i)))
	}
	if w := bad("203.0.113.50:1111", "198.51.100.99"); w.Code != 429 {
		t.Fatalf("spoofed X-Forwarded-For bypassed the limiter: %d", w.Code)
	}
	// Behind the local proxy the real client is the last forwarded entry.
	for i := 0; i < webLoginMaxFails; i++ {
		bad("127.0.0.1:2222", "10.9.9.9, 198.51.100.20")
	}
	if w := bad("127.0.0.1:2222", "1.2.3.4, 198.51.100.20"); w.Code != 429 {
		t.Fatalf("client address behind the proxy ignored: %d", w.Code)
	}
}

func TestWebSessionLifetime(t *testing.T) {
	e := newWebEnv(t)
	c := e.login()
	e.clock.advance(50 * time.Minute)
	if w := c.get("/api/nodes"); w.Code != 200 {
		t.Fatal("active session ended early")
	}
	e.clock.advance(50 * time.Minute) // 50 minutes since the last use: still inside the 60-minute idle limit
	if w := c.get("/api/nodes"); w.Code != 200 {
		t.Fatal("idle timer was not refreshed by use")
	}
	e.clock.advance(61 * time.Minute)
	if w := c.get("/api/nodes"); w.Code != 401 {
		t.Fatal("idle session not expired")
	}
	c = e.login()
	for i := 0; i < 14; i++ { // keep it busy past the absolute limit
		e.clock.advance(55 * time.Minute)
		c.get("/api/nodes")
	}
	if w := c.get("/api/nodes"); w.Code != 401 {
		t.Fatal("session outlived its maximum age")
	}
}

func TestWebPasswordChangeEndsSessions(t *testing.T) {
	e := newWebEnv(t)
	c := e.login()
	other := e.login()
	e.clock.advance(5 * time.Second)
	if er := e.a.SetWebPassword("a brand new long password"); er != nil {
		t.Fatal(er)
	}
	e.clock.advance(5 * time.Second)
	e.ws.invalidateConfig()
	for _, cl := range []*webClient{c, other} {
		if w := cl.get("/api/nodes"); w.Code != 401 {
			t.Fatalf("session survived a password change: %d", w.Code)
		}
	}
	if w := e.anon().do("POST", "/api/login", map[string]string{"password": webTestPassword}); w.Code != 401 {
		t.Fatal("old password still works")
	}
	if w := e.anon().do("POST", "/api/login", map[string]string{"password": "a brand new long password"}); w.Code != 200 {
		t.Fatal("new password rejected")
	}
}

func TestWebSessionManagement(t *testing.T) {
	e := newWebEnv(t)
	a, b, c3 := e.login(), e.login(), e.login()
	list := jsonOf(t, a.get("/api/sessions"))["sessions"].([]any)
	if len(list) != 3 {
		t.Fatalf("sessions: %d", len(list))
	}
	var cur, other string
	for _, s := range list {
		m := s.(map[string]any)
		if m["current"] == true {
			cur = m["id"].(string)
		} else if other == "" {
			other = m["id"].(string)
		}
		if _, leaked := m["token"]; leaked || m["csrf"] != nil {
			t.Fatalf("session list exposes credentials: %v", m)
		}
	}
	if cur == "" || other == "" {
		t.Fatal("current/other not identified")
	}
	if w := a.do("DELETE", "/api/sessions/"+other, nil); w.Code != 200 {
		t.Fatalf("revoke: %d %s", w.Code, w.Body.String())
	}
	if w := a.do("DELETE", "/api/sessions/"+other, nil); w.Code != 404 {
		t.Fatalf("revoking twice: %d", w.Code)
	}
	if w := a.do("DELETE", "/api/sessions/..%2Fetc", nil); w.Code != 404 {
		t.Fatalf("malformed id: %d", w.Code)
	}
	if w := a.do("POST", "/api/sessions/revoke-others", nil); w.Code != 200 {
		t.Fatalf("revoke others: %d", w.Code)
	}
	alive := 0
	for _, cl := range []*webClient{a, b, c3} {
		if cl.get("/api/nodes").Code == 200 {
			alive++
		}
	}
	if alive != 1 || a.get("/api/nodes").Code != 200 {
		t.Fatalf("revoke-others left %d sessions alive", alive)
	}
}

// ---- CSRF, origin, host ----

func TestWebStateChangingRequestsNeedCSRFAndOrigin(t *testing.T) {
	e := newWebEnv(t)
	c := e.login()
	body := map[string]string{"name": "x"}
	cases := []struct {
		name string
		opts []reqOpt
		want int
		code string
	}{
		{"no CSRF header", []reqOpt{withoutHeader("X-CSRF-Token")}, 403, "bad_csrf"},
		{"wrong CSRF token", []reqOpt{withHeader("X-CSRF-Token", strings.Repeat("a", len(c.csrf)))}, 403, "bad_csrf"},
		{"foreign origin", []reqOpt{withHeader("Origin", "https://evil.example")}, 403, "bad_origin"},
		{"null origin", []reqOpt{withHeader("Origin", "null")}, 403, "bad_origin"},
		{"origin with another port", []reqOpt{withHeader("Origin", "http://127.0.0.1:9999")}, 403, "bad_origin"},
		{"no origin, cross-site fetch metadata", []reqOpt{withoutHeader("Origin"), withHeader("Sec-Fetch-Site", "cross-site")}, 403, "bad_origin"},
		{"no origin, no referer", []reqOpt{withoutHeader("Origin")}, 403, "bad_origin"},
		{"foreign referer only", []reqOpt{withoutHeader("Origin"), withHeader("Referer", "https://evil.example/x")}, 403, "bad_origin"},
	}
	for _, tc := range cases {
		w := c.do("POST", "/api/subscriptions", body, tc.opts...)
		if w.Code != tc.want || errCode(t, w) != tc.code {
			t.Errorf("%s: %d %s", tc.name, w.Code, w.Body.String())
		}
	}
	// A foreign origin is refused before the session is even consulted.
	if w := e.anon().do("POST", "/api/logout", nil, withHeader("Origin", "https://evil.example")); w.Code != 403 {
		t.Errorf("logout CSRF: %d", w.Code)
	}
	// Legitimate forms of the same request pass the origin check.
	for name, opts := range map[string][]reqOpt{
		"same-origin fetch metadata": {withoutHeader("Origin"), withHeader("Sec-Fetch-Site", "same-origin")},
		"same-origin referer":        {withoutHeader("Origin"), withHeader("Referer", "http://"+webTestHost+"/nodes")},
	} {
		if w := c.do("POST", "/api/subscriptions", body, opts...); w.Code == 403 {
			t.Errorf("%s refused: %s", name, w.Body.String())
		}
	}
	// Safe methods are not subject to the check.
	if w := c.do("GET", "/api/nodes", nil, withHeader("Origin", "https://evil.example")); w.Code != 200 {
		t.Errorf("GET with foreign origin: %d", w.Code)
	}
}

func TestWebHostHeaderAllowList(t *testing.T) {
	e := newWebEnv(t)
	c := e.login()
	for _, host := range []string{"evil.example", "evil.example:8790", "127.0.0.1.evil.example", "10.0.0.5:8790"} {
		if w := c.do("GET", "/api/nodes", nil, withHost(host)); w.Code != http.StatusMisdirectedRequest {
			t.Errorf("host %q accepted: %d", host, w.Code)
		}
		if w := c.do("GET", "/", nil, withHost(host)); w.Code != http.StatusMisdirectedRequest {
			t.Errorf("UI served for host %q: %d", host, w.Code)
		}
	}
	for _, host := range []string{"127.0.0.1", "localhost:8790", "[::1]:8790"} {
		if w := c.do("GET", "/api/health", nil, withHost(host)); w.Code != 200 {
			t.Errorf("loopback host %q refused: %d", host, w.Code)
		}
	}
	if er := e.a.mutateWebConfig(func(c *WebConfig) error { c.AllowedHosts = []string{"panel.example.test"}; return nil }); er != nil {
		t.Fatal(er)
	}
	e.ws.invalidateConfig()
	if w := c.do("GET", "/api/health", nil, withHost("panel.example.test")); w.Code != 200 {
		t.Errorf("configured host refused: %d", w.Code)
	}
	// Behind the proxy the browser's origin is the public name.
	w := c.do("POST", "/api/subscriptions", map[string]string{"name": "x"}, withHost("panel.example.test"), withHeader("Origin", "https://panel.example.test"), withHeader("X-Forwarded-Proto", "https"))
	if w.Code == 403 || w.Code == http.StatusMisdirectedRequest {
		t.Errorf("proxied same-origin request refused: %d %s", w.Code, w.Body.String())
	}
	if w := c.do("POST", "/api/subscriptions", map[string]string{"name": "x"}, withHost("panel.example.test"), withHeader("Origin", "https://evil.example")); w.Code != 403 {
		t.Errorf("foreign origin against the public name: %d", w.Code)
	}
}

func TestWebRequestValidation(t *testing.T) {
	e := newWebEnv(t)
	c := e.login()
	if w := c.do("POST", "/api/subscriptions", `{"name":"x"}`, withHeader("Content-Type", "text/plain")); w.Code != 415 {
		t.Errorf("text/plain: %d", w.Code)
	}
	if w := c.do("POST", "/api/subscriptions", `{"name":"x","bogus":1}`); w.Code != 400 {
		t.Errorf("unknown field: %d", w.Code)
	}
	if w := c.do("POST", "/api/subscriptions", `{"name":"x"} {"name":"y"}`); w.Code != 400 {
		t.Errorf("trailing JSON: %d", w.Code)
	}
	if w := c.do("POST", "/api/subscriptions", `not json`); w.Code != 400 {
		t.Errorf("garbage: %d", w.Code)
	}
	big := `{"name":"` + strings.Repeat("a", 2<<20) + `"}`
	if w := c.do("POST", "/api/subscriptions", big); w.Code != 413 {
		t.Errorf("oversized body: %d", w.Code)
	}
	if w := c.do("GET", "/api/nodes/zzzz", nil); w.Code != 404 && w.Code != 405 {
		t.Errorf("bad id: %d", w.Code)
	}
	if w := c.do("PATCH", "/api/nodes/../../etc", `{}`); w.Code == 200 {
		t.Errorf("path traversal accepted: %d", w.Code)
	}
	if w := c.do("PATCH", "/api/nodes/zzzzzzzzzzzz", `{"name":"x"}`); w.Code != 404 {
		t.Errorf("non-hex id: %d", w.Code)
	}
}

func TestWebSecurityHeaders(t *testing.T) {
	e := newWebEnv(t)
	c := e.login()
	for _, path := range []string{"/api/nodes", "/api/health", "/", "/nodes"} {
		w := c.get(path)
		h := w.Header()
		if h.Get("X-Content-Type-Options") != "nosniff" || h.Get("X-Frame-Options") != "DENY" || h.Get("Referrer-Policy") != "no-referrer" {
			t.Errorf("%s: missing hardening headers: %v", path, h)
		}
		csp := h.Get("Content-Security-Policy")
		for _, want := range []string{"default-src 'self'", "script-src 'self'", "object-src 'none'", "frame-ancestors 'none'", "base-uri 'none'"} {
			if !strings.Contains(csp, want) {
				t.Errorf("%s: CSP lacks %q: %s", path, want, csp)
			}
		}
		if strings.Contains(csp, "unsafe-eval") || strings.Contains(csp, "script-src 'self' 'unsafe-inline'") {
			t.Errorf("%s: CSP allows inline or eval scripts: %s", path, csp)
		}
		if strings.HasPrefix(path, "/api/") && !strings.Contains(h.Get("Cache-Control"), "no-store") {
			t.Errorf("%s: API responses must not be cached", path)
		}
	}
	if w := c.do("POST", "/", `{}`); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST to the UI: %d", w.Code)
	}
}

// ---- password hashing and storage ----

func TestWebPBKDF2KnownVectors(t *testing.T) {
	for _, v := range []struct {
		iter int
		want string
	}{
		{1, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"},
		{2, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"},
		{4096, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"},
	} {
		got := hex.EncodeToString(pbkdf2SHA256([]byte("password"), []byte("salt"), v.iter, 32))
		if got != v.want {
			t.Errorf("PBKDF2-HMAC-SHA256 c=%d: %s", v.iter, got)
		}
	}
}

func TestWebPasswordStorage(t *testing.T) {
	old := webPBKDF2Iterations
	webPBKDF2Iterations = 1000
	defer func() { webPBKDF2Iterations = old }()
	a := testApp(t)
	if e := a.SetWebPassword("short"); e == nil {
		t.Fatal("a short password was accepted")
	}
	if e := a.SetWebPassword(webTestPassword); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(a.webConfigPath())
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(raw, []byte(webTestPassword)) {
		t.Fatal("the password is stored in clear text")
	}
	st, _ := os.Stat(a.webConfigPath())
	if st.Mode().Perm() != 0600 {
		t.Fatalf("web.json mode %v", st.Mode().Perm())
	}
	cfg, e := a.LoadWebConfig()
	if e != nil || !verifyPassword(cfg.PasswordHash, webTestPassword) || verifyPassword(cfg.PasswordHash, webTestPassword+"x") {
		t.Fatal("password verification")
	}
	h2, _ := hashPassword(webTestPassword)
	if h2 == cfg.PasswordHash {
		t.Fatal("hashes are not salted")
	}
	if verifyPassword("garbage", webTestPassword) || verifyPassword("", webTestPassword) {
		t.Fatal("a malformed record verified")
	}
	if !strings.HasPrefix(cfg.PasswordHash, "pbkdf2-sha256$") {
		t.Fatalf("hash format: %.20s", cfg.PasswordHash)
	}
	pw := GenerateWebPassword()
	if len(pw) < 20 || checkPasswordStrength(pw) != nil {
		t.Fatalf("generated password unusable: %q", pw)
	}
}

func TestWebServesOnLoopbackOnly(t *testing.T) {
	old := webPBKDF2Iterations
	webPBKDF2Iterations = 1000
	defer func() { webPBKDF2Iterations = old }()
	a := testApp(t)
	for _, addr := range []string{"0.0.0.0:0", "[::]:0", "203.0.113.5:8790", "example.com:80"} {
		if e := a.serveWeb(context.Background(), addr, t.Logf, nil); e == nil || !strings.Contains(e.Error(), "回环") {
			t.Errorf("%s: bound a non-loopback address (%v)", addr, e)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan net.Addr, 1)
	done := make(chan error, 1)
	go func() { done <- a.serveWeb(ctx, "127.0.0.1:0", t.Logf, func(ad net.Addr) { ready <- ad }) }()
	ad := <-ready
	resp, e := http.Get("http://" + ad.String() + "/api/health")
	if e != nil || resp.StatusCode != 200 {
		t.Fatalf("health over a real socket: %v", e)
	}
	resp.Body.Close()
	cancel()
	if e := <-done; e != nil {
		t.Fatalf("shutdown: %v", e)
	}
}

// ---- reauthentication ----

func TestWebSensitiveOperationsNeedRecentPassword(t *testing.T) {
	sc := newAggScene(t)
	e := newWebEnvFor(t, sc.a)
	sub, _ := sc.create(t, "main", 0, 1)
	c := e.login()
	node := sc.nodes[0].ID
	protected := []struct{ method, path string }{
		{"GET", "/api/nodes/" + node + "/link"},
		{"DELETE", "/api/nodes/" + node},
		{"GET", "/api/subscriptions/" + sub.ID + "/url"},
		{"POST", "/api/subscriptions/" + sub.ID + "/rotate"},
		{"DELETE", "/api/subscriptions/" + sub.ID},
		{"GET", "/api/sources/" + sc.links.ID + "/url"},
		{"DELETE", "/api/sources/" + sc.links.ID},
		{"GET", "/api/system/backup"},
		{"POST", "/api/system/restore"},
		{"PATCH", "/api/system/settings"},
		{"POST", "/api/system/permissions/fix"},
	}
	for _, p := range protected {
		var body any
		if p.method != "GET" && p.method != "DELETE" {
			body = map[string]any{}
		}
		if w := c.do(p.method, p.path, body); w.Code != 403 || errCode(t, w) != "reauth_required" {
			t.Errorf("%s %s without reauth: %d %s", p.method, p.path, w.Code, w.Body.String())
		}
	}
	if w := c.do("POST", "/api/reauth", map[string]string{"password": "wrong password again"}); w.Code != 401 {
		t.Fatalf("reauth with a wrong password: %d", w.Code)
	}
	if w := c.get("/api/nodes/" + node + "/link"); w.Code != 403 {
		t.Fatal("a failed reauth opened the window")
	}
	c.reauth()
	w := c.get("/api/nodes/" + node + "/link")
	want, _ := sc.nodes[0].URI()
	if w.Code != 200 || jsonOf(t, w)["link"] != want {
		t.Fatalf("link after reauth: %d %s", w.Code, w.Body.String())
	}
	// The window closes by itself.
	e.clock.advance(webReauthWindow + time.Second)
	if w := c.get("/api/nodes/" + node + "/link"); w.Code != 403 {
		t.Fatal("reauth window did not expire")
	}
	// Another session does not inherit it.
	c.reauth()
	if w := e.login().get("/api/nodes/" + node + "/link"); w.Code != 403 {
		t.Fatal("reauth leaked to another session")
	}
	// Bulk delete is checked inside the handler.
	c2 := e.login()
	if w := c2.do("POST", "/api/nodes/bulk", map[string]any{"action": "delete", "ids": []string{node}}); w.Code != 403 {
		t.Fatalf("bulk delete without reauth: %d", w.Code)
	}
	if w := c2.do("POST", "/api/nodes/bulk", map[string]any{"action": "disable", "ids": []string{node}}); w.Code != 200 {
		t.Fatalf("bulk disable needs no reauth: %d %s", w.Code, w.Body.String())
	}
}
