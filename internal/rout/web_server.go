package rout

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/VAR7IANT/Rout/internal/webui"
)

// WebServer is the management panel's HTTP service: a JSON API under /api and the embedded
// single-page application everywhere else.
type WebServer struct {
	a        *App
	now      func() time.Time
	sessions *sessionStore
	limiter  *loginLimiter
	audit    *auditLog
	metrics  *sysSampler
	loginSem chan struct{}
	mux      *http.ServeMux
	ui       http.Handler
	logf     func(string, ...any)

	cfgMu   sync.Mutex
	cfg     WebConfig
	cfgAt   time.Time
	cfgErr  error
	ipMu    sync.Mutex
	ipCache pubIPCache
	// detectIPs finds the server's public addresses and lookupHost resolves a name; tests
	// replace both.
	detectIPs  func() (string, string)
	lookupHost func(ctx context.Context, host string) ([]string, error)

	trMu    sync.Mutex
	trCache map[string]trafficEntry

	diagSem     chan struct{}
	updMu       sync.Mutex
	updCache    updateInfo
	updAt       time.Time
	fetchLatest func(ctx context.Context) (string, error)
}

type trafficEntry struct {
	at time.Time
	v  TrafficView
}

// rawResponse lets a handler send a file instead of JSON (backup download).
type rawResponse struct {
	ContentType string
	Filename    string
	Body        []byte
}

type routeOpts struct {
	public bool  // no session needed (login, state, health)
	reauth bool  // recent password confirmation needed
	body   int64 // maximum request body (default 1 MiB)
	raw    bool  // body is not JSON (backup upload)
}

type apiError struct {
	Status int
	Code   string
	Msg    string
	Retry  int // seconds, for 429
}

func (e *apiError) Error() string { return e.Msg }

func errBad(msg string) error {
	return &apiError{Status: http.StatusBadRequest, Code: "bad_request", Msg: msg}
}
func errNotFound(msg string) error {
	return &apiError{Status: http.StatusNotFound, Code: "not_found", Msg: msg}
}
func errConflict(msg string) error {
	return &apiError{Status: http.StatusConflict, Code: "conflict", Msg: msg}
}

// reqCtx is what a handler sees: the request, the session and an App whose language follows
// the browser.
type reqCtx struct {
	s     *WebServer
	a     *App
	w     http.ResponseWriter
	r     *http.Request
	sess  webSession
	token string
	lang  string
}

func (c *reqCtx) decode(v any) error {
	dec := json.NewDecoder(c.r.Body)
	dec.DisallowUnknownFields()
	if e := dec.Decode(v); e != nil {
		if errors.Is(e, io.EOF) {
			return errBad("请求内容为空")
		}
		var mb *http.MaxBytesError
		if errors.As(e, &mb) {
			return &apiError{Status: http.StatusRequestEntityTooLarge, Code: "too_large", Msg: "请求内容过大"}
		}
		return errBad("请求内容无效")
	}
	if dec.More() {
		return errBad("请求内容无效")
	}
	return nil
}

func (c *reqCtx) pathID(name string) (string, error) {
	id := c.r.PathValue(name)
	if !idPattern.MatchString(id) {
		return "", errNotFound("找不到对象")
	}
	return id, nil
}

// NewWebServer builds the service around an App. now is injectable for tests.
func NewWebServer(a *App, logf func(string, ...any)) *WebServer {
	if logf == nil {
		logf = func(format string, args ...any) { log.Printf(format, args...) }
	}
	now := time.Now
	s := &WebServer{a: a, now: now, sessions: newSessionStore(now), limiter: newLoginLimiter(now), audit: &auditLog{}, loginSem: make(chan struct{}, 2),
		mux: http.NewServeMux(), ui: webui.Handler(), logf: logf, detectIPs: DetectPublicIPs, lookupHost: net.DefaultResolver.LookupHost, trCache: map[string]trafficEntry{},
		diagSem: make(chan struct{}, 2), fetchLatest: latestReleaseTag}
	s.metrics = newSysSampler()
	s.routes()
	return s
}

func (s *WebServer) config() (WebConfig, error) {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	if s.now().Sub(s.cfgAt) < 2*time.Second && !s.cfgAt.IsZero() {
		return s.cfg, s.cfgErr
	}
	s.cfg, s.cfgErr = s.a.LoadWebConfig()
	s.cfgAt = s.now()
	return s.cfg, s.cfgErr
}

func (s *WebServer) invalidateConfig() {
	s.cfgMu.Lock()
	s.cfgAt = time.Time{}
	s.cfgMu.Unlock()
}

func (s *WebServer) setSecurityHeaders(w http.ResponseWriter, api bool) {
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
	h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
	if api {
		h.Set("Cache-Control", "no-store")
		h.Set("Pragma", "no-cache")
	}
}

// ServeHTTP applies the checks that every request passes before it reaches a route.
func (s *WebServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	api := strings.HasPrefix(r.URL.Path, "/api/")
	s.setSecurityHeaders(w, api)
	cfg, e := s.config()
	if e != nil {
		s.writeError(w, &reqCtx{a: s.a, lang: "zh-CN"}, &apiError{Status: http.StatusServiceUnavailable, Code: "config", Msg: "面板配置无效，请在服务器上检查 web.json"})
		return
	}
	if !hostAllowed(r.Host, cfg.AllowedHosts) {
		http.Error(w, "unknown host", http.StatusMisdirectedRequest)
		return
	}
	if !api {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.ui.ServeHTTP(w, r)
		return
	}
	s.mux.ServeHTTP(w, r)
}

func (s *WebServer) langOf(r *http.Request) string {
	switch v := strings.ToLower(r.Header.Get("X-Rout-Lang")); {
	case strings.HasPrefix(v, "en"):
		return "en"
	case strings.HasPrefix(v, "zh-tw"), strings.HasPrefix(v, "zh-hant"):
		return "zh-TW"
	}
	return "zh-CN"
}

// handle registers an API route with authentication, CSRF and size limits applied.
func (s *WebServer) handle(pattern string, o routeOpts, fn func(c *reqCtx) (any, error)) {
	s.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		cfg, _ := s.config()
		lang := s.langOf(r)
		aa := *s.a
		aa.Language = lang
		c := &reqCtx{s: s, a: &aa, w: w, r: r, lang: lang}
		unsafe := r.Method != http.MethodGet && r.Method != http.MethodHead
		if unsafe {
			if !sameOrigin(r, cfg.AllowedHosts) {
				s.writeError(w, c, &apiError{Status: http.StatusForbidden, Code: "bad_origin", Msg: "请求来源不被允许"})
				return
			}
			if !o.raw && r.ContentLength != 0 && !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
				s.writeError(w, c, &apiError{Status: http.StatusUnsupportedMediaType, Code: "bad_content_type", Msg: "请求必须使用 application/json"})
				return
			}
		}
		if !o.public {
			sess, token, ae := s.authenticate(w, r, cfg)
			if ae != nil {
				s.writeError(w, c, ae)
				return
			}
			c.sess, c.token = sess, token
			if unsafe && !csrfEqual(r.Header.Get("X-CSRF-Token"), sess.CSRF) {
				s.writeError(w, c, &apiError{Status: http.StatusForbidden, Code: "bad_csrf", Msg: "安全令牌无效，请刷新页面后重试"})
				return
			}
			if o.reauth && !s.now().Before(sess.ReauthUntil) {
				s.writeError(w, c, &apiError{Status: http.StatusForbidden, Code: "reauth_required", Msg: "此操作需要重新输入管理密码"})
				return
			}
		}
		limit := o.body
		if limit == 0 {
			limit = 1 << 20
		}
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		out, err := fn(c)
		if err != nil {
			s.writeError(w, c, err)
			return
		}
		if unsafe && !o.public {
			s.audit.add(s.now(), clientIP(r), r.Method+" "+r.Pattern)
		}
		if rr, ok := out.(*rawResponse); ok {
			h := w.Header()
			h.Set("Content-Type", rr.ContentType)
			h.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": rr.Filename}))
			h.Set("Content-Length", strconv.Itoa(len(rr.Body)))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(rr.Body)
			return
		}
		s.writeJSON(w, http.StatusOK, out)
	})
}

// authenticate resolves the session cookie. A session created before the password was last
// changed on the server is ended here.
func (s *WebServer) authenticate(w http.ResponseWriter, r *http.Request, cfg WebConfig) (webSession, string, *apiError) {
	ck, e := r.Cookie(webCookie)
	if e != nil {
		return webSession{}, "", &apiError{Status: http.StatusUnauthorized, Code: "unauthenticated", Msg: "请先登录"}
	}
	sess, ok := s.sessions.lookup(ck.Value, cfg.idle(), cfg.maxAge())
	if !ok {
		s.clearCookie(w, r, cfg)
		return webSession{}, "", &apiError{Status: http.StatusUnauthorized, Code: "unauthenticated", Msg: "登录已过期，请重新登录"}
	}
	if !cfg.PasswordChangedAt.IsZero() && sess.Created.Before(cfg.PasswordChangedAt) {
		s.sessions.destroy(ck.Value)
		s.clearCookie(w, r, cfg)
		return webSession{}, "", &apiError{Status: http.StatusUnauthorized, Code: "unauthenticated", Msg: "密码已更改，请重新登录"}
	}
	return sess, ck.Value, nil
}

func (s *WebServer) writeJSON(w http.ResponseWriter, status int, v any) {
	if v == nil {
		v = map[string]bool{"ok": true}
	}
	var buf bytes.Buffer
	if e := json.NewEncoder(&buf).Encode(v); e != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

func (s *WebServer) writeError(w http.ResponseWriter, c *reqCtx, err error) {
	var ae *apiError
	if !errors.As(err, &ae) {
		var mb *http.MaxBytesError
		var nr *errNoRoute
		switch {
		case errors.As(err, &nr):
			ae = &apiError{Status: http.StatusConflict, Code: "no_route", Msg: err.Error()}
		case errors.As(err, &mb):
			ae = &apiError{Status: http.StatusRequestEntityTooLarge, Code: "too_large", Msg: "请求内容过大"}
		case errors.Is(err, errLockBusy):
			ae = &apiError{Status: http.StatusConflict, Code: "busy", Msg: err.Error()}
		case errors.Is(err, errRefreshBusy):
			ae = &apiError{Status: http.StatusConflict, Code: "busy", Msg: err.Error()}
		default:
			ae = &apiError{Status: http.StatusBadRequest, Code: "error", Msg: err.Error()}
		}
	}
	msg := Translate(c.lang, ae.Msg)
	// Messages shown to the browser never carry a URL, whatever produced them.
	msg = urlInText.ReplaceAllString(msg, "…")
	body := map[string]any{"code": ae.Code, "message": msg}
	if ae.Retry > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(ae.Retry))
		body["retry_after"] = ae.Retry
	}
	s.writeJSON(w, ae.Status, map[string]any{"error": body})
}

func (s *WebServer) setCookie(w http.ResponseWriter, r *http.Request, cfg WebConfig, token string, maxAge time.Duration) {
	http.SetCookie(w, &http.Cookie{Name: webCookie, Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: requestIsSecure(r, cfg.SecureCookie), MaxAge: int(maxAge.Seconds())})
}
func (s *WebServer) clearCookie(w http.ResponseWriter, r *http.Request, cfg WebConfig) {
	http.SetCookie(w, &http.Cookie{Name: webCookie, Value: "", Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: requestIsSecure(r, cfg.SecureCookie), MaxAge: -1})
}

// ---- audit log -------------------------------------------------------------------------

type auditEntry struct {
	At     time.Time `json:"at"`
	IP     string    `json:"ip"`
	Action string    `json:"action"`
}
type auditLog struct {
	mu      sync.Mutex
	entries []auditEntry
}

func (l *auditLog) add(at time.Time, ip, action string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, auditEntry{at, ip, action})
	if len(l.entries) > 200 {
		l.entries = l.entries[len(l.entries)-200:]
	}
}
func (l *auditLog) recent(n int) []auditEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	if n > len(l.entries) {
		n = len(l.entries)
	}
	out := make([]auditEntry, n)
	for i := 0; i < n; i++ {
		out[i] = l.entries[len(l.entries)-1-i]
	}
	return out
}

// ---- serving ---------------------------------------------------------------------------

// ServeWeb runs the panel until ctx ends. It binds to loopback only.
func (a *App) ServeWeb(ctx context.Context, ready func(net.Addr)) error {
	cfg, e := a.LoadWebConfig()
	if e != nil {
		return e
	}
	logf := func(format string, args ...any) { fmt.Fprintf(os.Stderr, format+"\n", args...) }
	if cfg.PasswordHash == "" {
		logf("web: no administrator password is set; logins are refused until `rout web passwd` is run")
	}
	return a.serveWeb(ctx, net.JoinHostPort("127.0.0.1", itoa(cfg.port())), logf, ready)
}

func (a *App) serveWeb(ctx context.Context, addr string, logf func(string, ...any), ready func(net.Addr)) error {
	host, _, e := net.SplitHostPort(addr)
	if ip := net.ParseIP(host); e != nil || ip == nil || !ip.IsLoopback() {
		return errors.New("管理面板只能监听本机回环地址，请通过 HTTPS 反向代理对外提供")
	}
	ln, e := net.Listen("tcp", addr)
	if e != nil {
		return fmt.Errorf("管理面板无法监听 %s：%w", addr, e)
	}
	ws := NewWebServer(a, logf)
	ws.metrics.start(ctx)
	go a.RunRemoteScheduler(ctx, time.Minute, func(m string) { logf("web: %s", m) })
	srv := &http.Server{
		Handler:           ws,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	if ready != nil {
		ready(ln.Addr())
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()
	select {
	case e = <-done:
		return e
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	e = srv.Shutdown(shutdown)
	if se := <-done; se != nil && !errors.Is(se, http.ErrServerClosed) {
		e = errors.Join(e, se)
	}
	return e
}
