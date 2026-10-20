package rout

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// The subscription server is a small read-only HTTP endpoint (GET /s/{token}) meant to sit
// behind an administrator-configured HTTPS reverse proxy. It binds to loopback only, has no
// other routes, never writes any file, and reads state.json fresh (cached by file identity)
// on every request so CLI changes take effect immediately.

const (
	subscriptionMaxInFlight = 64
	subscriptionMaxConns    = 256
)

// stateCache re-parses state.json only when the file changed. AtomicWrite renames a new
// file into place, so inode, size and mtime identify a version without taking any lock.
type stateCache struct {
	a   *App
	mu  sync.Mutex
	key [3]int64
	set bool
	st  State
	err error
}

func (c *stateCache) load() (State, error) {
	path := filepath.Join(c.a.Home, "state.json")
	fi, e := os.Stat(path)
	if os.IsNotExist(e) {
		return State{Schema: 1, Profiles: []Profile{}}, nil
	}
	if e != nil {
		return State{}, e
	}
	key := [3]int64{int64(fi.Sys().(*syscall.Stat_t).Ino), fi.ModTime().UnixNano(), fi.Size()}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.set && c.key == key {
		return c.st, c.err
	}
	c.st, c.err = c.a.Load()
	c.key, c.set = key, true
	return c.st, c.err
}

type subscriptionHandler struct {
	load func() (State, error)
	logf func(format string, args ...any)
	sem  chan struct{}
	mu   sync.Mutex
	last map[string]string // subscription ID -> last logged warning set, to avoid log floods
}

func newSubscriptionHandler(load func() (State, error), logf func(string, ...any)) *subscriptionHandler {
	return &subscriptionHandler{load: load, logf: logf, sem: make(chan struct{}, subscriptionMaxInFlight), last: map[string]string{}}
}

func plain(w http.ResponseWriter, code int, body string) {
	h := w.Header()
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(code)
	_, _ = w.Write([]byte(body + "\n"))
}

// notFound is the single response for every unknown, malformed, disabled or revoked request.
func notFound(w http.ResponseWriter) { plain(w, http.StatusNotFound, "not found") }

func (h *subscriptionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		plain(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	token, ok := strings.CutPrefix(r.URL.Path, "/s/")
	if !ok || !tokenPattern.MatchString(token) {
		notFound(w)
		return
	}
	select {
	case h.sem <- struct{}{}:
		defer func() { <-h.sem }()
	default:
		w.Header().Set("Retry-After", "5")
		plain(w, http.StatusServiceUnavailable, "busy")
		return
	}
	s, e := h.load()
	if e != nil {
		h.logf("subscription: state unreadable: %s", e.Error())
		w.Header().Set("Retry-After", "30")
		plain(w, http.StatusServiceUnavailable, "temporarily unavailable")
		return
	}
	sub, ok := s.matchSubscription(token)
	if !ok || !sub.Enabled {
		notFound(w)
		return
	}
	exp := s.exportSubscription(sub)
	h.report(sub, exp)
	if len(exp.URIs) == 0 {
		// An explicit failure, never an empty success a client would use to erase its nodes.
		w.Header().Set("Retry-After", "300")
		plain(w, http.StatusServiceUnavailable, "no available nodes")
		return
	}
	body := renderSubscription(exp.URIs)
	hd := w.Header()
	hd.Set("Content-Type", "text/plain; charset=utf-8")
	hd.Set("Cache-Control", "no-store")
	hd.Set("Pragma", "no-cache")
	hd.Set("X-Content-Type-Options", "nosniff")
	hd.Set("Referrer-Policy", "no-referrer")
	hd.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write([]byte(body))
	}
}

// report logs export warnings (subscription ID and node names only) when they change.
func (h *subscriptionHandler) report(sub Subscription, exp SubscriptionExport) {
	joined := strings.Join(exp.Warnings, "; ")
	h.mu.Lock()
	changed := h.last[sub.ID] != joined
	h.last[sub.ID] = joined
	h.mu.Unlock()
	if changed && joined != "" {
		h.logf("subscription %s: %s", sub.ID, joined)
	}
}

// limitListener caps simultaneous connections.
type limitListener struct {
	net.Listener
	sem chan struct{}
}

func (l *limitListener) Accept() (net.Conn, error) {
	l.sem <- struct{}{}
	c, e := l.Listener.Accept()
	if e != nil {
		<-l.sem
		return nil, e
	}
	return &limitConn{Conn: c, release: func() { <-l.sem }}, nil
}

type limitConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitConn) Close() error {
	c.once.Do(c.release)
	return c.Conn.Close()
}

// serveSubscriptions listens on a loopback address and serves until ctx ends, then shuts
// down gracefully. ready (optional) receives the bound address.
func (a *App) serveSubscriptions(ctx context.Context, addr string, logf func(string, ...any), ready func(net.Addr)) error {
	host, _, e := net.SplitHostPort(addr)
	if ip := net.ParseIP(host); e != nil || ip == nil || !ip.IsLoopback() {
		return errors.New("订阅服务只能监听本机回环地址，请通过 HTTPS 反向代理对外提供")
	}
	ln, e := net.Listen("tcp", addr)
	if e != nil {
		return fmt.Errorf("订阅服务无法监听 %s：%w", addr, e)
	}
	cache := &stateCache{a: a}
	srv := &http.Server{
		Handler:           a.subscriptionHTTPHandler(cache.load, logf),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 << 10,
		ErrorLog:          nil,
	}
	if ready != nil {
		ready(ln.Addr())
	}
	done := make(chan error, 1)
	go func() {
		done <- srv.Serve(&limitListener{Listener: ln, sem: make(chan struct{}, subscriptionMaxConns)})
	}()
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

// ServeSubscriptions is `rout subscription serve`: it requires the server to be enabled in
// the saved settings and listens on 127.0.0.1 at the configured port.
func (a *App) ServeSubscriptions(ctx context.Context) error {
	st, e := a.LoadSettings()
	if e != nil {
		return e
	}
	if st.Subscription == nil || !st.Subscription.Enabled {
		return errors.New("订阅服务未启用，请先在“订阅管理 → 订阅服务设置”中启用")
	}
	logf := func(format string, args ...any) { fmt.Fprintf(os.Stderr, format+"\n", args...) }
	addr := net.JoinHostPort("127.0.0.1", itoa(st.Subscription.listenPort()))
	return a.serveSubscriptions(ctx, addr, logf, func(n net.Addr) { logf("subscription server listening on %s", n) })
}

// Diagnostic responses share the subscription transport, but can never export nodes.
func (a *App) subscriptionHTTPHandler(load func() (State, error), logf func(string, ...any)) http.Handler {
	normal := newSubscriptionHandler(load, logf)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == subscriptionProbePath {
			a.serveSubscriptionProbe(w, r)
			return
		}
		normal.ServeHTTP(w, r)
	})
}
