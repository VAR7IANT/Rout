package rout

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	webCookie        = "rout_session"
	webMaxSessions   = 20
	webReauthWindow  = 5 * time.Minute
	webLoginMaxFails = 5
	webLoginWindow   = 15 * time.Minute
	webGlobalFails   = 60
	webGlobalWindow  = 10 * time.Minute
)

// ---- sessions --------------------------------------------------------------------------

type webSession struct {
	ID          string // public handle for listing and revoking; not a credential
	tokenHash   [32]byte
	Created     time.Time
	LastSeen    time.Time
	ReauthUntil time.Time
	CSRF        string
	IP, Agent   string
}

type sessionStore struct {
	mu   sync.Mutex
	now  func() time.Time
	byID map[[32]byte]*webSession
}

func newSessionStore(now func() time.Time) *sessionStore {
	return &sessionStore{now: now, byID: map[[32]byte]*webSession{}}
}

func randomToken(n int) string {
	b := make([]byte, n)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// create returns the cookie value of a new session. Only its hash is kept.
func (s *sessionStore) create(ip, agent string) (token string, sess webSession) {
	token = randomToken(32)
	if len(agent) > 160 {
		agent = agent[:160]
	}
	now := s.now()
	ns := &webSession{ID: randomToken(8), tokenHash: sha256.Sum256([]byte(token)), Created: now, LastSeen: now, CSRF: randomToken(24), IP: ip, Agent: agent}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.byID) >= webMaxSessions {
		// Drop the least recently used session rather than refusing a legitimate login.
		var oldest [32]byte
		var at time.Time
		for k, v := range s.byID {
			if at.IsZero() || v.LastSeen.Before(at) {
				oldest, at = k, v.LastSeen
			}
		}
		delete(s.byID, oldest)
	}
	s.byID[ns.tokenHash] = ns
	return token, *ns
}

// lookup validates the cookie and refreshes the idle timer.
func (s *sessionStore) lookup(token string, idle, maxAge time.Duration) (webSession, bool) {
	if len(token) < 20 || len(token) > 100 {
		return webSession{}, false
	}
	h := sha256.Sum256([]byte(token))
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.byID[h]
	if !ok {
		return webSession{}, false
	}
	now := s.now()
	if now.Sub(sess.LastSeen) > idle || now.Sub(sess.Created) > maxAge {
		delete(s.byID, h)
		return webSession{}, false
	}
	sess.LastSeen = now
	return *sess, true
}

func (s *sessionStore) update(token string, change func(*webSession)) {
	h := sha256.Sum256([]byte(token))
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.byID[h]; ok {
		change(sess)
	}
}

func (s *sessionStore) destroy(token string) {
	h := sha256.Sum256([]byte(token))
	s.mu.Lock()
	delete(s.byID, h)
	s.mu.Unlock()
}

// revoke removes the session with a public ID.
func (s *sessionStore) revoke(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.byID {
		if v.ID == id {
			delete(s.byID, k)
			return true
		}
	}
	return false
}

// revokeAllExcept removes every session but the one with the given cookie (or all of them
// when keep is empty) and returns how many were removed.
func (s *sessionStore) revokeAllExcept(keep string) int {
	var keepHash [32]byte
	if keep != "" {
		keepHash = sha256.Sum256([]byte(keep))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for k := range s.byID {
		if keep == "" || k != keepHash {
			delete(s.byID, k)
			n++
		}
	}
	return n
}

func (s *sessionStore) list() []webSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]webSession, 0, len(s.byID))
	for _, v := range s.byID {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
	return out
}

// ---- login throttling ------------------------------------------------------------------

type loginLimiter struct {
	mu     sync.Mutex
	now    func() time.Time
	byIP   map[string]*loginRecord
	global []time.Time
}

type loginRecord struct {
	fails       []time.Time
	lockedUntil time.Time
	strikes     int
}

func newLoginLimiter(now func() time.Time) *loginLimiter {
	return &loginLimiter{now: now, byIP: map[string]*loginRecord{}}
}

// check says whether a login attempt from ip may be evaluated now, and when it may retry.
func (l *loginLimiter) check(ip string) (ok bool, retry time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.prune(now)
	if len(l.global) >= webGlobalFails {
		return false, webGlobalWindow
	}
	if r := l.byIP[ip]; r != nil && now.Before(r.lockedUntil) {
		return false, r.lockedUntil.Sub(now)
	}
	return true, 0
}

func (l *loginLimiter) failure(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.global = append(l.global, now)
	r := l.byIP[ip]
	if r == nil {
		if len(l.byIP) > 4096 {
			l.byIP = map[string]*loginRecord{}
		}
		r = &loginRecord{}
		l.byIP[ip] = r
	}
	r.fails = append(r.fails, now)
	cut := now.Add(-webLoginWindow)
	kept := r.fails[:0]
	for _, t := range r.fails {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	r.fails = kept
	if len(r.fails) >= webLoginMaxFails {
		// 1, 2, 4 ... minutes, at most 30, so a forgotten password costs minutes while
		// guessing becomes impractical.
		r.strikes++
		d := time.Minute << uint(min(r.strikes-1, 5))
		if d > 30*time.Minute {
			d = 30 * time.Minute
		}
		r.lockedUntil = now.Add(d)
		r.fails = nil
	}
}

func (l *loginLimiter) success(ip string) {
	l.mu.Lock()
	delete(l.byIP, ip)
	l.mu.Unlock()
}

func (l *loginLimiter) prune(now time.Time) {
	cut := now.Add(-webGlobalWindow)
	kept := l.global[:0]
	for _, t := range l.global {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	l.global = kept
}

// ---- request checks --------------------------------------------------------------------

// clientIP is the address of the browser. The panel only listens on loopback, so a peer is
// the local reverse proxy, whose X-Forwarded-For (rightmost entry: the one it appended)
// is trusted; a direct local connection has no such header.
func clientIP(r *http.Request) string {
	peer, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip := net.ParseIP(peer); ip != nil && ip.IsLoopback() {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			last := strings.TrimSpace(parts[len(parts)-1])
			if net.ParseIP(last) != nil {
				return last
			}
		}
	}
	return peer
}

// requestIsSecure reports whether the browser reached us over HTTPS.
func requestIsSecure(r *http.Request, force bool) bool {
	if force || r.TLS != nil {
		return true
	}
	peer, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip := net.ParseIP(peer); ip != nil && ip.IsLoopback() {
		return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
	}
	return false
}

// hostAllowed defends the loopback service against DNS rebinding: only loopback names (any
// port) and the configured public hosts are accepted.
func hostAllowed(host string, allowed []string) bool {
	host = strings.ToLower(host)
	bare := host
	if h, _, e := net.SplitHostPort(host); e == nil {
		bare = h
	}
	bare = strings.Trim(bare, "[]")
	if bare == "localhost" {
		return true
	}
	if ip := net.ParseIP(bare); ip != nil && ip.IsLoopback() {
		return true
	}
	for _, a := range allowed {
		if host == a || bare == a {
			return true
		}
	}
	return false
}

// sameOrigin implements the CSRF origin check for state-changing requests. A request must
// carry an Origin (or, failing that, a Referer or a same-origin Fetch Metadata header) that
// points back at one of the hosts we serve.
func sameOrigin(r *http.Request, allowed []string) bool {
	hostOK := func(h string) bool {
		return strings.EqualFold(h, r.Host) || hostAllowedExact(h, allowed)
	}
	if o := r.Header.Get("Origin"); o != "" {
		if o == "null" {
			return false
		}
		u, e := url.Parse(o)
		return e == nil && u.Host != "" && hostOK(u.Host)
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" {
		return site == "same-origin"
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		u, e := url.Parse(ref)
		return e == nil && u.Host != "" && hostOK(u.Host)
	}
	return false
}

func hostAllowedExact(h string, allowed []string) bool {
	h = strings.ToLower(h)
	for _, a := range allowed {
		if h == a {
			return true
		}
	}
	return false
}

func csrfEqual(a, b string) bool {
	return len(a) == len(b) && len(a) > 0 && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func shortHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:4])
}

func since(t, now time.Time) time.Duration { return now.Sub(t) }
