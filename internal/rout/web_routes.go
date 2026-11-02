package rout

import (
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

var sessionIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{6,64}$`)

func readSmall(path string, max int64) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, max))
}

type passwordReq struct {
	Password string `json:"password"`
}

// routes registers every API endpoint. Anything not marked public needs a session; anything
// that changes state also needs the CSRF header and a same-origin request (see handle).
func (s *WebServer) routes() {
	pub := routeOpts{public: true}
	s.handle("GET /api/health", pub, func(c *reqCtx) (any, error) { return map[string]bool{"ok": true}, nil })
	s.handle("GET /api/state", pub, s.apiState)
	s.handle("POST /api/login", routeOpts{public: true, body: 4096}, s.apiLogin)
	s.handle("POST /api/logout", routeOpts{}, s.apiLogout)
	s.handle("POST /api/reauth", routeOpts{body: 4096}, s.apiReauth)
	s.handle("GET /api/sessions", routeOpts{}, s.apiSessions)
	s.handle("DELETE /api/sessions/{sid}", routeOpts{}, s.apiRevokeSession)
	s.handle("POST /api/sessions/revoke-others", routeOpts{}, s.apiRevokeOthers)
	s.handle("GET /api/activity", routeOpts{}, func(c *reqCtx) (any, error) {
		return map[string]any{"entries": s.audit.recent(50)}, nil
	})
	s.handle("GET /api/overview", routeOpts{}, s.apiOverview)
	s.handle("GET /api/metrics", routeOpts{}, func(c *reqCtx) (any, error) { return s.metrics.snapshot(), nil })
	s.nodeRoutes()
	s.subscriptionRoutes()
	s.systemRoutes()
}

// ---- session ---------------------------------------------------------------------------

func (s *WebServer) apiState(c *reqCtx) (any, error) {
	cfg, _ := s.config()
	out := map[string]any{"configured": cfg.PasswordHash != "", "authenticated": false, "secure": requestIsSecure(c.r, cfg.SecureCookie)}
	if sess, _, ae := s.authenticate(c.w, c.r, cfg); ae == nil {
		out["authenticated"] = true
		out["csrf"] = sess.CSRF
		out["version"] = Version
		out["session_id"] = sess.ID
		if s.now().Before(sess.ReauthUntil) {
			out["reauth_until"] = sess.ReauthUntil
		}
	}
	return out, nil
}

// checkPassword is the single place a typed password is tested: it counts failures per client
// address, locks out repeated guessing, and bounds how many hashes run at once.
func (s *WebServer) checkPassword(c *reqCtx, cfg WebConfig, pw string) error {
	ip := clientIP(c.r)
	if cfg.PasswordHash == "" {
		return &apiError{Status: http.StatusConflict, Code: "not_configured", Msg: "尚未设置管理密码，请在服务器上运行 rout web passwd"}
	}
	if ok, retry := s.limiter.check(ip); !ok {
		return &apiError{Status: http.StatusTooManyRequests, Code: "rate_limited", Msg: "尝试次数过多，请稍后再试", Retry: int(retry.Seconds()) + 1}
	}
	select {
	case s.loginSem <- struct{}{}:
		defer func() { <-s.loginSem }()
	case <-c.r.Context().Done():
		return errBad("请求已取消")
	}
	// Failures recorded while this request waited for a hashing slot may have locked the
	// client out: look again before spending a hash (and a guess) on it.
	if ok, retry := s.limiter.check(ip); !ok {
		return &apiError{Status: http.StatusTooManyRequests, Code: "rate_limited", Msg: "尝试次数过多，请稍后再试", Retry: int(retry.Seconds()) + 1}
	}
	if !verifyPassword(cfg.PasswordHash, pw) {
		s.limiter.failure(ip)
		s.audit.add(s.now(), ip, "password rejected")
		return &apiError{Status: http.StatusUnauthorized, Code: "invalid_credentials", Msg: "密码错误"}
	}
	// The password may have been changed (rout web passwd) while this request waited for a
	// hashing slot or was hashing: the answer only counts for the password that is current now.
	if !s.passwordUnchanged(cfg) {
		return &apiError{Status: http.StatusConflict, Code: "password_changed", Msg: "管理密码刚刚被更改，请重新输入"}
	}
	s.limiter.success(ip)
	return nil
}

// passwordUnchanged reads the configuration afresh (not through the short-lived cache) and
// reports whether it still holds the password hash that was verified.
func (s *WebServer) passwordUnchanged(verified WebConfig) bool {
	cur, e := s.a.LoadWebConfig()
	return e == nil && cur.PasswordHash == verified.PasswordHash && cur.PasswordChangedAt.Equal(verified.PasswordChangedAt)
}

func (s *WebServer) apiLogin(c *reqCtx) (any, error) {
	cfg, e := s.config()
	if e != nil {
		return nil, e
	}
	var req passwordReq
	if e := c.decode(&req); e != nil {
		return nil, e
	}
	if e := s.checkPassword(c, cfg, req.Password); e != nil {
		return nil, e
	}
	token, sess := s.sessions.create(clientIP(c.r), c.r.UserAgent())
	if !s.passwordUnchanged(cfg) {
		// Changed between the check and the session: never hand out a session for the old password.
		s.sessions.destroy(token)
		return nil, &apiError{Status: http.StatusConflict, Code: "password_changed", Msg: "管理密码刚刚被更改，请重新输入"}
	}
	s.setCookie(c.w, c.r, cfg, token, cfg.maxAge())
	s.audit.add(s.now(), clientIP(c.r), "login")
	return map[string]any{"csrf": sess.CSRF, "session_id": sess.ID, "version": Version}, nil
}

func (s *WebServer) apiLogout(c *reqCtx) (any, error) {
	cfg, _ := s.config()
	s.sessions.destroy(c.token)
	s.clearCookie(c.w, c.r, cfg)
	return nil, nil
}

func (s *WebServer) apiReauth(c *reqCtx) (any, error) {
	cfg, e := s.config()
	if e != nil {
		return nil, e
	}
	var req passwordReq
	if e := c.decode(&req); e != nil {
		return nil, e
	}
	if e := s.checkPassword(c, cfg, req.Password); e != nil {
		return nil, e
	}
	until := s.now().Add(webReauthWindow)
	s.sessions.update(c.token, func(ss *webSession) { ss.ReauthUntil = until })
	return map[string]any{"until": until}, nil
}

type sessionView struct {
	ID       string    `json:"id"`
	Created  time.Time `json:"created_at"`
	LastSeen time.Time `json:"last_seen"`
	IP       string    `json:"ip"`
	Agent    string    `json:"agent"`
	Current  bool      `json:"current"`
}

func (s *WebServer) apiSessions(c *reqCtx) (any, error) {
	out := []sessionView{}
	for _, v := range s.sessions.list() {
		agent := v.Agent
		if len(agent) > 120 {
			agent = agent[:120]
		}
		out = append(out, sessionView{ID: v.ID, Created: v.Created, LastSeen: v.LastSeen, IP: v.IP, Agent: agent, Current: v.ID == c.sess.ID})
	}
	return map[string]any{"sessions": out}, nil
}

func (s *WebServer) apiRevokeSession(c *reqCtx) (any, error) {
	id := c.r.PathValue("sid")
	if !sessionIDPattern.MatchString(id) {
		return nil, errNotFound("找不到会话")
	}
	if !s.sessions.revoke(id) {
		return nil, errNotFound("找不到会话")
	}
	return nil, nil
}

func (s *WebServer) apiRevokeOthers(c *reqCtx) (any, error) {
	return map[string]int{"revoked": s.sessions.revokeAllExcept(c.token)}, nil
}

// ---- overview --------------------------------------------------------------------------

type Alert struct {
	Level   string `json:"level"` // info, warn, error
	Code    string `json:"code"`
	Subject string `json:"subject,omitempty"`
	Detail  string `json:"detail,omitempty"`
	Link    string `json:"link,omitempty"` // UI page the alert belongs to
}

type CertItem struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Days       int    `json:"days"`
	SelfSigned bool   `json:"self_signed"`
}

type QuotaItem struct {
	Kind  string     `json:"kind"` // node or subscription
	ID    string     `json:"id"`
	Name  string     `json:"name"`
	Used  uint64     `json:"used"`
	Limit uint64     `json:"limit"`
	Left  uint64     `json:"left"`
	Next  *time.Time `json:"next_reset,omitempty"`
}

type CountSet struct {
	Total    int `json:"total"`
	Running  int `json:"running"`
	Stopped  int `json:"stopped"`
	Disabled int `json:"disabled"`
}

type TopNode struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Up    uint64 `json:"up"`
	Down  uint64 `json:"down"`
	Total uint64 `json:"total"`
}

type Overview struct {
	Version string    `json:"version"`
	System  SysInfo   `json:"system"`
	Network PublicIPs `json:"network"`
	Counts  struct {
		Nodes         CountSet `json:"nodes"`
		Relays        CountSet `json:"relays"`
		Exits         int      `json:"exits"`
		Subscriptions int      `json:"subscriptions"`
		Aggregates    int      `json:"aggregates"`
		Sources       int      `json:"sources"`
		SourcesOK     int      `json:"sources_ok"`
		SourcesFailed int      `json:"sources_failed"`
		RemoteNodes   int      `json:"remote_nodes"`
	} `json:"counts"`
	Traffic struct {
		Monitoring bool      `json:"monitoring"`
		Up         uint64    `json:"up"`
		Down       uint64    `json:"down"`
		Total      uint64    `json:"total"`
		Top        []TopNode `json:"top"`
	} `json:"traffic"`
	Certs  []CertItem  `json:"certs"`
	Quotas []QuotaItem `json:"quotas"`
	Alerts []Alert     `json:"alerts"`
	Server struct {
		Enabled bool `json:"enabled"`
		Running bool `json:"running"`
		Managed bool `json:"managed"`
	} `json:"subscription_server"`
	Update updateInfo `json:"update"`
}

// trafficViews reads the traffic database once for a list of nodes. The per-node meter read
// is cached for a few seconds so refreshing the page does not run a command per node each time.
func (s *WebServer) trafficViews(a *App, nodes []Profile) (map[string]TrafficView, bool) {
	out := map[string]TrafficView{}
	if !a.trafficActive() {
		return out, false
	}
	db, e := a.loadTraffic()
	if e != nil {
		return out, false
	}
	now := s.now()
	for _, p := range nodes {
		s.trMu.Lock()
		ent, ok := s.trCache[p.ID]
		s.trMu.Unlock()
		if ok && now.Sub(ent.at) < 5*time.Second && ent.v.Limit == p.trafficPolicy().LimitBytes {
			out[p.ID] = ent.v
			continue
		}
		v := a.nodeTrafficFrom(db, p)
		s.trMu.Lock()
		s.trCache[p.ID] = trafficEntry{at: now, v: v}
		s.trMu.Unlock()
		out[p.ID] = v
	}
	return out, true
}

func (s *WebServer) apiOverview(c *reqCtx) (any, error) {
	st, e := c.a.Load()
	if e != nil {
		return nil, e
	}
	now := s.now()
	var o Overview
	o.Version = Version
	o.System = s.metrics.snapshot()
	o.Network = s.publicIPs()
	o.Update = s.updateStatus(c.r.Context(), false)
	o.Certs, o.Quotas, o.Alerts = []CertItem{}, []QuotaItem{}, []Alert{}
	o.Traffic.Top = []TopNode{}

	nodes := sortedProfiles(st, "node")
	relays := sortedProfiles(st, "relay")
	tv, monitoring := s.trafficViews(c.a, nodes)
	o.Traffic.Monitoring = monitoring
	count := func(set *CountSet, p Profile, state string) {
		set.Total++
		switch state {
		case "running":
			set.Running++
		case "disabled":
			set.Disabled++
		case "unmanaged", "unknown":
		default:
			set.Stopped++
		}
	}
	for _, p := range nodes {
		t, has := tv[p.ID]
		var tp *TrafficView
		if has {
			tp = &t
		}
		v := c.a.nodeView(st, p, now, tp)
		count(&o.Counts.Nodes, p, v.State)
		for _, w := range v.Warnings {
			lvl := "warn"
			if w == "cert_expired" || w == "service_down" || w == "quota_reached" {
				lvl = "error"
			}
			o.Alerts = append(o.Alerts, Alert{Level: lvl, Code: w, Subject: p.Name, Link: "nodes"})
		}
		if v.Cert != nil {
			o.Certs = append(o.Certs, CertItem{ID: p.ID, Name: p.Name, Days: v.Cert.Days, SelfSigned: v.Cert.SelfSigned})
		}
		if has && t.Active {
			o.Traffic.Up += t.Up
			o.Traffic.Down += t.Down
			o.Traffic.Total += t.Total
			o.Traffic.Top = append(o.Traffic.Top, TopNode{ID: p.ID, Name: p.Name, Up: t.Up, Down: t.Down, Total: t.Total})
		}
		if has && t.Limit > 0 {
			q := QuotaItem{Kind: "node", ID: p.ID, Name: p.Name, Used: t.Total, Limit: t.Limit, Left: t.Left, Next: t.Next}
			o.Quotas = append(o.Quotas, q)
		}
	}
	for _, p := range relays {
		v := c.a.nodeView(st, p, now, nil)
		count(&o.Counts.Relays, p, v.State)
		for _, w := range v.Warnings {
			if w == "service_down" {
				o.Alerts = append(o.Alerts, Alert{Level: "error", Code: w, Subject: p.Name, Link: "relays"})
			}
		}
	}
	sort.Slice(o.Traffic.Top, func(i, j int) bool { return o.Traffic.Top[i].Total > o.Traffic.Top[j].Total })
	if len(o.Traffic.Top) > 5 {
		o.Traffic.Top = o.Traffic.Top[:5]
	}
	o.Counts.Exits = len(st.Exits)

	for _, sub := range st.Subscriptions {
		o.Counts.Subscriptions++
		if sub.aggregate() {
			o.Counts.Aggregates++
		}
		if pv, ok := c.a.SubscriptionUsage(sub, now); ok && pv.Plan.LimitBytes > 0 {
			q := QuotaItem{Kind: "subscription", ID: sub.ID, Name: sub.Name, Used: pv.Used, Limit: pv.Plan.LimitBytes, Left: pv.remaining()}
			if !pv.Next.IsZero() {
				n := pv.Next
				q.Next = &n
			}
			o.Quotas = append(o.Quotas, q)
			if q.Left == 0 {
				o.Alerts = append(o.Alerts, Alert{Level: "error", Code: "subscription_quota_reached", Subject: sub.Name, Link: "subscriptions"})
			} else if q.Left*10 < q.Limit {
				o.Alerts = append(o.Alerts, Alert{Level: "warn", Code: "subscription_quota_low", Subject: sub.Name, Link: "subscriptions"})
			}
		}
	}
	if srcs, er := c.a.RemoteSources(); er == nil {
		for _, sv := range srcs {
			o.Counts.Sources++
			o.Counts.RemoteNodes += sv.Valid
			switch sv.Status.State {
			case "ok":
				o.Counts.SourcesOK++
			case "error":
				o.Counts.SourcesFailed++
				if sv.Enabled {
					o.Alerts = append(o.Alerts, Alert{Level: "warn", Code: "source_refresh_failed", Subject: sv.Name, Detail: sv.Status.LastError, Link: "sources"})
				}
			}
		}
	}
	if ss, er := c.a.SubscriptionServerStatus(); er == nil {
		o.Server.Enabled, o.Server.Running, o.Server.Managed = ss.Settings.Enabled, ss.Running, ss.Managed
		if ss.Settings.Enabled && ss.Managed && !ss.Running {
			o.Alerts = append(o.Alerts, Alert{Level: "error", Code: "subscription_server_down", Link: "system"})
		}
	}
	sys := o.System
	if sys.DiskTotal > 0 && sys.DiskUsed*100 >= sys.DiskTotal*90 {
		o.Alerts = append(o.Alerts, Alert{Level: "warn", Code: "disk_high", Link: "system"})
	}
	if sys.MemTotal > 0 && sys.MemUsed*100 >= sys.MemTotal*92 {
		o.Alerts = append(o.Alerts, Alert{Level: "warn", Code: "memory_high", Link: "system"})
	}
	if o.Update.Available {
		o.Alerts = append(o.Alerts, Alert{Level: "info", Code: "update_available", Detail: o.Update.Latest, Link: "system"})
	}
	cfg, _ := s.config()
	if !requestIsSecure(c.r, cfg.SecureCookie) && !isLoopbackHost(hostOf(c.r.Host)) {
		o.Alerts = append(o.Alerts, Alert{Level: "error", Code: "insecure_transport", Link: "system"})
	}
	sort.SliceStable(o.Alerts, func(i, j int) bool { return alertRank(o.Alerts[i].Level) < alertRank(o.Alerts[j].Level) })
	return o, nil
}

func alertRank(l string) int {
	switch l {
	case "error":
		return 0
	case "warn":
		return 1
	}
	return 2
}

func trimLower(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

func readAllLimit(r io.Reader, max int64) ([]byte, error) { return io.ReadAll(io.LimitReader(r, max)) }
