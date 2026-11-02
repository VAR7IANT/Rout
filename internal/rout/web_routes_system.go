package rout

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type ServiceItem struct {
	Unit  string `json:"unit"`
	Kind  string `json:"kind"` // subscription, web, node, relay
	Name  string `json:"name"`
	State string `json:"state"`
}

type SystemView struct {
	Version string     `json:"version"`
	Update  updateInfo `json:"update"`
	Runtime struct {
		OS   string `json:"os"`
		Arch string `json:"arch"`
		Go   string `json:"go"`
		Init string `json:"init"`
	} `json:"runtime"`
	System   SysInfo       `json:"system"`
	Services []ServiceItem `json:"services"`
	Web      struct {
		Port              int        `json:"port"`
		AllowedHosts      []string   `json:"allowed_hosts"`
		SessionIdleMin    int        `json:"session_idle_min"`
		SessionMaxHours   int        `json:"session_max_hours"`
		SecureCookie      bool       `json:"secure_cookie"`
		HTTPSDomain       string     `json:"https_domain,omitempty"`
		PasswordSet       bool       `json:"password_set"`
		PasswordChangedAt *time.Time `json:"password_changed_at,omitempty"`
		SecureRequest     bool       `json:"secure_request"`
	} `json:"web"`
	Subscription struct {
		Enabled       bool   `json:"enabled"`
		Running       bool   `json:"running"`
		Managed       bool   `json:"managed"`
		Port          int    `json:"port"`
		PublicURL     string `json:"public_url,omitempty"`
		MihomoTestURL string `json:"mihomo_test_url,omitempty"`
	} `json:"subscription"`
	Permissions []PermissionCheck `json:"permissions"`
}

func (s *WebServer) apiSystem(c *reqCtx) (any, error) {
	st, e := c.a.Load()
	if e != nil {
		return nil, e
	}
	cfg, _ := s.config()
	var v SystemView
	v.Version = Version
	v.Update = s.updateStatus(c.r.Context(), false)
	v.Runtime.OS, v.Runtime.Arch, v.Runtime.Go = runtime.GOOS, runtime.GOARCH, runtime.Version()
	if m, er := c.a.serviceManager(); er == nil {
		v.Runtime.Init = m
	} else {
		v.Runtime.Init = "unavailable"
	}
	v.System = s.metrics.snapshot()
	v.System.History = nil
	v.Services = []ServiceItem{}
	for _, kind := range []string{"node", "relay"} {
		for _, p := range sortedProfiles(st, kind) {
			v.Services = append(v.Services, ServiceItem{Unit: p.ID, Kind: kind, Name: p.Name, State: c.a.serviceStateOf(p)})
		}
	}
	ss, er := c.a.SubscriptionServerStatus()
	if er == nil {
		v.Subscription.Enabled, v.Subscription.Running, v.Subscription.Managed = ss.Settings.Enabled, ss.Running, ss.Managed
		v.Subscription.Port, v.Subscription.PublicURL = ss.Settings.listenPort(), ss.Settings.PublicURL
		v.Subscription.MihomoTestURL = ss.Settings.mihomoTestURL()
		state := "stopped"
		switch {
		case !ss.Settings.Enabled:
			state = "disabled"
		case !ss.Managed:
			state = "unmanaged"
		case ss.Running:
			state = "running"
		}
		v.Services = append([]ServiceItem{{Unit: "subscription", Kind: "subscription", Name: "subscription", State: state}}, v.Services...)
	}
	v.Services = append([]ServiceItem{{Unit: "web", Kind: "web", Name: "web", State: "running"}}, v.Services...)
	v.Web.Port, v.Web.SessionIdleMin, v.Web.SessionMaxHours = cfg.port(), int(cfg.idle().Minutes()), int(cfg.maxAge().Hours())
	v.Web.AllowedHosts = append([]string{}, cfg.AllowedHosts...)
	v.Web.SecureCookie, v.Web.HTTPSDomain, v.Web.PasswordSet = cfg.SecureCookie, cfg.HTTPSDomain, cfg.PasswordHash != ""
	if !cfg.PasswordChangedAt.IsZero() {
		t := cfg.PasswordChangedAt
		v.Web.PasswordChangedAt = &t
	}
	v.Web.SecureRequest = requestIsSecure(c.r, cfg.SecureCookie)
	v.Permissions = c.a.CheckPermissions()
	return v, nil
}

type settingsPatch struct {
	AllowedHosts    *[]string `json:"allowed_hosts"`
	SessionIdleMin  *int      `json:"session_idle_min"`
	SessionMaxHours *int      `json:"session_max_hours"`
	SecureCookie    *bool     `json:"secure_cookie"`
	Port            *int      `json:"port"`
}

func (s *WebServer) apiSettings(c *reqCtx) (any, error) {
	var req settingsPatch
	if e := c.decode(&req); e != nil {
		return nil, e
	}
	restart := false
	e := c.a.mutateWebConfig(func(w *WebConfig) error {
		if req.AllowedHosts != nil {
			hosts := []string{}
			for _, h := range *req.AllowedHosts {
				n, er := normalizeWebHost(h)
				if er != nil {
					return er
				}
				hosts = append(hosts, n)
			}
			w.AllowedHosts = hosts
		}
		if req.SessionIdleMin != nil {
			w.SessionIdleMin = *req.SessionIdleMin
		}
		if req.SessionMaxHours != nil {
			w.SessionMaxHours = *req.SessionMaxHours
		}
		if req.SecureCookie != nil {
			w.SecureCookie = *req.SecureCookie
		}
		if req.Port != nil && *req.Port != w.port() {
			w.Port = *req.Port
			restart = true
		}
		return nil
	})
	if e != nil {
		return nil, e
	}
	s.invalidateConfig()
	return map[string]bool{"restart_required": restart}, nil
}

// ---- logs ------------------------------------------------------------------------------

var (
	logUUID   = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
	logSecret = regexp.MustCompile(`[A-Za-z0-9+/_=-]{32,}`)
	logPass   = regexp.MustCompile(`(?i)("?(?:password|passwd|secret|token|private[_-]?key|uuid|auth)"?\s*[:=]\s*)("[^"]*"|\S+)`)
)

// redactLog removes what must never reach a browser from service output: URLs (which carry
// subscription keys), subscription tokens, UUIDs and anything shaped like a key.
func redactLog(s string) string {
	s = sanitizeSubscriptionLogs([]byte(s))
	s = urlInText.ReplaceAllString(s, "[url]")
	s = logUUID.ReplaceAllString(s, "[uuid]")
	s = logPass.ReplaceAllString(s, "${1}[redacted]")
	s = logSecret.ReplaceAllString(s, "[redacted]")
	return s
}

func tailText(b []byte, lines int) string {
	if len(b) > 256<<10 {
		b = b[len(b)-256<<10:]
	}
	parts := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(parts) > lines {
		parts = parts[len(parts)-lines:]
	}
	return strings.Join(parts, "\n")
}

// serviceLog returns the recent output of one of Rout's own units. unit is "subscription",
// "web" or a profile ID; nothing else is ever put on a command line.
func (a *App) serviceLog(st State, unit string, lines int) (string, error) {
	var name string
	switch {
	case unit == "subscription":
		name = a.subscriptionService()
	case unit == "web":
		name = a.webService()
	case idPattern.MatchString(unit):
		p, e := Find(st, unit)
		if e != nil {
			return "", errNotFound("找不到对象")
		}
		name = serviceName(p)
	default:
		return "", errBad("未知的服务")
	}
	m, e := a.serviceManager()
	if e != nil {
		return "", e
	}
	var raw []byte
	switch m {
	case "systemd":
		raw, e = runOutput(8*time.Second, "journalctl", "-u", name, "-n", strconv.Itoa(lines), "--no-pager", "-o", "short-iso")
		if e != nil {
			return "", fmt.Errorf("无法读取服务日志")
		}
	case "openrc":
		f, er := os.Open("/var/log/" + name + ".log")
		if er != nil {
			return "", fmt.Errorf("无法读取服务日志")
		}
		defer f.Close()
		if st, er := f.Stat(); er == nil && st.Size() > 256<<10 {
			_, _ = f.Seek(-(256 << 10), 2)
		}
		raw, _ = readAllLimit(f, 256<<10)
	default:
		return "", errConflict("当前环境没有受管理的服务日志")
	}
	return redactLog(tailText(raw, lines)), nil
}

type serviceReq struct {
	Unit   string `json:"unit"`
	Action string `json:"action"`
}

func (s *WebServer) apiService(c *reqCtx) (any, error) {
	var req serviceReq
	if e := c.decode(&req); e != nil {
		return nil, e
	}
	switch {
	case req.Unit == "subscription":
		switch req.Action {
		case "start":
			return nil, c.a.RefreshSubscriptionServer()
		case "restart":
			return nil, c.a.RestartSubscriptionServer()
		case "stop":
			if e := c.needReauth(); e != nil {
				return nil, e
			}
			return nil, c.a.StopSubscriptionServer()
		}
		return nil, errBad("不支持的服务操作")
	case idPattern.MatchString(req.Unit):
		if req.Action != "restart" {
			return nil, errBad("节点与中转请使用启用／停用，或重启")
		}
		st, e := c.a.Load()
		if e != nil {
			return nil, e
		}
		p, e := Find(st, req.Unit)
		if e != nil {
			return nil, errNotFound("找不到对象")
		}
		if !p.Enabled {
			return nil, errConflict("对象已停用，请先启用")
		}
		defer s.changed()
		return nil, c.a.Restart(req.Unit)
	}
	return nil, errBad("未知的服务")
}

// ---- HTTPS -----------------------------------------------------------------------------

type HTTPSView struct {
	Domain       string `json:"domain"`
	Installed    bool   `json:"installed"`
	Running      bool   `json:"running"`
	LocalRunning bool   `json:"local_running"`
	RouteFound   bool   `json:"route_found"`
	RouteOK      bool   `json:"route_ok"`
	Conflict     bool   `json:"route_conflict"`
	Ownership    string `json:"ownership,omitempty"`
	Renewal      string `json:"renewal,omitempty"`
	LastError    string `json:"last_error,omitempty"`
	DNS          struct {
		A       []string `json:"a"`
		AAAA    []string `json:"aaaa"`
		Matched bool     `json:"matched"`
		Proxied bool     `json:"proxied"`
		Unsure  bool     `json:"uncertain"`
	} `json:"dns"`
	Verified struct {
		LocalService bool       `json:"local_service"`
		LocalTLS     bool       `json:"local_tls"`
		Public       bool       `json:"public_from_host"`
		External     bool       `json:"external"`
		CertError    bool       `json:"certificate_error"`
		Expires      *time.Time `json:"expires,omitempty"`
		Error        string     `json:"error,omitempty"`
	} `json:"verification"`
	Issues []string `json:"issues"`
}

func (s *WebServer) apiHTTPS(c *reqCtx) (any, error) {
	type result struct {
		r SubscriptionHTTPSReport
		e error
	}
	done := make(chan result, 1)
	go func() {
		r, e := c.a.HTTPSDiagnostics()
		done <- result{r, e}
	}()
	var res result
	select {
	case res = <-done:
	case <-time.After(60 * time.Second):
		return nil, errConflict("HTTPS 检查超时")
	case <-c.r.Context().Done():
		return nil, errBad("请求已取消")
	}
	if res.e != nil {
		return nil, res.e
	}
	r := res.r
	var v HTTPSView
	v.Domain, v.Installed, v.Running, v.LocalRunning = r.Domain, r.Installed, r.Running, r.LocalRunning
	v.RouteFound, v.RouteOK, v.Conflict = r.Route.Found, r.Route.Correct, r.Route.Conflict
	v.Ownership, v.Renewal, v.LastError = r.Ownership, r.Renewal, urlInText.ReplaceAllString(c.a.T(r.LastError), "…")
	v.DNS.A, v.DNS.AAAA = append([]string{}, r.DNS.A...), append([]string{}, r.DNS.AAAA...)
	v.DNS.Matched, v.DNS.Proxied, v.DNS.Unsure = r.DNS.Matched, r.DNS.Cloudflare, r.DNS.Uncertain
	vf := r.Verification
	v.Verified.LocalService, v.Verified.LocalTLS, v.Verified.Public, v.Verified.External, v.Verified.CertError = vf.LocalService, vf.LocalTLS, vf.PublicFromHost, vf.External, vf.CertificateError
	if !vf.Expires.IsZero() {
		t := vf.Expires
		v.Verified.Expires = &t
	}
	v.Verified.Error = urlInText.ReplaceAllString(c.a.T(vf.Error), "…")
	v.Issues = []string{}
	for _, is := range r.Issues {
		v.Issues = append(v.Issues, urlInText.ReplaceAllString(c.a.T(is), "…"))
	}
	return v, nil
}

// ---- backup / restore ------------------------------------------------------------------

type restoreReq struct {
	Backup  json.RawMessage `json:"backup"`
	DryRun  bool            `json:"dry_run"`
	Confirm string          `json:"confirm"`
}

func (s *WebServer) apiRestore(c *reqCtx) (any, error) {
	var req restoreReq
	if e := c.decode(&req); e != nil {
		return nil, e
	}
	p, e := ParseBackup(req.Backup)
	if e != nil {
		return nil, e
	}
	plan, e := c.a.PlanRestore(p)
	if e != nil {
		return nil, e
	}
	if req.DryRun {
		return map[string]any{"plan": plan, "applied": false}, nil
	}
	if req.Confirm != "RESTORE" {
		return nil, errBad("请输入 RESTORE 以确认恢复")
	}
	if e := c.a.RestoreBackup(p); e != nil {
		return nil, e
	}
	s.changed()
	s.audit.add(s.now(), clientIP(c.r), "restore backup")
	fixed := c.a.FixPermissions()
	return map[string]any{"plan": plan, "applied": true, "permissions_fixed": fixed}, nil
}

func (s *WebServer) systemRoutes() {
	r := routeOpts{}
	rr := routeOpts{reauth: true}
	s.handle("GET /api/system", r, s.apiSystem)
	s.handle("POST /api/system/update-check", r, func(c *reqCtx) (any, error) {
		return s.updateStatus(c.r.Context(), true), nil
	})
	s.handle("GET /api/system/network", r, func(c *reqCtx) (any, error) { return s.networkView(c.r.Context()), nil })
	s.handle("GET /api/system/https", r, s.apiHTTPS)
	s.handle("GET /api/system/logs", r, func(c *reqCtx) (any, error) {
		unit := c.r.URL.Query().Get("unit")
		lines := 100
		if v := c.r.URL.Query().Get("lines"); v != "" {
			n, e := strconv.Atoi(v)
			if e != nil || n < 10 || n > 500 {
				return nil, errBad("行数应在 10 到 500 之间")
			}
			lines = n
		}
		st, e := c.a.Load()
		if e != nil {
			return nil, e
		}
		text, e := c.a.serviceLog(st, unit, lines)
		if e != nil {
			return nil, e
		}
		return map[string]string{"log": text}, nil
	})
	s.handle("POST /api/system/service", r, s.apiService)
	s.handle("PATCH /api/system/settings", rr, s.apiSettings)
	s.handle("GET /api/system/permissions", r, func(c *reqCtx) (any, error) {
		return map[string]any{"checks": c.a.CheckPermissions()}, nil
	})
	s.handle("POST /api/system/permissions/fix", rr, func(c *reqCtx) (any, error) {
		return map[string]int{"fixed": c.a.FixPermissions()}, nil
	})
	s.handle("GET /api/system/backup", rr, func(c *reqCtx) (any, error) {
		raw, e := c.a.EncodeBackup(s.now())
		if e != nil {
			return nil, e
		}
		s.audit.add(s.now(), clientIP(c.r), "download backup")
		return &rawResponse{ContentType: "application/json", Filename: "rout-backup-" + s.now().UTC().Format("20060102-150405") + ".json", Body: raw}, nil
	})
	s.handle("POST /api/system/restore", routeOpts{reauth: true, body: backupMaxSize + 4096}, s.apiRestore)
}

var _ = context.Background
var _ = http.StatusOK
