package rout

import (
	"context"
	"strconv"
	"strings"
	"time"
)

// Panel API for the Telegram Bot binding. The Bot Token is write-only: it is accepted by bind,
// probe and the credentials change, and no response, log or audit entry ever contains it.
// Anything that changes who can control this server needs the password re-confirmed.

type telegramServerView struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Self        bool   `json:"self"`
	Online      bool   `json:"online"`
	LastSeen    string `json:"last_seen,omitempty"`
	Fingerprint string `json:"fingerprint"`
	Version     string `json:"version,omitempty"`
	AIEnabled   *bool  `json:"ai_enabled,omitempty"`
	ExitName    string `json:"exit_name,omitempty"`
}

type telegramPendingView struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint"`
	RequestedAt string `json:"requested_at"`
}

type telegramConnView struct {
	State  string `json:"state"`
	Detail string `json:"detail,omitempty"`
	LastOK string `json:"last_ok,omitempty"`
}

type telegramHubView struct {
	Endpoints   []string `json:"endpoints"`
	Fingerprint string   `json:"fingerprint"`
	MultiServer bool     `json:"multi_server"`
	Port        int      `json:"port"`
}

type telegramFollowView struct {
	Endpoints   []string `json:"endpoints"`
	Fingerprint string   `json:"fingerprint"`
}

type telegramView struct {
	Bound       bool                  `json:"bound"`
	Role        string                `json:"role,omitempty"`
	ServerID    string                `json:"server_id,omitempty"`
	ServerName  string                `json:"server_name,omitempty"`
	BotUsername string                `json:"bot_username,omitempty"`
	ChatMasked  string                `json:"chat_id_masked,omitempty"`
	Fingerprint string                `json:"fingerprint,omitempty"`
	Service     map[string]bool       `json:"service"`
	Connection  telegramConnView      `json:"connection"`
	Hub         *telegramHubView      `json:"hub,omitempty"`
	Follows     *telegramFollowView   `json:"follows,omitempty"`
	Servers     []telegramServerView  `json:"servers"`
	Pending     []telegramPendingView `json:"pending"`
	Audit       []string              `json:"audit"`
}

// telegramConnState maps the service's runtime state onto what the page shows.
func telegramConnState(a *App, sum TelegramSummary) telegramConnView {
	rt := sum.Runtime
	v := telegramConnView{State: "starting"}
	if rt == nil || rt.State == "" {
		if sum.Service.Managed && !sum.Service.Installed {
			v.State = "stopped"
		} else if sum.Service.Installed && !sum.Service.Running {
			v.State = "stopped"
		}
		return v
	}
	v.Detail = a.T(rt.Detail)
	switch rt.State {
	case tgStateOK:
		v.State = "connected"
		v.LastOK = rt.UpdatedAt.UTC().Format(time.RFC3339)
	case tgStateConnecting:
		v.State = "connecting"
	case tgStateOffline:
		v.State = "connecting"
	case tgStatePending:
		v.State = "pending"
	case tgStateRevoked:
		v.State = "revoked"
	case tgStateStopped:
		v.State = "stopped"
	default: // error, conflict, hub_changed
		v.State = "error"
	}
	// A state older than the service's own update cadence means the service is not running.
	if sum.Service.Managed && sum.Service.Installed && !sum.Service.Running {
		v.State, v.Detail = "stopped", ""
	}
	return v
}

func (s *WebServer) telegramView(c *reqCtx) (telegramView, error) {
	a := c.a
	sum, e := a.TelegramSummary()
	if e != nil {
		return telegramView{}, e
	}
	v := telegramView{Bound: sum.Bound, Servers: []telegramServerView{}, Pending: []telegramPendingView{}, Audit: []string{},
		Service: map[string]bool{"installed": sum.Service.Installed, "running": sum.Service.Running, "managed": sum.Service.Managed}}
	if !sum.Bound {
		v.Connection = telegramConnView{State: "unbound"}
		return v, nil
	}
	v.Role, v.ServerID, v.ServerName, v.BotUsername, v.ChatMasked, v.Fingerprint = sum.Role, sum.ServerID, sum.Name, sum.BotUser, sum.ChatMasked, sum.Fingerprint
	v.Connection = telegramConnState(a, sum)
	v.Audit = a.telegramAuditTail(100)
	for i, d := range v.Audit {
		v.Audit[i] = tgScrub(d, 240)
	}
	switch sum.Role {
	case tgRoleHub:
		// The address agents are told to dial comes from what the service announced (or the
		// manual list): the panel refreshes every few seconds and must never look up this
		// server's public address, or start a service query per node, on each refresh.
		eps := append([]string(nil), sum.Advertise...)
		if len(eps) == 0 && sum.Runtime != nil {
			eps = append(eps, sum.Runtime.Endpoints...)
		}
		if !sum.MultiServer {
			eps = nil
		}
		if eps == nil {
			eps = []string{}
		}
		v.Hub = &telegramHubView{Endpoints: eps, Fingerprint: sum.Fingerprint, MultiServer: sum.MultiServer, Port: sum.Port}
		self := telegramServerView{ID: sum.ServerID, Name: sum.Name, Self: true, Online: true, Fingerprint: sum.Fingerprint, Version: Version}
		if st, er := a.Load(); er == nil {
			ai := a.aiSummary(st)
			en := ai.Config.Enabled
			self.AIEnabled, self.ExitName = &en, ai.ExitName
		}
		v.Servers = append(v.Servers, self)
		known := map[string]TelegramRuntimeServer{}
		if sum.Runtime != nil {
			for _, rs := range sum.Runtime.Servers {
				known[rs.ID] = rs
			}
		}
		for _, ag := range sum.Agents {
			sv := telegramServerView{ID: ag.ID, Name: ag.Name, Fingerprint: ag.FP, Online: ag.Online}
			if rs, ok := known[ag.ID]; ok {
				sv.Version, sv.ExitName = rs.Version, rs.ExitName
				en := rs.AIEnabled
				sv.AIEnabled = &en
				if !rs.LastSeen.IsZero() {
					sv.LastSeen = rs.LastSeen.UTC().Format(time.RFC3339)
				}
			}
			v.Servers = append(v.Servers, sv)
		}
		for _, p := range sum.Pending {
			v.Pending = append(v.Pending, telegramPendingView{ID: p.ID, Name: p.Name, Fingerprint: p.FP, RequestedAt: p.RequestedAt.UTC().Format(time.RFC3339)})
		}
	case tgRoleAgent:
		v.Follows = &telegramFollowView{Endpoints: sum.HubEndpoints, Fingerprint: sum.HubFP}
		if v.Follows.Endpoints == nil {
			v.Follows.Endpoints = []string{}
		}
	}
	return v, nil
}

type telegramProbeReq struct {
	Token  string `json:"token"`
	ChatID string `json:"chat_id"`
}

type telegramBindReq struct {
	Token         string `json:"token"`
	ChatID        string `json:"chat_id"`
	ServerName    string `json:"server_name"`
	Role          string `json:"role"`
	TrustHubFP    string `json:"trust_hub_fp"`
	MultiServer   bool   `json:"multi_server"`
	DeleteWebhook bool   `json:"delete_webhook"`
}

type telegramPatchReq struct {
	ServerName  *string `json:"server_name"`
	Token       *string `json:"token"`
	ChatID      *string `json:"chat_id"`
	MultiServer *bool   `json:"multi_server"`
}

func parseWebChatID(s string) (int64, error) {
	n, e := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if e != nil || n <= 0 {
		return 0, errBad(errNeedPrivate.Error())
	}
	return n, nil
}

func (s *WebServer) telegramRoutes() {
	r := routeOpts{}
	rr := routeOpts{reauth: true}
	view := func(c *reqCtx) (any, error) { return s.telegramView(c) }
	s.handle("GET /api/telegram", r, view)

	s.handle("POST /api/telegram/probe", rr, func(c *reqCtx) (any, error) {
		var req telegramProbeReq
		if e := c.decode(&req); e != nil {
			return nil, e
		}
		chat, e := parseWebChatID(req.ChatID)
		if e != nil {
			return nil, e
		}
		res, e := c.a.TelegramProbe(c.r.Context(), req.Token, chat)
		if e != nil {
			return nil, e
		}
		hub := map[string]any{"found": false}
		if res.HubFound {
			hub = map[string]any{"found": true, "endpoints": res.Endpoints, "fingerprint": res.HubFP, "hub_name": res.HubName}
		}
		return map[string]any{"bot_username": res.BotUser, "suggested_name": res.SuggestedName, "webhook_active": res.WebhookActive, "hub": hub}, nil
	})

	s.handle("POST /api/telegram/bind", rr, func(c *reqCtx) (any, error) {
		var req telegramBindReq
		if e := c.decode(&req); e != nil {
			return nil, e
		}
		chat, e := parseWebChatID(req.ChatID)
		if e != nil {
			return nil, e
		}
		if req.Role != tgRoleHub && req.Role != tgRoleAgent {
			return nil, errBad("角色无效")
		}
		if req.DeleteWebhook {
			// Rout never takes over a bot that another program is using.
			return nil, errBad("Rout 不会删除或覆盖机器人上已有的 webhook；请先在设置它的程序里移除，或换用专用机器人")
		}
		ctx, cancel := context.WithTimeout(c.r.Context(), 90*time.Second)
		defer cancel()
		res, e := c.a.TelegramBind(ctx, TelegramBindRequest{Token: req.Token, ChatID: chat, Name: req.ServerName, TrustHubFP: req.TrustHubFP})
		if e != nil {
			return nil, e
		}
		if res.NeedsTrust && req.Role == tgRoleHub {
			return nil, errConflict("这个机器人已经有控制中心；请改为加入它，或在服务器上用 rout telegram bind --hub 替换已废弃的控制中心")
		}
		if res.NeedsTrust {
			return nil, errBad("控制中心的证书指纹未确认，或与探测结果不一致")
		}
		if req.Role != res.Role {
			// The chat changed between the probe and the bind: undo rather than act differently.
			c.a.TelegramUnbind(ctx)
			return nil, errConflict("控制中心的状态在探测之后发生了变化，请重新探测后再绑定")
		}
		if res.Role == tgRoleHub && req.MultiServer {
			if e = c.a.TelegramSetMultiServer(true, 0, nil); e != nil {
				return nil, e
			}
		}
		if e = s.telegramInstall(c.a); e != nil {
			// The configuration is saved; the page shows the service state and the user can retry.
			s.logf("telegram service: %v", e)
		}
		s.changed()
		return view(c)
	})

	s.handle("PATCH /api/telegram", rr, func(c *reqCtx) (any, error) {
		var req telegramPatchReq
		if e := c.decode(&req); e != nil {
			return nil, e
		}
		if _, e := c.a.LoadTelegram(); e != nil {
			return nil, errNotFound(e.Error())
		}
		if req.ServerName != nil {
			if e := c.a.TelegramRename(*req.ServerName); e != nil {
				return nil, errBad(e.Error())
			}
		}
		if req.Token != nil || req.ChatID != nil {
			var tok string
			var chat int64
			if req.Token != nil {
				tok = *req.Token
			}
			if req.ChatID != nil && strings.TrimSpace(*req.ChatID) != "" {
				var e error
				if chat, e = parseWebChatID(*req.ChatID); e != nil {
					return nil, e
				}
			}
			ctx, cancel := context.WithTimeout(c.r.Context(), 90*time.Second)
			defer cancel()
			if _, e := c.a.TelegramSetCredentials(ctx, tok, chat); e != nil {
				return nil, e
			}
		}
		if req.MultiServer != nil {
			if e := c.a.TelegramSetMultiServer(*req.MultiServer, 0, nil); e != nil {
				return nil, e
			}
		}
		return view(c)
	})

	s.handle("POST /api/telegram/test", r, func(c *reqCtx) (any, error) {
		if _, e := c.a.LoadTelegram(); e != nil {
			return nil, errNotFound(e.Error())
		}
		ctx, cancel := context.WithTimeout(c.r.Context(), 90*time.Second)
		defer cancel()
		checks, e := c.a.TelegramTest(ctx)
		if e != nil {
			return nil, e
		}
		out := struct {
			OK    bool                `json:"ok"`
			Steps []map[string]string `json:"steps"`
		}{OK: true, Steps: []map[string]string{}}
		for _, ch := range checks {
			if ch.Level == "fail" {
				out.OK = false
			}
			out.Steps = append(out.Steps, map[string]string{"level": ch.Level, "text": tgScrub(ch.Text, 300, "")})
		}
		return out, nil
	})

	s.handle("POST /api/telegram/unbind", rr, func(c *reqCtx) (any, error) {
		ctx, cancel := context.WithTimeout(c.r.Context(), 60*time.Second)
		defer cancel()
		if _, e := c.a.TelegramUnbind(ctx); e != nil {
			return nil, e
		}
		s.changed()
		return view(c)
	})

	decide := func(approve bool) func(c *reqCtx) (any, error) {
		return func(c *reqCtx) (any, error) {
			id := c.r.PathValue("id")
			if len(id) != 12 || strings.Trim(id, "0123456789abcdef") != "" {
				return nil, errBad("请求 ID 无效")
			}
			cfg, e := c.a.LoadTelegram()
			if e != nil || cfg.Role != tgRoleHub {
				return nil, errNotFound("只有控制中心可以批准服务器")
			}
			hub := newTelegramHub(c.a)
			if approve {
				_, e = hub.approve(id)
			} else {
				_, e = hub.reject(id)
			}
			if e != nil {
				return nil, errNotFound(e.Error())
			}
			return view(c)
		}
	}
	s.handle("POST /api/telegram/pending/{id}/approve", rr, decide(true))
	s.handle("POST /api/telegram/pending/{id}/reject", rr, decide(false))

	s.handle("DELETE /api/telegram/servers/{id}", rr, func(c *reqCtx) (any, error) {
		id := c.r.PathValue("id")
		if !validServerID(id) {
			return nil, errBad("服务器 ID 无效")
		}
		cfg, e := c.a.LoadTelegram()
		if e != nil || cfg.Role != tgRoleHub {
			return nil, errNotFound("只有控制中心可以撤销服务器")
		}
		if id == cfg.ServerID {
			return nil, errBad("不能移除本机；如需停用请解绑")
		}
		if e = newTelegramHub(c.a).revoke(id); e != nil {
			return nil, errNotFound(e.Error())
		}
		return view(c)
	})
}

// telegramInstall starts the service; tests replace it.
func (s *WebServer) telegramInstall(a *App) error {
	if s.telegramSvc != nil {
		return s.telegramSvc("install")
	}
	return a.InstallTelegramService()
}
