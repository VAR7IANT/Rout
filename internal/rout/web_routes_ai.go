package rout

import (
	"context"
	"time"
)

// AI Smart Routing and panel HTTPS endpoints. Every mutation goes through the same App
// methods as the terminal menu, so both enforce identical validation and transactions.

type AINodeView struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Bound    bool   `json:"bound"`
	Eligible bool   `json:"eligible"`
	Running  string `json:"running"`
	InSync   bool   `json:"in_sync"`
	Note     string `json:"note,omitempty"`
	Exit     string `json:"exit"` // the node's ordinary route: exit name or "direct"
}

type AIView struct {
	Enabled          bool            `json:"enabled"`
	RuleSet          int             `json:"rule_set"`
	RuleSetAvailable int             `json:"rule_set_available"`
	ExitID           string          `json:"exit_id,omitempty"`
	Exit             *ExitView       `json:"exit,omitempty"`
	Problems         []string        `json:"problems"`
	Nodes            []AINodeView    `json:"nodes"`
	Exits            []ExitView      `json:"exits"`
	Relays           []RelayView     `json:"relays"`
	Services         []aiServiceView `json:"services"`
	Limits           []string        `json:"limits"`
}

// aiLimits are the identification boundaries stated next to every AI routing screen.
var aiLimits = []string{
	"只有勾选的入站节点参与 AI 分流；未绑定的节点完全不受影响",
	"按域名识别：优先匹配客户端提交的域名，IP 目标仅在 TLS SNI、HTTP Host 或受支持的 QUIC 中暴露域名时才能识别",
	"ECH、纯 IP 且无嗅探信息的连接以及隐藏目标的应用无法识别，会走原有路由；这不是零泄漏保证",
	"不劫持 DNS：客户端 DNS 查询保持原有路径",
	"AI 出口只转发 TCP：针对 AI 域名的 UDP（含 QUIC/HTTP3）会被拒绝，客户端可回退到 TCP",
	"AI 出口不可用时，AI 域名的连接会失败，不会改走原有出口",
	"SOCKS5 与 HTTP CONNECT 的认证和连接本身不加密；跨公网时请使用 HTTPS CONNECT、远程节点或 SSH 隧道",
}

func (s *WebServer) aiView(c *reqCtx) (AIView, error) {
	st, e := c.a.Load()
	if e != nil {
		return AIView{}, e
	}
	status, e := c.a.AIStatus()
	if e != nil {
		return AIView{}, e
	}
	v := AIView{Enabled: status.Config.Enabled, RuleSet: status.Config.RuleSetVersion, RuleSetAvailable: status.RuleSetAvailable, ExitID: status.Config.AIOutboundID,
		Problems: []string{}, Nodes: []AINodeView{}, Exits: []ExitView{}, Relays: []RelayView{}, Limits: []string{}}
	if v.RuleSet == 0 {
		v.RuleSet = AIRuleSetCurrent
	}
	v.Services = []aiServiceView{}
	for _, svc := range AIServices(v.RuleSet) {
		v.Services = append(v.Services, aiServiceView{Name: svc.Name, Suffixes: svc.Suffixes})
	}
	for _, p := range status.Problems {
		v.Problems = append(v.Problems, c.a.T(p))
	}
	for _, l := range aiLimits {
		v.Limits = append(v.Limits, c.a.T(l))
	}
	for _, n := range status.Nodes {
		p, _ := Find(st, n.ID)
		exit := "direct"
		if ex, er := FindExit(st, p.ExitID); er == nil {
			exit = ex.Name
		}
		v.Nodes = append(v.Nodes, AINodeView{ID: n.ID, Name: n.Name, Protocol: n.Protocol, Bound: n.Bound, Eligible: n.Eligible, Running: n.Running, InSync: n.InSync, Note: c.a.T(n.Note), Exit: exit})
	}
	for _, ex := range st.Exits {
		ev := exitView(c.a, st, ex)
		v.Exits = append(v.Exits, ev)
		if ex.ID == v.ExitID {
			cp := ev
			v.Exit = &cp
		}
	}
	now := s.now()
	for _, p := range sortedProfiles(st, "relay") {
		v.Relays = append(v.Relays, c.a.relayView(st, p, now))
	}
	return v, nil
}

type aiServiceView struct {
	Name     string   `json:"name"`
	Suffixes []string `json:"suffixes"`
}

type aiBindReq struct {
	IDs []string `json:"ids"`
}
type aiExitReq struct {
	ExitID string `json:"exit_id"`
}
type aiEnableReq struct {
	Enabled bool `json:"enabled"`
}
type aiSimReq struct {
	Host string `json:"host"`
}
type aiSimRow struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Route string `json:"route"` // ai, original, blocked
}

func (s *WebServer) aiRoutes() {
	r := routeOpts{}
	rr := routeOpts{reauth: true}
	view := func(c *reqCtx) (any, error) { return s.aiView(c) }
	s.handle("GET /api/ai", r, view)
	s.handle("PUT /api/ai/bindings", r, func(c *reqCtx) (any, error) {
		var req aiBindReq
		if e := c.decode(&req); e != nil {
			return nil, e
		}
		if len(req.IDs) > 200 {
			return nil, errBad("请选择 1–200 个对象")
		}
		for _, id := range req.IDs {
			if !idPattern.MatchString(id) {
				return nil, errBad("节点 ID 无效")
			}
		}
		if e := c.a.SetAIBindings(req.IDs); e != nil {
			return nil, e
		}
		s.changed()
		return view(c)
	})
	s.handle("PUT /api/ai/exit", r, func(c *reqCtx) (any, error) {
		var req aiExitReq
		if e := c.decode(&req); e != nil {
			return nil, e
		}
		if req.ExitID != "" && !idPattern.MatchString(req.ExitID) {
			return nil, errBad("出站代理名称或 ID 无效")
		}
		if e := c.a.SetAIExit(req.ExitID); e != nil {
			return nil, e
		}
		s.changed()
		return view(c)
	})
	s.handle("POST /api/ai/enabled", r, func(c *reqCtx) (any, error) {
		var req aiEnableReq
		if e := c.decode(&req); e != nil {
			return nil, e
		}
		if e := c.a.SetAIEnabled(req.Enabled); e != nil {
			return nil, e
		}
		s.changed()
		return view(c)
	})
	s.handle("POST /api/ai/apply", r, func(c *reqCtx) (any, error) {
		if e := c.a.ApplyAI(); e != nil {
			return nil, e
		}
		s.changed()
		return view(c)
	})
	s.handle("POST /api/ai/test", r, func(c *reqCtx) (any, error) {
		return s.runDiag(c, func(ctx context.Context) (DiagView, error) { return c.a.TestAIExit(ctx) })
	})
	s.handle("POST /api/ai/simulate", r, func(c *reqCtx) (any, error) {
		var req aiSimReq
		if e := c.decode(&req); e != nil {
			return nil, e
		}
		host := normalizeInput(req.Host)
		if host == "" || len(host) > 253 || !validHost(host) {
			return nil, errBad("域名无效")
		}
		st, e := c.a.Load()
		if e != nil {
			return nil, e
		}
		rows := []aiSimRow{}
		for _, p := range sortedProfiles(st, "node") {
			route, er := AIDecision(st, p.ID, host)
			if er != nil {
				return nil, er
			}
			rows = append(rows, aiSimRow{ID: p.ID, Name: p.Name, Route: route})
		}
		return map[string]any{"host": host, "nodes": rows}, nil
	})
	s.handle("POST /api/exits/chain", r, func(c *reqCtx) (any, error) {
		var spec ChainSpec
		if e := c.decode(&spec); e != nil {
			return nil, e
		}
		ex, e := c.a.CreateChainExit(spec)
		if e != nil {
			return nil, e
		}
		st, e := c.a.Load()
		if e != nil {
			return nil, e
		}
		return map[string]any{"exit": exitView(c.a, st, ex)}, nil
	})
	// Panel HTTPS: diagnosis, and a repair limited to an already running Caddy (installing or
	// starting Caddy needs the explicit consents of the terminal flow).
	s.handle("GET /api/system/panel", r, func(c *reqCtx) (any, error) {
		type result struct {
			r WebHTTPSReport
			e error
		}
		done := make(chan result, 1)
		go func() { rep, e := c.a.WebHTTPSDiagnostics(); done <- result{rep, e} }()
		select {
		case res := <-done:
			return res.r, res.e
		case <-time.After(60 * time.Second):
			return nil, errConflict("HTTPS 检查超时")
		case <-c.r.Context().Done():
			return nil, errBad("请求已取消")
		}
	})
	s.handle("POST /api/system/panel/repair", rr, func(c *reqCtx) (any, error) {
		res, e := c.a.RepairWebHTTPS(WebHTTPSOptions{})
		pending := e != nil && res.Pending
		if e != nil && !pending {
			return nil, e
		}
		s.invalidateConfig()
		return map[string]any{"ok": e == nil, "pending": pending, "diagnosis": c.a.T(res.Diagnosis)}, nil
	})
}
