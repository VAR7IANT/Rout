package rout

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"time"
)

type subCreateReq struct {
	Name    string    `json:"name"`
	NodeIDs []string  `json:"node_ids"`
	Items   []SubItem `json:"items"`
	// Aggregate asks for an aggregate subscription (custom names, third-party nodes, dedupe)
	// even when the items alone would fit a standard one.
	Aggregate     bool `json:"aggregate"`
	Dedupe        bool `json:"dedupe"`
	AllowInsecure bool `json:"allow_insecure"`
}

type subItemsReq struct {
	NodeIDs       []string  `json:"node_ids"`
	Items         []SubItem `json:"items"`
	Aggregate     bool      `json:"aggregate"`
	Dedupe        bool      `json:"dedupe"`
	AllowInsecure bool      `json:"allow_insecure"`
}

type subPatchReq struct {
	Name    *string `json:"name"`
	Enabled *bool   `json:"enabled"`
}

type planReq struct {
	LimitBytes uint64 `json:"limit_bytes"`
	BillingDay int    `json:"billing_day"`
	Timezone   string `json:"timezone"`
	Expires    string `json:"expires"`
}

type subNodeChoice struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Label    string `json:"label"`
	Kind     string `json:"kind"`
	Enabled  bool   `json:"enabled"`
}

func (s *WebServer) subView(c *reqCtx, id string) (SubscriptionView, error) {
	st, e := c.a.Load()
	if e != nil {
		return SubscriptionView{}, e
	}
	i, e := findSubscription(st, id)
	if e != nil {
		return SubscriptionView{}, errNotFound("找不到订阅")
	}
	tokens, _ := c.a.loadSubscriptionTokens()
	return c.a.subscriptionView(st, st.Subscriptions[i], s.now(), tokens), nil
}

func (s *WebServer) subscriptionRoutes() {
	r := routeOpts{}
	rr := routeOpts{reauth: true}

	s.handle("GET /api/subscriptions", r, func(c *reqCtx) (any, error) {
		st, e := c.a.Load()
		if e != nil {
			return nil, e
		}
		tokens, _ := c.a.loadSubscriptionTokens()
		now := s.now()
		subs := []SubscriptionView{}
		for _, sub := range st.Subscriptions {
			subs = append(subs, c.a.subscriptionView(st, sub, now, tokens))
		}
		nodes := []subNodeChoice{}
		for _, p := range sortedProfiles(st, "node") {
			nodes = append(nodes, subNodeChoice{ID: p.ID, Name: p.Name, Protocol: p.Protocol, Label: nodeLabel(p), Kind: "node", Enabled: p.Enabled})
		}
		for _, p := range sortedProfiles(st, "relay") {
			nodes = append(nodes, subNodeChoice{ID: p.ID, Name: p.Name, Protocol: p.Protocol, Label: ProtocolLabel(p.Protocol), Kind: "relay", Enabled: p.Enabled})
		}
		out := map[string]any{"subscriptions": subs, "nodes": nodes}
		if ss, er := c.a.SubscriptionServerStatus(); er == nil {
			out["server"] = map[string]any{"enabled": ss.Settings.Enabled, "running": ss.Running, "managed": ss.Managed, "public_url_set": ss.Settings.PublicURL != ""}
		}
		return out, nil
	})

	s.handle("POST /api/subscriptions", r, func(c *reqCtx) (any, error) {
		var req subCreateReq
		if e := c.decode(&req); e != nil {
			return nil, e
		}
		var (
			sub Subscription
			e   error
		)
		if len(req.Items) > 0 || req.Aggregate || req.Dedupe || req.AllowInsecure {
			if len(req.NodeIDs) > 0 {
				return nil, errBad("请只使用 items 或 node_ids 之一")
			}
			sub, _, e = c.a.CreateAggregateSubscription(req.Name, AggregateSpec{Items: req.Items, Dedupe: req.Dedupe, AllowInsecure: req.AllowInsecure})
		} else {
			sub, _, e = c.a.CreateSubscription(req.Name, req.NodeIDs)
		}
		if e != nil {
			return nil, e
		}
		v, e := s.subView(c, sub.ID)
		return map[string]any{"subscription": v}, e
	})

	s.handle("PATCH /api/subscriptions/{id}", r, func(c *reqCtx) (any, error) {
		id, e := c.pathID("id")
		if e != nil {
			return nil, e
		}
		var req subPatchReq
		if e := c.decode(&req); e != nil {
			return nil, e
		}
		if _, e := s.subView(c, id); e != nil {
			return nil, e
		}
		if req.Name != nil {
			if e := c.a.RenameSubscription(id, *req.Name); e != nil {
				return nil, e
			}
		}
		if req.Enabled != nil {
			if e := c.a.SetSubscriptionEnabled(id, *req.Enabled); e != nil {
				return nil, e
			}
		}
		return nil, nil
	})

	s.handle("PUT /api/subscriptions/{id}/items", r, func(c *reqCtx) (any, error) {
		id, e := c.pathID("id")
		if e != nil {
			return nil, e
		}
		var req subItemsReq
		if e := c.decode(&req); e != nil {
			return nil, e
		}
		st, e := c.a.Load()
		if e != nil {
			return nil, e
		}
		si, e := findSubscription(st, id)
		if e != nil {
			return nil, errNotFound("找不到订阅")
		}
		sub := st.Subscriptions[si]
		if len(req.Items) > 0 && len(req.NodeIDs) > 0 {
			return nil, errBad("请只使用 items 或 node_ids 之一")
		}
		hasRemote := false
		for _, it := range req.Items {
			if it.Kind == itemRemote {
				hasRemote = true
			}
		}
		// A subscription that has never used third-party nodes keeps its original code path
		// (and byte-identical output) until the administrator actually adds one.
		if !sub.aggregate() && !hasRemote && !req.Aggregate && !req.Dedupe && !req.AllowInsecure {
			ids := req.NodeIDs
			for _, it := range req.Items {
				if it.Kind != itemLocal || it.Name != "" {
					return nil, errBad("自定义名称仅适用于聚合订阅，请启用聚合模式")
				}
				ids = append(ids, it.NodeID)
			}
			return nil, c.a.SetSubscriptionNodes(id, ids)
		}
		items := req.Items
		for _, nid := range req.NodeIDs {
			items = append(items, SubItem{Kind: itemLocal, NodeID: nid})
		}
		return nil, c.a.SetSubscriptionItems(id, AggregateSpec{Items: items, Dedupe: req.Dedupe, AllowInsecure: req.AllowInsecure})
	})

	s.handle("PUT /api/subscriptions/{id}/plan", r, func(c *reqCtx) (any, error) {
		id, e := c.pathID("id")
		if e != nil {
			return nil, e
		}
		var req planReq
		if e := c.decode(&req); e != nil {
			return nil, e
		}
		if _, e := s.subView(c, id); e != nil {
			return nil, e
		}
		return nil, c.a.SetSubscriptionPlan(id, SubscriptionPlan{LimitBytes: req.LimitBytes, BillingDay: req.BillingDay, Timezone: strings.TrimSpace(req.Timezone), Expires: strings.TrimSpace(req.Expires)})
	})

	s.handle("POST /api/subscriptions/{id}/reset-usage", r, func(c *reqCtx) (any, error) {
		id, e := c.pathID("id")
		if e != nil {
			return nil, e
		}
		if _, e := s.subView(c, id); e != nil {
			return nil, e
		}
		return nil, c.a.ResetSubscriptionUsage(id, s.now())
	})

	s.handle("DELETE /api/subscriptions/{id}", rr, func(c *reqCtx) (any, error) {
		id, e := c.pathID("id")
		if e != nil {
			return nil, e
		}
		if _, e := s.subView(c, id); e != nil {
			return nil, e
		}
		return nil, c.a.DeleteSubscription(id)
	})

	s.handle("POST /api/subscriptions/{id}/rotate", rr, func(c *reqCtx) (any, error) {
		id, e := c.pathID("id")
		if e != nil {
			return nil, e
		}
		if _, e := s.subView(c, id); e != nil {
			return nil, e
		}
		if _, e := c.a.RotateSubscriptionToken(id); e != nil {
			return nil, e
		}
		return nil, nil
	})

	s.handle("GET /api/subscriptions/{id}/url", rr, func(c *reqCtx) (any, error) {
		id, e := c.pathID("id")
		if e != nil {
			return nil, e
		}
		st, e := c.a.Load()
		if e != nil {
			return nil, e
		}
		si, e := findSubscription(st, id)
		if e != nil {
			return nil, errNotFound("找不到订阅")
		}
		sub := st.Subscriptions[si]
		tokens, e := c.a.loadSubscriptionTokens()
		if e != nil {
			return nil, e
		}
		tok, ok := tokens[sub.TokenHash]
		if !ok {
			return nil, errConflict("此订阅的链接无法再次显示，请轮换令牌后重新生成")
		}
		cfg, e := c.a.subscriptionSettings()
		if e != nil {
			return nil, e
		}
		url := cfg.SubscriptionURL(tok)
		if url == "" {
			return nil, errConflict("尚未配置订阅 HTTPS 公网地址")
		}
		s.audit.add(s.now(), clientIP(c.r), "reveal subscription url "+sub.ID)
		return map[string]string{"base64_url": url, "mihomo_url": cfg.MihomoURL(tok)}, nil
	})

	// ---- third-party sources ----

	s.handle("GET /api/sources", r, func(c *reqCtx) (any, error) {
		views, e := c.a.RemoteSources()
		if e != nil {
			return nil, e
		}
		return map[string]any{"sources": views}, nil
	})

	s.handle("POST /api/sources", r, func(c *reqCtx) (any, error) {
		var spec RemoteSourceSpec
		if e := c.decode(&spec); e != nil {
			return nil, e
		}
		src, e := c.a.AddRemoteSource(spec)
		if e != nil {
			return nil, e
		}
		v, e := s.sourceView(c, src.ID)
		return map[string]any{"source": v}, e
	})

	s.handle("PATCH /api/sources/{id}", r, func(c *reqCtx) (any, error) {
		id, e := c.pathID("id")
		if e != nil {
			return nil, e
		}
		var patch RemoteSourcePatch
		if e := c.decode(&patch); e != nil {
			return nil, e
		}
		changed, e := c.a.UpdateRemoteSource(id, patch)
		if e != nil {
			return nil, e
		}
		return map[string]bool{"url_changed": changed}, nil
	})

	s.handle("DELETE /api/sources/{id}", rr, func(c *reqCtx) (any, error) {
		id, e := c.pathID("id")
		if e != nil {
			return nil, e
		}
		detach := c.r.URL.Query().Get("detach") == "1"
		return nil, c.a.DeleteRemoteSource(id, detach)
	})

	s.handle("POST /api/sources/{id}/refresh", r, func(c *reqCtx) (any, error) {
		id, e := c.pathID("id")
		if e != nil {
			return nil, e
		}
		ctx, cancel := context.WithTimeout(c.r.Context(), 90*time.Second)
		defer cancel()
		res, e := c.a.RefreshRemoteSource(ctx, id)
		if e != nil {
			return nil, e
		}
		return res, nil
	})

	s.handle("GET /api/sources/{id}/url", rr, func(c *reqCtx) (any, error) {
		id, e := c.pathID("id")
		if e != nil {
			return nil, e
		}
		raw, e := c.a.RemoteSourceSecret(id)
		if e != nil {
			return nil, errNotFound("找不到订阅源")
		}
		s.audit.add(s.now(), clientIP(c.r), "reveal source "+id)
		return map[string]string{"value": raw}, nil
	})

	s.handle("GET /api/sources/{id}/nodes", r, func(c *reqCtx) (any, error) {
		id, e := c.pathID("id")
		if e != nil {
			return nil, e
		}
		return s.sourceNodes(c, id)
	})

	s.handle("PUT /api/sources/{id}/nodes", r, func(c *reqCtx) (any, error) {
		id, e := c.pathID("id")
		if e != nil {
			return nil, e
		}
		var req struct {
			Disabled []string `json:"disabled"`
		}
		if e := c.decode(&req); e != nil {
			return nil, e
		}
		if req.Disabled == nil {
			req.Disabled = []string{}
		}
		_, e = c.a.UpdateRemoteSource(id, RemoteSourcePatch{DisabledNodes: &req.Disabled})
		return nil, e
	})
}

func (s *WebServer) sourceView(c *reqCtx, id string) (RemoteSourceView, error) {
	views, e := c.a.RemoteSources()
	if e != nil {
		return RemoteSourceView{}, e
	}
	for _, v := range views {
		if v.ID == id {
			return v, nil
		}
	}
	return RemoteSourceView{}, errNotFound("找不到订阅源")
}

type SourceNodeView struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Protocol  string   `json:"protocol"`
	Server    string   `json:"server"`
	Port      int      `json:"port"`
	Transport string   `json:"transport,omitempty"`
	Security  string   `json:"security,omitempty"`
	SNI       string   `json:"sni,omitempty"`
	UDP       bool     `json:"udp"`
	Enabled   bool     `json:"enabled"`
	LinkOK    bool     `json:"link_ok"`
	LinkIssue string   `json:"link_issue,omitempty"`
	FromClash bool     `json:"from_clash"`
	Notes     []string `json:"notes,omitempty"`
}

type SourceIssueView struct {
	Level    string `json:"level"`
	Line     int    `json:"line,omitempty"`
	Name     string `json:"name,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	Reason   string `json:"reason"`
}

func (s *WebServer) sourceNodes(c *reqCtx, id string) (any, error) {
	cfg, e := c.a.loadRemoteConfig()
	if e != nil {
		return nil, e
	}
	i, ok := cfg.find(id)
	if !ok {
		return nil, errNotFound("找不到订阅源")
	}
	src := cfg.Sources[i]
	snap, e := c.a.loadRemoteSnapshot(id)
	nodes, issues := []SourceNodeView{}, []SourceIssueView{}
	if e == nil && snap != nil {
		dis := map[string]bool{}
		for _, d := range src.DisabledNodes {
			dis[d] = true
		}
		for _, n := range snap.Nodes {
			nodes = append(nodes, SourceNodeView{ID: n.ID, Name: n.Name, Protocol: n.Protocol, Server: n.Server, Port: n.Port, Transport: n.Transport,
				Security: n.Security, SNI: n.SNI, UDP: n.UDP, Enabled: !dis[n.ID], LinkOK: n.Link != "", LinkIssue: c.a.T(n.LinkIssue), FromClash: n.Clash != nil, Notes: c.a.translateAll(n.Notes)})
		}
		for _, is := range snap.Issues {
			issues = append(issues, SourceIssueView{Level: is.Level, Line: is.Line, Name: is.Name, Protocol: is.Protocol, Reason: urlInText.ReplaceAllString(c.a.T(is.Reason), "…")})
		}
	}
	sort.SliceStable(issues, func(i, j int) bool { return issues[i].Line < issues[j].Line })
	return map[string]any{"nodes": nodes, "issues": issues}, nil
}

var _ = http.StatusOK
