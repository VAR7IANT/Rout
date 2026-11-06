package rout

import (
	"context"
	"net/http"
	"strings"
	"time"
)

// needReauth is for handlers whose danger depends on the request (bulk delete): the route
// itself is not marked reauth, so the check is made here.
func (c *reqCtx) needReauth() error {
	if !c.s.now().Before(c.sess.ReauthUntil) {
		return &apiError{Status: http.StatusForbidden, Code: "reauth_required", Msg: "此操作需要重新输入管理密码"}
	}
	return nil
}

// changed is called after anything that starts, stops or edits a service, so the next
// listing does not show a cached state.
func (s *WebServer) changed() {
	invalidateServiceStates()
	s.trMu.Lock()
	s.trCache = map[string]trafficEntry{}
	s.trMu.Unlock()
}

func profileOfKind(st State, id, kind string) (Profile, error) {
	p, e := Find(st, id)
	if e != nil || p.Kind != kind {
		return Profile{}, errNotFound("找不到对象")
	}
	return p, nil
}

type nodeList struct {
	Nodes      []NodeView  `json:"nodes"`
	Protocols  []protoInfo `json:"protocols"`
	Exits      []exitRef   `json:"exits"`
	Host       hostInfo    `json:"host"`
	Monitoring bool        `json:"monitoring"`
	// OutboundPolicies are the five policies in menu order, annotated for this host.
	OutboundPolicies []PolicyChoice `json:"outbound_policies"`
}

type protoInfo struct {
	ID       string   `json:"id"`
	Label    string   `json:"label"`
	Networks []string `json:"networks"`
}
type exitRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind"`
}
type hostInfo struct {
	IPv4 bool `json:"ipv4"`
	IPv6 bool `json:"ipv6"`
}

func protocolInfos() []protoInfo {
	out := []protoInfo{}
	for _, p := range createProtocols {
		out = append(out, protoInfo{ID: p, Label: ProtocolLabel(p), Networks: Profile{Kind: "node", Protocol: p}.Networks()})
	}
	return out
}

func exitRefs(st State) []exitRef {
	out := []exitRef{}
	for _, e := range st.Exits {
		k := "classic"
		if e.Kind == exitRemote {
			k = "remote"
		}
		out = append(out, exitRef{ID: e.ID, Name: e.Name, Kind: k})
	}
	return out
}

func (s *WebServer) nodeViewsFor(c *reqCtx, st State, ids map[string]bool) []NodeView {
	now := s.now()
	nodes := sortedProfiles(st, "node")
	tv, _ := s.trafficViews(c.a, nodes)
	out := []NodeView{}
	for _, p := range nodes {
		if ids != nil && !ids[p.ID] {
			continue
		}
		var tp *TrafficView
		if t, ok := tv[p.ID]; ok {
			tp = &t
		}
		out = append(out, c.a.nodeView(st, p, now, tp))
	}
	return out
}

func idSet(ps []Profile) map[string]bool {
	m := map[string]bool{}
	for _, p := range ps {
		m[p.ID] = true
	}
	return m
}

type bulkReq struct {
	Action string   `json:"action"`
	IDs    []string `json:"ids"`
	ExitID string   `json:"exit_id"`
}

func (s *WebServer) nodeRoutes() {
	r := routeOpts{}
	rr := routeOpts{reauth: true}

	// -- nodes
	s.handle("GET /api/nodes", r, func(c *reqCtx) (any, error) {
		st, e := c.a.Load()
		if e != nil {
			return nil, e
		}
		v4, v6 := hostFamilies()
		nodes := sortedProfiles(st, "node")
		_, mon := s.trafficViews(c.a, nodes)
		return nodeList{Nodes: s.nodeViewsFor(c, st, nil), Protocols: protocolInfos(), Exits: exitRefs(st), Host: hostInfo{v4, v6}, Monitoring: mon, OutboundPolicies: nodePolicyChoices(hostRoutes())}, nil
	})
	s.handle("POST /api/nodes", r, func(c *reqCtx) (any, error) {
		var spec NodeSpec
		if e := c.decode(&spec); e != nil {
			return nil, e
		}
		created, e := c.a.CreateNodes(spec)
		if e != nil {
			return nil, e
		}
		s.changed()
		st, e := c.a.Load()
		if e != nil {
			return nil, e
		}
		return map[string]any{"nodes": s.nodeViewsFor(c, st, idSet(created))}, nil
	})
	s.handle("PATCH /api/nodes/{id}", r, s.renameProfile("node"))
	s.handle("PUT /api/nodes/{id}/outbound-policy", r, s.setOutboundPolicy)
	s.handle("POST /api/nodes/{id}/egress-test", r, s.egressTest)
	s.handle("DELETE /api/nodes/{id}", rr, s.deleteProfile("node"))
	s.handle("GET /api/nodes/{id}/link", rr, s.profileLink("node"))
	s.handle("POST /api/nodes/{id}/test", r, s.testProfile("node"))
	s.handle("POST /api/nodes/{id}/restart", r, s.restartProfile("node"))
	s.handle("POST /api/nodes/bulk", r, s.bulkProfiles("node"))

	// -- relays
	s.handle("GET /api/relays", r, func(c *reqCtx) (any, error) {
		st, e := c.a.Load()
		if e != nil {
			return nil, e
		}
		now := s.now()
		out := []RelayView{}
		for _, p := range sortedProfiles(st, "relay") {
			out = append(out, c.a.relayView(st, p, now))
		}
		nodes := []exitRef{}
		for _, p := range sortedProfiles(st, "node") {
			nodes = append(nodes, exitRef{ID: p.ID, Name: p.Name, Kind: p.Protocol})
		}
		v4, v6 := hostFamilies()
		return map[string]any{"relays": out, "nodes": nodes, "host": hostInfo{v4, v6}, "exits": exitRefs(st)}, nil
	})
	s.handle("POST /api/relays", r, func(c *reqCtx) (any, error) {
		var spec RelaySpec
		if e := c.decode(&spec); e != nil {
			return nil, e
		}
		p, e := c.a.CreateRelay(spec)
		if e != nil {
			return nil, e
		}
		s.changed()
		st, e := c.a.Load()
		if e != nil {
			return nil, e
		}
		return map[string]any{"relay": c.a.relayView(st, p, s.now())}, nil
	})
	s.handle("PATCH /api/relays/{id}", r, func(c *reqCtx) (any, error) {
		id, e := c.pathID("id")
		if e != nil {
			return nil, e
		}
		var patch RelayPatch
		if e := c.decode(&patch); e != nil {
			return nil, e
		}
		st, e := c.a.Load()
		if e != nil {
			return nil, e
		}
		if _, e := profileOfKind(st, id, "relay"); e != nil {
			return nil, e
		}
		if e := c.a.UpdateRelay(id, patch); e != nil {
			return nil, e
		}
		s.changed()
		return nil, nil
	})
	s.handle("DELETE /api/relays/{id}", rr, s.deleteProfile("relay"))
	s.handle("GET /api/relays/{id}/link", rr, s.profileLink("relay"))
	s.handle("POST /api/relays/{id}/test", r, s.testProfile("relay"))
	s.handle("POST /api/relays/{id}/restart", r, s.restartProfile("relay"))
	s.handle("POST /api/relays/bulk", r, s.bulkProfiles("relay"))

	// -- exits
	s.handle("GET /api/exits", r, func(c *reqCtx) (any, error) {
		st, e := c.a.Load()
		if e != nil {
			return nil, e
		}
		out := []ExitView{}
		for _, ex := range st.Exits {
			out = append(out, exitView(c.a, st, ex))
		}
		return map[string]any{"exits": out}, nil
	})
	s.handle("POST /api/exits", r, func(c *reqCtx) (any, error) {
		var spec ExitSpec
		if e := c.decode(&spec); e != nil {
			return nil, e
		}
		ex, e := c.a.CreateExit(spec)
		if e != nil {
			return nil, e
		}
		st, e := c.a.Load()
		if e != nil {
			return nil, e
		}
		fresh, e := FindExit(st, ex.ID)
		if e != nil {
			return nil, e
		}
		return map[string]any{"exit": exitView(c.a, st, fresh)}, nil
	})
	s.handle("PATCH /api/exits/{id}", r, func(c *reqCtx) (any, error) {
		id, e := c.pathID("id")
		if e != nil {
			return nil, e
		}
		var patch ExitPatch
		if e := c.decode(&patch); e != nil {
			return nil, e
		}
		if e := c.a.UpdateExit(id, patch); e != nil {
			return nil, e
		}
		s.changed()
		return nil, nil
	})
	s.handle("DELETE /api/exits/{id}", rr, func(c *reqCtx) (any, error) {
		id, e := c.pathID("id")
		if e != nil {
			return nil, e
		}
		return nil, c.a.DeleteExitByID(id)
	})
	s.handle("POST /api/exits/{id}/test", r, func(c *reqCtx) (any, error) {
		id, e := c.pathID("id")
		if e != nil {
			return nil, e
		}
		st, e := c.a.Load()
		if e != nil {
			return nil, e
		}
		if _, e := FindExit(st, id); e != nil {
			return nil, errNotFound("找不到对象")
		}
		return s.runDiag(c, func(ctx context.Context) (DiagView, error) { return c.a.TestExit(ctx, id) })
	})
}

func (s *WebServer) runDiag(c *reqCtx, run func(context.Context) (DiagView, error)) (any, error) {
	return s.limited(c, func(ctx context.Context) (any, error) { return run(ctx) })
}

// limited runs a measurement under the shared one-at-a-time limit and the 90 s ceiling.
func (s *WebServer) limited(c *reqCtx, run func(context.Context) (any, error)) (any, error) {
	select {
	case s.diagSem <- struct{}{}:
		defer func() { <-s.diagSem }()
	default:
		return nil, &apiError{Status: http.StatusTooManyRequests, Code: "busy", Msg: "已有测试正在进行，请稍后再试", Retry: 5}
	}
	ctx, cancel := context.WithTimeout(c.r.Context(), 90*time.Second)
	defer cancel()
	return run(ctx)
}

// setOutboundPolicy changes one node's outbound IP family through the same code path as the menu.
// An "only" policy for a family the host cannot route answers 409 no_route until the request is
// repeated with force.
func (s *WebServer) setOutboundPolicy(c *reqCtx) (any, error) {
	id, e := c.pathID("id")
	if e != nil {
		return nil, e
	}
	var req struct {
		Policy string `json:"policy"`
		Force  bool   `json:"force"`
	}
	if e := c.decode(&req); e != nil {
		return nil, e
	}
	st, e := c.a.Load()
	if e != nil {
		return nil, e
	}
	if _, e := profileOfKind(st, id, "node"); e != nil {
		return nil, e
	}
	if e := c.a.SetNodeOutboundPolicy(id, req.Policy, req.Force); e != nil {
		return nil, e
	}
	s.changed()
	st, e = c.a.Load()
	if e != nil {
		return nil, e
	}
	return map[string]any{"nodes": s.nodeViewsFor(c, st, map[string]bool{id: true})}, nil
}

// egressTest measures the node's real outbound path against its policy.
func (s *WebServer) egressTest(c *reqCtx) (any, error) {
	id, e := c.pathID("id")
	if e != nil {
		return nil, e
	}
	var req struct {
		Quick bool `json:"quick"`
	}
	if c.r.ContentLength != 0 {
		if e := c.decode(&req); e != nil {
			return nil, e
		}
	}
	st, e := c.a.Load()
	if e != nil {
		return nil, e
	}
	if _, e := profileOfKind(st, id, "node"); e != nil {
		return nil, e
	}
	return s.limited(c, func(ctx context.Context) (any, error) {
		return c.a.nodeEgressTest(id, req.Quick, c.a.egressEnvironment())
	})
}

type renameReq struct {
	Name string `json:"name"`
}

func (s *WebServer) renameProfile(kind string) func(c *reqCtx) (any, error) {
	return func(c *reqCtx) (any, error) {
		id, e := c.pathID("id")
		if e != nil {
			return nil, e
		}
		var req renameReq
		if e := c.decode(&req); e != nil {
			return nil, e
		}
		st, e := c.a.Load()
		if e != nil {
			return nil, e
		}
		if _, e := profileOfKind(st, id, kind); e != nil {
			return nil, e
		}
		return nil, c.a.RenameProfile(id, req.Name)
	}
}

func (s *WebServer) deleteProfile(kind string) func(c *reqCtx) (any, error) {
	return func(c *reqCtx) (any, error) {
		id, e := c.pathID("id")
		if e != nil {
			return nil, e
		}
		st, e := c.a.Load()
		if e != nil {
			return nil, e
		}
		if _, e := profileOfKind(st, id, kind); e != nil {
			return nil, e
		}
		if e := c.a.DeleteProfiles([]string{id}); e != nil {
			return nil, e
		}
		s.changed()
		return nil, nil
	}
}

func (s *WebServer) profileLink(kind string) func(c *reqCtx) (any, error) {
	return func(c *reqCtx) (any, error) {
		id, e := c.pathID("id")
		if e != nil {
			return nil, e
		}
		st, e := c.a.Load()
		if e != nil {
			return nil, e
		}
		p, e := profileOfKind(st, id, kind)
		if e != nil {
			return nil, e
		}
		link, e := p.URI()
		if e != nil {
			return nil, e
		}
		s.audit.add(s.now(), clientIP(c.r), "reveal link "+p.ID)
		return map[string]string{"link": link}, nil
	}
}

func (s *WebServer) testProfile(kind string) func(c *reqCtx) (any, error) {
	return func(c *reqCtx) (any, error) {
		id, e := c.pathID("id")
		if e != nil {
			return nil, e
		}
		var req struct {
			Full bool `json:"full"`
		}
		if c.r.ContentLength != 0 {
			if e := c.decode(&req); e != nil {
				return nil, e
			}
		}
		st, e := c.a.Load()
		if e != nil {
			return nil, e
		}
		if _, e := profileOfKind(st, id, kind); e != nil {
			return nil, e
		}
		return s.runDiag(c, func(ctx context.Context) (DiagView, error) { return c.a.TestProfile(ctx, id, req.Full) })
	}
}

func (s *WebServer) restartProfile(kind string) func(c *reqCtx) (any, error) {
	return func(c *reqCtx) (any, error) {
		id, e := c.pathID("id")
		if e != nil {
			return nil, e
		}
		st, e := c.a.Load()
		if e != nil {
			return nil, e
		}
		p, e := profileOfKind(st, id, kind)
		if e != nil {
			return nil, e
		}
		if !p.Enabled {
			return nil, errConflict("对象已停用，请先启用")
		}
		if e := c.a.Restart(id); e != nil {
			return nil, e
		}
		s.changed()
		return nil, nil
	}
}

func (s *WebServer) bulkProfiles(kind string) func(c *reqCtx) (any, error) {
	return func(c *reqCtx) (any, error) {
		var req bulkReq
		if e := c.decode(&req); e != nil {
			return nil, e
		}
		if len(req.IDs) == 0 || len(req.IDs) > 200 {
			return nil, errBad("请选择 1 到 200 个对象")
		}
		st, e := c.a.Load()
		if e != nil {
			return nil, e
		}
		seen := map[string]bool{}
		for _, id := range req.IDs {
			if !idPattern.MatchString(id) || seen[id] {
				return nil, errBad("对象 ID 无效或重复")
			}
			seen[id] = true
			if _, e := profileOfKind(st, id, kind); e != nil {
				return nil, e
			}
		}
		switch strings.TrimSpace(req.Action) {
		case "enable":
			e = c.a.SetNodesEnabled(req.IDs, true)
		case "disable":
			e = c.a.SetNodesEnabled(req.IDs, false)
		case "delete":
			if e = c.needReauth(); e == nil {
				e = c.a.DeleteProfiles(req.IDs)
			}
		case "bind_exit":
			if kind != "node" {
				return nil, errBad("只有节点可以绑定出口")
			}
			if req.ExitID == "" {
				return nil, errBad("请选择出口")
			}
			e = c.a.BindNodesToExit(req.IDs, req.ExitID)
		case "unbind_exit":
			if kind != "node" {
				return nil, errBad("只有节点可以绑定出口")
			}
			e = c.a.BindNodesToExit(req.IDs, "")
		default:
			return nil, errBad("不支持的批量操作")
		}
		if e != nil {
			return nil, e
		}
		s.changed()
		return map[string]int{"count": len(req.IDs)}, nil
	}
}
