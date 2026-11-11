package rout

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// AI Smart Routing sends AI-service destinations of SELECTED inbound nodes to a chosen
// outbound proxy (the "AI exit"); everything else keeps the node's original route.
//
// Rout runs one sing-box process per node, each with its own configuration file and a
// single inbound. Isolation therefore follows from how the configuration is generated:
//
//   - Only nodes whose stable ID is in BoundInboundIDs get AI rules in their config file.
//     An unbound node's file is byte-identical to what it was before this feature.
//   - Every generated rule also matches the node's own inbound tag, so the rules never
//     apply to anything but that node's connections.
//   - An empty binding list binds nothing. There is no "all inbounds" value.
//
// The settings live in state.json beside the nodes, so they are backed up, restored,
// locked and rolled back by the same Commit transaction as every other change.

// AIRouting is the persisted configuration.
type AIRouting struct {
	Enabled         bool     `json:"enabled"`
	BoundInboundIDs []string `json:"bound_inbound_ids"`
	AIOutboundID    string   `json:"ai_outbound_id"`
	RuleSetVersion  int      `json:"rule_set_version"`
}

// AIRoute is the effective per-node routing derived from the configuration. It is never
// stored; State.withAIRoutes recomputes it on load and before every commit, so a node's
// generated configuration, the restart decision and the rollback all see the same value.
type AIRoute struct {
	// Outbound is the AI exit. nil means the exit is missing or invalid: AI destinations
	// are then rejected rather than silently sent through the node's original exit.
	Outbound *Proxy
	RuleSet  int
}

func (r AIRouting) clone() AIRouting {
	r.BoundInboundIDs = append([]string(nil), r.BoundInboundIDs...)
	return r
}

// aiBound is the set of bound IDs.
func (r AIRouting) aiBound() map[string]bool {
	out := map[string]bool{}
	for _, id := range r.BoundInboundIDs {
		out[id] = true
	}
	return out
}

// aiEligible says whether a profile can be an AI-routed inbound at all.
func aiEligible(p Profile) error {
	if p.Kind != "node" {
		return errors.New("端口转发（中转）没有路由规则，不能绑定 AI 智能分流")
	}
	if p.Protocol == "ss" && p.Network == "udp" {
		return errors.New("仅 UDP 的 Shadowsocks 无法承载 AI 服务的 TCP 流量")
	}
	if p.snellNode() {
		return errors.New("Snell 引擎没有路由规则，不能绑定 AI 智能分流")
	}
	return nil
}

// aiExitUsable checks that an outbound can serve as the AI exit: an authenticated
// SOCKS5/HTTP(S) proxy or a remote node link that Rout converts to a sing-box outbound.
// A relay chain is accepted when it ends in one of those (see aiExitProxy).
func aiExitUsable(p Proxy) error {
	if p.Protocol != "socks5" && p.Protocol != "http" && p.Protocol != "https" && p.Protocol != proxyNode {
		return errors.New("AI 出口必须是 SOCKS5、HTTP(S) 代理、远程节点或经由中转到达的代理")
	}
	return p.Validate()
}

// aiExitProxy is the complete check of an AI exit and the proxy the bound nodes must dial.
// A chain exit is dialed through its hop; its own references are checked instead of the
// loopback hop address, which is an explicit, internal reference to a Rout relay and not a
// loop. Every other exit must not point back at this server.
func aiExitProxy(s State, ex Exit, local map[string]bool) (Proxy, error) {
	if e := aiExitUsable(ex.Proxy); e != nil {
		return Proxy{}, e
	}
	if ex.isChain() {
		return resolveExit(s, ex, local)
	}
	if e := aiExitLoop(s, ex.Proxy, local); e != nil {
		return Proxy{}, e
	}
	return ex.Proxy, nil
}

// aiExitLoop refuses an exit that points back at this server's own entries, which would
// make AI traffic circle through Rout itself.
func aiExitLoop(s State, proxy Proxy, local map[string]bool) error {
	for _, p := range s.Profiles {
		if p.Port == proxy.Port && pointsAtThisHost(proxy.Host, local) {
			return fmt.Errorf("AI 出口指向本机上的 %s，会形成路由循环", p.Name)
		}
		if p.PublicPort == proxy.Port && sameHost(proxy.Host, p.PublicHost) {
			return fmt.Errorf("AI 出口指向本机上的 %s，会形成路由循环", p.Name)
		}
	}
	return nil
}

// AIProblems lists everything wrong with the AI configuration in s. It is strict, and is
// applied to changes; a stored configuration with a stale reference still loads (see
// withAIRoutes, which never lets a bad reference widen the binding).
func (s State) AIProblems() []string {
	ai := s.AI
	if ai == nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, id := range ai.BoundInboundIDs {
		if seen[id] {
			out = append(out, "入站绑定重复")
			continue
		}
		seen[id] = true
		p, e := Find(s, id)
		if e != nil {
			out = append(out, fmt.Sprintf("绑定的入站 %s 已不存在", id))
			continue
		}
		if e = aiEligible(p); e != nil {
			out = append(out, fmt.Sprintf("%s: %s", p.Name, e.Error()))
		}
	}
	if ai.AIOutboundID == "" {
		if ai.Enabled {
			out = append(out, "尚未选择 AI 出口")
		}
		return out
	}
	ex, e := FindExit(s, ai.AIOutboundID)
	if e != nil {
		return append(out, "所选 AI 出口已不存在")
	}
	if _, e = aiExitProxy(s, ex, localIPs()); e != nil {
		out = append(out, e.Error())
	}
	return out
}

// validateAI is the lenient structural check run on every load.
func (s State) validateAI() error {
	ai := s.AI
	if ai == nil {
		return nil
	}
	for _, id := range ai.BoundInboundIDs {
		if !idPattern.MatchString(id) {
			return errors.New("AI 智能分流配置无效")
		}
	}
	if ai.AIOutboundID != "" && !idPattern.MatchString(ai.AIOutboundID) {
		return errors.New("AI 智能分流配置无效")
	}
	if ai.RuleSetVersion < 0 {
		return errors.New("AI 智能分流配置无效")
	}
	return nil
}

// withAIRoutes returns a copy whose bound, eligible nodes carry their effective route.
// Rules apply only to IDs that exist and are eligible: a dangling or invalid reference is
// ignored, so it can never turn into "everything".
func (s State) withAIRoutes() State {
	out := s.Clone()
	for i := range out.Profiles {
		out.Profiles[i].AIRoute = nil
	}
	if s.AI == nil || !s.AI.Enabled {
		return out
	}
	var proxy *Proxy
	if ex, e := FindExit(s, s.AI.AIOutboundID); e == nil {
		if cp, er := aiExitProxy(s, ex, localIPs()); er == nil {
			proxy = &cp
		}
	}
	bound := s.AI.aiBound()
	for i, p := range out.Profiles {
		if bound[p.ID] && aiEligible(p) == nil {
			out.Profiles[i].AIRoute = &AIRoute{Outbound: proxy, RuleSet: s.AI.RuleSetVersion}
		}
	}
	return out
}

// newAIProblems returns the problems in next that old did not already have, so an old
// configuration with a pre-existing fault never blocks unrelated edits, while a change can
// never introduce one.
func newAIProblems(old, next State) []string {
	had := map[string]bool{}
	for _, p := range old.AIProblems() {
		had[p] = true
	}
	var out []string
	for _, p := range next.AIProblems() {
		if !had[p] {
			out = append(out, p)
		}
	}
	return out
}

const aiEgressTag = "ai-egress"

// aiRouteRules renders the rules placed in front of a node's normal ones. Order matters:
//
//  1. match the explicit destination before sniffing, so HTTP Host/SNI cannot hide it;
//  2. sniff, so a destination given only as an IP can still be classified by its TLS SNI,
//     HTTP Host or QUIC server name (this only fills in the domain used for matching; it
//     never rewrites the destination);
//  3. UDP to AI domains is rejected: the AI exit is a TCP-only proxy, so letting QUIC go
//     out directly would leak AI traffic through the original exit. Clients fall back to TCP;
//  4. TCP to AI domains goes to the AI exit.
//
// Every rule matches the node's own inbound, so no other node is ever affected.
func aiRouteRules(r AIRoute) (rules []any, outbound M) {
	suffixes := aiSuffixes(r.RuleSet)
	patterns := []string{aiDomainPattern(r.RuleSet)}
	in := []string{"entry"}
	match := []any{
		M{"inbound": in, "domain_suffix": suffixes, "domain_regex": patterns, "network": "udp", "action": "reject"},
	}
	if r.Outbound == nil {
		// Exit missing or invalid: fail closed, never fall back to the original exit.
		match = append(match, M{"inbound": in, "domain_suffix": suffixes, "domain_regex": patterns, "action": "reject"})
	} else {
		outbound = proxyConfig(*r.Outbound)
		outbound["tag"] = aiEgressTag
		match = append(match, M{"inbound": in, "domain_suffix": suffixes, "domain_regex": patterns, "action": "route", "outbound": aiEgressTag})
	}
	rules = append(rules, match...)
	rules = append(rules, M{"inbound": in, "action": "sniff", "sniffer": []string{"tls", "http", "quic"}, "timeout": "1s"})
	return append(rules, match...), outbound
}

// AIDecision reports where a bound or unbound node sends a TCP connection to host,
// evaluating the same rule set the generated configuration contains. It is a pure
// function used by diagnostics; it does not touch the network.
func AIDecision(s State, nodeID, host string) (route string, e error) {
	p, e := Find(s.withAIRoutes(), nodeID)
	if e != nil {
		return "", e
	}
	if p.AIRoute != nil && matchAIDomain(p.AIRoute.RuleSet, host) {
		if p.AIRoute.Outbound == nil {
			return "blocked", nil
		}
		return "ai", nil
	}
	return "original", nil
}

func (s State) aiConfigured() AIRouting {
	if s.AI == nil {
		return AIRouting{BoundInboundIDs: []string{}}
	}
	return s.AI.clone()
}

// --- Application service: every mutation is one Commit transaction -----------------

func (a *App) mutateAI(change func(*AIRouting, State) error) error {
	old, e := a.Load()
	if e != nil {
		return e
	}
	next := old.Clone()
	cfg := old.aiConfigured()
	if e = change(&cfg, old); e != nil {
		return e
	}
	if cfg.BoundInboundIDs == nil {
		cfg.BoundInboundIDs = []string{}
	}
	next.AI = &cfg
	return a.Commit(old, next, false)
}

// SetAIEnabled switches AI routing on or off. Switching it off keeps the exit and the
// bindings, and restores each bound node's original routing.
func (a *App) SetAIEnabled(on bool) error {
	return a.mutateAI(func(c *AIRouting, s State) error {
		c.Enabled = on
		if on && c.RuleSetVersion == 0 {
			c.RuleSetVersion = AIRuleSetCurrent
		}
		if on {
			s.AI = c
			if probs := s.AIProblems(); len(probs) > 0 {
				return errors.New(strings.Join(probs, "；"))
			}
		}
		return nil
	})
}

// SetAIBindings replaces the bound inbound set. An empty list binds nothing.
func (a *App) SetAIBindings(ids []string) error {
	return a.mutateAI(func(c *AIRouting, _ State) error {
		seen := map[string]bool{}
		c.BoundInboundIDs = []string{}
		for _, id := range ids {
			if !seen[id] {
				seen[id] = true
				c.BoundInboundIDs = append(c.BoundInboundIDs, id)
			}
		}
		if c.RuleSetVersion == 0 {
			c.RuleSetVersion = AIRuleSetCurrent
		}
		return nil
	})
}

// SetAIExit selects the AI exit by its stable outbound ID. Bound nodes are re-rendered; no
// inbound node is rebuilt and unbound nodes are not touched.
func (a *App) SetAIExit(id string) error {
	return a.mutateAI(func(c *AIRouting, s State) error {
		if id != "" {
			ex, e := FindExit(s, id)
			if e != nil {
				return e
			}
			if _, e = aiExitProxy(s, ex, localIPs()); e != nil {
				return e
			}
		}
		c.AIOutboundID = id
		if c.RuleSetVersion == 0 {
			c.RuleSetVersion = AIRuleSetCurrent
		}
		return nil
	})
}

// ApplyAI re-validates, upgrades to the newest built-in rule set and rewrites + restarts the
// bound nodes (only them), repairing a configuration that is saved but not in effect.
func (a *App) ApplyAI() error {
	old, e := a.Load()
	if e != nil {
		return e
	}
	if old.AI == nil {
		return errors.New("尚未配置 AI 智能分流")
	}
	next := old.Clone()
	cfg := old.AI.clone()
	cfg.RuleSetVersion = AIRuleSetCurrent
	next.AI = &cfg
	if probs := next.AIProblems(); len(probs) > 0 {
		return errors.New(strings.Join(probs, "；"))
	}
	return a.commit(old, next, true, cfg.aiBound())
}

// pruneAIBinding drops a removed inbound from the binding so nothing dangles.
func pruneAIBinding(s State, id string) State {
	if s.AI == nil {
		return s
	}
	cfg := s.AI.clone()
	kept := []string{}
	for _, v := range cfg.BoundInboundIDs {
		if v != id {
			kept = append(kept, v)
		}
	}
	cfg.BoundInboundIDs = kept
	s.AI = &cfg
	return s
}

// --- Runtime status -------------------------------------------------------------

type AINodeStatus struct {
	ID, Name, Protocol string
	Bound, Eligible    bool
	Running            string
	// InSync is true when the node's configuration file on disk is exactly what the saved
	// settings produce, i.e. the saved routing is what the node was last started with.
	InSync bool
	Note   string
}

type AIStatus struct {
	Config           AIRouting
	ExitName         string
	ExitProtocol     string
	ExitChain        bool
	Problems         []string
	Nodes            []AINodeStatus
	BoundCount       int
	RuleSetAvailable int
}

// configInSync compares a node's file on disk with what the current settings generate.
func (a *App) configInSync(p Profile) bool {
	c, e := serverConfig(p, a.profileDir(p.ID))
	if e != nil {
		return false
	}
	want, e := JSON(c)
	if e != nil {
		return false
	}
	have, e := os.ReadFile(filepath.Join(a.profileDir(p.ID), "config.json"))
	return e == nil && bytes.Equal(bytes.TrimSpace(have), bytes.TrimSpace(want))
}

func (a *App) diskHasAIRules(p Profile) bool {
	b, e := os.ReadFile(filepath.Join(a.profileDir(p.ID), "config.json"))
	return e == nil && bytes.Contains(b, []byte(`"sniff"`))
}

// AIStatus reads the persisted configuration and the real state of each node.
func (a *App) AIStatus() (AIStatus, error) {
	s, e := a.Load()
	if e != nil {
		return AIStatus{}, e
	}
	st := AIStatus{Config: s.aiConfigured(), Problems: s.AIProblems(), RuleSetAvailable: AIRuleSetCurrent}
	if ex, er := FindExit(s, st.Config.AIOutboundID); er == nil {
		st.ExitName, st.ExitProtocol = ex.Name, ex.Proxy.Kind()
		st.ExitChain = ex.isChain()
		if warning := proxySecurityWarning(ex.Proxy); warning != "" {
			st.Problems = append(st.Problems, warning)
		}
	}
	bound := st.Config.aiBound()
	for _, p := range s.Profiles {
		if p.Kind != "node" {
			continue
		}
		n := AINodeStatus{ID: p.ID, Name: p.Name, Protocol: p.Protocol, Bound: bound[p.ID], Eligible: aiEligible(p) == nil, Running: a.Running(p)}
		if er := aiEligible(p); er != nil {
			n.Note = er.Error()
		}
		// A routed node must match exactly what the settings generate; any other node must
		// simply carry no AI rules (it is not required to be re-rendered).
		if eff, er := Find(s.withAIRoutes(), p.ID); er == nil && eff.AIRoute != nil {
			n.InSync = a.configInSync(eff)
		} else {
			n.InSync = !a.diskHasAIRules(p)
		}
		if n.Bound {
			st.BoundCount++
		}
		st.Nodes = append(st.Nodes, n)
	}
	return st, nil
}

// AICheck is one line of the configuration test.
type AICheck struct {
	OK, Warning bool
	Text        string
}

// TestAI validates the saved configuration without changing anything: the references, the
// sing-box syntax of every bound node's candidate configuration, and (through probe) the
// AI exit. probe may be nil to skip the live exit test.
func (a *App) TestAI(probe func(Proxy) (string, error)) ([]AICheck, error) {
	s, e := a.Load()
	if e != nil {
		return nil, e
	}
	var out []AICheck
	add := func(ok, warn bool, text string) { out = append(out, AICheck{ok, warn, text}) }
	if s.AI == nil {
		add(false, true, "尚未配置 AI 智能分流")
		return out, nil
	}
	if probs := s.AIProblems(); len(probs) > 0 {
		for _, p := range probs {
			add(false, false, p)
		}
	} else {
		add(true, false, "引用检查通过：入站和 AI 出口均有效")
	}
	if len(s.AI.BoundInboundIDs) == 0 {
		add(false, true, "尚未选择入站节点：目前不会影响任何节点")
	}
	eff := s.withAIRoutes()
	if _, er := os.Stat(a.enginePath("sing-box")); er != nil {
		add(false, true, "未安装 sing-box 内核，跳过配置语法检查")
	} else {
		stage, er := os.MkdirTemp(a.Home, ".ai-check-")
		if er != nil {
			return out, er
		}
		defer os.RemoveAll(stage)
		for _, p := range eff.Profiles {
			if p.AIRoute == nil {
				continue
			}
			dir := filepath.Join(stage, p.ID)
			if er = writeProfileIn(p, dir); er != nil {
				return out, er
			}
			if er = a.checkConfig(filepath.Join(dir, "config.json")); er != nil {
				add(false, false, fmt.Sprintf("%s: %s", p.Name, er.Error()))
			} else {
				add(true, false, fmt.Sprintf("%s 的 sing-box 配置检查通过", p.Name))
			}
		}
	}
	if probe != nil && s.AI.AIOutboundID != "" {
		if ex, er := FindExit(s, s.AI.AIOutboundID); er == nil {
			if warning := proxySecurityWarning(ex.Proxy); warning != "" {
				add(false, true, warning)
			}
			dial, er := aiExitProxy(s, ex, localIPs())
			if er != nil {
				add(false, false, a.Error(er))
			} else if ip, er := probe(dial); er != nil {
				add(false, false, fmt.Sprintf("AI 出口不可用：%s", a.Error(er)))
			} else {
				add(true, false, fmt.Sprintf("AI 出口可用，实际出口 IP：%s", ip))
			}
		}
	}
	return out, nil
}

func joinNames(names []string) string { return strings.Join(names, "、") }

// diagnoseAI is the end-to-end AI exit test: the bound inbound nodes (layer 1), then every
// layer of the selected exit, through its relay when it is a chain, ending with a real
// request whose observed source address is the exit IP. Nothing is changed.
func (a *App) diagnoseAI(ctx context.Context, env diagEnv, opts diagOpts) (diagReport, error) {
	var rep diagReport
	d := diagger{a: a, rep: &rep}
	s, e := a.Load()
	if e != nil {
		return rep, e
	}
	if s.AI == nil || s.AI.AIOutboundID == "" {
		d.add(5, diagFail, "尚未选择 AI 出口")
		return rep, nil
	}
	eff := s.withAIRoutes()
	bound := s.AI.aiBound()
	if len(bound) == 0 {
		d.add(1, diagWarn, "尚未选择入站节点：目前不会影响任何节点")
	}
	for _, p := range eff.Profiles {
		if !bound[p.ID] {
			continue
		}
		if er := aiEligible(p); er != nil {
			d.add(1, diagFail, "%s：%s", p.Name, a.Error(er))
			continue
		}
		if !p.Enabled {
			d.add(1, diagWarn, "入站 %s 已停用", p.Name)
			continue
		}
		if managed, up := env.managed(a, p); managed && !up {
			d.add(1, diagFail, "入站 %s 的服务未运行", p.Name)
			continue
		}
		if s.AI.Enabled && p.AIRoute != nil && !a.configInSync(p) {
			d.add(1, diagWarn, "入站 %s 的配置与已保存的设置不一致，请选择“应用更改”", p.Name)
			continue
		}
		d.add(1, diagOK, "入站 %s 正常", p.Name)
	}
	if !s.AI.Enabled {
		d.add(1, diagWarn, "AI 智能分流尚未启用：以下只测试出口链路本身")
	}
	ex, e := FindExit(s, s.AI.AIOutboundID)
	if e != nil {
		d.add(5, diagFail, "所选 AI 出口已不存在")
		return rep, nil
	}
	if _, e = aiExitProxy(s, ex, env.local()); e != nil {
		d.add(5, diagFail, "%s", a.Error(e))
		return rep, nil
	}
	rep.Steps = append(rep.Steps, a.diagnoseProxy(ctx, ex, env, opts).Steps...)
	if _, failed := rep.Failed(); !failed && rep.Has(6, diagOK) {
		d.add(6, diagOK, "AI 出口链路可用")
	}
	return rep, nil
}

// TestAIExit runs diagnoseAI for the panel.
func (a *App) TestAIExit(ctx context.Context) (DiagView, error) {
	rep, e := a.diagnoseAI(ctx, a.diagEnvironment(), diagOpts{Full: true})
	if e != nil {
		return DiagView{}, e
	}
	return diagView(a, rep), nil
}
