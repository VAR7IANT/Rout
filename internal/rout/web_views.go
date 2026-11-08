package rout

import (
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// API views. They list what the interface needs to show and nothing secret: no password,
// UUID, private key, share link, subscription token, proxy credential or source URL. Those
// are returned only by explicit "reveal" endpoints that require a recent password check.

type TrafficView struct {
	Active     bool       `json:"active"`
	Up         uint64     `json:"up"`
	Down       uint64     `json:"down"`
	Total      uint64     `json:"total"`
	Limit      uint64     `json:"limit"`
	Left       uint64     `json:"left"`
	Next       *time.Time `json:"next_reset,omitempty"`
	BillingDay int        `json:"billing_day"`
	Timezone   string     `json:"timezone,omitempty"`
	Status     string     `json:"status"` // ok, stopped_quota, sealed, paused, manual
	Live       bool       `json:"live"`
	Incomplete bool       `json:"incomplete,omitempty"`
}

// nodeTrafficFrom reads the traffic record of a node the way `rout traffic show` does,
// without printing. A node with no monitoring still reports its configured limit.
func (a *App) nodeTrafficFrom(db TrafficState, p Profile) TrafficView {
	policy := p.trafficPolicy()
	v := TrafficView{Limit: policy.LimitBytes, BillingDay: policy.BillingDay, Timezone: policy.Timezone, Status: "ok"}
	r, ok := db.Records[p.ID]
	if !ok {
		return v
	}
	s, er := a.meter().Read(p)
	v.Live = er == nil && s.Hash == r.Rules && !r.Pending
	if v.Live {
		er = mergeTraffic(&r, s)
	}
	up, down, total, e := r.totals()
	if e != nil {
		return v
	}
	v.Active, v.Up, v.Down, v.Total = true, up, down, total
	if policy.LimitBytes > 0 && total < policy.LimitBytes {
		v.Left = policy.LimitBytes - total
	}
	if !r.Next.IsZero() {
		n := r.Next
		v.Next = &n
	}
	switch {
	case !p.Enabled:
		v.Status = "manual"
	case r.Blocked == blockQuota || (policy.LimitBytes > 0 && r.Consumed >= policy.LimitBytes):
		v.Status = "stopped_quota"
	case r.Blocked == blockSealed:
		v.Status = "sealed"
	case r.Blocked != "":
		v.Status = "paused"
	}
	v.Incomplete = er != nil || r.Incomplete
	return v
}

// serviceStates caches systemd/OpenRC lookups briefly: a list of fifty nodes would
// otherwise run fifty commands per refresh.
type serviceCache struct {
	mu    sync.Mutex
	at    time.Time
	gen   uint64
	state map[string]string
}

var svcCache serviceCache

// get returns the cached state for key, or runs lookup (without holding the lock) and caches
// its answer. An invalidation that happens while lookup runs bumps gen: the answer is still
// returned to this caller but is not stored, since it may predate the change.
func (c *serviceCache) get(key string, lookup func() string) string {
	c.mu.Lock()
	if c.state == nil || time.Since(c.at) > 3*time.Second {
		c.state, c.at = map[string]string{}, time.Now()
	}
	if v, ok := c.state[key]; ok {
		c.mu.Unlock()
		return v
	}
	gen := c.gen
	c.mu.Unlock()

	v := lookup()

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.gen == gen && c.state != nil {
		c.state[key] = v
	}
	return v
}

func (c *serviceCache) invalidate() {
	c.mu.Lock()
	c.gen++
	c.state = nil
	c.mu.Unlock()
}

// serviceStateOf returns running, stopped, disabled, unmanaged or unknown.
func (a *App) serviceStateOf(p Profile) string {
	if !p.Enabled {
		return "disabled"
	}
	m, e := a.serviceManager()
	if e != nil {
		return "unknown"
	}
	if m == "none" {
		return "unmanaged"
	}
	return svcCache.get(a.Home+"/"+p.ID, func() string {
		if serviceActive(m, serviceName(p)) {
			return "running"
		}
		return "stopped"
	})
}

// invalidateServiceStates is called after a change so the next list is fresh.
func invalidateServiceStates() { svcCache.invalidate() }

type CertView struct {
	Days       int  `json:"days"`
	SelfSigned bool `json:"self_signed"`
}

type NodeView struct {
	ID            string       `json:"id"`
	Name          string       `json:"name"`
	Kind          string       `json:"kind"`
	Protocol      string       `json:"protocol"`
	Label         string       `json:"label"`
	Enabled       bool         `json:"enabled"`
	State         string       `json:"state"`
	Listen        string       `json:"listen"`
	Port          int          `json:"port"`
	PublicHost    string       `json:"public_host"`
	PublicPort    int          `json:"public_port"`
	Networks      []string     `json:"networks"`
	Inbound       string       `json:"inbound,omitempty"`
	Family        string       `json:"family,omitempty"` // ipv4, ipv6 or dual: the address the link uses
	SNI           string       `json:"sni,omitempty"`
	ExitID        string       `json:"exit_id,omitempty"`
	ExitName      string       `json:"exit_name,omitempty"`
	Cert          *CertView    `json:"cert,omitempty"`
	Traffic       *TrafficView `json:"traffic,omitempty"`
	Created       *time.Time   `json:"created_at,omitempty"`
	Subscriptions []string     `json:"subscriptions"`
	Warnings      []string     `json:"warnings"`
	HasLink       bool         `json:"has_link"`
	// OutboundPolicy is the effective outbound IP family (auto, ipv4_first, ipv6_first,
	// ipv4_only, ipv6_only). Scope says what it governs: "direct" (the node's own connections to
	// the destination) or "proxy" (only the connection to its outbound proxy server).
	// OutboundEnforced is true only when Rout can guarantee the family of the connection that
	// leaves for the Internet.
	//
	// Only nodes carry these. A relay (which embeds this view) keeps its own outbound_policy field
	// and has nothing to say about "enforced": its policy is a different feature.
	OutboundPolicy   string `json:"outbound_policy,omitempty"`
	OutboundScope    string `json:"outbound_scope,omitempty"`
	OutboundEnforced *bool  `json:"outbound_enforced,omitempty"`
	OutboundNote     string `json:"outbound_note,omitempty"`
}

func (a *App) nodeView(s State, p Profile, now time.Time, tv *TrafficView) NodeView {
	v := NodeView{ID: p.ID, Name: p.Name, Kind: p.Kind, Protocol: p.Protocol, Label: ProtocolLabel(p.Protocol), Enabled: p.Enabled,
		State: a.serviceStateOf(p), Listen: p.Listen, Port: p.Port, PublicHost: p.PublicHost, PublicPort: p.PublicPort,
		Networks: p.Networks(), Inbound: p.inboundMode(), SNI: p.SNI, ExitID: p.ExitID, Created: p.CreatedAt, Subscriptions: []string{}, Warnings: []string{}}
	if p.Kind == "node" {
		info := p.egressInfo()
		enforced := info.Enforced
		v.OutboundPolicy, v.OutboundScope, v.OutboundEnforced, v.OutboundNote = info.Policy, info.Scope, &enforced, a.T(p.egressScopeNote())
	}
	if net.ParseIP(p.PublicHost) != nil {
		v.Family = familyOf(p.PublicHost)
	}
	if p.ExitID != "" {
		if ex, e := FindExit(s, p.ExitID); e == nil {
			v.ExitName = ex.Name
		}
	}
	if days, ok := p.CertificateDays(now); ok {
		v.Cert = &CertView{Days: days, SelfSigned: p.TLSGenerated}
		if days < 0 {
			v.Warnings = append(v.Warnings, "cert_expired")
		} else if days <= 14 {
			v.Warnings = append(v.Warnings, "cert_expiring")
		}
	}
	if _, e := p.URI(); e == nil {
		v.HasLink = true
	}
	for _, sub := range s.Subscriptions {
		for _, id := range sub.localIDs() {
			if id == p.ID {
				v.Subscriptions = append(v.Subscriptions, sub.Name)
				break
			}
		}
	}
	if tv != nil && p.Kind == "node" {
		t := *tv
		v.Traffic = &t
		if t.Status == "stopped_quota" {
			v.Warnings = append(v.Warnings, "quota_reached")
		} else if t.Limit > 0 && t.Active && t.Left*10 < t.Limit {
			v.Warnings = append(v.Warnings, "quota_low")
		}
	}
	if v.State == "stopped" {
		v.Warnings = append(v.Warnings, "service_down")
	}
	return v
}

type RelayView struct {
	NodeView
	Mode           string   `json:"mode"`                  // local or remote
	Target         string   `json:"target"`                // host:port; no credentials
	TargetKind     string   `json:"target_kind,omitempty"` // protocol name when the target is a node link
	Transport      string   `json:"transport"`
	OutboundPolicy string   `json:"outbound_policy,omitempty"`
	Engine         string   `json:"engine"`
	TargetNetwork  string   `json:"target_network,omitempty"`
	TargetNode     string   `json:"target_node,omitempty"` // name of the managed local node, when it is one
	Path           []string `json:"path"`
	// ChainExits names the relay-chain exits that dial through this relay (delete and
	// retarget protection); AIChain says one of them is the AI exit.
	ChainExits []string `json:"chain_exits"`
	AIChain    bool     `json:"ai_chain"`
}

func (a *App) relayView(s State, p Profile, now time.Time) RelayView {
	v := RelayView{NodeView: a.nodeView(s, p, now, nil), Mode: p.relayMode(), Target: p.Target, Transport: p.Protocol,
		OutboundPolicy: p.OutboundPolicy, Engine: p.Engine, TargetNetwork: p.TargetNetwork, ChainExits: []string{}}
	for _, ex := range relayChainUsers(s, p.ID) {
		v.ChainExits = append(v.ChainExits, ex.Name)
		v.AIChain = v.AIChain || (s.AI != nil && s.AI.AIOutboundID == ex.ID)
	}
	if v.Engine == "" {
		v.Engine = "gost"
	}
	if p.TargetURI != "" {
		if _, transport, ok := identifyLink(p.TargetURI); ok {
			v.TargetKind = transport
		} else if sch := linkScheme(p.TargetURI); sch != "" {
			v.TargetKind = sch
		}
	}
	if h, port, e := ParseEndpoint(p.Target); e == nil && p.relayMode() == relayLocal || isLoopbackHost(hostOf(p.Target)) {
		_ = h
		for _, n := range s.Profiles {
			if n.Kind == "node" && n.Port == port {
				v.TargetNode = n.Name
			}
		}
	}
	entry := net.JoinHostPort(p.PublicHost, itoa(p.PublicPort))
	v.Path = []string{entry, "relay:" + p.Name, p.Target}
	return v
}

type ExitView struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Kind          string   `json:"kind"` // classic, remote or chain
	Protocol      string   `json:"protocol"`
	Label         string   `json:"label"`
	Host          string   `json:"host"`
	Port          int      `json:"port"`
	HasAuth       bool     `json:"has_auth"`
	Transport     string   `json:"transport"`
	RemoteNetwork string   `json:"remote_network,omitempty"`
	Nodes         []string `json:"nodes"`
	NodeIDs       []string `json:"node_ids"`
	AI            bool     `json:"ai"`
	Refs          int      `json:"refs"`
	Warning       string   `json:"warning,omitempty"`
	// Relay chains: the hop (a relay of this server, or another server's address), the full
	// path for display and the reason it cannot be used, if any. Never any credential.
	ViaRelay     string   `json:"via_relay,omitempty"`
	ViaRelayName string   `json:"via_relay_name,omitempty"`
	ViaAddress   string   `json:"via_address,omitempty"`
	Path         []string `json:"path"`
	AIUsable     bool     `json:"ai_usable"`
	AIProblem    string   `json:"ai_problem,omitempty"`
}

func exitView(a *App, s State, e Exit) ExitView {
	v := ExitView{ID: e.ID, Name: e.Name, Kind: "classic", Protocol: e.Proxy.Protocol, Label: e.KindLabel(), Host: e.Proxy.Host, Port: e.Proxy.Port,
		HasAuth: e.Proxy.Username != "" || e.Proxy.Password != "" || e.Proxy.Link != "", Transport: exitTransport(e.Proxy), RemoteNetwork: e.RemoteNetwork,
		Nodes: []string{}, NodeIDs: []string{}}
	if e.Kind == exitRemote {
		v.Kind = "remote"
	}
	if e.isChain() {
		v.Kind, v.ViaRelay, v.ViaAddress = "chain", e.ViaRelay, e.ViaAddress
		if r, er := chainRelay(s, e); er == nil {
			v.ViaRelayName = r.Name
		}
	}
	v.Path = chainPath(a, s, e)
	if _, er := aiExitProxy(s, e, localIPs()); er != nil {
		v.AIProblem = a.Error(er)
	} else {
		v.AIUsable = true
	}
	if e.Proxy.Protocol == proxyNode {
		v.Protocol = linkScheme(e.Proxy.Link)
	}
	if w := proxySecurityWarning(e.Proxy); w != "" {
		v.Warning = a.T(w)
	}
	refs := exitReferences(s, e.ID)
	v.AI = refs.AI
	for _, n := range refs.Nodes {
		v.Nodes = append(v.Nodes, n.Name)
		v.NodeIDs = append(v.NodeIDs, n.ID)
	}
	v.Refs = len(refs.Nodes)
	if refs.AI {
		v.Refs++
	}
	return v
}

type SubscriptionView struct {
	ID            string        `json:"id"`
	Name          string        `json:"name"`
	Enabled       bool          `json:"enabled"`
	Aggregate     bool          `json:"aggregate"`
	Dedupe        bool          `json:"dedupe"`
	AllowInsecure bool          `json:"allow_insecure"`
	Created       time.Time     `json:"created_at"`
	Items         []SubItemView `json:"items"`
	Local         int           `json:"local_count"`
	Remote        int           `json:"remote_count"`
	Plan          *PlanView     `json:"plan,omitempty"`
	CanRevealURL  bool          `json:"can_reveal_url"`
}

type SubItemView struct {
	Kind      string   `json:"kind"`
	NodeID    string   `json:"node_id"`
	SourceID  string   `json:"source_id,omitempty"`
	Source    string   `json:"source,omitempty"`
	Name      string   `json:"name"`
	Custom    string   `json:"custom_name,omitempty"`
	Protocol  string   `json:"protocol,omitempty"`
	Status    string   `json:"status"` // ok, skipped
	Skipped   string   `json:"skipped,omitempty"`
	Base64OK  bool     `json:"base64_ok"`
	Base64Why string   `json:"base64_why,omitempty"`
	MihomoOK  bool     `json:"mihomo_ok"`
	MihomoWhy string   `json:"mihomo_why,omitempty"`
	Notes     []string `json:"notes,omitempty"`
}

type PlanView struct {
	Limit      uint64     `json:"limit"`
	Used       uint64     `json:"used"`
	Left       uint64     `json:"left"`
	BillingDay int        `json:"billing_day"`
	Timezone   string     `json:"timezone,omitempty"`
	Expires    string     `json:"expires,omitempty"`
	Next       *time.Time `json:"next_reset,omitempty"`
	Incomplete bool       `json:"incomplete,omitempty"`
}

func (a *App) subscriptionView(s State, sub Subscription, now time.Time, tokens map[string]string) SubscriptionView {
	v := SubscriptionView{ID: sub.ID, Name: sub.Name, Enabled: sub.Enabled, Aggregate: sub.aggregate(), Dedupe: sub.Dedupe, AllowInsecure: sub.AllowInsecure, Created: sub.CreatedAt, Items: []SubItemView{}}
	_, v.CanRevealURL = tokens[sub.TokenHash]
	byID := map[string]Profile{}
	for _, p := range s.Profiles {
		byID[p.ID] = p
	}
	if sub.aggregate() {
		exp := a.ExportAggregate(s, sub)
		for i, n := range exp.Nodes {
			it := sub.Items[i]
			iv := SubItemView{Kind: n.Kind, NodeID: it.NodeID, SourceID: it.SourceID, Source: n.Source, Name: n.Name, Custom: it.Name, Protocol: n.Protocol,
				Status: "ok", Skipped: a.T(n.Skipped), Base64OK: n.Base64OK, Base64Why: a.T(n.Base64Why), MihomoOK: n.MihomoOK, MihomoWhy: a.T(n.MihomoWhy), Notes: a.translateAll(n.Notes)}
			if it.Kind == itemRemote {
				// Return the node the entry resolved to: after a credential rotation the saved
				// ID is obsolete, and the editor sends this ID back when it saves.
				iv.NodeID = it.RemoteID
				if n.NodeID != "" {
					iv.NodeID = n.NodeID
				}
			}
			if n.Skipped != "" {
				iv.Status = "skipped"
			}
			if iv.Name == "" {
				iv.Name = it.NodeID
			}
			if it.Kind == itemLocal {
				v.Local++
			} else {
				v.Remote++
			}
			v.Items = append(v.Items, iv)
		}
	} else {
		exp := s.exportSubscription(sub)
		_ = exp
		for _, id := range sub.NodeIDs {
			iv := SubItemView{Kind: itemLocal, NodeID: id, Name: id, Status: "ok", Base64OK: true}
			p, ok := byID[id]
			switch {
			case !ok:
				iv.Status, iv.Skipped, iv.Base64OK = "skipped", a.T("节点已删除"), false
			case !p.Enabled:
				iv.Name, iv.Protocol = p.Name, p.Protocol
				iv.Status, iv.Skipped, iv.Base64OK = "skipped", a.T("节点已停用"), false
			default:
				iv.Name, iv.Protocol = p.Name, p.Protocol
				if _, e := p.URI(); e != nil {
					iv.Base64OK, iv.Base64Why = false, a.Error(e)
				}
				if _, e := mihomoNode(p); e == nil {
					iv.MihomoOK = true
				} else {
					iv.MihomoWhy = a.Error(e)
				}
			}
			v.Local++
			v.Items = append(v.Items, iv)
		}
	}
	if pv, ok := a.SubscriptionUsage(sub, now); ok {
		plan := &PlanView{Limit: pv.Plan.LimitBytes, Used: pv.Used, BillingDay: pv.Plan.BillingDay, Timezone: pv.Plan.Timezone, Expires: pv.Plan.Expires, Incomplete: pv.Incomplete}
		plan.Left = pv.remaining()
		if !pv.Next.IsZero() {
			n := pv.Next
			plan.Next = &n
		}
		v.Plan = plan
	}
	return v
}

func sortedProfiles(s State, kind string) []Profile {
	var out []Profile
	for _, p := range s.Profiles {
		if p.Kind == kind {
			out = append(out, p)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		ti, tj := time.Time{}, time.Time{}
		if out[i].CreatedAt != nil {
			ti = *out[i].CreatedAt
		}
		if out[j].CreatedAt != nil {
			tj = *out[j].CreatedAt
		}
		if !ti.Equal(tj) {
			return ti.Before(tj)
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out
}

// translateAll translates a list of server-generated messages into the request language.
func (a *App) translateAll(in []string) []string {
	if len(in) == 0 {
		return in
	}
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = a.T(s)
	}
	return out
}
