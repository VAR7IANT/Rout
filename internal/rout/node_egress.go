package rout

import (
	"errors"
	"fmt"
	"strings"
)

// Node outbound IP family.
//
// A node's traffic leaves through the "egress" outbound: a Direct connection by default, or
// the node's outbound proxy. Profile.OutboundPolicy (the same field and values relays use, see
// netpolicy.go) says which IP family that outbound may use. Unset means "auto": the generated
// configuration is then byte-for-byte what earlier versions wrote.
//
// What sing-box 1.14 enforces, established against the real engine (docs/NODE_EGRESS.md):
//
//   - dial.domain_resolver.strategy decides which of a NAME's addresses are used. ipv6_only
//     returns no address for an A-only name (the connection fails, nothing falls back to IPv4).
//   - It does NOT constrain a destination that is already an IP address: with only the
//     resolver set, a client that asks for 203.0.113.9 reaches it over IPv4 even in "ipv6_only".
//     A route rule on ip_version closes that: an "only" policy rejects the other family's
//     literals before they reach the outbound. sing-box already folds an IPv4-mapped IPv6
//     literal (::ffff:a.b.c.d) to IPv4, so that form cannot be used to get around the rule.
//   - The deprecated outbound "domain_strategy" is refused outright by sing-box 1.14, so it is
//     never generated.
//
// With an outbound proxy the policy cannot mean the same thing. Rout dials the proxy SERVER, so
// the policy governs that connection; which family the proxy then uses towards the website is
// the proxy's decision and cannot be enforced from here. The scope is reported everywhere
// (menu, panel, diagnostics) instead of being papered over.

// egressDNSTag names the resolver the generated configuration defines for a non-auto policy.
const egressDNSTag = "rout-egress-dns"

// Scopes of a node's outbound policy.
const (
	// egressScopeDirect: the node connects to the destination itself; the policy decides the
	// IP family of that connection.
	egressScopeDirect = "direct"
	// egressScopeProxy: the node connects to an outbound proxy; the policy decides the family
	// of the connection to the proxy server only.
	egressScopeProxy = "proxy"
)

// nodePolicyStrategy translates a policy into the sing-box resolver strategy.
func nodePolicyStrategy(policy string) string {
	switch policy {
	case outIPv4First:
		return "prefer_ipv4"
	case outIPv6First:
		return "prefer_ipv6"
	case outIPv4Only:
		return "ipv4_only"
	case outIPv6Only:
		return "ipv6_only"
	}
	return ""
}

func isOnlyPolicy(policy string) bool { return policy == outIPv4Only || policy == outIPv6Only }

// egressScope says what the node's policy governs, see the scope constants.
func (p Profile) egressScope() string {
	if p.Outbound != nil {
		return egressScopeProxy
	}
	return egressScopeDirect
}

// egressDial returns the dial fields to merge into the egress outbound, nil for auto.
func (p Profile) egressDial() M {
	s := nodePolicyStrategy(p.outboundPolicy())
	if p.Kind != "node" || s == "" {
		return nil
	}
	return M{"domain_resolver": M{"server": egressDNSTag, "strategy": s}}
}

// egressDNS returns the "dns" section a non-auto policy needs, nil for auto. The resolver is
// the system's own, exactly what an unset outbound uses.
func (p Profile) egressDNS() M {
	if p.egressDial() == nil {
		return nil
	}
	return M{"servers": []any{M{"type": "local", "tag": egressDNSTag}}}
}

// egressFamilyRule returns the route rule that makes an "only" policy hold for destinations
// that are IP addresses, nil when none is needed. It exists only for a Direct outbound: with an
// outbound proxy the destination's family is the proxy's business, see the scope above.
func (p Profile) egressFamilyRule() M {
	if p.Kind != "node" || p.Outbound != nil {
		return nil
	}
	switch p.outboundPolicy() {
	case outIPv6Only:
		return M{"inbound": []string{"entry"}, "ip_version": 4, "action": "reject"}
	case outIPv4Only:
		return M{"inbound": []string{"entry"}, "ip_version": 6, "action": "reject"}
	}
	return nil
}

// checkNodeEgress validates the node's outbound policy against its outbound. It runs as part of
// Profile.Validate, so every path that saves a node (menu, panel, restore, import) is covered.
func (p Profile) checkNodeEgress() error {
	if p.Kind != "node" {
		return nil
	}
	policy := p.outboundPolicy()
	if policy == outAuto || p.Outbound == nil {
		return nil
	}
	// The proxy server is dialed over the family the policy allows. A literal proxy address of
	// the other family can never be reached under an "only" policy; refuse it instead of
	// producing a node that cannot connect.
	f := familyOf(p.Outbound.Host)
	v4, v6 := outboundAllows(policy)
	if (f == "ipv4" && !v4) || (f == "ipv6" && !v6) {
		return fmt.Errorf("出站代理地址 %s 是 %s 地址，出站网络策略「%s」不允许使用；请改用自动，或使用域名形式的代理地址",
			p.Outbound.Host, map[string]string{"ipv4": "IPv4", "ipv6": "IPv6"}[f], outboundLabel(policy))
	}
	return nil
}

// ---- host capability --------------------------------------------------------------------------

// errNoRoute is returned by SetNodeOutboundPolicy when an "only" policy needs an IP family this
// host has no route for. Every connection would fail; the caller may confirm and force it
// (a route that appears later, or one the probe cannot see).
type errNoRoute struct{ Family string }

func (e *errNoRoute) Error() string {
	return fmt.Sprintf("本机没有 %s 出站路由，选择仅 %s 后节点将无法访问任何站点", e.Family, e.Family)
}

// requiredFamily is the family an "only" policy depends on ("" for the others).
func requiredFamily(policy string) string {
	switch policy {
	case outIPv4Only:
		return "IPv4"
	case outIPv6Only:
		return "IPv6"
	}
	return ""
}

// PolicyChoice is one entry of the policy list a menu or the panel offers.
type PolicyChoice struct {
	Policy string `json:"policy"` // auto, ipv4_first, ipv6_first, ipv4_only, ipv6_only
	// Available is false when choosing it would leave the node without any connectivity (an
	// "only" policy for a family the host has no route for).
	Available bool `json:"available"`
	// Missing names the IP family this policy involves that the host has no route for ("" when
	// none). A "first" policy with a missing family stays selectable: it simply behaves like the
	// other family.
	Missing string `json:"missing,omitempty"`
}

// nodePolicyChoices lists the five policies in their fixed order, annotated for this host. Nothing
// is hidden, so menu numbers never change with the host; a family the host cannot route is
// marked instead. When no route is detected at all everything is available, since the probe may
// simply be blind.
func nodePolicyChoices(routes familyRoutes) []PolicyChoice {
	blind := !routes.V4 && !routes.V6
	out := make([]PolicyChoice, 0, 5)
	for _, pol := range []string{outAuto, outIPv4First, outIPv6First, outIPv4Only, outIPv6Only} {
		c := PolicyChoice{Policy: pol, Available: true}
		if !blind {
			switch {
			case (pol == outIPv4First || pol == outIPv4Only) && !routes.V4:
				c.Missing = "IPv4"
			case (pol == outIPv6First || pol == outIPv6Only) && !routes.V6:
				c.Missing = "IPv6"
			}
			c.Available = !(c.Missing != "" && isOnlyPolicy(pol))
		}
		out = append(out, c)
	}
	return out
}

// checkPolicyRoute refuses an "only" policy for a family the host has no route for. A blind probe
// (no route of either family detected) never blocks.
func checkPolicyRoute(policy string) error {
	fam := requiredFamily(policy)
	if fam == "" {
		return nil
	}
	routes := hostRoutes()
	if (fam == "IPv4" && !routes.V4) || (fam == "IPv6" && !routes.V6) {
		if routes.V4 || routes.V6 {
			return &errNoRoute{Family: fam}
		}
	}
	return nil
}

// ---- change of policy ------------------------------------------------------------------------

// normalizeNodePolicy maps "auto" to the stored empty value, so an unset node and an explicit
// Auto are literally the same state.
func normalizeNodePolicy(policy string) (string, error) {
	policy = strings.TrimSpace(policy)
	switch {
	case policy == "" || policy == outAuto:
		return "", nil
	case validOutboundPolicy(policy):
		return policy, nil
	}
	return "", errors.New("出站网络策略无效")
}

// withNodePolicy returns s with the node's policy changed. It does not touch the host; the
// callers decide whether the route check applies.
func withNodePolicy(s State, id, policy string) (State, error) {
	p, e := Find(s, id)
	if e != nil {
		return s, e
	}
	if p.Kind != "node" {
		return s, errors.New("只有节点有出站网络策略；中转请在『修改网络』中设置")
	}
	norm, e := normalizeNodePolicy(policy)
	if e != nil {
		return s, e
	}
	p.OutboundPolicy = norm
	if e = p.Validate(); e != nil {
		return s, e
	}
	return replace(s, p), nil
}

// SetNodeOutboundPolicy changes one node's outbound IP family. It is the single code path of the
// menu and the panel: the new configuration is validated (including sing-box's own check), only
// the changed node is restarted and a failure restores the previous files and state. UUID, port,
// certificate and subscription links are untouched. An "only" policy on a host without a route
// for that family is refused unless force is set.
func (a *App) SetNodeOutboundPolicy(id, policy string, force bool) error {
	norm, e := normalizeNodePolicy(policy)
	if e != nil {
		return e
	}
	if !force {
		if e = checkPolicyRoute(norm); e != nil {
			return e
		}
	}
	return a.webMutate(func(old State) (State, error) { return withNodePolicy(old, id, norm) })
}

// ---- description ------------------------------------------------------------------------------

// EgressInfo is the node's outbound policy as shown to people: one description for the menu and
// the panel.
type EgressInfo struct {
	Policy string `json:"policy"` // effective: auto, ipv4_first, ipv6_first, ipv4_only, ipv6_only
	Scope  string `json:"scope"`  // direct or proxy
	// Enforced is true when Rout can guarantee the IP family of the connection that leaves for
	// the Internet: a Direct outbound with an "only" policy.
	Enforced bool `json:"enforced"`
}

func (p Profile) egressInfo() EgressInfo {
	pol := p.outboundPolicy()
	return EgressInfo{Policy: pol, Scope: p.egressScope(), Enforced: p.egressScope() == egressScopeDirect && isOnlyPolicy(pol)}
}

// egressScopeNote explains, in the catalog's source language, what the policy covers for this
// node. It is empty for auto.
func (p Profile) egressScopeNote() string {
	pol := p.outboundPolicy()
	if pol == outAuto {
		return ""
	}
	if p.Outbound != nil {
		if isOnlyPolicy(pol) {
			return "该节点使用出站代理：此策略只限制本机连接代理服务器所用的 IP 类型。代理访问网站时用哪种 IP 由代理决定，Rout 无法强制，也不会声称已强制"
		}
		return "该节点使用出站代理：此策略只影响本机连接代理服务器所用的 IP 类型；代理访问网站时用哪种 IP 由代理决定"
	}
	switch pol {
	case outIPv6Only:
		return "仅 IPv6：IPv4 地址和只有 A 记录的域名会被明确拒绝，不会回退 IPv4"
	case outIPv4Only:
		return "仅 IPv4：IPv6 地址和只有 AAAA 记录的域名会被明确拒绝，不会回退 IPv6"
	case outIPv6First:
		return "IPv6 优先：优先使用 IPv6，不通时回退 IPv4（UDP 会话只在建立时选择一次地址族）"
	case outIPv4First:
		return "IPv4 优先：优先使用 IPv4，不通时回退 IPv6（UDP 会话只在建立时选择一次地址族）"
	}
	return ""
}
