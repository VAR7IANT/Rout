package rout

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Configuration-level tests for the node outbound IP family. The behaviour of the generated
// configuration against the real sing-box engine is in node_egress_integration_test.go.

func egressNodeConfig(t *testing.T, p Profile) M {
	t.Helper()
	return egressNodeConfigIn(t, p, t.TempDir())
}

// egressNodeConfigIn renders in a given directory, so two renderings can be compared byte for byte
// (the certificate paths are part of the output).
func egressNodeConfigIn(t *testing.T, p Profile, dir string) M {
	t.Helper()
	cfg, e := serverConfig(p, dir)
	if e != nil {
		t.Fatal(e)
	}
	return cfg
}

func jsonOfValue(t *testing.T, v any) string {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return string(b)
}

func routeRules(t *testing.T, cfg M) []M {
	t.Helper()
	var out []M
	for _, r := range cfg["route"].(M)["rules"].([]any) {
		out = append(out, r.(M))
	}
	return out
}

func egressOutbound(t *testing.T, cfg M) M {
	t.Helper()
	for _, o := range cfg["outbounds"].([]any) {
		if m := o.(M); m["tag"] == "egress" {
			return m
		}
	}
	t.Fatal("no egress outbound")
	return nil
}

func TestNodeEgressAutoRendersExactlyWhatEarlierVersionsWrote(t *testing.T) {
	for _, protocol := range []string{"vless", "anytls", "ss", "hy2", "tuic"} {
		dir := t.TempDir()
		p := fixture(t, protocol)
		legacy := jsonOfValue(t, egressNodeConfigIn(t, p, dir))
		for _, policy := range []string{"", outAuto} {
			p.OutboundPolicy = policy
			if got := jsonOfValue(t, egressNodeConfigIn(t, p, dir)); got != legacy {
				t.Fatalf("%s policy %q changed the configuration of a legacy node:\n%s\n%s", protocol, policy, legacy, got)
			}
		}
		cfg := egressNodeConfig(t, fixture(t, protocol))
		if _, ok := cfg["dns"]; ok {
			t.Fatalf("%s: auto must not add a dns section", protocol)
		}
		if !reflect.DeepEqual(egressOutbound(t, cfg), M{"type": "direct", "tag": "egress"}) {
			t.Fatalf("%s: auto egress is %v", protocol, egressOutbound(t, cfg))
		}
		rules := routeRules(t, cfg)
		if len(rules) != 1 || rules[0]["action"] != "route" {
			t.Fatalf("%s: auto rules are %v", protocol, rules)
		}
	}
}

func TestNodeEgressPoliciesProduceTheDocumentedConfiguration(t *testing.T) {
	cases := []struct {
		policy, strategy string
		ruleVersion      int // 0: no family rule
	}{
		{outIPv4First, "prefer_ipv4", 0},
		{outIPv6First, "prefer_ipv6", 0},
		{outIPv4Only, "ipv4_only", 6},
		{outIPv6Only, "ipv6_only", 4},
	}
	for _, c := range cases {
		p := fixture(t, "vless")
		p.OutboundPolicy = c.policy
		cfg := egressNodeConfig(t, p)
		out := egressOutbound(t, cfg)
		if out["type"] != "direct" {
			t.Fatalf("%s: egress is no longer direct: %v", c.policy, out)
		}
		want := M{"server": egressDNSTag, "strategy": c.strategy}
		if !reflect.DeepEqual(out["domain_resolver"], want) {
			t.Fatalf("%s: domain_resolver %v, want %v", c.policy, out["domain_resolver"], want)
		}
		dns := cfg["dns"].(M)["servers"].([]any)
		if len(dns) != 1 || !reflect.DeepEqual(dns[0], M{"type": "local", "tag": egressDNSTag}) {
			t.Fatalf("%s: dns servers %v", c.policy, dns)
		}
		rules := routeRules(t, cfg)
		last := rules[len(rules)-1]
		if last["action"] != "route" || last["outbound"] != "egress" {
			t.Fatalf("%s: the route to egress must stay last: %v", c.policy, rules)
		}
		if c.ruleVersion == 0 {
			if len(rules) != 1 {
				t.Fatalf("%s: a First policy must not reject anything: %v", c.policy, rules)
			}
			continue
		}
		fam := rules[len(rules)-2]
		if fam["action"] != "reject" || fam["ip_version"] != c.ruleVersion || !reflect.DeepEqual(fam["inbound"], []string{"entry"}) {
			t.Fatalf("%s: family rule %v", c.policy, fam)
		}
		// the deprecated field sing-box 1.14 refuses is never generated
		if strings.Contains(jsonOfValue(t, cfg), "domain_strategy") {
			t.Fatalf("%s: configuration uses the removed domain_strategy", c.policy)
		}
	}
}

func TestNodeEgressRuleOrderWithTheIPv6InboundAndAI(t *testing.T) {
	p := fixture(t, "vless")
	p.OutboundPolicy = outIPv6Only
	p.InboundMode, p.Listen = inIPv6, "::"
	p.AIRoute = &AIRoute{Outbound: &Proxy{Protocol: "socks5", Host: "198.51.100.7", Port: 1080, Username: "u", Password: "p"}}
	cfg := egressNodeConfig(t, p)
	var kinds []string
	for _, r := range routeRules(t, cfg) {
		switch {
		case r["source_ip_cidr"] != nil:
			kinds = append(kinds, "ipv6-inbound-guard")
		case r["ip_version"] != nil:
			kinds = append(kinds, "family")
		case r["domain_suffix"] != nil || r["action"] == "sniff":
			kinds = append(kinds, "ai")
		case r["action"] == "route" && r["outbound"] == "egress":
			kinds = append(kinds, "egress")
		default:
			kinds = append(kinds, "other:"+jsonOfValue(t, r))
		}
	}
	idx := func(k string) int {
		for i, v := range kinds {
			if v == k {
				return i
			}
		}
		return -1
	}
	if idx("ipv6-inbound-guard") != 0 {
		t.Fatalf("the IPv6-inbound guard must stay first: %v", kinds)
	}
	last := func(k string) int {
		for i := len(kinds) - 1; i >= 0; i-- {
			if kinds[i] == k {
				return i
			}
		}
		return -1
	}
	if !(idx("ai") > 0 && last("ai") < idx("family") && idx("family") < idx("egress")) {
		t.Fatalf("AI rules must win over the family rule, which must precede the ordinary route: %v", kinds)
	}
	for _, k := range kinds {
		if strings.HasPrefix(k, "other:") {
			t.Fatalf("unexpected rule: %v", kinds)
		}
	}
	// the AI exit is a separate outbound that the node's policy does not touch
	seenAI := false
	for _, o := range cfg["outbounds"].([]any) {
		if m := o.(M); m["tag"] != "egress" {
			seenAI = true
			if m["domain_resolver"] != nil {
				t.Fatalf("the AI exit must not inherit the node policy: %v", m)
			}
		}
	}
	if !seenAI {
		t.Fatal("AI exit outbound missing")
	}
}

func TestNodeEgressWithAnOutboundProxyIsScopedToTheProxyConnection(t *testing.T) {
	for _, policy := range []string{outIPv4First, outIPv6First, outIPv4Only, outIPv6Only} {
		p := fixture(t, "vless")
		p.OutboundPolicy = policy
		p.Outbound = &Proxy{Protocol: "socks5", Host: "proxy.example.net", Port: 1080, Username: "u", Password: "p"}
		cfg := egressNodeConfig(t, p)
		out := egressOutbound(t, cfg)
		if out["type"] != "socks" || out["domain_resolver"] == nil {
			t.Fatalf("%s: the proxy connection must carry the policy: %v", policy, out)
		}
		for _, r := range routeRules(t, cfg) {
			if r["ip_version"] != nil {
				t.Fatalf("%s: destination literals are the proxy's business, no family rule may exist: %v", policy, r)
			}
		}
		// UDP stays rejected: there is no fallback around the proxy
		if r := routeRules(t, cfg)[0]; r["network"] != "udp" || r["action"] != "reject" {
			t.Fatalf("%s: UDP reject rule missing: %v", policy, r)
		}
		if p.egressScope() != egressScopeProxy || p.egressInfo().Enforced {
			t.Fatalf("%s: a proxy exit must never be reported as enforced: %+v", policy, p.egressInfo())
		}
		if note := p.egressScopeNote(); !strings.Contains(note, "代理") {
			t.Fatalf("%s: no scope note: %q", policy, note)
		}
	}
	d := fixture(t, "vless")
	d.OutboundPolicy = outIPv6Only
	if info := d.egressInfo(); info.Scope != egressScopeDirect || !info.Enforced {
		t.Fatalf("direct + only must be enforced: %+v", info)
	}
	d.OutboundPolicy = outIPv6First
	if info := d.egressInfo(); info.Enforced {
		t.Fatalf("a First policy is not an enforcement: %+v", info)
	}
}

func TestNodeEgressProxyExitTypesCarryTheResolver(t *testing.T) {
	link := "ss://MjAyMi1ibGFrZTMtYWVzLTEyOC1nY206QUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ@proxy.example.net:8388#x"
	for _, px := range []*Proxy{
		{Protocol: "http", Host: "proxy.example.net", Port: 8080, Username: "u", Password: "p"},
		{Protocol: "https", Host: "proxy.example.net", Port: 443, Username: "u", Password: "p"},
		{Protocol: proxyNode, Host: "proxy.example.net", Port: 8388, Link: link},
	} {
		p := fixture(t, "ss")
		p.OutboundPolicy = outIPv6Only
		p.Outbound = px
		out := egressOutbound(t, egressNodeConfig(t, p))
		if out["domain_resolver"] == nil || out["tag"] != "egress" {
			t.Fatalf("%s exit lost the policy: %v", px.Protocol, out)
		}
	}
}

func TestNodeEgressValidation(t *testing.T) {
	ok := func(p Profile) {
		t.Helper()
		if e := p.Validate(); e != nil {
			t.Fatalf("%+v: %v", p.OutboundPolicy, e)
		}
	}
	bad := func(p Profile, want string) {
		t.Helper()
		e := p.Validate()
		if e == nil || !strings.Contains(e.Error(), want) {
			t.Fatalf("expected %q, got %v", want, e)
		}
	}
	p := fixture(t, "vless")
	for _, pol := range []string{"", outAuto, outIPv4First, outIPv6First, outIPv4Only, outIPv6Only} {
		p.OutboundPolicy = pol
		ok(p)
	}
	p.OutboundPolicy = "ipv7"
	bad(p, "出站网络策略无效")
	// a literal proxy address of the forbidden family can never be dialed
	p = fixture(t, "vless")
	p.Outbound = &Proxy{Protocol: "socks5", Host: "198.51.100.7", Port: 1080, Username: "u", Password: "p"}
	p.OutboundPolicy = outIPv6Only
	bad(p, "不允许使用")
	p.OutboundPolicy = outIPv4Only
	ok(p)
	p.OutboundPolicy = outIPv6First
	ok(p)
	p.Outbound = &Proxy{Protocol: "socks5", Host: "2001:db8::7", Port: 1080, Username: "u", Password: "p"}
	p.OutboundPolicy = outIPv4Only
	bad(p, "不允许使用")
	p.OutboundPolicy = outIPv6Only
	ok(p)
	// a name may resolve to either family, so it is accepted under an "only" policy
	p.Outbound = &Proxy{Protocol: "socks5", Host: "proxy.example.net", Port: 1080, Username: "u", Password: "p"}
	p.OutboundPolicy = outIPv4Only
	ok(p)
}

func TestNodeEgressDoesNotTouchRelays(t *testing.T) {
	// the relay's own outbound policy keeps its rules and its engine requirement
	r := Profile{ID: "aaaaaaaaaaaa", Name: "r", Kind: "relay", Enabled: true, Protocol: "both", Listen: "0.0.0.0", Port: 24600, PublicHost: "203.0.113.10", PublicPort: 24600, Target: "203.0.113.20:443", OutboundPolicy: outIPv6Only}
	if e := r.Validate(); e == nil || !strings.Contains(e.Error(), "内置转发引擎") {
		t.Fatalf("a legacy relay with an outbound policy must still be refused: %v", e)
	}
	r.Engine = engineNative
	r.InboundMode = inIPv4
	if e := r.Validate(); e == nil {
		t.Fatal("a native relay must still refuse an IPv4 literal under IPv6 only")
	}
	if len(r.egressDial()) != 0 || r.egressFamilyRule() != nil || r.egressDNS() != nil {
		t.Fatal("relays never get node egress options")
	}
	cfg, e := serverConfig(Profile{ID: "bbbbbbbbbbbb", Kind: "relay", Enabled: true, Protocol: "tcp", Listen: "0.0.0.0", Port: 24601, Target: "203.0.113.20:443"}, t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if _, ok := cfg["dns"]; ok || cfg["services"] == nil {
		t.Fatalf("legacy relay configuration changed: %v", cfg)
	}
}

func TestNodePolicyChoicesFollowTheHost(t *testing.T) {
	order := []string{outAuto, outIPv4First, outIPv6First, outIPv4Only, outIPv6Only}
	cases := []struct {
		name    string
		routes  familyRoutes
		missing map[string]string // policy -> missing family
		blocked []string          // unavailable policies
	}{
		{"dual stack", familyRoutes{V4: true, V6: true}, nil, nil},
		{"IPv4-only VPS", familyRoutes{V4: true}, map[string]string{outIPv6First: "IPv6", outIPv6Only: "IPv6"}, []string{outIPv6Only}},
		{"IPv6-only VPS", familyRoutes{V6: true}, map[string]string{outIPv4First: "IPv4", outIPv4Only: "IPv4"}, []string{outIPv4Only}},
		{"blind probe offers everything", familyRoutes{}, nil, nil},
	}
	for _, c := range cases {
		got := nodePolicyChoices(c.routes)
		if len(got) != 5 {
			t.Fatalf("%s: %d choices", c.name, len(got))
		}
		for i, ch := range got {
			if ch.Policy != order[i] {
				t.Errorf("%s: menu order changed: %v", c.name, got)
			}
			if ch.Missing != c.missing[ch.Policy] {
				t.Errorf("%s: %s missing=%q, want %q", c.name, ch.Policy, ch.Missing, c.missing[ch.Policy])
			}
			if blocked := contains(c.blocked, ch.Policy); ch.Available == blocked {
				t.Errorf("%s: %s available=%v", c.name, ch.Policy, ch.Available)
			}
		}
	}
}

// ---- changing the policy of a stored node -------------------------------------------------------------

func withHostRoutes(t *testing.T, r familyRoutes) {
	t.Helper()
	old := hostRoutes
	hostRoutes = func() familyRoutes { return r }
	t.Cleanup(func() { hostRoutes = old })
}

func TestSetNodeOutboundPolicyKeepsEverythingElseAndOnlyRewritesThatNode(t *testing.T) {
	withHostRoutes(t, familyRoutes{V4: true, V6: true})
	a := testApp(t)
	a1 := aiTestNode(t, a, "vless", "Turkey-VLESS")
	b1 := aiTestNode(t, a, "ss", "Other-SS")
	read := func(p Profile) []byte {
		b, e := os.ReadFile(filepath.Join(a.profileDir(p.ID), "config.json"))
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	otherBefore := read(b1)
	before, _ := a.Load()
	nodeBefore, _ := Find(before, a1.ID)

	if e := a.SetNodeOutboundPolicy(a1.ID, outIPv6Only, false); e != nil {
		t.Fatal(e)
	}
	s, _ := a.Load()
	nodeAfter, _ := Find(s, a1.ID)
	if nodeAfter.OutboundPolicy != outIPv6Only {
		t.Fatalf("policy not stored: %q", nodeAfter.OutboundPolicy)
	}
	// identity, credentials, port, certificate and the subscription link are untouched
	nodeAfter.OutboundPolicy = nodeBefore.OutboundPolicy
	if !reflect.DeepEqual(nodeAfter, nodeBefore) {
		t.Fatalf("changing the policy changed more than the policy:\n%+v\n%+v", nodeBefore, nodeAfter)
	}
	cfg := string(read(a1))
	if !strings.Contains(cfg, `"strategy": "ipv6_only"`) || !strings.Contains(cfg, `"ip_version": 4`) {
		t.Fatalf("the node's configuration was not regenerated:\n%s", cfg)
	}
	if string(read(b1)) != string(otherBefore) {
		t.Fatal("another node's configuration was rewritten")
	}
	// back to Auto: the stored value disappears and the legacy configuration returns
	if e := a.SetNodeOutboundPolicy(a1.ID, outAuto, false); e != nil {
		t.Fatal(e)
	}
	s, _ = a.Load()
	if n, _ := Find(s, a1.ID); n.OutboundPolicy != "" {
		t.Fatalf("Auto must be stored as unset, got %q", n.OutboundPolicy)
	}
	if strings.Contains(string(read(a1)), "domain_resolver") || strings.Contains(string(read(a1)), `"dns"`) {
		t.Fatal("Auto left egress options behind")
	}
	// invalid input and relays
	if e := a.SetNodeOutboundPolicy(a1.ID, "bogus", false); e == nil {
		t.Fatal("bogus policy accepted")
	}
	if e := a.SetNodeOutboundPolicy("ffffffffffff", outIPv4Only, false); e == nil {
		t.Fatal("unknown node accepted")
	}
}

func TestSetNodeOutboundPolicyRollsBackWhenTheEngineRejectsIt(t *testing.T) {
	withHostRoutes(t, familyRoutes{V4: true, V6: true})
	a := testApp(t)
	n := aiTestNode(t, a, "vless", "Turkey-VLESS")
	state, _ := os.ReadFile(filepath.Join(a.Home, "state.json"))
	cfgPath := filepath.Join(a.profileDir(n.ID), "config.json")
	cfgBefore, _ := os.ReadFile(cfgPath)
	// sing-box refuses the new configuration
	if e := os.WriteFile(a.enginePath("sing-box"), []byte("#!/bin/sh\nexit 1\n"), 0755); e != nil {
		t.Fatal(e)
	}
	if e := a.SetNodeOutboundPolicy(n.ID, outIPv6Only, false); e == nil {
		t.Fatal("a rejected configuration was accepted")
	}
	stateAfter, _ := os.ReadFile(filepath.Join(a.Home, "state.json"))
	cfgAfter, _ := os.ReadFile(cfgPath)
	if string(state) != string(stateAfter) || string(cfgBefore) != string(cfgAfter) {
		t.Fatal("a failed change left state or configuration behind")
	}
}

func TestSetNodeOutboundPolicyOnAHostWithoutThatFamily(t *testing.T) {
	a := testApp(t)
	n := aiTestNode(t, a, "vless", "Turkey-VLESS")
	// IPv4-only VPS
	withHostRoutes(t, familyRoutes{V4: true})
	var nr *errNoRoute
	if e := a.SetNodeOutboundPolicy(n.ID, outIPv6Only, false); !errors.As(e, &nr) || nr.Family != "IPv6" {
		t.Fatalf("IPv6 only on an IPv4-only host must ask for confirmation: %v", e)
	}
	if s, _ := a.Load(); func() bool { p, _ := Find(s, n.ID); return p.OutboundPolicy != "" }() {
		t.Fatal("a refused change was stored")
	}
	for _, ok := range []string{outIPv4Only, outIPv4First, outIPv6First, outAuto} {
		if e := a.SetNodeOutboundPolicy(n.ID, ok, false); e != nil {
			t.Fatalf("%s must be allowed on an IPv4-only host: %v", ok, e)
		}
	}
	// the owner may confirm anyway
	if e := a.SetNodeOutboundPolicy(n.ID, outIPv6Only, true); e != nil {
		t.Fatal(e)
	}
	// IPv6-only VPS
	withHostRoutes(t, familyRoutes{V6: true})
	if e := a.SetNodeOutboundPolicy(n.ID, outIPv4Only, false); !errors.As(e, &nr) || nr.Family != "IPv4" {
		t.Fatalf("IPv4 only on an IPv6-only host must ask for confirmation: %v", e)
	}
	// dual stack and a blind probe never block
	for _, r := range []familyRoutes{{V4: true, V6: true}, {}} {
		withHostRoutes(t, r)
		for _, pol := range []string{outIPv4Only, outIPv6Only} {
			if e := a.SetNodeOutboundPolicy(n.ID, pol, false); e != nil {
				t.Fatalf("routes %+v policy %s: %v", r, pol, e)
			}
		}
	}
}

func TestSetNodeOutboundPolicyWithAnOutboundProxy(t *testing.T) {
	withHostRoutes(t, familyRoutes{V4: true, V6: true})
	a := testApp(t)
	n := aiTestNode(t, a, "vless", "Turkey-VLESS")
	ex := aiTestExit(t, a, "Proxy-v4", "198.51.100.77", 1080)
	s, _ := a.Load()
	s, e := BindExit(s, n.ID, ex.ID)
	if e != nil {
		t.Fatal(e)
	}
	if e = a.Commit(mustLoad(t, a), s, false); e != nil {
		t.Fatal(e)
	}
	// the proxy is an IPv4 literal: IPv6 only could never reach it
	if e = a.SetNodeOutboundPolicy(n.ID, outIPv6Only, false); e == nil || !strings.Contains(e.Error(), "不允许使用") {
		t.Fatalf("expected the literal-proxy conflict, got %v", e)
	}
	if e = a.SetNodeOutboundPolicy(n.ID, outIPv4Only, false); e != nil {
		t.Fatal(e)
	}
	// binding a proxy of the other family later is refused by the same validation
	s = mustLoad(t, a)
	p, _ := Find(s, n.ID)
	if info := p.egressInfo(); info.Scope != egressScopeProxy || info.Enforced {
		t.Fatalf("scope: %+v", info)
	}
	v6 := aiTestExit(t, a, "Proxy-v6", "2001:db8::77", 1080)
	next, _ := BindExit(mustLoad(t, a), n.ID, v6.ID)
	if e = a.Commit(mustLoad(t, a), next, false); e == nil {
		t.Fatal("binding an IPv6-literal proxy under IPv4 only must be refused")
	}
}
