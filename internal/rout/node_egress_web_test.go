package rout

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func webNodeID(t *testing.T, m map[string]any) string {
	t.Helper()
	nodes := listOf(t, m, "nodes")
	if len(nodes) != 1 {
		t.Fatalf("nodes: %v", nodes)
	}
	return nodes[0]["id"].(string)
}

func TestWebNodesListCarriesThePolicyChoicesAndLegacyNodesReadAsAuto(t *testing.T) {
	withHostRoutes(t, familyRoutes{V4: true})
	e := newWebEnv(t)
	n := aiTestNode(t, e.a, "vless", "Legacy")
	c := e.login()
	m := jsonOf(t, c.get("/api/nodes"))
	choices := m["outbound_policies"].([]any)
	var order []string
	for _, ch := range choices {
		order = append(order, ch.(map[string]any)["policy"].(string))
	}
	if strings.Join(order, ",") != "auto,ipv4_first,ipv6_first,ipv4_only,ipv6_only" {
		t.Fatalf("order %v", order)
	}
	// annotated for an IPv4-only host: IPv6 only is not available, IPv6 first only marked
	byPolicy := map[string]map[string]any{}
	for _, ch := range choices {
		byPolicy[ch.(map[string]any)["policy"].(string)] = ch.(map[string]any)
	}
	if byPolicy["ipv6_only"]["available"] != false || byPolicy["ipv6_only"]["missing"] != "IPv6" || byPolicy["ipv6_first"]["available"] != true || byPolicy["ipv6_first"]["missing"] != "IPv6" {
		t.Fatalf("IPv4-only host: %v", byPolicy)
	}
	nodes := listOf(t, m, "nodes")
	if nodes[0]["id"] != n.ID || nodes[0]["outbound_policy"] != "auto" || nodes[0]["outbound_scope"] != "direct" || nodes[0]["outbound_enforced"] != false {
		t.Fatalf("a node that never set a policy must read as Auto: %v", nodes[0])
	}
}

func TestWebCreateNodeWithAnOutboundPolicy(t *testing.T) {
	withHostRoutes(t, dualRoutes())
	e := newWebEnv(t)
	c := e.login()
	w := c.do("POST", "/api/nodes", map[string]any{"base_name": "Turkey", "protocols": []string{"vless"}, "inbound": "ipv4", "outbound_policy": "ipv6_only"})
	mustOK(t, w.Code, w.Body.String())
	m := jsonOf(t, w)
	node := listOf(t, m, "nodes")[0]
	if node["outbound_policy"] != "ipv6_only" || node["outbound_enforced"] != true || node["outbound_scope"] != "direct" {
		t.Fatalf("view: %v", node)
	}
	// the inbound stayed IPv4: the outbound choice is independent of it
	if node["inbound"] != "ipv4" || node["listen"] != "0.0.0.0" {
		t.Fatalf("inbound changed: %v", node)
	}
	id := node["id"].(string)
	s := mustLoad(t, e.a)
	p, _ := Find(s, id)
	if p.OutboundPolicy != outIPv6Only {
		t.Fatalf("stored %q", p.OutboundPolicy)
	}
	if b, _ := os.ReadFile(filepath.Join(e.a.profileDir(id), "config.json")); !strings.Contains(string(b), `"strategy": "ipv6_only"`) || !strings.Contains(string(b), `"ip_version": 4`) {
		t.Fatalf("config:\n%s", b)
	}
	// "auto" and an omitted field both store the legacy, unset value
	for _, body := range []map[string]any{
		{"base_name": "A", "protocols": []string{"ss"}, "inbound": "ipv4", "outbound_policy": "auto"},
		{"base_name": "B", "protocols": []string{"ss"}, "inbound": "ipv4"},
	} {
		w = c.do("POST", "/api/nodes", body)
		mustOK(t, w.Code, w.Body.String())
		id := listOf(t, jsonOf(t, w), "nodes")[0]["id"].(string)
		if p, _ := Find(mustLoad(t, e.a), id); p.OutboundPolicy != "" {
			t.Fatalf("%v stored %q", body, p.OutboundPolicy)
		}
	}
	// invalid values are rejected before anything is created
	before := len(mustLoad(t, e.a).Profiles)
	if w = c.do("POST", "/api/nodes", map[string]any{"base_name": "C", "protocols": []string{"ss"}, "outbound_policy": "ipv7"}); w.Code != 400 {
		t.Fatalf("invalid policy: %d %s", w.Code, w.Body.String())
	}
	if len(mustLoad(t, e.a).Profiles) != before {
		t.Fatal("a rejected request created a node")
	}
}

func TestWebCreateNodeOnAHostWithoutThatFamilyNeedsConfirmation(t *testing.T) {
	withHostRoutes(t, familyRoutes{V4: true})
	e := newWebEnv(t)
	c := e.login()
	body := map[string]any{"base_name": "T", "protocols": []string{"vless"}, "inbound": "ipv4", "outbound_policy": "ipv6_only"}
	w := c.do("POST", "/api/nodes", body)
	if w.Code != 409 || errCode(t, w) != "no_route" {
		t.Fatalf("expected 409 no_route, got %d %s", w.Code, w.Body.String())
	}
	if len(mustLoad(t, e.a).Profiles) != 0 {
		t.Fatal("a refused request created a node")
	}
	body["force"] = true
	mustOK(t, c.do("POST", "/api/nodes", body).Code, "forced create")
	// IPv6 first is never blocked
	w = c.do("POST", "/api/nodes", map[string]any{"base_name": "F", "protocols": []string{"ss"}, "inbound": "ipv4", "outbound_policy": "ipv6_first"})
	mustOK(t, w.Code, w.Body.String())
}

func TestWebSetOutboundPolicy(t *testing.T) {
	withHostRoutes(t, dualRoutes())
	e := newWebEnv(t)
	n := aiTestNode(t, e.a, "vless", "Turkey-VLESS")
	other := aiTestNode(t, e.a, "ss", "Other")
	otherCfg, _ := os.ReadFile(filepath.Join(e.a.profileDir(other.ID), "config.json"))
	c := e.login()
	path := "/api/nodes/" + n.ID + "/outbound-policy"

	w := c.do("PUT", path, map[string]any{"policy": "ipv6_only"})
	mustOK(t, w.Code, w.Body.String())
	view := listOf(t, jsonOf(t, w), "nodes")[0]
	if view["outbound_policy"] != "ipv6_only" || view["outbound_enforced"] != true || view["id"] != n.ID {
		t.Fatalf("response: %v", view)
	}
	got, _ := Find(mustLoad(t, e.a), n.ID)
	if got.UUID != n.UUID || got.Port != n.Port || got.PrivateKey != n.PrivateKey {
		t.Fatal("identity changed")
	}
	if b, _ := os.ReadFile(filepath.Join(e.a.profileDir(other.ID), "config.json")); string(b) != string(otherCfg) {
		t.Fatal("another node's configuration was rewritten")
	}
	// the list now shows it, and the CLI would see the same stored value
	if nodes := listOf(t, jsonOf(t, c.get("/api/nodes")), "nodes"); nodes[0]["outbound_policy"] == nil {
		t.Fatal("list lacks the policy")
	}
	// back to auto stores the legacy value
	mustOK(t, c.do("PUT", path, map[string]any{"policy": "auto"}).Code, "auto")
	if got, _ = Find(mustLoad(t, e.a), n.ID); got.OutboundPolicy != "" {
		t.Fatalf("auto stored %q", got.OutboundPolicy)
	}
	// rejected input
	for _, bad := range []map[string]any{{"policy": "ipv7"}, {"policy": 5}, {}} {
		if w = c.do("PUT", path, bad); w.Code < 400 || w.Code >= 500 {
			// an empty policy means auto; only the first two must be refused
			if len(bad) == 0 {
				continue
			}
			t.Fatalf("%v accepted: %d %s", bad, w.Code, w.Body.String())
		}
	}
	if w = c.do("PUT", "/api/nodes/ffffffffffff/outbound-policy", map[string]any{"policy": "ipv4_only"}); w.Code != 404 {
		t.Fatalf("unknown id: %d", w.Code)
	}
	// a relay is not a node
	relay := Profile{ID: "aaaaaaaaaaaa", Name: "r", Kind: "relay", Enabled: true, Protocol: "tcp", Listen: "0.0.0.0", Port: 24600, PublicHost: "203.0.113.10", PublicPort: 24600, Target: "127.0.0.1:" + itoa(n.Port), RelayMode: relayLocal}
	s := mustLoad(t, e.a)
	if er := e.a.Commit(s, replace(s, relay), false); er != nil {
		t.Skipf("fixture relay unavailable: %v", er)
	}
	if w = c.do("PUT", "/api/nodes/"+relay.ID+"/outbound-policy", map[string]any{"policy": "ipv4_only"}); w.Code != 404 {
		t.Fatalf("relay: %d %s", w.Code, w.Body.String())
	}
}

func TestWebSetOutboundPolicyNoRouteAndRollback(t *testing.T) {
	e := newWebEnv(t)
	n := aiTestNode(t, e.a, "vless", "Turkey-VLESS")
	c := e.login()
	path := "/api/nodes/" + n.ID + "/outbound-policy"
	withHostRoutes(t, familyRoutes{V4: true})
	w := c.do("PUT", path, map[string]any{"policy": "ipv6_only"}, withHeader("X-Rout-Lang", "en"))
	if w.Code != 409 || errCode(t, w) != "no_route" {
		t.Fatalf("expected 409 no_route: %d %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "This server has no IPv6 route") {
		t.Fatalf("message: %s", w.Body.String())
	}
	if got, _ := Find(mustLoad(t, e.a), n.ID); got.OutboundPolicy != "" {
		t.Fatal("a refused change was stored")
	}
	if strings.Contains(w.Body.String(), "本机") {
		t.Fatalf("Chinese in a response for an English client? %s", w.Body.String())
	}
	// confirmed
	mustOK(t, c.do("PUT", path, map[string]any{"policy": "ipv6_only", "force": true}).Code, "forced")

	// the engine refuses the new configuration: state and files are restored, the error reaches the client
	state, _ := os.ReadFile(filepath.Join(e.a.Home, "state.json"))
	cfgPath := filepath.Join(e.a.profileDir(n.ID), "config.json")
	cfgBefore, _ := os.ReadFile(cfgPath)
	if er := os.WriteFile(e.a.enginePath("sing-box"), []byte("#!/bin/sh\nexit 1\n"), 0755); er != nil {
		t.Fatal(er)
	}
	withHostRoutes(t, dualRoutes())
	if w = c.do("PUT", path, map[string]any{"policy": "ipv4_only"}); w.Code < 400 {
		t.Fatalf("a rejected configuration was accepted: %d", w.Code)
	}
	stateAfter, _ := os.ReadFile(filepath.Join(e.a.Home, "state.json"))
	cfgAfter, _ := os.ReadFile(cfgPath)
	if string(state) != string(stateAfter) || string(cfgBefore) != string(cfgAfter) {
		t.Fatal("a failed change left state or configuration behind")
	}
}

func TestWebEgressTestEndpoint(t *testing.T) {
	e := newWebEnv(t)
	n := egressNode(t, e.a, outIPv6Only, nil)
	f := egressFake{routes: dualRoutes(), hostV4: "203.0.113.10", hostV6: "2001:db8::10", lit: litTargets,
		probe: egressProbe{V6: "2001:db8::77", ErrV4: errBlocked, Lit4: blocked(), Lit6: allowed()}}
	env := f.env()
	e.a.webHooks.egress = &env
	c := e.login()
	path := "/api/nodes/" + n.ID + "/egress-test"

	w := c.do("POST", path, map[string]any{}, withHeader("X-Rout-Lang", "en"))
	mustOK(t, w.Code, w.Body.String())
	m := jsonOf(t, w)
	if m["result"] != "pass" || m["policy"] != "ipv6_only" || m["enforced"] != true || m["quick"] != false {
		t.Fatalf("report: %v", m)
	}
	host := m["host"].(map[string]any)["v6"].(map[string]any)
	node := m["node"].(map[string]any)["v6"].(map[string]any)
	if host["ip"] != "2001:db8::10" || node["ip"] != "2001:db8::77" {
		t.Fatalf("host/node measurements mixed: %v %v", host, node)
	}
	if hanRe.MatchString(w.Body.String()) {
		t.Fatalf("Chinese text in an English response: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "IPv4 fallback is blocked") {
		t.Fatalf("no policy verification in the report: %s", w.Body.String())
	}
	// the same report in Chinese
	w = c.do("POST", path, nil, withHeader("X-Rout-Lang", "zh-CN"))
	mustOK(t, w.Code, w.Body.String())
	if !strings.Contains(w.Body.String(), "回退已禁止") {
		t.Fatalf("zh-CN report: %s", w.Body.String())
	}
	// quick view: addresses, no verdict
	w = c.do("POST", path, map[string]any{"quick": true}, withHeader("X-Rout-Lang", "en"))
	mustOK(t, w.Code, w.Body.String())
	if q := jsonOf(t, w); q["quick"] != true || q["result"] != "" {
		t.Fatalf("quick: %v", q)
	}
	// what is not a running node
	if w = c.do("POST", "/api/nodes/ffffffffffff/egress-test", nil); w.Code != 404 {
		t.Fatalf("unknown: %d", w.Code)
	}
	// only one measurement at a time
	for i := 0; i < cap(e.ws.diagSem); i++ {
		e.ws.diagSem <- struct{}{}
	}
	if w = c.do("POST", path, nil); w.Code != 429 {
		t.Fatalf("a measurement beyond the limit: %d %s", w.Code, w.Body.String())
	}
	for i := 0; i < cap(e.ws.diagSem); i++ {
		<-e.ws.diagSem
	}
	// unauthenticated clients get nothing
	if w = e.anon().do("POST", path, nil); w.Code != 401 {
		t.Fatalf("anon: %d", w.Code)
	}
}

// The terminal and the panel edit one stored value through one code path.
func TestWebAndTerminalShareThePolicy(t *testing.T) {
	withHostRoutes(t, dualRoutes())
	e := newWebEnv(t)
	n := aiTestNode(t, e.a, "vless", "Turkey-VLESS")
	c := e.login()
	mustOK(t, c.do("PUT", "/api/nodes/"+n.ID+"/outbound-policy", map[string]any{"policy": "ipv4_only"}).Code, "panel set")
	// the terminal shows what the panel saved
	u, out := testUI(e.a, "8\n0\n0\n")
	u.routes = dualRoutes
	if er := u.nodeMenu(n.ID); er != nil {
		t.Fatal(er)
	}
	if !strings.Contains(out.String(), "Current policy: IPv4 only") {
		t.Fatalf("terminal does not show the panel's policy:\n%s", out.String())
	}
	// the terminal changes it, the panel shows it
	u, out = testUI(e.a, "8\n1\n3\n0\n0\n")
	u.routes = dualRoutes
	if er := u.nodeMenu(n.ID); er != nil {
		t.Fatal(er, out.String())
	}
	nodes := listOf(t, jsonOf(t, c.get("/api/nodes")), "nodes")
	if nodes[0]["outbound_policy"] != "ipv6_first" {
		t.Fatalf("panel does not show the terminal's policy: %v", nodes[0])
	}
}

// Relay views embed the node view; they must not inherit the node-only fields, and keep their own
// outbound_policy exactly as before.
func TestWebRelayViewsAreUnchangedByTheNodePolicyFields(t *testing.T) {
	e := newWebEnv(t)
	r := nativeRelayProfile(inIPv4, outIPv6Only, "target.example:443", 24690)
	r.ID, r.Name = "bbbbbbbbbbbb", "Native-Relay"
	s := mustLoad(t, e.a)
	if er := e.a.Commit(s, replace(s, r), false); er != nil {
		t.Fatal(er)
	}
	c := e.login()
	relays := listOf(t, jsonOf(t, c.get("/api/relays")), "relays")
	if len(relays) != 1 {
		t.Fatalf("relays: %v", relays)
	}
	if relays[0]["outbound_policy"] != "ipv6_only" {
		t.Fatalf("the relay's own policy changed: %v", relays[0]["outbound_policy"])
	}
	for _, key := range []string{"outbound_scope", "outbound_enforced", "outbound_note"} {
		if _, has := relays[0][key]; has {
			t.Fatalf("relay view inherited the node-only field %q: %v", key, relays[0])
		}
	}
}
