package rout

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These tests run entirely in temporary directories with ServiceMode "none" and a stub
// sing-box. They check the GENERATED CONFIGURATION and state transitions. Routing is
// evaluated by a small simulator (simulateRoute) that follows sing-box's first-match rule
// semantics over the generated JSON; it is a simulation, not a live network test.

func aiTestNode(t *testing.T, a *App, protocol, name string) Profile {
	t.Helper()
	p := fixture(t, protocol)
	p.Name = name
	p.Port, _ = freePort()
	p.PublicPort = p.Port
	if protocol == "hy2" || protocol == "tuic" {
		cert, key, e := GenerateCertificate("203.0.113.10")
		if e != nil {
			t.Fatal(e)
		}
		p.SNI, p.CertPEM, p.KeyPEM, p.TLSGenerated = "203.0.113.10", cert, key, true
	}
	s, e := a.Load()
	if e != nil {
		t.Fatal(e)
	}
	if e = a.Commit(s, replace(s, p), false); e != nil {
		t.Fatal(e)
	}
	return p
}

func aiTestExit(t *testing.T, a *App, name, host string, port int) Exit {
	t.Helper()
	s, e := a.Load()
	if e != nil {
		t.Fatal(e)
	}
	ex := Exit{ID: RandomHex(6), Name: name, Proxy: Proxy{"socks5", host, port, "user", "pass"}}
	if e = a.Commit(s, UpsertExit(s, ex), false); e != nil {
		t.Fatal(e)
	}
	return ex
}

func readConfigFile(t *testing.T, a *App, p Profile) ([]byte, M) {
	t.Helper()
	b, e := os.ReadFile(filepath.Join(a.profileDir(p.ID), "config.json"))
	if e != nil {
		t.Fatal(e)
	}
	var m M
	if e = json.Unmarshal(b, &m); e != nil {
		t.Fatal(e)
	}
	return b, m
}

func toStrings(v any) []string {
	var out []string
	switch x := v.(type) {
	case []any:
		for _, e := range x {
			out = append(out, e.(string))
		}
	case []string:
		out = x
	}
	return out
}

// simulateRoute evaluates a generated sing-box route the way sing-box does: rules in order;
// a sniff rule does not end evaluation; the first matching reject/route rule decides;
// otherwise route.final. A domain_suffix rule needs a known domain (domain=="" never matches).
// It returns "reject" or the outbound tag.
func simulateRoute(cfg M, inbound, network, domain string) string {
	route := cfg["route"].(map[string]any)
	for _, r := range route["rules"].([]any) {
		rule := r.(map[string]any)
		if v, ok := rule["inbound"]; ok {
			hit := false
			for _, tag := range toStrings(v) {
				hit = hit || tag == inbound
			}
			if !hit {
				continue
			}
		}
		if v, ok := rule["network"]; ok && v.(string) != network {
			continue
		}
		if v, ok := rule["domain_suffix"]; ok {
			hit := false
			for _, sfx := range toStrings(v) {
				hit = hit || (domain != "" && (domain == sfx || strings.HasSuffix(domain, "."+sfx)))
			}
			if !hit {
				continue
			}
		}
		switch rule["action"] {
		case "sniff":
			continue
		case "reject":
			return "reject"
		case "route":
			return rule["outbound"].(string)
		}
	}
	return route["final"].(string)
}

func outboundByTag(cfg M, tag string) map[string]any {
	for _, o := range cfg["outbounds"].([]any) {
		if o.(map[string]any)["tag"] == tag {
			return o.(map[string]any)
		}
	}
	return nil
}

// aiScene is the reference topology: two nodes to bind, two to leave alone, one AI exit.
type aiScene struct {
	a                   *App
	reality, anytls, vl Profile
	direct              Profile
	exit                Exit
}

func newAIScene(t *testing.T) *aiScene {
	t.Helper()
	a := testApp(t)
	sc := &aiScene{a: a}
	sc.reality = aiTestNode(t, a, "vless", "US-Reality-01")
	sc.anytls = aiTestNode(t, a, "anytls", "US-AnyTLS-02")
	sc.vl = aiTestNode(t, a, "ss", "US-SS-03")
	sc.direct = aiTestNode(t, a, "tuic", "CA-Direct-04")
	sc.exit = aiTestExit(t, a, "Canada", "198.51.100.77", 1080)
	return sc
}

func (sc *aiScene) cfg(t *testing.T, p Profile) (M, []byte) {
	t.Helper()
	b, m := readConfigFile(t, sc.a, p)
	return m, b
}

func TestAIBuiltinRuleSetIsPreciseAndDeduplicated(t *testing.T) {
	list := aiSuffixes(AIRuleSetCurrent)
	seen := map[string]bool{}
	for _, s := range list {
		if seen[s] {
			t.Fatalf("duplicate rule %q", s)
		}
		seen[s] = true
	}
	for _, broad := range []string{"google.com", "googleapis.com", "github.com", "githubusercontent.com", "microsoft.com", "azure.com", "com"} {
		if seen[broad] {
			t.Fatalf("overly broad suffix %q", broad)
		}
	}
	for _, want := range []string{"openai.com", "chatgpt.com", "anthropic.com", "claude.ai", "gemini.google.com", "aistudio.google.com", "huggingface.co", "githubcopilot.com", "cursor.com"} {
		if !seen[want] {
			t.Fatalf("missing coverage for %q", want)
		}
	}
	for host, want := range map[string]bool{
		"chat.openai.com": true, "api.openai.com": true, "chatgpt.com": true, "api.anthropic.com": true, "claude.ai": true,
		"gemini.google.com": true, "generativelanguage.googleapis.com": true, "aistudio.google.com": true,
		"huggingface.co": true, "cdn-lfs.huggingface.co": true, "api.githubcopilot.com": true, "api2.cursor.sh": true,
		"www.google.com": false, "github.com": false, "api.github.com": false, "storage.googleapis.com": false,
		"notopenai.com": false, "openai.com.evil.example": false, "example.com": false, "": false, "203.0.113.5": false,
	} {
		if got := matchAIDomain(AIRuleSetCurrent, host); got != want {
			t.Errorf("match(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestAINeverConfiguredLeavesEveryNodeUntouched(t *testing.T) {
	sc := newAIScene(t)
	for _, p := range []Profile{sc.reality, sc.anytls, sc.vl, sc.direct} {
		cfg, raw := sc.cfg(t, p)
		if bytes.Contains(raw, []byte(aiEgressTag)) || bytes.Contains(raw, []byte("sniff")) {
			t.Fatalf("%s carries AI rules without AI routing configured", p.Name)
		}
		if simulateRoute(cfg, "entry", "tcp", "chat.openai.com") != "egress" {
			t.Fatal("default route changed")
		}
	}
}

func TestAIEnableRequiresExitAndKeepsStateOnFailure(t *testing.T) {
	sc := newAIScene(t)
	before, _ := os.ReadFile(filepath.Join(sc.a.Home, "state.json"))
	if e := sc.a.SetAIEnabled(true); e == nil || !strings.Contains(e.Error(), "AI 出口") {
		t.Fatalf("enabling without an exit must fail, got %v", e)
	}
	after, _ := os.ReadFile(filepath.Join(sc.a.Home, "state.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("rejected change modified state.json")
	}
}

func TestAIBoundNodesRouteAIDomainsOthersUnchanged(t *testing.T) {
	sc := newAIScene(t)
	a := sc.a
	if e := a.SetAIExit(sc.exit.ID); e != nil {
		t.Fatal(e)
	}
	if e := a.SetAIBindings([]string{sc.reality.ID, sc.anytls.ID}); e != nil {
		t.Fatal(e)
	}
	// Unbound nodes: capture before enabling.
	type snap struct {
		raw  []byte
		mod  int64
		prof Profile
	}
	capture := func(p Profile) snap {
		raw, _ := sc.cfg(t, p)
		st, _ := os.Stat(filepath.Join(a.profileDir(p.ID), "config.json"))
		_ = raw
		b, _ := os.ReadFile(filepath.Join(a.profileDir(p.ID), "config.json"))
		return snap{b, st.ModTime().UnixNano(), p}
	}
	unboundBefore := []snap{capture(sc.vl), capture(sc.direct)}
	if e := a.SetAIEnabled(true); e != nil {
		t.Fatal(e)
	}
	for i, p := range []Profile{sc.vl, sc.direct} {
		now := capture(p)
		if !bytes.Equal(now.raw, unboundBefore[i].raw) || now.mod != unboundBefore[i].mod {
			t.Fatalf("unbound node %s was rewritten", p.Name)
		}
	}
	for _, p := range []Profile{sc.reality, sc.anytls} {
		cfg, _ := sc.cfg(t, p)
		if got := simulateRoute(cfg, "entry", "tcp", "chat.openai.com"); got != aiEgressTag {
			t.Fatalf("%s: AI domain went to %s", p.Name, got)
		}
		if got := simulateRoute(cfg, "entry", "tcp", "api.anthropic.com"); got != aiEgressTag {
			t.Fatalf("%s: Claude went to %s", p.Name, got)
		}
		if got := simulateRoute(cfg, "entry", "tcp", "www.example.com"); got != "egress" {
			t.Fatalf("%s: non-AI went to %s", p.Name, got)
		}
		if got := simulateRoute(cfg, "entry", "tcp", ""); got != "egress" {
			t.Fatalf("%s: IP-only destination must keep the original route, got %s", p.Name, got)
		}
		// QUIC to an AI domain must not leave through the original exit.
		if got := simulateRoute(cfg, "entry", "udp", "gemini.google.com"); got != "reject" {
			t.Fatalf("%s: UDP AI traffic went to %s", p.Name, got)
		}
		if got := simulateRoute(cfg, "entry", "udp", "www.example.com"); got != "egress" {
			t.Fatalf("%s: ordinary UDP changed to %s", p.Name, got)
		}
		// The rules only apply to this node's own inbound.
		if got := simulateRoute(cfg, "some-other-inbound", "tcp", "chat.openai.com"); got != "egress" {
			t.Fatalf("%s: AI rule leaked to another inbound: %s", p.Name, got)
		}
		out := outboundByTag(cfg, aiEgressTag)
		if out == nil || out["server"] != "198.51.100.77" || out["type"] != "socks" {
			t.Fatalf("%s: AI exit outbound wrong: %v", p.Name, out)
		}
		if outboundByTag(cfg, "egress")["type"] != "direct" {
			t.Fatal("original exit changed")
		}
		// Explicit domains are classified before sniffing; IP destinations after it.
		rules := cfg["route"].(map[string]any)["rules"].([]any)
		if rules[2].(map[string]any)["action"] != "sniff" {
			t.Fatal("sniff must follow explicit-domain matching")
		}
	}
}

func TestAIEmptyBindingAffectsNothing(t *testing.T) {
	sc := newAIScene(t)
	a := sc.a
	if e := a.SetAIExit(sc.exit.ID); e != nil {
		t.Fatal(e)
	}
	before := map[string][]byte{}
	for _, p := range []Profile{sc.reality, sc.anytls, sc.vl, sc.direct} {
		_, raw := sc.cfg(t, p)
		before[p.ID] = raw
	}
	if e := a.SetAIEnabled(true); e != nil {
		t.Fatal(e)
	}
	s, _ := a.Load()
	if s.AI == nil || !s.AI.Enabled || len(s.AI.BoundInboundIDs) != 0 {
		t.Fatalf("enabled with default empty binding expected: %+v", s.AI)
	}
	for _, p := range s.Profiles {
		if p.AIRoute != nil {
			t.Fatalf("empty binding must not route %s", p.Name)
		}
		_, raw := sc.cfg(t, p)
		if !bytes.Equal(raw, before[p.ID]) {
			t.Fatalf("empty binding changed %s", p.Name)
		}
	}
}

func TestAIDisableRestoresOriginalAndKeepsSettings(t *testing.T) {
	sc := newAIScene(t)
	a := sc.a
	_ = a.SetAIExit(sc.exit.ID)
	_ = a.SetAIBindings([]string{sc.reality.ID})
	_, original := sc.cfg(t, sc.reality)
	if e := a.SetAIEnabled(true); e != nil {
		t.Fatal(e)
	}
	_, enabled := sc.cfg(t, sc.reality)
	if bytes.Equal(original, enabled) {
		t.Fatal("enabling changed nothing")
	}
	if e := a.SetAIEnabled(false); e != nil {
		t.Fatal(e)
	}
	_, restored := sc.cfg(t, sc.reality)
	if !bytes.Equal(original, restored) {
		t.Fatal("disabling did not restore the original configuration byte-for-byte")
	}
	s, _ := a.Load()
	if s.AI == nil || s.AI.Enabled || s.AI.AIOutboundID != sc.exit.ID || len(s.AI.BoundInboundIDs) != 1 || s.AI.RuleSetVersion != AIRuleSetCurrent {
		t.Fatalf("disable must keep exit and bindings: %+v", s.AI)
	}
	if e := a.SetAIEnabled(true); e != nil {
		t.Fatal(e)
	}
	_, again := sc.cfg(t, sc.reality)
	if !bytes.Equal(enabled, again) {
		t.Fatal("re-enabling did not restore the saved settings")
	}
}

func TestAIPersistsAcrossRestart(t *testing.T) {
	sc := newAIScene(t)
	_ = sc.a.SetAIExit(sc.exit.ID)
	_ = sc.a.SetAIBindings([]string{sc.reality.ID, sc.anytls.ID})
	if e := sc.a.SetAIEnabled(true); e != nil {
		t.Fatal(e)
	}
	fresh := &App{Home: sc.a.Home, BinDir: sc.a.BinDir, ServiceMode: "none", Language: "en"}
	st, e := fresh.AIStatus()
	if e != nil {
		t.Fatal(e)
	}
	if !st.Config.Enabled || st.Config.AIOutboundID != sc.exit.ID || len(st.Config.BoundInboundIDs) != 2 || st.Config.RuleSetVersion != AIRuleSetCurrent {
		t.Fatalf("not persisted: %+v", st.Config)
	}
	if st.ExitName != "Canada" || st.BoundCount != 2 {
		t.Fatalf("status: %+v", st)
	}
	for _, n := range st.Nodes {
		if !n.InSync {
			t.Fatalf("%s: config on disk is not what the saved settings produce", n.Name)
		}
	}
	raw, _ := os.ReadFile(filepath.Join(sc.a.Home, "state.json"))
	for _, key := range []string{`"enabled"`, `"bound_inbound_ids"`, `"ai_outbound_id"`, `"rule_set_version"`} {
		if !bytes.Contains(raw, []byte(key)) {
			t.Fatalf("state.json misses %s", key)
		}
	}
	if bytes.Contains(raw, []byte(`"AIRoute"`)) {
		t.Fatal("derived route leaked into state.json")
	}
}

func TestAIRejectsInvalidInboundReferences(t *testing.T) {
	sc := newAIScene(t)
	a := sc.a
	_ = a.SetAIExit(sc.exit.ID)
	if e := a.SetAIBindings([]string{"deadbeef0000"}); e == nil {
		t.Fatal("accepted a binding to a node that does not exist")
	}
	if e := a.SetAIBindings([]string{"not-an-id"}); e == nil {
		t.Fatal("accepted a malformed id")
	}
	// Relays cannot be bound.
	s, _ := a.Load()
	relay := Profile{ID: RandomHex(6), Name: "relay", Kind: "relay", Enabled: true, Protocol: "tcp", Listen: "127.0.0.1", Port: 24999, PublicHost: "203.0.113.10", PublicPort: 24999, Target: "198.51.100.5:443", RelayMode: relayRemote}
	if e := os.WriteFile(a.enginePath("gost"), []byte("#!/bin/sh\nexit 0\n"), 0755); e != nil {
		t.Fatal(e)
	}
	if e := a.Commit(s, replace(s, relay), false); e != nil {
		t.Fatal(e)
	}
	if e := a.SetAIBindings([]string{relay.ID}); e == nil {
		t.Fatal("accepted a relay as an AI inbound")
	}
	// UDP-only Shadowsocks cannot carry the TCP traffic of AI services.
	s, _ = a.Load()
	udp := fixture(t, "ss")
	udp.Name, udp.Network = "ss-udp", "udp"
	udp.Port, _ = freePort()
	udp.PublicPort = udp.Port
	if e := a.Commit(s, replace(s, udp), false); e != nil {
		t.Fatal(e)
	}
	if e := a.SetAIBindings([]string{udp.ID}); e == nil {
		t.Fatal("accepted UDP-only SS")
	}
	st, _ := a.Load()
	if st.AI != nil && len(st.AI.BoundInboundIDs) != 0 {
		t.Fatalf("rejected binding left residue: %+v", st.AI)
	}
}

func TestAIDeletedInboundIsPrunedNeverWidened(t *testing.T) {
	sc := newAIScene(t)
	a := sc.a
	_ = a.SetAIExit(sc.exit.ID)
	_ = a.SetAIBindings([]string{sc.reality.ID, sc.anytls.ID})
	_ = a.SetAIEnabled(true)
	s, _ := a.Load()
	if e := a.Commit(s, removeProfile(s, sc.reality.ID), false); e != nil {
		t.Fatal(e)
	}
	s, _ = a.Load()
	if len(s.AI.BoundInboundIDs) != 1 || s.AI.BoundInboundIDs[0] != sc.anytls.ID {
		t.Fatalf("binding after delete: %v", s.AI.BoundInboundIDs)
	}
	for _, p := range s.Profiles {
		if (p.AIRoute != nil) != (p.ID == sc.anytls.ID) {
			t.Fatalf("%s: wrong routing after delete", p.Name)
		}
	}
	// A stale reference written by hand loads, is reported, and binds nothing extra.
	s.AI.BoundInboundIDs = append(s.AI.BoundInboundIDs, "0123456789ab")
	raw, _ := JSON(s)
	if e := AtomicWrite(filepath.Join(a.Home, "state.json"), raw, 0600); e != nil {
		t.Fatal(e)
	}
	loaded, e := a.Load()
	if e != nil {
		t.Fatalf("stale reference must not make the configuration unloadable: %v", e)
	}
	if len(loaded.AIProblems()) == 0 {
		t.Fatal("stale reference not detected")
	}
	for _, p := range loaded.Profiles {
		if (p.AIRoute != nil) != (p.ID == sc.anytls.ID) {
			t.Fatalf("%s: stale reference changed the scope", p.Name)
		}
	}
	// Any further change is rejected while it would add problems, and fixing it works.
	if e = a.SetAIBindings([]string{sc.anytls.ID}); e != nil {
		t.Fatal("cleaning the binding must be allowed:", e)
	}
}

func TestAIInvalidOutbound(t *testing.T) {
	sc := newAIScene(t)
	a := sc.a
	if e := a.SetAIExit("0123456789ab"); e == nil {
		t.Fatal("accepted unknown outbound")
	}
	// An exit that points at one of this server's own nodes would loop.
	loop := aiTestExit(t, a, "Loop", "127.0.0.1", sc.reality.Port)
	if e := a.SetAIExit(loop.ID); e == nil {
		// The loop is detected when enabling/binding; selecting alone is checked via problems.
		if e = a.SetAIEnabled(true); e == nil {
			t.Fatal("enabled AI routing with an exit that loops back into this server")
		}
	}
	// A used exit cannot be deleted.
	_ = a.SetAIExit(sc.exit.ID)
	s, _ := a.Load()
	if _, e := DeleteExit(s, sc.exit.ID); e == nil {
		t.Fatal("deleted the exit in use as AI exit")
	}
}

func TestAIExitFailsClosedWhenExitDisappears(t *testing.T) {
	sc := newAIScene(t)
	a := sc.a
	_ = a.SetAIExit(sc.exit.ID)
	_ = a.SetAIBindings([]string{sc.reality.ID})
	_ = a.SetAIEnabled(true)
	// Simulate hand-editing the exit away.
	s, _ := a.Load()
	s.Exits = nil
	raw, _ := JSON(s)
	_ = AtomicWrite(filepath.Join(a.Home, "state.json"), raw, 0600)
	loaded, e := a.Load()
	if e != nil {
		t.Fatal(e)
	}
	p, _ := Find(loaded, sc.reality.ID)
	if p.AIRoute == nil || p.AIRoute.Outbound != nil {
		t.Fatalf("a missing exit must fail closed, got %+v", p.AIRoute)
	}
	cfg, _ := serverConfig(p, a.profileDir(p.ID))
	b, _ := json.Marshal(cfg)
	var m M
	_ = json.Unmarshal(b, &m)
	if got := simulateRoute(m, "entry", "tcp", "claude.ai"); got != "reject" {
		t.Fatalf("AI traffic must be rejected, not silently sent to the original exit; got %s", got)
	}
	if outboundByTag(m, aiEgressTag) != nil {
		t.Fatal("no AI outbound may exist when the exit is invalid")
	}
	if got := simulateRoute(m, "entry", "tcp", "example.com"); got != "egress" {
		t.Fatal("unaffected traffic must stay on its route")
	}
}

func TestAIExitChangeOnlyRewritesBoundNodes(t *testing.T) {
	sc := newAIScene(t)
	a := sc.a
	second := aiTestExit(t, a, "Canada-2", "198.51.100.88", 1081)
	_ = a.SetAIExit(sc.exit.ID)
	_ = a.SetAIBindings([]string{sc.reality.ID})
	_ = a.SetAIEnabled(true)
	mod := func(p Profile) int64 {
		st, _ := os.Stat(filepath.Join(a.profileDir(p.ID), "config.json"))
		return st.ModTime().UnixNano()
	}
	other := mod(sc.anytls)
	if e := a.SetAIExit(second.ID); e != nil {
		t.Fatal(e)
	}
	if mod(sc.anytls) != other {
		t.Fatal("changing the AI exit rewrote an unbound node")
	}
	cfg, _ := sc.cfg(t, sc.reality)
	if outboundByTag(cfg, aiEgressTag)["server"] != "198.51.100.88" {
		t.Fatal("AI exit not switched on the bound node")
	}
	// The node itself (identity, port, credentials) is untouched.
	s, _ := a.Load()
	p, _ := Find(s, sc.reality.ID)
	if p.Port != sc.reality.Port || p.UUID != sc.reality.UUID || p.PublicKey != sc.reality.PublicKey {
		t.Fatal("inbound node changed by an AI exit change")
	}
}

func TestAIBoundNodeWithOwnOutboundKeepsItForOtherTraffic(t *testing.T) {
	sc := newAIScene(t)
	a := sc.a
	own := aiTestExit(t, a, "US-Residential", "192.0.2.50", 3128)
	s, _ := a.Load()
	next, e := BindExit(s, sc.reality.ID, own.ID)
	if e != nil {
		t.Fatal(e)
	}
	if e = a.Commit(s, next, false); e != nil {
		t.Fatal(e)
	}
	_ = a.SetAIExit(sc.exit.ID)
	_ = a.SetAIBindings([]string{sc.reality.ID})
	if e = a.SetAIEnabled(true); e != nil {
		t.Fatal(e)
	}
	cfg, _ := sc.cfg(t, sc.reality)
	if simulateRoute(cfg, "entry", "tcp", "chat.openai.com") != aiEgressTag {
		t.Fatal("AI traffic must prefer the AI exit")
	}
	if simulateRoute(cfg, "entry", "tcp", "example.com") != "egress" || outboundByTag(cfg, "egress")["server"] != "192.0.2.50" {
		t.Fatal("other traffic must keep the node's own outbound")
	}
	if simulateRoute(cfg, "entry", "udp", "example.com") != "reject" {
		t.Fatal("existing UDP policy for proxied nodes changed")
	}
}

func TestAIValidationFailureChangesNothing(t *testing.T) {
	sc := newAIScene(t)
	a := sc.a
	_ = a.SetAIExit(sc.exit.ID)
	_ = a.SetAIBindings([]string{sc.reality.ID})
	state, _ := os.ReadFile(filepath.Join(a.Home, "state.json"))
	_, cfgBefore := sc.cfg(t, sc.reality)
	// sing-box rejects the candidate configuration.
	if e := os.WriteFile(a.enginePath("sing-box"), []byte("#!/bin/sh\nexit 1\n"), 0755); e != nil {
		t.Fatal(e)
	}
	if e := a.SetAIEnabled(true); e == nil {
		t.Fatal("expected sing-box check failure")
	}
	stateAfter, _ := os.ReadFile(filepath.Join(a.Home, "state.json"))
	_, cfgAfter := sc.cfg(t, sc.reality)
	if !bytes.Equal(state, stateAfter) || !bytes.Equal(cfgBefore, cfgAfter) {
		t.Fatal("failed validation left changes behind")
	}
}

func TestAIApplyFailureRollsBackFilesAndState(t *testing.T) {
	sc := newAIScene(t)
	a := sc.a
	_ = a.SetAIExit(sc.exit.ID)
	_ = a.SetAIBindings([]string{sc.reality.ID, sc.anytls.ID})
	state, _ := os.ReadFile(filepath.Join(a.Home, "state.json"))
	_, firstBefore := sc.cfg(t, sc.reality)
	// The second bound node's config path cannot be replaced, so applying fails midway,
	// after the first node was already rewritten.
	blocked := filepath.Join(a.profileDir(sc.anytls.ID), "config.json")
	if e := os.Remove(blocked); e != nil {
		t.Fatal(e)
	}
	if e := os.MkdirAll(filepath.Join(blocked, "x"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := a.SetAIEnabled(true); e == nil {
		t.Fatal("expected apply failure")
	}
	stateAfter, _ := os.ReadFile(filepath.Join(a.Home, "state.json"))
	if !bytes.Equal(state, stateAfter) {
		t.Fatal("state.json not rolled back")
	}
	_, firstAfter := sc.cfg(t, sc.reality)
	if !bytes.Equal(firstBefore, firstAfter) {
		t.Fatal("already-rewritten node not restored")
	}
	s, _ := a.Load()
	if s.AI != nil && s.AI.Enabled {
		t.Fatal("AI routing reported enabled after a failed apply")
	}
}

func TestAIRelaysAndPortForwardingUnaffected(t *testing.T) {
	sc := newAIScene(t)
	a := sc.a
	s, _ := a.Load()
	relay := Profile{ID: RandomHex(6), Name: "fwd", Kind: "relay", Enabled: true, Protocol: "tcp", Listen: "127.0.0.1", Port: 24998, PublicHost: "203.0.113.10", PublicPort: 24998, Target: "198.51.100.5:443", RelayMode: relayRemote}
	if e := os.WriteFile(a.enginePath("gost"), []byte("#!/bin/sh\nexit 0\n"), 0755); e != nil {
		t.Fatal(e)
	}
	if e := a.Commit(s, replace(s, relay), false); e != nil {
		t.Fatal(e)
	}
	before, _ := os.ReadFile(filepath.Join(a.profileDir(relay.ID), "config.json"))
	_ = a.SetAIExit(sc.exit.ID)
	_ = a.SetAIBindings([]string{sc.reality.ID})
	if e := a.SetAIEnabled(true); e != nil {
		t.Fatal(e)
	}
	after, _ := os.ReadFile(filepath.Join(a.profileDir(relay.ID), "config.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("port forwarding configuration changed")
	}
	if bytes.Contains(after, []byte("domain_suffix")) {
		t.Fatal("AI rules leaked into a relay")
	}
}

func TestAIApplyUpgradesRuleSetAndTouchesOnlyBoundNodes(t *testing.T) {
	sc := newAIScene(t)
	a := sc.a
	_ = a.SetAIExit(sc.exit.ID)
	_ = a.SetAIBindings([]string{sc.reality.ID})
	_ = a.SetAIEnabled(true)
	mod := func(p Profile) int64 {
		st, _ := os.Stat(filepath.Join(a.profileDir(p.ID), "config.json"))
		return st.ModTime().UnixNano()
	}
	other := mod(sc.vl)
	if e := a.ApplyAI(); e != nil {
		t.Fatal(e)
	}
	if mod(sc.vl) != other {
		t.Fatal("apply touched an unbound node")
	}
	st, _ := a.AIStatus()
	if st.Config.RuleSetVersion != AIRuleSetCurrent {
		t.Fatal("rule set version not recorded")
	}
	fresh := testApp(t)
	if e := fresh.ApplyAI(); e == nil {
		t.Fatal("apply without configuration must fail")
	}
}

func TestAIStatusDetectsOutOfSyncConfiguration(t *testing.T) {
	sc := newAIScene(t)
	a := sc.a
	_ = a.SetAIExit(sc.exit.ID)
	_ = a.SetAIBindings([]string{sc.reality.ID})
	_ = a.SetAIEnabled(true)
	// Someone restores an old file: the node no longer has the rules the settings call for.
	b, _ := json.Marshal(M{"stale": true})
	_ = AtomicWrite(filepath.Join(a.profileDir(sc.reality.ID), "config.json"), b, 0600)
	st, _ := a.AIStatus()
	for _, n := range st.Nodes {
		if n.ID == sc.reality.ID && n.InSync {
			t.Fatal("status reports an out-of-date node as applied")
		}
	}
	if e := a.ApplyAI(); e != nil {
		t.Fatal(e)
	}
	st, _ = a.AIStatus()
	for _, n := range st.Nodes {
		if !n.InSync {
			t.Fatalf("%s still out of sync after apply", n.Name)
		}
	}
}

func TestAITestChecksReferencesSyntaxAndExit(t *testing.T) {
	sc := newAIScene(t)
	a := sc.a
	_ = a.SetAIExit(sc.exit.ID)
	_ = a.SetAIBindings([]string{sc.reality.ID, sc.anytls.ID})
	_ = a.SetAIEnabled(true)
	checks, e := a.TestAI(func(Proxy) (string, error) { return "198.51.100.77", nil })
	if e != nil {
		t.Fatal(e)
	}
	ok := 0
	for _, c := range checks {
		if !c.OK && !c.Warning {
			t.Fatalf("unexpected failure: %+v", c)
		}
		if c.OK {
			ok++
		}
	}
	if ok < 4 { // references, two nodes, exit
		t.Fatalf("expected 4 passing checks, got %+v", checks)
	}
	checks, _ = a.TestAI(func(Proxy) (string, error) { return "", os.ErrDeadlineExceeded })
	failed := false
	for _, c := range checks {
		failed = failed || (!c.OK && !c.Warning && strings.Contains(c.Text, "AI 出口不可用"))
	}
	if !failed {
		t.Fatal("an unreachable AI exit must be reported")
	}
}

func TestAIDecisionMatchesGeneratedConfig(t *testing.T) {
	sc := newAIScene(t)
	a := sc.a
	_ = a.SetAIExit(sc.exit.ID)
	_ = a.SetAIBindings([]string{sc.reality.ID})
	_ = a.SetAIEnabled(true)
	s, _ := a.Load()
	for _, p := range []Profile{sc.reality, sc.vl} {
		cfg, _ := sc.cfg(t, p)
		for _, host := range []string{"chat.openai.com", "claude.ai", "github.com", "www.google.com", "api.githubcopilot.com", "example.org"} {
			got, e := AIDecision(s, p.ID, host)
			if e != nil {
				t.Fatal(e)
			}
			want := "original"
			if simulateRoute(cfg, "entry", "tcp", host) == aiEgressTag {
				want = "ai"
			}
			if got != want {
				t.Fatalf("%s %s: decision %s, config says %s", p.Name, host, got, want)
			}
		}
	}
}

// Real sing-box syntax validation of the generated AI configuration. Skipped unless the
// pinned engines are available (CI installs them); never run against production services.
func TestAIGeneratedConfigPassesSingBoxCheck(t *testing.T) {
	a := integrationApp(t)
	p := fixture(t, "vless")
	p.Port, _ = freePort()
	p.PublicPort = p.Port
	s, _ := a.Load()
	ex := Exit{ID: RandomHex(6), Name: "Canada", Proxy: Proxy{"socks5", "198.51.100.77", 1080, "u", "p"}}
	s = UpsertExit(s, ex)
	s = replace(s, p)
	s.AI = &AIRouting{Enabled: true, BoundInboundIDs: []string{p.ID}, AIOutboundID: ex.ID, RuleSetVersion: AIRuleSetCurrent}
	if e := a.Commit(State{Schema: 1, Profiles: []Profile{}}, s, false); e != nil {
		t.Fatalf("sing-box rejected the AI routing configuration: %v", e)
	}
	// Fail-closed variant (no usable exit) must also be valid.
	s2, _ := a.Load()
	s2.Exits = nil
	s2.AI = &AIRouting{Enabled: true, BoundInboundIDs: []string{p.ID}, AIOutboundID: ex.ID, RuleSetVersion: AIRuleSetCurrent}
	pp, _ := Find(s2.withAIRoutes(), p.ID)
	dir := t.TempDir()
	if e := writeProfileIn(pp, dir); e != nil {
		t.Fatal(e)
	}
	if e := a.checkConfig(filepath.Join(dir, "config.json")); e != nil {
		t.Fatalf("fail-closed configuration rejected by sing-box: %v", e)
	}
}
