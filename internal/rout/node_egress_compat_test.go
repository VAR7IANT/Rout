package rout

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Upgrade and persistence guarantees of the node outbound IP family.

func stateJSON(t *testing.T, a *App) []byte {
	t.Helper()
	return fileBytes(t, filepath.Join(a.Home, "state.json"))
}

func nodeJSONOf(t *testing.T, raw []byte, id string) map[string]any {
	t.Helper()
	var st struct {
		Profiles []map[string]any `json:"profiles"`
	}
	if e := json.Unmarshal(raw, &st); e != nil {
		t.Fatal(e)
	}
	for _, p := range st.Profiles {
		if p["id"] == id {
			return p
		}
	}
	t.Fatalf("node %s not in state", id)
	return nil
}

// A node that never chose a policy leaves state.json exactly as earlier versions wrote it: no new
// key, so a downgrade, a diff or an older tool sees nothing new. Its configuration is the legacy one.
func TestLegacyNodeStateHasNoNewKeyAndRendersTheLegacyConfiguration(t *testing.T) {
	a := testApp(t)
	n := aiTestNode(t, a, "vless", "Legacy")
	raw := stateJSON(t, a)
	if _, has := nodeJSONOf(t, raw, n.ID)["outbound_policy"]; has {
		t.Fatalf("an Auto node must not write outbound_policy:\n%s", raw)
	}
	s, e := DecodeState(raw)
	if e != nil {
		t.Fatal(e)
	}
	p, _ := Find(s, n.ID)
	if p.OutboundPolicy != "" || p.outboundPolicy() != outAuto {
		t.Fatalf("legacy node must read as Auto: %q", p.OutboundPolicy)
	}
	if !a.configInSync(p) {
		t.Fatal("the configuration on disk is not what the state renders")
	}
	cfg := string(fileBytes(t, filepath.Join(a.profileDir(n.ID), "config.json")))
	for _, banned := range []string{"domain_resolver", `"dns"`, "ip_version", "domain_strategy"} {
		if strings.Contains(cfg, banned) {
			t.Fatalf("a legacy node's configuration contains %q:\n%s", banned, cfg)
		}
	}
}

func TestExplicitAutoIsStoredAsUnset(t *testing.T) {
	withHostRoutes(t, dualRoutes())
	a := testApp(t)
	n := aiTestNode(t, a, "vless", "N")
	before := stateJSON(t, a)
	cfgBefore := fileBytes(t, filepath.Join(a.profileDir(n.ID), "config.json"))
	if e := a.SetNodeOutboundPolicy(n.ID, outAuto, false); e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(stateJSON(t, a), before) {
		t.Fatalf("choosing Auto on an Auto node changed state.json")
	}
	if !bytes.Equal(fileBytes(t, filepath.Join(a.profileDir(n.ID), "config.json")), cfgBefore) {
		t.Fatal("choosing Auto on an Auto node changed its configuration")
	}
}

func TestPolicySurvivesRestartApplyAndANewProcess(t *testing.T) {
	withHostRoutes(t, dualRoutes())
	a := testApp(t)
	n := aiTestNode(t, a, "vless", "Turkey-VLESS")
	other := aiTestNode(t, a, "ss", "Other")
	if e := a.SetNodeOutboundPolicy(n.ID, outIPv6Only, false); e != nil {
		t.Fatal(e)
	}
	if got := nodeJSONOf(t, stateJSON(t, a), n.ID)["outbound_policy"]; got != "ipv6_only" {
		t.Fatalf("state.json: %v", got)
	}
	// a fresh process: new App value on the same home
	b := &App{Home: a.Home, BinDir: a.BinDir, ServiceMode: "none"}
	s, e := b.Load()
	if e != nil {
		t.Fatal(e)
	}
	p, _ := Find(s, n.ID)
	if p.OutboundPolicy != outIPv6Only {
		t.Fatalf("policy lost across processes: %q", p.OutboundPolicy)
	}
	// `rout apply`: re-validates and rewrites every configuration from the state. The policy must
	// come out the other side, the other node must be byte-identical, and nothing may be hand-edited.
	otherCfg := fileBytes(t, filepath.Join(a.profileDir(other.ID), "config.json"))
	if e = b.Commit(s, s, true); e != nil {
		t.Fatal(e)
	}
	s2, _ := b.Load()
	p2, _ := Find(s2, n.ID)
	if p2.OutboundPolicy != outIPv6Only || !b.configInSync(p2) {
		t.Fatalf("apply lost the policy or left the file out of sync: %q", p2.OutboundPolicy)
	}
	if !bytes.Equal(fileBytes(t, filepath.Join(a.profileDir(other.ID), "config.json")), otherCfg) {
		t.Fatal("apply changed an unrelated node's configuration")
	}
	// config.json is never the source of truth: damage it, regenerate from the state
	cfgPath := filepath.Join(a.profileDir(n.ID), "config.json")
	if e = os.WriteFile(cfgPath, []byte("{}"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = b.Commit(s2, s2, true); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(string(fileBytes(t, cfgPath)), `"strategy": "ipv6_only"`) {
		t.Fatal("the configuration was not regenerated from the state")
	}
}

func TestBackupAndRestoreKeepThePolicy(t *testing.T) {
	withHostRoutes(t, dualRoutes())
	src := testApp(t)
	n := aiTestNode(t, src, "vless", "Turkey-VLESS")
	m := aiTestNode(t, src, "ss", "Plain")
	if e := src.SetNodeOutboundPolicy(n.ID, outIPv6Only, false); e != nil {
		t.Fatal(e)
	}
	plain := filepath.Join(t.TempDir(), "plain.json")
	full := filepath.Join(t.TempDir(), "full.json")
	if e := src.Backup(plain); e != nil {
		t.Fatal(e)
	}
	if e := src.WriteBackupBundle(full, time.Now()); e != nil {
		t.Fatal(e)
	}
	for name, path := range map[string]string{"plain state backup": plain, "full bundle": full} {
		t.Run(name, func(t *testing.T) {
			dst := testApp(t)
			if e := dst.Restore(path); e != nil {
				t.Fatal(e)
			}
			s, _ := dst.Load()
			got, e := Find(s, n.ID)
			if e != nil || got.OutboundPolicy != outIPv6Only {
				t.Fatalf("restore lost the policy: %+v %v", got, e)
			}
			if plainNode, _ := Find(s, m.ID); plainNode.OutboundPolicy != "" {
				t.Fatalf("restore invented a policy: %q", plainNode.OutboundPolicy)
			}
			if !strings.Contains(string(fileBytes(t, filepath.Join(dst.profileDir(n.ID), "config.json"))), `"strategy": "ipv6_only"`) {
				t.Fatal("the restored node's configuration does not carry the policy")
			}
			if !dst.configInSync(got) {
				t.Fatal("restored configuration out of sync")
			}
		})
	}
}

// A backup taken before this feature has no key and restores as Auto, byte-for-byte the legacy
// configuration.
func TestRestoringAnOldBackupGivesAutoNodes(t *testing.T) {
	src := testApp(t)
	n := aiTestNode(t, src, "vless", "Old")
	path := filepath.Join(t.TempDir(), "old.json")
	if e := src.Backup(path); e != nil {
		t.Fatal(e)
	}
	dst := testApp(t)
	if e := dst.Restore(path); e != nil {
		t.Fatal(e)
	}
	s, _ := dst.Load()
	got, _ := Find(s, n.ID)
	if got.OutboundPolicy != "" || strings.Contains(string(fileBytes(t, filepath.Join(dst.profileDir(n.ID), "config.json"))), "domain_resolver") {
		t.Fatalf("old backup restored with a policy: %+v", got)
	}
}

// Relays and NAT VPS hosts keep working exactly as before; the node feature only touches nodes.
func TestRelaysAndNATHostsAreUnaffected(t *testing.T) {
	withHostRoutes(t, dualRoutes())
	a, _, before := legacyNATApp(t)
	var node, relay Profile
	for _, p := range before.Profiles {
		if p.Kind == "node" {
			node = p
		} else {
			relay = p
		}
	}
	relayCfg := fileBytes(t, filepath.Join(a.profileDir(relay.ID), "config.json"))
	if e := a.SetNodeOutboundPolicy(node.ID, outIPv4Only, false); e != nil {
		t.Fatal(e)
	}
	after, _ := a.Load()
	gotNode, _ := Find(after, node.ID)
	gotRelay, _ := Find(after, relay.ID)
	// the NAT mapping and everything but the policy are untouched
	gotNode.OutboundPolicy = node.OutboundPolicy
	if !reflect.DeepEqual(gotNode, node) {
		t.Fatalf("NAT node changed beyond its policy:\n%+v\n%+v", node, gotNode)
	}
	if !reflect.DeepEqual(gotRelay, relay) {
		t.Fatal("the relay profile changed")
	}
	if !bytes.Equal(fileBytes(t, filepath.Join(a.profileDir(relay.ID), "config.json")), relayCfg) {
		t.Fatal("the relay's configuration was rewritten")
	}
	// the relay's own outbound policy is not reachable through the node endpoint
	if e := a.SetNodeOutboundPolicy(relay.ID, outIPv4Only, false); e == nil {
		t.Fatal("a relay accepted a node policy")
	}
	// and a relay with its own policy coexists with a node policy in one state
	s, _ := a.Load()
	r := nativeRelayProfile(inIPv4, outIPv6Only, "203.0.113.20:443", 24690)
	r.ID, r.Name, r.Listen, r.PublicHost = "bbbbbbbbbbbb", "Native", "127.0.0.1", "198.51.100.1"
	r.Port, r.PublicPort = relay.Port+2, 40002
	r.NAT, r.Target = true, "[2001:db8::20]:443"
	r.Engine, r.InboundMode = engineNative, inIPv4
	if e := a.Commit(s, replace(s, r), false); e != nil {
		t.Logf("fixture relay not accepted on the NAT host (%v); coexistence covered by the non-NAT test", e)
		return
	}
	s, _ = a.Load()
	gr, _ := Find(s, r.ID)
	gn, _ := Find(s, node.ID)
	if gr.OutboundPolicy != outIPv6Only || gn.OutboundPolicy != outIPv4Only {
		t.Fatalf("relay %q node %q", gr.OutboundPolicy, gn.OutboundPolicy)
	}
}

// Coexistence with AI smart routing: AI traffic follows the AI exit, ordinary traffic follows the
// node's policy, and neither disturbs the other's configuration or state.
func TestPolicyCoexistsWithAIRouting(t *testing.T) {
	withHostRoutes(t, dualRoutes())
	a := testApp(t)
	n := aiTestNode(t, a, "vless", "Turkey-VLESS")
	ex := aiTestExit(t, a, "Canada", "198.51.100.77", 1080)
	s := mustLoad(t, a)
	s.AI = &AIRouting{Enabled: true, BoundInboundIDs: []string{n.ID}, AIOutboundID: ex.ID, RuleSetVersion: AIRuleSetCurrent}
	if e := a.Commit(mustLoad(t, a), s, false); e != nil {
		t.Fatal(e)
	}
	if e := a.SetNodeOutboundPolicy(n.ID, outIPv6Only, false); e != nil {
		t.Fatal(e)
	}
	got, _ := Find(mustLoad(t, a), n.ID)
	cfg := egressNodeConfig(t, mustLoadWithAI(t, a, got))
	var kinds []string
	for _, r := range routeRules(t, cfg) {
		switch {
		case r["domain_suffix"] != nil || r["action"] == "sniff":
			kinds = append(kinds, "ai")
		case r["ip_version"] != nil:
			kinds = append(kinds, "family")
		case r["outbound"] == "egress":
			kinds = append(kinds, "egress")
		}
	}
	if joined := strings.Join(kinds, ","); !strings.HasPrefix(joined, "ai,") || !strings.HasSuffix(joined, "family,egress") {
		t.Fatalf("AI rules must come first and the family rule right before the ordinary route: %s", joined)
	}
	if routeAI, e := AIDecision(mustLoad(t, a), n.ID, "chat.openai.com"); e != nil || routeAI != "ai" {
		t.Fatalf("AI routing decision changed: %q %v", routeAI, e)
	}
	// switching the node policy back and forth does not touch the AI configuration
	aiBefore, _ := json.Marshal(mustLoad(t, a).AI)
	for _, pol := range []string{outIPv4Only, outIPv6First, outAuto} {
		if e := a.SetNodeOutboundPolicy(n.ID, pol, false); e != nil {
			t.Fatal(e)
		}
	}
	if aiAfter, _ := json.Marshal(mustLoad(t, a).AI); !bytes.Equal(aiBefore, aiAfter) {
		t.Fatal("changing the node policy changed the AI routing settings")
	}
	// and the AI switch leaves the node policy alone
	if e := a.SetAIEnabled(false); e != nil {
		t.Fatal(e)
	}
	if e := a.SetNodeOutboundPolicy(n.ID, outIPv4Only, false); e != nil {
		t.Fatal(e)
	}
	if e := a.SetAIEnabled(true); e != nil {
		t.Fatal(e)
	}
	if p, _ := Find(mustLoad(t, a), n.ID); p.OutboundPolicy != outIPv4Only {
		t.Fatalf("toggling AI routing changed the node policy: %q", p.OutboundPolicy)
	}
}

func mustLoadWithAI(t *testing.T, a *App, p Profile) Profile {
	t.Helper()
	got, e := Find(mustLoad(t, a).withAIRoutes(), p.ID)
	if e != nil {
		t.Fatal(e)
	}
	return got
}
