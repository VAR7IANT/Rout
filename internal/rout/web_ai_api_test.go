package rout

import (
	"strings"
	"testing"
)

func TestWebAIRoutingAPIWithRelayChain(t *testing.T) {
	a := testApp(t)
	env := newWebEnvFor(t, a)
	c := env.login()
	// A bound node, an unbound node and a relay to a remote SOCKS5.
	sc := newChainScene(t, a, Proxy{Protocol: "socks5", Host: "198.51.100.20", Port: 1080, Username: "u0", Password: "p0"})
	old, _ := a.Load()
	next := old.Clone()
	next.Exits = nil // start from no exits: build the chain through the API
	next.AI = &AIRouting{BoundInboundIDs: []string{}, RuleSetVersion: AIRuleSetCurrent}
	if e := a.Commit(old, next, false); e != nil {
		t.Fatal(e)
	}
	// A bare forward is refused as the end of a chain.
	w := c.do("POST", "/api/exits/chain", map[string]any{"via_relay": sc.relay.ID, "protocol": "forward"})
	if w.Code != 400 {
		t.Fatalf("bare forward: %d %s", w.Code, w.Body.String())
	}
	w = c.do("POST", "/api/exits/chain", map[string]any{"name": "CA via hop", "via_relay": sc.relay.ID, "protocol": "socks5", "username": "chain-user", "password": "chain-SECRET-pw"})
	mustOK(t, w.Code, w.Body.String())
	if strings.Contains(w.Body.String(), "chain-SECRET-pw") || strings.Contains(w.Body.String(), "chain-user") {
		t.Fatal("credentials returned")
	}
	ex := jsonOf(t, w)["exit"].(map[string]any)
	if ex["kind"] != "chain" || ex["via_relay_name"] != "CA-hop" || ex["ai_usable"] != true {
		t.Fatalf("exit view %v", ex)
	}
	id := ex["id"].(string)
	mustOK(t, c.do("PUT", "/api/ai/exit", map[string]any{"exit_id": id}).Code, "")
	mustOK(t, c.do("PUT", "/api/ai/bindings", map[string]any{"ids": []string{sc.nodeA.ID}}).Code, "")
	w = c.do("POST", "/api/ai/enabled", map[string]any{"enabled": true})
	mustOK(t, w.Code, w.Body.String())
	view := jsonOf(t, c.get("/api/ai"))
	if view["enabled"] != true || view["exit_id"] != id {
		t.Fatalf("view %v", view)
	}
	bound := 0
	for _, n := range listOf(t, view, "nodes") {
		if n["bound"] == true {
			bound++
			if n["id"] != sc.nodeA.ID {
				t.Fatal("wrong node bound")
			}
		}
	}
	if bound != 1 || len(view["limits"].([]any)) < 5 || len(listOf(t, view, "relays")) != 1 {
		t.Fatalf("view %v", view)
	}
	relay := listOf(t, view, "relays")[0]
	if relay["ai_chain"] != true {
		t.Fatal("relay does not show its AI dependency")
	}
	if strings.Contains(c.get("/api/ai").Body.String(), "chain-SECRET-pw") {
		t.Fatal("AI view leaks credentials")
	}
	sim := jsonOf(t, c.do("POST", "/api/ai/simulate", map[string]any{"host": "api.openai.com"}))
	for _, n := range listOf(t, sim, "nodes") {
		want := "original"
		if n["id"] == sc.nodeA.ID {
			want = "ai"
		}
		if n["route"] != want {
			t.Fatalf("simulate %v", n)
		}
	}
	// Deleting the relay is protected and names both sides.
	c.reauth()
	w = c.do("DELETE", "/api/relays/"+sc.relay.ID, nil, withHeader("X-Rout-Lang", "en"))
	if w.Code == 200 || !strings.Contains(w.Body.String(), "CA-hop") || !strings.Contains(w.Body.String(), "CA via hop") {
		t.Fatalf("delete: %d %s", w.Code, w.Body.String())
	}
	// Selecting an unusable exit through the API is refused.
	if w = c.do("PUT", "/api/ai/exit", map[string]any{"exit_id": "zzz"}); w.Code != 400 {
		t.Fatalf("bad id: %d", w.Code)
	}
}

func TestWebPanelHTTPSStatusAPI(t *testing.T) {
	p := newPanelFake(t)
	env := newWebEnvFor(t, p.sc.a)
	c := env.login()
	if _, e := p.sc.a.DeployWebHTTPS("panel.example.com", WebHTTPSOptions{}); e != nil {
		t.Fatal(e)
	}
	env.ws.invalidateConfig()
	w := c.get("/api/system/panel")
	mustOK(t, w.Code, w.Body.String())
	m := jsonOf(t, w)
	if m["domain"] != "panel.example.com" || m["ownership"] != "managed" || m["url"] != "https://panel.example.com" {
		t.Fatalf("report %v", m)
	}
	if len(listOf(t, m, "checks")) < 5 {
		t.Fatal("checks missing")
	}
	// Repair needs a recent re-authentication.
	if w = c.do("POST", "/api/system/panel/repair", nil); w.Code != 403 {
		t.Fatalf("repair without reauth: %d", w.Code)
	}
	c.reauth()
	w = c.do("POST", "/api/system/panel/repair", nil)
	mustOK(t, w.Code, w.Body.String())
}
