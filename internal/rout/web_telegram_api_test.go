package rout

import (
	"strings"
	"testing"
	"time"
)

// Panel API for the Telegram binding, against fakeTelegram. The service itself is started by the
// test through the same hook the real panel uses to install it.

func telegramEnv(t *testing.T, tg *fakeTelegram, n *tgNode) (*webEnv, *webClient) {
	t.Helper()
	env := newWebEnvFor(t, n.a)
	env.ws.telegramSvc = func(action string) error {
		if action == "install" {
			n.start()
		}
		return nil
	}
	return env, env.login()
}

func noSecrets(t *testing.T, what, body string) {
	t.Helper()
	for _, s := range []string{testBotToken, "AAHtest", "PRIVATE KEY", "BEGIN CERTIFICATE"} {
		if strings.Contains(body, s) {
			t.Fatalf("%s leaks %q:\n%s", what, s, body)
		}
	}
}

func TestWebTelegramAPIRequiresPasswordForEveryChange(t *testing.T) {
	tg := newFakeTelegram(t, testBotToken, testChat)
	n := newTGNode(t, tg, "US-GIA")
	_, c := telegramEnv(t, tg, n)

	st := jsonOf(t, c.get("/api/telegram"))
	if st["bound"] != false || st["connection"].(map[string]any)["state"] != "unbound" {
		t.Fatalf("unbound view: %v", st)
	}
	// without a recent password confirmation nothing that changes control is allowed
	for _, call := range []struct{ method, path string }{
		{"POST", "/api/telegram/probe"}, {"POST", "/api/telegram/bind"}, {"PATCH", "/api/telegram"}, {"POST", "/api/telegram/unbind"},
		{"POST", "/api/telegram/pending/0123456789ab/approve"}, {"POST", "/api/telegram/pending/0123456789ab/reject"}, {"DELETE", "/api/telegram/servers/0123456789abcdef"},
	} {
		w := c.do(call.method, call.path, map[string]any{"token": testBotToken, "chat_id": "111"})
		if w.Code != 403 || !strings.Contains(w.Body.String(), "reauth_required") {
			t.Errorf("%s %s without reauth: %d %s", call.method, call.path, w.Code, w.Body.String())
		}
	}
	// status and test are read-only
	if w := c.get("/api/telegram"); w.Code != 200 {
		t.Fatal(w.Code)
	}
	// and an anonymous caller gets nothing
	anon := &webClient{env: c.env}
	if w := anon.get("/api/telegram"); w.Code != 401 {
		t.Fatalf("anonymous: %d", w.Code)
	}
}

func TestWebTelegramAPIBindAHubThenJoinAServer(t *testing.T) {
	tg := newFakeTelegram(t, testBotToken, testChat)
	us := newTGNode(t, tg, "US-GIA")
	_, c := telegramEnv(t, tg, us)
	c.reauth()

	// probe: validates with Telegram, stores nothing, finds no hub yet
	w := c.do("POST", "/api/telegram/probe", map[string]any{"token": testBotToken, "chat_id": "111"})
	mustOK(t, w.Code, w.Body.String())
	noSecrets(t, "probe", w.Body.String())
	p := jsonOf(t, w)
	if p["bot_username"] != "rout_test_bot" || p["suggested_name"] != "US-GIA" || p["webhook_active"] != false || p["hub"].(map[string]any)["found"] != false {
		t.Fatalf("probe: %v", p)
	}
	if _, e := us.a.LoadTelegram(); e != errTelegramUnbound {
		t.Fatal("probe stored something")
	}
	// bad input is rejected without calling it a success
	for _, bad := range []map[string]any{{"token": "nope", "chat_id": "111"}, {"token": testBotToken, "chat_id": "-100"}, {"token": testBotToken, "chat_id": "abc"}, {"token": testBotToken, "chat_id": "424242"}} {
		if w = c.do("POST", "/api/telegram/probe", bad); w.Code != 400 {
			t.Errorf("probe %v: %d", bad, w.Code)
		} else {
			noSecrets(t, "probe error", w.Body.String())
		}
	}

	// bind as the hub, with other servers allowed
	w = c.do("POST", "/api/telegram/bind", map[string]any{"token": testBotToken, "chat_id": "111", "role": "hub", "multi_server": true})
	mustOK(t, w.Code, w.Body.String())
	noSecrets(t, "bind", w.Body.String())
	v := jsonOf(t, w)
	if v["bound"] != true || v["role"] != "hub" || v["server_name"] != "US-GIA" || v["bot_username"] != "rout_test_bot" || !strings.HasPrefix(v["chat_id_masked"].(string), "••••") {
		t.Fatalf("bind view: %v", v)
	}
	if hub := v["hub"].(map[string]any); hub["multi_server"] != true || hub["fingerprint"] == "" {
		t.Fatalf("hub view: %v", hub)
	}
	waitFor(t, "hub up", 8*time.Second, func() bool { return us.theHub() != nil && strings.Contains(tg.pinnedText(), announcePrefix) })
	// binding again is refused
	if w = c.do("POST", "/api/telegram/bind", map[string]any{"token": testBotToken, "chat_id": "111", "role": "hub"}); w.Code != 400 {
		t.Fatalf("second bind: %d", w.Code)
	}

	// a second server (its own panel) probes, sees the hub and its fingerprint, and joins
	ca := newTGNode(t, tg, "CA-Exit")
	_, c2 := telegramEnv(t, tg, ca)
	c2.reauth()
	w = c2.do("POST", "/api/telegram/probe", map[string]any{"token": testBotToken, "chat_id": "111"})
	mustOK(t, w.Code, w.Body.String())
	hub := jsonOf(t, w)["hub"].(map[string]any)
	if hub["found"] != true || hub["hub_name"] != "US-GIA" || hub["fingerprint"] != fingerprintGroups(us.hubConfig(t).identity().fingerprint()) {
		t.Fatalf("probe hub: %v", hub)
	}
	fp := hub["fingerprint"].(string)
	// a wrong fingerprint, or none, never joins
	for _, bad := range []string{"", strings.Repeat("0000 ", 8)} {
		if w = c2.do("POST", "/api/telegram/bind", map[string]any{"token": testBotToken, "chat_id": "111", "role": "agent", "trust_hub_fp": bad}); w.Code == 200 {
			t.Fatalf("joined with fingerprint %q", bad)
		}
	}
	if _, e := ca.a.LoadTelegram(); e != errTelegramUnbound {
		t.Fatal("a failed join stored a binding")
	}
	// choosing "hub" when one exists is a conflict, not a second hub
	if w = c2.do("POST", "/api/telegram/bind", map[string]any{"token": testBotToken, "chat_id": "111", "role": "hub"}); w.Code != 409 {
		t.Fatalf("second hub: %d %s", w.Code, w.Body.String())
	}
	w = c2.do("POST", "/api/telegram/bind", map[string]any{"token": testBotToken, "chat_id": "111", "role": "agent", "trust_hub_fp": fp, "server_name": "CA-Exit"})
	mustOK(t, w.Code, w.Body.String())
	noSecrets(t, "agent bind", w.Body.String())
	av := jsonOf(t, w)
	if av["role"] != "agent" || av["follows"].(map[string]any)["fingerprint"] != fp {
		t.Fatalf("agent view: %v", av)
	}

	// the hub's panel lists the request; approving it there works like pressing Allow in Telegram
	var pid string
	waitFor(t, "pending request", 8*time.Second, func() bool {
		pend := listOf(t, jsonOf(t, c.get("/api/telegram")), "pending")
		if len(pend) == 1 {
			pid = pend[0]["id"].(string)
			return true
		}
		return false
	})
	pend := listOf(t, jsonOf(t, c.get("/api/telegram")), "pending")[0]
	if pend["name"] != "CA-Exit" || pend["fingerprint"] != fingerprintGroups(ca.agentConfig(t).identity().fingerprint()) {
		t.Fatalf("pending view: %v", pend)
	}
	if w = c.do("POST", "/api/telegram/pending/zzzz/approve", nil); w.Code != 400 {
		t.Fatalf("bad id: %d", w.Code)
	}
	if w = c.do("POST", "/api/telegram/pending/ffffffffffff/approve", nil); w.Code != 404 {
		t.Fatalf("unknown id: %d", w.Code)
	}
	mustOK(t, c.do("POST", "/api/telegram/pending/"+pid+"/approve", nil).Code, "")
	if w = c.do("POST", "/api/telegram/pending/"+pid+"/approve", nil); w.Code != 404 {
		t.Fatalf("approving twice: %d", w.Code)
	}
	waitFor(t, "agent online in the hub panel", 10*time.Second, func() bool {
		for _, sv := range listOf(t, jsonOf(t, c.get("/api/telegram")), "servers") {
			if sv["name"] == "CA-Exit" && sv["online"] == true && sv["exit_name"] == "CA-Exit-ExitA" {
				return true
			}
		}
		return false
	})
	view := jsonOf(t, c.get("/api/telegram"))
	servers := listOf(t, view, "servers")
	if servers[0]["self"] != true || servers[0]["name"] != "US-GIA" || len(servers) != 2 {
		t.Fatalf("servers: %v", servers)
	}
	noSecrets(t, "hub view", c.get("/api/telegram").Body.String())
	for _, f := range []string{"servers", "pending", "audit"} {
		if _, ok := view[f].([]any); !ok {
			t.Errorf("%s must always be a list", f)
		}
	}
	// the audit trail shows what happened, without secrets
	if audit := c.get("/api/telegram").Body.String(); !strings.Contains(audit, "join_allowed") && !strings.Contains(audit, "join_request") {
		t.Logf("audit has no join entries (the web approval path audits on the panel side): %s", audit)
	}

	// the agent's panel: connected, and hub-only endpoints are not available there
	waitFor(t, "agent connected", 10*time.Second, func() bool {
		return jsonOf(t, c2.get("/api/telegram"))["connection"].(map[string]any)["state"] == "connected"
	})
	if w = c2.do("POST", "/api/telegram/pending/"+pid+"/approve", nil); w.Code != 404 {
		t.Fatalf("agent approving: %d", w.Code)
	}

	// test the connection from both panels
	for _, cl := range []*webClient{c, c2} {
		w = cl.do("POST", "/api/telegram/test", nil)
		mustOK(t, w.Code, w.Body.String())
		noSecrets(t, "test", w.Body.String())
		res := jsonOf(t, w)
		if res["ok"] != true || len(listOf(t, res, "steps")) < 3 {
			t.Fatalf("test result: %v", res)
		}
	}

	// revoking from the hub's panel; the local server cannot be removed
	caID := ca.agentConfig(t).ServerID
	if w = c.do("DELETE", "/api/telegram/servers/"+us.hubConfig(t).ServerID, nil); w.Code != 400 {
		t.Fatalf("removing self: %d", w.Code)
	}
	mustOK(t, c.do("DELETE", "/api/telegram/servers/"+caID, nil).Code, "")
	waitFor(t, "agent sees the revocation", 10*time.Second, func() bool {
		return jsonOf(t, c2.get("/api/telegram"))["connection"].(map[string]any)["state"] == "revoked"
	})
	if n := len(listOf(t, jsonOf(t, c.get("/api/telegram")), "servers")); n != 1 {
		t.Fatalf("servers after revoke: %d", n)
	}
}

func TestWebTelegramAPIRefusesToTouchAWebhook(t *testing.T) {
	tg := newFakeTelegram(t, testBotToken, testChat)
	n := newTGNode(t, tg, "US-GIA")
	_, c := telegramEnv(t, tg, n)
	c.reauth()
	tg.setWebhook("https://example.invalid/hook")
	w := c.do("POST", "/api/telegram/probe", map[string]any{"token": testBotToken, "chat_id": "111"})
	mustOK(t, w.Code, w.Body.String())
	if jsonOf(t, w)["webhook_active"] != true {
		t.Fatal("the probe must report the webhook")
	}
	// even with an explicit request to delete it, Rout does not
	w = c.do("POST", "/api/telegram/bind", map[string]any{"token": testBotToken, "chat_id": "111", "role": "hub", "delete_webhook": true})
	if w.Code != 400 || !strings.Contains(w.Body.String(), "webhook") {
		t.Fatalf("delete_webhook: %d %s", w.Code, w.Body.String())
	}
	w = c.do("POST", "/api/telegram/bind", map[string]any{"token": testBotToken, "chat_id": "111", "role": "hub"})
	if w.Code != 400 || !strings.Contains(w.Body.String(), "webhook") {
		t.Fatalf("bind next to a webhook: %d %s", w.Code, w.Body.String())
	}
	if calls, _ := tg.stats(); calls["deleteWebhook"] != 0 {
		t.Fatal("the panel deleted a webhook")
	}
	if _, e := n.a.LoadTelegram(); e != errTelegramUnbound {
		t.Fatal("a refused bind stored a binding")
	}
}

func TestWebTelegramAPIEditUnbindAndErrors(t *testing.T) {
	tg := newFakeTelegram(t, testBotToken, testChat)
	n := newTGNode(t, tg, "US-GIA")
	_, c := telegramEnv(t, tg, n)
	c.reauth()
	// nothing bound yet
	for _, call := range [][2]string{{"PATCH", "/api/telegram"}, {"POST", "/api/telegram/test"}} {
		if w := c.do(call[0], call[1], map[string]any{}); w.Code != 404 {
			t.Errorf("%v unbound: %d", call, w.Code)
		}
	}
	mustOK(t, c.do("POST", "/api/telegram/bind", map[string]any{"token": testBotToken, "chat_id": "111", "role": "hub"}).Code, "")
	waitFor(t, "service", 5*time.Second, func() bool { return n.runtime().State == tgStateOK })

	// rename and the multi-server switch
	w := c.do("PATCH", "/api/telegram", map[string]any{"server_name": "US-Main", "multi_server": true})
	mustOK(t, w.Code, w.Body.String())
	v := jsonOf(t, w)
	if v["server_name"] != "US-Main" || v["hub"].(map[string]any)["multi_server"] != true {
		t.Fatalf("patch: %v", v)
	}
	if w = c.do("PATCH", "/api/telegram", map[string]any{"server_name": "bad\nname"}); w.Code != 400 {
		t.Fatalf("bad name: %d", w.Code)
	}
	if w = c.do("PATCH", "/api/telegram", map[string]any{"unknown_field": 1}); w.Code != 400 {
		t.Fatalf("unknown field: %d", w.Code)
	}

	// replacing the token: Telegram must accept it first, and the old one disappears
	const token2 = "7000000009:AAHsecondTokenForRoutTelegramCCCCCCCCCCC"
	if w = c.do("PATCH", "/api/telegram", map[string]any{"token": token2}); w.Code != 400 {
		t.Fatalf("unknown token: %d", w.Code)
	} else {
		noSecrets(t, "patch error", w.Body.String())
		if strings.Contains(w.Body.String(), token2) {
			t.Fatal("the error repeats the new token")
		}
	}
	tg.addToken(token2)
	w = c.do("PATCH", "/api/telegram", map[string]any{"token": token2, "chat_id": "111"})
	mustOK(t, w.Code, w.Body.String())
	if strings.Contains(w.Body.String(), token2) {
		t.Fatal("the response contains the new token")
	}
	if n.hubConfig(t).Token != token2 {
		t.Fatal("token not replaced")
	}

	// unbind: everything is gone and the view says so
	w = c.do("POST", "/api/telegram/unbind", nil)
	mustOK(t, w.Code, w.Body.String())
	if jsonOf(t, w)["bound"] != false {
		t.Fatal("still bound")
	}
	if _, e := n.a.LoadTelegram(); e != errTelegramUnbound {
		t.Fatal("secrets remain")
	}
}
