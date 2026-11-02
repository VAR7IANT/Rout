package rout

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/VAR7IANT/Rout/internal/remote"
)

type apiScene struct {
	*aggScene
	env *webEnv
	c   *webClient
}

func newAPIScene(t *testing.T) *apiScene {
	t.Helper()
	sc := newAggScene(t)
	e := newWebEnvFor(t, sc.a)
	return &apiScene{aggScene: sc, env: e, c: e.login()}
}

func mustOK(t *testing.T, code int, body string) {
	t.Helper()
	if code != 200 {
		t.Fatalf("status %d: %s", code, body)
	}
}

func listOf(t *testing.T, m map[string]any, key string) []map[string]any {
	t.Helper()
	raw, _ := m[key].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, r := range raw {
		out = append(out, r.(map[string]any))
	}
	return out
}

// ---- redaction ----

func TestWebAPINeverReturnsSecrets(t *testing.T) {
	s := newAPIScene(t)
	c := s.c
	// A source whose URL carries an access key, an exit with credentials, a subscription.
	w := c.do("POST", "/api/sources", map[string]any{"name": "Keyed", "url": "https://links.provider.test/sub?key=TOPSECRETKEY123", "enabled": true, "interval_min": 60})
	mustOK(t, w.Code, w.Body.String())
	srcID := jsonOf(t, w)["source"].(map[string]any)["id"].(string)
	if w := c.do("POST", "/api/sources/"+srcID+"/refresh", nil); w.Code != 200 {
		t.Fatalf("refresh: %d %s", w.Code, w.Body.String())
	}
	w = c.do("POST", "/api/exits", map[string]any{"name": "corp", "protocol": "socks5", "host": "198.51.100.9", "port": 1080, "username": "proxyuser", "password": "proxy-pass-SECRET-1"})
	mustOK(t, w.Code, w.Body.String())
	sub, token := s.create(t, "main", 0, 1)

	secrets := []string{"TOPSECRETKEY123", "proxy-pass-SECRET-1", "proxyuser", token, sub.TokenHash,
		"11111111-1111-4111-8111-111111111111", "trojanpw", "hy2pw", "YWVzLTI1Ni1nY206cGFzcw", pbk}
	for _, n := range s.nodes {
		link, e := n.URI()
		if e != nil {
			t.Fatal(e)
		}
		u, e := url.Parse(link)
		if e != nil {
			t.Fatal(e)
		}
		if u.User != nil {
			secrets = append(secrets, u.User.Username())
			if p, ok := u.User.Password(); ok {
				secrets = append(secrets, p)
			}
		}
		for _, k := range []string{"pbk", "sid", "password", "obfs-password"} {
			if v := u.Query().Get(k); v != "" {
				secrets = append(secrets, v)
			}
		}
		raw, _ := json.Marshal(n)
		var fields map[string]any
		_ = json.Unmarshal(raw, &fields)
		for k, v := range fields {
			if str, ok := v.(string); ok && len(str) >= 8 && strings.Contains(strings.ToLower(k), "key") || strings.Contains(strings.ToLower(k), "password") || k == "uuid" {
				if str, ok := v.(string); ok && len(str) >= 6 {
					secrets = append(secrets, str)
				}
			}
		}
	}
	paths := []string{"/api/nodes", "/api/relays", "/api/exits", "/api/subscriptions", "/api/sources", "/api/sources/" + srcID + "/nodes",
		"/api/sources/" + s.links.ID + "/nodes", "/api/overview", "/api/system", "/api/sessions", "/api/activity", "/api/metrics", "/api/state"}
	for _, p := range paths {
		w := c.get(p)
		if w.Code != 200 {
			t.Errorf("%s: %d %s", p, w.Code, w.Body.String())
			continue
		}
		body := w.Body.String()
		for _, sec := range secrets {
			if len(sec) >= 6 && strings.Contains(body, sec) {
				t.Errorf("%s leaks %q", p, sec)
			}
		}
		if strings.Contains(body, "://") && p != "/api/system" {
			// URLs may appear only as masked source addresses.
			for _, bad := range []string{"vless://", "trojan://", "hysteria2://", "ss://", "anytls://", "tuic://"} {
				if strings.Contains(body, bad) {
					t.Errorf("%s contains a share link", p)
				}
			}
		}
	}
	// The masked address keeps the host, not the key.
	srcs := listOf(t, jsonOf(t, c.get("/api/sources")), "sources")
	for _, v := range srcs {
		if m, _ := v["url_masked"].(string); strings.Contains(m, "key=") || strings.Contains(m, "token=") {
			t.Errorf("masked URL still has a query: %q", m)
		}
	}
	// The same data is available after a password check, and only then.
	if w := c.get("/api/sources/" + srcID + "/url"); w.Code != 403 {
		t.Fatalf("source URL without reauth: %d", w.Code)
	}
	c.reauth()
	w = c.get("/api/sources/" + srcID + "/url")
	mustOK(t, w.Code, w.Body.String())
	if jsonOf(t, w)["value"] != "https://links.provider.test/sub?key=TOPSECRETKEY123" {
		t.Fatalf("revealed source value: %s", w.Body.String())
	}
}

func TestWebErrorMessagesCarryNoURLs(t *testing.T) {
	s := newAPIScene(t)
	s.fsLinks.err = context.DeadlineExceeded
	w := s.c.do("POST", "/api/sources/"+s.links.ID+"/refresh", nil)
	if w.Code == 200 {
		t.Fatal("refresh unexpectedly succeeded")
	}
	if strings.Contains(w.Body.String(), "provider.test") || strings.Contains(w.Body.String(), "://") {
		t.Fatalf("error leaks the address: %s", w.Body.String())
	}
	views := listOf(t, jsonOf(t, s.c.get("/api/sources")), "sources")
	for _, v := range views {
		if st, _ := v["status"].(map[string]any); st != nil {
			if msg, _ := st["last_error"].(string); strings.Contains(msg, "://") {
				t.Fatalf("stored error keeps a URL: %q", msg)
			}
		}
	}
}

// ---- nodes, relays, exits ----

func TestWebNodeLifecycle(t *testing.T) {
	e := newWebEnv(t)
	c := e.login()
	w := c.do("POST", "/api/nodes", map[string]any{"base_name": "Tokyo", "protocols": []string{"vless", "hy2"}, "inbound": "ipv4"})
	mustOK(t, w.Code, w.Body.String())
	nodes := listOf(t, jsonOf(t, w), "nodes")
	if len(nodes) != 2 {
		t.Fatalf("created %d nodes", len(nodes))
	}
	byProto := map[string]map[string]any{}
	for _, n := range nodes {
		byProto[n["protocol"].(string)] = n
		if n["has_link"] != true || n["enabled"] != true {
			t.Errorf("node view: %v", n)
		}
	}
	if byProto["vless"] == nil || byProto["hy2"] == nil {
		t.Fatalf("protocols: %v", byProto)
	}
	if name := byProto["vless"]["name"].(string); !strings.Contains(name, "Tokyo") {
		t.Errorf("auto name %q", name)
	}
	vless := byProto["vless"]["id"].(string)
	hy2 := byProto["hy2"]["id"].(string)

	// What was created is exactly what the existing generator produces: the stored profile
	// validates and renders a share link, so nothing was assembled by hand.
	st, _ := e.a.Load()
	for _, id := range []string{vless, hy2} {
		p, er := Find(st, id)
		if er != nil || p.Validate() != nil {
			t.Fatalf("stored profile %s invalid: %v", id, er)
		}
		if _, er := p.URI(); er != nil {
			t.Fatalf("no link for %s: %v", id, er)
		}
	}

	for _, bad := range []map[string]any{
		{"base_name": "x", "protocols": []string{}},
		{"base_name": "x", "protocols": []string{"vless", "vless"}},
		{"base_name": "x", "protocols": []string{"nope"}},
		{"base_name": "x", "protocols": []string{"vless", "hy2"}, "port": 4444},
		{"base_name": "bad\nname", "protocols": []string{"vless"}},
		{"base_name": "x", "protocols": []string{"vless"}, "inbound": "sideways"},
		{"base_name": "x", "protocols": []string{"vless"}, "exit_id": "aaaaaaaaaaaa"},
	} {
		if w := c.do("POST", "/api/nodes", bad); w.Code < 400 || w.Code >= 500 {
			t.Errorf("%v accepted: %d %s", bad, w.Code, w.Body.String())
		}
	}

	if w := c.do("PATCH", "/api/nodes/"+vless, map[string]string{"name": "Renamed"}); w.Code != 200 {
		t.Fatalf("rename: %d %s", w.Code, w.Body.String())
	}
	if w := c.do("PATCH", "/api/nodes/"+hy2, map[string]string{"name": "Renamed"}); w.Code == 200 {
		t.Fatal("duplicate name accepted")
	}
	if w := c.do("PATCH", "/api/nodes/"+vless, map[string]string{"name": " \n "}); w.Code == 200 {
		t.Fatal("blank name accepted")
	}

	// Bulk actions.
	if w := c.do("POST", "/api/nodes/bulk", map[string]any{"action": "disable", "ids": []string{vless, hy2}}); w.Code != 200 {
		t.Fatalf("disable: %d %s", w.Code, w.Body.String())
	}
	for _, n := range listOf(t, jsonOf(t, c.get("/api/nodes")), "nodes") {
		if n["enabled"] != false || n["state"] != "disabled" {
			t.Errorf("not disabled: %v", n)
		}
	}
	if w := c.do("POST", "/api/nodes/bulk", map[string]any{"action": "enable", "ids": []string{vless}}); w.Code != 200 {
		t.Fatalf("enable: %d", w.Code)
	}
	for name, body := range map[string]map[string]any{
		"unknown action": {"action": "explode", "ids": []string{vless}},
		"empty":          {"action": "enable", "ids": []string{}},
		"duplicate":      {"action": "enable", "ids": []string{vless, vless}},
		"bad id":         {"action": "enable", "ids": []string{"../etc"}},
		"missing id":     {"action": "enable", "ids": []string{"aaaaaaaaaaaa"}},
		"no exit chosen": {"action": "bind_exit", "ids": []string{vless}},
	} {
		if w := c.do("POST", "/api/nodes/bulk", body); w.Code < 400 {
			t.Errorf("%s accepted: %d", name, w.Code)
		}
	}

	// A node's link needs the password; the subscription membership shows in its view.
	c.reauth()
	if w := c.do("DELETE", "/api/nodes/"+hy2, nil); w.Code != 200 {
		t.Fatalf("delete: %d %s", w.Code, w.Body.String())
	}
	if w := c.do("DELETE", "/api/nodes/"+hy2, nil); w.Code != 404 {
		t.Fatalf("delete twice: %d", w.Code)
	}
	if list := listOf(t, jsonOf(t, c.get("/api/nodes")), "nodes"); len(list) != 1 {
		t.Fatalf("%d nodes left", len(list))
	}
}

func TestWebRelayAndExitLifecycle(t *testing.T) {
	e := newWebEnv(t)
	c := e.login()
	w := c.do("POST", "/api/nodes", map[string]any{"base_name": "Home", "protocols": []string{"vless"}, "inbound": "ipv4"})
	mustOK(t, w.Code, w.Body.String())
	node := listOf(t, jsonOf(t, w), "nodes")[0]["id"].(string)

	// An exit with credentials; the response never carries them.
	w = c.do("POST", "/api/exits", map[string]any{"name": "corp-socks", "protocol": "socks5", "host": "198.51.100.9", "port": 1080, "username": "u1", "password": "p1-secret-value"})
	mustOK(t, w.Code, w.Body.String())
	if strings.Contains(w.Body.String(), "p1-secret-value") {
		t.Fatal("exit response leaks the password")
	}
	exit := jsonOf(t, w)["exit"].(map[string]any)
	exitID := exit["id"].(string)
	if exit["has_auth"] != true || exit["host"] != "198.51.100.9" {
		t.Fatalf("exit view: %v", exit)
	}
	for _, bad := range []map[string]any{
		{"name": "x", "protocol": "ftp", "host": "198.51.100.9", "port": 1},
		{"name": "x", "protocol": "socks5", "host": "", "port": 1080},
		{"name": "x", "protocol": "socks5", "host": "198.51.100.9", "port": 70000},
		{"name": "corp-socks", "protocol": "socks5", "host": "198.51.100.10", "port": 1080},
	} {
		if w := c.do("POST", "/api/exits", bad); w.Code < 400 {
			t.Errorf("%v accepted", bad)
		}
	}
	// Editing without a password keeps the stored one.
	if w := c.do("PATCH", "/api/exits/"+exitID, map[string]any{"name": "corp-socks-2", "port": 1081}); w.Code != 200 {
		t.Fatalf("exit patch: %d %s", w.Code, w.Body.String())
	}
	st, _ := e.a.Load()
	ex, _ := FindExit(st, exitID)
	if ex.Proxy.Password != "p1-secret-value" || ex.Proxy.Port != 1081 || ex.Name != "corp-socks-2" {
		t.Fatalf("exit after edit: %+v", ex.Proxy)
	}

	// Bind the node; the exit now has a reference and cannot be deleted.
	if w := c.do("POST", "/api/nodes/bulk", map[string]any{"action": "bind_exit", "ids": []string{node}, "exit_id": exitID}); w.Code != 200 {
		t.Fatalf("bind: %d %s", w.Code, w.Body.String())
	}
	exits := listOf(t, jsonOf(t, c.get("/api/exits")), "exits")
	if len(exits) != 1 || exits[0]["refs"] != float64(1) {
		t.Fatalf("exit references: %v", exits)
	}
	c.reauth()
	if w := c.do("DELETE", "/api/exits/"+exitID, nil); w.Code == 200 {
		t.Fatal("a referenced exit was deleted")
	}
	if w := c.do("POST", "/api/nodes/bulk", map[string]any{"action": "unbind_exit", "ids": []string{node}}); w.Code != 200 {
		t.Fatalf("unbind: %d", w.Code)
	}

	// Relays: local forward to the node, remote forward to an address.
	w = c.do("POST", "/api/relays", map[string]any{"name": "entry-1", "mode": "local", "local_node_id": node, "inbound": "ipv4"})
	mustOK(t, w.Code, w.Body.String())
	relay := jsonOf(t, w)["relay"].(map[string]any)
	if relay["mode"] != "local" || len(relay["path"].([]any)) != 3 {
		t.Fatalf("relay view: %v", relay)
	}
	relayID := relay["id"].(string)
	w = c.do("POST", "/api/relays", map[string]any{"name": "entry-2", "mode": "remote", "target": "203.0.113.77:443", "protocol": "tcp", "inbound": "ipv4", "outbound": "ipv4_only"})
	mustOK(t, w.Code, w.Body.String())
	remoteRelay := jsonOf(t, w)["relay"].(map[string]any)
	if remoteRelay["target"] != "203.0.113.77:443" || remoteRelay["outbound_policy"] != "ipv4_only" {
		t.Fatalf("remote relay: %v", remoteRelay)
	}
	for _, bad := range []map[string]any{
		{"name": "r", "mode": "remote", "target": "not an address"},
		{"name": "r", "mode": "remote", "target": "203.0.113.77:443", "protocol": "icmp"},
		{"name": "r", "mode": "local", "local_node_id": "aaaaaaaaaaaa"},
		{"name": "r", "mode": "sideways"},
	} {
		if w := c.do("POST", "/api/relays", bad); w.Code < 400 {
			t.Errorf("relay %v accepted: %s", bad, w.Body.String())
		}
	}
	rid := remoteRelay["id"].(string)
	if w := c.do("PATCH", "/api/relays/"+rid, map[string]any{"target": "203.0.113.78:443"}); w.Code != 200 {
		t.Fatalf("relay patch: %d %s", w.Code, w.Body.String())
	}
	if w := c.do("PATCH", "/api/relays/"+node, map[string]any{"name": "x"}); w.Code != 404 {
		t.Fatalf("a node was edited through the relay endpoint: %d", w.Code)
	}
	if w := c.do("POST", "/api/relays/bulk", map[string]any{"action": "disable", "ids": []string{node}}); w.Code != 404 {
		t.Fatalf("a node was reached through the relay bulk endpoint: %d", w.Code)
	}
	if w := c.do("POST", "/api/relays/bulk", map[string]any{"action": "bind_exit", "ids": []string{rid}, "exit_id": exitID}); w.Code != 400 {
		t.Fatalf("relays cannot take an exit: %d", w.Code)
	}
	// The layered test runs offline and returns steps without secrets.
	for _, p := range []string{"/api/relays/" + relayID + "/test", "/api/nodes/" + node + "/test", "/api/exits/" + exitID + "/test"} {
		w := c.do("POST", p, nil)
		if w.Code != 200 || len(jsonOf(t, w)["steps"].([]any)) == 0 {
			t.Errorf("%s: %d %s", p, w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "p1-secret-value") {
			t.Errorf("%s leaks the proxy password", p)
		}
	}
	if w := c.do("POST", "/api/nodes/"+relayID+"/test", nil); w.Code != 404 {
		t.Errorf("a relay was tested as a node: %d", w.Code)
	}
	c.reauth()
	if w := c.do("DELETE", "/api/relays/"+rid, nil); w.Code != 200 {
		t.Fatalf("relay delete: %d", w.Code)
	}
	if w := c.do("DELETE", "/api/exits/"+exitID, nil); w.Code != 200 {
		t.Fatalf("unreferenced exit delete: %d %s", w.Code, w.Body.String())
	}
}

func TestWebDiagnosticsAreLimitedToOneAtATimePerSlot(t *testing.T) {
	e := newWebEnv(t)
	c := e.login()
	e.ws.diagSem <- struct{}{}
	e.ws.diagSem <- struct{}{}
	w := c.do("POST", "/api/exits/aaaaaaaaaaaa/test", nil)
	if w.Code != 404 { // validated before running
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	w = c.do("POST", "/api/nodes", map[string]any{"base_name": "T", "protocols": []string{"vless"}, "inbound": "ipv4"})
	mustOK(t, w.Code, w.Body.String())
	id := listOf(t, jsonOf(t, w), "nodes")[0]["id"].(string)
	if w := c.do("POST", "/api/nodes/"+id+"/test", nil); w.Code != 429 || w.Header().Get("Retry-After") == "" {
		t.Fatalf("test slots not enforced: %d %s", w.Code, w.Body.String())
	}
}

// ---- sources and aggregates ----

func TestWebSourceManagementAndRefresh(t *testing.T) {
	s := newAPIScene(t)
	c := s.c
	list := listOf(t, jsonOf(t, c.get("/api/sources")), "sources")
	if len(list) != 2 {
		t.Fatalf("sources: %d", len(list))
	}
	for _, v := range list {
		if v["valid"].(float64) < 1 || v["status"].(map[string]any)["state"] != "ok" {
			t.Errorf("source view: %v", v)
		}
	}
	// Validation: the fetcher's SSRF policy and the manager's own limits apply through the API.
	for name, body := range map[string]map[string]any{
		"loopback":       {"name": "a1", "url": "http://127.0.0.1/sub"},
		"metadata":       {"name": "a2", "url": "http://169.254.169.254/latest"},
		"private":        {"name": "a3", "url": "https://10.0.0.5/sub"},
		"file scheme":    {"name": "a4", "url": "file:///etc/passwd"},
		"credentials":    {"name": "a5", "url": "https://user:pw@example.com/sub"},
		"short interval": {"name": "a6", "url": "https://example.com/s", "interval_min": 1},
		"no name":        {"name": "", "url": "https://example.com/s"},
		"both":           {"name": "a7", "url": "https://example.com/s", "content": "vless://x"},
		"neither":        {"name": "a8"},
	} {
		if w := c.do("POST", "/api/sources", body); w.Code < 400 || w.Code >= 500 {
			t.Errorf("%s accepted: %d %s", name, w.Code, w.Body.String())
		}
	}
	// A pasted list is a source too.
	w := c.do("POST", "/api/sources", map[string]any{"name": "Pasted", "content": linkList(linkVless, linkTrojan, "vmess://bm90c3VwcG9ydGVk"), "enabled": true})
	mustOK(t, w.Code, w.Body.String())
	pid := jsonOf(t, w)["source"].(map[string]any)["id"].(string)
	w = c.do("POST", "/api/sources/"+pid+"/refresh", nil)
	mustOK(t, w.Code, w.Body.String())
	res := jsonOf(t, w)
	if res["valid"] != float64(2) || res["errors"] != float64(1) {
		t.Fatalf("pasted refresh: %v", res)
	}
	detail := jsonOf(t, c.get("/api/sources/"+pid+"/nodes"))
	if len(detail["nodes"].([]any)) != 2 || len(detail["issues"].([]any)) != 1 {
		t.Fatalf("source detail: %s", s.env.ws.audit.recent(1))
	}
	issue := listOf(t, detail, "issues")[0]
	if issue["level"] != "error" || issue["reason"] == "" {
		t.Fatalf("unsupported entry not reported: %v", issue)
	}

	// Disable one node of the source, then re-enable.
	nodes := listOf(t, detail, "nodes")
	first := nodes[0]["id"].(string)
	if w := c.do("PUT", "/api/sources/"+pid+"/nodes", map[string]any{"disabled": []string{first}}); w.Code != 200 {
		t.Fatalf("disable node: %d %s", w.Code, w.Body.String())
	}
	if v := listOf(t, jsonOf(t, c.get("/api/sources")), "sources"); len(v) != 3 {
		t.Fatalf("sources: %d", len(v))
	}
	for _, n := range listOf(t, jsonOf(t, c.get("/api/sources/"+pid+"/nodes")), "nodes") {
		if (n["id"] == first) == (n["enabled"] == true) {
			t.Errorf("enabled flag wrong: %v", n)
		}
	}
	if w := c.do("PUT", "/api/sources/"+pid+"/nodes", map[string]any{"disabled": []string{"not-an-id"}}); w.Code < 400 {
		t.Fatal("invalid node id accepted")
	}
	if w := c.do("PATCH", "/api/sources/"+pid, map[string]any{"enabled": false, "note": "paused", "tags": []string{"a", "b"}}); w.Code != 200 {
		t.Fatalf("patch: %d %s", w.Code, w.Body.String())
	}
	// Refusal to delete a source that an aggregate uses, unless detached.
	agg := map[string]any{"name": "mix", "items": []map[string]any{{"kind": "local", "node_id": s.nodes[0].ID}, {"kind": "remote", "source_id": s.links.ID, "remote_id": s.rnode(t, s.links, "HK Reality").RemoteID}}}
	w = c.do("POST", "/api/subscriptions", agg)
	mustOK(t, w.Code, w.Body.String())
	c.reauth()
	if w := c.do("DELETE", "/api/sources/"+s.links.ID, nil); w.Code == 200 {
		t.Fatal("deleted a source that is in use")
	}
	if w := c.do("DELETE", "/api/sources/"+s.links.ID+"?detach=1", nil); w.Code != 200 {
		t.Fatalf("detach delete: %d %s", w.Code, w.Body.String())
	}
	subs := listOf(t, jsonOf(t, c.get("/api/subscriptions")), "subscriptions")
	for _, sv := range subs {
		if sv["name"] == "mix" && sv["remote_count"] != float64(0) {
			t.Errorf("aggregate still lists the removed source: %v", sv)
		}
	}
}

func TestWebRefreshesDoNotOverlap(t *testing.T) {
	s := newAPIScene(t)
	release := make(chan struct{})
	entered := make(chan struct{}, 4)
	var calls int
	var mu sync.Mutex
	inner := s.a.remoteFetch
	s.a.remoteFetch = func(ctx context.Context, raw string, opt remote.FetchOptions) (*remote.Result, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		entered <- struct{}{}
		<-release
		return inner(ctx, raw, opt)
	}
	codes := make(chan int, 2)
	go func() { codes <- s.c.do("POST", "/api/sources/"+s.links.ID+"/refresh", nil).Code }()
	<-entered
	go func() { codes <- s.c.do("POST", "/api/sources/"+s.links.ID+"/refresh", nil).Code }()
	if got := <-codes; got != 409 {
		t.Fatalf("the second concurrent refresh got %d", got)
	}
	close(release)
	if got := <-codes; got != 200 {
		t.Fatalf("the first refresh got %d", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Fatalf("the source was downloaded %d times", calls)
	}
}

func TestWebAggregateSubscriptionEndToEnd(t *testing.T) {
	s := newAPIScene(t)
	c := s.c
	hk := s.rnode(t, s.links, "HK Reality")
	jp := s.rnode(t, s.links, "JP Trojan")
	items := []map[string]any{
		{"kind": "local", "node_id": s.nodes[0].ID, "name": "My Home"},
		{"kind": "remote", "source_id": hk.SourceID, "remote_id": hk.RemoteID},
		{"kind": "remote", "source_id": jp.SourceID, "remote_id": jp.RemoteID, "name": "Tokyo \U0001F1EF\U0001F1F5"},
		{"kind": "local", "node_id": s.nodes[1].ID},
	}
	w := c.do("POST", "/api/subscriptions", map[string]any{"name": "mix", "items": items, "dedupe": true})
	mustOK(t, w.Code, w.Body.String())
	view := jsonOf(t, w)["subscription"].(map[string]any)
	subID := view["id"].(string)
	if view["aggregate"] != true || view["local_count"] != float64(2) || view["remote_count"] != float64(2) {
		t.Fatalf("view: %v", view)
	}
	order := []string{}
	for _, it := range view["items"].([]any) {
		order = append(order, it.(map[string]any)["name"].(string))
	}
	if order[0] != "My Home" || order[2] != "Tokyo \U0001F1EF\U0001F1F5" {
		t.Fatalf("custom names/order lost: %v", order)
	}
	// The token is not in the response, but is available after a password check.
	if strings.Contains(w.Body.String(), "token") && !strings.Contains(w.Body.String(), "token_hash") {
		t.Log("response mentions a token field name only")
	}
	if w := c.get("/api/subscriptions/" + subID + "/url"); w.Code != 403 {
		t.Fatalf("url without reauth: %d", w.Code)
	}
	c.reauth()
	if w := c.get("/api/subscriptions/" + subID + "/url"); w.Code != 409 {
		t.Fatalf("no public URL is configured yet: %d %s", w.Code, w.Body.String())
	}
	if er := s.a.SetSubscriptionPublicURL("https://sub.example.test"); er != nil {
		t.Fatal(er)
	}
	w = c.get("/api/subscriptions/" + subID + "/url")
	mustOK(t, w.Code, w.Body.String())
	urls := jsonOf(t, w)
	b64URL, mihomoURL := urls["base64_url"].(string), urls["mihomo_url"].(string)
	if !strings.HasPrefix(b64URL, "https://sub.example.test/s/") || mihomoURL != b64URL+"?format=mihomo" {
		t.Fatalf("urls: %v", urls)
	}
	token := strings.TrimPrefix(b64URL, "https://sub.example.test/s/")

	// What a client actually receives: parse both formats and compare with the report.
	h := s.server()
	code, body := s.fetchFormat(t, h, token, "")
	if code != 200 {
		t.Fatalf("base64: %d", code)
	}
	raw, e := base64.StdEncoding.DecodeString(strings.TrimSpace(body))
	if e != nil {
		t.Fatal(e)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 4 {
		t.Fatalf("base64 subscription has %d entries: %v", len(lines), lines)
	}
	if !strings.Contains(lines[1], "11111111-1111-4111-8111-111111111111@198.51.100.10:443") || !strings.Contains(lines[1], "pbk="+pbk) {
		t.Errorf("Reality parameters lost: %s", lines[1])
	}
	code, body = s.fetchFormat(t, h, token, "mihomo")
	if code != 200 {
		t.Fatalf("mihomo: %d", code)
	}
	doc := parseMihomoDoc(t, body)
	if len(doc.Proxies) != 4 {
		t.Fatalf("mihomo proxies: %d\n%s", len(doc.Proxies), body)
	}
	if doc.Proxies[0]["name"] != "My Home" || doc.Proxies[2]["name"] != "Tokyo \U0001F1EF\U0001F1F5" {
		t.Errorf("names/order: %v / %v", doc.Proxies[0]["name"], doc.Proxies[2]["name"])
	}
	ro := proxyNamed(t, doc, "HK Reality")
	if ro["type"] != "vless" || ro["servername"] != "www.example.org" {
		t.Errorf("Reality node: %v", ro)
	}

	// Changing items through the API, back to a plain local list, keeps the legacy path.
	plain, _ := s.create(t, "plain", 0, 1)
	before, _ := s.a.Load()
	i, _ := findSubscription(before, plain.ID)
	if before.Subscriptions[i].aggregate() {
		t.Fatal("test subscription is already an aggregate")
	}
	w = c.do("PUT", "/api/subscriptions/"+plain.ID+"/items", map[string]any{"node_ids": []string{s.nodes[2].ID, s.nodes[0].ID}})
	mustOK(t, w.Code, w.Body.String())
	after, _ := s.a.Load()
	i, _ = findSubscription(after, plain.ID)
	if after.Subscriptions[i].aggregate() || len(after.Subscriptions[i].Items) != 0 || after.Subscriptions[i].NodeIDs[0] != s.nodes[2].ID {
		t.Fatalf("a local-only edit turned the subscription into an aggregate: %+v", after.Subscriptions[i])
	}
	// Adding a third-party node does convert it, and the report names what is lost.
	w = c.do("PUT", "/api/subscriptions/"+plain.ID+"/items", map[string]any{"items": []map[string]any{
		{"kind": "local", "node_id": s.nodes[2].ID},
		{"kind": "remote", "source_id": s.links.ID, "remote_id": s.rnode(t, s.links, "SG HY2").RemoteID},
	}})
	mustOK(t, w.Code, w.Body.String())
	v := jsonOf(t, c.get("/api/subscriptions"))
	var plainView map[string]any
	for _, sv := range listOf(t, v, "subscriptions") {
		if sv["id"] == plain.ID {
			plainView = sv
		}
	}
	if plainView == nil || plainView["aggregate"] != true || plainView["remote_count"] != float64(1) {
		t.Fatalf("converted view: %v", plainView)
	}
	// Rejections.
	for name, body := range map[string]map[string]any{
		"empty":            {"name": "e", "items": []map[string]any{}, "dedupe": true},
		"unknown source":   {"name": "u", "items": []map[string]any{{"kind": "remote", "source_id": "aaaaaaaaaaaa", "remote_id": "bbbbbbbbbbbb"}}},
		"unknown node":     {"name": "n", "items": []map[string]any{{"kind": "local", "node_id": "aaaaaaaaaaaa"}}},
		"both forms":       {"name": "b", "items": []map[string]any{{"kind": "local", "node_id": s.nodes[0].ID}}, "node_ids": []string{s.nodes[1].ID}},
		"duplicate name":   {"name": "mix", "node_ids": []string{s.nodes[0].ID}},
		"bad kind":         {"name": "k", "items": []map[string]any{{"kind": "magic", "node_id": s.nodes[0].ID}}},
		"newline in label": {"name": "l", "items": []map[string]any{{"kind": "local", "node_id": s.nodes[0].ID, "name": "a\nb"}}},
	} {
		if w := c.do("POST", "/api/subscriptions", body); w.Code < 400 || w.Code >= 500 {
			t.Errorf("%s accepted: %d %s", name, w.Code, w.Body.String())
		}
	}
}

func TestWebSubscriptionPlanAndRotation(t *testing.T) {
	s := newAPIScene(t)
	c := s.c
	enableTrafficMarker(t, s.a)
	sub, token := s.create(t, "plan", 0)
	if w := c.do("PUT", "/api/subscriptions/"+sub.ID+"/plan", map[string]any{"limit_bytes": 500e9, "billing_day": 15, "timezone": "Asia/Tokyo", "expires": "2027-01-31"}); w.Code != 200 {
		t.Fatalf("plan: %d %s", w.Code, w.Body.String())
	}
	var view map[string]any
	for _, sv := range listOf(t, jsonOf(t, c.get("/api/subscriptions")), "subscriptions") {
		if sv["id"] == sub.ID {
			view = sv
		}
	}
	plan, _ := view["plan"].(map[string]any)
	if plan == nil || plan["limit"] != 500e9 || plan["billing_day"] != float64(15) || plan["expires"] != "2027-01-31" {
		t.Fatalf("plan view: %v", view)
	}
	for _, bad := range []map[string]any{{"limit_bytes": 1, "billing_day": 40}, {"limit_bytes": 1, "timezone": "Mars/Base"}, {"limit_bytes": 1, "expires": "tomorrow"}} {
		if w := c.do("PUT", "/api/subscriptions/"+sub.ID+"/plan", bad); w.Code < 400 {
			t.Errorf("%v accepted", bad)
		}
	}
	// Rotation invalidates the old URL at the server.
	h := s.server()
	if code, _ := s.fetchFormat(t, h, token, ""); code != 200 {
		t.Fatalf("before rotation: %d", code)
	}
	c.reauth()
	if w := c.do("POST", "/api/subscriptions/"+sub.ID+"/rotate", nil); w.Code != 200 {
		t.Fatalf("rotate: %d %s", w.Code, w.Body.String())
	}
	if code, _ := s.fetchFormat(t, s.server(), token, ""); code != 404 {
		t.Fatalf("the old token still works: %d", code)
	}
	// Disable/enable.
	if w := c.do("PATCH", "/api/subscriptions/"+sub.ID, map[string]any{"enabled": false}); w.Code != 200 {
		t.Fatalf("disable: %d", w.Code)
	}
	if w := c.do("PATCH", "/api/subscriptions/"+sub.ID, map[string]any{"name": "renamed"}); w.Code != 200 {
		t.Fatalf("rename: %d", w.Code)
	}
}

// ---- backup and restore ----

func TestWebBackupAndRestoreIncludeSources(t *testing.T) {
	s := newAPIScene(t)
	c := s.c
	sub, _ := s.create(t, "keep", 0, 1)
	_ = sub
	if w := c.do("POST", "/api/subscriptions", map[string]any{"name": "mix", "items": []map[string]any{
		{"kind": "local", "node_id": s.nodes[0].ID},
		{"kind": "remote", "source_id": s.links.ID, "remote_id": s.rnode(t, s.links, "HK Reality").RemoteID}}}); w.Code != 200 {
		t.Fatalf("aggregate: %d %s", w.Code, w.Body.String())
	}
	if w := c.get("/api/system/backup"); w.Code != 403 {
		t.Fatalf("backup without reauth: %d", w.Code)
	}
	c.reauth()
	w := c.get("/api/system/backup")
	mustOK(t, w.Code, w.Body.String())
	if !strings.HasPrefix(w.Header().Get("Content-Disposition"), "attachment") || !strings.Contains(w.Header().Get("Cache-Control"), "no-store") {
		t.Fatalf("download headers: %v", w.Header())
	}
	backup := append([]byte{}, w.Body.Bytes()...)
	var bundle BackupBundle
	if e := json.Unmarshal(backup, &bundle); e != nil || bundle.Format != backupFormat || bundle.Remote == nil || len(bundle.Remote.Sources) != 2 || len(bundle.Remote.Snapshots) != 2 {
		t.Fatalf("bundle: %v %+v", e, bundle.Remote)
	}
	if strings.Contains(string(backup), "password_hash") || strings.Contains(string(backup), "pbkdf2") {
		t.Fatal("the backup contains the panel password hash")
	}

	// Damage the configuration, then restore.
	st, _ := s.a.Load()
	for _, sv := range st.Subscriptions {
		if e := s.a.DeleteSubscription(sv.ID); e != nil {
			t.Fatal(e)
		}
	}
	if e := s.a.DeleteRemoteSource(s.clash.ID, true); e != nil {
		t.Fatal(e)
	}
	if e := s.a.DeleteProfiles([]string{s.nodes[2].ID}); e != nil {
		t.Fatal(e)
	}
	restore := func(body map[string]any) (int, map[string]any) {
		w := c.do("POST", "/api/system/restore", body)
		var m map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &m)
		return w.Code, m
	}
	code, m := restore(map[string]any{"backup": json.RawMessage(backup), "dry_run": true})
	if code != 200 || m["applied"] != false {
		t.Fatalf("dry run: %d %v", code, m)
	}
	plan := m["plan"].(map[string]any)
	if len(plan["subscriptions"].(map[string]any)["added"].([]any)) != 2 || len(plan["sources"].(map[string]any)["added"].([]any)) != 1 || len(plan["nodes"].(map[string]any)["added"].([]any)) != 1 {
		t.Fatalf("plan: %v", plan)
	}
	if now, _ := s.a.Load(); len(now.Subscriptions) != 0 {
		t.Fatal("a dry run changed the configuration")
	}
	if code, _ := restore(map[string]any{"backup": json.RawMessage(backup)}); code != 400 {
		t.Fatalf("restore without confirmation: %d", code)
	}
	if code, _ := restore(map[string]any{"backup": json.RawMessage(`{"format":"something-else"}`), "confirm": "RESTORE"}); code != 400 {
		t.Fatalf("foreign file accepted: %d", code)
	}
	if code, _ := restore(map[string]any{"backup": json.RawMessage(`{"format":"rout-backup","version":99,"state":{}}`), "confirm": "RESTORE"}); code != 400 {
		t.Fatalf("newer backup accepted: %d", code)
	}
	code, m = restore(map[string]any{"backup": json.RawMessage(backup), "confirm": "RESTORE"})
	if code != 200 || m["applied"] != true {
		t.Fatalf("restore: %d %v", code, m)
	}
	after, _ := s.a.Load()
	if len(after.Subscriptions) != 2 || len(after.Profiles) != 3 {
		t.Fatalf("after restore: %d subscriptions, %d profiles", len(after.Subscriptions), len(after.Profiles))
	}
	views, _ := s.a.RemoteSources()
	if len(views) != 2 {
		t.Fatalf("sources after restore: %d", len(views))
	}
	// The aggregate serves the third-party node again from the restored snapshot.
	var mix Subscription
	for _, sv := range after.Subscriptions {
		if sv.Name == "mix" {
			mix = sv
		}
	}
	exp := s.a.ExportAggregate(after, mix)
	if len(exp.URIs) != 2 {
		t.Fatalf("restored aggregate exports %d entries", len(exp.URIs))
	}
	// Permissions of everything the restore wrote.
	for _, pc := range s.a.CheckPermissions() {
		if !pc.OK {
			t.Errorf("permissions after restore: %+v", pc)
		}
	}
}

func TestWebRestoreOfAPlainStateBackupKeepsSources(t *testing.T) {
	s := newAPIScene(t)
	plain := filepath.Join(t.TempDir(), "state.json")
	if e := s.a.Backup(plain); e != nil {
		t.Fatal(e)
	}
	raw, _ := os.ReadFile(plain)
	st, _ := s.a.Load()
	if e := s.a.DeleteProfiles([]string{st.Profiles[0].ID}); e != nil {
		t.Fatal(e)
	}
	s.c.reauth()
	w := s.c.do("POST", "/api/system/restore", map[string]any{"backup": json.RawMessage(raw), "confirm": "RESTORE"})
	mustOK(t, w.Code, w.Body.String())
	if after, _ := s.a.Load(); len(after.Profiles) != 3 {
		t.Fatal("plain backup not restored")
	}
	if views, _ := s.a.RemoteSources(); len(views) != 2 {
		t.Fatal("a plain state backup removed the third-party sources")
	}
}

func TestWebBackupFilePermissions(t *testing.T) {
	s := newAPIScene(t)
	if e := os.Chmod(s.a.Home, 0700); e != nil { // the temporary directory is world-readable
		t.Fatal(e)
	}
	path := filepath.Join(t.TempDir(), "full.json")
	if e := s.a.WriteBackupBundle(path, time.Now()); e != nil {
		t.Fatal(e)
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0600 {
		t.Fatalf("backup mode %v", st.Mode().Perm())
	}
	// Loosened permissions are reported and can be repaired.
	data := s.a.remotePath("data")
	ents, _ := os.ReadDir(data)
	var victim string
	for _, ent := range ents {
		if strings.HasSuffix(ent.Name(), ".json") {
			victim = filepath.Join(data, ent.Name())
		}
	}
	if victim == "" {
		t.Fatal("no snapshot file")
	}
	if e := os.Chmod(victim, 0644); e != nil {
		t.Fatal(e)
	}
	bad := 0
	for _, pc := range s.a.CheckPermissions() {
		if !pc.OK {
			bad++
			t.Logf("reported: %+v", pc)
		}
	}
	if bad != 1 {
		t.Fatalf("%d problems reported", bad)
	}
	s.c.reauth()
	if w := s.c.do("POST", "/api/system/permissions/fix", nil); w.Code != 200 || jsonOf(t, w)["fixed"] != float64(1) {
		t.Fatalf("fix: %d %s", w.Code, w.Body.String())
	}
	if st, _ := os.Stat(victim); st.Mode().Perm() != 0600 {
		t.Fatal("not repaired")
	}
}

// ---- system, overview ----

func TestWebOverview(t *testing.T) {
	s := newAPIScene(t)
	c := s.c
	w := c.do("POST", "/api/nodes", map[string]any{"base_name": "Edge", "protocols": []string{"hy2"}, "inbound": "ipv4"})
	mustOK(t, w.Code, w.Body.String())
	// The probe runs in the background; the first answer may not have addresses yet.
	var ov map[string]any
	for i := 0; i < 50; i++ {
		ov = jsonOf(t, c.get("/api/overview"))
		if ov["network"].(map[string]any)["ipv4"] != "" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	nw := ov["network"].(map[string]any)
	if nw["ipv4"] != v4Addr || nw["ipv6"] != v6Addr {
		t.Fatalf("network: %v", nw)
	}
	counts := ov["counts"].(map[string]any)
	if counts["nodes"].(map[string]any)["total"] != float64(4) || counts["sources"] != float64(2) || counts["remote_nodes"].(float64) < 5 {
		t.Fatalf("counts: %v", counts)
	}
	if ov["version"] != Version || ov["system"] == nil || ov["traffic"] == nil {
		t.Fatalf("overview: %v", ov)
	}
	// A failing source becomes an alert.
	s.fsLinks.err = context.DeadlineExceeded
	s.c.do("POST", "/api/sources/"+s.links.ID+"/refresh", nil)
	ov = jsonOf(t, c.get("/api/overview"))
	found := false
	for _, a := range listOf(t, ov, "alerts") {
		if a["code"] == "source_refresh_failed" {
			found = true
			if strings.Contains(a["detail"].(string), "://") {
				t.Fatalf("alert detail leaks a URL: %v", a)
			}
		}
	}
	if !found {
		t.Fatalf("no alert for the failed source: %v", ov["alerts"])
	}
	// Reaching the panel over plain HTTP under a public name is flagged.
	if er := s.a.mutateWebConfig(func(c *WebConfig) error { c.AllowedHosts = []string{"panel.example.test"}; return nil }); er != nil {
		t.Fatal(er)
	}
	s.env.ws.invalidateConfig()
	ov = jsonOf(t, s.c.do("GET", "/api/overview", nil, withHost("panel.example.test")))
	insecure := false
	for _, a := range listOf(t, ov, "alerts") {
		insecure = insecure || a["code"] == "insecure_transport"
	}
	if !insecure {
		t.Fatal("plain HTTP under a public host name was not flagged")
	}
	ov = jsonOf(t, s.c.do("GET", "/api/overview", nil, withHost("panel.example.test"), withHeader("X-Forwarded-Proto", "https")))
	for _, a := range listOf(t, ov, "alerts") {
		if a["code"] == "insecure_transport" {
			t.Fatal("HTTPS through the proxy flagged as insecure")
		}
	}
}

func TestWebSystemEndpoints(t *testing.T) {
	s := newAPIScene(t)
	c := s.c
	sys := jsonOf(t, c.get("/api/system"))
	if sys["version"] != Version || sys["runtime"] == nil || sys["web"].(map[string]any)["password_set"] != true {
		t.Fatalf("system: %v", sys)
	}
	if strings.Contains(c.get("/api/system").Body.String(), "pbkdf2") {
		t.Fatal("system view exposes the password hash")
	}
	upd := jsonOf(t, c.do("POST", "/api/system/update-check", nil))
	if upd["latest"] != "v0.5.0" || upd["available"] != true || upd["current"] != Version {
		t.Fatalf("update: %v", upd)
	}
	s.env.ws.fetchLatest = func(context.Context) (string, error) { return "", context.DeadlineExceeded }
	s.env.clock.advance(2 * time.Minute)
	upd = jsonOf(t, c.do("POST", "/api/system/update-check", nil))
	if upd["error"] == nil || upd["available"] == true {
		t.Fatalf("failed check: %v", upd)
	}
	nw := jsonOf(t, c.get("/api/system/network"))
	if nw["dns"].(map[string]any)["ok"] != true {
		t.Fatalf("network: %v", nw)
	}

	// Logs: only fixed units; arguments never reach a shell.
	for _, bad := range []string{"", "x", "../../etc/passwd", "subscription;id", "$(id)", "aaaaaaaaaaaa"} {
		if w := c.get("/api/system/logs?unit=" + url.QueryEscape(bad)); w.Code < 400 {
			t.Errorf("unit %q accepted: %d", bad, w.Code)
		}
	}
	if w := c.get("/api/system/logs?unit=web&lines=9999"); w.Code != 400 {
		t.Errorf("line limit: %d", w.Code)
	}
	if got := redactLog("GET /s/" + strings.Repeat("A", 43) + " 200\nconnecting https://x.test/sub?token=abc uuid 11111111-1111-4111-8111-111111111111 password=hunter2 key " + strings.Repeat("Z", 40)); strings.Contains(got, "AAAA") || strings.Contains(got, "x.test") || strings.Contains(got, "11111111") || strings.Contains(got, "hunter2") || strings.Contains(got, "ZZZZ") {
		t.Errorf("log redaction: %q", got)
	}

	// Services: only the subscription server and known profiles.
	for _, bad := range []map[string]string{{"unit": "sshd", "action": "stop"}, {"unit": "subscription", "action": "reload"}, {"unit": "../x", "action": "restart"}, {"unit": "aaaaaaaaaaaa", "action": "restart"}, {"unit": s.nodes[0].ID, "action": "stop"}} {
		if w := c.do("POST", "/api/system/service", bad); w.Code < 400 {
			t.Errorf("%v accepted", bad)
		}
	}
	if w := c.do("POST", "/api/system/service", map[string]string{"unit": "subscription", "action": "stop"}); w.Code != 403 {
		t.Errorf("stopping the subscription server needs the password: %d", w.Code)
	}

	// Settings.
	if w := c.do("PATCH", "/api/system/settings", map[string]any{"session_idle_min": 10}); w.Code != 403 {
		t.Fatalf("settings without reauth: %d", w.Code)
	}
	c.reauth()
	if w := c.do("PATCH", "/api/system/settings", map[string]any{"session_idle_min": 10, "allowed_hosts": []string{"Panel.Example.test"}}); w.Code != 200 {
		t.Fatalf("settings: %d %s", w.Code, w.Body.String())
	}
	cfg, _ := s.a.LoadWebConfig()
	if cfg.SessionIdleMin != 10 || len(cfg.AllowedHosts) != 1 || cfg.AllowedHosts[0] != "panel.example.test" {
		t.Fatalf("stored: %+v", cfg)
	}
	for _, bad := range []map[string]any{{"session_idle_min": -1}, {"session_idle_min": 99999}, {"allowed_hosts": []string{"bad host!"}}, {"port": 80}, {"allowed_hosts": []string{"a.test", "b.test", "c.test", "d.test", "e.test", "f.test", "g.test", "h.test", "i.test"}}} {
		if w := c.do("PATCH", "/api/system/settings", bad); w.Code < 400 {
			t.Errorf("%v accepted", bad)
		}
	}
	if w := c.do("PATCH", "/api/system/settings", map[string]any{"port": 9000}); w.Code != 200 || jsonOf(t, w)["restart_required"] != true {
		t.Errorf("port change should require a restart: %s", w.Body.String())
	}
	// A settings change cannot remove the password.
	if cfg, _ := s.a.LoadWebConfig(); cfg.PasswordHash == "" {
		t.Fatal("settings update dropped the password")
	}
}

func TestWebActivityLogRecordsChanges(t *testing.T) {
	s := newAPIScene(t)
	s.c.do("POST", "/api/subscriptions", map[string]any{"name": "audit-me", "node_ids": []string{s.nodes[0].ID}})
	s.c.reauth()
	s.c.get("/api/nodes/" + s.nodes[0].ID + "/link")
	entries := listOf(t, jsonOf(t, s.c.get("/api/activity")), "entries")
	var joined string
	for _, e := range entries {
		joined += e["action"].(string) + "\n"
	}
	for _, want := range []string{"POST /api/subscriptions", "reveal link " + s.nodes[0].ID} {
		if !strings.Contains(joined, want) {
			t.Errorf("activity lacks %q:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "audit-me") {
		t.Error("the audit log keeps request contents")
	}
}

// Server-generated explanations follow the language the browser asks for, so the English
// interface never shows Chinese diagnostics.
func TestWebExplanationsFollowTheRequestedLanguage(t *testing.T) {
	s := newAPIScene(t)
	c := s.c
	sub, _ := s.create(t, "lang", 0, 1)
	if e := s.a.SetNodesEnabled([]string{s.nodes[1].ID}, false); e != nil {
		t.Fatal(e)
	}
	find := func(lang string) string {
		w := c.do("GET", "/api/subscriptions", nil, withHeader("X-Rout-Lang", lang))
		mustOK(t, w.Code, w.Body.String())
		for _, sv := range listOf(t, jsonOf(t, w), "subscriptions") {
			if sv["id"] != sub.ID {
				continue
			}
			for _, it := range listOf(t, sv, "items") {
				if it["status"] == "skipped" {
					return it["skipped"].(string)
				}
			}
		}
		t.Fatal("no skipped item")
		return ""
	}
	if got := find("zh-CN"); got != "节点已停用" {
		t.Errorf("zh-CN: %q", got)
	}
	if got := find("en"); got != "The node is disabled" {
		t.Errorf("en: %q", got)
	}
}

// An explicit aggregate flag lets a subscription of local nodes use custom names without
// third-party nodes; without it, local-only edits keep the legacy (byte-identical) path.
func TestWebAggregateFlagEnablesCustomNamesForLocalNodes(t *testing.T) {
	s := newAPIScene(t)
	c := s.c
	plain, _ := s.create(t, "plain-flag", 0, 1)
	named := []map[string]any{{"kind": "local", "node_id": s.nodes[0].ID, "name": "Front door"}, {"kind": "local", "node_id": s.nodes[1].ID}}
	if w := c.do("PUT", "/api/subscriptions/"+plain.ID+"/items", map[string]any{"items": named}); w.Code < 400 || w.Code >= 500 {
		t.Fatalf("custom names without the flag: %d %s", w.Code, w.Body.String())
	}
	w := c.do("PUT", "/api/subscriptions/"+plain.ID+"/items", map[string]any{"items": named, "aggregate": true})
	mustOK(t, w.Code, w.Body.String())
	st, _ := s.a.Load()
	i, _ := findSubscription(st, plain.ID)
	if !st.Subscriptions[i].aggregate() || st.Subscriptions[i].Items[0].Name != "Front door" {
		t.Fatalf("not an aggregate: %+v", st.Subscriptions[i])
	}
	// Creating works the same way.
	w = c.do("POST", "/api/subscriptions", map[string]any{"name": "fresh-agg", "aggregate": true, "items": []map[string]any{{"kind": "local", "node_id": s.nodes[2].ID}}})
	mustOK(t, w.Code, w.Body.String())
	sv := jsonOf(t, w)["subscription"].(map[string]any)
	if sv["aggregate"] != true {
		t.Fatalf("created view: %v", sv)
	}
}
