package rout

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func snellSetup() ServerSetup {
	return ServerSetup{PublicHost: v4Addr, Listen: "0.0.0.0", IPv4: v4Addr, Network: "both", Family: "ipv4"}
}

// ---- subscriptions --------------------------------------------------------------------------

type snellSubScene struct {
	a                         *App
	snell5, snell6, ss, vless Profile
}

func newSnellSubScene(t *testing.T) *snellSubScene {
	t.Helper()
	a := testApp(t)
	return &snellSubScene{
		a:      a,
		snell5: aiTestNode(t, a, "snell", "Tokyo-Snell"),
		snell6: aiTestNode(t, a, "snell6", "Tokyo-Snell6"),
		ss:     aiTestNode(t, a, "ss", "Tokyo-SS"),
		vless:  aiTestNode(t, a, "vless", "Tokyo-VLESS"),
	}
}
func (sc *snellSubScene) handler() http.Handler {
	cache := &stateCache{a: sc.a}
	return newSubscriptionHandler(cache.load, func(string, ...any) {})
}

func TestSnellSubscriptionSurgeFormat(t *testing.T) {
	sc := newSnellSubScene(t)
	// A subscription may mix Snell with other nodes; each format carries what its client can run.
	_, token, e := sc.a.CreateSubscription("Phone", []string{sc.snell5.ID, sc.ss.ID, sc.snell6.ID, sc.vless.ID})
	if e != nil {
		t.Fatalf("Snell nodes cannot join a subscription: %v", e)
	}
	h := sc.handler()

	w := get(h, "GET", "/s/"+token+"?format=surge")
	if w.Code != 200 || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/plain") {
		t.Fatalf("surge format: %d %s %s", w.Code, w.Header().Get("Content-Type"), w.Body.String())
	}
	body := w.Body.String()
	lines := strings.Split(strings.TrimSpace(body), "\n")
	want5, _ := sc.snell5.Share()
	want6, _ := sc.snell6.Share()
	if len(lines) != 2 || lines[0] != want5 || lines[1] != want6 {
		t.Fatalf("Surge list (saved order, Snell only):\n%s\nwant\n%s\n%s", body, want5, want6)
	}
	for _, other := range []Profile{sc.ss, sc.vless} {
		if strings.Contains(body, other.Name) || strings.Contains(body, other.Password) {
			t.Fatalf("a %s node leaked into the Surge list", other.Protocol)
		}
	}
	if got := w.Header().Get("X-Rout-Skipped-Nodes"); got != "2" {
		t.Errorf("skipped nodes header %q", got)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Error("credentials may be cached")
	}
	// Surge's HEAD probe works like every other format.
	if w := get(h, "HEAD", "/s/"+token+"?format=surge"); w.Code != 200 || w.Body.Len() != 0 {
		t.Errorf("HEAD: %d %q", w.Code, w.Body.String())
	}

	// Base64 and Mihomo are unchanged for the nodes they can carry and skip Snell without damage.
	b64 := get(h, "GET", "/s/"+token)
	if b64.Code != 200 {
		t.Fatalf("base64: %d %s", b64.Code, b64.Body.String())
	}
	var sawSS, sawVLESS bool
	for _, l := range decodeBody(t, b64.Body.String()) {
		sawSS = sawSS || strings.HasPrefix(l, "ss://")
		sawVLESS = sawVLESS || strings.HasPrefix(l, "vless://")
		if strings.Contains(l, "snell") || strings.Contains(l, sc.snell5.Password) {
			t.Fatalf("a Snell node was forced into the Base64 list: %q", l)
		}
	}
	if !sawSS || !sawVLESS {
		t.Fatal("Base64 lost its own nodes")
	}
	mh := get(h, "GET", "/s/"+token+"?format=mihomo")
	// Only a diagnostic comment may mention the skipped Snell nodes; no proxy and no secret.
	if mh.Code != 200 || strings.Contains(mh.Body.String(), `"type":"snell"`) || strings.Contains(mh.Body.String(), sc.snell5.Password) || strings.Contains(mh.Body.String(), sc.snell6.Password) || !strings.Contains(mh.Body.String(), "Tokyo-SS") {
		t.Fatalf("mihomo: %d\n%s", mh.Code, mh.Body.String())
	}
	if w := get(h, "GET", "/s/"+token+"?format=quantumult"); w.Code != 400 || !strings.Contains(w.Body.String(), "surge") {
		t.Errorf("unknown format: %d %s", w.Code, w.Body.String())
	}
	if w := get(h, "GET", "/s/"+token+"?format=surge&format=base64"); w.Code != 400 {
		t.Errorf("ambiguous format: %d", w.Code)
	}
	// An unknown token is a uniform 404 even with the Surge format.
	if w := get(h, "GET", "/s/"+strings.Repeat("a", 43)+"?format=surge"); w.Code != 404 {
		t.Errorf("unknown token: %d", w.Code)
	}
}

func TestSnellOnlySubscriptionAndFormatsWithoutSnell(t *testing.T) {
	sc := newSnellSubScene(t)
	_, snellToken, e := sc.a.CreateSubscription("Surge only", []string{sc.snell5.ID})
	if e != nil {
		t.Fatal(e)
	}
	_, plainToken, e := sc.a.CreateSubscription("Plain", []string{sc.ss.ID, sc.vless.ID})
	if e != nil {
		t.Fatal(e)
	}
	h := sc.handler()
	// A Snell-only subscription has nothing for Base64 or Mihomo clients, and says so.
	for _, format := range []string{"", "?format=mihomo", "?format=clash"} {
		w := get(h, "GET", "/s/"+snellToken+format)
		if w.Code != 503 || strings.Contains(w.Body.String(), sc.snell5.Password) {
			t.Errorf("Snell-only subscription as %q: %d %s", format, w.Code, w.Body.String())
		}
	}
	if w := get(h, "GET", "/s/"+snellToken+"?format=surge"); w.Code != 200 || !strings.Contains(w.Body.String(), "version=5") {
		t.Errorf("Surge: %d %s", w.Code, w.Body.String())
	}
	// A subscription without Snell has nothing for Surge.
	if w := get(h, "GET", "/s/"+plainToken+"?format=surge"); w.Code != 503 || !strings.Contains(w.Body.String(), "Snell") {
		t.Errorf("no Snell nodes: %d %s", w.Code, w.Body.String())
	}
	if w := get(h, "GET", "/s/"+plainToken); w.Code != 200 {
		t.Errorf("existing Base64 subscription: %d", w.Code)
	}
}

func TestSnellSubscriptionFollowsTheNodeAndSurvivesUpdates(t *testing.T) {
	sc := newSnellSubScene(t)
	sub, token, e := sc.a.CreateSubscription("Phone", []string{sc.snell5.ID, sc.snell6.ID})
	if e != nil {
		t.Fatal(e)
	}
	h := sc.handler()
	fetch := func() string {
		w := get(h, "GET", "/s/"+token+"?format=surge")
		if w.Code != 200 {
			t.Fatalf("%d %s", w.Code, w.Body.String())
		}
		return w.Body.String()
	}
	before := fetch()
	if !strings.Contains(before, "psk="+sc.snell5.Password) || !strings.Contains(before, "psk="+sc.snell6.Password) {
		t.Fatalf("both nodes expected:\n%s", before)
	}

	// New PSK, new port and a new public endpoint (NAT remap): the next fetch carries them.
	s, _ := sc.a.Load()
	moved := sc.snell5
	moved.Password = "ChangedPskChangedPsk1234567890ab"
	moved.PublicHost, moved.PublicPort = "snell.example.com", 8443
	if e = sc.a.Commit(s, replace(s, moved), false); e != nil {
		t.Fatal(e)
	}
	after := fetch()
	if !strings.Contains(after, "Tokyo-Snell = snell, snell.example.com, 8443, psk=ChangedPskChangedPsk1234567890ab, version=5") || strings.Contains(after, sc.snell5.Password) {
		t.Fatalf("subscription did not follow the node:\n%s", after)
	}
	// Renaming the node renames it in the list; membership and order stay.
	s, _ = sc.a.Load()
	renamed := moved
	renamed.Name = "Osaka-Snell"
	if e = sc.a.Commit(s, replace(s, renamed), false); e != nil {
		t.Fatal(e)
	}
	if got := fetch(); !strings.HasPrefix(got, "Osaka-Snell = snell, ") || !strings.Contains(got, "Tokyo-Snell6 = snell,") {
		t.Fatalf("rename:\n%s", got)
	}
	s, _ = sc.a.Load()
	if len(s.Subscriptions) != 1 || len(s.Subscriptions[0].NodeIDs) != 2 || s.Subscriptions[0].ID != sub.ID {
		t.Fatalf("subscription membership changed: %+v", s.Subscriptions)
	}

	// Disabled nodes are skipped; a deleted node leaves the subscription.
	s, _ = sc.a.Load()
	off := renamed
	off.Enabled = false
	if e = sc.a.Commit(s, replace(s, off), false); e != nil {
		t.Fatal(e)
	}
	if got := fetch(); strings.Contains(got, "Osaka-Snell") || !strings.Contains(got, "Tokyo-Snell6") {
		t.Fatalf("disabled node:\n%s", got)
	}
	s, _ = sc.a.Load()
	if e = sc.a.Commit(s, removeProfile(s, sc.snell6.ID), false); e != nil {
		t.Fatal(e)
	}
	if w := get(h, "GET", "/s/"+token+"?format=surge"); w.Code != 503 {
		t.Fatalf("nothing left to serve: %d %s", w.Code, w.Body.String())
	}
	s, _ = sc.a.Load()
	if ids := s.Subscriptions[0].NodeIDs; len(ids) != 1 || ids[0] != sc.snell5.ID {
		t.Fatalf("deleted node still referenced: %v", ids)
	}
}

func TestSnellSubscriptionLineSyntaxAndIPv6(t *testing.T) {
	sc := newSnellSubScene(t)
	v6 := sc.snell6
	v6.Listen, v6.InboundMode, v6.PublicHost = "::", inDual, "2001:db8::7"
	dupe := sc.snell5
	dupe.Name = "Tokyo-Snell6" // collides with the other node's name after sanitising
	st := State{Schema: 1, Profiles: []Profile{v6, dupe}}
	lines, warnings := st.exportSurge(Subscription{NodeIDs: []string{v6.ID, dupe.ID}})
	if len(warnings) != 0 || len(lines) != 2 {
		t.Fatalf("%v %v", lines, warnings)
	}
	if !strings.Contains(lines[0], ", 2001:db8::7, ") || strings.Contains(lines[0], "[") {
		t.Errorf("IPv6 literal must be bare: %q", lines[0])
	}
	name := func(l string) string { return l[:strings.Index(l, " = ")] }
	if name(lines[0]) == name(lines[1]) {
		t.Errorf("duplicate policy names in one Surge list: %q %q", lines[0], lines[1])
	}
	pattern := regexp.MustCompile(`^[^=,]+ = snell, [^, ]+, [0-9]+, psk=[A-Za-z0-9._~+-]{12,255}, version=[56]$`)
	for _, l := range lines {
		if !pattern.MatchString(l) {
			t.Errorf("not a Surge snell line: %q", l)
		}
	}
	// A subscription that references a node that is gone says so instead of failing.
	_, warnings = st.exportSurge(Subscription{NodeIDs: []string{"ffffffffffff"}})
	if len(warnings) != 1 {
		t.Errorf("warnings %v", warnings)
	}
}

// ---- interactive flows ----------------------------------------------------------------------

func TestSnellCreateFlowPrintsSurgeConfigAndKeepsEveryOtherProtocolWorking(t *testing.T) {
	a := relayTestApp(t, snellSetup())
	u, out := testUI(a, "Tokyo\n6 7 3\n\n")
	if e := u.create(); e != nil {
		t.Fatal(e, out.String())
	}
	s, _ := a.Load()
	if len(s.Profiles) != 3 {
		t.Fatalf("%d nodes created\n%s", len(s.Profiles), out.String())
	}
	byName := map[string]Profile{}
	for _, p := range s.Profiles {
		byName[p.Name] = p
	}
	v5, v6, ss := byName["Tokyo-Snell"], byName["Tokyo-Snell6"], byName["Tokyo-SS"]
	if v5.snellVersion() != snellV5 || v6.snellVersion() != snellV6 || ss.Protocol != "ss" {
		t.Fatalf("created: %v", byName)
	}
	if v5.Port == v6.Port || v5.Port == ss.Port || v6.Port == ss.Port {
		t.Fatal("ports collide")
	}
	if len(v5.Password) != 32 || len(v6.Password) != 32 || v5.Password == v6.Password {
		t.Fatalf("PSKs: %q %q", v5.Password, v6.Password)
	}
	for _, p := range []Profile{v5, v6} {
		line, _ := p.Share()
		if !strings.Contains(out.String(), line) {
			t.Errorf("the Surge configuration of %s was not printed:\n%s", p.Name, out.String())
		}
		if !strings.Contains(out.String(), "[Proxy]") {
			t.Error("no instruction about where the line goes")
		}
		if e := checkSnellConf(filepath.Join(a.profileDir(p.ID), snellConf), p); e != nil {
			t.Error(e)
		}
	}
	if !strings.Contains(out.String(), "ss://") {
		t.Error("the Shadowsocks link is gone")
	}
	if !strings.Contains(out.String(), "Snell v5") || !strings.Contains(out.String(), "Snell v6 (beta)") {
		t.Errorf("menu does not name the versions:\n%s", out.String())
	}
}

func TestSnellCreateFlowManualPortAndName(t *testing.T) {
	a := relayTestApp(t, snellSetup())
	port, e := freePort()
	if e != nil {
		t.Fatal(e)
	}
	u, out := testUI(a, "Osaka Home\n6\n2\n"+itoa(port)+"\n\n")
	if e = u.create(); e != nil {
		t.Fatal(e, out.String())
	}
	s, _ := a.Load()
	if len(s.Profiles) != 1 || s.Profiles[0].Port != port || s.Profiles[0].PublicPort != port || s.Profiles[0].Name != "Osaka Home-Snell" {
		t.Fatalf("%+v\n%s", s.Profiles, out.String())
	}
	if !strings.Contains(out.String(), "Osaka Home-Snell = snell, "+v4Addr+", "+itoa(port)+", psk=") {
		t.Errorf("Surge line:\n%s", out.String())
	}
	// A port someone else holds is refused and asked for again.
	a2 := relayTestApp(t, snellSetup())
	taken := aiTestNode(t, a2, "ss", "taken")
	free, _ := freePort()
	u, out = testUI(a2, "N\n6\n2\n"+itoa(taken.Port)+"\n"+itoa(free)+"\n\n")
	if e = u.create(); e != nil {
		t.Fatal(e, out.String())
	}
	s, _ = a2.Load()
	var got Profile
	for _, p := range s.Profiles {
		if p.snellNode() {
			got = p
		}
	}
	if got.Port != free || !strings.Contains(out.String(), "same") {
		t.Fatalf("port conflict not handled: port %d\n%s", got.Port, out.String())
	}
}

func TestSnellCreateFlowDoesNotBindAnOutboundProxy(t *testing.T) {
	a := relayTestApp(t, snellSetup())
	ex := aiTestExit(t, a, "corp", "198.51.100.9", 1080)
	// With an exit available the menu asks which outbound the batch uses (1 = the first choice).
	u, out := testUI(a, "Mix\n6 3\n1\n\n")
	u.probeProxy = func(Proxy) (string, error) { return "198.51.100.9", nil }
	if e := u.create(); e != nil {
		t.Fatal(e, out.String())
	}
	s, _ := a.Load()
	for _, p := range s.Profiles {
		switch {
		case p.snellNode() && (p.ExitID != "" || p.Outbound != nil):
			t.Fatalf("Snell node bound to %s", ex.Name)
		}
	}
	if !strings.Contains(out.String(), "direct") {
		t.Errorf("no note that the Snell node connects directly:\n%s", out.String())
	}
}

func TestSnellNodeMenuOffersOnlyWhatApplies(t *testing.T) {
	a := testApp(t)
	snell := aiTestNode(t, a, "snell", "snell")
	ss := aiTestNode(t, a, "ss", "ss")
	menu := func(p Profile) string {
		u, out := testUI(a, "0\n")
		if e := u.nodeMenu(p.ID); e != nil {
			t.Fatal(e)
		}
		return out.String()
	}
	got, other := menu(snell), menu(ss)
	if !strings.Contains(got, "Change listen address") || !strings.Contains(got, "Set PSK") || strings.Contains(got, "outbound proxy") && strings.Contains(got, "Choose outbound") {
		t.Errorf("Snell menu:\n%s", got)
	}
	if strings.Contains(other, "Set PSK") || strings.Contains(other, "listen address") {
		t.Errorf("Snell entries leaked into another protocol's menu:\n%s", other)
	}
}

func TestSnellEditPSKAndListenAddress(t *testing.T) {
	a := testApp(t)
	p := aiTestNode(t, a, "snell6", "snell")
	other := aiTestNode(t, a, "snell", "other")
	otherConf, _ := os.ReadFile(filepath.Join(a.profileDir(other.ID), snellConf))
	apply := func(input, action string) (Profile, string, error) {
		u, out := testUI(a, input)
		s, _ := a.Load()
		cur, _ := Find(s, p.ID)
		e := u.nodeAction(s, cur, action)
		s, _ = a.Load()
		cur, _ = Find(s, p.ID)
		return cur, out.String(), e
	}

	got, out, e := apply("BrandNewPsk-123456\n", "psk")
	if e != nil || got.Password != "BrandNewPsk-123456" || !strings.Contains(out, "psk=BrandNewPsk-123456") {
		t.Fatalf("custom PSK: %v %q\n%s", e, got.Password, out)
	}
	if conf, _ := os.ReadFile(filepath.Join(a.profileDir(p.ID), snellConf)); !strings.Contains(string(conf), "psk = BrandNewPsk-123456\n") {
		t.Fatalf("PSK not written:\n%s", conf)
	}
	// A bad PSK changes nothing.
	for _, bad := range []string{"short\n", "has spaces in the key\n", "comma,comma,comma,\n"} {
		before := got.Password
		got, _, e = apply(bad, "psk")
		if e == nil || got.Password != before {
			t.Errorf("bad PSK %q: %v / %q", bad, e, got.Password)
		}
	}
	// Leaving the prompt empty cancels.
	before := got.Password
	if got, _, e = apply("\n", "psk"); e != nil || got.Password != before {
		t.Errorf("empty PSK: %v %q", e, got.Password)
	}
	// Resetting credentials makes a new random PSK and keeps the version.
	got, _, e = apply("y\n", "credentials")
	if e != nil || got.Password == before || len(got.Password) != 32 || got.snellVersion() != snellV6 {
		t.Fatalf("reset: %v %+v", e, got)
	}

	// Listen on every IPv4 address, then on one address of this host.
	got, out, e = apply("1\n", "listen")
	if e != nil || got.Listen != "0.0.0.0" || got.InboundMode != inIPv4 {
		t.Fatalf("listen 0.0.0.0: %v %+v\n%s", e, got, out)
	}
	if conf, _ := os.ReadFile(filepath.Join(a.profileDir(p.ID), snellConf)); !strings.Contains(string(conf), "listen = 0.0.0.0:"+itoa(p.Port)+"\n") {
		t.Fatalf("listen not written:\n%s", conf)
	}
	got, out, e = apply("2\n192.0.2.77\n127.0.0.1\n", "listen")
	if e != nil || got.Listen != "127.0.0.1" || !strings.Contains(out, "not an address") {
		t.Fatalf("specific address: %v %+v\n%s", e, got, out)
	}
	// Nothing here touched the other instance.
	if conf, _ := os.ReadFile(filepath.Join(a.profileDir(other.ID), snellConf)); string(conf) != string(otherConf) {
		t.Fatal("another Snell instance changed")
	}
}

// ---- web API --------------------------------------------------------------------------------

func TestWebSnellCreateLinkAndRules(t *testing.T) {
	withHostRoutes(t, dualRoutes())
	e := newWebEnv(t)
	c := e.login()
	c.reauth()

	w := c.do("POST", "/api/nodes", map[string]any{"base_name": "Web", "protocols": []string{"snell", "snell6"}, "inbound": "dual"})
	mustOK(t, w.Code, w.Body.String())
	nodes := listOf(t, jsonOf(t, w), "nodes")
	if len(nodes) != 2 {
		t.Fatalf("nodes: %v", nodes)
	}
	labels := map[string]string{}
	for _, n := range nodes {
		labels[n["name"].(string)] = n["label"].(string)
		if n["protocol"] != "snell" || n["has_link"] != true || n["inbound"] != "dual" || n["listen"] != "::" {
			t.Errorf("view: %v", n)
		}
		if strings.Contains(strings.ToLower(w.Body.String()), "psk") {
			t.Error("the panel's node list exposes a PSK")
		}
	}
	if labels["Web-Snell"] != "Snell" || labels["Web-Snell6"] != "Snell6" {
		t.Errorf("labels: %v", labels)
	}
	// The protocol list the panel offers names both versions.
	list := jsonOf(t, c.get("/api/nodes"))
	var offered []string
	for _, p := range listOf(t, list, "protocols") {
		offered = append(offered, p["id"].(string))
	}
	if !contains(offered, "snell") || !contains(offered, "snell6") || len(offered) != 7 {
		t.Errorf("offered protocols %v", offered)
	}
	for _, p := range listOf(t, list, "protocols") {
		if strings.HasPrefix(p["id"].(string), "snell") && (len(p["networks"].([]any)) != 1 || p["networks"].([]any)[0] != "tcp") {
			t.Errorf("networks %v", p)
		}
	}

	// The link endpoint returns the Surge line and says what it is.
	id := nodes[0]["id"].(string)
	lw := c.get("/api/nodes/" + id + "/link")
	mustOK(t, lw.Code, lw.Body.String())
	link := jsonOf(t, lw)
	if link["format"] != "surge" || !strings.Contains(link["link"].(string), " = snell, ") || !strings.Contains(link["link"].(string), "psk=") {
		t.Errorf("link: %v", link)
	}
	// Other protocols answer exactly as before.
	ow := c.do("POST", "/api/nodes", map[string]any{"base_name": "Web", "protocols": []string{"ss"}, "inbound": "dual"})
	mustOK(t, ow.Code, ow.Body.String())
	for _, n := range listOf(t, jsonOf(t, ow), "nodes") {
		if n["protocol"] == "ss" {
			lw = c.get("/api/nodes/" + n["id"].(string) + "/link")
			if m := jsonOf(t, lw); m["format"] != nil || !strings.HasPrefix(m["link"].(string), "ss://") {
				t.Errorf("ss link: %v", m)
			}
		}
	}

	// Rules: no IPv6-only listener, no outbound proxy, policies the engine can express.
	if w = c.do("POST", "/api/nodes", map[string]any{"base_name": "V6", "protocols": []string{"snell"}, "inbound": "ipv6"}); w.Code != 400 {
		t.Errorf("IPv6-only Snell on a dual-stack host: %d %s", w.Code, w.Body.String())
	}
	ex := c.do("POST", "/api/exits", map[string]any{"name": "corp", "protocol": "socks5", "host": "198.51.100.9", "port": 1080, "username": "u", "password": "p"})
	mustOK(t, ex.Code, ex.Body.String())
	exitID := jsonOf(t, ex)["exit"].(map[string]any)["id"].(string)
	if w = c.do("POST", "/api/nodes", map[string]any{"base_name": "X", "protocols": []string{"snell6"}, "exit_id": exitID}); w.Code != 400 {
		t.Errorf("Snell with an exit: %d %s", w.Code, w.Body.String())
	}
	if w = c.do("POST", "/api/nodes", map[string]any{"base_name": "P", "protocols": []string{"snell"}, "inbound": "ipv4", "outbound_policy": "ipv6_first"}); w.Code != 400 {
		t.Errorf("v5 with a policy its engine cannot express: %d %s", w.Code, w.Body.String())
	}
	if w = c.do("POST", "/api/nodes", map[string]any{"base_name": "P", "protocols": []string{"snell6"}, "inbound": "ipv4", "outbound_policy": "ipv6_first"}); w.Code != 200 {
		t.Errorf("v6 with ipv6_first: %d %s", w.Code, w.Body.String())
	}
	// Restart and delete work like any node.
	if w = c.do("POST", "/api/nodes/"+id+"/restart", nil); w.Code != 200 {
		t.Errorf("restart: %d %s", w.Code, w.Body.String())
	}
	if w = c.do("DELETE", "/api/nodes/"+id, nil); w.Code != 200 {
		t.Errorf("delete: %d %s", w.Code, w.Body.String())
	}
	if _, er := os.Stat(e.a.profileDir(id)); er == nil {
		t.Error("deleted node left its directory")
	}
}

var _ = httptest.NewRecorder

func TestWebSnellOutboundPolicyFollowsTheEngine(t *testing.T) {
	withHostRoutes(t, dualRoutes())
	e := newWebEnv(t)
	c := e.login()
	w := c.do("POST", "/api/nodes", map[string]any{"base_name": "Pol", "protocols": []string{"snell", "snell6"}, "inbound": "ipv4"})
	mustOK(t, w.Code, w.Body.String())
	ids := map[string]string{}
	for _, n := range listOf(t, jsonOf(t, w), "nodes") {
		ids[n["label"].(string)] = n["id"].(string)
	}
	conf := func(label string) string {
		b, er := os.ReadFile(filepath.Join(e.a.profileDir(ids[label]), snellConf))
		if er != nil {
			t.Fatal(er)
		}
		return string(b)
	}
	put := func(label, policy string) *httptest.ResponseRecorder {
		return c.do("PUT", "/api/nodes/"+ids[label]+"/outbound-policy", map[string]any{"policy": policy})
	}
	// v6 expresses every policy; the view never claims Snell enforces it.
	for policy, want := range map[string]string{"ipv6_first": "prefer-ipv6", "ipv4_only": "ipv4-only", "ipv6_only": "ipv6-only", "ipv4_first": "prefer-ipv4", "auto": "default"} {
		w = put("Snell6", policy)
		mustOK(t, w.Code, w.Body.String())
		n := listOf(t, jsonOf(t, w), "nodes")[0]
		if n["outbound_policy"] != policy || n["outbound_enforced"] != false {
			t.Fatalf("%s: view %v", policy, n)
		}
		if !strings.Contains(conf("Snell6"), "dns-ip-preference = "+want+"\n") {
			t.Fatalf("%s: configuration\n%s", policy, conf("Snell6"))
		}
	}
	// v5 has one switch: IPv6 on or off.
	mustOK(t, put("Snell", "ipv4_only").Code, "v5 ipv4_only")
	if !strings.Contains(conf("Snell"), "ipv6 = false\n") {
		t.Fatalf("v5 IPv4 only:\n%s", conf("Snell"))
	}
	for _, policy := range []string{"ipv6_first", "ipv6_only", "ipv4_first"} {
		before := conf("Snell")
		if w = put("Snell", policy); w.Code != 400 || conf("Snell") != before {
			t.Errorf("v5 %s: %d %s", policy, w.Code, w.Body.String())
		}
	}
	mustOK(t, put("Snell", "auto").Code, "v5 auto")
	if !strings.Contains(conf("Snell"), "ipv6 = true\n") {
		t.Fatalf("v5 auto:\n%s", conf("Snell"))
	}
	// There is no Snell client to measure the egress with: refused, not faked.
	if w = c.do("POST", "/api/nodes/"+ids["Snell"]+"/egress-test", map[string]any{"quick": true}); w.Code == 200 {
		t.Errorf("an egress test claimed to run through Snell: %s", w.Body.String())
	}
}

// An aggregate subscription (local nodes mixed with third-party ones) accepts Snell nodes like
// a plain one does, and its Surge, Base64 and Mihomo outputs each carry what their client can.
func TestSnellInAnAggregateSubscription(t *testing.T) {
	sc := newAggScene(t)
	snell := aiTestNode(t, sc.a, "snell", "Agg-Snell")
	snell6 := aiTestNode(t, sc.a, "snell6", "Agg-Snell6")
	items := []SubItem{
		{Kind: itemLocal, NodeID: snell.ID},
		sc.rnode(t, sc.links, "HK Reality"),
		sc.local(0),
		{Kind: itemLocal, NodeID: snell6.ID},
	}
	sub, token, e := sc.a.CreateAggregateSubscription("Mixed with Snell", AggregateSpec{Items: items})
	if e != nil {
		t.Fatalf("Snell cannot join an aggregate subscription: %v", e)
	}
	h := sc.server()
	code, body := sc.fetchFormat(t, h, token, "surge")
	want5, _ := snell.Share()
	want6, _ := snell6.Share()
	if code != 200 || strings.TrimSpace(body) != want5+"\n"+want6 {
		t.Fatalf("Surge list of an aggregate: %d\n%s", code, body)
	}
	// Base64 keeps its own nodes and never carries Snell.
	code, body = sc.fetchFormat(t, h, token, "")
	if code != 200 {
		t.Fatal(code, body)
	}
	for _, l := range decodeBody(t, body) {
		if strings.Contains(l, snell.Password) || strings.Contains(l, snell6.Password) {
			t.Fatalf("a Snell PSK reached the Base64 list: %q", l)
		}
	}
	// Editing the aggregate to add or drop a Snell node works too.
	if e = sc.a.SetSubscriptionItems(sub.ID, AggregateSpec{Items: items[:3]}); e != nil {
		t.Fatalf("update: %v", e)
	}
	if code, body = sc.fetchFormat(t, h, token, "surge"); code != 200 || strings.TrimSpace(body) != want5 {
		t.Fatalf("after the update: %d\n%s", code, body)
	}
}
