package rout

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/VAR7IANT/Rout/internal/remote"
	"gopkg.in/yaml.v3"
)

// aggScene has two local nodes (alpha vless, bravo ss) and two sources: one that lists share
// links and one that serves a Clash file.
type aggScene struct {
	*subScene
	links, clash       RemoteSource
	linksSnap, clashSn *RemoteSnapshot
	fsLinks, fsClash   *fakeSource
}

func newAggScene(t *testing.T) *aggScene {
	t.Helper()
	sc := &aggScene{subScene: newSubScene(t)}
	sc.fsLinks = &fakeSource{body: linkList(linkVless, linkTrojan, linkHy2, linkSS, linkSSPlug, linkInsec)}
	sc.fsClash = &fakeSource{body: clashFixture}
	sc.a.remoteFetch = func(ctx context.Context, rawURL string, opt remote.FetchOptions) (*remote.Result, error) {
		if strings.Contains(rawURL, "clash") {
			return sc.fsClash.fetch(ctx, rawURL, opt)
		}
		return sc.fsLinks.fetch(ctx, rawURL, opt)
	}
	var e error
	if sc.links, e = sc.a.AddRemoteSource(RemoteSourceSpec{Name: "Links", URL: "https://links.provider.test/s?t=1", Enabled: true, IntervalMin: 60}); e != nil {
		t.Fatal(e)
	}
	if sc.clash, e = sc.a.AddRemoteSource(RemoteSourceSpec{Name: "Clash", URL: "https://clash.provider.test/s?t=2", Enabled: true, IntervalMin: 60}); e != nil {
		t.Fatal(e)
	}
	for _, id := range []string{sc.links.ID, sc.clash.ID} {
		if _, e = sc.a.RefreshRemoteSource(context.Background(), id); e != nil {
			t.Fatal(e)
		}
	}
	sc.linksSnap, sc.clashSn = snapshotOf(t, sc.a, sc.links.ID), snapshotOf(t, sc.a, sc.clash.ID)
	return sc
}

// rnode finds an imported node by its original name.
func (sc *aggScene) rnode(t *testing.T, src RemoteSource, name string) SubItem {
	t.Helper()
	snap := sc.linksSnap
	if src.ID == sc.clash.ID {
		snap = sc.clashSn
	}
	for _, n := range snap.Nodes {
		if n.Name == name {
			return SubItem{Kind: itemRemote, SourceID: src.ID, RemoteID: n.ID}
		}
	}
	t.Fatalf("no imported node %q in %s", name, src.Name)
	return SubItem{}
}
func (sc *aggScene) local(i int) SubItem { return SubItem{Kind: itemLocal, NodeID: sc.nodes[i].ID} }

func (sc *aggScene) server() *subscriptionHandler {
	h := newSubscriptionHandler((&stateCache{a: sc.a}).load, func(string, ...any) {})
	h.remote = newRemoteCache(sc.a).lookup
	return h
}

func (sc *aggScene) fetchFormat(t *testing.T, h *subscriptionHandler, token, format string) (int, string) {
	t.Helper()
	path := "/s/" + token
	if format != "" {
		path += "?format=" + format
	}
	w := get(h, "GET", path)
	return w.Code, w.Body.String()
}

type mihomoDoc struct {
	Proxies []map[string]any `yaml:"proxies"`
	Groups  []map[string]any `yaml:"proxy-groups"`
}

func parseMihomoDoc(t *testing.T, body string) mihomoDoc {
	t.Helper()
	var doc mihomoDoc
	if e := yaml.Unmarshal([]byte(body), &doc); e != nil {
		t.Fatalf("Mihomo output is not valid YAML: %v\n%s", e, body)
	}
	return doc
}

func proxyNamed(t *testing.T, doc mihomoDoc, name string) map[string]any {
	t.Helper()
	for _, p := range doc.Proxies {
		if p["name"] == name {
			return p
		}
	}
	t.Fatalf("no proxy %q in %v", name, names(doc))
	return nil
}
func names(doc mihomoDoc) []string {
	var out []string
	for _, p := range doc.Proxies {
		out = append(out, p["name"].(string))
	}
	return out
}

func TestAggregateBase64KeepsOrderNamesAndEveryParameter(t *testing.T) {
	sc := newAggScene(t)
	items := []SubItem{sc.local(0), sc.rnode(t, sc.links, "HK Reality"), sc.rnode(t, sc.clash, "🇭🇰 Clash VLESS WS"), sc.local(1), sc.rnode(t, sc.links, "SG HY2"), sc.rnode(t, sc.links, "JP Trojan")}
	_, token, e := sc.a.CreateAggregateSubscription("Mixed", AggregateSpec{Items: items})
	if e != nil {
		t.Fatal(e)
	}
	code, body := sc.fetchFormat(t, sc.server(), token, "")
	if code != 200 {
		t.Fatal(code, body)
	}
	lines := decodeBody(t, body)
	if len(lines) != 6 {
		t.Fatalf("%d lines: %v", len(lines), lines)
	}
	local0, _ := sc.nodes[0].URI()
	local1, _ := sc.nodes[1].URI()
	if lines[0] != local0 || lines[3] != local1 {
		t.Fatal("local nodes are not exported byte-identically to the single-node links")
	}
	// A node whose name did not change is the provider's link, byte for byte.
	if lines[1] != linkVless || lines[4] != linkHy2 || lines[5] != linkTrojan {
		t.Fatalf("imported links changed:\n%s\n%s\n%s", lines[1], lines[4], lines[5])
	}
	// Re-parse everything with the importer: protocol, credentials and TLS/Reality settings.
	parsed, e := remote.ParseLinks(strings.Join(lines, "\n"))
	if e != nil || len(parsed.Nodes) != 6 || len(parsed.Issues) != 0 {
		t.Fatalf("re-parse: %v %+v", e, parsed.Issues)
	}
	byName := map[string]remote.Node{}
	for _, n := range parsed.Nodes {
		byName[n.Name] = n
	}
	for name, want := range map[string]string{"HK Reality": "reality", "JP Trojan": "tls", "SG HY2": "tls"} {
		if got := byName[name].Security; got != want {
			t.Errorf("%s security %q, want %q", name, got, want)
		}
	}
	if !strings.Contains(byName["HK Reality"].Link, "pbk="+pbk) || !strings.Contains(byName["HK Reality"].Link, "sid=0123abcd") || !strings.Contains(byName["HK Reality"].Link, "flow=xtls-rprx-vision") {
		t.Errorf("Reality parameters lost: %s", byName["HK Reality"].Link)
	}
	if got := byName["🇭🇰 Clash VLESS WS"]; got.Transport != "ws" || got.SNI != "cdn.example.net" || !strings.Contains(got.Link, "alpn=") || !strings.Contains(got.Link, "fp=chrome") {
		t.Errorf("Clash-origin node lost parameters: %+v", got)
	}
}

func TestAggregateMihomoOutputIsRealYAMLWithFaithfulProxies(t *testing.T) {
	sc := newAggScene(t)
	items := []SubItem{sc.local(0), sc.rnode(t, sc.links, "HK Reality"), sc.rnode(t, sc.clash, "🇭🇰 Clash VLESS WS"), sc.rnode(t, sc.links, "SG HY2"), sc.rnode(t, sc.links, "JP Trojan"), sc.rnode(t, sc.links, "US SS"), sc.rnode(t, sc.clash, "Clash SS")}
	_, token, e := sc.a.CreateAggregateSubscription("Mixed", AggregateSpec{Items: items})
	if e != nil {
		t.Fatal(e)
	}
	code, body := sc.fetchFormat(t, sc.server(), token, "mihomo")
	if code != 200 {
		t.Fatal(code, body)
	}
	doc := parseMihomoDoc(t, body)
	if got := names(doc); len(got) != 7 || got[0] != "alpha" || got[1] != "HK Reality" || got[2] != "🇭🇰 Clash VLESS WS" || got[6] != "Clash SS" {
		t.Fatalf("order/names: %v", got)
	}
	reality := proxyNamed(t, doc, "HK Reality")
	ro, _ := reality["reality-opts"].(map[string]any)
	if reality["type"] != "vless" || reality["flow"] != "xtls-rprx-vision" || reality["servername"] != "www.example.org" ||
		reality["client-fingerprint"] != "chrome" || ro["public-key"] != pbk || ro["short-id"] != "0123abcd" || reality["server"] != "198.51.100.10" {
		t.Fatalf("Reality proxy: %v", reality)
	}
	ws := proxyNamed(t, doc, "🇭🇰 Clash VLESS WS")
	wo, _ := ws["ws-opts"].(map[string]any)
	if ws["network"] != "ws" || wo["path"] != "/vl" || ws["servername"] != "cdn.example.net" || ws["client-fingerprint"] != "chrome" || ws["uuid"] != "22222222-2222-4222-8222-222222222222" {
		t.Fatalf("Clash passthrough proxy: %v", ws)
	}
	hy := proxyNamed(t, doc, "SG HY2")
	if hy["type"] != "hysteria2" || hy["obfs"] != "salamander" || hy["obfs-password"] != "xyz" || hy["sni"] != "h.example.net" || hy["password"] != "hy2pw" {
		t.Fatalf("HY2 proxy: %v", hy)
	}
	tr := proxyNamed(t, doc, "JP Trojan")
	two, _ := tr["ws-opts"].(map[string]any)
	if tr["network"] != "ws" || two["path"] != "/ws" || tr["sni"] != "t.example.net" || tr["password"] != "trojanpw" {
		t.Fatalf("Trojan proxy: %v", tr)
	}
	if ss := proxyNamed(t, doc, "US SS"); ss["cipher"] != "aes-256-gcm" || ss["password"] != "pass" || ss["type"] != "ss" {
		t.Fatalf("SS proxy: %v", ss)
	}
	// Rout's own importer reads the exported file back to the same set of nodes.
	back, e := remote.Parse([]byte(body))
	if e != nil || len(back.Nodes) != 7 {
		t.Fatalf("Rout cannot re-import its own Mihomo output: %v (%d nodes) %+v", e, len(back.Nodes), back.Issues)
	}
	// Every group lists only real proxy names.
	valid := map[string]bool{"DIRECT": true}
	for _, n := range names(doc) {
		valid[n] = true
	}
	for _, g := range doc.Groups {
		for _, m := range g["proxies"].([]any) {
			if !valid[m.(string)] && m != mihomoAutoGroup && m != mihomoFallbackGroup {
				t.Errorf("group %v references %v", g["name"], m)
			}
		}
	}
}

func TestAggregateUnverifiedTLSIsRefusedUnlessAllowed(t *testing.T) {
	sc := newAggScene(t)
	items := []SubItem{sc.local(0), sc.rnode(t, sc.links, "Insecure Trojan"), sc.rnode(t, sc.clash, "Clash Hy2 Insecure")}
	sub, token, e := sc.a.CreateAggregateSubscription("Insecure", AggregateSpec{Items: items})
	if e != nil {
		t.Fatal(e)
	}
	h := sc.server()
	_, body := sc.fetchFormat(t, h, token, "mihomo")
	if got := names(parseMihomoDoc(t, body)); len(got) != 1 || got[0] != "alpha" {
		t.Fatalf("unverified-TLS nodes exported by default: %v", got)
	}
	if !strings.Contains(body, "cannot") && !strings.Contains(body, "无法生成") && !strings.Contains(body, "diagnostic") {
		t.Errorf("no diagnostic for the omitted nodes:\n%s", body)
	}
	// The same policy applies to Base64: unverified-TLS links are withheld by default.
	_, b64 := sc.fetchFormat(t, h, token, "")
	if lines := decodeBody(t, b64); len(lines) != 1 || strings.Contains(strings.Join(lines, "\n"), "nsecure=1") {
		t.Fatalf("Base64 exported unverified-TLS links by default: %v", lines)
	}
	// Explicit opt-in exports them with the setting the provider chose.
	if e = sc.a.SetSubscriptionItems(sub.ID, AggregateSpec{Items: items, AllowInsecure: true}); e != nil {
		t.Fatal(e)
	}
	_, b64 = sc.fetchFormat(t, h, token, "")
	if joined := strings.Join(decodeBody(t, b64), "\n"); !strings.Contains(joined, "allowInsecure=1") {
		t.Fatalf("opt-in Base64 lost the provider's link: %s", joined)
	}
	_, body = sc.fetchFormat(t, h, token, "mihomo")
	doc := parseMihomoDoc(t, body)
	if len(doc.Proxies) != 3 {
		t.Fatalf("after opt-in: %v", names(doc))
	}
	for _, n := range []string{"Insecure Trojan", "Clash Hy2 Insecure"} {
		if proxyNamed(t, doc, n)["skip-cert-verify"] != true {
			t.Errorf("%s lost its explicit skip-cert-verify", n)
		}
	}
}

func TestAggregateCompatibilityReport(t *testing.T) {
	sc := newAggScene(t)
	items := []SubItem{sc.rnode(t, sc.links, "SS Plugin"), sc.rnode(t, sc.links, "HK Reality"), sc.local(0)}
	_, _, e := sc.a.CreateAggregateSubscription("Report", AggregateSpec{Items: items})
	if e != nil {
		t.Fatal(e)
	}
	st := sc.state(t)
	exp := sc.a.ExportAggregate(st, st.Subscriptions[0])
	if len(exp.Nodes) != 3 {
		t.Fatal(len(exp.Nodes))
	}
	plug := exp.Nodes[0]
	if !plug.Base64OK || plug.MihomoOK || plug.MihomoWhy == "" || len(plug.Notes) == 0 {
		t.Fatalf("a Shadowsocks plugin node must be Base64-only with a reason: %+v", plug)
	}
	if !strings.Contains(plug.Notes[0], "plugin") && !strings.Contains(plug.Notes[0], "插件") {
		t.Errorf("note: %v", plug.Notes)
	}
	if !exp.Nodes[1].Base64OK || !exp.Nodes[1].MihomoOK || !exp.Nodes[2].Base64OK || !exp.Nodes[2].MihomoOK {
		t.Fatalf("%+v", exp.Nodes)
	}
	if len(exp.URIs) != 3 || len(exp.Proxies) != 2 {
		t.Fatalf("uris=%d proxies=%d", len(exp.URIs), len(exp.Proxies))
	}
	for _, w := range exp.Warnings {
		for _, secret := range []string{"obfs-local", "SS Plugin", "YWVzLTI1Ni1nY206cGFzcw", "pass"} {
			if strings.Contains(w, secret) && secret != "pass" {
				t.Errorf("warning leaks %q: %s", secret, w)
			}
		}
	}
}

func TestAggregateRenameDuplicateNamesAndDedupe(t *testing.T) {
	sc := newAggScene(t)
	dupe := linkVless // the same endpoint and account under another name
	other := &fakeSource{body: linkList(dupe, strings.Replace(linkTrojan, "JP%20Trojan", "HK%20Reality", 1))}
	sc.a.remoteFetch = other.fetch
	src2, e := sc.a.AddRemoteSource(RemoteSourceSpec{Name: "Second", URL: "https://second.provider.test/s", Enabled: true})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = sc.a.RefreshRemoteSource(context.Background(), src2.ID); e != nil {
		t.Fatal(e)
	}
	snap2 := snapshotOf(t, sc.a, src2.ID)
	if len(snap2.Nodes) != 2 {
		t.Fatalf("second source: %d nodes", len(snap2.Nodes))
	}
	same := SubItem{Kind: itemRemote, SourceID: src2.ID, RemoteID: snap2.Nodes[0].ID}
	namesake := SubItem{Kind: itemRemote, SourceID: src2.ID, RemoteID: snap2.Nodes[1].ID}
	first := sc.rnode(t, sc.links, "HK Reality")
	renamed := sc.rnode(t, sc.links, "SG HY2")
	renamed.Name = "🔥 Fast"
	items := []SubItem{first, same, namesake, renamed}

	_, token, e := sc.a.CreateAggregateSubscription("Names", AggregateSpec{Items: items})
	if e != nil {
		t.Fatal(e)
	}
	h := sc.server()
	// Without dedupe all four are exported; the three called "HK Reality" get unique names.
	_, body := sc.fetchFormat(t, h, token, "mihomo")
	doc := parseMihomoDoc(t, body)
	got := names(doc)
	seen := map[string]bool{}
	for _, n := range got {
		if seen[n] {
			t.Fatalf("duplicate proxy name %q in %v", n, got)
		}
		seen[n] = true
	}
	if len(got) != 4 || got[3] != "🔥 Fast" || !strings.HasPrefix(got[0], "HK Reality [") {
		t.Fatalf("%v", got)
	}
	if proxyNamed(t, doc, "🔥 Fast")["type"] != "hysteria2" {
		t.Fatal("rename changed the wrong node")
	}
	// Dedupe removes the repeated endpoint, keeping the first occurrence and the order.
	st := sc.state(t)
	if e = sc.a.SetSubscriptionItems(st.Subscriptions[0].ID, AggregateSpec{Items: items, Dedupe: true}); e != nil {
		t.Fatal(e)
	}
	_, body = sc.fetchFormat(t, h, token, "mihomo")
	if got = names(parseMihomoDoc(t, body)); len(got) != 3 {
		t.Fatalf("dedupe: %v", got)
	}
	st = sc.state(t)
	exp := sc.a.ExportAggregate(st, st.Subscriptions[0])
	if exp.Nodes[1].Skipped == "" || exp.Nodes[1].DuplicateOf != 1 {
		t.Fatalf("the duplicate is not reported: %+v", exp.Nodes[1])
	}
	// The sources themselves are untouched by all of this.
	if after := snapshotOf(t, sc.a, sc.links.ID); len(after.Nodes) != len(sc.linksSnap.Nodes) || after.Nodes[0].Name != sc.linksSnap.Nodes[0].Name {
		t.Fatal("aggregation modified the source")
	}
	// A name equal to a Mihomo reserved word or group name never reaches the output as is.
	items[3].Name = "DIRECT"
	if e = sc.a.SetSubscriptionItems(st.Subscriptions[0].ID, AggregateSpec{Items: items}); e != nil {
		t.Fatal(e)
	}
	_, body = sc.fetchFormat(t, h, token, "mihomo")
	for _, n := range names(parseMihomoDoc(t, body)) {
		if n == "DIRECT" {
			t.Fatal("a proxy named DIRECT would shadow the built-in")
		}
	}
}

func TestAggregateSourceProblemsNeverAffectLocalNodes(t *testing.T) {
	sc := newAggScene(t)
	items := []SubItem{sc.local(0), sc.rnode(t, sc.links, "HK Reality"), sc.local(1)}
	_, token, e := sc.a.CreateAggregateSubscription("Resilient", AggregateSpec{Items: items})
	if e != nil {
		t.Fatal(e)
	}
	h := sc.server()
	expect := func(label string, remoteNodes int) {
		t.Helper()
		for _, format := range []string{"", "mihomo"} {
			code, body := sc.fetchFormat(t, h, token, format)
			if code != 200 {
				t.Fatalf("%s/%s: %d %s", label, format, code, body)
			}
			n := 0
			if format == "" {
				n = len(decodeBody(t, body))
			} else {
				n = len(parseMihomoDoc(t, body).Proxies)
			}
			if n != 2+remoteNodes {
				t.Fatalf("%s/%s: %d entries, want %d", label, format, n, 2+remoteNodes)
			}
		}
	}
	expect("healthy", 1)
	// 1. The provider goes down: the last good snapshot keeps being served.
	sc.fsLinks.set("", os.ErrDeadlineExceeded)
	_, _ = sc.a.RefreshRemoteSource(context.Background(), sc.links.ID)
	expect("provider down", 1)
	// 2. The snapshot file is corrupted: only the remote entry disappears.
	if e = os.WriteFile(sc.a.remoteSnapshotPath(sc.links.ID), []byte("{broken"), 0600); e != nil {
		t.Fatal(e)
	}
	expect("corrupt snapshot", 0)
	// 3. The snapshot file is gone.
	_ = os.Remove(sc.a.remoteSnapshotPath(sc.links.ID))
	expect("missing snapshot", 0)
	// 4. The whole source list is corrupted.
	if e = os.WriteFile(sc.a.remoteConfigPath(), []byte("not json"), 0600); e != nil {
		t.Fatal(e)
	}
	expect("corrupt sources.json", 0)
	// 5. The whole remote directory is gone.
	if e = os.RemoveAll(sc.a.remotePath()); e != nil {
		t.Fatal(e)
	}
	expect("no remote dir", 0)
}

func TestAggregateFollowsRefreshRemovalAndCredentialRotation(t *testing.T) {
	sc := newAggScene(t)
	items := []SubItem{sc.rnode(t, sc.links, "HK Reality"), sc.rnode(t, sc.links, "JP Trojan"), sc.local(0)}
	_, token, e := sc.a.CreateAggregateSubscription("Follow", AggregateSpec{Items: items})
	if e != nil {
		t.Fatal(e)
	}
	h := sc.server()
	// The provider rotates the Trojan password (same host and port) and drops the Reality node.
	rotated := strings.Replace(linkTrojan, "trojanpw", "newpassword", 1)
	sc.fsLinks.set(linkList(rotated, linkHy2), nil)
	if _, e = sc.a.RefreshRemoteSource(context.Background(), sc.links.ID); e != nil {
		t.Fatal(e)
	}
	_, body := sc.fetchFormat(t, h, token, "")
	lines := decodeBody(t, body)
	if len(lines) != 2 || lines[0] != rotated {
		t.Fatalf("expected the rotated Trojan node (followed by endpoint) and alpha; got %v", lines)
	}
	st := sc.state(t)
	exp := sc.a.ExportAggregate(st, st.Subscriptions[0])
	if exp.Nodes[0].Skipped == "" {
		t.Fatalf("the vanished node must be reported, not hidden: %+v", exp.Nodes[0])
	}
	// Disabling a node or the whole source drops it from the output.
	snap := snapshotOf(t, sc.a, sc.links.ID)
	var tid string
	for _, n := range snap.Nodes {
		if n.Protocol == "trojan" {
			tid = n.ID
		}
	}
	dis := []string{tid}
	if _, e = sc.a.UpdateRemoteSource(sc.links.ID, RemoteSourcePatch{DisabledNodes: &dis}); e != nil {
		t.Fatal(e)
	}
	_, body = sc.fetchFormat(t, h, token, "")
	if lines = decodeBody(t, body); len(lines) != 1 {
		t.Fatalf("node disabled in the source still exported: %v", lines)
	}
	// Re-enabling brings it back; disabling the source removes it again.
	none := []string{}
	_, _ = sc.a.UpdateRemoteSource(sc.links.ID, RemoteSourcePatch{DisabledNodes: &none})
	if _, body = sc.fetchFormat(t, h, token, ""); len(decodeBody(t, body)) != 2 {
		t.Fatal("re-enabled node missing")
	}
	off := false
	_, _ = sc.a.UpdateRemoteSource(sc.links.ID, RemoteSourcePatch{Enabled: &off})
	if _, body = sc.fetchFormat(t, h, token, ""); len(decodeBody(t, body)) != 1 {
		t.Fatal("node of a disabled source still exported")
	}
}

func TestLegacySubscriptionsAreUnchangedByTheNewFeature(t *testing.T) {
	sc := newSubScene(t)
	sub, token := sc.create(t, "Legacy", 0, 1, 2)
	raw, e := os.ReadFile(sc.a.Home + "/state.json")
	if e != nil {
		t.Fatal(e)
	}
	for _, key := range []string{`"items"`, `"dedupe"`, `"allow_insecure"`} {
		if strings.Contains(string(raw), key) {
			t.Fatalf("a v0.4.0-shaped subscription gained %s in state.json", key)
		}
	}
	if sub.aggregate() {
		t.Fatal("legacy subscription reported as aggregate")
	}
	h, _ := sc.handler() // no remote lookup at all, as in v0.4.0
	var want []string
	for _, i := range []int{0, 1, 2} {
		u, _ := sc.nodes[i].URI()
		want = append(want, u)
	}
	if got := decodeBody(t, get(h, "GET", "/s/"+token).Body.String()); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("legacy output changed:\n%v\n%v", got, want)
	}
	// Even with sources present, a legacy subscription takes the old path.
	fs := &fakeSource{body: linkList(linkVless)}
	sc.a.remoteFetch = fs.fetch
	src, _ := sc.a.AddRemoteSource(RemoteSourceSpec{Name: "S", URL: secretURL, Enabled: true})
	_, _ = sc.a.RefreshRemoteSource(context.Background(), src.ID)
	if got := decodeBody(t, get(h, "GET", "/s/"+token).Body.String()); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatal("adding a source changed a legacy subscription")
	}
	// A legacy subscription cannot be silently edited into an aggregate by the CLI path.
	b, _ := json.Marshal(sc.state(t).Subscriptions[0])
	if strings.Contains(string(b), "items") {
		t.Fatalf("%s", b)
	}
	// No remote data is created until a source is added.
	fresh := newSubScene(t)
	fresh.create(t, "L", 0)
	if _, err := os.Stat(fresh.a.remotePath()); !os.IsNotExist(err) {
		t.Fatal("remote directory created without any source")
	}
}

func TestAggregateStateStaysReadableByOlderVersions(t *testing.T) {
	sc := newAggScene(t)
	items := []SubItem{sc.rnode(t, sc.links, "HK Reality"), sc.local(1), sc.local(0)}
	sub, _, e := sc.a.CreateAggregateSubscription("Rollback", AggregateSpec{Items: items})
	if e != nil {
		t.Fatal(e)
	}
	// v0.4.0 only knows NodeIDs: it must see exactly the local nodes, in order.
	if len(sub.NodeIDs) != 2 || sub.NodeIDs[0] != sc.nodes[1].ID || sub.NodeIDs[1] != sc.nodes[0].ID {
		t.Fatalf("legacy mirror: %v", sub.NodeIDs)
	}
	// Deleting a local node removes it from both views and leaves the remote entry.
	st := pruneSubscriptionNode(sc.state(t), sc.nodes[1].ID)
	got := st.Subscriptions[0]
	if len(got.NodeIDs) != 1 || len(got.Items) != 2 || got.Items[0].Kind != itemRemote {
		t.Fatalf("%+v", got)
	}
	if e = st.Validate(); e != nil {
		t.Fatal(e)
	}
}

func TestAggregateEditValidation(t *testing.T) {
	sc := newAggScene(t)
	good := sc.rnode(t, sc.links, "HK Reality")
	cases := map[string][]SubItem{
		"empty":                {},
		"unknown local":        {{Kind: itemLocal, NodeID: "aaaaaaaaaaaa"}},
		"unknown remote node":  {{Kind: itemRemote, SourceID: sc.links.ID, RemoteID: "aaaaaaaaaaaa"}},
		"unknown source":       {{Kind: itemRemote, SourceID: "bbbbbbbbbbbb", RemoteID: good.RemoteID}},
		"node of other source": {{Kind: itemRemote, SourceID: sc.clash.ID, RemoteID: good.RemoteID}},
		"duplicate":            {good, good},
		"bad kind":             {{Kind: "other", NodeID: sc.nodes[0].ID}},
		"mixed fields":         {{Kind: itemLocal, NodeID: sc.nodes[0].ID, SourceID: sc.links.ID}},
		"bad name":             {{Kind: itemRemote, SourceID: good.SourceID, RemoteID: good.RemoteID, Name: "a\nb"}},
	}
	for name, items := range cases {
		if _, _, e := sc.a.CreateAggregateSubscription("X"+name, AggregateSpec{Items: items}); e == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if subs := sc.state(t).Subscriptions; len(subs) != 0 {
		t.Fatalf("rejected requests left %d subscriptions behind", len(subs))
	}
	// The client cannot smuggle identity fields: Loose is recomputed on the server.
	forged := good
	forged.Loose = "vless|evil.example|1"
	sub, _, e := sc.a.CreateAggregateSubscription("Forged", AggregateSpec{Items: []SubItem{forged}})
	if e != nil {
		t.Fatal(e)
	}
	if sub.Items[0].Loose == forged.Loose || !strings.HasPrefix(sub.Items[0].Loose, "vless|198.51.100.10|") {
		t.Fatalf("Loose=%q", sub.Items[0].Loose)
	}
	// The CLI node editor refuses to flatten an aggregate.
	if e = sc.a.SetSubscriptionNodes(sub.ID, []string{sc.nodes[0].ID}); e == nil {
		t.Fatal("SetSubscriptionNodes silently dropped the third-party items")
	}
}

// A node the administrator excluded at the source must stay excluded when the provider rotates
// its credentials and the aggregate follows it to the replacement.
func TestAggregateDisabledNodeStaysDisabledAfterCredentialRotation(t *testing.T) {
	sc := newAggScene(t)
	trojan := sc.rnode(t, sc.links, "JP Trojan")
	_, token, e := sc.a.CreateAggregateSubscription("Disabled", AggregateSpec{Items: []SubItem{trojan, sc.local(0)}})
	if e != nil {
		t.Fatal(e)
	}
	dis := []string{trojan.RemoteID}
	if _, e = sc.a.UpdateRemoteSource(sc.links.ID, RemoteSourcePatch{DisabledNodes: &dis}); e != nil {
		t.Fatal(e)
	}
	h := sc.server()
	if _, body := sc.fetchFormat(t, h, token, ""); len(decodeBody(t, body)) != 1 {
		t.Fatalf("setup: disabled node exported: %v", decodeBody(t, body))
	}
	sc.fsLinks.set(linkList(strings.Replace(linkTrojan, "trojanpw", "newpassword", 1), linkHy2), nil)
	if _, e = sc.a.RefreshRemoteSource(context.Background(), sc.links.ID); e != nil {
		t.Fatal(e)
	}
	_, body := sc.fetchFormat(t, h, token, "")
	if lines := decodeBody(t, body); len(lines) != 1 || strings.Contains(lines[0], "newpassword") {
		t.Fatalf("credential rotation re-enabled an excluded node: %v", lines)
	}
}
