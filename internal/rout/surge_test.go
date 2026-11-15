package rout

import (
	"context"
	"strings"
	"testing"

	"github.com/VAR7IANT/Rout/internal/remote"
)

// surgeFields splits a Surge [Proxy] line into its name, type, server, port and key=value map.
func surgeFields(t *testing.T, line string) (name, kind, host, port string, kv map[string]string) {
	t.Helper()
	name, rest, ok := strings.Cut(line, " = ")
	if !ok {
		t.Fatalf("not a Surge proxy line: %q", line)
	}
	parts := strings.Split(rest, ", ")
	if len(parts) < 3 {
		t.Fatalf("Surge line too short: %q", line)
	}
	kv = map[string]string{}
	for _, p := range parts[3:] {
		k, v, ok := strings.Cut(p, "=")
		if !ok || k == "" {
			t.Fatalf("bad parameter %q in %q", p, line)
		}
		if _, dup := kv[k]; dup {
			t.Fatalf("duplicate parameter %q in %q", k, line)
		}
		kv[k] = v
	}
	return name, parts[0], parts[1], parts[2], kv
}

func TestSurgeLineEveryLocalProtocol(t *testing.T) {
	for _, protocol := range []string{"ss", "hy2", "tuic", "vless"} {
		t.Run(protocol, func(t *testing.T) {
			p := linkFixture(t, protocol, "203.0.113.7")
			p.Name = "Node " + protocol
			line, kind, e := p.surgeLine(p.PublicHost, p.PublicPort)
			if e != nil {
				t.Fatal(e)
			}
			name, typ, host, port, kv := surgeFields(t, line)
			if name != p.Name || host != "203.0.113.7" || port != itoa(p.PublicPort) || typ != kind {
				t.Fatalf("endpoint or name changed: %s", line)
			}
			switch protocol {
			case "ss":
				if typ != "ss" || kv["encrypt-method"] != p.Method || kv["password"] != p.Password || kv["udp-relay"] != "true" {
					t.Fatalf("SS: %s", line)
				}
			case "hy2", "tuic":
				pin, _ := CertificatePin(p.CertPEM)
				if kv["server-cert-fingerprint-sha256"] != pin || kv["sni"] != p.SNI || kv["password"] != p.Password || kv["skip-cert-verify"] == "true" {
					t.Fatalf("TLS trust lost: %s", line)
				}
				if protocol == "hy2" && typ != "hysteria2" {
					t.Fatalf("type: %s", line)
				}
				if protocol == "tuic" && (typ != "tuic-v5" || kv["uuid"] != p.UUID || kv["alpn"] != "h3") {
					t.Fatalf("TUIC: %s", line)
				}
			case "vless":
				if typ != surgeKindVLESS || kv["username"] != p.UUID || kv["flow"] != "xtls-rprx-vision" || kv["reality-public-key"] != p.PublicKey || kv["reality-short-id"] != p.ShortID || kv["sni"] != p.SNI {
					t.Fatalf("VLESS Reality: %s", line)
				}
			}
			for _, secret := range []string{p.PrivateKey, p.KeyPEM} {
				if secret != "" && strings.Contains(line, secret) {
					t.Fatal("a server secret reached the client line")
				}
			}
			// The exported wrapper agrees with the internal one.
			if got, e := p.SurgeLine(p.PublicHost, p.PublicPort); e != nil || got != line {
				t.Fatal("SurgeLine differs from surgeLine")
			}
		})
	}
}

func TestSurgeLineRefusesWhatSurgeCannotRun(t *testing.T) {
	p := fixture(t, "anytls")
	if _, e := p.SurgeLine(p.PublicHost, p.PublicPort); e == nil || !strings.Contains(e.Error(), "AnyTLS") || strings.Contains(e.Error(), "Mihomo") {
		t.Fatalf("AnyTLS Reality: %v", e)
	}
	ss := fixture(t, "ss")
	for _, host := range []string{"", "a,b", "a b", "a=b"} {
		if _, e := ss.SurgeLine(host, ss.PublicPort); e == nil {
			t.Errorf("host %q accepted", host)
		}
	}
	if _, e := ss.SurgeLine(ss.PublicHost, 0); e == nil {
		t.Error("port 0 accepted")
	}
	// Unknown Mihomo keys are refused rather than dropped.
	if _, _, e := surgeFromMihomo("x", M{"type": "ss", "server": "198.51.100.1", "port": 443, "cipher": "aes-128-gcm", "password": "p", "plugin": "obfs"}); e == nil || !strings.Contains(e.Error(), "plugin") {
		t.Fatalf("unknown key: %v", e)
	}
	if _, _, e := surgeFromMihomo("x", M{"type": "vmess", "server": "198.51.100.1", "port": 443}); e == nil {
		t.Fatal("unsupported type accepted")
	}
	// A value that would break the line is refused.
	if _, _, e := surgeFromMihomo("x", M{"type": "ss", "server": "198.51.100.1", "port": 443, "cipher": "aes-128-gcm", "password": "a,b"}); e == nil {
		t.Fatal("comma in a value accepted")
	}
	// ALPN cannot smuggle a second line or extra keys, whether it has one value or several.
	for _, alpn := range [][]any{
		{"h3\nInjected = ss, 198.51.100.9, 443, encrypt-method=aes-128-gcm, password=x"},
		{"h3, password=x"},
		{"h2", "h3\nInjected = ss"},
	} {
		m := M{"type": "trojan", "server": "198.51.100.1", "port": 443, "password": "p", "sni": "tls.example", "alpn": alpn}
		if line, _, e := surgeFromMihomo("x", m); e == nil {
			t.Errorf("ALPN %q accepted: %q", alpn, line)
		}
	}
	for alpn, want := range map[string][]any{"alpn=h3": {"h3"}, `alpn="h2,h3"`: {"h2", "h3"}} {
		m := M{"type": "trojan", "server": "198.51.100.1", "port": 443, "password": "p", "sni": "tls.example", "alpn": want}
		if line, _, e := surgeFromMihomo("x", m); e != nil || !strings.Contains(line, alpn) {
			t.Errorf("ALPN %v: %q %v", want, line, e)
		}
	}
}

func TestSurgeRelayLines(t *testing.T) {
	node := fixture(t, "vless")
	raw, _ := node.URI()
	cases := []struct{ link, network, kind string }{
		{raw, "tcp", "vless"},
		{"trojan://secret@origin.example:443?sni=tls.example&type=ws&host=tls.example&path=%2Fws", "tcp", "trojan"},
		{"ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@origin.example:443", "both", "ss"},
		{"hysteria2://password@origin.example:443?sni=tls.example&alpn=h3&insecure=1&pinSHA256=" + strings.Repeat("a", 64), "udp", "hysteria2"},
	}
	for _, tc := range cases {
		target, _, e := ParseTarget(tc.link)
		if e != nil {
			t.Fatal(e)
		}
		relay := Profile{ID: RandomHex(6), Name: "Relay", Kind: "relay", Protocol: tc.network, Enabled: true, Listen: "127.0.0.1", Port: 24000, PublicHost: "198.51.100.9", PublicPort: 34000, Target: target, TargetURI: tc.link, RelayMode: relayRemote}
		line, e := relay.SurgeLine(relay.PublicHost, relay.PublicPort)
		if e != nil {
			t.Fatalf("%s: %v", tc.kind, e)
		}
		_, typ, host, port, kv := surgeFields(t, line)
		if typ != tc.kind || host != "198.51.100.9" || port != "34000" {
			t.Fatalf("relay endpoint: %s", line)
		}
		switch tc.kind {
		case "trojan":
			if kv["password"] != "secret" || kv["ws"] != "true" || kv["ws-path"] != "/ws" || kv["sni"] != "tls.example" {
				t.Fatalf("Trojan WS: %s", line)
			}
		case "hysteria2":
			if kv["server-cert-fingerprint-sha256"] != strings.Repeat("a", 64) {
				t.Fatalf("pin dropped: %s", line)
			}
		}
	}
}

func TestSurgeNames(t *testing.T) {
	for in, want := range map[string]string{"HK, 01": "HK  01", "a=b": "a-b", `"q"`: "'q'", "#x": "x", "[Proxy]": "Proxy]", "": "fallback"} {
		if got := surgeName(in, "fallback"); got != want {
			t.Errorf("surgeName(%q) = %q, want %q", in, got, want)
		}
	}
	taken := map[string]bool{}
	if got := uniqueSurgeName(taken, "DIRECT"); strings.EqualFold(got, "direct") {
		t.Fatal("reserved policy name used for a proxy")
	}
	a, b := uniqueSurgeName(taken, "Tokyo"), uniqueSurgeName(taken, "tokyo")
	if strings.EqualFold(a, b) {
		t.Fatalf("names collide: %q %q", a, b)
	}
	if got := renameSurgeLine("old = ss, h, 1, password=x", "new"); got != "new = ss, h, 1, password=x" {
		t.Fatal(got)
	}
}

func TestSurgeSubscriptionVLESSGateAndWarnings(t *testing.T) {
	sc := newSubScene(t) // alpha vless, bravo ss, charlie anytls (Reality)
	sub, _ := sc.create(t, "Phone", 0, 1, 2)
	s := sc.state(t)
	lines, warnings := s.exportSurgeWith(sub, nil, surgeOptions{})
	if len(lines) != 1 || !strings.HasPrefix(lines[0], sc.nodes[1].Name+" = ss, ") {
		t.Fatalf("default Surge list: %v", lines)
	}
	joined := strings.Join(warnings, "\n")
	if !strings.Contains(joined, "VLESS") || !strings.Contains(joined, "AnyTLS") {
		t.Fatalf("warnings: %v", warnings)
	}
	lines, _ = s.exportSurgeWith(sub, nil, surgeOptions{VLESS: true})
	if len(lines) != 2 || !strings.HasPrefix(lines[0], sc.nodes[0].Name+" = vless, ") {
		t.Fatalf("opt-in Surge list: %v", lines)
	}
	if !surgeQueryOptions("format=surge&vless=1").VLESS || surgeQueryOptions("format=surge").VLESS || surgeQueryOptions("vless=0").VLESS {
		t.Fatal("vless query option")
	}
	all := allSurge(s)
	if !strings.Contains(all, " = vless, ") || !strings.Contains(all, " = ss, ") || strings.Contains(all, " = anytls, ") {
		t.Fatalf("allSurge: %s", all)
	}
}

func TestSurgeAggregateIncludesRemoteNodes(t *testing.T) {
	sc := newAggScene(t)
	items := []SubItem{sc.local(1), sc.rnode(t, sc.links, "SG HY2"), sc.rnode(t, sc.links, "JP Trojan"), sc.rnode(t, sc.links, "SS Plugin"), sc.rnode(t, sc.links, "HK Reality")}
	_, token, e := sc.a.CreateAggregateSubscription("Mixed", AggregateSpec{Items: items})
	if e != nil {
		t.Fatal(e)
	}
	h := sc.server()
	w := get(h, "GET", "/s/"+token+"?format=surge")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	lines := strings.Split(strings.TrimSpace(w.Body.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("aggregate Surge list: %v", lines)
	}
	if !strings.HasPrefix(lines[0], sc.nodes[1].Name+" = ss, ") || !strings.HasPrefix(lines[1], "SG HY2 = hysteria2, 203.0.113.30, 8443, ") || !strings.HasPrefix(lines[2], "JP Trojan = trojan, 203.0.113.20, 443, ") {
		t.Fatalf("order or content: %v", lines)
	}
	_, _, _, _, hy2 := surgeFields(t, lines[1])
	if hy2["password"] != "hy2pw" || hy2["salamander-password"] != "xyz" || hy2["sni"] != "h.example.net" {
		t.Fatalf("HY2: %s", lines[1])
	}
	// The plugin node can't be expressed and the VLESS node waits for the opt-in.
	if got := w.Header().Get("X-Rout-Skipped-Nodes"); got != "2" {
		t.Fatalf("skipped %q", got)
	}
	opt := get(h, "GET", "/s/"+token+"?format=surge&vless=1")
	if !strings.Contains(opt.Body.String(), "HK Reality = vless, 198.51.100.10, 443, ") {
		t.Fatalf("VLESS opt-in: %s", opt.Body.String())
	}
}

func TestWebSurgeLineEndpoint(t *testing.T) {
	s := newAPIScene(t)
	if w := s.c.get("/api/nodes/" + s.nodes[1].ID + "/surge"); w.Code != 403 {
		t.Fatalf("revealing a Surge line needs the password again: %d", w.Code)
	}
	s.c.reauth()
	w := s.c.get("/api/nodes/" + s.nodes[1].ID + "/surge")
	mustOK(t, w.Code, w.Body.String())
	if line, _ := jsonOf(t, w)["line"].(string); !strings.HasPrefix(line, s.nodes[1].Name+" = ss, ") {
		t.Fatalf("surge endpoint: %s", w.Body.String())
	}
	if w := s.c.get("/api/nodes/" + s.nodes[2].ID + "/surge"); w.Code == 200 {
		t.Fatalf("AnyTLS Reality got a Surge line: %s", w.Body.String())
	}
	nodes := listOf(t, jsonOf(t, s.c.get("/api/nodes")), "nodes")
	for _, n := range nodes {
		if want := n["protocol"] != "anytls"; n["has_surge"] != want {
			t.Errorf("has_surge for %v: %v", n["protocol"], n["has_surge"])
		}
	}
	entries := listOf(t, jsonOf(t, s.c.get("/api/activity")), "entries")
	var found bool
	for _, e := range entries {
		found = found || e["action"] == "reveal surge "+s.nodes[1].ID
	}
	if !found {
		t.Error("revealing a Surge line was not audited")
	}
}

// TestSurgeSourceImportsSnell: a Surge list (here, what another Rout serves as ?format=surge)
// is imported as a third-party source; its Snell nodes go out again as Surge lines, as Mihomo
// proxies where Mihomo can run them (not v6), and never into Base64, which has no Snell link.
func TestSurgeSourceImportsSnell(t *testing.T) {
	sc := newAggScene(t)
	fs := &fakeSource{body: "Far-Snell = snell, 203.0.113.40, 30001, psk=Q0123456789abcdefghijklmnopqrstu, version=4, obfs=http, obfs-host=bing.com\n" +
		"Far-Snell6 = snell, 2001:db8::40, 30002, psk=Q0123456789abcdefghijklmnopqrstu, version=6\n" +
		"Far-SS = ss, 203.0.113.40, 30003, encrypt-method=2022-blake3-aes-128-gcm, password=YWJjZGVmZ2hpamtsbW5vcA==\n"}
	prev := sc.a.remoteFetch
	sc.a.remoteFetch = func(ctx context.Context, rawURL string, opt remote.FetchOptions) (*remote.Result, error) {
		if strings.Contains(rawURL, "surge") {
			return fs.fetch(ctx, rawURL, opt)
		}
		return prev(ctx, rawURL, opt)
	}
	src, e := sc.a.AddRemoteSource(RemoteSourceSpec{Name: "Surge", URL: "https://surge.provider.test/s?t=3", Enabled: true, IntervalMin: 60})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = sc.a.RefreshRemoteSource(context.Background(), src.ID); e != nil {
		t.Fatal(e)
	}
	snap := snapshotOf(t, sc.a, src.ID)
	if len(snap.Nodes) != 3 {
		t.Fatalf("imported: %+v", snap.Nodes)
	}
	var items []SubItem
	for _, n := range snap.Nodes {
		items = append(items, SubItem{Kind: itemRemote, SourceID: src.ID, RemoteID: n.ID})
	}
	_, token, e := sc.a.CreateAggregateSubscription("Far", AggregateSpec{Items: items})
	if e != nil {
		t.Fatal(e)
	}
	h := sc.server()
	w := get(h, "GET", "/s/"+token+"?format=surge")
	lines := strings.Split(strings.TrimSpace(w.Body.String()), "\n")
	if w.Code != 200 || len(lines) != 3 {
		t.Fatalf("Surge: %d %s", w.Code, w.Body.String())
	}
	_, typ, host, port, kv := surgeFields(t, lines[0])
	if typ != "snell" || host != "203.0.113.40" || port != "30001" || kv["psk"] != "Q0123456789abcdefghijklmnopqrstu" || kv["version"] != "4" || kv["obfs"] != "http" || kv["obfs-host"] != "bing.com" {
		t.Fatalf("Snell line: %s", lines[0])
	}
	if !strings.HasPrefix(lines[1], "Far-Snell6 = snell, 2001:db8::40, 30002, ") || !strings.HasSuffix(lines[1], "version=6") {
		t.Fatalf("Snell v6 line: %s", lines[1])
	}
	m := get(h, "GET", "/s/"+token+"?format=mihomo")
	if m.Code != 200 || !strings.Contains(m.Body.String(), "Far-Snell") || strings.Contains(m.Body.String(), "Far-Snell6") || !strings.Contains(m.Body.String(), `"type":"snell"`) {
		t.Fatalf("Mihomo: %d %s", m.Code, m.Body.String())
	}
	b := get(h, "GET", "/s/"+token)
	dec, _ := decode64(strings.TrimSpace(b.Body.String()))
	if links := strings.Fields(string(dec)); b.Code != 200 || len(links) != 1 || !strings.HasPrefix(links[0], "ss://") {
		t.Fatalf("Base64: %d %q", b.Code, dec)
	}
}
