package rout

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

// Decode the JSON-compatible YAML flow values independently of their Go types.
// Full YAML parsing and Mihomo semantic validation are tested by the real core.
func readMihomo(t *testing.T, body string) (proxies, groups []M, rules []string) {
	t.Helper()
	section := ""
	for _, line := range strings.Split(body, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		switch line {
		case "proxies:", "proxy-groups:", "rules:":
			section = line
			continue
		}
		if !strings.HasPrefix(line, "  - ") {
			t.Fatal("invalid YAML section")
		}
		value := []byte(line[4:])
		switch section {
		case "proxies:":
			var m M
			if e := json.Unmarshal(value, &m); e != nil {
				t.Fatal(e)
			}
			proxies = append(proxies, m)
		case "proxy-groups:":
			var m M
			if e := json.Unmarshal(value, &m); e != nil {
				t.Fatal(e)
			}
			groups = append(groups, m)
		case "rules:":
			var rule string
			if e := json.Unmarshal(value, &rule); e != nil {
				t.Fatal(e)
			}
			rules = append(rules, rule)
		default:
			t.Fatal("unexpected YAML value")
		}
	}
	return
}

func TestSubscriptionMihomoFormatsAndBase64Preservation(t *testing.T) {
	sc := newSubScene(t)
	sub, token := sc.create(t, "Original", 2, 0, 1)
	stateBefore, _ := os.ReadFile(filepath.Join(sc.a.Home, "state.json"))
	if e := sc.a.SaveSettings(Settings{Language: "en", Subscription: &SubscriptionSettings{Enabled: true, Port: 8787, PublicURL: "https://saved.example/prefix"}}); e != nil {
		t.Fatal(e)
	}
	settingsBefore, _ := os.ReadFile(filepath.Join(sc.a.Home, "settings.json"))
	h := sc.a.subscriptionHTTPHandler(sc.a.Load, func(string, ...any) {})
	expected := sc.state(t).exportSubscription(sub)
	want := renderSubscription(expected.URIs)
	for _, query := range []string{"", "?x=1", "?format=base64"} {
		w := get(h, "GET", "/s/"+token+query)
		if w.Code != 200 || w.Body.String() != want || w.Header().Get("Content-Type") != "text/plain; charset=utf-8" {
			t.Fatal("Base64 compatibility changed")
		}
	}
	for _, query := range []string{"?format=mihomo", "?format=clash", "?format=mihomo&x=1"} {
		w := get(h, "GET", "/s/"+token+query)
		if w.Code != 200 || !utf8.Valid(w.Body.Bytes()) || w.Header().Get("Content-Type") != "application/yaml; charset=utf-8" {
			t.Fatal("Mihomo HTTP response", w.Code)
		}
		for key, value := range map[string]string{"Cache-Control": "no-store", "Pragma": "no-cache", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "X-Rout-Skipped-Nodes": "1"} {
			if w.Header().Get(key) != value {
				t.Fatal(key)
			}
		}
		if strings.Contains(w.Body.String(), token) || strings.Contains(w.Body.String(), sub.TokenHash) {
			t.Fatal("subscription secret leaked")
		}
		proxies, groups, rules := readMihomo(t, w.Body.String())
		if len(proxies) != 2 || proxies[0]["name"] != sc.nodes[0].Name || proxies[1]["name"] != sc.nodes[1].Name {
			t.Fatal("selection/order changed")
		}
		if len(groups) != 3 || !reflect.DeepEqual(rules, []string{"MATCH," + mihomoProxyGroup}) {
			t.Fatal("incomplete configuration")
		}
		head := get(h, "HEAD", "/s/"+token+query)
		if head.Code != 200 || head.Body.Len() != 0 || head.Header().Get("Content-Length") != w.Header().Get("Content-Length") {
			t.Fatal("HEAD differs")
		}
	}
	for _, query := range []string{"?format=unknown", "?format=", "?format=mihomo&format=base64", "?format=mihomo&bad=%zz"} {
		w := get(h, "GET", "/s/"+token+query)
		if w.Code != 400 || !strings.Contains(w.Body.String(), "format") || strings.Contains(w.Body.String(), token) {
			t.Fatal("bad format not safely rejected")
		}
		if get(h, "GET", "/s/"+strings.Repeat("A", 43)+query).Code != 404 {
			t.Fatal("format disclosed subscription authentication")
		}
	}
	for _, name := range []string{"state.json", "settings.json"} {
		raw, _ := os.ReadFile(filepath.Join(sc.a.Home, name))
		before := stateBefore
		if name == "settings.json" {
			before = settingsBefore
		}
		if !bytes.Equal(raw, before) {
			t.Fatal("rendering modified persistence", name)
		}
	}
}

func TestSubscriptionMihomoNativeProtocolsAndTLS(t *testing.T) {
	for _, protocol := range []string{"vless", "ss", "hy2", "tuic"} {
		t.Run(protocol, func(t *testing.T) {
			p := linkFixture(t, protocol, "2001:db8::7")
			proxy, e := mihomoNode(p)
			if e != nil {
				t.Fatal(e)
			}
			if proxy["server"] != p.PublicHost || proxy["port"] != p.PublicPort {
				t.Fatal("public endpoint changed")
			}
			switch protocol {
			case "vless":
				for key, want := range (M{"type": "vless", "uuid": p.UUID, "network": "tcp", "tls": true, "servername": p.SNI, "flow": "xtls-rprx-vision", "client-fingerprint": "chrome"}) {
					if proxy[key] != want {
						t.Fatal(key)
					}
				}
				if !reflect.DeepEqual(proxy["reality-opts"], M{"public-key": p.PublicKey, "short-id": p.ShortID, "support-x25519mlkem768": true}) {
					t.Fatal("Reality settings lost")
				}
			case "ss":
				if proxy["cipher"] != p.Method || proxy["password"] != p.Password || proxy["udp"] != true {
					t.Fatal("SS credentials changed")
				}
			case "hy2", "tuic":
				wantPin, _ := CertificatePin(p.CertPEM)
				if proxy["fingerprint"] != wantPin {
					t.Fatal("server certificate pin changed")
				}
				if proxy["password"] != p.Password || proxy["sni"] != p.SNI || proxy["skip-cert-verify"] == true || proxy["fingerprint"] == nil {
					t.Fatal("TLS trust or authentication lost")
				}
				if protocol == "tuic" && (proxy["uuid"] != p.UUID || proxy["congestion-controller"] != "bbr" || !reflect.DeepEqual(proxy["alpn"], []string{"h3"})) {
					t.Fatal("TUIC parameters lost")
				}
			}
			body := renderMihomo([]M{withMihomoName(proxy, p.Name)}, nil, mihomoDefaultTestURL)
			for _, secret := range []string{p.PrivateKey, p.KeyPEM} {
				if secret != "" && strings.Contains(body, secret) {
					t.Fatal("private server key leaked")
				}
			}
		})
	}
}
func withMihomoName(proxy M, name string) M { proxy["name"] = name; return proxy }

func TestSubscriptionMihomoNamesAndReferences(t *testing.T) {
	sc := newSubScene(t)
	s := sc.state(t)
	s.Profiles[0].Name = "🇨🇳 香港: [A] # yes \"\\\t"
	s.Profiles[1].Name = s.Profiles[0].Name
	s.Profiles[2].Name = mihomoProxyGroup
	extra := fixture(t, "ss")
	extra.Name = s.Profiles[0].Name + " [" + s.Profiles[0].ID + "]"
	s.Profiles = append(s.Profiles, extra)
	sub := Subscription{NodeIDs: []string{s.Profiles[1].ID, s.Profiles[0].ID, extra.ID}}
	proxies, warnings := s.exportMihomo(sub)
	if len(proxies) != 3 || len(warnings) != 0 {
		t.Fatal(warnings)
	}
	body := renderMihomo(proxies, warnings, mihomoDefaultTestURL)
	parsed, groups, _ := readMihomo(t, body)
	names := map[string]bool{"DIRECT": true}
	for _, p := range parsed {
		n := p["name"].(string)
		if names[n] {
			t.Fatal("duplicate name")
		}
		names[n] = true
		if !strings.Contains(n, "🇨🇳 香港") {
			t.Fatal("original flag/name lost")
		}
	}
	for _, g := range groups {
		names[g["name"].(string)] = true
	}
	for _, g := range groups {
		for _, ref := range g["proxies"].([]any) {
			if !names[ref.(string)] {
				t.Fatal("dangling group reference")
			}
		}
	}
	reversed := sub
	reversed.NodeIDs = []string{extra.ID, s.Profiles[0].ID, s.Profiles[1].ID}
	again, _ := s.exportMihomo(reversed)
	if parsed[0]["name"] != again[2]["name"] || parsed[1]["name"] != again[1]["name"] {
		t.Fatal("names depend on selection order")
	}
}

func TestSubscriptionMihomoUnsupportedEmptyAndDynamic(t *testing.T) {
	sc := newSubScene(t)
	sub, token := sc.create(t, "Live", 0, 1)
	h, logs := sc.handler()
	fetch := func() string {
		w := get(h, "GET", "/s/"+token+"?format=mihomo")
		if w.Code != 200 {
			t.Fatal(w.Code)
		}
		return w.Body.String()
	}
	before := fetch()
	s := sc.state(t)
	p := s.Profiles[0]
	p.Name = "🇫🇷 renamed"
	p.PublicHost = "changed.example.com"
	if e := sc.a.Commit(s, replace(s, p), false); e != nil {
		t.Fatal(e)
	}
	after := fetch()
	if before == after || !strings.Contains(after, "🇫🇷 renamed") || !strings.Contains(after, "changed.example.com") {
		t.Fatal("stale Mihomo snapshot")
	}
	if e := sc.a.SetSubscriptionNodes(sub.ID, sc.ids(1, 0)); e != nil {
		t.Fatal(e)
	}
	parsed, _, _ := readMihomo(t, fetch())
	if parsed[0]["type"] != "ss" {
		t.Fatal("order update ignored")
	}
	if e := sc.a.SetSubscriptionNodes(sub.ID, sc.ids(2)); e != nil {
		t.Fatal(e)
	}
	w := get(h, "GET", "/s/"+token+"?format=mihomo")
	if w.Code != 503 || !strings.Contains(w.Body.String(), "AnyTLS Reality") || get(h, "GET", "/s/"+token).Code != 200 {
		t.Fatal("unsupported protocol corrupted Base64 or returned empty success")
	}
	s = sc.state(t)
	s.Profiles[2].Enabled = false
	data, _ := JSON(s)
	if e := AtomicWrite(filepath.Join(sc.a.Home, "state.json"), data, 0600); e != nil {
		t.Fatal(e)
	}
	if get(h, "GET", "/s/"+token+"?format=mihomo").Code != 503 {
		t.Fatal("empty subscription succeeded")
	}
	if strings.Contains(strings.Join(*logs, "\n"), token) {
		t.Fatal("token logged")
	}
	if e := sc.a.SetSubscriptionEnabled(sub.ID, false); e != nil {
		t.Fatal(e)
	}
	if get(h, "GET", "/s/"+token+"?format=mihomo").Code != 404 {
		t.Fatal("disabled token accepted")
	}
}

func TestSubscriptionMihomoURLsSettingsAndCLI(t *testing.T) {
	sc := newSubScene(t)
	_, token := sc.create(t, "Saved", 0)
	before, _ := os.ReadFile(filepath.Join(sc.a.Home, "state.json"))
	if e := sc.a.SetSubscriptionPublicURL("https://custom.example/prefix"); e != nil {
		t.Fatal(e)
	}
	cfg, _ := sc.a.subscriptionSettings()
	if cfg.MihomoURL(token) != cfg.SubscriptionURL(token)+"?format=mihomo" {
		t.Fatal("URL not derived from public settings")
	}
	for _, lang := range []string{"en", "zh-CN"} {
		sc.a.Language = lang
		u, out := testUI(sc.a, "")
		u.showToken(token, "订阅已创建", "测试订阅")
		if !strings.Contains(out.String(), cfg.SubscriptionURL(token)) || !strings.Contains(out.String(), cfg.MihomoURL(token)) || (lang == "en" && hasHan(out.String())) {
			t.Fatal("new token URLs or translation missing")
		}
		u, out = testUI(sc.a, "")
		u.showExistingSubscriptionURL()
		if strings.Contains(out.String(), token) || !strings.Contains(out.String(), "/s/{access_token}?format=mihomo") || (lang == "en" && hasHan(out.String())) {
			t.Fatal("existing token recovered/rotated or untranslated")
		}
	}
	for _, raw := range []string{"http://health.example/test", "https://u:p@health.example/", "https://health.example/?token=secret", "https://health.example/#x", "https://health.example:99999/"} {
		if sc.a.SetMihomoTestURL(raw) == nil {
			t.Fatal("unsafe health URL accepted")
		}
	}
	h := sc.a.subscriptionHTTPHandler(sc.a.Load, func(string, ...any) {})
	if e := sc.a.SetMihomoTestURL("https://health.example/check"); e != nil {
		t.Fatal(e)
	}
	w := get(h, "GET", "/s/"+token+"?format=mihomo")
	_, groups, _ := readMihomo(t, w.Body.String())
	if groups[1]["url"] != "https://health.example/check" || groups[1]["interval"] != float64(600) || groups[1]["lazy"] != true {
		t.Fatal("health settings not dynamic")
	}
	if e := sc.a.SetMihomoTestURL(""); e != nil {
		t.Fatal(e)
	}
	after, _ := os.ReadFile(filepath.Join(sc.a.Home, "state.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("settings changed tokens or selections")
	}
}

func TestSubscriptionMihomoRelayParameters(t *testing.T) {
	node := fixture(t, "vless")
	raw, _ := node.URI()
	cases := []struct{ link, network, kind string }{
		{raw, "tcp", "vless"},
		{"vless://" + node.UUID + "@origin.example:443?security=tls&type=ws&sni=tls.example&host=ws.example&path=%2Fsocket&fp=firefox&alpn=h2%2Chttp%2F1.1", "tcp", "vless"},
		{"vless://" + node.UUID + "@origin.example:443?security=none&type=tcp", "tcp", "vless"},
		{"trojan://secret%3Apassword@origin.example:443?sni=tls.example&type=grpc&serviceName=service&authority=tls.example", "tcp", "trojan"},
		{"ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@origin.example:443", "both", "ss"},
		{"hysteria2://password@origin.example:443?sni=tls.example&alpn=h3&insecure=1&pinSHA256=" + strings.Repeat("a", 64), "udp", "hysteria2"},
		{"tuic://" + node.UUID + ":password@origin.example:443?sni=tls.example&alpn=h3&congestion_control=cubic&udp_relay_mode=quic", "udp", "tuic"},
	}
	for _, tc := range cases {
		target, _, e := ParseTarget(tc.link)
		if e != nil {
			t.Fatal(e)
		}
		relay := Profile{ID: RandomHex(6), Name: "Relay", Kind: "relay", Protocol: tc.network, Enabled: true, Listen: "127.0.0.1", Port: 24000, PublicHost: "2001:db8::9", PublicPort: 34000, Target: target, TargetURI: tc.link, RelayMode: relayRemote}
		proxy, e := mihomoNode(relay)
		if e != nil {
			t.Fatal(e)
		}
		if proxy["type"] != tc.kind || proxy["server"] != relay.PublicHost || proxy["port"] != relay.PublicPort || proxy["udp"] != (tc.kind != "ss" || tc.network != "tcp") {
			t.Fatal("relay endpoint/network changed")
		}
		if strings.Contains(tc.link, "type=ws") && (proxy["client-fingerprint"] != "firefox" || proxy["ws-opts"].(M)["path"] != "/socket") {
			t.Fatal("WS/TLS parameters dropped")
		}
		if tc.kind == "trojan" && proxy["password"] != "secret:password" {
			t.Fatal("Trojan authentication changed")
		}
		if tc.kind == "hysteria2" && proxy["fingerprint"] != strings.Repeat("a", 64) {
			t.Fatal("certificate pin dropped")
		}
	}
	for _, query := range []string{"security=reality&pbk=bad", "security=tls&unknown=secret", "security=tls&type=quic", "security=tls&insecure=1", "security=tls&type=grpc&authority=other.example&sni=tls.example", "security=tls&fp=not-supported", "security=tls&security=none", "security=tls&type=ws&path=%FF", "security=none&type=grpc&serviceName=service"} {
		link := "vless://" + node.UUID + "@origin.example:443?" + query
		target, _, _ := ParseTarget(link)
		p := Profile{ID: RandomHex(6), Name: "Bad relay", Kind: "relay", Protocol: "tcp", Enabled: true, Listen: "127.0.0.1", Port: 24000, PublicHost: "198.51.100.2", PublicPort: 34000, Target: target, TargetURI: link, RelayMode: relayRemote}
		if _, e := mihomoNode(p); e == nil || strings.Contains(e.Error(), "vless://") || strings.Contains(e.Error(), node.UUID) {
			t.Fatal("unsafe relay silently accepted or exposed")
		}
	}
}

func TestSubscriptionMihomoScalarInjection(t *testing.T) {
	values := []string{"a: [b] # !tag &anchor *alias", "\"}\nexternal-controller: 0.0.0.0:9090\n---", "yes", "null", "0123", "🇯🇵 東京\\\"\t", "\x00\u2028\u2029"}
	for _, value := range values {
		body := renderMihomo([]M{{"name": value, "password": value, "type": "ss"}}, nil, mihomoDefaultTestURL)
		proxies, _, _ := readMihomo(t, body)
		if proxies[0]["name"] != value || proxies[0]["password"] != value || !utf8.ValidString(body) || strings.Contains(body, "\nexternal-controller:") {
			t.Fatal("YAML injection or scalar coercion")
		}
	}
	// Ensure the default format remains ordinary Base64, not YAML encoded as Base64.
	data, _ := base64.StdEncoding.DecodeString(renderSubscription([]string{"vless://example"}))
	if string(data) != "vless://example" {
		t.Fatal("Base64 semantics changed")
	}
}

func TestSubscriptionMihomoReadOnlyRoutingAndTraffic(t *testing.T) {
	sc := newSubScene(t)
	ex := aiTestExit(t, sc.a, "Existing AI exit", "198.51.100.3", 1080)
	_, token := sc.create(t, "Existing", 0, 1)
	s := sc.state(t)
	s.Schema = 2
	s.Profiles[0].Traffic = &TrafficPolicy{LimitBytes: 123456789, BillingDay: 17, Timezone: "UTC"}
	s.AI = &AIRouting{Enabled: true, AIOutboundID: ex.ID, BoundInboundIDs: []string{s.Profiles[0].ID}, RuleSetVersion: AIRuleSetCurrent}
	uri, _ := s.Profiles[0].URI()
	target, _, _ := ParseTarget(uri)
	s.Profiles = append(s.Profiles, Profile{ID: RandomHex(6), Name: "Existing NAT relay", Kind: "relay", Enabled: true, Protocol: "tcp", Listen: "127.0.0.1", Port: 27001, PublicHost: "198.51.100.4", PublicPort: 37001, NAT: true, Target: target, TargetURI: uri, RelayMode: relayRemote})
	if e := s.Validate(); e != nil {
		t.Fatal(e)
	}
	data, _ := JSON(s)
	if e := AtomicWrite(filepath.Join(sc.a.Home, "state.json"), data, 0600); e != nil {
		t.Fatal(e)
	}
	if e := AtomicWrite(filepath.Join(sc.a.Home, "traffic.json"), []byte("existing accounting sentinel; must never be read or rewritten by export"), 0600); e != nil {
		t.Fatal(e)
	}
	snapshot := map[string][]byte{}
	for _, path := range []string{filepath.Join(sc.a.Home, "state.json"), filepath.Join(sc.a.Home, "traffic.json"), filepath.Join(sc.a.profileDir(s.Profiles[0].ID), "config.json")} {
		raw, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		snapshot[path] = raw
	}
	sc.a.subscriptionHTTPS = &subscriptionHTTPSRuntime{run: func(string, string, ...string) ([]byte, error) {
		t.Fatal("format request attempted Caddy management")
		return nil, nil
	}}
	h := sc.a.subscriptionHTTPHandler(sc.a.Load, func(string, ...any) {})
	for _, query := range []string{"", "?format=mihomo"} {
		if get(h, "GET", "/s/"+token+query).Code != 200 {
			t.Fatal("existing token rejected")
		}
	}
	for path, before := range snapshot {
		after, e := os.ReadFile(path)
		if e != nil || !bytes.Equal(before, after) {
			t.Fatal("export changed routing, credentials, bindings, traffic or relay state")
		}
	}
	p := s.Profiles[1]
	p.Network = "udp"
	if _, e := mihomoNode(p); e == nil {
		t.Fatal("UDP-only SS silently converted")
	}
}
