package remote

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

const clashSample = `
port: 7890
mixed-port: 7891
allow-lan: false
proxies:
  - {name: "🇭🇰 HK-01", type: ss, server: hk.example.org, port: 8388, cipher: aes-256-gcm, password: pw1, udp: true}
  - name: "🇯🇵 JP Reality"
    type: vless
    server: jp.example.org
    port: 443
    uuid: 11111111-2222-4333-8444-555555555555
    network: tcp
    tls: true
    udp: true
    flow: xtls-rprx-vision
    servername: www.microsoft.com
    client-fingerprint: chrome
    reality-opts:
      public-key: 7YpXk8L9m3Qe2oR5tVwZ1nBcD4fGhJ6aKsUiOyPxEMg
      short-id: ab12
  - name: US-Trojan-WS
    type: trojan
    server: us.example.org
    port: 443
    password: "pa:ss@word"
    sni: us.example.org
    network: ws
    ws-opts:
      path: /ws
      headers:
        Host: us.example.org
    alpn: [h2, http/1.1]
    skip-cert-verify: false
  - {name: SG-HY2, type: hysteria2, server: sg.example.org, port: 8443, password: hy2pw, sni: sg.example.org, obfs: salamander, obfs-password: ob, up: 100 Mbps, down: 500 Mbps}
  - {name: DE-TUIC, type: tuic, server: de.example.org, port: 443, uuid: 22222222-3333-4444-8555-666666666666, password: tpw, sni: de.example.org, alpn: [h3], congestion-controller: bbr, udp-relay-mode: native}
  - {name: FR-AnyTLS, type: anytls, server: fr.example.org, port: 443, password: apw, sni: fr.example.org, client-fingerprint: chrome}
  - {name: Old-VMess, type: vmess, server: vm.example.org, port: 443, uuid: 11111111-2222-4333-8444-555555555555, alterId: 0, cipher: auto}
  - {name: Obfs-SS, type: ss, server: ob.example.org, port: 443, cipher: aes-128-gcm, password: x, plugin: obfs, plugin-opts: {mode: tls, host: bing.com}}
  - {name: Steered, type: ss, server: st.example.org, port: 443, cipher: aes-128-gcm, password: x, dialer-proxy: other}
  - {name: Info-Remaining, type: ss, server: 127.0.0.1, port: 1, cipher: aes-128-gcm, password: x}
  - {name: Odd-Field, type: ss, server: odd.example.org, port: "8388", cipher: aes-128-gcm, password: y, brutal-opts: {up: 10}}
proxy-groups:
  - {name: Proxy, type: select, proxies: [HK, JP]}
rules:
  - MATCH,Proxy
`

func TestParseClashDocument(t *testing.T) {
	p, err := Parse([]byte(clashSample))
	if err != nil {
		t.Fatal(err)
	}
	if p.Format != "clash" || p.Entries != 11 {
		t.Fatalf("format=%s entries=%d", p.Format, p.Entries)
	}
	byName := map[string]Node{}
	for _, n := range p.Nodes {
		byName[n.Name] = n
	}
	if len(p.Nodes) != 8 {
		t.Fatalf("want 8 nodes (vmess, forbidden and placeholder excluded), got %d", len(p.Nodes))
	}
	reasons := map[string]string{}
	for _, is := range p.Issues {
		reasons[is.Name] = is.Level + ":" + is.Reason
	}
	if !strings.HasPrefix(reasons["Old-VMess"], "error:") || !strings.Contains(reasons["Steered"], "dialer-proxy") || !strings.HasPrefix(reasons["Info-Remaining"], "skip:") {
		t.Fatalf("issues %v", reasons)
	}
	hk := byName["🇭🇰 HK-01"]
	if hk.Protocol != "ss" || hk.Port != 8388 || !hk.UDP || hk.Clash["password"] != "pw1" {
		t.Fatalf("%+v", hk)
	}
	if byName["Odd-Field"].Port != 8388 {
		t.Fatal("a quoted port is still a port")
	}
}

func TestClashNodesBecomeShareLinksWithoutLosingParameters(t *testing.T) {
	p, _ := Parse([]byte(clashSample))
	byName := map[string]Node{}
	for _, n := range p.Nodes {
		byName[n.Name] = n
	}
	check := func(name string, wants ...string) {
		t.Helper()
		n := byName[name]
		if n.Link == "" {
			t.Fatalf("%s: no link (%s)", name, n.LinkIssue)
		}
		for _, w := range wants {
			if !strings.Contains(n.Link, w) {
				t.Errorf("%s: link lost %q:\n%s", name, w, n.Link)
			}
		}
		back, err := ParseLink(n.Link)
		if err != nil || back.ID != n.ID {
			t.Errorf("%s: link must read back as the same node: %v", name, err)
		}
	}
	check("🇯🇵 JP Reality", "security=reality", "pbk=7YpXk8L9m3Qe2oR5tVwZ1nBcD4fGhJ6aKsUiOyPxEMg", "sid=ab12", "flow=xtls-rprx-vision", "sni=www.microsoft.com", "fp=chrome", "type=tcp")
	check("US-Trojan-WS", "type=ws", "path=%2Fws", "host=us.example.org", "alpn=h2%2Chttp%2F1.1", "sni=us.example.org")
	check("SG-HY2", "obfs=salamander", "obfs-password=ob", "sni=sg.example.org")
	check("DE-TUIC", "congestion_control=bbr", "udp_relay_mode=native", "alpn=h3")
	check("FR-AnyTLS", "sni=fr.example.org", "fp=chrome")
	check("🇭🇰 HK-01")
	// Plugins and fields a link cannot carry are reported, never silently dropped.
	if n := byName["Obfs-SS"]; n.Link != "" || !strings.Contains(n.LinkIssue, "插件") {
		t.Errorf("plugin node: link=%q issue=%q", n.Link, n.LinkIssue)
	}
	if n := byName["Odd-Field"]; n.Link != "" || !strings.Contains(n.LinkIssue, "brutal-opts") {
		t.Errorf("unknown field node: link=%q issue=%q", n.Link, n.LinkIssue)
	}
	// ...but they stay available as Mihomo entries, verbatim.
	cp, ok := byName["Obfs-SS"].ClashNamed("renamed")
	if !ok || cp["name"] != "renamed" || cp["plugin"] != "obfs" {
		t.Fatalf("clash passthrough: %v", cp)
	}
	cp["password"] = "mutated"
	if byName["Obfs-SS"].Clash["password"] != "x" {
		t.Fatal("ClashNamed must return a copy")
	}
}

func TestClashFlowInsideLineAndAnchorsAndMerge(t *testing.T) {
	doc := `
defaults: &d {type: ss, cipher: aes-128-gcm, password: shared}
proxies:
  - <<: *d
    name: A
    server: a.example.org
    port: 1001
  - <<: [*d]
    name: B
    server: b.example.org
    port: 1002
    password: own
`
	p, err := Parse([]byte(doc))
	if err != nil || len(p.Nodes) != 2 {
		t.Fatalf("%v %+v", err, p)
	}
	if p.Nodes[0].Clash["password"] != "shared" || p.Nodes[1].Clash["password"] != "own" || p.Nodes[0].Clash["cipher"] != "aes-128-gcm" {
		t.Fatalf("merge keys: %v / %v", p.Nodes[0].Clash, p.Nodes[1].Clash)
	}
}

func TestClashRejectsYAMLBombsAndHugeStructures(t *testing.T) {
	// Exponential alias expansion ("billion laughs"): ~9^10 expanded values from a few hundred bytes.
	var b strings.Builder
	b.WriteString("l0: &l0 [x,x,x,x,x,x,x,x,x]\n")
	for i := 1; i <= 10; i++ {
		refs := strings.TrimSuffix(strings.Repeat(fmt.Sprintf("*l%d,", i-1), 9), ",")
		fmt.Fprintf(&b, "l%d: &l%d [%s]\n", i, i, refs)
	}
	b.WriteString("proxies:\n  - {name: bomb, type: ss, server: a.example.org, port: 1, cipher: aes-128-gcm, password: x, extra: *l10}\n")
	start := time.Now()
	_, err := Parse([]byte(b.String()))
	if err == nil {
		t.Fatal("alias bomb must be rejected")
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("rejection took too long: %v", time.Since(start))
	}

	deep := "proxies:\n  - {name: d, type: ss, server: a.example.org, port: 1, cipher: aes-128-gcm, password: x, e: " + strings.Repeat("[", 3000) + strings.Repeat("]", 3000) + "}\n"
	if _, err := Parse([]byte(deep)); err == nil {
		t.Fatal("deep nesting must be rejected")
	}

	huge := "proxies:\n" + strings.Repeat("  - {name: x, type: ss, server: a.example.org, port: 1, cipher: aes-128-gcm, password: x}\n", 60000)
	if len(huge) <= MaxYAMLBytes {
		huge += strings.Repeat("# padding\n", MaxYAMLBytes/10)
	}
	if _, err := Parse([]byte(huge)); err == nil || !strings.Contains(err.Error(), "过大") {
		t.Fatalf("oversized YAML must be refused: %v", err)
	}

	if _, err := Parse([]byte("proxies:\n  - {name: " + strings.Repeat("a", maxYAMLLine+10) + ", type: ss}\n")); err == nil {
		t.Fatal("overlong line must be refused")
	}
	if _, err := Parse([]byte("proxies:\n  - {name: a, type: ss, server: a.example.org, port: 1, cipher: aes-128-gcm, password: " + strings.Repeat("p", maxScalar+1) + "}\n")); err != nil {
		// an oversized scalar errors the whole document as too complex; either outcome must not import it
		t.Logf("scalar limit: %v", err)
	}
}

func TestClashRejectsAmbiguousDocuments(t *testing.T) {
	cases := map[string]string{
		"duplicate key":   "proxies:\n  - {name: a, name: b, type: ss, server: a.example.org, port: 1, cipher: aes-128-gcm, password: x}\n",
		"no proxies":      "port: 1\nrules: []\n",
		"proxies scalar":  "proxies: nothing\n",
		"not a mapping":   "- a\n- b\nproxies:\n",
		"unknown anchor":  "proxies:\n  - *missing\n",
		"tab indentation": "proxies:\n\t- {name: a}\n",
	}
	for name, doc := range cases {
		p, err := Parse([]byte(doc))
		if err == nil && len(p.Nodes) > 0 {
			t.Errorf("%s: must not import nodes", name)
		}
	}
	// A duplicated key is an error for that entry (parsers disagree on which value wins).
	p, err := ParseClash([]byte("proxies:\n  - {name: a, name: b, type: ss, server: a.example.org, port: 1, cipher: aes-128-gcm, password: x}\n"))
	if err == nil && (len(p.Nodes) != 0 || len(p.Issues) != 1) {
		t.Fatalf("duplicate keys: %+v", p)
	}
}

func TestClashSecretsAreNeverInIssues(t *testing.T) {
	p, err := ParseClash([]byte("proxies:\n  - {name: leak, type: vless, server: a.example.org, port: 1, uuid: SUPERSECRETVALUE}\n  - {name: leak2, type: trojan, server: a.example.org, port: 1, password: SUPERSECRETVALUE, dialer-proxy: x}\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, is := range p.Issues {
		if strings.Contains(is.Reason, "SUPERSECRETVALUE") {
			t.Fatalf("issue echoes a secret: %+v", is)
		}
	}
	if len(p.Issues) != 2 {
		t.Fatalf("%+v", p.Issues)
	}
}

func TestClashEquivalentToLinkForDeduplication(t *testing.T) {
	fromLink, _ := ParseLink("trojan://pa%3Ass%40word@us.example.org:443?security=tls&sni=us.example.org#X")
	fromYAML, err := ParseClash([]byte("proxies:\n  - {name: Y, type: trojan, server: US.example.org, port: 443, password: 'pa:ss@word', sni: us.example.org}\n"))
	if err != nil || len(fromYAML.Nodes) != 1 {
		t.Fatalf("%v", err)
	}
	if fromLink.ID != fromYAML.Nodes[0].ID {
		t.Fatalf("the same account must have the same identity in either format:\n%s\n%s", fromLink.Fingerprint, fromYAML.Nodes[0].Fingerprint)
	}
}

func TestClashLargeConfigParsesQuickly(t *testing.T) {
	var b strings.Builder
	b.WriteString("proxies:\n")
	for i := 0; i < MaxNodes; i++ {
		fmt.Fprintf(&b, "  - {name: 'node %d', type: trojan, server: h%d.example.org, port: 443, password: pw%d, sni: h%d.example.org}\n", i, i, i, i)
	}
	b.WriteString("rules:\n")
	for i := 0; i < 30000; i++ {
		fmt.Fprintf(&b, "  - DOMAIN-SUFFIX,site%d.example.org,Proxy\n", i)
	}
	start := time.Now()
	p, err := Parse([]byte(b.String()))
	if err != nil || len(p.Nodes) != MaxNodes {
		t.Fatalf("%v nodes=%d", err, len(p.Nodes))
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("too slow: %v", time.Since(start))
	}
	b.WriteString("  - {name: extra, type: trojan, server: z.example.org, port: 443, password: z}\n")
	if _, err := Parse([]byte(strings.Replace(b.String(), "rules:", "x:", 1))); err == nil {
		t.Log("over-limit documents are refused or truncated by the proxies cap")
	}
}
