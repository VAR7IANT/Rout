package remote

import (
	"encoding/base64"
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

const (
	pbk   = "7YpXk8L9m3Qe2oR5tVwZ1nBcD4fGhJ6aKsUiOyPxEMg"
	uuid1 = "11111111-2222-4333-8444-555555555555"
	uuid2 = "22222222-3333-4444-8555-666666666666"
)

var sampleLinks = []string{
	"vless://" + uuid1 + "@vless.example.org:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=" + pbk + "&sid=ab12&type=tcp#%F0%9F%87%AF%F0%9F%87%B5%20Tokyo%20Reality",
	"trojan://pass%40word@trojan.example.org:443?security=tls&sni=t.example.org&type=ws&host=t.example.org&path=%2Fws#Trojan-WS",
	"ss://2022-blake3-aes-128-gcm:AAAAAAAAAAAAAAAAAAAAAA%3D%3D@ss.example.org:8388#SS2022",
	"hysteria2://auth-secret@hy2.example.org:8443/?sni=hy2.example.org&obfs=salamander&obfs-password=ob#HY2",
	"tuic://" + uuid2 + ":pw@tuic.example.org:443?congestion_control=bbr&alpn=h3&sni=tuic.example.org#TUIC",
	"anytls://anypass@any.example.org:443?sni=any.example.org#AnyTLS",
}

func TestParseLinkAllSupportedProtocols(t *testing.T) {
	want := []struct {
		proto, server string
		port          int
		name, sec     string
		udp           bool
	}{
		{"vless", "vless.example.org", 443, "🇯🇵 Tokyo Reality", "reality", false},
		{"trojan", "trojan.example.org", 443, "Trojan-WS", "tls", false},
		{"ss", "ss.example.org", 8388, "SS2022", "none", true},
		{"hysteria2", "hy2.example.org", 8443, "HY2", "tls", true},
		{"tuic", "tuic.example.org", 443, "TUIC", "tls", true},
		{"anytls", "any.example.org", 443, "AnyTLS", "tls", false},
	}
	for i, link := range sampleLinks {
		n, err := ParseLink(link)
		if err != nil {
			t.Fatalf("%s: %v", want[i].proto, err)
		}
		w := want[i]
		if n.Protocol != w.proto || n.Server != w.server || n.Port != w.port || n.Name != w.name || n.Security != w.sec || n.UDP != w.udp {
			t.Errorf("%s parsed as %+v", w.proto, n)
		}
		if n.ID == "" || len(n.ID) != 12 || n.Fingerprint == "" {
			t.Errorf("%s: missing identity", w.proto)
		}
		if w.proto != "ss" && n.Link != link {
			t.Errorf("%s: original link must be kept byte for byte:\n got %s\nwant %s", w.proto, n.Link, link)
		}
	}
}

func TestParseLinkKeepsTLSRealityAndTransportParameters(t *testing.T) {
	n, err := ParseLink(sampleLinks[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, must := range []string{"pbk=" + pbk, "sid=ab12", "flow=xtls-rprx-vision", "fp=chrome", "sni=www.microsoft.com", "security=reality"} {
		if !strings.Contains(n.Link, must) {
			t.Errorf("link lost %s", must)
		}
	}
	n, _ = ParseLink(sampleLinks[1])
	if n.Transport != "ws" || !strings.Contains(n.Link, "path=%2Fws") {
		t.Errorf("ws transport lost: %+v", n)
	}
}

func TestLegacyShadowsocksIsNormalised(t *testing.T) {
	legacy := "ss://" + base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:pw123@legacy.example.org:8443")) + "#Legacy%20SS"
	n, err := ParseLink(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if n.Server != "legacy.example.org" || n.Port != 8443 || n.Name != "Legacy SS" {
		t.Fatalf("%+v", n)
	}
	sip := "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:pw123")) + "@legacy.example.org:8443#Other"
	m, err := ParseLink(sip)
	if err != nil {
		t.Fatal(err)
	}
	if m.ID != n.ID {
		t.Fatal("legacy and SIP002 spellings of one account must be the same node")
	}
	if !strings.HasPrefix(n.Link, "ss://"+base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:pw123"))+"@legacy.example.org:8443") {
		t.Fatalf("not normalised to SIP002: %s", n.Link)
	}
	if _, err := ParseLink("ss://" + base64.StdEncoding.EncodeToString([]byte("rc4-md5:pw@x.example.org:1")) + "#x"); !IsUnsupported(err) {
		t.Fatalf("legacy stream ciphers must be refused as unsupported, got %v", err)
	}
}

func TestShadowsocksPluginIsNotedNotDropped(t *testing.T) {
	n, err := ParseLink("ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:pw")) + "@p.example.org:443/?plugin=obfs-local%3Bobfs%3Dtls#Plug")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(n.Link, "plugin=obfs-local") || len(n.Notes) == 0 {
		t.Fatalf("plugin must be preserved in the link and reported: %+v", n)
	}
}

func TestParseLinkRejectsUnsupportedAndMalformed(t *testing.T) {
	cases := map[string]string{
		"vmess://eyJ2IjoiMiJ9":                                            "unsupported",
		"ssr://abc":                                                       "unsupported",
		"hysteria://h.example.org:1?auth=x":                               "unsupported",
		"wireguard://k@h.example.org:1":                                   "unsupported",
		"foo://x@h.example.org:1":                                         "unsupported",
		"vless://not-a-uuid@h.example.org:443":                            "error",
		"vless://" + uuid1 + "@h.example.org:99999":                       "error",
		"vless://" + uuid1 + "@h.example.org:443?encryption=mlkem":        "unsupported",
		"vless://" + uuid1 + "@h.example.org:443?security=weird":          "unsupported",
		"vless://h.example.org:443":                                       "error",
		"trojan://@h.example.org:443":                                     "error",
		"tuic://" + uuid2 + "@h.example.org:443":                          "error",
		"hysteria2://a@h.example.org:1000,2000-3000/":                     "unsupported",
		"anytls://pw@bad_host!.example.org:443":                           "error",
		"not a link":                                                      "error",
		"vless://" + uuid1 + "@127.0.0.1:443?security=none":               "placeholder",
		"trojan://x@example.com:443":                                      "placeholder",
		"vless://" + uuid1 + "@" + strings.Repeat("a", 9000) + ".org:443": "error",
	}
	for link, kind := range cases {
		_, err := ParseLink(link)
		if err == nil {
			t.Errorf("%.60q must fail", link)
			continue
		}
		switch kind {
		case "unsupported":
			if !IsUnsupported(err) {
				t.Errorf("%.60q: want unsupported, got %v", link, err)
			}
		case "placeholder":
			if !IsPlaceholder(err) {
				t.Errorf("%.60q: want placeholder, got %v", link, err)
			}
		}
	}
}

func TestParseListsAndBase64Forms(t *testing.T) {
	plain := strings.Join(sampleLinks, "\n")
	p, err := Parse([]byte(plain))
	if err != nil || p.Format != "links" || len(p.Nodes) != 6 || len(p.Issues) != 0 {
		t.Fatalf("plain list: %v %+v", err, p)
	}
	encoders := map[string]*base64.Encoding{"std": base64.StdEncoding, "raw": base64.RawStdEncoding, "url": base64.URLEncoding, "rawurl": base64.RawURLEncoding}
	for name, enc := range encoders {
		body := enc.EncodeToString([]byte(plain))
		p, err = Parse([]byte(body))
		if err != nil || p.Format != "base64" || len(p.Nodes) != 6 {
			t.Errorf("%s: %v format=%s nodes=%d", name, err, p.Format, len(p.Nodes))
		}
	}
	// MIME-style wrapped Base64, CRLF and a BOM are all tolerated.
	body := base64.StdEncoding.EncodeToString([]byte(plain))
	var wrapped strings.Builder
	for len(body) > 76 {
		wrapped.WriteString(body[:76] + "\r\n")
		body = body[76:]
	}
	wrapped.WriteString(body)
	p, err = Parse([]byte("\xef\xbb\xbf" + wrapped.String()))
	if err != nil || len(p.Nodes) != 6 {
		t.Fatalf("wrapped base64: %v %d", err, len(p.Nodes))
	}
	p, err = Parse([]byte(strings.ReplaceAll(plain, "\n", "\r\n")))
	if err != nil || len(p.Nodes) != 6 {
		t.Fatalf("crlf: %v", err)
	}
}

func TestParseReportsEveryEntryThatIsNotImported(t *testing.T) {
	list := strings.Join([]string{
		sampleLinks[0], sampleLinks[0], // duplicate
		"vmess://eyJ2IjoiMiJ9",
		"vless://bad@h.example.org:443",
		"trojan://x@127.0.0.1:443?security=tls#剩余流量",
		"# a comment is not an entry",
		sampleLinks[2],
	}, "\n")
	p, err := Parse([]byte(list))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Nodes) != 2 || p.Duplicates != 1 || p.Entries != 6 {
		t.Fatalf("nodes=%d dup=%d entries=%d", len(p.Nodes), p.Duplicates, p.Entries)
	}
	var errs, skips int
	for _, is := range p.Issues {
		if is.Reason == "" {
			t.Error("every issue needs a reason")
		}
		switch is.Level {
		case "error":
			errs++
		case "skip":
			skips++
		}
	}
	if errs != 2 || skips != 1 {
		t.Fatalf("errors=%d skips=%d issues=%+v", errs, skips, p.Issues)
	}
	if p.Issues[0].Line != 3 {
		t.Fatalf("issue must name its line: %+v", p.Issues[0])
	}
	for _, is := range p.Issues {
		if strings.Contains(is.Reason, "pass") || strings.Contains(is.Reason, "bad@") {
			t.Fatalf("issues must not echo credentials: %+v", is)
		}
	}
}

func TestParseRejectsWhatItCannotRead(t *testing.T) {
	for name, body := range map[string]string{
		"empty":    "   \n ",
		"garbage":  "this is not a subscription at all!!",
		"singbox":  `{"outbounds":[{"type":"direct"}]}`,
		"provider": "proxy-providers:\n  p:\n    type: http\n    url: https://example.org/x\n",
		"htmlpage": "<html><body>Access denied</body></html>",
	} {
		if _, err := Parse([]byte(body)); err == nil {
			t.Errorf("%s must fail", name)
		}
	}
}

func TestNodeIdentityIgnoresNameButNotCredentials(t *testing.T) {
	a, _ := ParseLink("anytls://pw1@h.example.org:443?sni=h.example.org#One")
	b, _ := ParseLink("anytls://pw1@H.EXAMPLE.ORG:443?sni=h.example.org#Two")
	c, _ := ParseLink("anytls://pw2@h.example.org:443?sni=h.example.org#One")
	if a.ID != b.ID {
		t.Error("renaming or changing host case must not change the identity")
	}
	if a.ID == c.ID {
		t.Error("another credential is another node")
	}
	if a.Loose() != c.Loose() {
		t.Error("loose identity ignores credentials")
	}
}

func TestSetNameKeepsEverythingElse(t *testing.T) {
	got := SetName(sampleLinks[0], "🇸🇬 新名字 #1")
	if !strings.HasPrefix(got, strings.SplitN(sampleLinks[0], "#", 2)[0]+"#") {
		t.Fatal("only the fragment may change")
	}
	n, err := ParseLink(got)
	if err != nil || n.Name != "🇸🇬 新名字 #1" {
		t.Fatalf("renamed link must read back: %v %q", err, n.Name)
	}
}

func TestCleanNameIsSafeEverywhere(t *testing.T) {
	if got := cleanName("a\r\nb\x00c\u2028d"); got != "a b c d" {
		t.Fatalf("%q", got)
	}
	if got := cleanName(strings.Repeat("长", 500)); len([]rune(got)) != maxNameRunes {
		t.Fatalf("name not bounded: %d", len([]rune(got)))
	}
	if got := cleanName("ok\xff\xfe"); got != "ok" {
		t.Fatalf("%q", got)
	}
}

func TestNodeLimit(t *testing.T) {
	var b strings.Builder
	for i := 0; i < MaxNodes+5; i++ {
		fmt.Fprintf(&b, "trojan://pw%d@h%d.example.org:443?security=tls#n%d\n", i, i, i)
	}
	p, err := Parse([]byte(b.String()))
	if err == nil || !strings.Contains(err.Error(), "上限") || len(p.Nodes) != 0 {
		t.Fatalf("an oversized list must be refused as a whole: %v nodes=%d", err, len(p.Nodes))
	}
}

// Parse must never panic or hang, whatever it is given.
func TestParseSurvivesGarbage(t *testing.T) {
	r := rand.New(rand.NewSource(7))
	seeds := append([]string{}, sampleLinks...)
	seeds = append(seeds, "proxies:\n  - {name: a, type: ss, server: a.example.org, port: 1, cipher: aes-128-gcm, password: x}\n")
	alphabet := []byte("abc:/@#?&=-_%[]{} \n\t\"'*&<>!|,.0123456789")
	for i := 0; i < 3000; i++ {
		var in []byte
		if i%3 == 0 {
			in = make([]byte, r.Intn(300))
			for j := range in {
				in[j] = alphabet[r.Intn(len(alphabet))]
			}
		} else {
			in = []byte(seeds[r.Intn(len(seeds))])
			for k := 0; k < 1+r.Intn(6) && len(in) > 0; k++ {
				in[r.Intn(len(in))] = alphabet[r.Intn(len(alphabet))]
			}
		}
		_, _ = Parse(in)
	}
}

func FuzzParse(f *testing.F) {
	for _, s := range sampleLinks {
		f.Add([]byte(s))
	}
	f.Add([]byte("proxies:\n  - {name: a, type: ss, server: a.example.org, port: 1, cipher: aes-128-gcm, password: x}\n"))
	f.Fuzz(func(t *testing.T, in []byte) {
		if len(in) > 1<<16 {
			return
		}
		_, _ = Parse(in)
	})
}
