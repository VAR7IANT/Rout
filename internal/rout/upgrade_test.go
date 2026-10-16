package rout

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"unicode"
)

func testApp(t *testing.T) *App {
	t.Helper()
	a := &App{Home: t.TempDir(), BinDir: t.TempDir(), ServiceMode: "none", Language: "en"}
	if e := os.WriteFile(a.enginePath("sing-box"), []byte("#!/bin/sh\nexit 0\n"), 0755); e != nil {
		t.Fatal(e)
	}
	return a
}
func testUI(a *App, input string) (*UI, *bytes.Buffer) {
	out := &bytes.Buffer{}
	return &UI{a: a, in: bufio.NewReader(strings.NewReader(input)), out: out, detectIP: func() string { return "203.0.113.10" }}, out
}
func TestLanguagePersistenceAndSwitch(t *testing.T) {
	a := testApp(t)
	a.Language = ""
	u, out := testUI(a, "2\n0\n")
	if e := u.menu(); e != nil {
		t.Fatal(e)
	}
	s, e := a.LoadSettings()
	if e != nil || s.Language != "en" {
		t.Fatal("language not persisted")
	}
	if !strings.Contains(out.String(), "Manage exits") {
		t.Fatal("English menu missing")
	}
	a.Language = ""
	u, out = testUI(a, "0\n")
	if e = u.menu(); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(out.String(), "Select language") {
		t.Fatal("asked for language twice")
	}
	u, _ = testUI(a, "1\n1\n")
	if e = u.settings(); e != nil {
		t.Fatal(e)
	}
	s, _ = a.LoadSettings()
	if s.Language != "zh-CN" {
		t.Fatal("language switch not saved")
	}
	if _, e = os.Stat(filepath.Join(a.Home, "state.json")); !os.IsNotExist(e) {
		t.Fatal("language change touched runtime state")
	}
}
func TestCreateBatchAsksCommonFieldsOnce(t *testing.T) {
	a := testApp(t)
	u, out := testUI(a, "1\n\n127.0.0.1\nDMIT-LAX\n1 2 4\nn\ny\n\n1\n\n")
	if e := u.create(); e != nil {
		t.Fatalf("%v\n%s", e, out.String())
	}
	s, e := a.Load()
	if e != nil {
		t.Fatal(e)
	}
	if len(s.Profiles) != 3 {
		t.Fatal("wrong node count")
	}
	for i, name := range []string{"DMIT-LAX-VLESS", "DMIT-LAX-AnyTLS", "DMIT-LAX-HY2"} {
		if s.Profiles[i].Name != name {
			t.Fatal("incorrect generated name")
		}
	}
	if strings.Count(out.String(), "Server type") != 1 || strings.Count(out.String(), "Base node name") != 1 || strings.Count(out.String(), "Public connection IP") != 1 {
		t.Fatal("common setup repeated")
	}
	p := s.Profiles[2]
	if e = p.Ready(); e != nil {
		t.Fatal(e)
	}
	uri, e := p.URI()
	if e != nil {
		t.Fatal(e)
	}
	parsed, _ := url.Parse(uri)
	if parsed.Scheme != "hysteria2" || parsed.Query().Get("pinSHA256") == "" || parsed.Query().Get("insecure") != "1" || !p.TLSGenerated {
		t.Fatal("automatic HY2 URI/TLS missing")
	}
	client, e := ClientConfig(p, p.PublicHost, p.PublicPort, 2080)
	if e != nil {
		t.Fatal(e)
	}
	tlsConf := client["outbounds"].([]any)[0].(M)["tls"].(M)
	if tlsConf["insecure"] == true || tlsConf["certificate"] == nil {
		t.Fatal("client config does not verify certificate")
	}
	u, out = testUI(a, "")
	u.list(s)
	for _, p := range s.Profiles {
		uri, _ := p.URI()
		if !strings.Contains(out.String(), uri) {
			t.Fatal("node list omitted complete URI")
		}
	}
}
func freeRange(t *testing.T, count int) (int, int) {
	t.Helper()
	for i := 0; i < 100; i++ {
		start, e := freePort()
		if e != nil {
			t.Fatal(e)
		}
		if start+count > 65535 {
			continue
		}
		ok := true
		for j := 0; j < count; j++ {
			p := fixture(t, "ss")
			p.Port = start + j
			if CheckAvailable(p) != nil {
				ok = false
				break
			}
		}
		if ok {
			return start, start + count - 1
		}
	}
	t.Fatal("no free range")
	return 0, 0
}
func TestNATPlanningAndBatch(t *testing.T) {
	a := testApp(t)
	start, end := freeRange(t, 5)
	setup := ServerSetup{NAT: true, PublicHost: "198.51.100.1", Listen: "127.0.0.1", LocalStart: start, LocalEnd: end, PublicStart: 20000, Network: "both"}
	s := State{Schema: 1, Profiles: []Profile{}}
	for _, protocol := range []string{"vless", "anytls", "hy2"} {
		p := fixture(t, protocol)
		p, e := PlanPort(p, setup, s)
		if e != nil {
			t.Fatal(e)
		}
		if p.Port < start || p.Port > end || p.PublicPort != 20000+p.Port-start {
			t.Fatal("mapping escaped assigned range")
		}
		s = replace(s, p)
	}
	setup.Network = "tcp"
	if _, e := PlanPort(fixture(t, "hy2"), setup, s); e == nil {
		t.Fatal("HY2 accepted TCP-only NAT")
	}
	ss, e := PlanPort(fixture(t, "ss"), setup, s)
	if e != nil || ss.Network != "tcp" {
		t.Fatal("SS failed to adapt to TCP-only mapping")
	}
	input := fmt.Sprintf("2\n198.51.100.1\n127.0.0.1\n%d-%d\n20000\n1\nNAT-LAX\n1 2\nn\ny\n\n", start, end)
	u, out := testUI(a, input)
	if e = u.create(); e != nil {
		t.Fatalf("%v\n%s", e, out.String())
	}
	actual, _ := a.Load()
	if len(actual.Profiles) != 2 || !actual.Profiles[0].NAT {
		t.Fatal("NAT creation failed")
	}
	if strings.Count(out.String(), "Server type") != 1 || strings.Count(out.String(), "Allowed local port range") != 1 {
		t.Fatal("NAT setup repeated")
	}
}
func TestIndependentReusableExitsAndMigration(t *testing.T) {
	a := testApp(t)
	a.ServiceMode = "auto" // Exit-only edits do not require an init system or engine.
	u, out := testUI(a, "1\nUS-ISP\n1\n192.0.2.10:6719:user:p:a@ss%\n")
	if e := u.exits(); e != nil {
		t.Fatalf("%v\n%s", e, out.String())
	}
	s, e := a.Load()
	if e != nil {
		t.Fatal(e)
	}
	if len(s.Profiles) != 0 || len(s.Exits) != 1 {
		t.Fatal("exit required a node")
	}
	if strings.Contains(out.String(), "p:a@ss%") {
		t.Fatal("exit password displayed")
	}
	a.ServiceMode = "none"
	for _, proto := range []string{"vless", "anytls"} {
		p := fixture(t, proto)
		p.Port, _ = freePort()
		p.PublicPort = p.Port
		s = replace(s, p)
		s, e = BindExit(s, p.ID, s.Exits[0].ID)
		if e != nil {
			t.Fatal(e)
		}
	}
	if e = s.Validate(); e != nil {
		t.Fatal(e)
	}
	if _, e = DeleteExit(s, s.Exits[0].ID); e == nil {
		t.Fatal("deleted an in-use exit")
	}
	ex := s.Exits[0]
	ex.Proxy.Password = "new-secret"
	next := UpsertExit(s, ex)
	for _, p := range next.Profiles {
		if p.Outbound.Password != "new-secret" {
			t.Fatal("shared exit did not update all users")
		}
	}
	legacy := State{Schema: 1, Profiles: append([]Profile{}, s.Profiles...)}
	for i := range legacy.Profiles {
		legacy.Profiles[i].ExitID = ""
	}
	b, _ := JSON(legacy)
	migrated, e := DecodeState(b)
	if e != nil {
		t.Fatal(e)
	}
	if len(migrated.Exits) != 1 || migrated.Profiles[0].ExitID != migrated.Profiles[1].ExitID {
		t.Fatal("legacy proxies not deduplicated")
	}
	again, _ := DecodeState(b)
	if migrated.Exits[0].ID != again.Exits[0].ID {
		t.Fatal("migration IDs are unstable")
	}
	// Keep mirrored outbound fields so older versions still understand the runtime exit.
	b, _ = JSON(migrated)
	var oldReader struct {
		Schema   int
		Profiles []struct{ Outbound *Proxy }
	}
	if e = json.Unmarshal(b, &oldReader); e != nil {
		t.Fatal(e)
	}
	for _, p := range oldReader.Profiles {
		if p.Outbound == nil || *p.Outbound != s.Exits[0].Proxy {
			t.Fatal("legacy outbound was lost")
		}
	}
}
func TestCustomCredentialsAndAtomicNATFailure(t *testing.T) {
	t.Run("custom credentials", func(t *testing.T) {
		a := testApp(t)
		password := "custom:password@123"
		u, out := testUI(a, "1\n127.0.0.1\n127.0.0.1\nCustom\n4\nn\nn\n1\nexample.test\n"+password+"\n")
		if e := u.create(); e != nil {
			t.Fatalf("%v\n%s", e, out.String())
		}
		s, _ := a.Load()
		if len(s.Profiles) != 1 || s.Profiles[0].Password != password {
			t.Fatal("custom credentials not retained")
		}
		uri, _ := s.Profiles[0].URI()
		parsed, _ := url.Parse(uri)
		if parsed.User.Username() != password {
			t.Fatal("share URI corrupted password delimiters")
		}
	})
	t.Run("batch cannot fit", func(t *testing.T) {
		a := testApp(t)
		start, _ := freeRange(t, 1)
		input := fmt.Sprintf("2\n198.51.100.1\n127.0.0.1\n%d\n20000\n1\nSmall\n1 2\nn\ny\n\n", start)
		u, _ := testUI(a, input)
		if e := u.create(); e == nil {
			t.Fatal("expected insufficient NAT ports")
		}
		s, _ := a.Load()
		if len(s.Profiles) != 0 {
			t.Fatal("failed batch partially installed nodes")
		}
		if _, e := os.Stat(filepath.Join(a.Home, "profiles")); !os.IsNotExist(e) {
			t.Fatal("failed batch touched runtime files")
		}
	})
}
func TestExitPreflightFailurePreservesNodes(t *testing.T) {
	a := testApp(t)
	old, _ := a.Load()
	p := fixture(t, "vless")
	p.Port, _ = freePort()
	p.PublicPort = p.Port
	ex := Exit{ID: RandomHex(6), Name: "Shared", Proxy: Proxy{"socks5", "192.0.2.10", 6719, "u", "p"}}
	next := UpsertExit(replace(old, p), ex)
	next, _ = BindExit(next, p.ID, ex.ID)
	if e := a.Commit(old, next, false); e != nil {
		t.Fatal(e)
	}
	stateBefore, _ := os.ReadFile(filepath.Join(a.Home, "state.json"))
	configBefore, _ := os.ReadFile(filepath.Join(a.profileDir(p.ID), "config.json"))
	u, _ := testUI(a, "3\n"+ex.ID+"\n\ny\n1\n192.0.2.11:6719:new:bad\n")
	u.probeProxy = func(Proxy) (string, error) { return "", errors.New("authentication failed") }
	if e := u.exits(); e == nil {
		t.Fatal("accepted a failed shared exit update")
	}
	stateAfter, _ := os.ReadFile(filepath.Join(a.Home, "state.json"))
	configAfter, _ := os.ReadFile(filepath.Join(a.profileDir(p.ID), "config.json"))
	if !bytes.Equal(stateBefore, stateAfter) || !bytes.Equal(configBefore, configAfter) {
		t.Fatal("failed proxy preflight changed live state/config")
	}
}
func TestPreflightAndMetadataDoNotTouchLiveConfig(t *testing.T) {
	a := testApp(t)
	old, _ := a.Load()
	p := fixture(t, "vless")
	p.Port, _ = freePort()
	p.PublicPort = p.Port
	if e := a.Commit(old, replace(old, p), false); e != nil {
		t.Fatal(e)
	}
	old, _ = a.Load()
	path := filepath.Join(a.profileDir(p.ID), "config.json")
	before, _ := os.ReadFile(path)
	if e := os.WriteFile(a.enginePath("sing-box"), []byte("#!/bin/sh\nexit 1\n"), 0755); e != nil {
		t.Fatal(e)
	}
	p.Name = "Renamed"
	p.PublicHost = "203.0.113.99"
	p.PublicPort++
	if e := a.Commit(old, replace(old, p), false); e != nil {
		t.Fatal("metadata unexpectedly revalidated/restarted runtime", e)
	}
	old, _ = a.Load()
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("metadata edit rewrote runtime config")
	}
	p.SNI = "new.example"
	if e := a.Commit(old, replace(old, p), false); e == nil {
		t.Fatal("expected config-check failure")
	}
	actual, _ := a.Load()
	if !reflect.DeepEqual(old, actual) {
		t.Fatal("failed preflight changed state")
	}
	after, _ = os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("failed preflight touched live config")
	}
}
func TestAutomaticCertificateAndPin(t *testing.T) {
	for _, host := range []string{"example.test", "127.0.0.1", "2001:db8::1"} {
		cert, key, e := GenerateCertificate(host)
		if e != nil {
			t.Fatal(e)
		}
		p := fixture(t, "hy2")
		p.SNI = host
		p.CertPEM = cert
		p.KeyPEM = key
		p.TLSGenerated = true
		if e = p.Validate(); e != nil {
			t.Fatal(e)
		}
		if e = p.Ready(); e != nil {
			t.Fatal(e)
		}
		pair, _ := tls.X509KeyPair([]byte(cert), []byte(key))
		sum := sha256.Sum256(pair.Certificate[0])
		pin, _ := CertificatePin(cert)
		if pin != hex.EncodeToString(sum[:]) {
			t.Fatal("incorrect certificate pin")
		}
		uri, _ := p.URI()
		if _, e = URIOutbound(uri); e == nil {
			t.Fatal("pin was silently dropped by the URI importer")
		}
	}
}
func TestEnglishCatalogCoversAllApplicationMessages(t *testing.T) {
	paths, _ := filepath.Glob("*.go")
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, e := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if e != nil {
			t.Fatal(e)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			s, e := strconv.Unquote(lit.Value)
			if e != nil {
				return true
			}
			han := false
			for _, c := range s {
				han = han || unicode.Is(unicode.Han, c)
			}
			if han {
				if _, ok := messages[s]; !ok {
					t.Errorf("missing English translation in %s: %q", path, s)
				}
			}
			return true
		})
	}
	for key, value := range messages {
		if strings.HasPrefix(key, "请选择语言 /") {
			continue
		}
		for _, c := range value {
			if unicode.Is(unicode.Han, c) {
				t.Errorf("English translation contains Chinese: %q", key)
			}
		}
		if len(formatToken.FindAllString(key, -1)) != len(formatToken.FindAllString(value, -1)) {
			t.Errorf("placeholder mismatch: %q", key)
		}
	}
	err := fmt.Errorf("%s: %w", "node", errors.New("证书域名不匹配"))
	if got := Translate("en", err.Error()); got != "node: Certificate does not match the hostname" {
		t.Fatal(got)
	}
	if got := Translate("en", "IP 检测 HTTP 407"); got != "IP check returned HTTP 407" {
		t.Fatal(got)
	}
}
