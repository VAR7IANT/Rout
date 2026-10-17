package rout

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBackupRetentionKeepsNewest(t *testing.T) {
	a := testApp(t)
	a.BackupKeep = 3
	manual := filepath.Join(a.Home, "backups", "manual-keep.json")
	if e := AtomicWrite(manual, []byte("{}"), 0600); e != nil {
		t.Fatal(e)
	}
	p := fixture(t, "ss")
	p.Port, _ = freePort()
	p.PublicPort = p.Port
	s, _ := a.Load()
	if e := a.Commit(s, replace(s, p), false); e != nil {
		t.Fatal(e)
	}
	var newest string
	for i := 0; i < 6; i++ {
		s, _ = a.Load()
		if e := a.Commit(s, s, true); e != nil {
			t.Fatal(e)
		}
		files := a.automaticBackups()
		newest = files[len(files)-1]
	}
	files := a.automaticBackups()
	if len(files) != 3 || files[len(files)-1] != newest {
		t.Fatal("retention did not keep exactly the newest backups", files)
	}
	for _, f := range files {
		if st, _ := os.Stat(f); st.Mode().Perm() != 0600 {
			t.Fatal("backup permissions widened")
		}
	}
	if _, e := os.Stat(manual); e != nil {
		t.Fatal("manual backup was pruned")
	}
	a.pruneBackups(0)
	if len(a.automaticBackups()) != 1 {
		t.Fatal("pruning must never remove the only backup")
	}
	if a.pruneOldestBackup() {
		t.Fatal("removed the last known-good backup to free space")
	}
}

func TestInvalidProtocolCombinations(t *testing.T) {
	a := testApp(t)
	p := fixture(t, "ss")
	p.Network = "udp"
	p.Port, _ = freePort()
	p.PublicPort = p.Port
	ex := Exit{ID: RandomHex(6), Name: "Exit", Proxy: Proxy{"socks5", "192.0.2.10", 1080, "u", "p"}}
	old, _ := a.Load()
	next := UpsertExit(replace(old, p), ex)
	next, _ = BindExit(next, p.ID, ex.ID)
	if e := a.Commit(old, next, false); e == nil || !strings.Contains(e.Error(), "Shadowsocks") {
		t.Fatal("UDP-only Shadowsocks behind a TCP-only exit was accepted", e)
	}
	// The same entry without an exit is valid, and an existing broken state still loads.
	if e := a.Commit(old, replace(old, p), false); e != nil {
		t.Fatal(e)
	}
	b, _ := JSON(next)
	if _, e := DecodeState(b); e != nil {
		t.Fatal("existing configuration became unloadable", e)
	}
	// NAT planning rejects QUIC protocols on TCP-only mappings and adapts SS.
	start, end := freeRange(t, 2)
	setup := ServerSetup{NAT: true, PublicHost: "198.51.100.1", Listen: "127.0.0.1", LocalStart: start, LocalEnd: end, PublicStart: start, Network: "tcp"}
	for _, proto := range []string{"hy2", "tuic"} {
		if _, e := PlanPort(fixture(t, proto), setup, State{Schema: 1}); e == nil {
			t.Fatal(proto, "accepted a TCP-only mapping")
		}
	}
	setup.Network = "udp"
	if _, e := PlanPort(fixture(t, "vless"), setup, State{Schema: 1}); e == nil {
		t.Fatal("VLESS accepted a UDP-only mapping")
	}
}

func TestShadowsocks2022LinkFollowsSIP002(t *testing.T) {
	p := fixture(t, "ss")
	p.Password = "YctPZ6U7xPPcU+gp3u/PVg=="
	p.Name = "Tokyo SS #1"
	uri, e := p.URI()
	if e != nil {
		t.Fatal(e)
	}
	if !strings.HasPrefix(uri, "ss://2022-blake3-aes-128-gcm:YctPZ6U7xPPcU%2Bgp3u%2FPVg%3D%3D@") {
		t.Fatal("AEAD-2022 userinfo must be percent-encoded, not Base64", uri)
	}
	u, _ := url.Parse(uri)
	if pass, _ := u.User.Password(); pass != p.Password || u.Fragment != p.Name {
		t.Fatal("link does not round-trip", uri)
	}
	out, e := URIOutbound(uri)
	if e != nil || out["password"] != p.Password || out["method"] != p.Method {
		t.Fatal("importer cannot read the new link", out, e)
	}
	// Legacy Base64 links remain importable for relays.
	legacy := "ss://" + strings.TrimRight(base64URL(p.Method+":"+p.Password), "=") + "@203.0.113.1:443#old"
	if out, e = URIOutbound(legacy); e != nil || out["password"] != p.Password {
		t.Fatal("legacy SIP002 link no longer imports", e)
	}
}

func TestCertificateExpiryRegenerationAndApply(t *testing.T) {
	a := testApp(t)
	h := fixture(t, "hy2")
	h.Port, _ = freePort()
	h.PublicPort = h.Port
	h.SNI = "example.test"
	h.CertPEM, h.KeyPEM = expiredCertificate(t, "example.test")
	v := fixture(t, "vless")
	v.Port, _ = freePort()
	v.PublicPort = v.Port
	if days, ok := h.CertificateDays(time.Now()); !ok || days >= 0 {
		t.Fatal("expired certificate not reported", days)
	}
	if _, ok := v.CertificateExpiry(); ok {
		t.Fatal("Reality node reported a file certificate")
	}
	// Seed the state directly: an expired certificate that was valid when installed.
	b, _ := JSON(State{Schema: 1, Profiles: []Profile{v, h}})
	if e := AtomicWrite(filepath.Join(a.Home, "state.json"), b, 0600); e != nil {
		t.Fatal(e)
	}
	s, _ := a.Load()
	if e := a.Commit(s, s, true); e != nil {
		t.Fatal("one expired certificate blocked re-applying unrelated nodes", e)
	}
	if _, e := os.Stat(filepath.Join(a.profileDir(v.ID), "config.json")); e != nil {
		t.Fatal("unrelated node was not applied")
	}
	if e := a.Restart(h.ID); e == nil {
		t.Fatal("expired node restarted without renewal")
	}
	oldPin, _ := CertificatePin(h.CertPEM)
	renewed, e := RegenerateCertificate(h)
	if e != nil {
		t.Fatal(e)
	}
	newPin, _ := CertificatePin(renewed.CertPEM)
	days, _ := renewed.CertificateDays(time.Now())
	if newPin == oldPin || !renewed.TLSGenerated || days < 3600 || renewed.Validate() != nil || renewed.Ready() != nil {
		t.Fatal("regeneration did not produce a valid long-lived replacement", days)
	}
	s, _ = a.Load()
	if e = a.Commit(s, replace(s, renewed), false); e != nil {
		t.Fatal(e)
	}
	uri, _ := renewed.URI()
	if !strings.Contains(uri, "pinSHA256="+newPin) {
		t.Fatal("share link does not carry the new pin")
	}
	// The CLI renews only after explicit confirmation.
	u, out := testUI(a, "n\n")
	s, _ = a.Load()
	if e = u.certCommand(s, []string{"cert", "renew", h.ID}); e != nil {
		t.Fatal(e)
	}
	after, _ := a.Load()
	if current, _ := Find(after, h.ID); current.CertPEM != renewed.CertPEM || !strings.Contains(out.String(), "fingerprint") {
		t.Fatal("certificate replaced without confirmation or warning")
	}
}

func TestUpdateRefusesDowngrades(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{{"v0.2.2", "v0.2.1", 1}, {"v0.2.1", "v0.2.2", -1}, {"v0.10.0", "v0.9.9", 1}, {"v1.0.0", "v1.0.0", 0}}
	for _, c := range cases {
		x, ok1 := parseVersion(c.a)
		y, ok2 := parseVersion(c.b)
		if !ok1 || !ok2 || compareVersions(x, y) != c.want {
			t.Fatal("version comparison", c)
		}
	}
	for _, bad := range []string{"0.2.2", "v0.2", "v0.2.2-rc1", "v01.2.3", "latest", "v0.2.x"} {
		if _, ok := parseVersion(bad); ok {
			t.Fatal("accepted release tag", bad)
		}
	}
}

func TestPublicAddressDetectionFamilies(t *testing.T) {
	serve := func(network, body string) string {
		l, e := net.Listen(network, map[string]string{"tcp4": "127.0.0.1:0", "tcp6": "[::1]:0"}[network])
		if e != nil {
			return ""
		}
		s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
		s.Listener = l
		s.Start()
		t.Cleanup(s.Close)
		return s.URL
	}
	dead := "http://127.0.0.1:1"
	saved := ipEndpoints
	t.Cleanup(func() { ipEndpoints = saved })
	// IPv4-only host: IPv6 is simply unavailable, IPv4 is used.
	ipEndpoints = map[string][]string{"tcp4": {serve("tcp4", "203.0.113.7")}, "tcp6": {dead}}
	if v4, v6 := DetectPublicIPs(); v4 != "203.0.113.7" || v6 != "" || DetectPublicIP() != "203.0.113.7" {
		t.Fatal("IPv4-only detection", v4, v6)
	}
	// A wrong-family answer is never accepted.
	ipEndpoints = map[string][]string{"tcp4": {serve("tcp4", "2001:db8::7")}, "tcp6": {dead}}
	if DetectPublicIP() != "" {
		t.Fatal("accepted an IPv6 answer as IPv4")
	}
	v6URL := serve("tcp6", "2001:db8::7")
	if v6URL == "" {
		t.Skip("IPv6 loopback unavailable in this environment")
	}
	// IPv6-only host: no IPv4 requirement.
	ipEndpoints = map[string][]string{"tcp4": {dead}, "tcp6": {v6URL}}
	if ip := DetectPublicIP(); ip != "2001:db8::7" {
		t.Fatal("IPv6-only host needed IPv4", ip)
	}
	a := testApp(t)
	u, _ := testUI(a, "1\n\n\n")
	u.detectIP = DetectPublicIP
	setup, e := u.serverSetup()
	if e != nil || setup.PublicHost != "2001:db8::7" || setup.Listen != "::" {
		t.Fatal("IPv6-only setup did not listen on IPv6", setup, e)
	}
}

func TestGlobalFlagsAnywhereAndNaming(t *testing.T) {
	flags, rest := splitFlags([]string{"list", "--lang", "en", "--home=/tmp/x", "ID", "--", "--lang"})
	if strings.Join(flags, " ") != "--lang en --home=/tmp/x" || strings.Join(rest, " ") != "list ID --lang" {
		t.Fatal("flag split", flags, rest)
	}
	s := State{Profiles: []Profile{{Name: "Tokyo-VLESS"}, {Name: "tokyo-vless-2"}}}
	if n := uniqueName(s, "Tokyo-VLESS"); n != "Tokyo-VLESS-3" {
		t.Fatal("duplicate batch name", n)
	}
	if n := uniqueName(s, "Tokyo-HY2"); n != "Tokyo-HY2" {
		t.Fatal("renamed a unique name", n)
	}
}

func TestPickersHideCredentialsAndLinksExport(t *testing.T) {
	a := testApp(t)
	p := fixture(t, "ss")
	p.Port, _ = freePort()
	p.PublicPort = p.Port
	s, _ := a.Load()
	if e := a.Commit(s, replace(s, p), false); e != nil {
		t.Fatal(e)
	}
	s, _ = a.Load()
	u, out := testUI(a, "0\n")
	if _, e := u.pick(s, false); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(out.String(), p.Password) || strings.Contains(out.String(), "ss://") {
		t.Fatal("selection menu displayed credentials")
	}
	links := AllLinks(s)
	uri, _ := p.URI()
	if !strings.Contains(links, uri) || !strings.Contains(links, p.Name) {
		t.Fatal("export all omitted a node")
	}
	path := filepath.Join(a.Home, "exports", "links.txt")
	u, _ = testUI(a, "y\n"+path+"\n")
	if e := u.exportAll(s); e != nil {
		t.Fatal(e)
	}
	if st, e := os.Stat(path); e != nil || st.Mode().Perm() != 0600 {
		t.Fatal("exported links not private", e)
	}
}

func TestRenderedServiceDefinitions(t *testing.T) {
	a := testApp(t)
	limited := fixture(t, "hy2")
	limited.Traffic = &TrafficPolicy{LimitBytes: 1000, BillingDay: 1}
	unit := a.systemdUnit(limited)
	for _, want := range []string{"ExecStartPre=+", "Requires=rout-traffic-", "CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN", "ProtectSystem=strict", "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK"} {
		if !strings.Contains(unit, want) {
			t.Fatal("systemd unit missing", want)
		}
	}
	if u := a.systemdUnit(fixture(t, "vless")); !strings.Contains(u, "CapabilityBoundingSet=CAP_NET_BIND_SERVICE\n") || strings.Contains(u, "ExecStartPre") {
		t.Fatal("unlimited TCP engine unit")
	}
	for _, p := range []Profile{limited, fixture(t, "ss")} {
		script := a.openrcScript(p)
		path := filepath.Join(t.TempDir(), "init")
		if e := os.WriteFile(path, []byte(script), 0700); e != nil {
			t.Fatal(e)
		}
		if out, e := exec.Command("sh", "-n", path).CombinedOutput(); e != nil {
			t.Fatal("OpenRC script syntax", e, string(out))
		}
		if !strings.Contains(script, "respawn_period=60") || !strings.Contains(script, "mv -f \"$output_log\" \"$output_log.1\"") {
			t.Fatal("OpenRC log/respawn bounds missing")
		}
	}
	if !strings.Contains(a.openrcScript(limited), "|| return 1;") {
		t.Fatal("OpenRC guard missing")
	}
}

func TestSocketBoundReadsProc(t *testing.T) {
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := l.Addr().(*net.TCPAddr).Port
	if !socketBound("tcp", port) {
		t.Fatal("listening TCP socket not detected")
	}
	l.Close()
	if socketBound("tcp", port) {
		t.Fatal("closed socket still detected")
	}
	c, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	if !socketBound("udp", c.LocalAddr().(*net.UDPAddr).Port) {
		t.Fatal("UDP socket not detected")
	}
}

func base64URL(s string) string { return base64.URLEncoding.EncodeToString([]byte(s)) }
func expiredCertificate(t *testing.T, host string) (string, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host}, NotBefore: time.Now().AddDate(-2, 0, 0), NotAfter: time.Now().AddDate(-1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, c, c, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	pk, _ := x509.MarshalPKCS8PrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}))
}
