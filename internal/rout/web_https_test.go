package rout

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// panelFake extends the subscription Caddy fixture with the panel's own probes. The panel
// "answers" like a real host: HTTPS works only while Caddy runs with a site for the domain,
// the certificate is issued (certOK) and the domain is in web.json's allow-list.
type panelFake struct {
	*fakeSubscriptionHTTPS
	sc      *subScene
	panelUp bool
	certOK  bool
	acmeBad map[string]bool
	journal string
}

func newPanelFake(t *testing.T) *panelFake {
	t.Helper()
	sc, f := newFakeSubscriptionHTTPS(t)
	p := &panelFake{fakeSubscriptionHTTPS: f, sc: sc, panelUp: true, certOK: true, acmeBad: map[string]bool{}}
	f.verifyByCaddy = true
	f.runtime.panelProbe = func(domain string, port int) panelVerification {
		v := panelVerification{LocalService: p.panelUp}
		if !p.panelUp {
			return v
		}
		cfg, _ := sc.a.LoadWebConfig()
		v.HostAllowed = domain == "" || hostAllowed(domain, cfg.AllowedHosts)
		serving := f.running && inspectCaddyDomain(f.activeJSON, domain, port).Found
		if serving && !p.certOK {
			v.CertificateError = true
		}
		if serving && p.certOK && v.HostAllowed {
			v.LocalTLS, v.PublicFromHost, v.LoginPage = true, true, true
			v.Issuer, v.Expires = "Fake LE", time.Now().Add(60*24*time.Hour)
		}
		return v
	}
	f.runtime.acmeProbe = func(u string) error {
		if p.acmeBad[u] {
			return errors.New("unreachable")
		}
		return nil
	}
	f.runtime.journal = func() ([]byte, error) { return []byte(p.journal), nil }
	f.runtime.extraAddresses = func() []net.IP { return []net.IP{net.ParseIP("198.51.100.9")} }
	for _, port := range []int{80, 443} {
		f.ports[port] = []httpsListener{{Address: "*:" + itoa(port), Owner: "caddy", PID: 4242}}
	}
	return p
}

func (p *panelFake) read(t *testing.T, path string) string {
	t.Helper()
	b, _ := os.ReadFile(path)
	return string(b)
}

func (p *panelFake) calledWith(part string) int {
	n := 0
	for _, c := range p.calls {
		if strings.Contains(c, part) {
			n++
		}
	}
	return n
}

func TestPanelHTTPSFreshDeploymentIsVerifiedAndIdempotent(t *testing.T) {
	p := newPanelFake(t)
	a := p.sc.a
	res, e := a.DeployWebHTTPS("panel.example.com", WebHTTPSOptions{})
	if e != nil {
		t.Fatal(e)
	}
	if !res.Verification.ok() || res.Pending {
		t.Fatalf("not verified: %+v", res)
	}
	frag := p.read(t, a.webHTTPSFile())
	if !strings.Contains(frag, "panel.example.com {") || !strings.Contains(frag, "reverse_proxy 127.0.0.1:8790") || !strings.Contains(frag, "X-Forwarded-Proto") {
		t.Fatalf("fragment:\n%s", frag)
	}
	main := p.read(t, a.httpsMain())
	if strings.Count(main, "import ") != 1 || !strings.HasPrefix(main, "# existing root configuration\n") {
		t.Fatalf("Caddyfile:\n%s", main)
	}
	cfg, _ := a.LoadWebConfig()
	if cfg.HTTPSDomain != "panel.example.com" || !cfg.SecureCookie || !contains(cfg.AllowedHosts, "panel.example.com") {
		t.Fatalf("web config %+v", cfg)
	}
	st, _ := a.loadWebHTTPSState()
	if st.Ownership != "managed" || st.Pending || st.Digest == "" {
		t.Fatalf("state %+v", st)
	}
	// Repeating the installation changes nothing and creates no duplicate site.
	reloads := p.calledWith("systemctl reload caddy")
	res, e = a.DeployWebHTTPS("panel.example.com", WebHTTPSOptions{})
	if e != nil || !res.Unchanged {
		t.Fatalf("repeat: %+v %v", res, e)
	}
	if p.calledWith("systemctl reload caddy") != reloads {
		t.Fatal("idempotent repair reloaded Caddy")
	}
	if p.read(t, a.httpsMain()) != main || p.read(t, a.webHTTPSFile()) != frag {
		t.Fatal("repeat rewrote files")
	}
	cfg2, _ := a.LoadWebConfig()
	if len(cfg2.AllowedHosts) != len(cfg.AllowedHosts) {
		t.Fatal("repeat duplicated the allowed host")
	}
}

func TestPanelHTTPSRefusesTheSubscriptionDomainAndSuggestsASubdomain(t *testing.T) {
	p := newPanelFake(t)
	a := p.sc.a
	if e := a.DeploySubscriptionHTTPS("hk.oioio.uk", false); e != nil {
		t.Fatal(e)
	}
	subFrag := p.read(t, a.httpsFile())
	before := p.read(t, a.httpsMain())
	_, e := a.DeployWebHTTPS("hk.oioio.uk", WebHTTPSOptions{})
	var used *DomainInUseError
	if !errors.As(e, &used) || used.Suggestion != "panel.hk.oioio.uk" {
		t.Fatalf("got %v", e)
	}
	if !strings.Contains(Translate("en", e.Error()), "hk.oioio.uk is already used by the Rout subscription service") {
		t.Fatal(Translate("en", e.Error()))
	}
	if _, er := os.Stat(a.webHTTPSFile()); !os.IsNotExist(er) || p.read(t, a.httpsMain()) != before {
		t.Fatal("refused deployment wrote files")
	}
	// The suggested sub-domain coexists with the subscription site: one import line, the
	// subscription fragment untouched, both domains served.
	if _, e = a.DeployWebHTTPS(used.Suggestion, WebHTTPSOptions{}); e != nil {
		t.Fatal(e)
	}
	if strings.Count(p.read(t, a.httpsMain()), "import ") != 1 || p.read(t, a.httpsFile()) != subFrag {
		t.Fatal("subscription configuration changed")
	}
	if !inspectCaddyDomain(p.activeJSON, "hk.oioio.uk", 8787).Correct || !inspectCaddyDomain(p.activeJSON, "panel.hk.oioio.uk", 8790).Correct {
		t.Fatal("both sites must be active")
	}
	// Removing the panel site keeps the subscription site.
	if e = a.RemoveWebHTTPS(); e != nil {
		t.Fatal(e)
	}
	if inspectCaddyDomain(p.activeJSON, "panel.hk.oioio.uk", 8790).Found || !inspectCaddyDomain(p.activeJSON, "hk.oioio.uk", 8787).Correct {
		t.Fatal("removal affected the wrong site")
	}
	if p.read(t, a.httpsFile()) != subFrag {
		t.Fatal("removal touched the subscription fragment")
	}
}

func TestPanelHTTPSNeverOverwritesAnExistingSite(t *testing.T) {
	p := newPanelFake(t)
	a := p.sc.a
	path := p.external(t, "panel.example.com", true)
	before := p.read(t, path)
	if _, e := a.DeployWebHTTPS("panel.example.com", WebHTTPSOptions{}); e == nil {
		t.Fatal("existing site overwritten")
	}
	if p.read(t, path) != before {
		t.Fatal("existing site file changed")
	}
	if _, er := os.Stat(a.webHTTPSFile()); !os.IsNotExist(er) {
		t.Fatal("fragment written")
	}
}

func TestPanelHTTPSMultipleImportsArePreserved(t *testing.T) {
	p := newPanelFake(t)
	a := p.sc.a
	sites := filepath.Join(p.runtime.root, "sites")
	os.MkdirAll(sites, 0755)
	os.WriteFile(filepath.Join(sites, "a.caddy"), []byte("a.example.org {\n reverse_proxy 127.0.0.1:9001\n}\n"), 0644)
	os.WriteFile(filepath.Join(sites, "b.caddy"), []byte("b.example.org {\n reverse_proxy 127.0.0.1:9002\n}\n"), 0644)
	main := "# shared\nimport sites/*.caddy\n"
	os.WriteFile(a.httpsMain(), []byte(main), 0644)
	p.activeJSON = p.adapt(a.httpsMain())
	if _, e := a.DeployWebHTTPS("panel.example.com", WebHTTPSOptions{}); e != nil {
		t.Fatal(e)
	}
	got := p.read(t, a.httpsMain())
	if !strings.HasPrefix(got, main) || strings.Count(got, "import ") != 2 {
		t.Fatalf("Caddyfile:\n%s", got)
	}
	for _, d := range []string{"a.example.org", "b.example.org", "panel.example.com"} {
		if !inspectCaddyDomain(p.activeJSON, d, 0).Found {
			t.Fatalf("%s missing after deploy", d)
		}
	}
}

func TestPanelHTTPSValidationAndReloadFailuresRollBack(t *testing.T) {
	for _, fail := range []string{"caddy validate --config " /* the full layout */, "systemctl reload caddy"} {
		t.Run(fail, func(t *testing.T) {
			p := newPanelFake(t)
			a := p.sc.a
			main := p.read(t, a.httpsMain())
			web, _ := os.ReadFile(a.webConfigPath())
			active := append([]byte(nil), p.activeJSON...)
			if fail == "caddy validate --config " {
				fail += a.httpsMain()
			}
			p.fail = fail
			_, e := a.DeployWebHTTPS("panel.example.com", WebHTTPSOptions{})
			if e == nil || errors.Is(e, ErrPanelHTTPSPending) {
				t.Fatalf("got %v", e)
			}
			if !strings.Contains(e.Error(), "previous configuration restored and verified") {
				t.Fatalf("rollback not verified: %v", e)
			}
			if p.read(t, a.httpsMain()) != main {
				t.Fatal("Caddyfile not restored")
			}
			if _, er := os.Stat(a.webHTTPSFile()); !os.IsNotExist(er) {
				t.Fatal("fragment left behind")
			}
			now, _ := os.ReadFile(a.webConfigPath())
			if string(now) != string(web) {
				t.Fatal("web.json not restored")
			}
			if !caddyConfigEqual(p.activeJSON, active) {
				t.Fatal("previous active configuration not reloaded")
			}
		})
	}
}

func TestPanelHTTPSCaddyfileSyntaxErrorChangesNothing(t *testing.T) {
	p := newPanelFake(t)
	a := p.sc.a
	main := p.read(t, a.httpsMain())
	p.fail = "caddy adapt"
	if _, e := a.DeployWebHTTPS("panel.example.com", WebHTTPSOptions{}); e == nil {
		t.Fatal("broken Caddyfile accepted")
	}
	if p.read(t, a.httpsMain()) != main || p.calledWith("systemctl reload") != 0 {
		t.Fatal("changed a broken configuration")
	}
}

func TestPanelHTTPSInstallsCaddyOnlyWithConsent(t *testing.T) {
	p := newPanelFake(t)
	a := p.sc.a
	p.installed, p.running, p.enabled = false, false, false
	p.ports = map[int][]httpsListener{}
	if _, e := a.DeployWebHTTPS("panel.example.com", WebHTTPSOptions{}); e == nil {
		t.Fatal("installed Caddy without consent")
	}
	if p.calledWith("apt-get") != 0 {
		t.Fatal("package manager called without consent")
	}
	if _, e := a.DeployWebHTTPS("panel.example.com", WebHTTPSOptions{HTTPSDeployOptions: HTTPSDeployOptions{AllowInstall: true}}); e != nil {
		t.Fatal(e)
	}
	if p.calledWith("apt-get install -y caddy") != 1 || !p.running {
		t.Fatal("Caddy not installed and started")
	}
}

func TestPanelHTTPSPureIPv6NeedsNoARecord(t *testing.T) {
	p := newPanelFake(t)
	a := p.sc.a
	v6 := "2001:db8::9"
	p.runtime.addresses = func() Addresses { return Addresses{IPv6: v6} }
	p.runtime.extraAddresses = func() []net.IP { return []net.IP{net.ParseIP(v6)} }
	p.runtime.lookup = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP(v6)}, nil }
	if n := a.panelNetwork(); !n.IPv6Only || n.IPv6NAT {
		t.Fatalf("network %+v", n)
	}
	if _, e := a.DeployWebHTTPS("panel.example.com", WebHTTPSOptions{}); e != nil {
		t.Fatal(e)
	}
	guide := strings.Join(dnsGuidance("panel.example.com", a.panelNetwork()), "\n")
	if !strings.Contains(guide, "AAAA  panel.example.com  →  "+v6) || strings.Contains(guide, "A     ") {
		t.Fatalf("guidance:\n%s", guide)
	}
	rep, e := a.WebHTTPSDiagnostics()
	if e != nil {
		t.Fatal(e)
	}
	text := checksText(rep)
	if !strings.Contains(text, "IPv6-only server") || strings.Contains(text, "fail:") {
		t.Fatalf("diagnosis:\n%s", text)
	}
}

func checksText(r WebHTTPSReport) string {
	var b strings.Builder
	for _, c := range r.Checks {
		b.WriteString(c.Level + ": " + c.Text + "\n")
	}
	return b.String()
}

func TestPanelHTTPSWrongOrMissingDNSChangesNothing(t *testing.T) {
	p := newPanelFake(t)
	a := p.sc.a
	main := p.read(t, a.httpsMain())
	v6 := "2001:db8::9"
	p.runtime.addresses = func() Addresses { return Addresses{IPv6: v6} }
	p.runtime.extraAddresses = func() []net.IP { return []net.IP{net.ParseIP(v6)} }
	for _, ips := range [][]net.IP{nil, {net.ParseIP("2001:db8::77")}} {
		p.runtime.lookup = func(string) ([]net.IP, error) {
			if ips == nil {
				return nil, errors.New("NXDOMAIN")
			}
			return ips, nil
		}
		_, e := a.DeployWebHTTPS("panel.example.com", WebHTTPSOptions{})
		var pending *DNSPendingError
		if !errors.As(e, &pending) || len(pending.Records) == 0 || !strings.Contains(pending.Records[0], "AAAA") {
			t.Fatalf("got %v", e)
		}
	}
	if p.read(t, a.httpsMain()) != main || p.calledWith("caddy validate") != 0 {
		t.Fatal("DNS failure touched Caddy")
	}
}

func TestPanelHTTPSPendingCertificateKeepsConfigurationAndRepairs(t *testing.T) {
	p := newPanelFake(t)
	a := p.sc.a
	p.certOK = false
	res, e := a.DeployWebHTTPS("panel.example.com", WebHTTPSOptions{})
	if !errors.Is(e, ErrPanelHTTPSPending) || !res.Pending {
		t.Fatalf("got %+v %v", res, e)
	}
	if !inspectCaddyDomain(p.activeJSON, "panel.example.com", 8790).Found {
		t.Fatal("a valid, loaded configuration was rolled back because issuance is pending")
	}
	st, _ := a.loadWebHTTPSState()
	if !st.Pending || st.LastError == "" {
		t.Fatalf("pending not recorded: %+v", st)
	}
	// The certificate arrives: repair verifies, clears the state, and reloads nothing.
	p.certOK = true
	reloads := p.calledWith("systemctl reload caddy")
	res, e = a.RepairWebHTTPS(WebHTTPSOptions{})
	if e != nil || !res.Verification.ok() {
		t.Fatalf("repair: %+v %v", res, e)
	}
	if p.calledWith("systemctl reload caddy") != reloads {
		t.Fatal("repair reloaded a correct configuration")
	}
	st, _ = a.loadWebHTTPSState()
	if st.Pending || st.LastError != "" {
		t.Fatalf("pending not cleared: %+v", st)
	}
}

func TestPanelHTTPSNATNeedsExplicitConfirmation(t *testing.T) {
	p := newPanelFake(t)
	a := p.sc.a
	p.runtime.addresses = func() Addresses { return Addresses{IPv4: "198.51.100.9"} }
	p.runtime.extraAddresses = func() []net.IP { return []net.IP{net.ParseIP("10.0.0.5")} }
	_, e := a.DeployWebHTTPS("panel.example.com", WebHTTPSOptions{})
	var nat *NATConfirmError
	if !errors.As(e, &nat) {
		t.Fatalf("got %v", e)
	}
	if p.calledWith("caddy validate") != 0 {
		t.Fatal("NAT host deployed without confirmation")
	}
	if _, e = a.DeployWebHTTPS("panel.example.com", WebHTTPSOptions{AcceptNAT: true}); e != nil {
		t.Fatal(e)
	}
}

func TestPanelHTTPSRestartedServiceRecovers(t *testing.T) {
	p := newPanelFake(t)
	a := p.sc.a
	if _, e := a.DeployWebHTTPS("panel.example.com", WebHTTPSOptions{}); e != nil {
		t.Fatal(e)
	}
	p.panelUp = false
	if _, e := a.RepairWebHTTPS(WebHTTPSOptions{}); e == nil {
		t.Fatal("a stopped panel was reported as working")
	}
	rep, _ := a.WebHTTPSDiagnostics()
	if !strings.Contains(checksText(rep), "fail: The panel service does not answer on 127.0.0.1:8790") {
		t.Fatalf("diagnosis:\n%s", checksText(rep))
	}
	p.panelUp = true
	if _, e := a.RepairWebHTTPS(WebHTTPSOptions{}); e != nil {
		t.Fatal(e)
	}
}

func TestPanelHTTPSDiagnosisSeparatesLayersAndClassifiesCaddyLogs(t *testing.T) {
	p := newPanelFake(t)
	a := p.sc.a
	p.certOK = false
	_, _ = a.DeployWebHTTPS("panel.example.com", WebHTTPSOptions{})
	p.journal = strings.Join([]string{
		`{"level":"error","msg":"could not get certificate from issuer","identifier":"panel.example.com","error":"DNS problem: NXDOMAIN looking up A for panel.example.com"}`,
		`{"level":"error","msg":"caddy_legacy_user_removed"}`,
		`{"level":"error","identifier":"panel.example.com","error":"remote error: tls: alert internal error"}`,
		`{"level":"error","identifier":"panel.example.com","error":"read: connection reset by peer"}`,
		`{"level":"error","identifier":"other.example.org","error":"secret-other-site rateLimited"}`,
	}, "\n")
	p.acmeBad["https://acme-staging-v02.api.letsencrypt.org/directory"] = true
	rep, e := a.WebHTTPSDiagnostics()
	if e != nil {
		t.Fatal(e)
	}
	text := checksText(rep)
	for _, want := range []string{"NXDOMAIN", "caddy_legacy_user_removed", "internal error", "Connection reset", "ok: Let's Encrypt production is reachable", "info: Let's Encrypt staging unreachable", "fail: The HTTPS certificate is invalid or not issued yet"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in\n%s", want, text)
		}
	}
	if strings.Contains(text, "rate limit") || strings.Contains(text, "secret-other-site") || strings.Contains(text, "other.example.org") {
		t.Fatalf("another site's log line leaked into the diagnosis:\n%s", text)
	}
	if !rep.Pending {
		t.Fatal("pending state not reported")
	}
}

func TestPanelHTTPSRefusesAnEditedFragment(t *testing.T) {
	p := newPanelFake(t)
	a := p.sc.a
	if _, e := a.DeployWebHTTPS("panel.example.com", WebHTTPSOptions{}); e != nil {
		t.Fatal(e)
	}
	os.WriteFile(a.webHTTPSFile(), []byte("# edited by the administrator\npanel.example.com {\n reverse_proxy 127.0.0.1:8790\n}\n"), 0644)
	if _, e := a.DeployWebHTTPS("panel.example.com", WebHTTPSOptions{}); e == nil {
		t.Fatal("edited fragment overwritten")
	}
	if e := a.RemoveWebHTTPS(); e == nil {
		t.Fatal("edited fragment removed")
	}
}

func TestWebMenuSetupAndPasswordAreNeverEchoedTwice(t *testing.T) {
	p := newPanelFake(t)
	a := p.sc.a
	webPBKDF2Iterations = 1000
	u, out := testUI(a, "1\n1\npanel.example.com\n0\n")
	var actions []string
	u.webService = func(action string) error { actions = append(actions, action); return nil }
	if e := u.webMenu(); e != nil {
		t.Fatal(e)
	}
	text := out.String()
	for _, want := range []string{"Web management panel", "One-click install / initialize panel", "Rout Web installed successfully", "https://panel.example.com", "DNS verified", "Login page reachable"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in\n%s", want, text)
		}
	}
	if len(actions) != 1 || actions[0] != "install" {
		t.Fatalf("service actions %v", actions)
	}
	cfg, _ := a.LoadWebConfig()
	if cfg.PasswordHash == "" {
		t.Fatal("no password set")
	}
	// The generated password appears exactly once in the whole session output.
	line := ""
	for _, l := range strings.Split(text, "\n") {
		if strings.Contains(l, "(shown only once):") {
			line = l
		}
	}
	if line == "" {
		t.Fatalf("password line missing:\n%s", text)
	}
	pw := strings.TrimSpace(line[strings.LastIndex(line, ":")+1:])
	if len(pw) < 12 || strings.Count(text, pw) != 1 {
		t.Fatalf("password printed %d times", strings.Count(text, pw))
	}
}

func TestWebMenuSuggestsSubdomainWhenTheSubscriptionUsesTheDomain(t *testing.T) {
	p := newPanelFake(t)
	a := p.sc.a
	if e := a.DeploySubscriptionHTTPS("hk.oioio.uk", false); e != nil {
		t.Fatal(e)
	}
	u, out := testUI(a, "4\nhk.oioio.uk\n1\n0\n")
	u.webService = func(string) error { return nil }
	if e := u.webMenu(); e != nil {
		t.Fatal(e)
	}
	text := out.String()
	for _, want := range []string{"hk.oioio.uk is already used by the Rout subscription service", "Suggested panel domain: panel.hk.oioio.uk", "Use the suggested domain", "Enter another domain", "https://panel.hk.oioio.uk"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in\n%s", want, text)
		}
	}
}

// ---- remove and redeploy (Codex P2: the removed placeholder must stay Rout's) -----------------

func (p *panelFake) deploy(t *testing.T, domain string) {
	t.Helper()
	if _, e := p.sc.a.DeployWebHTTPS(domain, WebHTTPSOptions{}); e != nil {
		t.Fatalf("deploy %s: %v", domain, e)
	}
}

// subscriptionSnapshot captures what the subscription site must never lose.
type subscriptionSnapshot struct {
	fragment, state string
	publicURL       string
}

func (p *panelFake) subscriptionSnapshot(t *testing.T) subscriptionSnapshot {
	t.Helper()
	a := p.sc.a
	cfg, _ := a.subscriptionSettings()
	return subscriptionSnapshot{fragment: p.read(t, a.httpsFile()), state: p.read(t, filepath.Join(a.Home, "state.json")), publicURL: cfg.PublicURL}
}

func (p *panelFake) assertSubscriptionIntact(t *testing.T, before subscriptionSnapshot, token string) {
	t.Helper()
	after := p.subscriptionSnapshot(t)
	if after != before {
		t.Fatal("the panel changed the subscription site, its URL or the stored state")
	}
	assertSubscriptionStorage(t, p.sc.a, []byte(before.state), token)
	if !inspectCaddyDomain(p.activeJSON, "hk.oioio.uk", 8787).Correct {
		t.Fatal("the subscription site is no longer served by Caddy")
	}
}

func TestPanelHTTPSDeployRemoveDeploySucceedsAndKeepsTheSubscription(t *testing.T) {
	p := newPanelFake(t)
	a := p.sc.a
	_, token := p.sc.create(t, "Shadowrocket", 2, 0)
	if e := a.DeploySubscriptionHTTPS("hk.oioio.uk", false); e != nil {
		t.Fatal(e)
	}
	before := p.subscriptionSnapshot(t)
	p.deploy(t, "panel.hk.oioio.uk")
	if e := a.RemoveWebHTTPS(); e != nil {
		t.Fatal(e)
	}
	placeholder := p.read(t, a.webHTTPSFile())
	if strings.Contains(placeholder, "reverse_proxy") || inspectCaddyDomain(p.activeJSON, "panel.hk.oioio.uk", 8790).Found {
		t.Fatalf("removal left the site behind:\n%s", placeholder)
	}
	st, _ := a.loadWebHTTPSState()
	if !st.Removed || st.Ownership != "managed" || st.Digest != hashToken(placeholder) {
		t.Fatalf("state after removal %+v", st)
	}
	p.assertSubscriptionIntact(t, before, token)
	// Redeploy over Rout's own, digest-verified placeholder.
	res, e := a.DeployWebHTTPS("panel.hk.oioio.uk", WebHTTPSOptions{})
	if e != nil || !res.Verification.ok() {
		t.Fatalf("redeploy after removal: %+v %v", res, e)
	}
	site := p.read(t, a.webHTTPSFile())
	if !strings.Contains(site, "panel.hk.oioio.uk {") || !strings.Contains(site, "reverse_proxy 127.0.0.1:8790") {
		t.Fatalf("fragment:\n%s", site)
	}
	st, _ = a.loadWebHTTPSState()
	if st.Removed || st.Pending || st.Ownership != "managed" || st.Domain != "panel.hk.oioio.uk" || st.Digest != hashToken(site) {
		t.Fatalf("state after redeploy %+v", st)
	}
	if strings.Count(p.read(t, a.httpsMain()), "import ") != 1 {
		t.Fatal("redeploy added a second import line")
	}
	if !inspectCaddyDomain(p.activeJSON, "panel.hk.oioio.uk", 8790).Correct {
		t.Fatal("the panel site is not active after redeploy")
	}
	p.assertSubscriptionIntact(t, before, token)
	// The cycle can be repeated, and each step is idempotent.
	if e = a.RemoveWebHTTPS(); e != nil {
		t.Fatal(e)
	}
	reloads := p.calledWith("systemctl reload caddy")
	if e = a.RemoveWebHTTPS(); e != nil || p.calledWith("systemctl reload caddy") != reloads {
		t.Fatalf("a second removal was not a no-op: %v", e)
	}
	p.deploy(t, "panel.hk.oioio.uk")
	reloads = p.calledWith("systemctl reload caddy")
	if res, e = a.DeployWebHTTPS("panel.hk.oioio.uk", WebHTTPSOptions{}); e != nil || !res.Unchanged || p.calledWith("systemctl reload caddy") != reloads {
		t.Fatalf("a repeated deploy was not a no-op: %+v %v", res, e)
	}
	p.assertSubscriptionIntact(t, before, token)
}

// Repair resumes a site that exists; after an explicit removal there is nothing to resume, so
// it says how to deploy again instead of resurrecting a site the administrator removed.
func TestPanelHTTPSRepairAfterRemovalAsksForADomainAndChangesNothing(t *testing.T) {
	p := newPanelFake(t)
	a := p.sc.a
	p.deploy(t, "panel.example.com")
	if e := a.RemoveWebHTTPS(); e != nil {
		t.Fatal(e)
	}
	files := p.read(t, a.webHTTPSFile()) + p.read(t, a.httpsMain()) + p.read(t, a.webHTTPSStatePath())
	reloads := p.calledWith("systemctl reload caddy")
	_, e := a.RepairWebHTTPS(WebHTTPSOptions{})
	if e == nil || !strings.Contains(Translate("en", e.Error()), "rout web https deploy DOMAIN") {
		t.Fatalf("repair after removal: %v", e)
	}
	if p.read(t, a.webHTTPSFile())+p.read(t, a.httpsMain())+p.read(t, a.webHTTPSStatePath()) != files || p.calledWith("systemctl reload caddy") != reloads {
		t.Fatal("a refused repair changed something")
	}
	// Deploying with the explicit domain works, and a later repair is then the normal one.
	p.deploy(t, "panel.example.com")
	if res, e := a.RepairWebHTTPS(WebHTTPSOptions{}); e != nil || !res.Unchanged {
		t.Fatalf("repair after redeploy: %+v %v", res, e)
	}
}

func TestPanelHTTPSRemovalLeavesNoStaleHostOrCookiePolicy(t *testing.T) {
	p := newPanelFake(t)
	a := p.sc.a
	p.deploy(t, "panel.example.com")
	if e := a.RemoveWebHTTPS(); e != nil {
		t.Fatal(e)
	}
	cfg, _ := a.LoadWebConfig()
	if contains(cfg.AllowedHosts, "panel.example.com") || cfg.HTTPSDomain != "" || cfg.SecureCookie {
		t.Fatalf("web.json after removal: %+v", cfg)
	}
	// A host the administrator added by hand is theirs and stays, with its cookie policy.
	if e := a.mutateWebConfig(func(c *WebConfig) error { c.AllowedHosts = append(c.AllowedHosts, "manual.example.org"); return nil }); e != nil {
		t.Fatal(e)
	}
	p.deploy(t, "panel.example.com")
	if e := a.RemoveWebHTTPS(); e != nil {
		t.Fatal(e)
	}
	cfg, _ = a.LoadWebConfig()
	if !contains(cfg.AllowedHosts, "manual.example.org") || contains(cfg.AllowedHosts, "panel.example.com") || !cfg.SecureCookie {
		t.Fatalf("a manually allowed host was disturbed: %+v", cfg)
	}
}

func TestPanelHTTPSEditedPlaceholderIsNeverOverwritten(t *testing.T) {
	p := newPanelFake(t)
	a := p.sc.a
	p.deploy(t, "panel.example.com")
	if e := a.RemoveWebHTTPS(); e != nil {
		t.Fatal(e)
	}
	edited := "# placeholder edited by the administrator\nadmin.example.org {\n respond \"hand written\" 200\n}\n"
	if e := os.WriteFile(a.webHTTPSFile(), []byte(edited), 0644); e != nil {
		t.Fatal(e)
	}
	p.activeJSON = p.adapt(a.httpsMain()) // the administrator reloaded Caddy after editing
	main := p.read(t, a.httpsMain())
	reloads := p.calledWith("systemctl reload caddy")
	_, e := a.DeployWebHTTPS("panel.example.com", WebHTTPSOptions{})
	if e == nil || !strings.Contains(Translate("en", e.Error()), "changed externally") {
		t.Fatalf("an edited placeholder was not refused: %v", e)
	}
	if p.read(t, a.webHTTPSFile()) != edited || p.read(t, a.httpsMain()) != main || p.calledWith("systemctl reload caddy") != reloads {
		t.Fatal("the edited file or Caddy was touched")
	}
	// The same protection for a domain change, and for removal being repeated.
	if _, e = a.DeployWebHTTPS("other.example.com", WebHTTPSOptions{}); e == nil || p.read(t, a.webHTTPSFile()) != edited {
		t.Fatalf("edited placeholder overwritten by a new domain: %v", e)
	}
	if e = a.RemoveWebHTTPS(); e != nil || p.read(t, a.webHTTPSFile()) != edited {
		t.Fatalf("removal touched an edited placeholder: %v", e)
	}
}

func TestPanelHTTPSDeletedPlaceholderIsRecreated(t *testing.T) {
	p := newPanelFake(t)
	a := p.sc.a
	p.deploy(t, "panel.example.com")
	if e := a.RemoveWebHTTPS(); e != nil {
		t.Fatal(e)
	}
	if e := os.Remove(a.webHTTPSFile()); e != nil { // for example /etc/caddy was purged
		t.Fatal(e)
	}
	p.deploy(t, "panel.example.com")
	if !strings.Contains(p.read(t, a.webHTTPSFile()), "reverse_proxy 127.0.0.1:8790") {
		t.Fatal("site not recreated")
	}
}

func TestPanelHTTPSDomainChangeAfterRemovalAndOnALiveSite(t *testing.T) {
	p := newPanelFake(t)
	a := p.sc.a
	_, token := p.sc.create(t, "Shadowrocket", 2, 0)
	if e := a.DeploySubscriptionHTTPS("hk.oioio.uk", false); e != nil {
		t.Fatal(e)
	}
	before := p.subscriptionSnapshot(t)
	p.deploy(t, "one.example.com")
	if e := a.RemoveWebHTTPS(); e != nil {
		t.Fatal(e)
	}
	p.deploy(t, "two.example.com") // a different domain over the removed placeholder
	if inspectCaddyDomain(p.activeJSON, "one.example.com", 8790).Found || !inspectCaddyDomain(p.activeJSON, "two.example.com", 8790).Correct {
		t.Fatal("wrong domain served after a change over the placeholder")
	}
	cfg, _ := a.LoadWebConfig()
	if cfg.HTTPSDomain != "two.example.com" || contains(cfg.AllowedHosts, "one.example.com") {
		t.Fatalf("web.json %+v", cfg)
	}
	// A live site can be moved to another domain without a removal in between.
	p.deploy(t, "three.example.com")
	if inspectCaddyDomain(p.activeJSON, "two.example.com", 8790).Found || !inspectCaddyDomain(p.activeJSON, "three.example.com", 8790).Correct {
		t.Fatal("wrong domain served after moving a live site")
	}
	if cfg, _ = a.LoadWebConfig(); cfg.HTTPSDomain != "three.example.com" || contains(cfg.AllowedHosts, "two.example.com") || strings.Count(p.read(t, a.httpsMain()), "import ") != 1 {
		t.Fatalf("web.json %+v", cfg)
	}
	p.assertSubscriptionIntact(t, before, token)
}

func TestPanelHTTPSFailedRedeployAfterRemovalRollsBackAndCanBeRetried(t *testing.T) {
	for _, fail := range []string{"systemctl reload caddy", "caddy validate --config {main}"} {
		t.Run(fail, func(t *testing.T) {
			p := newPanelFake(t)
			a := p.sc.a
			_, token := p.sc.create(t, "Shadowrocket", 2, 0)
			if e := a.DeploySubscriptionHTTPS("hk.oioio.uk", false); e != nil {
				t.Fatal(e)
			}
			before := p.subscriptionSnapshot(t)
			p.deploy(t, "panel.hk.oioio.uk")
			if e := a.RemoveWebHTTPS(); e != nil {
				t.Fatal(e)
			}
			placeholder, main := p.read(t, a.webHTTPSFile()), p.read(t, a.httpsMain())
			web, _ := os.ReadFile(a.webConfigPath())
			active := append([]byte(nil), p.activeJSON...)
			p.fail = strings.ReplaceAll(fail, "{main}", a.httpsMain())
			_, e := a.DeployWebHTTPS("panel.hk.oioio.uk", WebHTTPSOptions{})
			if e == nil || errors.Is(e, ErrPanelHTTPSPending) || !strings.Contains(e.Error(), "previous configuration restored and verified") {
				t.Fatalf("got %v", e)
			}
			if p.read(t, a.webHTTPSFile()) != placeholder || p.read(t, a.httpsMain()) != main {
				t.Fatal("files not restored byte for byte")
			}
			if now, _ := os.ReadFile(a.webConfigPath()); string(now) != string(web) {
				t.Fatal("web.json not restored")
			}
			if !caddyConfigEqual(p.activeJSON, active) {
				t.Fatal("the previous active Caddy configuration was not restored")
			}
			st, _ := a.loadWebHTTPSState()
			if !st.Removed || st.Digest != hashToken(placeholder) || st.LastError == "" {
				t.Fatalf("state must stay consistent with the restored placeholder: %+v", st)
			}
			p.assertSubscriptionIntact(t, before, token)
			// The failure left nothing that blocks the next attempt.
			p.deploy(t, "panel.hk.oioio.uk")
			if !inspectCaddyDomain(p.activeJSON, "panel.hk.oioio.uk", 8790).Correct {
				t.Fatal("retry did not deploy")
			}
			p.assertSubscriptionIntact(t, before, token)
		})
	}
}
