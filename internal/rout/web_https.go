package rout

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Panel HTTPS: one-click Caddy deployment for the management panel.
//
// It reuses everything the subscription HTTPS deployment already proved (the per-App Caddy
// runtime, the layout and port checks, private snapshots, `caddy validate`, verified
// reloads and rollback) and adds only what is specific to the panel:
//
//   - its own fragment, panel.caddy, in Rout's private Caddy directory next to the
//     subscription fragment, pulled in by the same single import line (never a second one);
//   - its own ownership record, web-https.json, with the fragment's digest. Rout edits or
//     removes the fragment only while the file still matches that digest;
//   - a domain already used by the subscription site is never reused: an independent
//     sub-domain (panel.<domain>) is suggested instead, so no duplicate site definition can
//     ever be produced;
//   - certificate issuance is asynchronous. A Caddy configuration that validated and
//     reloaded is KEPT when the certificate is not yet issued (Caddy keeps retrying and no
//     other site is affected); the state is recorded as pending with a diagnosis and
//     `rout web https repair` resumes. A failed validation or reload is rolled back.
//
// The panel itself keeps listening on 127.0.0.1 only.

const webHTTPSVersion = 1

type webHTTPSState struct {
	Version   int       `json:"version"`
	Domain    string    `json:"domain,omitempty"`
	Ownership string    `json:"ownership,omitempty"` // managed, external
	Main      string    `json:"main,omitempty"`
	File      string    `json:"file,omitempty"`
	Digest    string    `json:"digest,omitempty"`
	Pending   bool      `json:"pending,omitempty"` // configured, certificate/endpoint not verified yet
	Removed   bool      `json:"removed,omitempty"`
	LastError string    `json:"last_error,omitempty"`
	Updated   time.Time `json:"updated,omitempty"`
}

func (a *App) webHTTPSStatePath() string { return filepath.Join(a.Home, "web-https.json") }
func (a *App) webHTTPSFile() string {
	return filepath.Join(filepath.Dir(a.httpsFile()), "panel.caddy")
}

func (a *App) loadWebHTTPSState() (webHTTPSState, error) {
	var s webHTTPSState
	b, e := os.ReadFile(a.webHTTPSStatePath())
	if os.IsNotExist(e) {
		return s, nil
	}
	if e != nil {
		return s, e
	}
	if json.Unmarshal(b, &s) != nil || s.Version != webHTTPSVersion {
		return s, errors.New("面板 HTTPS 记录文件 web-https.json 无效；请保留文件并检查")
	}
	if s.Domain != "" {
		if _, e := subscriptionDomain(s.Domain); e != nil {
			return s, errors.New("面板 HTTPS 记录文件 web-https.json 无效；请保留文件并检查")
		}
	}
	if s.Ownership != "" && s.Ownership != "managed" && s.Ownership != "external" {
		return s, errors.New("面板 HTTPS 记录文件 web-https.json 无效；请保留文件并检查")
	}
	return s, nil
}

func (a *App) saveWebHTTPSState(s webHTTPSState) error {
	s.Version = webHTTPSVersion
	s.Updated = time.Now().UTC()
	b, e := JSON(s)
	if e != nil {
		return e
	}
	old, e := snapshotSubscriptionFile(a.webHTTPSStatePath())
	if e != nil {
		return e
	}
	return atomicSubscriptionFile(old, b, 0600)
}

// renderPanelCaddy is the panel's site. The marker line identifies the file; ownership is
// still decided by the recorded digest, never by the marker.
func renderPanelCaddy(domain string, port int) string {
	return "# Rout web panel HTTPS v1\n" + caddySnippet(domain, port)
}

// ownedPanelFragment returns the fragment when it is still exactly what Rout wrote.
func (a *App) ownedPanelFragment(s webHTTPSState) (subscriptionFileSnapshot, error) {
	r := a.httpsRuntime()
	if s.Ownership != "managed" || s.File == "" || !safeProxyPath(r.root, s.File) || s.Main != a.httpsMain() {
		return subscriptionFileSnapshot{}, errors.New("面板 HTTPS 配置不是由 Rout 管理的，不会自动修改")
	}
	f, e := snapshotSubscriptionFile(s.File)
	if e != nil {
		return f, e
	}
	if !f.Exists || hashToken(string(f.Data)) != s.Digest {
		return f, errors.New("Rout 管理的面板 HTTPS 配置已被外部修改；已保留文件，请检查后再继续")
	}
	return f, nil
}

// ---- domain conflicts ---------------------------------------------------------------------

// DomainInUseError says the domain already belongs to Rout's subscription site. A second
// site with the same name would make Caddy reject the whole configuration (ambiguous site
// definition), so an independent sub-domain is suggested instead.
type DomainInUseError struct {
	Domain, Suggestion string
}

func (e *DomainInUseError) Error() string {
	return fmt.Sprintf("检测到 %s 已被 Rout 订阅服务使用", e.Domain)
}

// subscriptionDomains lists every domain Rout's subscription HTTPS uses.
func (a *App) subscriptionDomains() []string {
	var out []string
	add := func(d string) {
		if d != "" && !contains(out, d) {
			out = append(out, d)
		}
	}
	if s, e := a.loadHTTPSState(); e == nil && !s.Removed {
		add(s.Domain)
		for _, d := range s.Domains {
			add(d)
		}
	}
	if cfg, e := a.subscriptionSettings(); e == nil && cfg.PublicURL != "" {
		if u, er := url.Parse(cfg.PublicURL); er == nil {
			add(strings.ToLower(u.Hostname()))
		}
	}
	return out
}

func (a *App) checkPanelDomain(domain string) error {
	if contains(a.subscriptionDomains(), domain) {
		return &DomainInUseError{Domain: domain, Suggestion: "panel." + domain}
	}
	return nil
}

// ---- network facts ------------------------------------------------------------------------

// PanelNetwork describes how the Internet reaches this server: public addresses per family,
// whether that address is configured on an interface (otherwise a NAT maps it) and whether
// the server is IPv6-only.
type PanelNetwork struct {
	IPv4     string `json:"ipv4,omitempty"`
	IPv6     string `json:"ipv6,omitempty"`
	IPv4NAT  bool   `json:"ipv4_nat"`
	IPv6NAT  bool   `json:"ipv6_nat"`
	IPv6Only bool   `json:"ipv6_only"`
}

func (a *App) panelNetwork() PanelNetwork {
	r := a.httpsRuntime()
	addr := r.addresses()
	out := PanelNetwork{IPv4: addr.IPv4, IPv6: addr.IPv6}
	onInterface := func(ip string) bool {
		want := net.ParseIP(ip)
		if want == nil || r.extraAddresses == nil {
			return true // cannot tell: do not claim NAT
		}
		for _, have := range r.extraAddresses() {
			if have.Equal(want) {
				return true
			}
		}
		return false
	}
	out.IPv4NAT = out.IPv4 != "" && !onInterface(out.IPv4)
	out.IPv6NAT = out.IPv6 != "" && !onInterface(out.IPv6)
	out.IPv6Only = out.IPv4 == "" && out.IPv6 != ""
	return out
}

// dnsGuidance tells the user exactly which records to create, per family. An IPv6-only
// server needs only AAAA; a missing A record is never an error there.
func dnsGuidance(domain string, n PanelNetwork) []string {
	var out []string
	if n.IPv6 != "" {
		out = append(out, fmt.Sprintf("AAAA  %s  →  %s", domain, n.IPv6))
	}
	if n.IPv4 != "" {
		out = append(out, fmt.Sprintf("A     %s  →  %s", domain, n.IPv4))
	} else if n.IPv6 != "" {
		out = append(out, "本机没有公网 IPv4：不要添加 A 记录（多余的 A 记录会让证书签发失败）")
	}
	if len(out) == 0 {
		out = append(out, "未能检测到本机公网地址；请确认网络后重试")
	}
	return out
}

// DNSPendingError carries the records to create; nothing was changed.
type DNSPendingError struct {
	Domain, Cause string
	Records       []string
}

func (e *DNSPendingError) Error() string {
	return fmt.Sprintf("域名 %s 的 DNS 尚未指向本机：%s", e.Domain, e.Cause)
}

// natProblem explains why ACME cannot reach a NAT-mapped family directly.
func natProblem(d httpsDNS, n PanelNetwork) string {
	if len(d.A) > 0 && n.IPv4NAT {
		return "本机公网 IPv4 由 NAT 映射：只有当服务商把公网 TCP 80 和 443 端口原样转发到本机时，证书才能签发；只提供高位端口映射的 NAT VPS 无法使用此方式，请改用 SSH 隧道访问面板，或使用带公网 IPv6 的 AAAA 记录"
	}
	if len(d.AAAA) > 0 && n.IPv6NAT {
		return "本机公网 IPv6 不在网卡上（可能经过 NAT/转发）：请确认公网 TCP 80 和 443 端口会转发到本机"
	}
	return ""
}

// ---- verification -------------------------------------------------------------------------

type panelVerification struct {
	LocalService     bool      `json:"local_service"`
	HostAllowed      bool      `json:"host_allowed"`
	LocalTLS         bool      `json:"local_tls"`
	PublicFromHost   bool      `json:"public_https"`
	LoginPage        bool      `json:"login_page"`
	CertificateError bool      `json:"certificate_error"`
	Expires          time.Time `json:"expires,omitempty"`
	Issuer           string    `json:"issuer,omitempty"`
}

func (v panelVerification) ok() bool {
	return v.LocalService && v.HostAllowed && v.LocalTLS && v.PublicFromHost && v.LoginPage
}

func panelHealth(client *http.Client, base, host string) (int, *tls.ConnectionState, error) {
	req, e := http.NewRequest(http.MethodGet, base+"/api/health", nil)
	if e != nil {
		return 0, nil, e
	}
	if host != "" {
		req.Host = host
	}
	resp, e := client.Do(req)
	if e != nil {
		return 0, nil, e
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
	if resp.StatusCode == 200 && !strings.Contains(string(b), `"ok":true`) {
		return 0, resp.TLS, errors.New("unexpected health response")
	}
	return resp.StatusCode, resp.TLS, nil
}

// verifyPanelHTTPS checks the panel from the inside out: the loopback service, the Host
// allow-list, TLS through this server's own port 443, the same through public DNS, and that
// the login page itself is served. Nothing logs in and no credential is sent.
func verifyPanelHTTPS(domain string, port int) panelVerification {
	out := panelVerification{}
	if domain == "" {
		// Loopback service only (used before a domain exists).
		plain := &http.Client{Timeout: 4 * time.Second, Transport: &http.Transport{Proxy: nil}}
		if code, _, e := panelHealth(plain, "http://"+net.JoinHostPort("127.0.0.1", itoa(port)), ""); e == nil && code == 200 {
			out.LocalService, out.HostAllowed = true, true
		}
		return out
	}
	plain := &http.Client{Timeout: 4 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	base := "http://" + net.JoinHostPort("127.0.0.1", itoa(port))
	if code, _, e := panelHealth(plain, base, ""); e == nil && code == 200 {
		out.LocalService = true
	} else {
		return out
	}
	if code, _, e := panelHealth(plain, base, domain); e == nil && code == 200 {
		out.HostAllowed = true
	}
	tlsTransport := func(local bool) *http.Transport {
		t := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: domain}}
		if local {
			t.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
				d := &net.Dialer{Timeout: 3 * time.Second}
				c, e := d.DialContext(ctx, "tcp", "127.0.0.1:443")
				if e != nil {
					c, e = d.DialContext(ctx, "tcp", "[::1]:443")
				}
				return c, e
			}
		}
		return t
	}
	record := func(st *tls.ConnectionState) {
		if st != nil && len(st.PeerCertificates) > 0 {
			out.Expires = st.PeerCertificates[0].NotAfter
			out.Issuer = st.PeerCertificates[0].Issuer.CommonName
		}
	}
	certErr := func(e error) {
		var v *tls.CertificateVerificationError
		if errors.As(e, &v) {
			out.CertificateError = true
		}
	}
	for _, local := range []bool{true, false} {
		t := tlsTransport(local)
		client := &http.Client{Timeout: 8 * time.Second, Transport: t, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		code, st, e := panelHealth(client, "https://"+domain, "")
		t.CloseIdleConnections()
		certErr(e)
		if e == nil && code == 200 {
			record(st)
			if local {
				out.LocalTLS = true
			} else {
				out.PublicFromHost = true
			}
		}
	}
	if out.LocalTLS || out.PublicFromHost {
		t := tlsTransport(!out.PublicFromHost)
		defer t.CloseIdleConnections()
		client := &http.Client{Timeout: 8 * time.Second, Transport: t}
		if resp, e := client.Get("https://" + domain + "/"); e == nil {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
			resp.Body.Close()
			out.LoginPage = resp.StatusCode == 200 && strings.Contains(string(b), `id="root"`)
		}
	}
	return out
}

// panelFailure names the layer that failed, from the inside out.
func panelFailure(v panelVerification) string {
	switch {
	case !v.LocalService:
		return "本机的管理面板服务没有响应：请运行 rout web restart 后重试"
	case !v.HostAllowed:
		return "面板拒绝了该域名（Host 白名单）：请运行 rout web host add 域名"
	case v.CertificateError:
		return "HTTPS 证书尚未生效或无效：证书签发可能仍在进行，请检查 DNS、公网 TCP 80/443 和 ACME 诊断"
	case !v.LocalTLS:
		return "Caddy 尚未在本机 443 端口为该域名提供 HTTPS：证书签发可能仍在进行，请稍后运行 rout web https repair"
	case !v.PublicFromHost:
		return "HTTPS 在本机可用，但经公网 DNS 访问失败：请检查 A/AAAA 记录、CDN 代理和服务商防火墙"
	case !v.LoginPage:
		return "HTTPS 可用，但没有返回面板登录页：请检查是否有其他站点规则覆盖了该域名"
	}
	return ""
}

// ---- deployment ---------------------------------------------------------------------------

// WebHTTPSOptions carries the consents the CLI collected, each confirmed separately.
type WebHTTPSOptions struct {
	HTTPSDeployOptions
	AcceptNAT bool // the operator confirmed public TCP 80/443 reach this NAT host
}

// WebHTTPSResult is what a deployment proved.
type WebHTTPSResult struct {
	Domain       string
	Verification panelVerification
	// Pending: Caddy is configured and running but the certificate or public endpoint is not
	// verified yet. The configuration is kept and `rout web https repair` resumes.
	Pending   bool
	Diagnosis string
	Unchanged bool
}

// ErrPanelHTTPSPending is returned (wrapped) when the site is configured but not verified.
var ErrPanelHTTPSPending = errors.New("面板 HTTPS 站点已配置，但证书或公网访问尚未验证通过")

// DeployWebHTTPS installs, repairs or moves the panel's HTTPS site. It is idempotent: an
// already working, owned site is verified and left untouched.
func (a *App) DeployWebHTTPS(domain string, opts WebHTTPSOptions) (res WebHTTPSResult, err error) {
	domain, err = subscriptionDomain(domain)
	if err != nil {
		return res, err
	}
	res.Domain = domain
	unlock, e := lockFile(filepath.Join(a.Home, ".subscription.lock"), trafficLockWait)
	if e != nil {
		return res, e
	}
	defer unlock()
	if e = a.requireHTTPSManagement(); e != nil {
		return res, e
	}
	if e = a.checkPanelDomain(domain); e != nil {
		return res, e
	}
	cfg, e := a.LoadWebConfig()
	if e != nil {
		return res, e
	}
	port := cfg.port()
	r := a.httpsRuntime()
	if !r.panelVerify("", port).LocalService { // loopback only: no domain, no TLS probes yet
		return res, errors.New("本机的管理面板服务没有响应：请先运行 rout web install（或 rout web restart）")
	}
	previous, e := a.loadWebHTTPSState()
	if e != nil {
		return res, e
	}
	network := a.panelNetwork()
	dns := r.dns(domain)
	if dns.Error != "" {
		return res, &DNSPendingError{Domain: domain, Cause: a.T(dns.Error), Records: dnsGuidance(domain, network)}
	}
	if p := natProblem(dns, network); p != "" && !opts.AcceptNAT {
		return res, &NATConfirmError{Detail: p}
	}
	if e = a.checkHTTPSPorts(); e != nil {
		return res, e
	}
	wasInstalled, wasRunning := r.installed(), r.running()
	wasEnabled := false
	if wasInstalled {
		_, e = r.run("", "systemctl", "is-enabled", "caddy")
		wasEnabled = e == nil
	}
	installedNow := false
	startStopped := wasInstalled && !wasRunning && opts.AllowStart
	defer func() {
		// A Caddy this deployment installed or started returns to its stopped state when the
		// deployment fails before anything was kept.
		if err != nil && !errors.Is(err, ErrPanelHTTPSPending) && (installedNow || startStopped) && !wasRunning && r.installed() {
			var stop, disable error
			if installedNow || r.running() {
				_, stop = r.run("", "systemctl", "stop", "caddy")
			}
			if installedNow || !wasEnabled {
				_, disable = r.run("", "systemctl", "disable", "caddy")
			}
			err = errors.Join(err, stop, disable)
		}
	}()
	if !wasInstalled {
		if !opts.AllowInstall {
			return res, errors.New("Caddy installation requires explicit confirmation")
		}
		if _, e = r.run("", "apt-get", "update"); e != nil {
			return res, e
		}
		installedNow = true
		if _, e = r.run("", "apt-get", "install", "-y", "caddy"); e != nil {
			return res, e
		}
		if !r.installed() {
			return res, errors.New("Caddy package installation did not provide a working executable")
		}
	} else if !wasRunning && !opts.AllowStart {
		return res, errors.New(msgConfirmStartCaddy)
	}
	if e = a.checkHTTPSPorts(); e != nil {
		return res, e
	}
	main, active, e := a.checkCaddyLayout()
	if e != nil {
		return res, e
	}
	if !caddyAutomaticHTTPS(active) {
		return res, errors.New("Caddy automatic certificate management is disabled in the existing configuration; no global TLS policy will be changed")
	}
	// Rout owns the fragment while the recorded digest matches it. That includes the
	// placeholder RemoveWebHTTPS leaves behind (Removed): it is Rout's own file, verified by
	// the digest recorded for it, and may be replaced by a redeployment. A fragment whose
	// bytes differ from the record was edited by someone else and is never touched.
	owned := previous.Ownership == "managed"
	file := a.webHTTPSFile()
	if owned {
		f, er := a.ownedPanelFragment(previous)
		switch {
		case er == nil:
			file = f.Path
		case os.IsNotExist(statErr(previous.File)):
			owned = false // Caddy's configuration was purged; nothing left to protect
		default:
			return res, er
		}
	}
	route := inspectCaddyDomain(active, domain, port)
	// A removed site is no longer served, so a route for the domain is somebody else's.
	ownDomain := owned && !previous.Removed && previous.Domain == domain
	if !ownDomain && (route.Found || route.Conflict) {
		return res, errors.New("该域名在 Caddy 中已有站点配置，不会覆盖；请换用其他域名（例如独立的子域名）")
	}
	if !safeProxyPath(r.root, file) {
		return res, errors.New("unsafe HTTPS fragment path; no configuration changed")
	}
	fragment, e := snapshotSubscriptionFile(file)
	if e != nil {
		return res, e
	}
	if fragment.Exists && !owned {
		return res, errors.New("面板 HTTPS 配置文件已存在但不属于 Rout 的记录，不会覆盖")
	}
	data := []byte(renderPanelCaddy(domain, port))
	// Idempotent repair: the owned site is already correct; only verify it.
	if ownDomain && route.Found && route.Correct && !route.Conflict && bytesEqual(fragment.Data, data) && r.running() {
		if e = a.allowPanelDomain(domain, previous.Domain); e != nil {
			return res, e
		}
		v := r.panelVerify(domain, port)
		res.Verification, res.Unchanged = v, true
		previous.Pending, previous.LastError = !v.ok(), ""
		if !v.ok() {
			res.Pending, res.Diagnosis = true, panelFailure(v)
			previous.LastError = res.Diagnosis
		}
		if !wasEnabled {
			if _, er := r.run("", "systemctl", "enable", "caddy"); er != nil {
				return res, er
			}
		}
		if er := a.saveWebHTTPSState(previous); er != nil {
			return res, er
		}
		if res.Pending {
			return res, fmt.Errorf("%w：%s", ErrPanelHTTPSPending, a.T(res.Diagnosis))
		}
		return res, nil
	}
	webFile, e := snapshotSubscriptionFile(a.webConfigPath())
	if e != nil {
		return res, e
	}
	snapshots, e := a.backupSubscriptionFiles("panel-https", main.Path, file, a.webHTTPSStatePath(), a.webConfigPath())
	if e != nil {
		return res, e
	}
	if !sameFileSnapshot(main) || !sameFileSnapshot(fragment) {
		return res, errors.New("Caddy files changed during inspection; retry without overwriting the external change")
	}
	expected := map[string]string{}
	activated, webChanged := false, false
	defer func() {
		if err == nil || errors.Is(err, ErrPanelHTTPSPending) {
			return
		}
		var rollback []error
		for _, s := range snapshots[:2] {
			digest, changed := expected[s.Path]
			if !changed || sameFileSnapshot(s) {
				continue
			}
			now, er := snapshotSubscriptionFile(s.Path)
			if er != nil || !now.Exists || hashToken(string(now.Data)) != digest {
				rollback = append(rollback, fmt.Errorf("external change detected at %s; automatic restore refused", s.Path))
				continue
			}
			rollback = append(rollback, s.restore())
		}
		if webChanged {
			rollback = append(rollback, webFile.restore())
		}
		if activated && wasRunning {
			_, er := r.run("", "caddy", "validate", "--config", main.Path, "--adapter", "caddyfile")
			rollback = append(rollback, er)
			if er == nil {
				_, er = r.run("", "systemctl", "reload", "caddy")
				rollback = append(rollback, er)
			}
			restored, er := r.active()
			if er != nil || !caddyConfigEqual(restored, active) {
				rollback = append(rollback, errors.New("previous active Caddy configuration could not be verified"))
			}
		}
		if rb := errors.Join(rollback...); rb != nil {
			err = errors.Join(err, fmt.Errorf("rollback incomplete: %w; recover from %s, validate %s and reload Caddy only after review", rb, snapshots[0].backup, main.Path))
		} else {
			err = fmt.Errorf("%w; previous configuration restored and verified", err)
		}
		previous.LastError = sanitizeSubscriptionLogs([]byte(err.Error()))
		if len(previous.LastError) > 2048 {
			previous.LastError = previous.LastError[:2048]
		}
		_ = a.saveWebHTTPSState(previous)
	}()
	// Validate the fragment on its own before it can replace a file.
	if e = os.MkdirAll(filepath.Dir(file), 0755); e != nil {
		return res, e
	}
	check, e := os.CreateTemp(filepath.Dir(file), ".rout-validate-*")
	if e != nil {
		return res, e
	}
	checkPath := check.Name()
	defer os.Remove(checkPath)
	if _, e = check.Write(data); e != nil {
		check.Close()
		return res, e
	}
	if e = check.Close(); e != nil {
		return res, e
	}
	if _, e = r.run("", "caddy", "validate", "--config", checkPath, "--adapter", "caddyfile"); e != nil {
		return res, e
	}
	expected[file] = hashToken(string(data))
	if e = atomicSubscriptionFile(fragment, data, 0644); e != nil {
		return res, e
	}
	if file == a.webHTTPSFile() && !strings.Contains(string(main.Data), a.httpsImport()) {
		next := append(append([]byte(nil), main.Data...), []byte(a.httpsImport())...)
		expected[main.Path] = hashToken(string(next))
		if e = atomicSubscriptionFile(main, next, main.Mode); e != nil {
			return res, e
		}
	}
	if _, e = r.run("", "caddy", "validate", "--config", main.Path, "--adapter", "caddyfile"); e != nil {
		return res, e
	}
	// The Host allow-list and Secure cookie must be in place before Caddy forwards the
	// domain, or the first verified request would be refused with 421.
	webChanged = true
	if e = a.allowPanelDomain(domain, previous.Domain); e != nil {
		return res, e
	}
	if _, e = r.run("", "systemctl", "enable", "caddy"); e != nil {
		return res, e
	}
	activated = true
	action := "reload"
	if !r.running() {
		action = "start"
	}
	if _, e = r.run("", "systemctl", action, "caddy"); e != nil {
		return res, e
	}
	if !r.running() {
		return res, errors.New("Caddy did not remain running")
	}
	adapted, e := r.run("", "caddy", "adapt", "--config", main.Path, "--adapter", "caddyfile")
	if e != nil {
		return res, e
	}
	loaded, e := r.active()
	if e != nil || !caddyConfigEqual(adapted, loaded) {
		return res, errors.New("Caddy reload did not activate the validated configuration; endpoint verification alone cannot prove ownership")
	}
	saved := webHTTPSState{Domain: domain, Ownership: "managed", Main: main.Path, File: file, Digest: hashToken(string(data))}
	if e = a.saveWebHTTPSState(saved); e != nil {
		return res, e
	}
	// From here the configuration is valid, loaded and recorded: it is kept whatever the
	// certificate does. Issuance is asynchronous, so wait for it a while.
	var v panelVerification
	deadline := time.Now().Add(r.verificationWait)
	for {
		v = r.panelVerify(domain, port)
		if v.ok() || time.Now().After(deadline) {
			break
		}
		time.Sleep(2 * time.Second)
	}
	res.Verification = v
	if !v.ok() {
		res.Pending, res.Diagnosis = true, panelFailure(v)
		saved.Pending, saved.LastError = true, res.Diagnosis
		if er := a.saveWebHTTPSState(saved); er != nil {
			return res, er
		}
		return res, fmt.Errorf("%w：%s", ErrPanelHTTPSPending, a.T(res.Diagnosis))
	}
	return res, nil
}

func statErr(path string) error {
	_, e := os.Lstat(path)
	return e
}

// NATConfirmError asks the operator to confirm the NAT forwards public 80/443.
type NATConfirmError struct{ Detail string }

func (e *NATConfirmError) Error() string { return e.Detail }

// allowPanelDomain adds the domain to the Host allow-list, forces Secure cookies and records
// it; a previous Rout-deployed panel domain is removed from the list.
func (a *App) allowPanelDomain(domain, previous string) error {
	return a.mutateWebConfig(func(c *WebConfig) error {
		var hosts []string
		for _, h := range c.AllowedHosts {
			if h != domain && (previous == "" || previous == domain || h != previous) {
				hosts = append(hosts, h)
			}
		}
		if len(hosts) >= 8 {
			return errors.New("允许的主机名最多 8 个")
		}
		c.AllowedHosts = append(hosts, domain)
		c.SecureCookie, c.HTTPSDomain = true, domain
		return nil
	})
}

// RepairWebHTTPS re-runs the deployment for the recorded domain.
func (a *App) RepairWebHTTPS(opts WebHTTPSOptions) (WebHTTPSResult, error) {
	s, e := a.loadWebHTTPSState()
	if e != nil {
		return WebHTTPSResult{}, e
	}
	domain := s.Domain
	if domain == "" || s.Removed {
		cfg, er := a.LoadWebConfig()
		if er != nil {
			return WebHTTPSResult{}, er
		}
		domain = cfg.HTTPSDomain
	}
	if domain == "" {
		return WebHTTPSResult{}, errors.New("尚未设置面板域名：请先运行 rout web https deploy 域名")
	}
	return a.DeployWebHTTPS(domain, opts)
}

// RemoveWebHTTPS replaces Rout's panel site with a placeholder and reloads Caddy. It never
// stops Caddy, never removes certificates and never touches the subscription site.
func (a *App) RemoveWebHTTPS() (err error) {
	unlock, e := lockFile(filepath.Join(a.Home, ".subscription.lock"), trafficLockWait)
	if e != nil {
		return e
	}
	defer unlock()
	previous, e := a.loadWebHTTPSState()
	if e != nil {
		return e
	}
	if previous.Ownership != "managed" || previous.Removed {
		return nil
	}
	if e = a.requireHTTPSManagement(); e != nil {
		return e
	}
	fragment, e := a.ownedPanelFragment(previous)
	if e != nil {
		return e
	}
	main, active, e := a.checkCaddyLayout()
	if e != nil {
		return e
	}
	snapshots, e := a.backupSubscriptionFiles("panel-https-remove", fragment.Path, a.webHTTPSStatePath())
	if e != nil {
		return e
	}
	r := a.httpsRuntime()
	placeholder := []byte("# Rout web panel HTTPS removed; certificates preserved\n")
	changed := false
	defer func() {
		if err != nil && changed {
			rb := restoreSubscriptionFiles(snapshots)
			if rb == nil {
				if _, rb = r.run("", "caddy", "validate", "--config", main.Path, "--adapter", "caddyfile"); rb == nil {
					_, rb = r.run("", "systemctl", "reload", "caddy")
				}
			}
			if restored, er := r.active(); er != nil || !caddyConfigEqual(active, restored) {
				rb = errors.Join(rb, errors.New("old active configuration not verified"))
			}
			if rb != nil {
				err = errors.Join(err, fmt.Errorf("rollback incomplete: %w; inspect recovery snapshot %s", rb, snapshots[0].backup))
			}
		}
	}()
	changed = true
	if e = atomicSubscriptionFile(fragment, placeholder, fragment.Mode); e != nil {
		return e
	}
	if _, e = r.run("", "caddy", "validate", "--config", main.Path, "--adapter", "caddyfile"); e != nil {
		return e
	}
	if r.running() {
		if _, e = r.run("", "systemctl", "reload", "caddy"); e != nil {
			return e
		}
		current, er := r.active()
		if er != nil {
			return er
		}
		if inspectCaddyDomain(current, previous.Domain, 0).Found {
			return errors.New("removed domain is still present in Caddy; inspect duplicate/shared routes")
		}
	}
	previous.Removed, previous.Pending, previous.LastError = true, false, ""
	previous.Digest = hashToken(string(placeholder))
	if e = a.saveWebHTTPSState(previous); e != nil {
		return e
	}
	// Forget what the deployment added to web.json: the domain no longer reaches the panel,
	// and the Secure-cookie policy it forced would stop an SSH-tunnel login over plain HTTP
	// (Safari refuses Secure cookies there). Hosts the administrator allowed by hand stay.
	return a.mutateWebConfig(func(c *WebConfig) error {
		hosts := []string{}
		for _, h := range c.AllowedHosts {
			if h != previous.Domain {
				hosts = append(hosts, h)
			}
		}
		c.AllowedHosts = hosts
		if c.HTTPSDomain == previous.Domain {
			c.HTTPSDomain = ""
			c.SecureCookie = len(hosts) > 0
		}
		return nil
	})
}

// ---- diagnostics --------------------------------------------------------------------------

// PanelCheck is one line of the panel HTTPS diagnosis.
type PanelCheck struct {
	Key   string `json:"key"`
	Level string `json:"level"` // ok, warn, fail, info
	Text  string `json:"text"`
}

// WebHTTPSReport separates every layer an HTTPS failure can come from: DNS, the ports,
// Caddy, ACME reachability, the certificate, the public endpoint and the panel itself.
type WebHTTPSReport struct {
	Domain       string            `json:"domain"`
	Ownership    string            `json:"ownership"`
	Pending      bool              `json:"pending"`
	LastError    string            `json:"last_error,omitempty"`
	Network      PanelNetwork      `json:"network"`
	Records      []string          `json:"records,omitempty"`
	Verification panelVerification `json:"verification"`
	Checks       []PanelCheck      `json:"checks"`
	URL          string            `json:"url,omitempty"`
}

var acmeDirectories = []struct{ key, label, url string }{
	{"acme_production", "Let’s Encrypt 正式环境", "https://acme-v02.api.letsencrypt.org/directory"},
	{"acme_staging", "Let’s Encrypt 测试环境", "https://acme-staging-v02.api.letsencrypt.org/directory"},
}

func probeACME(u string) error {
	client := &http.Client{Timeout: 8 * time.Second, Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}}
	resp, e := client.Get(u)
	if e != nil {
		return classifyFetch(e)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != 200 || !strings.Contains(string(b), "newOrder") {
		return &fetchError{Kind: fetchHTTP, Status: resp.StatusCode}
	}
	return nil
}

// caddyLogFindings classifies Caddy's recent journal. Only categories are reported: raw
// lines can carry other sites' names and paths and are never shown.
var caddyLogPatterns = []struct {
	re   *regexp.Regexp
	text string
}{
	{regexp.MustCompile(`(?i)NXDOMAIN|no such host|no valid A records|DNS problem`), "ACME 查询域名失败（NXDOMAIN / DNS problem）：记录尚未生效或拼写错误；生效前不会反复申请"},
	{regexp.MustCompile(`(?i)caddy_legacy_user_removed`), "Caddy 的数据目录属于已移除的旧用户（caddy_legacy_user_removed）：请检查 /var/lib/caddy 的所有权，或重新安装 caddy 软件包后运行 rout web https repair"},
	{regexp.MustCompile(`(?i)alert internal error`), "TLS 握手返回 internal error：证书尚未签发时访问会出现此错误，请等待签发完成或查看 ACME 错误"},
	{regexp.MustCompile(`(?i)connection reset by peer`), "连接被重置：公网到本机 80/443 的连接被防火墙、运营商或 CDN 中断"},
	{regexp.MustCompile(`(?i)timeout during connect|i/o timeout|Timeout during`), "ACME 验证连接超时：公网 TCP 80/443 可能没有开放或没有转发到本机"},
	{regexp.MustCompile(`(?i)rateLimited|too many (certificates|failed authorizations)`), "触发 Let’s Encrypt 速率限制：请等待一段时间后再修复，不要反复重试"},
	{regexp.MustCompile(`(?i)urn:ietf:params:acme:error:unauthorized|403 Forbidden.*acme`), "ACME 验证被拒绝（unauthorized）：域名可能没有指向本机，或存在多余的 A/AAAA 记录"},
	{regexp.MustCompile(`(?i)ambiguous site definition`), "Caddy 配置中有重复的站点定义（ambiguous site definition）：同一域名被定义了两次"},
}

func caddyLogFindings(b []byte, domain string) (findings []string, issued bool) {
	for _, line := range strings.Split(string(b), "\n") {
		if domain != "" && !strings.Contains(line, domain) && !strings.Contains(line, "caddy_legacy_user_removed") {
			continue
		}
		if strings.Contains(line, "certificate obtained successfully") {
			issued = true
		}
		for _, p := range caddyLogPatterns {
			if p.re.MatchString(line) && !contains(findings, p.text) {
				findings = append(findings, p.text)
			}
		}
	}
	return findings, issued
}

// WebHTTPSDiagnostics inspects every layer without changing anything.
func (a *App) WebHTTPSDiagnostics() (WebHTTPSReport, error) {
	out := WebHTTPSReport{Checks: []PanelCheck{}, Ownership: "none"}
	cfg, e := a.LoadWebConfig()
	if e != nil {
		return out, e
	}
	saved, e := a.loadWebHTTPSState()
	if e != nil {
		return out, e
	}
	add := func(key, level, text string, args ...any) {
		out.Checks = append(out.Checks, PanelCheck{Key: key, Level: level, Text: fmt.Sprintf(a.T(text), args...)})
	}
	out.Domain = cfg.HTTPSDomain
	if out.Domain == "" && !saved.Removed {
		out.Domain = saved.Domain
	}
	out.Pending, out.LastError = saved.Pending, a.T(saved.LastError)
	if saved.Ownership == "managed" && !saved.Removed {
		out.Ownership = "managed"
		if _, er := a.ownedPanelFragment(saved); er != nil {
			out.Ownership = "modified"
			add("ownership", "warn", "%s", a.Error(er))
		}
	} else if out.Domain != "" {
		out.Ownership = "external"
	}
	r := a.httpsRuntime()
	out.Network = a.panelNetwork()
	switch {
	case out.Network.IPv6Only:
		add("network", "info", "纯 IPv6 服务器：公网 IPv6 %s；不需要 A 记录，Caddy 通过 IPv6 提供 HTTPS", out.Network.IPv6)
	case out.Network.IPv4 != "" && out.Network.IPv6 != "":
		add("network", "info", "双栈：公网 IPv4 %s，IPv6 %s", out.Network.IPv4, out.Network.IPv6)
	case out.Network.IPv4 != "":
		add("network", "info", "仅 IPv4：公网 IPv4 %s", out.Network.IPv4)
	default:
		add("network", "warn", "未能检测到本机公网地址")
	}
	if out.Network.IPv4NAT {
		add("network", "warn", "公网 IPv4 由 NAT 映射：需要服务商把公网 TCP 80/443 转发到本机")
	}
	v := r.panelVerify(out.Domain, cfg.port())
	if v.LocalService {
		add("service", "ok", "面板服务在 127.0.0.1:%d 正常响应", cfg.port())
	} else {
		add("service", "fail", "面板服务没有在 127.0.0.1:%d 响应：请运行 rout web restart", cfg.port())
	}
	if out.Domain == "" {
		add("domain", "info", "尚未设置管理域名：可用 SSH 隧道访问，或运行 rout web https deploy 域名")
		return out, nil
	}
	out.URL = "https://" + out.Domain
	out.Records = dnsGuidance(out.Domain, out.Network)
	dns := r.dns(out.Domain)
	switch {
	case dns.Error != "":
		add("dns", "fail", "DNS：%s", a.T(dns.Error))
	case dns.Cloudflare:
		add("dns", "warn", "DNS 指向 Cloudflare 代理：无法确认源站，签发证书时请使用 DNS only（灰色云）")
	default:
		add("dns", "ok", "DNS 已指向本机（A：%s；AAAA：%s）", joinOrNone(a, dns.A), joinOrNone(a, dns.AAAA))
	}
	if len(dns.A) == 0 && len(dns.AAAA) > 0 && out.Network.IPv6Only {
		add("dns", "info", "仅有 AAAA 记录，符合纯 IPv6 服务器")
	}
	for _, port := range []int{80, 443} {
		ls, er := r.listeners(port)
		switch {
		case er != nil:
			add("ports", "warn", "无法读取 TCP %d 的监听者：%s", port, a.Error(er))
		case len(ls) == 0:
			add("ports", "fail", "TCP %d 没有程序监听：Caddy 未运行或未启用自动 HTTPS", port)
		default:
			owner := ls[0].Owner
			level := "ok"
			if owner != "caddy" {
				level = "warn"
			}
			add("ports", level, "TCP %d 由 %s 监听", port, owner)
		}
	}
	switch {
	case !r.installed():
		add("caddy", "fail", "未安装 Caddy：运行 rout web https deploy 域名 安装并部署")
	case !r.running():
		add("caddy", "fail", "Caddy 已安装但未运行")
	default:
		if active, er := r.active(); er != nil {
			add("caddy", "warn", "Caddy 正在运行，但无法读取其当前配置（管理 API 不可用）")
		} else if route := inspectCaddyDomain(active, out.Domain, cfg.port()); route.Found && route.Correct && !route.Conflict {
			add("caddy", "ok", "Caddy 已为 %s 反向代理到面板", out.Domain)
		} else if route.Found {
			add("caddy", "fail", "Caddy 中 %s 的站点没有指向面板端口 %d", out.Domain, cfg.port())
		} else {
			add("caddy", "fail", "Caddy 正在运行，但没有 %s 的站点：运行 rout web https repair", out.Domain)
		}
	}
	for _, d := range acmeDirectories {
		if er := r.acme(d.url); er != nil {
			level := "warn"
			if d.key == "acme_staging" {
				level = "info" // the staging CA being unreachable says nothing about production
			}
			add(d.key, level, "%s 不可达：%s", a.T(d.label), a.Error(er))
		} else {
			add(d.key, "ok", "%s 可以访问", a.T(d.label))
		}
	}
	if logs, er := r.caddyLog(); er == nil {
		findings, issued := caddyLogFindings(logs, out.Domain)
		for _, f := range findings {
			add("acme_log", "warn", "%s", a.T(f))
		}
		if issued {
			add("acme_log", "ok", "Caddy 日志显示证书已成功签发")
		}
	}
	out.Verification = v
	switch {
	case v.LocalTLS || v.PublicFromHost:
		if v.Expires.IsZero() {
			add("certificate", "ok", "HTTPS 证书有效")
		} else {
			add("certificate", "ok", "HTTPS 证书有效（签发者 %s，到期 %s）", v.Issuer, v.Expires.Local().Format("2006-01-02"))
		}
	case v.CertificateError:
		add("certificate", "fail", "HTTPS 证书无效或尚未签发")
	default:
		add("certificate", "fail", "本机 443 端口没有为 %s 提供 HTTPS", out.Domain)
	}
	if v.HostAllowed {
		add("hosts", "ok", "Host 白名单包含 %s", out.Domain)
	} else if v.LocalService {
		add("hosts", "fail", "Host 白名单不包含 %s：请运行 rout web host add %s", out.Domain, out.Domain)
	}
	if v.PublicFromHost {
		add("public", "ok", "经公网 DNS 访问 HTTPS 正常")
	} else if v.LocalTLS {
		add("public", "warn", "本机可用，但经公网 DNS 访问失败（NAT 回环或防火墙）；请从外部设备确认")
	}
	if v.LoginPage {
		add("login", "ok", "登录页面可以访问")
	}
	return out, nil
}
