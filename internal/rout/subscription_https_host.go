package rout

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"
)

// Dependencies are per-App (never global), keeping tests isolated from host services.
// Production paths and the admin URL are fixed; domains never become shell input.
type subscriptionHTTPSRuntime struct {
	root             string
	verificationWait time.Duration
	run              func(string, string, ...string) ([]byte, error)
	installed        func() bool
	running          func() bool
	manager          func() (string, error)
	listeners        func(int) ([]httpsListener, error)
	lookup           func(string) ([]net.IP, error)
	addresses        func() Addresses
	extraAddresses   func() []net.IP
	active           func() ([]byte, error)
	verify           func(string, int, string, string) httpsVerification
	external         func(string, string, string) error
	osID             func() string
}

type httpsListener struct {
	Address, Owner string
	PID            int
}
type httpsVerification struct {
	LocalService, LocalTLS, PublicFromHost, External bool
	// Answered: a TLS/HTTP exchange completed but the reply was not Rout's probe response
	// (wrong upstream, rewritten path, outdated helper). CertificateError: the TLS
	// handshake reached the server but its certificate was refused.
	Answered, CertificateError bool
	Expires                    time.Time
	Error                      string
}
type httpsDNS struct {
	A, AAAA                        []string
	Addresses                      Addresses
	Cloudflare, Matched, Uncertain bool
	Error                          string
}

func httpsExec(input, name string, args ...string) ([]byte, error) {
	timeout := 30 * time.Second
	if name == "apt-get" {
		timeout = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "DEBIAN_FRONTEND=noninteractive")
	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}
	// Never include subprocess output in an error: a shared Caddyfile can contain
	// unrelated secrets, and Caddy's validation errors may quote configuration lines.
	b, e := cmd.Output()
	if e != nil {
		action := name
		if len(args) > 0 {
			action += " " + args[0]
		}
		if ctx.Err() != nil {
			return nil, fmt.Errorf("%s timed out; inspect it locally (output withheld to protect credentials)", action)
		}
		return nil, fmt.Errorf("%s failed (%v); inspect it locally (output withheld to protect credentials)", action, e)
	}
	if len(b) > 8<<20 {
		return nil, errors.New("proxy configuration exceeds the safe inspection limit")
	}
	return b, nil
}

func readOSID() string {
	b, _ := os.ReadFile("/etc/os-release")
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "ID="); ok {
			return strings.Trim(v, `"`)
		}
	}
	return ""
}

var ssOwner = regexp.MustCompile(`\("([^"\r\n]+)",pid=([0-9]+)`)

func httpsPortListeners(port int) ([]httpsListener, error) {
	b, e := httpsExec("", "ss", "-H", "-ltnp", "sport = :"+itoa(port))
	if e != nil {
		return nil, errors.New("cannot identify the TCP listener; install iproute2 and run as root")
	}
	var out []httpsListener
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			return nil, errors.New("cannot parse TCP listener ownership")
		}
		owners := ssOwner.FindAllStringSubmatch(line, -1)
		if len(owners) == 0 {
			out = append(out, httpsListener{Address: fields[3], Owner: "unknown"})
			continue
		}
		for _, m := range owners {
			pid, _ := parseUint(m[2])
			out = append(out, httpsListener{Address: fields[3], Owner: m[1], PID: int(pid)})
		}
	}
	return out, nil
}

func (a *App) httpsRuntime() *subscriptionHTTPSRuntime {
	if a.subscriptionHTTPS != nil {
		return a.subscriptionHTTPS
	}
	r := &subscriptionHTTPSRuntime{root: "/etc/caddy", verificationWait: 45 * time.Second, run: httpsExec, manager: a.serviceManager, osID: readOSID}
	r.installed = func() bool { _, e := exec.LookPath("caddy"); return e == nil }
	r.running = func() bool { return serviceActive("systemd", "caddy") }
	r.listeners = httpsPortListeners
	r.lookup = func(host string) ([]net.IP, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		return net.DefaultResolver.LookupIP(ctx, "ip", host)
	}
	r.addresses = DetectAddresses
	r.extraAddresses = func() []net.IP {
		var out []net.IP
		addrs, _ := net.InterfaceAddrs()
		for _, addr := range addrs {
			if n, ok := addr.(*net.IPNet); ok && (publicIPv4(n.IP) || publicIPv6(n.IP)) {
				out = append(out, n.IP)
			}
		}
		return out
	}
	r.active = func() ([]byte, error) {
		client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		resp, e := client.Get("http://127.0.0.1:2019/config/")
		if e != nil {
			return nil, errors.New("Caddy's loopback admin configuration is unavailable")
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, errors.New("Caddy's loopback admin configuration is unavailable")
		}
		b, e := io.ReadAll(io.LimitReader(resp.Body, 8<<20+1))
		if e != nil || len(b) > 8<<20 {
			return nil, errors.New("cannot safely read Caddy's active configuration")
		}
		return b, nil
	}
	r.verify = verifySubscriptionHTTPS
	return r
}

func subscriptionDomain(raw string) (string, error) {
	domain := strings.ToLower(strings.TrimSpace(raw))
	// Automatic HTTPS accepts an ASCII DNS hostname only. PublicURL retains its
	// existing backwards-compatible validation (including manually managed prefixes).
	if len(domain) > 253 || !strings.Contains(domain, ".") || net.ParseIP(domain) != nil || strings.ContainsAny(domain, "/:;\\\"'`$@*?#%{}[]()|&<> \t\r\n") {
		return "", errors.New("enter a DNS domain only, without a URL, path, wildcard or port")
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("invalid DNS hostname")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", errors.New("invalid DNS hostname; use its ASCII/punycode form")
			}
		}
	}
	return domain, nil
}

// Published Cloudflare proxy ranges. These mean an origin comparison is inconclusive,
// not a mismatch and not proof that the CDN actually points at this server.
var cloudflarePrefixes = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range strings.Fields("173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13 104.24.0.0/14 172.64.0.0/13 131.0.72.0/22 2400:cb00::/32 2606:4700::/32 2803:f800::/32 2405:b500::/32 2405:8100::/32 2a06:98c0::/29 2c0f:f248::/32") {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

func isCloudflare(ip net.IP) bool {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	a = a.Unmap()
	for _, p := range cloudflarePrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
func (r *subscriptionHTTPSRuntime) dns(domain string) httpsDNS {
	out := httpsDNS{Addresses: r.addresses()}
	ips, e := r.lookup(domain)
	if e != nil || len(ips) == 0 {
		out.Error = "DNS lookup failed; check A/AAAA records and allow time for propagation"
		return out
	}
	known := []net.IP{net.ParseIP(out.Addresses.IPv4), net.ParseIP(out.Addresses.IPv6)}
	if r.extraAddresses != nil {
		known = append(known, r.extraAddresses()...)
	}
	mismatch := false
	for _, ip := range ips {
		value := ip.String()
		origin := out.Addresses.IPv6
		if ip.To4() != nil {
			out.A = append(out.A, value)
			origin = out.Addresses.IPv4
		} else {
			out.AAAA = append(out.AAAA, value)
		}
		knownAddress := false
		for _, address := range known {
			if address.Equal(ip) {
				knownAddress = true
				break
			}
		}
		switch {
		case isCloudflare(ip):
			out.Cloudflare = true
		case knownAddress:
			out.Matched = true
		case origin == "":
			out.Uncertain = true
		case net.ParseIP(origin).Equal(ip):
			out.Matched = true
		default:
			mismatch = true
		}
	}
	sort.Strings(out.A)
	sort.Strings(out.AAAA)
	if mismatch {
		out.Error = "DNS includes an address for another origin; correct every A/AAAA record or wait for propagation"
	}
	if out.Uncertain {
		out.Error = "cannot verify every advertised DNS family; check public address detection and remove stale AAAA records on IPv4-only servers"
	}
	return out
}

func probeHTTP(client *http.Client, base, token, body string) (time.Time, error) {
	req, e := http.NewRequest(http.MethodGet, strings.TrimRight(base, "/")+subscriptionProbePath, nil)
	if e != nil {
		return time.Time{}, errSubscriptionProbe
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, e := client.Do(req)
	if e != nil {
		var verification *tls.CertificateVerificationError
		if errors.As(e, &verification) {
			if len(verification.UnverifiedCertificates) > 0 {
				return verification.UnverifiedCertificates[0].NotAfter, errSubscriptionProbeCertificate
			}
			return time.Time{}, errSubscriptionProbeCertificate
		}
		return time.Time{}, errSubscriptionProbe
	}
	defer resp.Body.Close()
	b, e := io.ReadAll(io.LimitReader(resp.Body, 4097))
	if e != nil || resp.StatusCode != 200 || len(b) > 4096 || strings.TrimSpace(string(b)) != body || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/plain") {
		return time.Time{}, errSubscriptionProbeResponse
	}
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		return resp.TLS.PeerCertificates[0].NotAfter, nil
	}
	return time.Time{}, nil
}
func verifySubscriptionHTTPS(base string, port int, token, body string) httpsVerification {
	out := httpsVerification{}
	transport := func(local bool) *http.Transport {
		t := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
		if local {
			t.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", "443"))
			}
		}
		return t
	}
	client := func(t *http.Transport) *http.Client {
		return &http.Client{Transport: t, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	t := transport(false)
	defer t.CloseIdleConnections()
	if _, e := probeHTTP(client(t), "http://127.0.0.1:"+itoa(port), token, body); e != nil {
		out.Error = "local subscription response unavailable; check the service and refresh an older subscription helper"
		return out
	}
	out.LocalService = true
	local := transport(true)
	defer local.CloseIdleConnections()
	expires, localErr := probeHTTP(client(local), base, token, body)
	out.Expires = expires
	if localErr == nil {
		out.LocalTLS = true
	}
	expires, publicErr := probeHTTP(client(t), base, token, body)
	if publicErr == nil {
		out.PublicFromHost = true
		if out.Expires.IsZero() {
			out.Expires = expires
		}
	}
	out.Answered = errors.Is(localErr, errSubscriptionProbeResponse) || errors.Is(publicErr, errSubscriptionProbeResponse)
	out.CertificateError = errors.Is(localErr, errSubscriptionProbeCertificate) || errors.Is(publicErr, errSubscriptionProbeCertificate)
	if !out.LocalTLS && !out.PublicFromHost {
		out.Error = "TLS or authenticated subscription response unavailable; check DNS, port reachability, certificate issuance and Caddy logs (redact /s/ tokens)"
	}
	return out
}

func decodeCaddy(b []byte) (map[string]any, error) {
	var v map[string]any
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if e := d.Decode(&v); e != nil {
		return nil, errors.New("cannot inspect the Caddy JSON configuration")
	}
	if d.Decode(new(any)) != io.EOF {
		return nil, errors.New("invalid Caddy JSON configuration")
	}
	return v, nil
}
func caddyConfigEqual(a, b []byte) bool {
	x, e := decodeCaddy(a)
	if e != nil {
		return false
	}
	y, e := decodeCaddy(b)
	if e != nil {
		return false
	}
	xb, _ := json.Marshal(x)
	yb, _ := json.Marshal(y)
	return bytes.Equal(xb, yb)
}
func safeProxyPath(root, path string) bool {
	rel, e := filepath.Rel(root, path)
	if e != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	for cur := path; cur != filepath.Dir(root); cur = filepath.Dir(cur) {
		st, e := os.Lstat(cur)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0022 != 0 {
			return false
		}
		if owner, ok := st.Sys().(*syscall.Stat_t); !ok || int(owner.Uid) != os.Geteuid() {
			return false
		}
		if cur == root {
			break
		}
	}
	return true
}
