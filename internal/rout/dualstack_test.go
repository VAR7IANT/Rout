package rout

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// IPv4, IPv6 and dual-stack behaviour (v0.3.1). Tests that need a working IPv6 stack skip
// themselves with a clear reason; everything about address handling, validation, link
// formatting and configuration generation runs everywhere.

func requireIPv6(t *testing.T) {
	t.Helper()
	l, e := net.Listen("tcp", "[::1]:0")
	if e != nil {
		t.Skip("IPv6 loopback is unavailable in this environment: ", e)
	}
	l.Close()
}

const (
	v4Addr = "203.0.113.10"
	v6Addr = "2001:db8::7"
)

func TestHostValidation(t *testing.T) {
	for _, ok := range []string{"2001:db8::1", "::1", "example.com", "a-b.example.org", "203.0.113.1", "xn--fiq228c.example", "localhost.localdomain"} {
		if !validHost(ok) {
			t.Errorf("rejected valid host %q", ok)
		}
	}
	for _, bad := range []string{"", "[::1]", "fe80::1%eth0", "-a.example", "a-.example", "a..example", "exa_mple.com", "例子.测试", strings.Repeat("a", 64) + ".com"} {
		if validHost(bad) || validHostStrict(bad) {
			t.Errorf("accepted invalid host %q", bad)
		}
	}
	// Newly typed malformed IPv4 literals are refused; stored state keeps the looser rule so
	// a configuration written by an older version always stays loadable.
	for _, bad := range []string{"999.1.1.1", "1.2.3", "1234", "256.0.0.1."} {
		if validHostStrict(bad) {
			t.Errorf("accepted malformed IPv4 literal %q for new input", bad)
		}
		if !validHost(bad) {
			t.Errorf("stored configurations containing %q would no longer load", bad)
		}
	}
	// Public connection addresses additionally exclude what no client can ever reach.
	for _, ok := range []string{"2001:db8::1", "example.com", "192.0.2.1", "2606:4700::1111"} {
		if !validPublicHost(ok) {
			t.Errorf("rejected valid public host %q", ok)
		}
	}
	for _, bad := range []string{"fe80::1", "169.254.1.1", "::", "0.0.0.0", "ff02::1", "224.0.0.1", "[2001:db8::1]"} {
		if validPublicHost(bad) {
			t.Errorf("accepted unusable public host %q", bad)
		}
	}
	if !sameHost("2001:DB8:0::1", "2001:db8::1") || !sameHost("Example.COM.", "example.com") || sameHost("2001:db8::1", "2001:db8::2") {
		t.Error("host comparison")
	}
}

func TestAddressClassification(t *testing.T) {
	for ip, want := range map[string]bool{"2001:db8::7": true, "2606:4700::1111": true, "fe80::1": false, "fc00::1": false, "fd12:3456::1": false, "::1": false, "ff02::1": false, "::": false, "::ffff:203.0.113.5": false} {
		if got := publicIPv6(net.ParseIP(ip)); got != want {
			t.Errorf("publicIPv6(%s)=%v", ip, got)
		}
	}
	for ip, want := range map[string]bool{"203.0.113.5": true, "10.1.2.3": false, "192.168.0.1": false, "172.16.0.1": false, "100.64.0.1": false, "169.254.1.1": false, "127.0.0.1": false, "224.0.0.1": false, "2001:db8::1": false} {
		if got := publicIPv4(net.ParseIP(ip)); got != want {
			t.Errorf("publicIPv4(%s)=%v", ip, got)
		}
	}
}

func fakeInterfaces(t *testing.T, cidrs ...string) {
	t.Helper()
	prev := interfaceAddrs
	t.Cleanup(func() { interfaceAddrs = prev })
	interfaceAddrs = func() ([]net.Addr, error) {
		var out []net.Addr
		for _, c := range cidrs {
			ip, n, e := net.ParseCIDR(c)
			if e != nil {
				t.Fatal(e)
			}
			out = append(out, &net.IPNet{IP: ip, Mask: n.Mask})
		}
		return out, nil
	}
}

// The echo endpoints are unreachable here, so detection must fall back to the interfaces.
func deadEndpoints(t *testing.T) {
	t.Helper()
	saved := ipEndpoints
	t.Cleanup(func() { ipEndpoints = saved })
	ipEndpoints = map[string][]string{"tcp4": {"http://127.0.0.1:1"}, "tcp6": {"http://127.0.0.1:1"}}
}

func TestDetectAddressesByHostType(t *testing.T) {
	deadEndpoints(t)
	cases := []struct {
		name         string
		cidrs        []string
		want4, want6 string
	}{
		{"IPv4-only", []string{"127.0.0.1/8", "203.0.113.5/24", "fe80::1/64"}, "203.0.113.5", ""},
		{"IPv6-only", []string{"127.0.0.1/8", "::1/128", "2001:db8::7/64", "fe80::1/64"}, "", "2001:db8::7"},
		{"dual-stack", []string{"127.0.0.1/8", "203.0.113.5/24", "2001:db8::7/64", "fe80::2/64"}, "203.0.113.5", "2001:db8::7"},
		{"link-local and ULA only", []string{"127.0.0.1/8", "fe80::1/64", "fd00::5/64"}, "", ""},
		{"private IPv4 behind NAT, public address unknown", []string{"10.0.0.4/24"}, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fakeInterfaces(t, tc.cidrs...)
			got := DetectAddresses()
			if got.IPv4 != tc.want4 || got.IPv6 != tc.want6 {
				t.Fatalf("got %+v", got)
			}
		})
	}
}

func TestDetectAddressesAsksOnlyPlausibleFamilies(t *testing.T) {
	// An IPv6-only host must not depend on IPv4, and a host with only a link-local IPv6
	// address must not be treated as having IPv6.
	var asked []string
	saved := ipEndpoints
	t.Cleanup(func() { ipEndpoints = saved })
	srv := func(label string) string {
		l, e := net.Listen("tcp4", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		go func() {
			for {
				c, e := l.Accept()
				if e != nil {
					return
				}
				asked = append(asked, label)
				c.Close()
			}
		}()
		t.Cleanup(func() { l.Close() })
		return "http://" + l.Addr().String()
	}
	ipEndpoints = map[string][]string{"tcp4": {srv("v4")}, "tcp6": {srv("v6")}}
	fakeInterfaces(t, "127.0.0.1/8", "fe80::1/64")
	DetectAddresses()
	time.Sleep(50 * time.Millisecond)
	if len(asked) != 0 {
		t.Fatalf("queried echo services without any candidate address: %v", asked)
	}
}

func TestChooseListen(t *testing.T) {
	both := Addresses{IPv4: v4Addr, IPv6: v6Addr}
	dual := listenCaps{V6: true, DualStack: true}
	for _, tc := range []struct {
		name, family, saved, want string
		addrs                     Addresses
		caps                      listenCaps
	}{
		{"IPv4-only host", "ipv4", "", "0.0.0.0", Addresses{IPv4: v4Addr}, listenCaps{}},
		{"IPv4-only host with IPv6 disabled", "ipv4", "", "0.0.0.0", Addresses{IPv4: v4Addr}, listenCaps{}},
		{"IPv6-only host", "ipv6", "", "::", Addresses{IPv6: v6Addr}, dual},
		{"IPv6-only host, no dual-stack support", "ipv6", "", "::", Addresses{IPv6: v6Addr}, listenCaps{V6: true}},
		{"dual-stack, exporting IPv4", "ipv4", "", "::", both, dual},
		{"dual-stack, exporting IPv6", "ipv6", "", "::", both, dual},
		{"dual-stack, IPv4-mapped sockets refused", "ipv4", "", "0.0.0.0", both, listenCaps{V6: true}},
		{"dual-stack, IPv6 export, no mapping", "ipv6", "", "::", both, listenCaps{V6: true}},
		{"custom domain on dual-stack", "custom", "", "::", both, dual},
		{"custom domain on IPv4 host", "custom", "", "0.0.0.0", Addresses{IPv4: v4Addr}, dual},
		{"saved wildcard is recomputed", "ipv4", "0.0.0.0", "::", both, dual},
		{"saved specific address is kept", "ipv4", "198.51.100.9", "198.51.100.9", both, dual},
	} {
		if got := chooseListen(tc.family, tc.addrs, tc.caps, tc.saved); got != tc.want {
			t.Errorf("%s: got %s want %s", tc.name, got, tc.want)
		}
	}
}

// A [::] listener accepting IPv4 must be tested, never assumed: this is the same probe the
// installer relies on, run for real where the kernel has IPv6.
func TestDualStackListenerProbeAndSockets(t *testing.T) {
	requireIPv6(t)
	caps := probeListenCaps()
	if !caps.V6 {
		t.Fatal("IPv6 loopback works but [::] cannot be bound")
	}
	// Whatever the answer, it must match reality for both TCP and UDP.
	l, e := net.Listen("tcp", "[::]:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			c.Close()
		}
	}()
	c, e := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(port)), time.Second)
	if (e == nil) != caps.DualStack {
		t.Fatalf("probe says dual-stack=%v but an IPv4 client connect gave %v", caps.DualStack, e)
	}
	if e == nil {
		c.Close()
	}
	if c, e = net.DialTimeout("tcp", net.JoinHostPort("::1", itoa(port)), time.Second); e != nil {
		t.Fatal("IPv6 client rejected:", e)
	}
	c.Close()
	if caps.DualStack {
		u, e := net.ListenPacket("udp", "[::]:0")
		if e != nil {
			t.Fatal(e)
		}
		defer u.Close()
		for _, host := range []string{"127.0.0.1", "::1"} {
			cl, e := net.Dial("udp", net.JoinHostPort(host, itoa(u.LocalAddr().(*net.UDPAddr).Port)))
			if e != nil {
				t.Fatal(e)
			}
			cl.Write([]byte("x"))
			cl.Close()
			u.SetReadDeadline(time.Now().Add(time.Second))
			if _, _, e := u.ReadFrom(make([]byte, 4)); e != nil {
				t.Fatalf("UDP over %s through [::]: %v", host, e)
			}
		}
	}
}

func TestServerSetupByHostType(t *testing.T) {
	dual := listenCaps{V6: true, DualStack: true}
	t.Run("IPv4-only is automatic", func(t *testing.T) {
		a := testApp(t)
		u, out := testUI(a, "")
		u.detectAddrs = func() Addresses { return Addresses{IPv4: v4Addr} }
		u.caps = func() listenCaps { return listenCaps{} }
		s, e := u.serverSetup()
		if e != nil || s.PublicHost != v4Addr || s.Listen != "0.0.0.0" || s.Family != "ipv4" || s.NAT {
			t.Fatalf("%+v %v\n%s", s, e, out)
		}
		if strings.Contains(out.String(), "IPv6") && strings.Contains(out.String(), "Which address") {
			t.Fatal("asked an unnecessary question")
		}
	})
	t.Run("IPv6-only is automatic and needs no IPv4", func(t *testing.T) {
		a := testApp(t)
		u, out := testUI(a, "")
		u.detectAddrs = func() Addresses { return Addresses{IPv6: v6Addr} }
		u.caps = func() listenCaps { return dual }
		s, e := u.serverSetup()
		if e != nil || s.PublicHost != v6Addr || s.Listen != "::" || s.Family != "ipv6" {
			t.Fatalf("%+v %v\n%s", s, e, out)
		}
	})
	t.Run("dual-stack defaults to IPv4 and offers IPv6", func(t *testing.T) {
		a := testApp(t)
		u, out := testUI(a, "\n")
		u.detectAddrs = func() Addresses { return Addresses{IPv4: v4Addr, IPv6: v6Addr} }
		u.caps = func() listenCaps { return dual }
		s, e := u.serverSetup()
		if e != nil || s.PublicHost != v4Addr || s.Family != "ipv4" || s.Listen != "::" || s.IPv4 != v4Addr || s.IPv6 != v6Addr {
			t.Fatalf("%+v %v\n%s", s, e, out)
		}
		for _, want := range []string{"IPv4 " + v4Addr, "IPv6 " + v6Addr, "Best compatibility (default)"} {
			if !strings.Contains(out.String(), want) {
				t.Fatalf("missing %q:\n%s", want, out)
			}
		}
		if hasHan(out.String()) {
			t.Fatalf("untranslated text:\n%s", out)
		}
	})
	t.Run("dual-stack IPv6 choice", func(t *testing.T) {
		a := testApp(t)
		u, _ := testUI(a, "2\n")
		u.detectAddrs = func() Addresses { return Addresses{IPv4: v4Addr, IPv6: v6Addr} }
		u.caps = func() listenCaps { return dual }
		s, e := u.serverSetup()
		if e != nil || s.PublicHost != v6Addr || s.Family != "ipv6" || s.Listen != "::" {
			t.Fatalf("%+v %v", s, e)
		}
	})
	t.Run("dual-stack without IPv4-mapped sockets stays on 0.0.0.0 for IPv4", func(t *testing.T) {
		a := testApp(t)
		u, _ := testUI(a, "\n")
		u.detectAddrs = func() Addresses { return Addresses{IPv4: v4Addr, IPv6: v6Addr} }
		u.caps = func() listenCaps { return listenCaps{V6: true} }
		s, e := u.serverSetup()
		if e != nil || s.Listen != "0.0.0.0" {
			t.Fatalf("%+v %v", s, e)
		}
		if _, _, ok := s.AltAddress(Profile{Listen: s.Listen, PublicHost: s.PublicHost}); ok {
			t.Fatal("IPv6 link offered for an IPv4-only listener")
		}
	})
	t.Run("undetectable address is typed by hand and validated", func(t *testing.T) {
		a := testApp(t)
		u, out := testUI(a, "fe80::1\n::\n\nvpn.example.com\n")
		u.detectAddrs = func() Addresses { return Addresses{} }
		u.caps = func() listenCaps { return listenCaps{} }
		s, e := u.serverSetup()
		if e != nil || s.PublicHost != "vpn.example.com" || s.Family != "custom" || s.Listen != "0.0.0.0" {
			t.Fatalf("%+v %v\n%s", s, e, out)
		}
		if strings.Count(out.String(), "Invalid address") != 3 {
			t.Fatalf("link-local / unspecified / empty were not refused:\n%s", out)
		}
	})
}

func TestSavedFamilyPreferenceAndSilentReuse(t *testing.T) {
	dual := listenCaps{V6: true, DualStack: true}
	a := testApp(t)
	u, _ := testUI(a, "2\n")
	u.detectAddrs = func() Addresses { return Addresses{IPv4: v4Addr, IPv6: v6Addr} }
	u.caps = func() listenCaps { return dual }
	s, e := u.serverSetup()
	if e != nil || s.Family != "ipv6" {
		t.Fatal(s, e)
	}
	if e = u.saveServer(s); e != nil {
		t.Fatal(e)
	}
	// Saved: no detection, no question, same answer.
	u, out := testUI(a, "")
	u.detectAddrs = func() Addresses { t.Fatal("detected again although the setup is saved"); return Addresses{} }
	again, e := u.serverSetup()
	if e != nil || again != s || strings.Contains(out.String(), "?") {
		t.Fatalf("%+v %v\n%s", again, e, out)
	}
	// Re-detecting from Settings starts from the previous preference (IPv6 stays the default).
	u, out = testUI(a, "\n")
	u.detectAddrs = func() Addresses { return Addresses{IPv4: v4Addr, IPv6: v6Addr} }
	u.caps = func() listenCaps { return dual }
	redo, e := u.buildServer(&s, true)
	if e != nil || redo.Family != "ipv6" {
		t.Fatalf("saved preference lost: %+v %v", redo, e)
	}
}

func TestSettingsFromV030StayValid(t *testing.T) {
	a := testApp(t)
	raw := `{"language":"en","server":{"nat":false,"public_host":"203.0.113.10","listen":"0.0.0.0","network":"both"},"relay_mode":"remote"}`
	if e := os.WriteFile(a.Home+"/settings.json", []byte(raw), 0600); e != nil {
		t.Fatal(e)
	}
	s, e := a.LoadSettings()
	if e != nil || s.Server == nil || s.Server.Family != "" || s.Server.PublicHost != "203.0.113.10" {
		t.Fatal(s, e)
	}
	u, out := testUI(a, "")
	u.detectAddrs = func() Addresses { t.Fatal("v0.3.0 settings were discarded"); return Addresses{} }
	got, e := u.serverSetup()
	if e != nil || got.PublicHost != "203.0.113.10" || got.Listen != "0.0.0.0" || got.NAT {
		t.Fatal(got, e, out.String())
	}
	if _, _, ok := got.AltAddress(Profile{Listen: "0.0.0.0", PublicHost: "203.0.113.10"}); ok {
		t.Fatal("alternate address without detected addresses")
	}
}

func linkFixture(t *testing.T, protocol, host string) Profile {
	t.Helper()
	p := fixture(t, protocol)
	p.PublicHost = host
	p.Listen = "::"
	if protocol == "hy2" || protocol == "tuic" {
		cert, key, e := GenerateCertificate(host)
		if e != nil {
			t.Fatal(e)
		}
		p.SNI, p.CertPEM, p.KeyPEM, p.TLSGenerated = host, cert, key, true
	}
	if e := p.Validate(); e != nil {
		t.Fatalf("%s on %s: %v", protocol, host, e)
	}
	return p
}

func TestLinksForEveryProtocolAndFamily(t *testing.T) {
	for _, host := range []string{v4Addr, v6Addr, "vpn.example.com"} {
		for _, protocol := range []string{"vless", "anytls", "ss", "hy2", "tuic"} {
			t.Run(protocol+"@"+host, func(t *testing.T) {
				p := linkFixture(t, protocol, host)
				uri, e := p.URI()
				if e != nil {
					t.Fatal(e)
				}
				wantHost := net.JoinHostPort(host, itoa(p.PublicPort))
				if net.ParseIP(host) != nil && strings.Contains(host, ":") && !strings.Contains(uri, "["+host+"]:"+itoa(p.PublicPort)) {
					t.Fatalf("IPv6 literal is not bracketed: %s", uri)
				}
				u, e := url.Parse(uri)
				if e != nil || u.Host != wantHost || u.Hostname() != host {
					t.Fatalf("link host %q (%v) in %s", u.Host, e, uri)
				}
				// The link must be accepted by Rout's own parser and describe the same endpoint.
				target, _, e := ParseTarget(uri)
				if e != nil || target != wantHost {
					t.Fatalf("ParseTarget(%s) = %q %v", uri, target, e)
				}
				if _, e = URIOutbound(uri); e != nil && protocol != "hy2" {
					t.Fatal(e)
				}
				c, e := ClientConfig(p, host, p.PublicPort, 2080)
				if e != nil {
					t.Fatal(e)
				}
				if got := c["outbounds"].([]any)[0].(M)["server"]; got != host {
					t.Fatalf("client config server %v, want the bare host", got)
				}
			})
		}
	}
}

func TestSameNodeExportedForBothFamilies(t *testing.T) {
	setup := ServerSetup{PublicHost: v4Addr, Listen: "::", Family: "ipv4", IPv4: v4Addr, IPv6: v6Addr}
	for _, protocol := range []string{"vless", "anytls", "ss", "hy2", "tuic"} {
		p := linkFixture(t, protocol, v4Addr)
		primary, _ := p.URI()
		label, alt, ok := altLink(setup, p)
		if !ok || label != "IPv6" {
			t.Fatalf("%s: no IPv6 link: %q", protocol, alt)
		}
		// Same service: only the endpoint differs; credentials, parameters and name are identical.
		want := strings.Replace(primary, v4Addr+":", "["+v6Addr+"]:", 1)
		if alt != want {
			t.Fatalf("%s: alternate link differs beyond the host\n%s\n%s", protocol, primary, alt)
		}
	}
	// Exporting from the IPv6 side offers IPv4.
	p := linkFixture(t, "vless", v6Addr)
	if label, alt, ok := altLink(setup, p); !ok || label != "IPv4" || !strings.Contains(alt, "@"+v4Addr+":") {
		t.Fatal(label, alt, ok)
	}
	// No alternate when one listener cannot serve both families, or the host has one family.
	p = linkFixture(t, "vless", v4Addr)
	p.Listen = "0.0.0.0"
	if _, _, ok := altLink(setup, p); ok {
		t.Fatal("IPv6 offered for an IPv4-only listener")
	}
	p.Listen = "::"
	one := setup
	one.IPv6 = ""
	if _, _, ok := altLink(one, p); ok {
		t.Fatal("alternate without a second address")
	}
	p.NAT = true
	if _, _, ok := altLink(setup, p); ok {
		t.Fatal("alternate offered for a legacy NAT entry")
	}
}

func TestRelayIPv6Destinations(t *testing.T) {
	relay := func(target string) Profile {
		return Profile{ID: RandomHex(6), Name: "r", Kind: "relay", Enabled: true, Protocol: "both", Listen: "::", Port: 30000, PublicHost: v4Addr, PublicPort: 30000, Target: target, RelayMode: relayRemote}
	}
	p := relay("[2001:db8::99]:443")
	if e := p.Validate(); e != nil {
		t.Fatal(e)
	}
	c, e := serverConfig(p, t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	for _, s := range c["services"].([]any) {
		svc := s.(M)
		if svc["addr"] != "[::]:30000" || svc["forwarder"].(M)["nodes"].([]any)[0].(M)["addr"] != "[2001:db8::99]:443" {
			t.Fatalf("relay service %+v", svc)
		}
	}
	for in, want := range map[string]string{"[2001:db8::1]:443": "[2001:db8::1]:443", "vpn.example.com:8443": "vpn.example.com:8443", "192.0.2.1:1": "192.0.2.1:1"} {
		got, _, e := ParseTarget(in)
		if e != nil || got != want {
			t.Errorf("ParseTarget(%q) = %q %v", in, got, e)
		}
	}
	for _, bad := range []string{"2001:db8::1:443", "[2001:db8::1]", "[fe80::1%eth0]:443", "[::1:443"} {
		if _, _, e := ParseTarget(bad); e == nil {
			t.Errorf("accepted malformed destination %q", bad)
		}
	}
	// A loop is recognised whichever way the IPv6 public address is written.
	loop := relay("[2001:DB8:0::7]:30000")
	loop.PublicHost = v6Addr
	if e := loop.Validate(); e == nil {
		t.Fatal("IPv6 self-loop through a differently written public address was accepted")
	}
	if e := relayLoop(State{Schema: 1}, loop, nil); e == nil {
		t.Fatal("relayLoop missed the IPv6 self-loop")
	}
	// A relay in front of a local IPv6 service is local, and still loop-checked.
	local := relay("[::1]:30000")
	local.RelayMode = relayLocal
	if e := local.Validate(); e == nil {
		t.Fatal("relay to its own IPv6 listening port was accepted")
	}
	local.Target = "[::1]:31000"
	if e := local.Validate(); e != nil {
		t.Fatal(e)
	}
	// A link pasted for an IPv6 server becomes an IPv6 destination and re-exports correctly.
	node := linkFixture(t, "vless", v6Addr)
	nodeLink, _ := node.URI()
	rel := relay("")
	rel.Protocol = "tcp"
	rel.Target, rel.TargetURI = mustTarget(t, nodeLink), nodeLink
	if e := rel.Validate(); e != nil {
		t.Fatal(e)
	}
	out, e := rel.URI()
	if e != nil || !strings.Contains(out, "@"+v4Addr+":30000") {
		t.Fatalf("relay link %q %v", out, e)
	}
}
func mustTarget(t *testing.T, uri string) string {
	t.Helper()
	target, _, e := ParseTarget(uri)
	if e != nil {
		t.Fatal(e)
	}
	return target
}

func TestRelayFlowAcceptsIPv6Destinations(t *testing.T) {
	prev := relayDialTimeout
	relayDialTimeout = 300 * time.Millisecond
	t.Cleanup(func() { relayDialTimeout = prev })
	for name, input := range map[string]string{
		// bare IPv6 literal, then the port
		"literal":   "2\n\n2001:db8::99\n443\n1\n\n\n",
		"bracketed": "2\n\n[2001:db8::99]:443\n1\n\n\n",
	} {
		t.Run(name, func(t *testing.T) {
			a := relayTestApp(t, ServerSetup{PublicHost: v4Addr, Listen: "0.0.0.0", Network: "both", Family: "ipv4"})
			u, out := testUI(a, input)
			if e := u.relayCreate(); e != nil {
				t.Fatal(e, out.String())
			}
			p := onlyRelay(t, a)
			if p.Target != "[2001:db8::99]:443" || p.RelayMode != relayRemote || p.PublicHost != v4Addr {
				t.Fatalf("%+v", p)
			}
			if !strings.Contains(out.String(), "[2001:db8::99]:443") {
				t.Fatalf("diagram does not show the bracketed destination:\n%s", out)
			}
		})
	}
	// A remote destination is never silently replaced by localhost.
	a := relayTestApp(t, ServerSetup{PublicHost: v4Addr, Listen: "0.0.0.0", Network: "both"})
	u, out := testUI(a, "2\n\n\n2001:db8::99\n443\n1\n\n\n")
	if e := u.relayCreate(); e != nil {
		t.Fatal(e, out.String())
	}
	if p := onlyRelay(t, a); !strings.Contains(p.Target, "2001:db8::99") || isLoopbackHost(strings.Trim(strings.Split(p.Target, "]")[0], "[")) {
		t.Fatalf("remote destination was replaced: %+v", p)
	}
}

// ---- Real IPv6 behaviour (skipped without an IPv6 stack) ----

func TestIPv6OnlyNodeCreation(t *testing.T) {
	requireIPv6(t)
	caps := probeListenCaps()
	a := testApp(t)
	u, out := testUI(a, "V6\n1 3 4\n\n")
	u.detectAddrs = func() Addresses { return Addresses{IPv6: v6Addr} }
	u.caps = func() listenCaps { return caps }
	if e := u.create(); e != nil {
		t.Fatal(e, out.String())
	}
	s, _ := a.Load()
	if len(s.Profiles) != 3 {
		t.Fatalf("created %d nodes", len(s.Profiles))
	}
	for _, p := range s.Profiles {
		if p.Listen != "::" || p.PublicHost != v6Addr || p.PublicPort != p.Port || p.NAT {
			t.Fatalf("%+v", p)
		}
		uri, _ := p.URI()
		if !strings.Contains(uri, "["+v6Addr+"]:"+itoa(p.Port)) {
			t.Fatalf("link %s", uri)
		}
	}
	if st, _ := a.LoadSettings(); st.Server == nil || st.Server.Family != "ipv6" || st.Server.IPv4 != "" {
		t.Fatalf("settings %+v", st.Server)
	}
}

func TestDualStackNodeCreationOneServiceTwoLinks(t *testing.T) {
	requireIPv6(t)
	caps := probeListenCaps()
	if !caps.DualStack {
		t.Skip("this host's [::] listener does not accept IPv4: dual-stack export is deliberately not offered")
	}
	a := testApp(t)
	u, out := testUI(a, "\nDual\n1 3\n\n")
	u.detectAddrs = func() Addresses { return Addresses{IPv4: v4Addr, IPv6: v6Addr} }
	u.caps = func() listenCaps { return caps }
	if e := u.create(); e != nil {
		t.Fatal(e, out.String())
	}
	s, _ := a.Load()
	if len(s.Profiles) != 2 {
		t.Fatalf("a dual-stack host must not duplicate nodes: %d", len(s.Profiles))
	}
	text := out.String()
	for _, p := range s.Profiles {
		if p.Listen != "::" || p.PublicHost != v4Addr {
			t.Fatalf("%+v", p)
		}
		v4, _ := p.URI()
		_, v6, ok := altLink(ServerSetup{Listen: "::", IPv4: v4Addr, IPv6: v6Addr}, p)
		if !ok || !strings.Contains(text, v4) || !strings.Contains(text, v6) || !strings.Contains(text, "Same node, other address: IPv6") {
			t.Fatalf("both links must be shown for %s:\n%s", p.Name, text)
		}
	}
	// The remembered family: the next creation asks nothing about addresses.
	u, out = testUI(a, "More\n1\n\n")
	u.detectAddrs = func() Addresses { t.Fatal("detected again"); return Addresses{} }
	if e := u.create(); e != nil {
		t.Fatal(e, out.String())
	}
}

// ---- Real engines on a dual-stack listener (needs IPv6 and ROUT_TEST_ENGINES) ----

// One node, one listener on "::": clients reach it over IPv4 and over IPv6 with the same
// credentials, for every protocol. This is the evidence behind exporting two links for one node.
func TestIntegrationDualStackListener(t *testing.T) {
	requireIPv6(t)
	a := integrationApp(t)
	if !probeListenCaps().DualStack {
		t.Skip("[::] does not accept IPv4 on this host")
	}
	cert, key, camouflage := tlsFixture(t)
	camHost, camPort, _ := ParseEndpoint(strings.TrimPrefix(camouflage.URL, "https://"))
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "198.51.100.19") }))
	defer origin.Close()
	for _, protocol := range []string{"vless", "anytls", "ss", "hy2", "tuic"} {
		for _, host := range []string{"127.0.0.1", "::1"} {
			t.Run(protocol+"/"+host, func(t *testing.T) {
				isolated := *a
				isolated.Home = t.TempDir()
				p := fixture(t, protocol)
				p.Listen = "::"
				p.Port, _ = freePort()
				p.PublicHost, p.PublicPort = host, p.Port
				p.SNI, p.CertPEM, p.KeyPEM = "example.test", cert, key
				if e := p.Validate(); e != nil {
					t.Fatal(e)
				}
				conf, e := serverConfig(p, t.TempDir())
				if e != nil {
					t.Fatal(e)
				}
				if protocol == "vless" || protocol == "anytls" {
					conf["inbounds"].([]any)[0].(M)["tls"].(M)["reality"].(M)["handshake"] = M{"server": camHost, "server_port": camPort}
				}
				path := configFile(t, conf)
				if e = isolated.checkConfig(path); e != nil {
					t.Fatal(e)
				}
				startEngine(t, profileSockets(p), a.enginePath("sing-box"), "run", "-c", path)
				port, _ := freePort()
				client, e := ClientConfig(p, host, p.Port, port)
				if e != nil {
					t.Fatal(e)
				}
				e = isolated.withClient(client, port, func(proxy string) error {
					ip, e := fetchIP(proxy, origin.URL)
					if e == nil && ip != "198.51.100.19" {
						e = fmt.Errorf("unexpected response %q", ip)
					}
					return e
				})
				if e != nil {
					t.Fatalf("%s over %s through a [::] listener: %v", protocol, host, e)
				}
			})
		}
	}
}

func TestIntegrationDualStackRelay(t *testing.T) {
	requireIPv6(t)
	a := integrationApp(t)
	if !probeListenCaps().DualStack {
		t.Skip("[::] does not accept IPv4 on this host")
	}
	for _, network := range []string{"tcp", "udp"} {
		for _, host := range []string{"127.0.0.1", "::1"} {
			t.Run(network+"/"+host, func(t *testing.T) {
				var target string
				if network == "tcp" {
					l, e := net.Listen("tcp", "[::1]:0") // the destination itself is IPv6
					if e != nil {
						t.Fatal(e)
					}
					defer l.Close()
					target = l.Addr().String()
					go func() {
						for {
							c, e := l.Accept()
							if e != nil {
								return
							}
							go func() { defer c.Close(); b := make([]byte, 64); n, _ := c.Read(b); c.Write(b[:n]) }()
						}
					}()
				} else {
					l, e := net.ListenPacket("udp", "[::1]:0")
					if e != nil {
						t.Fatal(e)
					}
					defer l.Close()
					target = l.LocalAddr().String()
					go func() {
						b := make([]byte, 64)
						for {
							n, addr, e := l.ReadFrom(b)
							if e != nil {
								return
							}
							l.WriteTo(b[:n], addr)
						}
					}()
				}
				port, _ := freePort()
				p := Profile{ID: RandomHex(6), Name: "dual-relay", Kind: "relay", Enabled: true, Protocol: network, Listen: "::", Port: port, PublicHost: "203.0.113.1", PublicPort: port, Target: target, RelayMode: relayRemote}
				if e := p.Validate(); e != nil {
					t.Fatal(e)
				}
				c, e := serverConfig(p, t.TempDir())
				if e != nil {
					t.Fatal(e)
				}
				startEngine(t, profileSockets(p), a.enginePath("gost"), "-C", configFile(t, c))
				conn, e := net.DialTimeout(network, net.JoinHostPort(host, itoa(port)), time.Second)
				if e != nil {
					t.Fatal(e)
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				conn.Write([]byte("ping"))
				b := make([]byte, 4)
				if _, e = io.ReadFull(conn, b); e != nil || string(b) != "ping" {
					t.Fatalf("%s relay over %s to an IPv6 destination: %v", network, host, e)
				}
			})
		}
	}
}
