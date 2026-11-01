package rout

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// ---- helpers -----------------------------------------------------------------

// echoTCP starts a TCP echo server on addr and returns its port.
func echoTCP(t *testing.T, network, addr string) (net.Listener, int) {
	t.Helper()
	l, e := net.Listen(network, addr)
	if e != nil {
		t.Skipf("cannot listen %s %s: %v", network, addr, e)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	return l, l.Addr().(*net.TCPAddr).Port
}

func echoUDP(t *testing.T, network, addr string) (net.PacketConn, int) {
	t.Helper()
	pc, e := net.ListenPacket(network, addr)
	if e != nil {
		t.Skipf("cannot listen %s %s: %v", network, addr, e)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		b := make([]byte, 2048)
		for {
			n, from, e := pc.ReadFrom(b)
			if e != nil {
				return
			}
			pc.WriteTo(b[:n], from)
		}
	}()
	return pc, pc.LocalAddr().(*net.UDPAddr).Port
}

func ipv6Available() bool {
	l, e := net.Listen("tcp6", "[::1]:0")
	if e != nil {
		return false
	}
	l.Close()
	return true
}

func startRelay(t *testing.T, cfg nativeRelayConfig, tweak func(*relayRuntime)) *relayRuntime {
	t.Helper()
	var logBuf bytes.Buffer
	r := newRelayRuntime(cfg, &lockedWriter{w: &logBuf})
	r.dialer.RouteTo = func(a netip.Addr) bool { return a.Is4() || ipv6Available() }
	if tweak != nil {
		tweak(r)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- r.Serve(ctx, ready) }()
	select {
	case <-ready:
	case e := <-done:
		cancel()
		t.Fatalf("relay did not start: %v\n%s", e, logBuf.String())
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("relay start timeout")
	}
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("relay did not stop")
		}
	})
	return r
}

type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(b []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(b)
}

// boundPort returns the port of the first bound TCP listener.
func boundPort(r *relayRuntime) int {
	for _, b := range r.bound {
		if strings.HasPrefix(b, "tcp") {
			_, p, _ := net.SplitHostPort(strings.SplitN(b, " ", 2)[1])
			n := 0
			for _, c := range p {
				n = n*10 + int(c-'0')
			}
			return n
		}
	}
	return 0
}

func roundTrip(t *testing.T, network, addr string, payload string) error {
	t.Helper()
	c, e := net.DialTimeout(network, addr, 2*time.Second)
	if e != nil {
		return e
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, e = c.Write([]byte(payload)); e != nil {
		return e
	}
	buf := make([]byte, len(payload))
	if _, e = io.ReadFull(c, buf); e != nil {
		return e
	}
	if string(buf) != payload {
		return errors.New("payload mismatch")
	}
	return nil
}

// ---- unit: configuration ---------------------------------------------------------

func nativeRelayProfile(mode, policy, target string, port int) Profile {
	listen := listenAddrFor(mode, "")
	return Profile{ID: "aaaaaaaaaaaa", Name: "r", Kind: "relay", Enabled: true, Protocol: "tcp", Listen: listen, Port: port, PublicHost: "203.0.113.5", PublicPort: port, Target: target, Engine: engineNative, InboundMode: mode, OutboundPolicy: policy}
}

func TestBindSpecsPerMode(t *testing.T) {
	cases := []struct {
		mode, protocol string
		want           []string
	}{
		{inIPv4, "tcp", []string{"tcp4 0.0.0.0:7000"}},
		{inIPv6, "tcp", []string{"tcp6 [::]:7000"}},
		{inDual, "tcp", []string{"tcp4 0.0.0.0:7000", "tcp6 [::]:7000"}},
		{inDual, "both", []string{"tcp4 0.0.0.0:7000", "tcp6 [::]:7000", "udp4 0.0.0.0:7000", "udp6 [::]:7000"}},
		{inIPv6, "udp", []string{"udp6 [::]:7000"}},
	}
	for _, c := range cases {
		p := nativeRelayProfile(c.mode, outAuto, "198.51.100.7:443", 7000)
		p.Protocol = c.protocol
		var got []string
		for _, s := range p.bindSpecs() {
			got = append(got, s.Network+" "+s.Addr())
		}
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s/%s: got %v want %v", c.mode, c.protocol, got, c.want)
		}
	}
	// A specific interface address (legacy NAT hosts) is kept for its own family only.
	p := nativeRelayProfile(inIPv4, outAuto, "198.51.100.7:443", 7000)
	p.Listen = "10.0.0.5"
	if s := p.bindSpecs(); len(s) != 1 || s[0].IP != "10.0.0.5" {
		t.Fatalf("%v", s)
	}
}

func TestEffectiveModeOfLegacyProfiles(t *testing.T) {
	no := false
	cases := []struct {
		listen string
		mapped *bool
		want   string
	}{
		{"0.0.0.0", nil, inIPv4},
		{"::", nil, inDual},
		{"::", &no, inIPv6},
		{"10.1.2.3", nil, inIPv4},
		{"2001:db8::5", nil, inIPv6},
	}
	for _, c := range cases {
		p := Profile{Listen: c.listen, IPv4Mapped: c.mapped}
		if got := p.inboundMode(); got != c.want {
			t.Errorf("%s: %s want %s", c.listen, got, c.want)
		}
	}
	if (Profile{}).outboundPolicy() != outAuto {
		t.Fatal("legacy outbound")
	}
}

func TestNativeRelayValidation(t *testing.T) {
	good := nativeRelayProfile(inDual, outIPv4First, "ft.example.net:44275", 7001)
	if e := good.Validate(); e != nil {
		t.Fatal(e)
	}
	bad := map[string]func(p *Profile){
		"unknown mode":          func(p *Profile) { p.InboundMode = "tri" },
		"unknown policy":        func(p *Profile) { p.OutboundPolicy = "fast" },
		"v4 mode on ::":         func(p *Profile) { p.InboundMode = inIPv4 },
		"v6 mode on 0.0.0.0":    func(p *Profile) { p.InboundMode = inIPv6; p.Listen = "0.0.0.0" },
		"dual on 0.0.0.0":       func(p *Profile) { p.Listen = "0.0.0.0" },
		"ipv6 public in v4":     func(p *Profile) { p.InboundMode = inIPv4; p.Listen = "0.0.0.0"; p.PublicHost = "2001:db8::1" },
		"ipv4 public in v6":     func(p *Profile) { p.InboundMode = inIPv6; p.PublicHost = "203.0.113.5" },
		"v6 literal, v4 only":   func(p *Profile) { p.OutboundPolicy = outIPv4Only; p.Target = "[2001:db8::9]:443" },
		"v4 literal, v6 only":   func(p *Profile) { p.OutboundPolicy = outIPv6Only; p.Target = "198.51.100.9:443" },
		"native on node":        func(p *Profile) { p.Kind = "node" },
		"policy without native": func(p *Profile) { p.Engine = "" },
	}
	for name, f := range bad {
		p := good
		f(&p)
		if e := p.Validate(); e == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// Literals of the allowed family pass.
	for _, c := range [][2]string{{outIPv6Only, "[2001:db8::9]:443"}, {outIPv4Only, "198.51.100.9:443"}, {outIPv6First, "198.51.100.9:443"}} {
		p := good
		p.OutboundPolicy, p.Target = c[0], c[1]
		if e := p.Validate(); e != nil {
			t.Errorf("%v: %v", c, e)
		}
	}
}

// ---- integration (real loopback sockets) -------------------------------------------

func TestNativeRelayTCPIPv4ToIPv4(t *testing.T) {
	_, port := echoTCP(t, "tcp4", "127.0.0.1:0")
	p := nativeRelayProfile(inIPv4, outIPv4Only, "127.0.0.1:"+itoa(port), 0)
	p.Listen = "127.0.0.1"
	p.Port = 0
	cfg, _ := nativeRelayConfigOf(p)
	cfg.Listen = []nativeListen{{"tcp4", "127.0.0.1:0"}}
	r := startRelay(t, cfg, nil)
	if e := roundTrip(t, "tcp4", "127.0.0.1:"+itoa(boundPort(r)), "hello v4"); e != nil {
		t.Fatal(e)
	}
	if r.stats.accepted.Load() != 1 {
		t.Fatal("not counted")
	}
}

func TestNativeRelayUDPForwarding(t *testing.T) {
	_, port := echoUDP(t, "udp4", "127.0.0.1:0")
	cfg := nativeRelayConfig{Version: 1, Engine: "rout-relay", ID: "x", Listen: []nativeListen{{"udp4", "127.0.0.1:0"}}, Target: "127.0.0.1:" + itoa(port), Outbound: outIPv4Only}
	var udpAddr string
	r := startRelay(t, cfg, nil)
	for _, b := range r.bound {
		udpAddr = strings.SplitN(b, " ", 2)[1]
	}
	for i := 0; i < 2; i++ { // two datagrams in one session, then a second client
		c, e := net.Dial("udp4", udpAddr)
		if e != nil {
			t.Fatal(e)
		}
		defer c.Close()
		for _, msg := range []string{"one", "two"} {
			c.SetDeadline(time.Now().Add(2 * time.Second))
			c.Write([]byte(msg))
			b := make([]byte, 16)
			n, e := c.Read(b)
			if e != nil || string(b[:n]) != msg {
				t.Fatalf("udp echo %q: %v %q", msg, e, b[:n])
			}
		}
	}
	if r.stats.udpSessions.Load() != 2 {
		t.Fatalf("sessions: %d", r.stats.udpSessions.Load())
	}
}

func TestNativeRelayUDPIdleSessionsAreReaped(t *testing.T) {
	_, port := echoUDP(t, "udp4", "127.0.0.1:0")
	cfg := nativeRelayConfig{Version: 1, Engine: "rout-relay", ID: "x", Listen: []nativeListen{{"udp4", "127.0.0.1:0"}}, Target: "127.0.0.1:" + itoa(port), Outbound: outIPv4Only, UDPIdleSec: 1}
	r := startRelay(t, cfg, nil)
	addr := strings.SplitN(r.bound[0], " ", 2)[1]
	c, _ := net.Dial("udp4", addr)
	defer c.Close()
	c.Write([]byte("x"))
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	c.Read(make([]byte, 4))
	time.Sleep(2500 * time.Millisecond)
	c.Write([]byte("y")) // a new session is created after the first one was reaped
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, e := c.Read(make([]byte, 4)); e != nil {
		t.Fatal(e)
	}
	if r.stats.udpSessions.Load() != 2 {
		t.Fatalf("expected a fresh session after reaping, got %d", r.stats.udpSessions.Load())
	}
}

func TestNativeRelayRefusesToForwardToItself(t *testing.T) {
	cfg := nativeRelayConfig{Version: 1, Engine: "rout-relay", ID: "x", Listen: []nativeListen{{"tcp4", "127.0.0.1:0"}}, Target: "127.0.0.1:1", Outbound: outIPv4Only}
	var r *relayRuntime
	r = startRelay(t, cfg, func(rt *relayRuntime) {
		// Point the target at the relay's own (not yet known) port once bound.
		rt.listenTCP = func(network, addr string) (net.Listener, error) {
			l, e := net.Listen(network, addr)
			if e == nil {
				rt.cfg.Target = "127.0.0.1:" + itoa(l.Addr().(*net.TCPAddr).Port)
			}
			return l, e
		}
	})
	c, e := net.Dial("tcp4", "127.0.0.1:"+itoa(boundPort(r)))
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, e = c.Read(make([]byte, 1)); e == nil {
		t.Fatal("expected the relay to close the connection")
	}
	if r.stats.dialFail.Load() != 1 {
		t.Fatal("loop dial was not refused")
	}
}

func TestNativeRelayHalfCloseAndLargeTransfer(t *testing.T) {
	// A server that reads to EOF and then answers: needs half-close propagation.
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Skip(e)
	}
	defer l.Close()
	go func() {
		c, e := l.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		b, _ := io.ReadAll(c)
		c.Write([]byte(strings.ToUpper(string(b))))
	}()
	cfg := nativeRelayConfig{Version: 1, Engine: "rout-relay", ID: "x", Listen: []nativeListen{{"tcp4", "127.0.0.1:0"}}, Target: l.Addr().String(), Outbound: outAuto}
	r := startRelay(t, cfg, nil)
	c, e := net.Dial("tcp4", "127.0.0.1:"+itoa(boundPort(r)))
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	payload := strings.Repeat("abc", 200000)
	go func() { c.Write([]byte(payload)); c.(*net.TCPConn).CloseWrite() }()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, e := io.ReadAll(c)
	if e != nil || string(got) != strings.ToUpper(payload) {
		t.Fatalf("half-close transfer failed: %v (%d bytes)", e, len(got))
	}
}

func TestNativeRelayRefusesWhenLimitReached(t *testing.T) {
	_, port := echoTCP(t, "tcp4", "127.0.0.1:0")
	cfg := nativeRelayConfig{Version: 1, Engine: "rout-relay", ID: "x", Listen: []nativeListen{{"tcp4", "127.0.0.1:0"}}, Target: "127.0.0.1:" + itoa(port), Outbound: outIPv4Only, MaxConns: 1}
	r := startRelay(t, cfg, nil)
	addr := "127.0.0.1:" + itoa(boundPort(r))
	first, e := net.Dial("tcp4", addr)
	if e != nil {
		t.Fatal(e)
	}
	defer first.Close()
	first.Write([]byte("a"))
	first.Read(make([]byte, 1)) // established through the relay
	second, e := net.Dial("tcp4", addr)
	if e != nil {
		t.Fatal(e)
	}
	defer second.Close()
	second.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, e = second.Read(make([]byte, 1)); e == nil {
		t.Fatal("second connection should have been refused")
	}
	if r.stats.refusedBusy.Load() != 1 {
		t.Fatal("limit not enforced")
	}
}

func TestNativeRelayBindFailureClosesEverything(t *testing.T) {
	var opened, closed atomic.Int32
	cfg := nativeRelayConfig{Version: 1, Engine: "rout-relay", ID: "x", Listen: []nativeListen{{"tcp4", "127.0.0.1:0"}, {"tcp6", "[::1]:0"}}, Target: "127.0.0.1:9", Outbound: outAuto}
	r := newRelayRuntime(cfg, io.Discard)
	r.listenTCP = func(network, addr string) (net.Listener, error) {
		if network == "tcp6" {
			return nil, errors.New("address family not supported")
		}
		l, e := net.Listen(network, addr)
		if e == nil {
			opened.Add(1)
			return &countingListener{Listener: l, closed: &closed}, nil
		}
		return l, e
	}
	e := r.Serve(context.Background(), nil)
	if e == nil || !strings.Contains(e.Error(), "tcp6") {
		t.Fatalf("expected a tcp6 bind error, got %v", e)
	}
	if opened.Load() != 1 || closed.Load() != 1 {
		t.Fatalf("partial bind leaked: opened=%d closed=%d", opened.Load(), closed.Load())
	}
}

type countingListener struct {
	net.Listener
	closed *atomic.Int32
}

func (c *countingListener) Close() error { c.closed.Add(1); return c.Listener.Close() }

// ---- IPv6 (skipped on hosts without IPv6) ----------------------------------------------

func TestNativeRelayIPv6OnlyDoesNotAcceptIPv4(t *testing.T) {
	requireIPv6(t)
	_, port := echoTCP(t, "tcp4", "127.0.0.1:0")
	cfg := nativeRelayConfig{Version: 1, Engine: "rout-relay", ID: "x", Listen: []nativeListen{{"tcp6", "[::]:0"}}, Target: "127.0.0.1:" + itoa(port), Outbound: outIPv4Only}
	r := startRelay(t, cfg, nil)
	p := itoa(boundPort(r))
	if e := roundTrip(t, "tcp6", "[::1]:"+p, "v6 in, v4 out"); e != nil {
		t.Fatalf("IPv6 in -> IPv4 out: %v", e)
	}
	if e := roundTrip(t, "tcp4", "127.0.0.1:"+p, "x"); e == nil {
		t.Fatal("an IPv6-only relay accepted an IPv4 connection (IPV6_V6ONLY not set)")
	}
}

func TestNativeRelayDualStackUsesTwoSocketsOnOnePort(t *testing.T) {
	requireIPv6(t)
	_, port := echoTCP(t, "tcp4", "127.0.0.1:0")
	// Find a port free in both families, then bind both explicitly.
	l, e := net.Listen("tcp4", "0.0.0.0:0")
	if e != nil {
		t.Skip(e)
	}
	fp := l.Addr().(*net.TCPAddr).Port
	l.Close()
	cfg := nativeRelayConfig{Version: 1, Engine: "rout-relay", ID: "x", Listen: []nativeListen{{"tcp4", "0.0.0.0:" + itoa(fp)}, {"tcp6", "[::]:" + itoa(fp)}}, Target: "127.0.0.1:" + itoa(port), Outbound: outIPv4Only}
	r := startRelay(t, cfg, nil)
	if len(r.bound) != 2 {
		t.Fatalf("bound %v", r.bound)
	}
	for _, c := range [][2]string{{"tcp4", "127.0.0.1"}, {"tcp6", "[::1]"}} {
		if e := roundTrip(t, c[0], c[1]+":"+itoa(fp), "dual "+c[0]); e != nil {
			t.Fatalf("%s: %v", c[0], e)
		}
	}
}

func TestNativeRelayIPv4InToIPv6Out(t *testing.T) {
	requireIPv6(t)
	_, port := echoTCP(t, "tcp6", "[::1]:0")
	cfg := nativeRelayConfig{Version: 1, Engine: "rout-relay", ID: "x", Listen: []nativeListen{{"tcp4", "127.0.0.1:0"}}, Target: "[::1]:" + itoa(port), Outbound: outIPv6Only}
	r := startRelay(t, cfg, nil)
	if e := roundTrip(t, "tcp4", "127.0.0.1:"+itoa(boundPort(r)), "v4 in, v6 out"); e != nil {
		t.Fatal(e)
	}
}

// ---- dialer policy (injected resolver and dial: independent of the host's families) ----

type dialRecorder struct {
	mu    sync.Mutex
	calls []string
	fail  map[string]error // address -> error
	delay map[string]time.Duration
}

func (d *dialRecorder) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	d.mu.Lock()
	d.calls = append(d.calls, network+" "+addr)
	err := d.fail[addr]
	delay := d.delay[addr]
	d.mu.Unlock()
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if err != nil {
		return nil, err
	}
	a, b := net.Pipe()
	go func() { io.Copy(io.Discard, b) }()
	return a, nil
}
func (d *dialRecorder) list() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return strings.Join(d.calls, " | ")
}

func fakeLookup(records map[string][]string, counter *atomic.Int32) func(context.Context, string, string) ([]netip.Addr, error) {
	return func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		if counter != nil {
			counter.Add(1)
		}
		var out []netip.Addr
		for _, s := range records[host] {
			a := netip.MustParseAddr(s)
			if network == "ip4" && !a.Is4() || network == "ip6" && !a.Is6() {
				continue
			}
			out = append(out, a)
		}
		if len(out) == 0 {
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		}
		return out, nil
	}
}

func policyDialer(policy string, rec *dialRecorder, records map[string][]string, routes familyRoutes) *PolicyDialer {
	d := NewPolicyDialer(policy)
	d.Resolver.Lookup = fakeLookup(records, nil)
	d.RouteTo = func(a netip.Addr) bool {
		if a.Is4() {
			return routes.V4
		}
		return routes.V6
	}
	d.Dial = rec.dial
	d.Timeout = 500 * time.Millisecond
	return d
}

func TestOutboundPolicyOrderAndFiltering(t *testing.T) {
	both := map[string][]string{"x.example": {"2001:db8::1", "192.0.2.1"}}
	cases := []struct {
		policy string
		routes familyRoutes
		want   string
	}{
		{outIPv4First, familyRoutes{true, true}, "tcp4 192.0.2.1:443"},
		{outIPv6First, familyRoutes{true, true}, "tcp6 [2001:db8::1]:443"},
		{outIPv4Only, familyRoutes{true, true}, "tcp4 192.0.2.1:443"},
		{outIPv6Only, familyRoutes{true, true}, "tcp6 [2001:db8::1]:443"},
	}
	for _, c := range cases {
		rec := &dialRecorder{}
		d := policyDialer(c.policy, rec, both, c.routes)
		conn, rep, e := d.DialContext(context.Background(), "x.example:443")
		if e != nil {
			t.Fatalf("%s: %v", c.policy, e)
		}
		conn.Close()
		if rec.list() != c.want {
			t.Errorf("%s dialed %q, want %q", c.policy, rec.list(), c.want)
		}
		if (c.want[3] == '4') != (rep.Family() == "ipv4") {
			t.Errorf("%s: report family %s", c.policy, rep.Family())
		}
	}
}

func TestOnlyPoliciesNeverTryTheOtherFamily(t *testing.T) {
	// IPv4-only: the IPv4 address fails; the IPv6 address must not be tried as a fallback.
	rec := &dialRecorder{fail: map[string]error{"192.0.2.1:443": syscallRefused()}}
	d := policyDialer(outIPv4Only, rec, map[string][]string{"x.example": {"192.0.2.1", "2001:db8::1"}}, familyRoutes{true, true})
	_, _, e := d.DialContext(context.Background(), "x.example:443")
	if e == nil || strings.Contains(rec.list(), "2001:db8") {
		t.Fatalf("ipv4_only touched IPv6: %v / %s", e, rec.list())
	}
	var de *DialError
	if !errors.As(e, &de) || de.Kind != kindRefused || de.Stage != stageConnect {
		t.Fatalf("want connect/refused, got %#v", e)
	}
	rec = &dialRecorder{fail: map[string]error{"[2001:db8::1]:443": syscallRefused()}}
	d = policyDialer(outIPv6Only, rec, map[string][]string{"x.example": {"192.0.2.1", "2001:db8::1"}}, familyRoutes{true, true})
	if _, _, e = d.DialContext(context.Background(), "x.example:443"); e == nil || strings.Contains(rec.list(), "192.0.2.1") {
		t.Fatalf("ipv6_only touched IPv4: %v / %s", e, rec.list())
	}
}

func TestPreferredPolicyFallsBackToTheOtherFamily(t *testing.T) {
	rec := &dialRecorder{fail: map[string]error{"192.0.2.1:443": syscallRefused()}}
	d := policyDialer(outIPv4First, rec, map[string][]string{"x.example": {"192.0.2.1", "2001:db8::1"}}, familyRoutes{true, true})
	c, rep, e := d.DialContext(context.Background(), "x.example:443")
	if e != nil {
		t.Fatal(e)
	}
	c.Close()
	if rep.Family() != "ipv6" || !strings.HasPrefix(rec.list(), "tcp4 192.0.2.1:443") {
		t.Fatalf("fallback order wrong: %s (%s)", rec.list(), rep.Family())
	}
}

func syscallRefused() error {
	return &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
}

func TestLiteralOfForbiddenFamilyIsRefusedWithoutDialing(t *testing.T) {
	for _, c := range []struct{ policy, target string }{{outIPv4Only, "[2001:db8::7]:443"}, {outIPv6Only, "192.0.2.7:443"}} {
		rec := &dialRecorder{}
		d := policyDialer(c.policy, rec, nil, familyRoutes{true, true})
		_, _, e := d.DialContext(context.Background(), c.target)
		var de *DialError
		if !errors.As(e, &de) || de.Kind != kindFamily || rec.list() != "" {
			t.Fatalf("%s %s: %v dialed=%q", c.policy, c.target, e, rec.list())
		}
	}
}

func TestIPv4MappedLiteralIsTreatedAsIPv4(t *testing.T) {
	rec := &dialRecorder{}
	d := policyDialer(outIPv4Only, rec, nil, familyRoutes{true, true})
	c, _, e := d.DialContext(context.Background(), "[::ffff:192.0.2.9]:443")
	if e != nil {
		t.Fatal(e)
	}
	c.Close()
	if rec.list() != "tcp4 192.0.2.9:443" {
		t.Fatal(rec.list())
	}
	d = policyDialer(outIPv6Only, &dialRecorder{}, nil, familyRoutes{true, true})
	if _, _, e = d.DialContext(context.Background(), "[::ffff:192.0.2.9]:443"); e == nil {
		t.Fatal("an IPv4-mapped literal must not pass as IPv6")
	}
}

func TestNoRecordOfTheRequiredFamily(t *testing.T) {
	rec := &dialRecorder{}
	d := policyDialer(outIPv6Only, rec, map[string][]string{"v4only.example": {"192.0.2.1"}}, familyRoutes{true, true})
	_, _, e := d.DialContext(context.Background(), "v4only.example:443")
	var de *DialError
	if !errors.As(e, &de) || de.Stage != stageResolve || de.Kind != kindDNS {
		// Only A records exist and AAAA was the only query: the lookup itself reports no host.
		t.Fatalf("got %#v", e)
	}
	if rec.list() != "" {
		t.Fatal("dialed despite no AAAA record")
	}
}

func TestAutoDropsFamiliesWithoutARoute(t *testing.T) {
	rec := &dialRecorder{}
	d := policyDialer(outAuto, rec, map[string][]string{"x.example": {"2001:db8::1", "192.0.2.1"}}, familyRoutes{V4: true, V6: false})
	c, _, e := d.DialContext(context.Background(), "x.example:443")
	if e != nil {
		t.Fatal(e)
	}
	c.Close()
	if rec.list() != "tcp4 192.0.2.1:443" {
		t.Fatalf("auto used a family without a route: %s", rec.list())
	}
	// No route for the only available family is reported as unreachable, not as DNS.
	d = policyDialer(outAuto, &dialRecorder{}, map[string][]string{"x.example": {"2001:db8::1"}}, familyRoutes{V4: true, V6: false})
	_, _, e = d.DialContext(context.Background(), "x.example:443")
	var de *DialError
	if !errors.As(e, &de) || de.Kind != kindUnreachable {
		t.Fatalf("got %#v", e)
	}
}

func TestAutoHappyEyeballsDoesNotWaitForABlackholedFamily(t *testing.T) {
	rec := &dialRecorder{delay: map[string]time.Duration{"[2001:db8::1]:443": 3 * time.Second}}
	d := policyDialer(outAuto, rec, map[string][]string{"x.example": {"2001:db8::1", "192.0.2.1"}}, familyRoutes{true, true})
	d.HappyEyeballsDelay = 50 * time.Millisecond
	d.Timeout = 5 * time.Second
	start := time.Now()
	c, rep, e := d.DialContext(context.Background(), "x.example:443")
	if e != nil {
		t.Fatal(e)
	}
	c.Close()
	if time.Since(start) > time.Second || rep.Family() != "ipv4" {
		t.Fatalf("auto waited %v (family %s)", time.Since(start), rep.Family())
	}
	// The family that worked is preferred next time.
	rec2 := &dialRecorder{}
	d.Dial = rec2.dial
	c, _, _ = d.DialContext(context.Background(), "x.example:443")
	c.Close()
	if !strings.HasPrefix(rec2.list(), "tcp4 ") {
		t.Fatalf("remembered family not preferred: %s", rec2.list())
	}
}

// ---- resolver: TTL, dynamic domains, stale answers -----------------------------------

func TestResolverTTLAndDynamicDomain(t *testing.T) {
	var calls atomic.Int32
	records := map[string][]string{"dyn.example": {"192.0.2.1"}}
	var mu sync.Mutex
	r := NewResolver()
	r.Lookup = func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		mu.Lock()
		defer mu.Unlock()
		return fakeLookup(records, &calls)(ctx, network, host)
	}
	now := time.Now()
	r.Now = func() time.Time { return now }
	r.TTL = 30 * time.Second
	get := func() string {
		res, e := r.Resolve(context.Background(), "dyn.example", true, true)
		if e != nil {
			t.Fatal(e)
		}
		return res.Addrs[0].String()
	}
	if get() != "192.0.2.1" || get() != "192.0.2.1" || calls.Load() != 1 {
		t.Fatalf("not cached: %d lookups", calls.Load())
	}
	mu.Lock()
	records["dyn.example"] = []string{"192.0.2.99"}
	mu.Unlock()
	if get() != "192.0.2.1" {
		t.Fatal("changed before the TTL ran out")
	}
	now = now.Add(31 * time.Second)
	if get() != "192.0.2.99" || calls.Load() != 2 {
		t.Fatal("new address not picked up after the TTL")
	}
}

func TestDialReresolvesWhenEveryCachedAddressFails(t *testing.T) {
	records := map[string][]string{"dyn.example": {"192.0.2.1"}}
	var mu sync.Mutex
	rec := &dialRecorder{fail: map[string]error{"192.0.2.1:443": syscallRefused()}}
	d := NewPolicyDialer(outIPv4First)
	d.RouteTo = func(netip.Addr) bool { return true }
	d.Resolver.Lookup = func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		mu.Lock()
		defer mu.Unlock()
		return fakeLookup(records, nil)(ctx, network, host)
	}
	d.Dial = rec.dial
	// Warm the cache with the old address.
	if _, _, e := d.DialContext(context.Background(), "dyn.example:443"); e == nil {
		t.Fatal("the old address should fail")
	}
	mu.Lock()
	records["dyn.example"] = []string{"192.0.2.77"} // the NAT changed address
	mu.Unlock()
	c, rep, e := d.DialContext(context.Background(), "dyn.example:443")
	if e != nil {
		t.Fatalf("dial did not recover after the address changed: %v (%s)", e, rec.list())
	}
	c.Close()
	if rep.Used.Addr().String() != "192.0.2.77" {
		t.Fatal(rep.Used)
	}
}

func TestResolverServesStaleAnswerWhenDNSFails(t *testing.T) {
	var down atomic.Bool
	r := NewResolver()
	r.Lookup = func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		if down.Load() {
			return nil, &net.DNSError{Err: "server misbehaving", Name: host}
		}
		return []netip.Addr{netip.MustParseAddr("192.0.2.5")}, nil
	}
	now := time.Now()
	r.Now = func() time.Time { return now }
	if _, e := r.Resolve(context.Background(), "a.example", true, true); e != nil {
		t.Fatal(e)
	}
	down.Store(true)
	now = now.Add(time.Minute)
	res, e := r.Resolve(context.Background(), "a.example", true, true)
	if e != nil || !res.Stale || res.Addrs[0].String() != "192.0.2.5" {
		t.Fatalf("stale fallback: %#v %v", res, e)
	}
	now = now.Add(time.Hour) // beyond StaleFor
	if _, e = r.Resolve(context.Background(), "a.example", true, true); e == nil {
		t.Fatal("an answer older than StaleFor must not be used")
	}
}

func TestResolverReportsDNSFailureWithItsStage(t *testing.T) {
	d := policyDialer(outAuto, &dialRecorder{}, map[string][]string{}, familyRoutes{true, true})
	_, rep, e := d.DialContext(context.Background(), "missing.example:443")
	var de *DialError
	if !errors.As(e, &de) || de.Stage != stageResolve || de.Kind != kindDNS || len(rep.Attempts) != 0 {
		t.Fatalf("%#v", e)
	}
}

func TestResolverCoalescesConcurrentLookups(t *testing.T) {
	var calls atomic.Int32
	gate := make(chan struct{})
	r := NewResolver()
	r.Lookup = func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		calls.Add(1)
		<-gate
		return []netip.Addr{netip.MustParseAddr("192.0.2.5")}, nil
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); r.Resolve(context.Background(), "c.example", true, true) }()
	}
	time.Sleep(100 * time.Millisecond)
	close(gate)
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("%d lookups for 8 concurrent callers", calls.Load())
	}
}

func TestNativeRelayRealPortConflictNamesTheFamily(t *testing.T) {
	occupied, e := net.Listen("tcp4", "0.0.0.0:0")
	if e != nil {
		t.Skip(e)
	}
	defer occupied.Close()
	port := occupied.Addr().(*net.TCPAddr).Port
	cfg := nativeRelayConfig{Version: 1, Engine: "rout-relay", ID: "x", Listen: []nativeListen{{"tcp4", "0.0.0.0:" + itoa(port)}}, Target: "198.51.100.7:443", Outbound: outAuto}
	err := newRelayRuntime(cfg, io.Discard).Serve(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "cannot listen on tcp4") || !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("got %v", err)
	}
	// The same check at save time, before anything is written.
	p := nativeRelayProfile(inIPv4, outAuto, "198.51.100.7:443", port)
	p.Listen = "0.0.0.0"
	if e = CheckAvailable(p); e == nil || !strings.Contains(e.Error(), "IPv4") {
		t.Fatalf("CheckAvailable: %v", e)
	}
}

func TestNativeRelayStopReleasesEverySocket(t *testing.T) {
	// Changing a relay's family restarts it; the old sockets must be gone the moment it stops.
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Skip(e)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	cfg := nativeRelayConfig{Version: 1, Engine: "rout-relay", ID: "x", Listen: []nativeListen{{"tcp4", "127.0.0.1:" + itoa(port)}, {"udp4", "127.0.0.1:" + itoa(port)}}, Target: "127.0.0.1:9", Outbound: outIPv4Only}
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- newRelayRuntime(cfg, io.Discard).Serve(ctx, ready) }()
	<-ready
	// While it runs, both ports are taken.
	if _, e = net.Listen("tcp4", "127.0.0.1:"+itoa(port)); e == nil {
		t.Fatal("TCP port free while the relay runs")
	}
	cancel()
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	tl, e := net.Listen("tcp4", "127.0.0.1:"+itoa(port))
	if e != nil {
		t.Fatalf("TCP socket leaked after stop: %v", e)
	}
	tl.Close()
	uc, e := net.ListenPacket("udp4", "127.0.0.1:"+itoa(port))
	if e != nil {
		t.Fatalf("UDP socket leaked after stop: %v", e)
	}
	uc.Close()
}

func TestNativeRelayDoesNotLeakGoroutinesAcrossRestarts(t *testing.T) {
	_, port := echoTCP(t, "tcp4", "127.0.0.1:0")
	run := func() {
		cfg := nativeRelayConfig{Version: 1, Engine: "rout-relay", ID: "x", Listen: []nativeListen{{"tcp4", "127.0.0.1:0"}}, Target: "127.0.0.1:" + itoa(port), Outbound: outIPv4Only}
		r := newRelayRuntime(cfg, io.Discard)
		ctx, cancel := context.WithCancel(context.Background())
		ready := make(chan struct{})
		done := make(chan error, 1)
		go func() { done <- r.Serve(ctx, ready) }()
		<-ready
		c, e := net.Dial("tcp4", "127.0.0.1:"+itoa(boundPort(r)))
		if e == nil {
			c.Write([]byte("x"))
			c.Read(make([]byte, 1))
			c.Close()
		}
		cancel()
		<-done
	}
	run() // warm up lazily started runtime goroutines
	before := runtimeGoroutines()
	for i := 0; i < 20; i++ {
		run()
	}
	time.Sleep(200 * time.Millisecond)
	if after := runtimeGoroutines(); after > before+5 {
		t.Fatalf("goroutines grew from %d to %d over 20 restarts", before, after)
	}
}

func runtimeGoroutines() int { return runtime.NumGoroutine() }

func TestNativeRelayStopsPromptlyWithLongLivedTunnelsOpen(t *testing.T) {
	// A proxy tunnel can stay open for hours. Stopping the relay (systemctl stop, a restart,
	// a configuration change) must close it, not wait for it.
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Skip(e)
	}
	defer l.Close()
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			go func() { io.Copy(io.Discard, c) }() // never closes by itself
		}
	}()
	cfg := nativeRelayConfig{Version: 1, Engine: "rout-relay", ID: "x", Listen: []nativeListen{{"tcp4", "127.0.0.1:0"}}, Target: l.Addr().String(), Outbound: outIPv4Only}
	r := newRelayRuntime(cfg, io.Discard)
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- r.Serve(ctx, ready) }()
	<-ready
	var clients []net.Conn
	for i := 0; i < 5; i++ {
		c, e := net.Dial("tcp4", "127.0.0.1:"+itoa(boundPort(r)))
		if e != nil {
			t.Fatal(e)
		}
		defer c.Close()
		c.Write([]byte("hold"))
		clients = append(clients, c)
	}
	time.Sleep(100 * time.Millisecond)
	start := time.Now()
	cancel()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the relay did not stop while tunnels were open")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("stop took %v", time.Since(start))
	}
	for _, c := range clients {
		c.SetReadDeadline(time.Now().Add(time.Second))
		if _, e := c.Read(make([]byte, 1)); e == nil {
			t.Fatal("a tunnel survived the relay")
		}
	}
}
