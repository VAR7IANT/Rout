package rout

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Tests of the layered diagnostics. They are integration-style: real loopback sockets and
// real in-process relays where the layer is about sockets, fakes only for DNS and for the
// engine-based protocol test, which need the network or an engine.

func diagApp() *App {
	return &App{Home: "/nonexistent", BinDir: "/nonexistent", ServiceMode: "none", Language: "en"}
}

// diagEnvFor returns the default environment with a scripted resolver/dialer.
func diagEnvFor(records map[string][]string, dial func(ctx context.Context, network, addr string) (net.Conn, error)) diagEnv {
	env := defaultDiagEnv()
	env.newDialer = func(policy string) *PolicyDialer {
		d := NewPolicyDialer(policy)
		d.Resolver.Lookup = fakeLookup(records, nil)
		d.RouteTo = func(netip.Addr) bool { return true }
		if dial != nil {
			d.Dial = dial
		}
		return d
	}
	env.hasV6 = func() bool { return false }
	return env
}

func stepsText(rep diagReport, layer int) string {
	var b strings.Builder
	for _, s := range rep.Steps {
		if s.Layer == layer {
			b.WriteString(s.Text + "\n")
		}
	}
	return b.String()
}

// ---- kernel socket table ------------------------------------------------------------------

const procTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12346 1 0000000000000000 100 0 0 10 0
   2: 0100007F:C350 0100007F:1F90 01 00000000:00000000 00:00000000 00000000     0        0 12347 1 0000000000000000 20 4 30 10 -1
`
const procTCP6 = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 22345 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000001000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 22346 1 0000000000000000 100 0 0 10 0
   2: B80D01200000000000000000 01000000:01BB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 22347 1 0000000000000000 100 0 0 10 0
`
const procUDP = `   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  100: 00000000:1F90 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 32345 2 0000000000000000 0
  101: 0100007F:1F91 0100007F:0035 01 00000000:00000000 00:00000000 00000000     0        0 32346 2 0000000000000000 0
`

func TestParseProcNetReadsAddressesAndFamilies(t *testing.T) {
	// The IPv6 fixture's third line has a space inside the address column in this file only
	// because of line wrapping; normalize it as the kernel prints it.
	v6 := strings.Replace(procTCP6, "B80D01200000000000000000 01000000", "B80D0120000000000000000001000000", 1)
	tcp := parseProcNet("tcp4", []byte(procTCP))
	if len(tcp) != 2 || tcp[0].Addr() != "0.0.0.0:8080" || tcp[1].Addr() != "127.0.0.1:53" {
		t.Fatalf("tcp4 %v", tcp)
	}
	six := parseProcNet("tcp6", []byte(v6))
	if len(six) != 3 || six[0].Addr() != "[::]:8080" || !six[0].Dual || six[1].Addr() != "[::1]:80" || six[1].Dual || six[2].Addr() != "[2001:db8::1]:443" {
		t.Fatalf("tcp6 %v", six)
	}
	udp := parseProcNet("udp4", []byte(procUDP))
	if len(udp) != 1 || udp[0].Addr() != "0.0.0.0:8080" {
		t.Fatalf("udp4 %v (connected sockets must not count)", udp)
	}
	// Garbage never panics and yields nothing.
	if got := parseProcNet("tcp4", []byte("header\nnot a socket line\n0: zz:zz 0\n")); len(got) != 0 {
		t.Fatal(got)
	}
	if live, e := readSockets(); e == nil {
		for _, s := range live {
			if s.Port == 0 || !s.IP.IsValid() {
				t.Fatalf("bad live entry %+v", s)
			}
		}
	}
}

// ---- layer 1 -------------------------------------------------------------------------------------

func fakeSockets(entries ...sockEntry) func() ([]sockEntry, error) {
	return func() ([]sockEntry, error) { return entries, nil }
}
func sock(network, ip string, port int) sockEntry {
	a := netip.MustParseAddr(ip)
	return sockEntry{Network: network, IP: a, Port: port, Dual: network[3] == '6' && a.IsUnspecified()}
}

func TestLayerOneReportsActualSocketsPerFamily(t *testing.T) {
	a := diagApp()
	p := nativeRelayProfile(inDual, outAuto, "relay-target.example:443", 7100)
	run := func(env diagEnv) diagReport {
		var rep diagReport
		diagger{a: a, rep: &rep}.layerListen(env, p)
		return rep
	}
	env := defaultDiagEnv()
	env.managed = func(*App, Profile) (bool, bool) { return true, true }

	env.sockets = fakeSockets(sock("tcp4", "0.0.0.0", 7100), sock("tcp6", "::", 7100))
	rep := run(env)
	if rep.Count(diagFail) != 0 || !strings.Contains(stepsText(rep, 1), "TCP 0.0.0.0:7100 (IPv4) is listening") || !strings.Contains(stepsText(rep, 1), "TCP [::]:7100 (IPv6) is listening") {
		t.Fatalf("both families bound:\n%s", rep.Text())
	}
	// The IPv6 socket is missing: named, as a failure.
	env.sockets = fakeSockets(sock("tcp4", "0.0.0.0", 7100))
	rep = run(env)
	if !rep.Has(1, diagFail) || !strings.Contains(stepsText(rep, 1), "TCP [::]:7100 (IPv6) is not listening") {
		t.Fatalf("missing IPv6 socket not reported:\n%s", rep.Text())
	}
	// Service stopped.
	env.managed = func(*App, Profile) (bool, bool) { return true, false }
	if rep = run(env); !rep.Has(1, diagFail) || !strings.Contains(rep.Text(), "not running") {
		t.Fatalf("stopped service:\n%s", rep.Text())
	}
}

func TestLayerOneFlagsAFamilyOutsideTheMode(t *testing.T) {
	a := diagApp()
	env := defaultDiagEnv()
	env.managed = func(*App, Profile) (bool, bool) { return false, false }
	p := nativeRelayProfile(inIPv6, outAuto, "relay-target.example:443", 7101)
	env.sockets = fakeSockets(sock("tcp6", "::", 7101), sock("tcp4", "0.0.0.0", 7101))
	var rep diagReport
	diagger{a: a, rep: &rep}.layerListen(env, p)
	if !rep.Has(1, diagWarn) || !strings.Contains(rep.Text(), "outside inbound mode") {
		t.Fatalf("an IPv4 socket next to an IPv6-only relay must be flagged:\n%s", rep.Text())
	}
	// A legacy wildcard says it may accept IPv4 as well, and is not an error.
	legacy := legacyRelayFixture(t)
	legacy.Listen, legacy.Port = "::", 7102
	env.sockets = fakeSockets(sock("tcp6", "::", 7102))
	rep = diagReport{}
	diagger{a: a, rep: &rep}.layerListen(env, legacy)
	if rep.Count(diagFail) != 0 || !strings.Contains(rep.Text(), "may accept IPv4 as well") {
		t.Fatalf("legacy wildcard:\n%s", rep.Text())
	}
}

// ---- layers 2 and 3 -------------------------------------------------------------------------

func TestLayerTwoShowsFamiliesAndChecksPolicy(t *testing.T) {
	a := diagApp()
	records := map[string][]string{"dual.example": {"192.0.2.10", "2001:db8::10"}, "v4.example": {"192.0.2.11"}}
	ok := func(addr string) (net.Conn, error) { c, _ := net.Pipe(); return c, nil }
	env := diagEnvFor(records, func(ctx context.Context, network, addr string) (net.Conn, error) { return ok(addr) })
	run := func(policy, target string) diagReport {
		p := nativeRelayProfile(inIPv4, policy, target, 7200)
		var rep diagReport
		diagger{a: a, rep: &rep}.layerTarget(context.Background(), env, p)
		return rep
	}
	rep := run(outIPv4Only, "dual.example:443")
	text := stepsText(rep, 2)
	if !strings.Contains(text, "IPv4: 192.0.2.10; IPv6: 2001:db8::10") || !strings.Contains(text, `policy "IPv4 only" matches`) || rep.Count(diagFail) != 0 {
		t.Fatalf("dual-stack name, IPv4 only:\n%s", rep.Text())
	}
	if !strings.Contains(stepsText(rep, 3), "TCP connection succeeded: IPv4 192.0.2.10:443") {
		t.Fatalf("layer 3:\n%s", rep.Text())
	}
	// An IPv6-only policy on a name that has no AAAA record cannot work: layer 2 says so, and
	// layer 3 is not attempted.
	rep = run(outIPv6Only, "v4.example:443")
	if !rep.Has(2, diagFail) || !strings.Contains(stepsText(rep, 2), "no usable address") && !strings.Contains(stepsText(rep, 2), "Name resolution failed") {
		t.Fatalf("IPv6 only on an A-only name:\n%s", rep.Text())
	}
	if len(stepsText(rep, 3)) != 0 {
		t.Fatalf("layer 3 ran after a layer 2 failure:\n%s", rep.Text())
	}
	// A literal of the wrong family.
	rep = run(outIPv4Only, "[2001:db8::99]:443")
	if !rep.Has(2, diagFail) || !strings.Contains(rep.Text(), "does not fit outbound policy") {
		t.Fatalf("literal family:\n%s", rep.Text())
	}
	// Preferred family missing: allowed, with a notice.
	rep = run(outIPv6First, "v4.example:443")
	if rep.Count(diagFail) != 0 || !strings.Contains(stepsText(rep, 2), "other family will be used") {
		t.Fatalf("IPv6 first on an A-only name:\n%s", rep.Text())
	}
	// A name that does not exist.
	rep = run(outAuto, "missing.example:443")
	if !rep.Has(2, diagFail) || !strings.Contains(stepsText(rep, 2), "Name resolution failed: missing.example") {
		t.Fatalf("NXDOMAIN:\n%s", rep.Text())
	}
}

func TestLayerThreeNamesTheKindOfConnectFailure(t *testing.T) {
	a := diagApp()
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"refused", os.NewSyscallError("connect", syscall.ECONNREFUSED), "refused the connection (port closed or service not running)"},
		{"timeout", context.DeadlineExceeded, "timed out"},
		{"unreachable", os.NewSyscallError("connect", syscall.ENETUNREACH), "no route to the destination"},
	}
	for _, c := range cases {
		env := diagEnvFor(map[string][]string{"t.example": {"192.0.2.10", "2001:db8::10"}}, func(ctx context.Context, network, addr string) (net.Conn, error) { return nil, c.err })
		p := nativeRelayProfile(inIPv4, outIPv4First, "t.example:443", 7201)
		var rep diagReport
		diagger{a: a, rep: &rep}.layerTarget(context.Background(), env, p)
		text := stepsText(rep, 3)
		if !rep.Has(3, diagFail) || !strings.Contains(text, c.want) {
			t.Errorf("%s: %q not in\n%s", c.name, c.want, rep.Text())
		}
		// Every address that was tried is named, with its reason.
		if !strings.Contains(text, "192.0.2.10:443") || !strings.Contains(text, "[2001:db8::10]:443") {
			t.Errorf("%s: attempts not listed:\n%s", c.name, text)
		}
	}
}

func TestLayerThreeDetectsADomainThatPointsBackAtTheRelay(t *testing.T) {
	a := diagApp()
	env := diagEnvFor(map[string][]string{"me.example": {"127.0.0.1"}}, nil)
	p := nativeRelayProfile(inIPv4, outAuto, "me.example:7202", 7202)
	var rep diagReport
	diagger{a: a, rep: &rep}.layerTarget(context.Background(), env, p)
	if !rep.Has(3, diagFail) || !strings.Contains(rep.Text(), "forwarding loop") {
		t.Fatalf("loop through DNS not detected:\n%s", rep.Text())
	}
}

func TestStaleDNSAnswerIsReportedNotHidden(t *testing.T) {
	a := diagApp()
	var down bool
	env := defaultDiagEnv()
	env.newDialer = func(policy string) *PolicyDialer {
		d := NewPolicyDialer(policy)
		d.RouteTo = func(netip.Addr) bool { return true }
		now := time.Now()
		d.Resolver.Now = func() time.Time { return now }
		d.Resolver.Lookup = func(ctx context.Context, network, host string) ([]netip.Addr, error) {
			if down {
				return nil, &net.DNSError{Err: "server misbehaving", Name: host}
			}
			return []netip.Addr{netip.MustParseAddr("192.0.2.30")}, nil
		}
		d.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) { c, _ := net.Pipe(); return c, nil }
		// Warm the cache, then let it expire while DNS is down.
		_, _ = d.Resolver.Resolve(context.Background(), "s.example", true, true)
		down = true
		now = now.Add(time.Minute)
		return d
	}
	var rep diagReport
	diagger{a: a, rep: &rep}.layerTarget(context.Background(), env, nativeRelayProfile(inIPv4, outAuto, "s.example:443", 7203))
	if !rep.Has(2, diagWarn) || !strings.Contains(rep.Text(), "DNS is temporarily unavailable; using an answer from 60 seconds ago") {
		t.Fatalf("stale answer hidden:\n%s", rep.Text())
	}
}

// ---- layer 4: through the relay ------------------------------------------------------------------

func TestProbeThroughTCPDistinguishesTheOutcomes(t *testing.T) {
	holding, _ := net.Listen("tcp4", "127.0.0.1:0") // accepts and says nothing (a proxy server waiting for a client)
	banner, _ := net.Listen("tcp4", "127.0.0.1:0")  // speaks first (SSH-like)
	t.Cleanup(func() { holding.Close(); banner.Close() })
	go func() {
		for {
			c, e := holding.Accept()
			if e != nil {
				return
			}
			t.Cleanup(func() { c.Close() })
		}
	}()
	go func() {
		for {
			c, e := banner.Accept()
			if e != nil {
				return
			}
			c.Write([]byte("SSH-2.0-test\r\n"))
			c.Close()
		}
	}()
	closed, _ := net.Listen("tcp4", "127.0.0.1:0")
	closedAddr := closed.Addr().String()
	closed.Close()

	relayTo := func(target string) string {
		cfg := nativeRelayConfig{Version: 1, Engine: "rout-relay", ID: "x", Listen: []nativeListen{{"tcp4", "127.0.0.1:0"}}, Target: target, Outbound: outIPv4Only}
		r := startRelay(t, cfg, nil)
		return "127.0.0.1:" + itoa(boundPort(r))
	}
	ctx := context.Background()
	if r := probeThroughTCP(ctx, relayTo(holding.Addr().String())); r.kind != relayHeld {
		t.Errorf("destination that waits: %v %v", r.kind, r.err)
	}
	if r := probeThroughTCP(ctx, relayTo(banner.Addr().String())); r.kind != relayData {
		t.Errorf("destination that speaks first: %v %v", r.kind, r.err)
	}
	// A destination that refuses: the relay accepts the client and closes it at once. This
	// is exactly the case a bare "socket is listening" check would call healthy.
	if r := probeThroughTCP(ctx, relayTo(closedAddr)); r.kind != relayClosedEarly {
		t.Errorf("unreachable destination: %v %v", r.kind, r.err)
	}
	// Nothing at the entry.
	if r := probeThroughTCP(ctx, closedAddr); r.kind != relayRefused {
		t.Errorf("dead entry: %v %v", r.kind, r.err)
	}
}

func TestDiagnoseRelayEndToEndOnALiveRelayIsHonestAboutTheProtocol(t *testing.T) {
	a := diagApp()
	_, echoPort := echoTCP(t, "tcp4", "127.0.0.1:0")
	port, _ := freePort()
	p := nativeRelayProfile(inIPv4, outIPv4Only, "127.0.0.1:"+itoa(echoPort), port)
	p.Listen = "0.0.0.0"
	cfg, _ := nativeRelayConfigOf(p)
	startRelay(t, cfg, nil)
	env := defaultDiagEnv()
	env.hasV6 = func() bool { return false }
	rep := a.diagnoseRelay(context.Background(), p, env, diagOpts{Full: true})
	// Local relay target (loopback): layers 1, 2, 3, 4 pass.
	for _, layer := range []int{1, 3, 4} {
		if !rep.Has(layer, diagOK) {
			t.Errorf("layer %d did not pass:\n%s", layer, rep.Text())
		}
	}
	if rep.Count(diagFail) != 0 {
		t.Fatalf("unexpected failure:\n%s", rep.Text())
	}
	// No protocol information: the report must say the protocol is NOT verified, and must
	// not contain a layer-5 or layer-6 success.
	if rep.Has(5, diagOK) || rep.Has(6, diagOK) {
		t.Fatalf("claimed more than was proved:\n%s", rep.Text())
	}
	if !strings.Contains(rep.Text(), "has not been verified") {
		t.Fatalf("missing the unverified-protocol notice:\n%s", rep.Text())
	}
	// And the verdict does not call the node usable.
	var out bytes.Buffer
	u := &UI{a: a, out: &out}
	u.printReport(rep)
	if strings.Contains(out.String(), "all verified") || !strings.Contains(out.String(), "do not conclude that the whole node works") {
		t.Fatalf("verdict overclaims:\n%s", out.String())
	}
}

func TestDiagnoseRelayRemoteTargetUsesPolicyAndReportsTheEntryFamily(t *testing.T) {
	a := diagApp()
	// A destination server that holds connections; reached through a real relay whose
	// dialer is scripted so the "remote" name resolves to loopback.
	hold, _ := net.Listen("tcp4", "127.0.0.1:0")
	t.Cleanup(func() { hold.Close() })
	go func() {
		for {
			c, e := hold.Accept()
			if e != nil {
				return
			}
			t.Cleanup(func() { c.Close() })
		}
	}()
	port, _ := freePort()
	holdPort := hold.Addr().(*net.TCPAddr).Port
	target := "ft-us.example:" + itoa(holdPort)
	p := nativeRelayProfile(inIPv4, outIPv4First, target, port)
	p.Listen = "0.0.0.0"
	cfg, _ := nativeRelayConfigOf(p)
	startRelay(t, cfg, func(r *relayRuntime) {
		r.dialer.Resolver.Lookup = fakeLookup(map[string][]string{"ft-us.example": {"127.0.0.1"}}, nil)
	})
	env := diagEnvFor(map[string][]string{"ft-us.example": {"127.0.0.1"}}, nil)
	rep := a.diagnoseRelay(context.Background(), p, env, diagOpts{})
	if rep.Count(diagFail) != 0 {
		t.Fatalf("%s", rep.Text())
	}
	if !strings.Contains(stepsText(rep, 4), "inbound IPv4 → outbound IPv4") {
		t.Fatalf("the entry and exit families are not shown:\n%s", rep.Text())
	}
	// With the destination closed, layer 3 fails with the real reason and layer 4 is skipped.
	hold.Close()
	rep = a.diagnoseRelay(context.Background(), p, env, diagOpts{})
	if !rep.Has(3, diagFail) || !strings.Contains(stepsText(rep, 3), "refused the connection") || !strings.Contains(stepsText(rep, 4), "skipping the test through the relay") {
		t.Fatalf("closed destination:\n%s", rep.Text())
	}
}

// ---- QUIC probe --------------------------------------------------------------------------------------

func TestVersionNegotiationDetection(t *testing.T) {
	scid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	vn := append([]byte{0x80, 0, 0, 0, 0, 8}, scid...)
	vn = append(vn, 8, 9, 9, 9, 9, 9, 9, 9, 9, 0, 0, 0, 1)
	if !isVersionNegotiation(vn, scid) {
		t.Fatal("a real Version Negotiation packet was not recognized")
	}
	for name, b := range map[string][]byte{
		"short":            {0x80, 0, 0},
		"short header":     append([]byte{0x40, 0, 0, 0, 0, 8}, scid...),
		"nonzero version":  append([]byte{0x80, 0, 0, 0, 1, 8}, scid...),
		"other connection": append([]byte{0x80, 0, 0, 0, 0, 8}, []byte{9, 9, 9, 9, 9, 9, 9, 9}...),
		"truncated id":     {0x80, 0, 0, 0, 0, 8, 1, 2},
	} {
		if isVersionNegotiation(b, scid) {
			t.Errorf("%s accepted", name)
		}
	}
}

// fakeQUIC answers like any compliant QUIC server: a long-header packet of an unknown
// version gets a Version Negotiation packet echoing the client's source connection ID.
func fakeQUIC(t *testing.T, answer bool) string {
	t.Helper()
	pc, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Skip(e)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		b := make([]byte, 2048)
		for {
			n, from, e := pc.ReadFrom(b)
			if e != nil {
				return
			}
			if !answer || n < 1200 || b[0]&0x80 == 0 {
				continue
			}
			dl := int(b[5])
			sl := int(b[6+dl])
			scid := b[7+dl : 7+dl+sl]
			resp := []byte{0x80, 0, 0, 0, 0, byte(sl)}
			resp = append(resp, scid...)
			resp = append(resp, byte(dl))
			resp = append(resp, b[6:6+dl]...)
			resp = append(resp, 0, 0, 0, 1)
			pc.WriteTo(resp, from)
		}
	}()
	return pc.LocalAddr().String()
}

func TestQUICProbeAgainstRealSockets(t *testing.T) {
	ctx := context.Background()
	if e := quicVersionProbe(ctx, "udp4", fakeQUIC(t, true)); e != nil {
		t.Fatalf("a QUIC endpoint was not recognized: %v", e)
	}
	if e := quicVersionProbe(ctx, "udp4", fakeQUIC(t, false)); !errors.Is(e, errNoQUICAnswer) {
		t.Fatalf("a silent UDP port must be inconclusive, got %v", e)
	}
	// A closed UDP port answers with ICMP port unreachable, which is a definite "no service".
	pc, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	addr := pc.LocalAddr().String()
	pc.Close()
	if e := quicVersionProbe(ctx, "udp4", addr); !errors.Is(e, syscall.ECONNREFUSED) {
		t.Fatalf("closed UDP port: %v", e)
	}
	_ = rand.Reader
}

func TestQUICProbeThroughAUDPRelay(t *testing.T) {
	// The probe sent to a relay's UDP entry must come back through the relay: a UDP relay
	// in front of a (fake) QUIC server forwards the datagram both ways.
	target := fakeQUIC(t, true)
	cfg := nativeRelayConfig{Version: 1, Engine: "rout-relay", ID: "x", Listen: []nativeListen{{"udp4", "127.0.0.1:0"}}, Target: target, Outbound: outIPv4Only}
	r := startRelay(t, cfg, nil)
	entry := strings.SplitN(r.bound[0], " ", 2)[1]
	if e := quicVersionProbe(context.Background(), "udp4", entry); e != nil {
		t.Fatalf("UDP did not make the round trip through the relay: %v", e)
	}
}

func TestLayerThreeUDPUsesQUICOnlyForQUICLinks(t *testing.T) {
	a := diagApp()
	hy2 := "hysteria2://pw@relay-target.example:8443?sni=x.example#h"
	mk := func(uri string) Profile {
		p := nativeRelayProfile(inIPv4, outAuto, "relay-target.example:8443", 7300)
		p.Protocol, p.TargetURI = "udp", uri
		return p
	}
	cases := []struct {
		name  string
		uri   string
		probe error
		level diagLevel
		want  string
	}{
		{"answered", hy2, nil, diagOK, "answered QUIC version negotiation"},
		{"silent", hy2, errNoQUICAnswer, diagWarn, "did not answer the QUIC probe"},
		{"icmp", hy2, syscall.ECONNREFUSED, diagFail, "ICMP port unreachable"},
		{"plain udp", "", nil, diagWarn, "UDP has no connection handshake"},
	}
	for _, c := range cases {
		env := diagEnvFor(map[string][]string{"relay-target.example": {"192.0.2.44"}}, func(ctx context.Context, network, addr string) (net.Conn, error) {
			cc, _ := net.Pipe()
			return cc, nil
		})
		probed := false
		env.quicProbe = func(ctx context.Context, network, addr string) error { probed = true; return c.probe }
		var rep diagReport
		diagger{a: a, rep: &rep}.layerTarget(context.Background(), env, mk(c.uri))
		if !rep.Has(3, c.level) || !strings.Contains(stepsText(rep, 3), c.want) {
			t.Errorf("%s: want %q at level %d:\n%s", c.name, c.want, c.level, rep.Text())
		}
		if probed != (c.uri != "") {
			t.Errorf("%s: QUIC probe used = %v", c.name, probed)
		}
	}
}

// ---- outbound proxy handshakes and the exit diagnosis ----------------------------------------------

// proxyServer is a scripted SOCKS5 or HTTP CONNECT proxy for the credential checks.
func proxyServer(t *testing.T, kind string, user, pass string) string {
	t.Helper()
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Skip(e)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(3 * time.Second))
				switch kind {
				case "socks5", "socks5-anon":
					head := make([]byte, 2)
					if _, e := io.ReadFull(c, head); e != nil {
						return
					}
					io.ReadFull(c, make([]byte, head[1]))
					if kind == "socks5-anon" {
						c.Write([]byte{5, 0})
						return
					}
					c.Write([]byte{5, 2})
					v := make([]byte, 2)
					io.ReadFull(c, v[:2])
					u := make([]byte, v[1])
					io.ReadFull(c, u)
					pl := make([]byte, 1)
					io.ReadFull(c, pl)
					pw := make([]byte, pl[0])
					io.ReadFull(c, pw)
					if string(u) == user && string(pw) == pass {
						c.Write([]byte{1, 0})
					} else {
						c.Write([]byte{1, 1})
					}
				case "http":
					buf := make([]byte, 1024)
					n, _ := c.Read(buf)
					if strings.Contains(string(buf[:n]), "Proxy-Authorization: Basic dGVzdC11c2VyOnNlY3JldA==") { // test-user:secret
						c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
					} else {
						c.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"))
					}
				case "not-a-proxy":
					c.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
				}
			}(c)
		}
	}()
	return l.Addr().String()
}

func proxyAt(protocol, addr, user, pass string) Proxy {
	h, p, _ := ParseEndpoint(addr)
	return Proxy{Protocol: protocol, Host: h, Port: p, Username: user, Password: pass}
}

func TestProxyHandshakeSeparatesAuthFailureFromOtherFailures(t *testing.T) {
	a := diagApp()
	for _, tc := range []struct {
		name, kind, protocol, user, pass string
		want                             proxyHandshakeResult
	}{
		{"socks5 accepted", "socks5", "socks5", "test-user", "secret", proxyAccepted},
		{"socks5 wrong password", "socks5", "socks5", "test-user", "wrong", proxyAuthRejected},
		{"socks5 open proxy", "socks5-anon", "socks5", "u", "p", proxyNoSupport},
		{"socks5 against ssh", "not-a-proxy", "socks5", "u", "p", proxyBadReply},
		{"http accepted", "http", "http", "test-user", "secret", proxyAccepted},
		{"http 407", "http", "http", "test-user", "wrong", proxyAuthRejected},
		{"http against ssh", "not-a-proxy", "http", "u", "p", proxyBadReply},
	} {
		addr := proxyServer(t, tc.kind, "test-user", "secret")
		conn, e := net.Dial("tcp", addr)
		if e != nil {
			t.Fatal(e)
		}
		got, err := a.proxyAuthCheck(context.Background(), conn, proxyAt(tc.protocol, addr, tc.user, tc.pass))
		if got != tc.want {
			t.Errorf("%s: got %v (%v), want %v", tc.name, got, err, tc.want)
		}
	}
}

func TestDiagnoseProxyReportsTheFailingLayerOfARemoteExit(t *testing.T) {
	a := diagApp()
	env := defaultDiagEnv()
	env.hasV6 = func() bool { return false }
	exit := func(p Proxy) Exit { return Exit{ID: "aaaaaaaaaaaa", Name: "remote", Kind: exitRemote, Proxy: p} }

	// 1. Remote exit unreachable (connection failure): layer 3.
	closed, _ := net.Listen("tcp4", "127.0.0.1:0")
	dead := closed.Addr().String()
	closed.Close()
	rep := a.diagnoseProxy(context.Background(), exit(proxyAt("socks5", dead, "u", "p")), env, diagOpts{})
	if layer, ok := rep.Failed(); !ok || layer != 3 || !strings.Contains(rep.Text(), "refused the connection") {
		t.Fatalf("connection failure:\n%s", rep.Text())
	}

	// 2. Authentication failure: layer 5, after layer 3 proved the port.
	addr := proxyServer(t, "socks5", "test-user", "secret")
	rep = a.diagnoseProxy(context.Background(), exit(proxyAt("socks5", addr, "test-user", "WRONG")), env, diagOpts{Full: true})
	if layer, ok := rep.Failed(); !ok || layer != 5 || !rep.Has(3, diagOK) || !strings.Contains(rep.Text(), "rejected the username or password") {
		t.Fatalf("authentication failure:\n%s", rep.Text())
	}

	// 3. Credentials accepted but no verification of the exit address was possible: warn, never a pass.
	addr = proxyServer(t, "socks5", "test-user", "secret")
	env.fullProxy = nil
	rep = a.diagnoseProxy(context.Background(), exit(proxyAt("socks5", addr, "test-user", "secret")), env, diagOpts{Full: true})
	if rep.Count(diagFail) != 0 || !rep.Has(5, diagOK) || !rep.Has(5, diagWarn) || rep.Has(6, diagOK) {
		t.Fatalf("accepted credentials alone must not claim a working exit:\n%s", rep.Text())
	}

	// 4. The full chain: exit addresses per family.
	addr = proxyServer(t, "socks5", "test-user", "secret")
	env.fullProxy = func(*App, Proxy) fullProbe {
		return fullProbe{V4: "198.51.100.77", ErrV6: errors.New("socks connect: network unreachable")}
	}
	rep = a.diagnoseProxy(context.Background(), exit(proxyAt("socks5", addr, "test-user", "secret")), env, diagOpts{Full: true})
	text := rep.Text()
	if rep.Count(diagFail) != 0 || !strings.Contains(text, "Exit IPv4: 198.51.100.77") || !strings.Contains(text, "Exit IPv6: unavailable") || !strings.Contains(text, "Address family that worked: IPv4") {
		t.Fatalf("full chain:\n%s", text)
	}
}

func TestDiagnoseProxyForRemoteNodeLinksAndQUIC(t *testing.T) {
	a := diagApp()
	env := defaultDiagEnv()
	// A QUIC (hy2) remote node behind a UDP-filtering NAT: inconclusive, not a pass.
	link := "hysteria2://secret@" + fakeQUICHostPort(t, false) + "?sni=x.example#r"
	p, e := ParseRemoteNode(link)
	if e != nil {
		t.Fatal(e)
	}
	rep := a.diagnoseProxy(context.Background(), Exit{Kind: exitRemote, RemoteNetwork: "both", Proxy: *p}, env, diagOpts{})
	if !rep.Has(3, diagWarn) || !strings.Contains(rep.Text(), "did not answer the QUIC probe") || rep.Has(3, diagOK) {
		t.Fatalf("QUIC remote node:\n%s", rep.Text())
	}
	link = "hysteria2://secret@" + fakeQUICHostPort(t, true) + "?sni=x.example#r"
	p, _ = ParseRemoteNode(link)
	rep = a.diagnoseProxy(context.Background(), Exit{Kind: exitRemote, RemoteNetwork: "both", Proxy: *p}, env, diagOpts{})
	if !rep.Has(3, diagOK) || !strings.Contains(rep.Text(), "answered QUIC version negotiation") {
		t.Fatalf("QUIC remote node answering:\n%s", rep.Text())
	}
}

func fakeQUICHostPort(t *testing.T, answer bool) string { return fakeQUIC(t, answer) }

// ---- fetch error classification ------------------------------------------------------------------------

func TestFetchErrorsNameTheStage(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{&net.DNSError{Err: "no such host", Name: "x"}, fetchDNS},
		{errors.New(`Get "https://api.ipify.org": socks connect tcp 127.0.0.1:1->api.ipify.org:443: connection refused`), fetchRefused},
		{errors.New(`Get "https://x": socks connect tcp 127.0.0.1:1->x:443: unknown error host unreachable`), fetchRoute},
		{errors.New(`Get "https://x": socks connect tcp 127.0.0.1:1->x:443: unknown error general SOCKS server failure`), fetchProxy},
		{errors.New(`Get "https://x": context deadline exceeded (Client.Timeout exceeded while awaiting headers)`), fetchTimeout},
		{errors.New(`Get "https://x": tls: failed to verify certificate: x509: certificate signed by unknown authority`), fetchTLS},
		{errors.New(`proxyconnect tcp: authentication failed`), fetchAuth},
		{errors.New("something else entirely"), fetchInternal},
	}
	for _, c := range cases {
		if got := classifyFetch(c.err).Kind; got != c.want {
			t.Errorf("%v: %s, want %s", c.err, got, c.want)
		}
	}
	// Every message is specific; none is the old catch-all.
	for _, k := range []string{fetchDNS, fetchRefused, fetchTimeout, fetchRoute, fetchTLS, fetchAuth, fetchProxy} {
		if strings.Contains((&fetchError{Kind: k}).Error(), "连接、认证、TLS 或网络不可用") {
			t.Errorf("%s still uses the catch-all message", k)
		}
	}
	// Credentials in a URL never survive into the detail.
	d := sanitizeFetchDetail(`Get "http://user:hunter2@proxy.example:3128/": dial failed`)
	if strings.Contains(d, "hunter2") {
		t.Fatal(d)
	}
	for log, want := range map[string]string{
		"ERROR outbound/vless[node]: REALITY handshake failed: verification error": "reality",
		"ERROR authentication failed for user":                                     "auth",
		"ERROR dial tcp 1.2.3.4:443: i/o timeout":                                  "timeout",
		"ERROR dial tcp: lookup nope.example: no such host":                        "dns",
		"INFO nothing relevant":                                                    "",
	} {
		if got := classifyClientLog(log); got != want {
			t.Errorf("log %q: %q, want %q", log, got, want)
		}
	}
}

// reportRaces keeps the unused-import guard honest.
var _ sync.Mutex

// ---- regressions from review of the first push ----------------------------------------------------

func TestUDPOnlyRelayStillGetsTheProtocolAndExitLayers(t *testing.T) {
	a := diagApp()
	quic := fakeQUIC(t, true)
	_, quicPort, _ := ParseEndpoint(quic)
	port, _ := freePort()
	// A remote Hysteria2 relay: UDP only, so no TCP entry ever answers layer 4.
	p := nativeRelayProfile(inIPv4, outIPv4Only, "quic-host.example:"+itoa(quicPort), port)
	p.Listen, p.Protocol, p.RelayMode = "0.0.0.0", "udp", relayRemote
	p.TargetURI = "hysteria2://secret@quic-host.example:" + itoa(quicPort) + "?sni=x.example#h"
	cfg, _ := nativeRelayConfigOf(p)
	startRelay(t, cfg, func(r *relayRuntime) {
		r.dialer.Resolver.Lookup = fakeLookup(map[string][]string{"quic-host.example": {"127.0.0.1"}}, nil)
	})
	env := diagEnvFor(map[string][]string{"quic-host.example": {"127.0.0.1"}}, nil)
	ran := 0
	env.full = func(*App, Profile, string, int) fullProbe {
		ran++
		return fullProbe{V4: "198.51.100.19", ErrV6: errors.New("network unreachable")}
	}
	rep := a.diagnoseRelay(context.Background(), p, env, diagOpts{Full: true})
	if ran != 1 || !rep.Has(5, diagOK) || !rep.Has(6, diagOK) {
		t.Fatalf("the engine-based test did not run for a UDP-only relay (ran=%d):\n%s", ran, rep.Text())
	}
	if strings.Contains(rep.Text(), "skipping the protocol test") {
		t.Fatalf("protocol test skipped although the UDP entry answered:\n%s", rep.Text())
	}
	// A definite UDP failure at the entry still stops the protocol layers.
	env.quicProbe = func(context.Context, string, string) error { return syscall.ECONNREFUSED }
	ran = 0
	rep = a.diagnoseRelay(context.Background(), p, env, diagOpts{Full: true})
	if ran != 0 || !rep.Has(4, diagFail) {
		t.Fatalf("a refused UDP entry must stop the run (ran=%d):\n%s", ran, rep.Text())
	}
}

func TestStaleDNSLimitCountsFromTheOriginalAnswer(t *testing.T) {
	// During a sustained outage every refresh used to restart the ten-minute clock, so an
	// obsolete address could be used forever. The limit must hold across repeated refreshes.
	r := NewResolver()
	r.StaleFor = 10 * time.Minute
	var down bool
	r.Lookup = func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		if down {
			return nil, &net.DNSError{Err: "server misbehaving", Name: host}
		}
		return []netip.Addr{netip.MustParseAddr("192.0.2.5")}, nil
	}
	now := time.Now()
	r.Now = func() time.Time { return now }
	if _, e := r.Resolve(context.Background(), "o.example", true, true); e != nil {
		t.Fatal(e)
	}
	down = true
	// A call every 40 seconds (longer than the cache lifetimes) for eleven minutes.
	var lastOK time.Duration
	for elapsed := 40 * time.Second; elapsed <= 11*time.Minute; elapsed += 40 * time.Second {
		now = now.Add(40 * time.Second)
		res, e := r.Resolve(context.Background(), "o.example", true, true)
		if e == nil {
			if !res.Stale {
				t.Fatalf("at %v: an answer from a dead resolver is not stale?", elapsed)
			}
			lastOK = elapsed
			if res.Age < elapsed-time.Second {
				t.Fatalf("at %v: reported age %v is younger than the real age", elapsed, res.Age)
			}
		}
	}
	if lastOK < 9*time.Minute || lastOK >= 10*time.Minute+40*time.Second {
		t.Fatalf("stale answers were served until %v, expected the 10 minute limit", lastOK)
	}
	if _, e := r.Resolve(context.Background(), "o.example", true, true); e == nil {
		t.Fatal("still resolving from a stale answer after the limit")
	}
	// Recovery works: once DNS is back the fresh answer replaces the stale one.
	down = false
	now = now.Add(time.Minute)
	res, e := r.Resolve(context.Background(), "o.example", true, true)
	if e != nil || res.Stale {
		t.Fatalf("recovery: %+v %v", res, e)
	}
}
