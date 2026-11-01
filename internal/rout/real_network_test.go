package rout

import (
	"context"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// Real-network tests. They talk to public Internet hosts, so they are OFF by default and are
// not part of the simulated (loopback) suites: set ROUT_TEST_REALNET=1 on a machine whose
// network you want to examine. A skipped or passing run here says nothing about a VPS or
// NAT you did not run it on. IPv6 cases additionally need a working IPv6 route.

func realNet(t *testing.T, hosts ...string) {
	t.Helper()
	if os.Getenv("ROUT_TEST_REALNET") != "1" {
		t.Skip("set ROUT_TEST_REALNET=1 to run tests against the real Internet")
	}
	// An offline machine skips (it proves nothing about the network) rather than fails.
	for _, h := range hosts {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, e := net.DefaultResolver.LookupHost(ctx, h)
		cancel()
		if e != nil {
			t.Skipf("this machine cannot resolve %s (no direct Internet access): %v", h, e)
		}
	}
}

func TestRealNetworkOutboundPoliciesAgainstADualStackHost(t *testing.T) {
	realNet(t, "one.one.one.one")
	const target = "one.one.one.one:443" // publishes both A and AAAA records
	routes := hostRoutes()
	for _, policy := range []string{outIPv4Only, outIPv6Only, outIPv4First, outIPv6First, outAuto} {
		t.Run(policy, func(t *testing.T) {
			wantFamily := map[string]string{outIPv4Only: "ipv4", outIPv6Only: "ipv6", outIPv4First: "ipv4", outIPv6First: "ipv6"}[policy]
			if (wantFamily == "ipv4" && !routes.V4) || (wantFamily == "ipv6" && !routes.V6) {
				t.Skipf("this host has no %s route", wantFamily)
			}
			d := NewPolicyDialer(policy)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			c, rep, e := d.DialContext(ctx, target)
			if e != nil {
				t.Fatalf("%s: %v", policy, e)
			}
			c.Close()
			if wantFamily != "" && rep.Family() != wantFamily {
				t.Fatalf("%s connected over %s, want %s (%v)", policy, rep.Family(), wantFamily, rep.Used)
			}
			t.Logf("%s -> %s", policy, rep.Used)
		})
	}
}

func TestRealNetworkQUICProbeAgainstAPublicServer(t *testing.T) {
	realNet(t, "cloudflare-quic.com")
	// Cloudflare's public QUIC endpoint answers Version Negotiation like any QUIC server.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	addrs, e := net.DefaultResolver.LookupHost(ctx, "cloudflare-quic.com")
	if e != nil || len(addrs) == 0 {
		t.Skipf("cannot resolve a public QUIC host: %v", e)
	}
	network := "udp4"
	if strings.Contains(addrs[0], ":") {
		network = "udp6"
	}
	if e = quicVersionProbe(ctx, network, net.JoinHostPort(addrs[0], "443")); e != nil {
		t.Fatalf("no Version Negotiation from a public QUIC server: %v", e)
	}
}

func TestRealNetworkFullDiagnosisOfALocalRelayToAPublicHost(t *testing.T) {
	realNet(t, "one.one.one.one")
	a := diagApp()
	port, _ := freePort()
	p := nativeRelayProfile(inIPv4, outAuto, "one.one.one.one:443", port)
	p.Listen = "0.0.0.0"
	cfg, _ := nativeRelayConfigOf(p)
	startRelay(t, cfg, func(r *relayRuntime) { r.dialer.RouteTo = routeTo })
	env := defaultDiagEnv()
	env.hasV6 = func() bool { return false }
	rep := a.diagnoseRelay(context.Background(), p, env, diagOpts{})
	t.Log("\n" + rep.Text())
	for _, layer := range []int{1, 2, 3, 4} {
		if !rep.Has(layer, diagOK) {
			t.Errorf("layer %d did not pass", layer)
		}
	}
}
