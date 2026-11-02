package remote

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
)

func TestCheckIPBlocksDangerousDestinations(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "127.1.2.3", "::1", "0.0.0.0", "::", "10.0.0.5", "172.16.0.1", "172.31.255.254",
		"192.168.1.1", "169.254.169.254", "169.254.0.1", "100.64.0.1", "100.100.100.200", "198.18.0.1",
		"192.0.2.10", "198.51.100.7", "203.0.113.9", "224.0.0.1", "239.255.255.250", "240.0.0.1",
		"255.255.255.255", "fe80::1", "fd00:ec2::254", "fc00::1", "ff02::1", "::ffff:127.0.0.1",
		"::ffff:10.0.0.1", "::ffff:169.254.169.254", "64:ff9b::7f00:1", "2002:7f00:1::1", "2001::1",
		"2001:db8::1", "100::1", "fec0::1", "::2",
	}
	for _, s := range blocked {
		ip := netip.MustParseAddr(s)
		if err := CheckIP(ip); !errors.Is(err, ErrBlockedAddress) {
			t.Errorf("%s must be blocked, got %v", s, err)
		}
	}
	allowed := []string{"1.1.1.1", "8.8.8.8", "93.184.216.34", "104.16.0.1", "2606:4700:4700::1111", "2001:4860:4860::8888"}
	for _, s := range allowed {
		if err := CheckIP(netip.MustParseAddr(s)); err != nil {
			t.Errorf("%s must be allowed, got %v", s, err)
		}
	}
	// A zone identifier must not hide a link-local address.
	if err := CheckIP(netip.MustParseAddr("fe80::1%eth0")); err == nil {
		t.Error("zoned link-local address must be blocked")
	}
}

func TestValidateURL(t *testing.T) {
	good := []string{"https://example.org/sub?token=abc", "http://example.org:8080/a", "https://user:pw@example.org/x", "https://8.8.8.8/x"}
	for _, u := range good {
		if _, err := ValidateURL(u); err != nil {
			t.Errorf("%s should be valid: %v", u, err)
		}
	}
	bad := []string{
		"", "ftp://example.org/a", "file:///etc/passwd", "gopher://example.org", "javascript:alert(1)", "//example.org/a",
		"http://localhost/a", "http://LOCALHOST./a", "http://foo.localhost/a", "http://127.0.0.1/a", "http://[::1]/a",
		"http://169.254.169.254/latest/meta-data", "http://metadata.google.internal/", "https://printer.local/x",
		"http://10.0.0.1:8080/", "http://192.168.0.10/", "http://0.0.0.0/", "http://[::ffff:127.0.0.1]/",
		"https://example.org:0/", "https://example.org:70000/", "https://exämple.org/", "https://a b.org/",
		"https://example.org/\nHost: evil", "http://[fd00:ec2::254]/", "http://2130706433/",
		"https://" + strings.Repeat("a", 5000) + ".org/",
	}
	for _, u := range bad {
		if _, err := ValidateURL(u); err == nil {
			t.Errorf("%q must be rejected", u)
		}
	}
}

// dialRecorder replaces the real network: it records the address that would be connected to.
type dialRecorder struct{ addrs []string }

func (d *dialRecorder) dial(_ context.Context, _, address string) (net.Conn, error) {
	d.addrs = append(d.addrs, address)
	c, _ := net.Pipe()
	return c, nil
}

func newTestGuard(answers func(call int) []netip.Addr) (*guard, *dialRecorder, *int) {
	rec := &dialRecorder{}
	calls := 0
	g := &guard{check: CheckIP, dial: rec.dial}
	g.lookup = func(_ context.Context, _ string) ([]netip.Addr, error) {
		calls++
		return answers(calls), nil
	}
	return g, rec, &calls
}

func TestGuardDialsTheValidatedAddress(t *testing.T) {
	g, rec, calls := newTestGuard(func(int) []netip.Addr { return []netip.Addr{netip.MustParseAddr("93.184.216.34")} })
	conn, err := g.DialContext(context.Background(), "tcp", "sub.example.org:443")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if *calls != 1 {
		t.Fatalf("name must be resolved exactly once per connection, got %d", *calls)
	}
	if len(rec.addrs) != 1 || rec.addrs[0] != "93.184.216.34:443" {
		t.Fatalf("must connect to the validated IP, not the name: %v", rec.addrs)
	}
}

func TestGuardRefusesRebindingAndMixedAnswers(t *testing.T) {
	// DNS rebinding: the first answer is public, the next one is the metadata service.
	g, rec, _ := newTestGuard(func(call int) []netip.Addr {
		if call == 1 {
			return []netip.Addr{netip.MustParseAddr("93.184.216.34")}
		}
		return []netip.Addr{netip.MustParseAddr("169.254.169.254")}
	})
	if c, err := g.DialContext(context.Background(), "tcp", "rebind.example.org:80"); err != nil {
		t.Fatal(err)
	} else {
		c.Close()
	}
	if _, err := g.DialContext(context.Background(), "tcp", "rebind.example.org:80"); !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("second resolution to a private address must be refused, got %v", err)
	}
	if len(rec.addrs) != 1 {
		t.Fatalf("no connection may be made to the rebinding answer: %v", rec.addrs)
	}
	// Mixed answers: one public and one private record. Picking the public one would still
	// let a later retry reach the private one, so the whole answer is refused.
	g, rec, _ = newTestGuard(func(int) []netip.Addr {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("10.0.0.7")}
	})
	if _, err := g.DialContext(context.Background(), "tcp", "mixed.example.org:443"); !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("mixed answer must be refused, got %v", err)
	}
	if len(rec.addrs) != 0 {
		t.Fatal("nothing may be dialled for a refused answer")
	}
	// IP literals skip DNS but not the check.
	g, rec, calls := newTestGuard(func(int) []netip.Addr { return nil })
	for _, addr := range []string{"127.0.0.1:80", "[::1]:80", "[::ffff:192.168.1.1]:80", "169.254.169.254:80"} {
		if _, err := g.DialContext(context.Background(), "tcp", addr); !errors.Is(err, ErrBlockedAddress) {
			t.Errorf("%s must be refused, got %v", addr, err)
		}
	}
	if *calls != 0 || len(rec.addrs) != 0 {
		t.Fatal("literals must not be resolved or dialled")
	}
}

func TestGuardControlHookRechecksTheSocketAddress(t *testing.T) {
	g := newGuard()
	for _, addr := range []string{"127.0.0.1:80", "[::1]:443", "10.1.1.1:80", "169.254.169.254:80", "not-an-address"} {
		if err := g.control("tcp", addr, nil); err == nil {
			t.Errorf("control must refuse %s", addr)
		}
	}
	if err := g.control("tcp", "93.184.216.34:443", nil); err != nil {
		t.Errorf("public address refused: %v", err)
	}
}
