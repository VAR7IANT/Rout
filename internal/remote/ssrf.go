// Package remote imports third-party proxy subscriptions. Everything it reads is treated as
// hostile: addresses are validated where the connection is really made, bodies and YAML are
// bounded, and nothing here touches Rout's own nodes or configuration.
package remote

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"time"
)

// blockedPrefixes are destinations a subscription download must never reach: loopback,
// private and shared address space, link-local (including cloud metadata at 169.254.169.254),
// documentation and benchmarking ranges, multicast/reserved, and the IPv6 transition
// mechanisms that can smuggle an IPv4 address past a naive check.
var blockedPrefixes = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
		"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"::/96", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/32", "2001:2::/48",
		"2001:db8::/32", "2002::/16", "fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8",
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// ErrBlockedAddress marks a refused destination.
var ErrBlockedAddress = errors.New("目标地址被禁止（回环、内网、链路本地、云元数据或保留地址）")

// CheckIP returns ErrBlockedAddress for any address a download must not connect to.
// IPv4-mapped IPv6 addresses are judged as the IPv4 address they carry.
func CheckIP(ip netip.Addr) error {
	ip = ip.WithZone("").Unmap()
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
		return ErrBlockedAddress
	}
	for _, p := range blockedPrefixes {
		if p.Contains(ip) {
			return ErrBlockedAddress
		}
	}
	return nil
}

// guard resolves and connects. The address that is validated is the address that is
// dialled: names are resolved exactly once per connection, every answer must pass (a mixed
// public/private answer is refused, which defeats rebinding by multiple A records), and the
// socket's Control hook checks the address once more at connect time.
type guard struct {
	lookup func(ctx context.Context, host string) ([]netip.Addr, error)
	check  func(netip.Addr) error
	dial   func(ctx context.Context, network, address string) (net.Conn, error)
}

func newGuard() *guard {
	g := &guard{
		check: CheckIP,
		lookup: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		},
	}
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: -1, Control: g.control}
	g.dial = d.DialContext
	return g
}

func (g *guard) control(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return ErrBlockedAddress
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return ErrBlockedAddress
	}
	return g.check(ip)
}

func (g *guard) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	var addrs []netip.Addr
	if ip, perr := netip.ParseAddr(strings.Trim(host, "[]")); perr == nil {
		addrs = []netip.Addr{ip}
	} else {
		addrs, err = g.lookup(ctx, host)
		if err != nil {
			return nil, userError("域名解析失败")
		}
	}
	if len(addrs) == 0 {
		return nil, errors.New("域名没有解析结果")
	}
	for _, ip := range addrs {
		if e := g.check(ip); e != nil {
			return nil, e
		}
	}
	var last error
	for _, ip := range addrs {
		conn, e := g.dial(ctx, network, net.JoinHostPort(ip.String(), port))
		if e == nil {
			return conn, nil
		}
		last = e
		if ctx.Err() != nil {
			break
		}
	}
	return nil, last
}

// sensitiveHost reports names that can only mean "this machine or its network".
func sensitiveHost(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if h == "localhost" || h == "metadata" || h == "metadata.google.internal" {
		return true
	}
	for _, suffix := range []string{".localhost", ".local", ".internal", ".localdomain", ".lan", ".home", ".corp", ".intranet", ".private"} {
		if strings.HasSuffix(h, suffix) {
			return true
		}
	}
	return false
}
