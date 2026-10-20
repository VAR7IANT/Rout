package rout

import (
	"net"
	"sync"
	"time"
)

// Addresses are the public addresses clients can use to reach this host, one per family
// ("" when the family is unavailable). They are what a share link points at; the local
// listening address (Listen) is a separate setting.
type Addresses struct{ IPv4, IPv6 string }

var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

// publicIPv4 accepts globally routable IPv4 addresses only: private (RFC 1918), CGNAT
// (100.64/10), loopback, link-local and multicast addresses are rejected.
func publicIPv4(ip net.IP) bool {
	return ip != nil && ip.To4() != nil && ip.IsGlobalUnicast() && !ip.IsPrivate() && !cgnat.Contains(ip)
}

// publicIPv6 accepts global unicast IPv6 addresses. Link-local (fe80::/10), unique-local
// (fc00::/7), loopback, multicast and IPv4-mapped addresses are rejected: a link-local
// address is never reachable by a client, even though the interface has one.
func publicIPv6(ip net.IP) bool {
	return ip != nil && ip.To4() == nil && ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLinkLocalUnicast()
}

// interfaceAddrs is replaced by tests.
var interfaceAddrs = net.InterfaceAddrs

type ifaceScan struct {
	known  bool      // the interface list could be read
	anyV4  bool      // some non-loopback, non-link-local IPv4 exists (maybe private, behind NAT)
	public Addresses // first globally routable address of each family
}

func scanInterfaces() ifaceScan {
	var out ifaceScan
	addrs, e := interfaceAddrs()
	if e != nil {
		return out
	}
	out.known = true
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip := n.IP
		if ip4 := ip.To4(); ip4 != nil {
			if !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsUnspecified() {
				out.anyV4 = true
			}
			if out.public.IPv4 == "" && publicIPv4(ip) {
				out.public.IPv4 = ip.String()
			}
		} else if out.public.IPv6 == "" && publicIPv6(ip) {
			out.public.IPv6 = ip.String()
		}
	}
	return out
}

// DetectAddresses finds this host's public IPv4 and IPv6 addresses. An external echo
// service is asked per family (it also sees through NAT), but only for a family the host
// plausibly has; when the service is unreachable the interface addresses are used. Every
// result is validated, so a link-local or private IPv6 address is never returned.
func DetectAddresses() Addresses {
	scan := scanInterfaces()
	var ext4, ext6 string
	var wg sync.WaitGroup
	if !scan.known || scan.anyV4 {
		wg.Add(1)
		go func() { defer wg.Done(); ext4 = detectDirect("tcp4") }()
	}
	if !scan.known || scan.public.IPv6 != "" {
		wg.Add(1)
		go func() { defer wg.Done(); ext6 = detectDirect("tcp6") }()
	}
	wg.Wait()
	out := scan.public
	if publicIPv4(net.ParseIP(ext4)) {
		out.IPv4 = ext4
	}
	if ip := net.ParseIP(ext6); publicIPv6(ip) {
		out.IPv6 = ip.String()
	}
	return out
}

// familyOf names the family of an IP literal ("" for a domain).
func familyOf(host string) string {
	ip := net.ParseIP(host)
	switch {
	case ip == nil:
		return ""
	case ip.To4() != nil:
		return "ipv4"
	}
	return "ipv6"
}

// listenCaps describes what this host's network stack lets a listener do.
type listenCaps struct {
	V4        bool // required sockets can bind 0.0.0.0
	V6        bool // a socket can bind [::]
	DualStack bool // a [::] listener also accepts IPv4 (IPV6_V6ONLY is off for it)
}

// probeCaps is replaced by tests.
var probeCaps = probeListenCaps

// probeListenCaps checks local sockets, independently of public address detection.
// Explicit family binds avoid Go's wildcard fallback when a family is disabled.
// Dual-stack is offered only when engine-style [::] sockets accept IPv4 on
// every required transport; a successful IPv6 bind alone does not establish this.
func probeListenCaps() listenCaps {
	// Keep the existing server/relay TCP probe; new nodes pass their required transports.
	return probeListenCapsWith(net.Listen, net.ListenPacket, net.DialTimeout, "tcp")
}

func probeListenCapsWith(listen func(string, string) (net.Listener, error), packet func(string, string) (net.PacketConn, error), dial func(string, string, time.Duration) (net.Conn, error), networks ...string) listenCaps {
	if len(networks) == 0 {
		networks = []string{"tcp", "udp"}
	}
	family := func(suffix, host string) bool {
		for _, network := range networks {
			addr := net.JoinHostPort(host, "0")
			if network == "tcp" {
				l, e := listen("tcp"+suffix, addr)
				if e != nil {
					return false
				}
				l.Close()
			} else {
				p, e := packet("udp"+suffix, addr)
				if e != nil {
					return false
				}
				p.Close()
			}
		}
		return true
	}
	caps := listenCaps{V4: family("4", "0.0.0.0"), V6: family("6", "::")}
	if !caps.V4 || !caps.V6 {
		return caps
	}
	if contains(networks, "tcp") {
		l, e := listen("tcp", "[::]:0")
		if e != nil {
			return caps
		}
		defer l.Close()
		// A generic wildcard can fall back to IPv4; that is not an IPv6 listener.
		if l.Addr().(*net.TCPAddr).IP.To4() != nil {
			return caps
		}
		port := l.Addr().(*net.TCPAddr).Port
		c, e := dial("tcp4", net.JoinHostPort("127.0.0.1", itoa(port)), time.Second)
		if e != nil {
			return caps
		}
		c.Close()
	}
	if !contains(networks, "udp") {
		caps.DualStack = true
		return caps
	}
	p, e := packet("udp", "[::]:0")
	if e != nil {
		return caps
	}
	defer p.Close()
	if p.LocalAddr().(*net.UDPAddr).IP.To4() != nil {
		return caps
	}
	port := p.LocalAddr().(*net.UDPAddr).Port
	c, e := dial("udp4", net.JoinHostPort("127.0.0.1", itoa(port)), time.Second)
	if e != nil {
		return caps
	}
	defer c.Close()
	if e = c.SetWriteDeadline(time.Now().Add(time.Second)); e != nil {
		return caps
	}
	if _, e = c.Write([]byte("rout")); e != nil {
		return caps
	}
	if e = p.SetReadDeadline(time.Now().Add(time.Second)); e != nil {
		return caps
	}
	b := make([]byte, 16)
	n, _, e := p.ReadFrom(b)
	caps.DualStack = e == nil && string(b[:n]) == "rout"
	return caps
}

// chooseListen retains the server/relay defaults. New node creation uses
// nodeListeningSetup independently so saved wildcard defaults cannot override IPv4.
//
//   - a host with a usable global IPv6 address and a working dual-stack socket listens on
//     "::", which serves IPv4 and IPv6 clients with ONE listener (no duplicate nodes);
//   - an IPv6-only host listens on "::";
//   - otherwise "0.0.0.0" keeps the long-standing IPv4 behaviour.
//
// A saved address that is neither wildcard (a specific interface address chosen by the
// user earlier) is kept as is.
func chooseListen(family string, addrs Addresses, caps listenCaps, saved string) string {
	if saved != "" && saved != "0.0.0.0" && saved != "::" && net.ParseIP(saved) != nil {
		return saved
	}
	hasV4, hasV6 := addrs.IPv4 != "", addrs.IPv6 != ""
	switch {
	case family == "ipv6" && !hasV4:
		return "::" // IPv6-only host: nothing else to listen on
	case hasV6 && caps.V6 && caps.DualStack:
		return "::"
	case family == "ipv6":
		return "::"
	}
	return "0.0.0.0"
}
