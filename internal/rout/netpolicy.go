package rout

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Address-family model.
//
// Two independent settings describe how an entry uses the network:
//
//   - the INBOUND mode says which IP families it accepts connections on;
//   - the OUTBOUND policy says which families it may use to reach its destination.
//
// They never influence each other: an IPv6-only entry may forward to an IPv4 server and
// the reverse. Both are stored explicitly on the profile. A profile written by an older
// version carries neither; its mode is then derived from the listening address, exactly as
// those versions behaved (see Profile.inboundMode).
const (
	inIPv4 = "ipv4"
	inIPv6 = "ipv6"
	inDual = "dual"

	outIPv4First = "ipv4_first"
	outIPv6First = "ipv6_first"
	outIPv4Only  = "ipv4_only"
	outIPv6Only  = "ipv6_only"
	outAuto      = "auto"

	// engineNative marks a relay served by Rout's own forwarder (see relay_native.go)
	// instead of the legacy GOST service. Only the native forwarder can bind a family
	// exclusively (IPV6_V6ONLY), apply an outbound policy and re-resolve a domain.
	engineNative = "native"
)

func validInboundMode(m string) bool { return m == inIPv4 || m == inIPv6 || m == inDual }
func validOutboundPolicy(m string) bool {
	switch m {
	case outIPv4First, outIPv6First, outIPv4Only, outIPv6Only, outAuto:
		return true
	}
	return false
}

// inboundLabel and outboundLabel are the menu texts (also used in previews).
func inboundLabel(m string) string {
	switch m {
	case inIPv4:
		return "IPv4"
	case inIPv6:
		return "IPv6"
	case inDual:
		return "双栈"
	}
	return m
}
func outboundLabel(m string) string {
	switch m {
	case outIPv4First:
		return "IPv4 优先"
	case outIPv6First:
		return "IPv6 优先"
	case outIPv4Only:
		return "仅 IPv4"
	case outIPv6Only:
		return "仅 IPv6"
	case outAuto:
		return "自动"
	}
	return m
}

// outboundAllows says which families an outbound policy may use at all.
func outboundAllows(policy string) (v4, v6 bool) {
	switch policy {
	case outIPv4Only:
		return true, false
	case outIPv6Only:
		return false, true
	}
	return true, true
}

// inboundAllows says which families clients may reach an entry with.
func inboundAllows(mode string) (v4, v6 bool) {
	switch mode {
	case inIPv4:
		return true, false
	case inIPv6:
		return false, true
	}
	return true, true
}

// inboundMode is the effective inbound mode. An explicit setting wins; a profile from an
// older version is classified by what its listening address does: 0.0.0.0 is IPv4 only,
// a specific address serves its own family, and "::" serves both families unless a probe at
// creation recorded that IPv4 does not reach it (IPv4Mapped false).
func (p Profile) inboundMode() string {
	if p.InboundMode != "" {
		return p.InboundMode
	}
	ip := net.ParseIP(p.Listen)
	switch {
	case ip == nil, ip.To4() != nil:
		return inIPv4
	case ip.IsUnspecified():
		if p.IPv4Mapped != nil && !*p.IPv4Mapped {
			return inIPv6
		}
		return inDual
	}
	return inIPv6
}

// outboundPolicy is the effective outbound policy. A legacy relay lets the engine resolve
// and dial however it likes, which is what "auto" means.
func (p Profile) outboundPolicy() string {
	if p.OutboundPolicy != "" {
		return p.OutboundPolicy
	}
	return outAuto
}

func (p Profile) nativeRelay() bool { return p.Kind == "relay" && p.Engine == engineNative }

// listenAddrFor returns the local address a mode binds. A specific interface address the
// user chose earlier (NAT hosts) is kept when its family matches the mode.
func listenAddrFor(mode, current string) string {
	ip := net.ParseIP(current)
	switch mode {
	case inIPv4:
		if ip != nil && ip.To4() != nil {
			return current
		}
		return "0.0.0.0"
	case inIPv6:
		if ip != nil && ip.To4() == nil {
			return current
		}
	}
	return "::"
}

// listenSpec is one socket a native entry binds. The network is always an explicit
// family ("tcp4", "tcp6", "udp4", "udp6"): Go sets IPV6_V6ONLY on every "6" network, so
// the result never depends on the kernel's bindv6only default or on a wildcard fallback.
type listenSpec struct {
	Network string
	IP      string
	Port    int
}

func (s listenSpec) Addr() string { return net.JoinHostPort(s.IP, strconv.Itoa(s.Port)) }
func (s listenSpec) String() string {
	return strings.ToUpper(s.Network[:3]) + " " + s.Addr() + " (" + familyName(s.Network) + ")"
}
func familyName(network string) string {
	if strings.HasSuffix(network, "6") {
		return "IPv6"
	}
	return "IPv4"
}

// bindSpecs lists the sockets of a native entry. Dual stack is TWO sockets, one per
// family, so IPv4 and IPv6 are bound and diagnosed independently and nothing relies on a
// dual-stack wildcard socket.
func (p Profile) bindSpecs() []listenSpec {
	var out []listenSpec
	mode := p.inboundMode()
	v4, v6 := inboundAllows(mode)
	for _, n := range p.Networks() {
		if v4 {
			ip := "0.0.0.0"
			if f := net.ParseIP(p.Listen); f != nil && f.To4() != nil && mode == inIPv4 {
				ip = p.Listen
			}
			out = append(out, listenSpec{Network: n + "4", IP: ip, Port: p.Port})
		}
		if v6 {
			ip := "::"
			if f := net.ParseIP(p.Listen); f != nil && f.To4() == nil && !f.IsUnspecified() && mode == inIPv6 {
				ip = p.Listen
			}
			out = append(out, listenSpec{Network: n + "6", IP: ip, Port: p.Port})
		}
	}
	return out
}

// validateNetPolicy checks the explicit fields; legacy profiles (all empty) pass.
func (p Profile) validateNetPolicy() error {
	if p.InboundMode != "" && !validInboundMode(p.InboundMode) {
		return errors.New("入站网络模式无效")
	}
	if p.OutboundPolicy != "" && !validOutboundPolicy(p.OutboundPolicy) {
		return errors.New("出站网络策略无效")
	}
	if e := p.checkNodeEgress(); e != nil {
		return e
	}
	if p.Engine != "" && p.Engine != engineNative {
		return errors.New("中转引擎无效")
	}
	if p.Engine == engineNative && p.Kind != "relay" {
		return errors.New("只有中转可以使用内置转发引擎")
	}
	if p.Kind == "relay" && p.OutboundPolicy != "" && p.Engine != engineNative {
		return errors.New("出站网络策略需要内置转发引擎")
	}
	if p.InboundMode == "" {
		return nil
	}
	ip := net.ParseIP(p.Listen)
	if ip == nil {
		return errors.New("监听地址无效")
	}
	switch p.InboundMode {
	case inIPv4:
		if ip.To4() == nil {
			return errors.New("入站模式 IPv4 与监听地址不匹配")
		}
	case inIPv6:
		if ip.To4() != nil {
			return errors.New("入站模式 IPv6 与监听地址不匹配")
		}
	case inDual:
		if p.Listen != "::" {
			return errors.New("双栈入站必须监听 ::")
		}
	}
	// The address clients are told to use must be reachable in the chosen mode.
	if f := familyOf(p.PublicHost); f != "" {
		v4, v6 := inboundAllows(p.InboundMode)
		if (f == "ipv4" && !v4) || (f == "ipv6" && !v6) {
			return fmt.Errorf("公网地址 %s 的地址族与入站模式 %s 不匹配", p.PublicHost, inboundLabel(p.InboundMode))
		}
	}
	return nil
}

// checkRelayFamilies validates a relay destination against its outbound policy, so a
// literal address the policy forbids is refused when the relay is saved, not at the first
// connection.
func (p Profile) checkRelayFamilies() error {
	if !p.nativeRelay() {
		return nil
	}
	h, _, e := ParseEndpoint(p.Target)
	if e != nil {
		return nil
	}
	f := familyOf(h)
	if f == "" {
		return nil
	}
	v4, v6 := outboundAllows(p.outboundPolicy())
	if (f == "ipv4" && !v4) || (f == "ipv6" && !v6) {
		return fmt.Errorf("目标 %s 是 %s 地址，出站策略「%s」不允许使用", h, map[string]string{"ipv4": "IPv4", "ipv6": "IPv6"}[f], outboundLabel(p.outboundPolicy()))
	}
	return nil
}
