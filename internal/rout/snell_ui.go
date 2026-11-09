package rout

import (
	"net"
	"strings"
)

// hasSnell reports whether a batch of protocol ids contains a Snell node.
func hasSnell(protocols []string) bool {
	return contains(protocols, protoSnell) || contains(protocols, snell6Alias)
}

// listenItemsFor narrows the listening choices for a batch that contains Snell. snell-server
// cannot bind IPv6 exclusively (no IPV6_V6ONLY switch, and Rout will not fake one with a
// firewall rule), so "IPv6 only" is offered only where the host has no IPv4 at all and a
// wildcard IPv6 socket is IPv6-only by necessity.
func listenItemsFor(items []menuItem, caps listenCaps, protocols []string) []menuItem {
	if !hasSnell(protocols) || !caps.V4 {
		return items
	}
	out := make([]menuItem, 0, len(items))
	for _, it := range items {
		if it.key != inIPv6 {
			out = append(out, it)
		}
	}
	return out
}

// snellListenMenu changes where a Snell node listens: IPv4, dual stack, or one address of
// this host. The public address stays what it was; Rout refuses a combination that makes it
// unreachable (see Profile.Validate), so nothing is silently rewritten.
func (u *UI) snellListenMenu(p *Profile) error {
	caps := u.listenCapabilities("tcp")
	items := listenItemsFor(nodeListenOptions(caps), caps, []string{protoSnell})
	items = append(items, itemNote("custom", "指定本机 IP", "只在这个地址上监听；必须是本机网卡上的地址"))
	choice := u.option("监听地址", items, p.inboundMode())
	if u.err != nil || choice == "" {
		return u.err
	}
	switch choice {
	case inIPv4:
		p.Listen, p.InboundMode, p.IPv4Mapped = "0.0.0.0", inIPv4, nil
	case inDual:
		mapped := caps.DualStack
		p.Listen, p.InboundMode, p.IPv4Mapped = "::", inDual, &mapped
	case inIPv6:
		mapped := false
		p.Listen, p.InboundMode, p.IPv4Mapped = "::", inIPv6, &mapped
	case "custom":
		for u.err == nil {
			ip := strings.TrimSpace(u.ask("本机 IP 地址", ""))
			if u.err != nil {
				return u.err
			}
			parsed := net.ParseIP(ip)
			if parsed == nil || parsed.IsUnspecified() || parsed.IsMulticast() || !localIPs()[parsed.String()] {
				u.say("该地址不是本机网卡上的地址")
				continue
			}
			p.Listen, p.IPv4Mapped = parsed.String(), nil
			p.InboundMode = inIPv6
			if parsed.To4() != nil {
				p.InboundMode = inIPv4
			}
			break
		}
	}
	return u.err
}

// snellPSKMenu sets a PSK of the user's choosing (the default is a random 32 characters).
func (u *UI) snellPSKMenu(p *Profile) error {
	u.say("Snell PSK：12–255 个字符，只能包含字母、数字和 . _ ~ + -（留空取消）")
	psk := strings.TrimSpace(u.secret("新的 PSK"))
	if u.err != nil {
		return u.err
	}
	if psk == "" {
		return errCancelled
	}
	if e := validSnellPSK(psk); e != nil {
		return e
	}
	p.Password = psk
	return nil
}

// snellNotes prints what a person must know about a freshly created Snell node and that the
// Surge line alone does not say.
func (u *UI) snellNotes(p Profile, setup ServerSetup) {
	if !p.snellNode() {
		return
	}
	if p.snellVersion() == snellV6 {
		u.warn("Snell v6 目前是官方 Beta：协议可能发生不兼容变更，服务器和 Surge 都需要保持最新 Beta 版本")
		return
	}
	if setup.NAT && setup.Network == "tcp" {
		u.warn("此 NAT 只映射 TCP：Snell v5 的 QUIC 代理模式需要 UDP。请在 Surge 中把该节点的 version 改为 4（v5 服务端兼容 v4 客户端）")
	}
}
