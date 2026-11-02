package rout

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// Address-family choices of the relay flows: how the entry accepts connections (inbound)
// and how it reaches its destination (outbound). They are independent questions.

// relayInboundOptions lists the inbound modes this host can really serve, in the order
// shown to the user. A family the host cannot bind is not offered at all; dual stack is
// offered only when an IPv4 and an IPv6 socket can share a port.
func relayInboundOptions(c listenCaps) []menuItem {
	var items []menuItem
	if c.V4 {
		items = append(items, itemNote(inIPv4, "IPv4", "只监听 IPv4（0.0.0.0）；不创建 IPv6 监听"))
	}
	if c.V6 {
		items = append(items, itemNote(inIPv6, "IPv6", "只监听 IPv6（::，IPV6_V6ONLY）；不接受 IPv4 连接"))
	}
	if c.V4 && c.V6 && !c.SplitConflict {
		items = append(items, itemNote(inDual, "双栈", "IPv4 和 IPv6 各用一个独立的监听套接字，同一端口"))
	}
	return items
}

func (u *UI) hostRoutesNow() familyRoutes {
	if u.routes != nil {
		return u.routes()
	}
	return hostRoutes()
}

// relayPrefs are the last inbound/outbound choices, offered as defaults next time.
func (u *UI) relayPrefs() (inbound, outbound string) {
	if s, e := u.a.LoadSettings(); e == nil {
		return s.RelayInbound, s.RelayOutbound
	}
	return "", ""
}
func (u *UI) saveRelayPrefs(inbound, outbound string) {
	s, e := u.a.LoadSettings()
	if e != nil || (s.RelayInbound == inbound && s.RelayOutbound == outbound) {
		return
	}
	if inbound != "" {
		s.RelayInbound = inbound
	}
	if outbound != "" {
		s.RelayOutbound = outbound
	}
	if s.Language == "" {
		s.Language = u.a.Language
	}
	_ = u.a.SaveSettings(s)
}

// relayInbound chooses the inbound mode of a native relay and returns the setup with a
// public address that fits it. The user's saved server defaults are not changed.
func (u *UI) relayInbound(p *Profile, setup ServerSetup, def string) (ServerSetup, error) {
	caps := u.listenCapabilities("tcp")
	items := relayInboundOptions(caps)
	if len(items) == 0 {
		return setup, errors.New("本机没有可用的监听地址")
	}
	selected := items[0].key
	if len(items) > 1 {
		for _, it := range items {
			if it.key == def {
				selected = def
			}
		}
		selected = u.option("入站网络（客户端用哪种 IP 连接本中转）", items, selected)
		if u.err != nil {
			return setup, u.err
		}
	} else {
		u.printf("入站网络：%s（本机只支持这一种）\n", inboundLabel(selected))
	}
	p.InboundMode = selected
	p.Listen = listenAddrFor(selected, "")
	p.Engine = engineNative
	var e error
	if setup, e = u.alignPublicHost(setup, selected); e != nil {
		return setup, e
	}
	p.PublicHost = setup.PublicHost
	return setup, nil
}

// outboundMenu returns the outbound policies to offer, given what the host can route and
// what the destination is. ok is false when there is nothing to choose.
func outboundMenu(routes familyRoutes, target string) (items []menuItem, ok bool) {
	if !(routes.V4 && routes.V6) {
		return nil, false
	}
	literal := ""
	if h, _, e := ParseEndpoint(target); e == nil {
		literal = familyOf(h)
	}
	for _, it := range []menuItem{
		itemNote(outIPv4First, "IPv4 优先", "优先使用 A 记录；IPv4 不通时回退 IPv6"),
		itemNote(outIPv6First, "IPv6 优先", "优先使用 AAAA 记录；IPv6 不通时回退 IPv4"),
		itemNote(outIPv4Only, "仅 IPv4", "绝不使用 IPv6"),
		itemNote(outIPv6Only, "仅 IPv6", "绝不使用 IPv4"),
		itemNote(outAuto, "自动", "按本机路由和实际连通性选择"),
	} {
		// A literal address of one family can never be reached by the other family's
		// "only" policy; do not offer a choice that would fail at save time.
		if (it.key == outIPv6Only && literal == "ipv4") || (it.key == outIPv4Only && literal == "ipv6") {
			continue
		}
		items = append(items, it)
	}
	return items, true
}

// relayOutbound chooses how the relay reaches a remote destination. Local relays forward
// to this machine's own loopback and have nothing to choose. On a host with a single
// address family there is no real choice either: "auto" is stored and says so.
func (u *UI) relayOutbound(p *Profile, def string) {
	if p.relayMode() == relayLocal {
		p.OutboundPolicy = outAuto
		return
	}
	routes := u.hostRoutesNow()
	items, ok := outboundMenu(routes, p.Target)
	if !ok {
		p.OutboundPolicy = outAuto
		switch {
		case routes.V4:
			u.say("出站策略：自动（本机只有 IPv4 出站路由）")
		case routes.V6:
			u.say("出站策略：自动（本机只有 IPv6 出站路由）")
		default:
			u.warn("未检测到出站路由；出站策略设为自动，连接目标时再判断")
		}
		return
	}
	choice := outIPv4First
	for _, it := range items {
		if it.key == def {
			choice = def
		}
	}
	p.OutboundPolicy = u.option("出站策略（本中转连接目标服务器时使用的 IP 类型）", items, choice)
}

// relayTargetNetwork records what a remote destination accepts when the relay carries UDP
// and nothing else tells: a TCP-only NAT mapping cannot carry QUIC protocols.
func (u *UI) relayTargetNetwork(p *Profile) {
	p.TargetNetwork = ""
	// Asked when the relay carries UDP to a remote server and the destination is not a
	// link for a TCP protocol: a QUIC link (Hysteria2/TUIC) cannot work through a TCP-only NAT.
	if p.relayMode() == relayLocal || !contains(p.Networks(), "udp") || (p.TargetURI != "" && quicProtocolName(p.TargetURI) == "") {
		return
	}
	if u.option("目标服务器的端口映射支持哪些传输？", []menuItem{
		itemNote("both", "TCP + UDP（或不确定）", "不做限制；创建后用测试确认"),
		itemNote("tcp", "仅 TCP", "例如只映射了 TCP 端口的 NAT；UDP 无法转发"),
	}, "both") == "tcp" {
		p.TargetNetwork = "tcp"
	}
}

// relayNetworkLine describes a relay's address-family settings on one line.
func (u *UI) relayNetworkLine(p Profile) string {
	if !p.nativeRelay() {
		return u.a.T("旧版引擎（GOST）：监听与出站由引擎默认行为决定；『修改网络』可迁移到内置转发")
	}
	return fmt.Sprintf(u.a.T("入站 %s · 出站 %s"), u.a.T(inboundLabel(p.inboundMode())), u.a.T(outboundLabel(p.outboundPolicy())))
}

// relayBindLine lists the sockets a native relay binds.
func relayBindLine(p Profile) string {
	var parts []string
	for _, s := range p.bindSpecs() {
		parts = append(parts, s.Network[:3]+" "+s.Addr()+" ("+familyName(s.Network)+")")
	}
	return strings.ToUpper(strings.Join(parts, " + "))
}

// modeOfListen derives the inbound mode of an address typed by hand (legacy NAT hosts).
func modeOfListen(listen string) string {
	ip := net.ParseIP(listen)
	switch {
	case ip == nil, ip.To4() != nil:
		return inIPv4
	case ip.IsUnspecified():
		return inDual
	}
	return inIPv6
}
