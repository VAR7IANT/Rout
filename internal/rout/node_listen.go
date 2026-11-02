package rout

import (
	"errors"
	"net"
	"strings"
)

// nodeListenOptions is ordered by recommendation, independently of public IPs or
// previously saved wildcard defaults. All node protocols share this policy.
func nodeListenOptions(c listenCaps) []menuItem {
	var items []menuItem
	if c.V4 {
		items = append(items, item(inIPv4, "IPv4 (0.0.0.0)"))
	}
	if c.V4 && c.V6 && c.DualStack {
		items = append(items, item(inDual, "双栈 (IPv4 + IPv6)"))
	}
	if c.V6 {
		items = append(items, item(inIPv6, "IPv6 (::)"))
	}
	return items
}

// nodeListeningSetup changes only the copy used for this batch of new nodes.
// Saved server settings, relays, existing nodes and explicit interface/NAT binds
// retain their previous behavior.
func (u *UI) nodeListeningSetup(setup ServerSetup, protocols ...string) (ServerSetup, error) {
	if setup.NAT || (setup.Listen != "0.0.0.0" && setup.Listen != "::" && net.ParseIP(setup.Listen) != nil) {
		return setup, nil
	}
	var networks []string
	for _, protocol := range protocols {
		for _, network := range (Profile{Protocol: protocol}).Networks() {
			if !contains(networks, network) {
				networks = append(networks, network)
			}
		}
	}
	caps := u.listenCapabilities(networks...)
	items := nodeListenOptions(caps)
	if len(items) == 0 {
		return setup, errors.New("本机没有可用的监听地址")
	}
	selected := items[0].key
	items[0].label += " [推荐]"
	if len(items) > 1 {
		selected = u.option("选择监听地址", items, selected)
		if u.err != nil {
			return setup, u.err
		}
	} else {
		u.say(items[0].label)
	}
	setup.inbound = selected
	switch selected {
	case inIPv4:
		setup.Listen = "0.0.0.0"
	case inDual, inIPv6:
		setup.Listen = "::"
		// "dual" is a verified dual-stack wildcard. "ipv6" is recorded as not serving
		// IPv4: the engine cannot set IPV6_V6ONLY, so the node config rejects IPv4
		// sources explicitly (see serverConfig) instead of relying on the socket.
		mapped := selected == inDual && caps.DualStack
		setup.ipv4Mapped = &mapped
	}
	return u.alignPublicHost(setup, selected)
}

// alignPublicHost keeps the address clients are told to use consistent with the inbound
// mode. A public endpoint is separate from the listening capability: custom domains and
// compatible addresses are kept; an IPv6 literal is never advertised for an IPv4 listener
// (or vice versa) just because it was saved previously.
func (u *UI) alignPublicHost(setup ServerSetup, selected string) (ServerSetup, error) {
	family := familyOf(setup.PublicHost)
	if selected == inDual || family == "" || family == selected {
		return setup, nil
	}
	host := setup.IPv4
	if selected == inIPv6 {
		host = setup.IPv6
	}
	for host == "" && u.err == nil {
		host = u.ask("公网连接 IP 或域名", "")
		if !validPublicHost(host) || (familyOf(host) != "" && familyOf(host) != selected) {
			u.say("公网连接地址与所选监听模式不匹配")
			host = ""
		}
	}
	if u.err != nil {
		return setup, u.err
	}
	setup.PublicHost = host
	setup.Family = familyOf(host)
	if setup.Family == "" {
		setup.Family = "custom"
	}
	return setup, nil
}

// freeNodePort uses the selected family rather than depending on IPv4 loopback.
func freeNodePort(p Profile) (int, error) {
	network := p.Networks()[0]
	if familyOf(p.Listen) == "ipv6" {
		network += "6"
	} else {
		network += "4"
	}
	addr := net.JoinHostPort(p.Listen, "0")
	if strings.HasPrefix(network, "udp") {
		l, e := net.ListenPacket(network, addr)
		if e != nil {
			return 0, e
		}
		defer l.Close()
		return l.LocalAddr().(*net.UDPAddr).Port, nil
	}
	l, e := net.Listen(network, addr)
	if e != nil {
		return 0, e
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}
