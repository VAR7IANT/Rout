package rout

import (
	"fmt"
)

// Server setup answers three questions without asking the user for technical detail:
// which address clients connect to, which family it is, and where the engine listens.
// Everything is detected; the user chooses only when there is a real choice (a dual-stack
// host) and the choice is remembered. NAT/VPS is not a question any more: new entries
// always use regular-VPS behavior (public port = listening port). Settings saved by
// v0.3.0 in NAT mode are still honoured, see serverSetup.

func (u *UI) detectAddresses() Addresses {
	switch {
	case u.detectAddrs != nil:
		return u.detectAddrs()
	case u.detectIP != nil:
		switch ip := u.detectIP(); familyOf(ip) {
		case "ipv4":
			return Addresses{IPv4: ip}
		case "ipv6":
			return Addresses{IPv6: ip}
		}
		return Addresses{}
	}
	return DetectAddresses()
}
func (u *UI) listenCapabilities() listenCaps {
	if u.caps != nil {
		return u.caps()
	}
	return probeCaps()
}

// listenLabel says in plain words what a listening address serves.
func listenLabel(s ServerSetup) string {
	switch {
	case s.Listen == "0.0.0.0":
		return "0.0.0.0 (IPv4)"
	case s.Listen == "::" && s.IPv4 == "" && s.IPv6 != "":
		return ":: (IPv6)"
	case s.Listen == "::":
		return ":: (IPv4 + IPv6)"
	case familyOf(s.Listen) == "ipv6":
		return s.Listen + " (IPv6)"
	}
	return s.Listen + " (IPv4)"
}

// serverSummary describes the saved server defaults on one line.
func (u *UI) serverSummary(s ServerSetup) string {
	line := u.a.T("公网") + " " + s.PublicHost + " · " + u.a.T("监听") + " " + listenLabel(s)
	if s.NAT {
		line = u.a.T("旧版 NAT") + " · " + line + fmt.Sprintf(" · %d-%d → %d · %s", s.LocalStart, s.LocalEnd, s.PublicStart, ProtocolLabel(s.Network))
	}
	return line
}

// serverSetup returns the saved defaults, or detects them on first use.
func (u *UI) serverSetup() (ServerSetup, error) {
	saved, e := u.a.LoadSettings()
	if e != nil {
		return ServerSetup{}, e
	}
	if s := saved.Server; s != nil && s.PublicHost != "" && s.Validate() == nil {
		u.printf("服务器地址：%s\n", u.serverSummary(*s))
		if s.NAT {
			// Compatibility: a host that was set up as NAT keeps its provider mapping for
			// new entries, otherwise they would be unreachable. Nothing here rewrites it.
			u.warn("此服务器沿用旧版 NAT 端口映射，新节点和中转也按该映射分配端口；改用普通 VPS：设置 → 服务器地址")
		}
		return *s, nil
	}
	return u.buildServer(saved.Server, true)
}

// buildServer creates a regular-VPS setup. With detect it inspects the host first; if
// nothing can be detected (or detect is false) the user types the address.
func (u *UI) buildServer(prev *ServerSetup, detect bool) (ServerSetup, error) {
	var addrs Addresses
	if detect {
		u.say("正在检测服务器公网地址…")
		addrs = u.detectAddresses()
	}
	s := ServerSetup{Network: "both", IPv4: addrs.IPv4, IPv6: addrs.IPv6}
	switch {
	case addrs.IPv4 != "" && addrs.IPv6 != "":
		def := "ipv4"
		if prev != nil && prev.Family == "ipv6" {
			def = "ipv6"
		}
		s.Family = u.option("本服务器同时有 IPv4 和 IPv6，客户端使用哪个地址连接？", []menuItem{
			itemNote("ipv4", "IPv4 "+addrs.IPv4, "兼容性最好（默认）"),
			itemNote("ipv6", "IPv6 "+addrs.IPv6, "仅当客户端网络支持 IPv6"),
		}, def)
		if u.err != nil {
			return s, u.err
		}
	case addrs.IPv4 != "":
		s.Family = "ipv4"
	case addrs.IPv6 != "":
		s.Family = "ipv6"
	}
	switch s.Family {
	case "ipv4":
		s.PublicHost = addrs.IPv4
	case "ipv6":
		s.PublicHost = addrs.IPv6
	default:
		if detect {
			u.warn("无法自动检测公网地址，请手动填写")
		}
		def := ""
		if prev != nil {
			def = prev.PublicHost
		}
		for u.err == nil {
			s.PublicHost = u.ask("公网连接 IP 或域名", def)
			if validPublicHost(s.PublicHost) {
				break
			}
			u.say("地址无效：不能是空值、未指定地址或链路本地地址（如 fe80::）")
		}
		if u.err != nil {
			return s, u.err
		}
		s.Family = "custom"
	}
	saved := ""
	if prev != nil && !prev.NAT {
		saved = prev.Listen
	}
	s.Listen = chooseListen(s.Family, addrs, u.listenCapabilities(), saved)
	if u.err != nil {
		return s, u.err
	}
	return s, s.Validate()
}
func (u *UI) saveServer(server ServerSetup) error {
	s, e := u.a.LoadSettings()
	if e != nil {
		return e
	}
	s.Server = &server
	if s.Language == "" {
		s.Language = u.a.Language
		if s.Language == "" {
			s.Language = "zh-CN"
		}
	}
	return u.a.SaveSettings(s)
}

// serverMenu is Settings → Server address: re-detect, type an address, or leave the
// legacy NAT mode.
func (u *UI) serverMenu() error {
	saved, e := u.a.LoadSettings()
	if e != nil {
		return e
	}
	items := []menuItem{item("detect", "重新检测并选择 IPv4 / IPv6"), item("manual", "手动填写 IP 或域名")}
	if s := saved.Server; s != nil {
		u.printf("当前设置：%s\n", u.serverSummary(*s))
		if s.NAT {
			u.say("旧版 NAT 映射仍在使用，已有的 NAT 节点和中转不会被改动。")
			items = append(items, item("regular", "改用普通 VPS（公网端口 = 监听端口）"))
		}
	} else {
		u.say("尚未保存服务器设置；创建节点时会自动检测。")
	}
	v := u.menu("", items, "返回")
	if u.err != nil || v == "" {
		return u.err
	}
	if v == "regular" {
		u.say("改用普通 VPS 后，新节点的公网端口等于监听端口。已有的 NAT 节点和中转保持原样，其端口映射不会被改写；之后编辑它们时仍会询问商家映射的公网端口。")
		if !u.yes("改用普通 VPS", false) {
			return u.err
		}
	}
	setup, e := u.buildServer(saved.Server, v != "manual")
	if e != nil {
		return e
	}
	if e = u.saveServer(setup); e != nil {
		return e
	}
	u.printf("服务器地址：%s\n", u.serverSummary(setup))
	u.good("服务器设置已保存；现有节点不受影响")
	return nil
}

// altLink returns the same node's link at its other address family, when the host has both
// and the node listens on a dual-stack wildcard.
func altLink(setup ServerSetup, p Profile) (label, uri string, ok bool) {
	host, label, ok := setup.AltAddress(p)
	if !ok {
		return "", "", false
	}
	uri, e := p.URIAt(host, p.PublicPort)
	if e != nil {
		return "", "", false
	}
	return label, uri, true
}

// printLinks shows a node's link and, on a dual-stack host, the same node's link for the
// other address family (same port and credentials: one service serves both).
func (u *UI) printLinks(p Profile, setup *ServerSetup) error {
	uri, e := p.URI()
	if e != nil {
		return e
	}
	fmt.Fprintln(u.writer(), uri)
	if setup == nil {
		if st, er := u.a.LoadSettings(); er == nil {
			setup = st.Server
		}
	}
	if setup == nil {
		return nil
	}
	if label, alt, ok := altLink(*setup, p); ok {
		fmt.Fprintf(u.writer(), "%s\n%s\n", u.a.T("同一节点的另一地址：")+label, alt)
	}
	return nil
}

// fitListen makes an IPv6 public address usable on a node that listens on IPv4 only.
func (u *UI) fitListen(p *Profile) {
	if p.NAT || familyOf(p.PublicHost) != "ipv6" || p.Listen != "0.0.0.0" {
		return
	}
	u.warn("该节点目前只监听 IPv4，IPv6 地址无法连接")
	if !u.yes("改为监听 ::（IPv4 与 IPv6 同时可用，会重启节点）", true) {
		return
	}
	if c := u.listenCapabilities(); !c.V6 || !c.DualStack {
		u.fail(u.a.T("本机无法在同一监听上同时接受 IPv4 和 IPv6，保持 IPv4"))
		return
	}
	p.Listen = "::"
}
