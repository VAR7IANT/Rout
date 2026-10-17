package rout

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// Relay management. Terminology used everywhere:
//   entry       = the CURRENT server: public endpoint (what clients dial) and the local
//                 listening address/port the relay binds;
//   destination = where traffic is forwarded: a port on this server (local) or another
//                 server (remote). A destination is never an outbound proxy.

func relayEndpoint(p Profile) string { return net.JoinHostPort(p.PublicHost, itoa(p.PublicPort)) }
func relayListen(p Profile) string   { return net.JoinHostPort(p.Listen, itoa(p.Port)) }
func (u *UI) relayModeLabel(p Profile) string {
	if p.relayMode() == relayLocal {
		return u.a.T("本机")
	}
	return u.a.T("远程服务器")
}
func relayTransport(p Profile) string { return ProtocolLabel(p.Protocol) }

// relayCard is the credential-free summary used in relay lists.
func (u *UI) relayCard(i int, p Profile) {
	state := u.a.T("启用")
	if !p.Enabled {
		state = u.a.T("停用")
	}
	fmt.Fprintf(u.writer(), "  %s %s %s\n", u.paint("36", fmt.Sprintf("%2d.", i)), u.bold(p.Name), u.dim("["+p.ID+"]"))
	fmt.Fprintf(u.writer(), "      %s · %s/%s\n", relayTransport(p), state, u.a.Running(p))
	fmt.Fprintf(u.writer(), "      "+u.a.T("公网入口 %s → 本机监听 %s → 目标 %s（%s）")+"\n", relayEndpoint(p), relayListen(p), p.Target, u.relayModeLabel(p))
}

// relayDiagram draws the complete path from the client to the destination.
func (u *UI) relayDiagram(p Profile) {
	w := u.writer()
	line := func(label, value string) {
		fmt.Fprintf(w, "    %s\n", u.bold(u.a.T(label)))
		if value != "" {
			fmt.Fprintf(w, "    %s\n", value)
		}
	}
	arrow := func() { fmt.Fprintf(w, "      %s\n      %s\n", u.paint("36", "│"), u.paint("36", "▼")) }
	line("客户端", "")
	arrow()
	line("当前服务器（中转入口）", fmt.Sprintf("%s %s", u.a.T("公网 IP:端口"), relayEndpoint(p)))
	arrow()
	line("本机监听", fmt.Sprintf("%s %s", u.a.T("监听地址:端口"), relayListen(p)))
	arrow()
	dest := u.a.T("目标服务器")
	if p.relayMode() == relayLocal {
		dest = u.a.T("目标服务（本机）")
	}
	line(dest, fmt.Sprintf("%s %s", u.a.T("目标 IP:端口"), p.Target))
	fmt.Fprintf(w, "\n    "+u.a.T("传输协议：%s")+"\n", relayTransport(p))
}
func (u *UI) relayChecks(checks []relayCheck) {
	for _, c := range checks {
		switch {
		case c.ok:
			u.good(c.text)
		case c.warning:
			u.warn(c.text)
		default:
			u.fail(u.a.T(c.text))
		}
	}
}

// askPortValue reads a port; an empty answer keeps def (0 means "required").
func (u *UI) askPortValue(prompt string, def int) int {
	for u.err == nil {
		d := ""
		if def > 0 {
			d = itoa(def)
		}
		v := u.ask(prompt, d)
		if u.err != nil {
			return 0
		}
		if n, e := strconv.Atoi(strings.TrimSpace(v)); e == nil && validPort(n) {
			return n
		}
		u.say("端口应为 1–65535")
	}
	return 0
}

// relayEntry configures the CURRENT server side: listening address/port and the public
// endpoint clients use. A new relay reuses the saved server defaults and a planned free
// port, shown once for confirmation; answering no (or editing) asks for each value.
// On NAT the public port is the provider's mapping, never assumed.
func (u *UI) relayEntry(p *Profile, setup ServerSetup, s State) error {
	ownPort := p.Port // when editing, the running relay already holds its own port
	u.heading("中转入口 — 当前服务器")
	kind := u.a.T("普通 VPS")
	if setup.NAT {
		kind = u.a.T("NAT VPS")
	}
	u.printf("服务器类型：%s\n", kind)
	if setup.PublicHost == "" {
		for u.err == nil {
			setup.PublicHost = u.ask("本服务器的公网 IP 或域名（客户端连接的地址）", "")
			if validHost(setup.PublicHost) {
				break
			}
			u.say("地址或端口无效")
		}
	}
	u.printf("公网 IP：%s（客户端连接此地址；可在 设置 → 服务器类型与默认设置 中修改）\n", setup.PublicHost)
	p.PublicHost = setup.PublicHost
	p.NAT = setup.NAT
	if p.Listen == "" {
		p.Listen = setup.Listen
	}
	if net.ParseIP(p.Listen) == nil {
		p.Listen = "0.0.0.0"
	}
	// The public port a NAT provider maps to an internal port, when the saved range says so.
	mapped := func(port int) int {
		if setup.NAT && port >= setup.LocalStart && port <= setup.LocalEnd {
			return setup.PublicStart + port - setup.LocalStart
		}
		return 0
	}
	// The transport is chosen after this step, so a new port must be free for every
	// transport the relay may still use.
	probe := func() Profile {
		q := *p
		if q.Protocol == "" {
			q.Protocol = "both"
			if setup.NAT && setup.Network != "both" {
				q.Protocol = setup.Network
			}
		}
		return q
	}
	if ownPort == 0 {
		planned, e := PlanPort(probe(), setup, s)
		if e == nil && (!setup.NAT || mapped(planned.Port) > 0) {
			p.Port = planned.Port
			p.PublicPort = planned.Port
			if setup.NAT {
				p.PublicPort = mapped(planned.Port)
			}
			u.printf("监听：%s（已自动选择空闲端口）\n", relayListen(*p))
			u.printf("公网入口：%s\n", relayEndpoint(*p))
			if u.yes("使用此监听地址和端口", true) {
				return nil
			}
			if u.err != nil {
				return u.err
			}
		} else {
			u.say("没有可自动分配的端口，请手动填写")
		}
	}
	for u.err == nil {
		listen := u.ask("本机监听地址（0.0.0.0 / :: 表示所有网卡，不是公网地址）", p.Listen)
		if net.ParseIP(listen) != nil {
			p.Listen = listen
			break
		}
		u.say("监听地址或公网地址无效")
	}
	suggest := p.Port
	for u.err == nil {
		prompt := "本机监听端口"
		if setup.NAT {
			prompt = "本机监听端口（内部端口，应在商家分配的范围内）"
		}
		p.Port = u.askPortValue(prompt, suggest)
		if u.err != nil {
			return u.err
		}
		if setup.NAT && (p.Port < setup.LocalStart || p.Port > setup.LocalEnd) {
			u.warnf("端口 %d 不在已保存的 NAT 范围 %d-%d 内，请确认商家确实映射了此端口", p.Port, setup.LocalStart, setup.LocalEnd)
		}
		if p.Port != ownPort || ownPort == 0 {
			if e := CheckAvailable(probe()); e != nil {
				u.fail(u.a.Error(e))
				suggest = 0
				continue
			}
		}
		break
	}
	if !setup.NAT {
		p.PublicPort = p.Port
		u.printf("公网端口：%d（普通 VPS 的公网端口与监听端口相同）\n", p.PublicPort)
		return u.err
	}
	def := mapped(p.Port)
	if def == 0 && p.Port == ownPort {
		def = p.PublicPort
	}
	u.say("NAT：商家把公网端口映射到上面的内部端口；两者可以不同")
	p.PublicPort = u.askPortValue(fmt.Sprintf(u.a.T("商家映射到内部端口 %d 的公网端口"), p.Port), def)
	return u.err
}

// relayDestination configures where traffic goes. Local destinations default to
// 127.0.0.1; remote ones must be typed explicitly and are never filled in from the
// current server's own address.
func (u *UI) relayDestination(p *Profile, s State) error {
	if p.RelayMode == relayLocal {
		u.heading("目标 — 本服务器上的服务")
		u.say("填写本服务器上正在运行的服务端口，流量将转发到这里")
		var nodes []Profile
		for _, n := range s.Profiles {
			if n.Kind == "node" && n.ID != p.ID {
				nodes = append(nodes, n)
			}
		}
		if len(nodes) > 0 {
			u.say("本机已有节点（可直接输入其监听端口）：")
			for _, n := range nodes {
				fmt.Fprintf(u.writer(), "      %s  %s %d  %s\n", pad(n.Name, 22), u.a.T("监听端口"), n.Port, strings.ToUpper(strings.Join(n.Networks(), "+")))
			}
		}
		host := "127.0.0.1"
		if h, _, e := ParseEndpoint(p.Target); e == nil {
			host = h
		}
		port := 0
		if _, n, e := ParseEndpoint(p.Target); e == nil {
			port = n
		}
		port = u.askPortValue("目标服务端口（本服务器上）", port)
		for u.err == nil {
			host = u.ask("目标地址（高级，通常保持 127.0.0.1）", host)
			if validHost(host) {
				break
			}
			u.say("地址或端口无效")
		}
		if u.err != nil {
			return u.err
		}
		p.Target = net.JoinHostPort(host, itoa(port))
		p.TargetURI = ""
		// Reuse a managed node's link so the relay gets a complete share link.
		for _, n := range nodes {
			if n.Port == port && isLoopbackHost(host) {
				if uri, e := n.URI(); e == nil {
					p.TargetURI = uri
				}
				if p.Protocol == "" {
					p.Protocol = networkProtocol(n.Networks())
				}
			}
		}
		return nil
	}
	u.heading("目标 — 远程服务器")
	u.say("以下地址和端口属于远程服务器，不是本服务器")
	for u.err == nil {
		raw := strings.TrimSpace(u.ask("远程服务器 IP 或域名（也可以粘贴远程节点的分享链接）", ""))
		if u.err != nil {
			return u.err
		}
		if raw == "" {
			u.say("必须填写远程服务器地址")
			continue
		}
		if strings.Contains(raw, "://") {
			target, network, e := ParseTarget(raw)
			if e != nil {
				u.fail(u.a.Error(e))
				continue
			}
			p.Target, p.TargetURI = target, raw
			if network != "both" {
				p.Protocol = network
			}
			u.printf("已识别链接：目标 %s，传输 %s\n", target, strings.ToUpper(network))
			return nil
		}
		host := strings.Trim(raw, "[]")
		if h, port, e := ParseEndpoint(raw); e == nil {
			p.Target, p.TargetURI = net.JoinHostPort(h, itoa(port)), ""
			return nil
		}
		if !validHost(host) {
			u.say("请输入有效的 IP 地址或域名（IPv6 可直接输入，不需要方括号）")
			continue
		}
		port := u.askPortValue("远程服务器上的目标端口", 0)
		if u.err != nil {
			return u.err
		}
		p.Target, p.TargetURI = net.JoinHostPort(host, itoa(port)), ""
		return nil
	}
	return u.err
}
func networkProtocol(networks []string) string {
	if len(networks) == 2 {
		return "both"
	}
	if len(networks) == 1 {
		return networks[0]
	}
	return "tcp"
}

// relayProtocol picks TCP, UDP or both, within what a NAT mapping allows.
func (u *UI) relayProtocol(p *Profile, setup ServerSetup) {
	items := []menuItem{
		itemNote("tcp", "TCP", "VLESS、AnyTLS、Trojan、SS（TCP）以及大多数网页和 SSH 流量"),
		itemNote("udp", "UDP", "Hysteria2、TUIC 等基于 QUIC 的协议，以及 DNS 和游戏流量"),
		itemNote("both", "TCP+UDP", "两者都转发，例如 Shadowsocks；会同时占用 TCP 和 UDP 端口"),
	}
	if setup.NAT && setup.Network != "both" {
		var allowed []menuItem
		for _, it := range items {
			if it.key == setup.Network {
				allowed = append(allowed, it)
			}
		}
		items = allowed
		u.printf("NAT 映射只允许 %s\n", ProtocolLabel(setup.Network))
	}
	def := p.Protocol
	if def == "" {
		def = "tcp"
	}
	p.Protocol = u.option("传输协议（必须与目标服务使用的协议一致）", items, def)
}

// validateRelay returns blocking problems and informational checks.
func (u *UI) validateRelay(s State, p Profile, setup ServerSetup, probe bool) (error, []relayCheck) {
	if e := p.Validate(); e != nil {
		return e, nil
	}
	if e := relayLoop(s, p, localIPs()); e != nil {
		return e, nil
	}
	if setup.NAT && setup.Network != "both" {
		for _, n := range p.Networks() {
			if n != setup.Network {
				return errors.New("所选协议需要的网络不在 NAT 允许范围内"), nil
			}
		}
	}
	if !probe {
		return nil, nil
	}
	return nil, checkRelayDestination(p)
}

// preferLocal offers to switch a "remote" destination that is really this server.
func (u *UI) preferLocal(s State, p *Profile) {
	h, port, e := ParseEndpoint(p.Target)
	if e != nil || p.RelayMode != relayRemote {
		return
	}
	node, managed := localNodeForPublicPort(s, h, port)
	if !strings.EqualFold(h, p.PublicHost) && !managed {
		return
	}
	if managed && node.ID != p.ID {
		u.warnf("%s 是本服务器节点 %s 的公网地址", p.Target, node.Name)
		if u.yes(fmt.Sprintf(u.a.T("改为本机模式，直接转发到 127.0.0.1:%d？"), node.Port), true) {
			p.RelayMode, p.Target = relayLocal, net.JoinHostPort("127.0.0.1", itoa(node.Port))
			if uri, e := node.URI(); e == nil && p.TargetURI == "" {
				p.TargetURI = uri
			}
			if p.Protocol == "" && node.Kind == "node" {
				p.Protocol = networkProtocol(node.Networks())
			}
		}
		return
	}
	u.warn("目标地址与本服务器公网 IP 相同；如果目标服务就在本机，选择『本机』模式更可靠（NAT 环境通常不支持回环）")
}
func (u *UI) saveRelayMode(mode string) {
	if s, e := u.a.LoadSettings(); e == nil && s.RelayMode != mode {
		s.RelayMode = mode
		if s.Language == "" {
			s.Language = u.a.Language
		}
		_ = u.a.SaveSettings(s)
	}
}

// relayCreate is the guided creation flow: destination type, entry (this server),
// destination, protocol, then a preview with the full path before anything changes.
func (u *UI) relayCreate() error {
	old, e := u.a.Load()
	if e != nil {
		return e
	}
	settings, _ := u.a.LoadSettings()
	u.heading("创建中转节点")
	mode := settings.RelayMode
	if mode == "" {
		mode = relayRemote
	}
	mode = u.option("转发目标在哪里？", []menuItem{
		itemNote(relayLocal, "本机", "转发到本服务器上的另一个端口或服务"),
		itemNote(relayRemote, "远程服务器", "转发到另一台服务器"),
	}, mode)
	if u.err != nil {
		return u.err
	}
	setup, e := u.serverSetup()
	if e != nil {
		return e
	}
	p := Profile{ID: RandomHex(6), Kind: "relay", Enabled: true, RelayMode: mode}
	now := time.Now()
	p.CreatedAt = &now
	if e = u.relayEntry(&p, setup, old); e != nil {
		return e
	}
	if e = u.relayDestination(&p, old); e != nil {
		return e
	}
	u.preferLocal(old, &p)
	u.relayProtocol(&p, setup)
	def := "Relay"
	if h, port, er := ParseEndpoint(p.Target); er == nil {
		if p.RelayMode == relayRemote {
			def = "Relay-" + h
		}
		for _, n := range old.Profiles {
			if n.Kind == "node" && n.Port == port && isLoopbackHost(h) {
				def = "Relay-" + n.Name
			}
		}
	}
	p.Name = uniqueName(old, u.ask("中转名称", def))
	if u.err != nil {
		return u.err
	}
	return u.relayConfirm(old, replace(old, p), p, setup, "创建此中转")
}

// relayConfirm validates, previews and commits a new or edited relay.
func (u *UI) relayConfirm(old, next State, p Profile, setup ServerSetup, question string) error {
	blocking, checks := u.validateRelay(next, p, setup, true)
	u.heading("中转预览")
	u.relayDiagram(p)
	fmt.Fprintln(u.writer())
	if blocking != nil {
		return blocking
	}
	u.relayChecks(checks)
	if !u.yes(question, true) {
		return u.err
	}
	if e := u.a.Commit(old, next, false); e != nil {
		return e
	}
	u.saveRelayMode(p.relayMode())
	u.good("中转已保存")
	u.relayEndpointInfo(p)
	return u.saveServer(setup)
}

// relayEndpointInfo prints the copyable endpoint and, when known, the share link.
func (u *UI) relayEndpointInfo(p Profile) {
	u.printf("客户端连接地址：%s\n", relayEndpoint(p))
	if uri, e := p.URI(); e == nil {
		u.say("分享链接（已改为中转入口，保留原 SNI 等参数）：")
		fmt.Fprintln(u.writer(), uri)
	} else {
		u.printf("在客户端中把服务器地址改为 %s，端口改为 %d，其余参数保持不变\n", p.PublicHost, p.PublicPort)
	}
}
func relaysOf(s State) []Profile {
	var out []Profile
	for _, p := range s.Profiles {
		if p.Kind == "relay" {
			out = append(out, p)
		}
	}
	return out
}

// pickRelay selects a relay by its displayed number.
func (u *UI) pickRelay(s State) (Profile, bool) {
	relays := relaysOf(s)
	if len(relays) == 0 {
		u.say("暂无中转节点")
		return Profile{}, false
	}
	for i, p := range relays {
		u.relayCard(i+1, p)
	}
	n := u.number("选择中转编号（0 返回）", len(relays))
	if n <= 0 {
		return Profile{}, false
	}
	return relays[n-1], true
}

// relays is Relay Management.
func (u *UI) relays() error {
	for {
		v := u.menu("中转管理", []menuItem{item("view", "查看中转"), item("create", "创建中转"), item("edit", "编辑中转"), item("test", "测试中转"), item("delete", "删除中转")}, "返回")
		if u.err != nil || v == "" {
			return u.err
		}
		var e error
		if v == "create" {
			e = u.relayCreate()
		} else {
			var s State
			if s, e = u.a.Load(); e == nil {
				if p, ok := u.pickRelay(s); ok {
					switch v {
					case "view":
						u.relayDiagram(p)
						fmt.Fprintln(u.writer())
						u.relayEndpointInfo(p)
					case "edit":
						e = u.relayEdit(p.ID)
					case "test":
						e = u.relayTest(p)
					case "delete":
						e = u.relayDelete(s, p)
					}
				}
			}
		}
		if e != nil {
			if errors.Is(e, errQuit) || errors.Is(e, io.EOF) {
				return e
			}
			u.fail(u.a.Error(e))
		}
		if u.err != nil {
			return u.err
		}
	}
}

// relayEdit changes one aspect of a relay and re-runs validation and the preview.
func (u *UI) relayEdit(id string) error {
	s, e := u.a.Load()
	if e != nil {
		return e
	}
	p, e := Find(s, id)
	if e != nil {
		return e
	}
	toggle := "停用中转"
	if !p.Enabled {
		toggle = "启用中转"
	}
	v := u.menu(p.Name, []menuItem{item("destination", "修改目标"), item("entry", "修改入口（监听端口/公网端口）"), item("protocol", "修改传输协议"), item("name", "重命名"), item("toggle", toggle)}, "返回")
	if u.err != nil || v == "" {
		return u.err
	}
	setup := u.relaySetup(p)
	switch v {
	case "destination":
		p.RelayMode = u.option("转发目标在哪里？", []menuItem{
			itemNote(relayLocal, "本机", "转发到本服务器上的另一个端口或服务"),
			itemNote(relayRemote, "远程服务器", "转发到另一台服务器"),
		}, p.relayMode())
		if p.RelayMode != relayLocal {
			p.Target = ""
		}
		if e = u.relayDestination(&p, s); e != nil {
			return e
		}
		u.preferLocal(s, &p)
	case "entry":
		if e = u.relayEntry(&p, setup, removeProfile(s, p.ID)); e != nil {
			return e
		}
	case "protocol":
		u.relayProtocol(&p, setup)
	case "name":
		p.Name = u.ask("中转名称", p.Name)
		if u.err != nil {
			return u.err
		}
		if e = u.a.Commit(s, replace(s, p), false); e == nil {
			u.good("已保存")
		}
		return e
	case "toggle":
		p.Enabled = !p.Enabled
		if e = u.a.Commit(s, replace(s, p), false); e == nil {
			u.good("已保存")
		}
		return e
	}
	if u.err != nil {
		return u.err
	}
	if p.RelayMode == "" {
		p.RelayMode = p.relayMode()
	}
	next := replace(s, p)
	blocking, checks := u.validateRelay(next, p, setup, true)
	u.heading("中转预览")
	u.relayDiagram(p)
	if blocking != nil {
		return blocking
	}
	u.relayChecks(checks)
	if !u.yes("保存修改", true) {
		return u.err
	}
	if e = u.a.Commit(s, next, false); e != nil {
		return e
	}
	u.good("中转已保存")
	u.relayEndpointInfo(p)
	return nil
}

// relaySetup describes the relay's own entry as server settings (for edits).
func (u *UI) relaySetup(p Profile) ServerSetup {
	setup := ServerSetup{NAT: p.NAT, PublicHost: p.PublicHost, Listen: p.Listen, Network: "both"}
	if saved, e := u.a.LoadSettings(); e == nil && saved.Server != nil && saved.Server.NAT == p.NAT {
		setup.LocalStart, setup.LocalEnd, setup.PublicStart, setup.Network = saved.Server.LocalStart, saved.Server.LocalEnd, saved.Server.PublicStart, saved.Server.Network
	}
	return setup
}

// relayTest checks the relay service, its destination and, when the original link is
// known, a full protocol round trip through the relay.
func (u *UI) relayTest(p Profile) error {
	u.relayDiagram(p)
	fmt.Fprintln(u.writer())
	if !p.Enabled {
		return errors.New("中转已停用")
	}
	if u.a.Running(p) == u.a.T("运行中") || u.a.ServiceMode == "none" {
		if listening(p) {
			u.good(fmt.Sprintf(u.a.T("中转正在监听 %s"), relayListen(p)))
		} else {
			u.warn(fmt.Sprintf(u.a.T("中转未在 %s 上监听"), relayListen(p)))
		}
	} else {
		u.fail(fmt.Sprintf(u.a.T("中转服务未运行，运行 rout logs %s 查看原因"), p.ID))
	}
	u.relayChecks(checkRelayDestination(p))
	if p.TargetURI != "" && u.yes("通过中转执行完整协议测试", true) {
		return u.a.Probe(p)
	}
	u.say("端口可达不代表代理协议可用；请再用实际客户端连接公网入口验证")
	return u.err
}
func (u *UI) relayDelete(s State, p Profile) error {
	u.relayDiagram(p)
	if !u.yes(fmt.Sprintf(u.a.T("删除中转 %s 及其服务"), p.Name), false) {
		return u.err
	}
	if e := u.a.Commit(s, removeProfile(s, p.ID), false); e != nil {
		return e
	}
	u.good("中转已删除")
	return nil
}
