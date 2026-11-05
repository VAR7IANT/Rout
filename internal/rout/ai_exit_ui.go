package rout

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// AI exit selection. Four ways lead to an exit that really carries traffic out:
//
//  1. an existing outbound (SOCKS5 / HTTP(S) / remote node / chain)
//  2. through an existing Rout port forward, ending in a real proxy or node
//  3. a remote node's share link
//  4. a new chain: create the forward and the exit in one step
//
// Whatever is created is tested layer by layer before it is selected, and removed again
// when the user declines to keep an exit that failed.

func (u *UI) aiSelectExit() error {
	defer u.enter("选择 AI 出口")()
	for {
		v := u.menu("选择 AI 出口", []menuItem{
			itemNote("existing", "现有出站代理", "SOCKS5 / HTTP(S) / 远程节点 / 已建立的转发链路"),
			itemNote("relay", "经由现有端口转发", "AI 流量 → 本机 Rout 中转 → 远端代理或节点 → 互联网"),
			itemNote("link", "远程节点分享链接", "VLESS Reality / AnyTLS / Trojan / SS / Hysteria2 / TUIC"),
			itemNote("new", "建立新的出口链路", "在一个流程中完成中转与远端代理设置"),
		}, "返回")
		if u.err != nil || v == "" {
			return u.err
		}
		var e error
		switch v {
		case "existing":
			e = u.aiPickExistingExit()
		case "relay":
			e = u.aiChainThroughRelay()
		case "link":
			e = u.aiExitFromLink()
		case "new":
			e = u.aiNewChain()
		}
		if e == nil || errors.Is(e, errCancelled) {
			if u.err != nil {
				return u.err
			}
			if e == nil {
				return nil
			}
			u.say("已取消，未做任何更改")
			continue
		}
		return e
	}
}

// aiExitLine prints one exit with the reason it cannot be the AI exit, if any.
func (u *UI) aiExitLine(s State, i int, ex Exit, current string, local map[string]bool) bool {
	_, why := aiExitProxy(s, ex, local)
	mark := ""
	if ex.ID == current {
		mark = " " + u.paint(colorOK, u.a.T("（当前）"))
	}
	fmt.Fprintf(u.writer(), "  %s %s — %s%s\n", u.paint(accent, fmt.Sprintf("%2d.", i)), u.bold(ex.Name), ex.KindLabel(), mark)
	u.segments("      ", u.dim(strings.Join(chainPath(u.a, s, ex), " → ")))
	if why != nil {
		fmt.Fprintf(u.writer(), "      %s\n", u.paint(colorErr, "✗ "+u.a.Error(why)))
	}
	return why == nil
}

func (u *UI) aiPickExistingExit() error {
	s, e := u.a.Load()
	if e != nil {
		return e
	}
	if len(s.Exits) == 0 {
		u.say("暂无出站代理。请选择其他方式建立 AI 出口")
		return errCancelled
	}
	cfg := s.aiConfigured()
	u.heading("现有出站代理")
	local := localIPs()
	usable := map[int]bool{}
	for i, ex := range s.Exits {
		usable[i+1] = u.aiExitLine(s, i+1, ex, cfg.AIOutboundID, local)
	}
	n := u.number("选择 AI 出口编号（0 返回）", len(s.Exits))
	if n <= 0 {
		if u.err != nil {
			return u.err
		}
		return errCancelled
	}
	if !usable[n] {
		return errors.New("此出站代理不能作为 AI 出口")
	}
	return u.aiAdopt(s.Exits[n-1], nil)
}

// aiAdopt tests an exit through the whole chain and selects it. cleanup removes what this
// flow just created when the user does not keep it.
func (u *UI) aiAdopt(ex Exit, cleanup func() error) error {
	cfg := State{}.aiConfigured()
	if s, e := u.a.Load(); e == nil {
		cfg = s.aiConfigured()
	}
	if ex.ID == cfg.AIOutboundID {
		u.say("AI 出口未改变")
		return nil
	}
	if w := proxySecurityWarning(ex.Proxy); w != "" {
		u.warn(w)
	}
	if er := u.aiExitCheck(ex); er != nil {
		u.fail(u.a.Error(er))
		if !u.yes("出口当前不可用，仍然选择它", false) {
			if u.err != nil {
				return u.err
			}
			if cleanup != nil {
				if ce := cleanup(); ce != nil {
					return ce
				}
			}
			return errCancelled
		}
	}
	if cfg.Enabled {
		u.say("只会重启已绑定的节点；其他节点和入站配置不受影响")
	}
	if !u.yes(fmt.Sprintf(u.a.T("将 AI 出口设为 %s"), ex.Name), true) {
		if u.err != nil {
			return u.err
		}
		if cleanup != nil {
			if ce := cleanup(); ce != nil {
				return ce
			}
		}
		return errCancelled
	}
	if e := u.a.SetAIExit(ex.ID); e != nil {
		if cleanup != nil {
			e = errors.Join(e, cleanup())
		}
		return e
	}
	u.good("AI 出口已更新")
	return nil
}

// aiExitCheck tests a stored exit layer by layer (through its relay for a chain).
func (u *UI) aiExitCheck(ex Exit) error {
	if u.probeProxy != nil {
		s, e := u.a.Load()
		if e != nil {
			return e
		}
		dial, e := aiExitProxy(s, ex, localIPs())
		if e != nil {
			return e
		}
		ip, e := u.probeProxy(dial)
		if e != nil {
			return e
		}
		u.printf("实际出口 IP：%s\n", ip)
		return nil
	}
	u.heading("AI 出口测试")
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	rep := u.a.diagnoseProxy(ctx, ex, u.diagEnvOrDefault(), diagOpts{Full: true})
	u.printReport(rep)
	return reportError(rep)
}

// chainProxyInput asks what the end of the chain is. endpoint is the proxy address as the
// hop reaches it; relayLink is the relay's own target link (a node), offered as default.
func (u *UI) chainProxyInput(endpoint, relayLink string, udpOnly bool) (ChainSpec, error) {
	spec := ChainSpec{}
	def := "socks5"
	if relayLink != "" || udpOnly {
		def = "node"
	}
	items := []menuItem{
		itemNote("socks5", "SOCKS5 代理", "需要账号密码；SOCKS5 本身不加密"),
		itemNote("http", "HTTP CONNECT 代理", "需要账号密码；明文传输认证信息"),
		itemNote("https", "HTTPS CONNECT 代理", "验证证书，认证信息经 TLS 加密"),
		itemNote("node", "远程节点（分享链接）", "VLESS Reality / AnyTLS / Trojan / SS / Hysteria2 / TUIC"),
		itemNote("forward", "只是另一个端口转发", "不是出口：末端必须是真正的代理"),
	}
	if udpOnly {
		// A relay that forwards UDP only can carry QUIC nodes (Hysteria2/TUIC), no TCP proxy.
		u.say("此中转只转发 UDP：链路末端只能是 Hysteria2 / TUIC 节点")
		items = []menuItem{items[3], items[4]}
	}
	spec.Protocol = u.option("链路末端是什么服务？", items, def)
	if u.err != nil {
		return spec, u.err
	}
	switch spec.Protocol {
	case "forward":
		return spec, errors.New("端口转发的末端必须是真正的代理（SOCKS5 / HTTP(S) CONNECT）或远程节点；请选择代理协议并填写认证信息")
	case "node":
		if relayLink != "" && u.yes("使用中转目标自带的节点链接", true) {
			spec.Link = relayLink
			return spec, nil
		}
		if u.err != nil {
			return spec, u.err
		}
		spec.Link = u.secret("粘贴远程节点的分享链接（vless:// anytls:// trojan:// ss:// hysteria2:// tuic://）")
		return spec, u.err
	}
	if w := proxySecurityWarning(Proxy{Protocol: spec.Protocol}); w != "" {
		u.warn(w)
	}
	if endpoint == "" {
		raw := normalizeInput(u.ask("出口代理的地址（中转所转发到的 地址:端口）", ""))
		if u.err != nil {
			return spec, u.err
		}
		h, p, e := ParseEndpoint(raw)
		if e != nil {
			return spec, e
		}
		spec.Host, spec.Port = h, p
	} else {
		h, p, e := ParseEndpoint(endpoint)
		if e != nil {
			return spec, e
		}
		spec.Host, spec.Port = h, p
	}
	spec.Username = strings.TrimSpace(u.ask("代理用户名", ""))
	if u.err != nil {
		return spec, u.err
	}
	spec.Password = u.secret("代理密码（输入时不显示）")
	return spec, u.err
}

func (u *UI) aiChainThroughRelay() error {
	s, e := u.a.Load()
	if e != nil {
		return e
	}
	var relays []Profile
	for _, p := range s.Profiles {
		if p.Kind == "relay" {
			relays = append(relays, p)
		}
	}
	if len(relays) == 0 {
		u.say("暂无端口转发。可选择“建立新的出口链路”同时创建中转和出口")
		return errCancelled
	}
	u.heading("经由现有端口转发")
	local := localIPs()
	usable := map[int]bool{}
	for i, r := range relays {
		why := chainProblem(s, chainProbeExit(r), local)
		state := u.a.T("已启用")
		if !r.Enabled {
			state = u.a.T("已停用")
		}
		fmt.Fprintf(u.writer(), "  %s %s — %s · %s\n", u.paint(accent, fmt.Sprintf("%2d.", i+1)), u.bold(r.Name), strings.ToUpper(r.Protocol), state)
		u.segments("      ", u.dim(net.JoinHostPort(r.Listen, itoa(r.Port))), u.dim("→ "+r.Target))
		if why != nil {
			fmt.Fprintf(u.writer(), "      %s\n", u.paint(colorErr, "✗ "+u.a.Error(why)))
		}
		usable[i+1] = why == nil
	}
	n := u.number("选择中转编号（0 返回）", len(relays))
	if n <= 0 {
		if u.err != nil {
			return u.err
		}
		return errCancelled
	}
	if !usable[n] {
		return errors.New("此中转不能作为 AI 出口链路")
	}
	r := relays[n-1]
	u.printf("中转 %s 会把连接送到 %s。该地址上必须运行真正的代理或节点，流量才会从那里进入互联网。\n", r.Name, r.Target)
	spec, e := u.chainProxyInput(r.Target, r.TargetURI, !contains(r.Networks(), "tcp"))
	if e != nil {
		return e
	}
	spec.ViaRelay = r.ID
	spec.Name = u.ask("出口链路名称", "")
	if u.err != nil {
		return u.err
	}
	ex, e := u.a.CreateChainExit(spec)
	if e != nil {
		return e
	}
	return u.aiAdopt(ex, func() error { return u.a.DeleteExitByID(ex.ID) })
}

func (u *UI) aiExitFromLink() error {
	raw := u.secret("粘贴远程节点的分享链接（vless:// anytls:// trojan:// ss:// hysteria2:// tuic://）")
	if u.err != nil {
		return u.err
	}
	ex, e := u.a.CreateExit(ExitSpec{Protocol: "remote", Link: raw})
	if e != nil {
		return e
	}
	u.printf("已保存远程节点出口 %s\n", ex.Name)
	return u.aiAdopt(ex, func() error { return u.a.DeleteExitByID(ex.ID) })
}

// aiNewChain creates the hop and the exit in one flow. A hop on this server is a new Rout
// relay listening on 127.0.0.1 only, so it is never an open forwarder on the Internet.
func (u *UI) aiNewChain() error {
	u.heading("建立新的出口链路")
	u.say("链路：已绑定节点的 AI 流量 → 中转 → 远端代理或节点 → 互联网。端口转发本身不是出口，末端必须是真正的代理。")
	where := u.option("中转在哪里？", []menuItem{
		itemNote("local", "在本机新建 Rout 中转", "仅监听 127.0.0.1，可设置出站地址族（例如经 IPv6 到达远端）"),
		itemNote("remote", "另一台服务器上的转发端口", "例如 NAT 或纯 IPv6 服务器映射到远端代理的端口"),
	}, "local")
	if u.err != nil {
		return u.err
	}
	if where == "remote" {
		via := normalizeInput(u.ask("中转服务器的 地址:端口（IPv6 使用 [地址]:端口）", ""))
		if u.err != nil {
			return u.err
		}
		if _, _, e := ParseEndpoint(via); e != nil {
			return e
		}
		spec, e := u.chainProxyInput("", "", false)
		if e != nil {
			return e
		}
		spec.ViaAddress = via
		ex, e := u.a.CreateChainExit(spec)
		if e != nil {
			return e
		}
		return u.aiAdopt(ex, func() error { return u.a.DeleteExitByID(ex.ID) })
	}
	spec, e := u.chainProxyInput("", "", false)
	if e != nil {
		return e
	}
	target := net.JoinHostPort(spec.Host, itoa(spec.Port))
	network := "tcp"
	if spec.Link != "" {
		p, er := ParseRemoteNode(spec.Link)
		if er != nil {
			return er
		}
		target = p.hostPort()
		network = exitTransport(*p)
	}
	policy := u.option("中转连接远端时使用的地址族", []menuItem{
		item(outAuto, "自动"), item(outIPv4Only, "仅 IPv4"), item(outIPv6Only, "仅 IPv6"), item(outIPv4First, "IPv4 优先"), item(outIPv6First, "IPv6 优先"),
	}, outAuto)
	if u.err != nil {
		return u.err
	}
	relay, e := u.a.CreateRelay(RelaySpec{Mode: relayRemote, Target: target, Protocol: network, Outbound: policy, Loopback: true, Name: boundedChainName("AI-hop", spec.Host)})
	if e != nil {
		return e
	}
	removeRelay := func() error { return u.a.DeleteProfiles([]string{relay.ID}) }
	spec.ViaRelay = relay.ID
	ex, e := u.a.CreateChainExit(spec)
	if e != nil {
		return errors.Join(e, removeRelay())
	}
	u.printf("已创建中转 %s（127.0.0.1:%d → %s）和出口链路 %s\n", relay.Name, relay.Port, target, ex.Name)
	return u.aiAdopt(ex, func() error { return errors.Join(u.a.DeleteExitByID(ex.ID), removeRelay()) })
}
