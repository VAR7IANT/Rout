package rout

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

var createProtocols = []string{"vless", "anytls", "ss", "hy2", "tuic"}
var createLabels = []string{"VLESS Reality", "AnyTLS Reality", "Shadowsocks 2022", "Hysteria2", "TUIC v5"}

func (u *UI) selectProtocols() []string {
	u.say("可创建的协议：")
	for i, label := range createLabels {
		fmt.Fprintf(u.writer(), "  %s  %s\n", u.paint("36", fmt.Sprintf("%2d", i+1)), label)
	}
	for u.err == nil {
		parts := strings.Fields(strings.ReplaceAll(u.ask("选择协议，可多选，如 1 2", "1"), ",", " "))
		ok := len(parts) > 0
		seen := map[string]bool{}
		var selected []string
		for _, v := range parts {
			n, er := strconv.Atoi(v)
			if er != nil || n < 1 || n > len(createProtocols) || seen[v] {
				ok = false
				break
			}
			seen[v] = true
			selected = append(selected, createProtocols[n-1])
		}
		if ok {
			return selected
		}
		u.say("协议编号无效或重复")
	}
	return nil
}

// realityTarget validates the handshake target from this server. The default is checked
// without asking; the user is only prompted when it fails or when changing it deliberately.
func (u *UI) realityTarget(sni string, ask bool) (string, error) {
	for u.err == nil {
		if ask {
			sni = u.ask("Reality SNI（所选协议共用）", sni)
		}
		ask = true
		if !validHost(sni) || net.ParseIP(sni) != nil {
			u.say("Reality SNI 应为有效域名")
			continue
		}
		u.say("正在从本机检查 Reality 目标…")
		if e := u.realityCheck(sni); e != nil {
			u.warn(u.a.Error(e))
			if !u.yes("仍然使用此 SNI", false) {
				continue
			}
		} else {
			u.good("Reality 目标支持 TLS 1.3 和 HTTP/2")
		}
		return sni, nil
	}
	return "", u.err
}

// portConflict reports why a listening port cannot be used by p: another entry already
// uses it on a shared network (TCP and UDP are checked separately), or the port is bound
// on this host.
func portConflict(s State, p Profile) error {
	for _, other := range s.Profiles {
		if other.ID != p.ID && other.Port == p.Port {
			for _, n := range p.Networks() {
				if sharesNetwork(other.Networks(), []string{n}) {
					return fmt.Errorf("%s 与 %s 占用相同 %s 端口", other.Name, p.Name, strings.ToUpper(n))
				}
			}
		}
	}
	return CheckAvailable(p)
}

// askListenPort reads a listening port for p and keeps asking until it is free on every
// network p uses. On a legacy NAT host the mapped public port is derived from the saved range.
func (u *UI) askListenPort(s State, setup ServerSetup, p *Profile) {
	for u.err == nil {
		p.Port = u.askPortValue(p.Name+" "+u.a.T("监听端口"), p.Port)
		if u.err != nil {
			return
		}
		p.PublicPort = p.Port
		if setup.NAT {
			p.PublicPort = setup.PublicStart + p.Port - setup.LocalStart
			if !AllowedPort(*p, setup) {
				u.say("端口超出 NAT 分配范围")
				continue
			}
		}
		if e := portConflict(s, *p); e != nil {
			u.fail(u.a.Error(e))
			continue
		}
		return
	}
}

func (u *UI) createSummary(setup ServerSetup, s State, ids []string) {
	u.heading("确认创建")
	u.printf("服务器地址：%s\n", u.serverSummary(setup))
	for _, id := range ids {
		p, _ := Find(s, id)
		ports := strings.ToUpper(strings.Join(p.Networks(), "+"))
		fmt.Fprintf(u.writer(), "  %s  %s  %s %d  →  %s\n", pad(p.Name, 26), pad(ProtocolLabel(p.Protocol), 8), ports, p.Port, net.JoinHostPort(p.PublicHost, itoa(p.PublicPort)))
	}
}

// create is the guided node-creation flow: addresses (detected), one base name, one or
// several protocols, automatic ports and credentials, a single confirmation.
func (u *UI) create() error {
	old, e := u.a.Load()
	if e != nil {
		return e
	}
	setup, e := u.serverSetup()
	if e != nil {
		return e
	}
	base := u.ask("基础节点名称（仅填写一次，例如 Tokyo）", "Rout")
	selected := u.selectProtocols()
	if u.err != nil {
		return u.err
	}
	if setup.NAT && setup.Network == "udp" && contains(selected, "ss") {
		u.warn("仅 UDP 映射下的 Shadowsocks 只能转发 UDP 应用流量，网页等 TCP 应用无法使用")
	}
	realitySNI := "addons.mozilla.org"
	if contains(selected, "vless") || contains(selected, "anytls") {
		if realitySNI, e = u.realityTarget(realitySNI, false); e != nil {
			return e
		}
	}
	cert, key, tlsSNI := "", "", setup.PublicHost
	if contains(selected, "hy2") || contains(selected, "tuic") {
		// Self-signed by default: no domain needed. Advanced options switch to a PEM pair.
		if cert, key, e = GenerateCertificate(tlsSNI); e != nil {
			return e
		}
		u.say("HY2/TUIC 使用自动生成的自签证书（高级选项中可改用现有 PEM 证书）")
	}
	exitID := ""
	if len(old.Exits) > 0 {
		u.say("这批节点的出站（同一批节点使用相同出站）：")
		var ok bool
		if exitID, ok = u.pickOutbound(old, ""); !ok {
			return u.err
		}
		if exitID != "" {
			ex, er := FindExit(old, exitID)
			if er != nil {
				return er
			}
			if _, er = u.testExit(ex.Proxy); er != nil {
				return er
			}
		}
	}
	next := old.Clone()
	var created []string
	for _, protocol := range selected {
		p, e := NewProfile(protocol)
		if e != nil {
			return e
		}
		p.Name = uniqueName(next, base+"-"+ProtocolLabel(protocol))
		p.SNI = realitySNI
		if protocol == "hy2" || protocol == "tuic" {
			p.SNI, p.CertPEM, p.KeyPEM, p.TLSGenerated = tlsSNI, cert, key, true
		}
		if p, e = PlanPort(p, setup, next); e != nil {
			return fmt.Errorf("%s: %w", p.Name, e)
		}
		if e = p.Validate(); e != nil {
			return fmt.Errorf("%s: %w", p.Name, e)
		}
		next = replace(next, p)
		if exitID != "" {
			if next, e = BindExit(next, p.ID, exitID); e != nil {
				return e
			}
		}
		created = append(created, p.ID)
	}
confirm:
	for {
		u.createSummary(setup, next, created)
		switch u.option("确认创建这些节点？", []menuItem{
			itemNote("create", "创建", "端口和认证凭据已自动生成"),
			itemNote("ports", "修改端口", "手动指定监听端口；会检查 TCP 和 UDP 是否被占用"),
			itemNote("advanced", "高级选项", "自定义凭据、Reality SNI、使用现有 PEM 证书"),
			item("cancel", "取消"),
		}, "create") {
		case "create":
			break confirm
		case "ports":
			for _, id := range created {
				p, _ := Find(next, id)
				u.askListenPort(next, setup, &p)
				if u.err != nil {
					return u.err
				}
				next = replace(next, p)
			}
		case "advanced":
			if next, e = u.createAdvanced(next, created); e != nil {
				return e
			}
		default:
			if u.err != nil {
				return u.err
			}
			u.say("已取消")
			return nil
		}
	}
	for _, id := range created {
		p, _ := Find(next, id)
		if e = p.Validate(); e != nil {
			return fmt.Errorf("%s: %w", p.Name, e)
		}
	}
	if e = u.a.Commit(old, next, false); e != nil {
		return e
	}
	u.good("节点创建成功")
	for _, id := range created {
		p, _ := Find(next, id)
		fmt.Fprintln(u.writer(), u.bold(p.Name))
		if e = u.printLinks(p, &setup); e != nil {
			return e
		}
	}
	return u.saveServer(setup)
}

// createAdvanced groups the rarely needed choices so the default path stays short.
func (u *UI) createAdvanced(next State, ids []string) (State, error) {
	has := func(protocols ...string) bool {
		for _, id := range ids {
			p, _ := Find(next, id)
			if contains(protocols, p.Protocol) {
				return true
			}
		}
		return false
	}
	var items []menuItem
	if has("vless", "anytls") {
		items = append(items, item("reality", "Reality SNI"))
	}
	if has("hy2", "tuic") {
		items = append(items, item("tls", "HY2/TUIC 证书"))
	}
	items = append(items, item("credentials", "自定义认证凭据"))
	v := u.menu("高级选项", items, "返回")
	if u.err != nil || v == "" {
		return next, u.err
	}
	each := func(protocols []string, fn func(*Profile)) {
		for _, id := range ids {
			p, _ := Find(next, id)
			if contains(protocols, p.Protocol) {
				fn(&p)
				next = replace(next, p)
			}
		}
	}
	switch v {
	case "reality":
		var cur string
		each([]string{"vless", "anytls"}, func(p *Profile) { cur = p.SNI })
		sni, e := u.realityTarget(cur, true)
		if e != nil {
			return next, e
		}
		each([]string{"vless", "anytls"}, func(p *Profile) { p.SNI = sni })
	case "tls":
		var cur string
		each([]string{"hy2", "tuic"}, func(p *Profile) { cur = p.SNI })
		choice := u.option("HY2/TUIC 证书", []menuItem{item("self", "自动生成自签证书（推荐，无需域名）"), item("pem", "使用现有 PEM 证书文件")}, "self")
		sni := u.ask("TLS 证书域名或 IP", cur)
		if u.err != nil {
			return next, u.err
		}
		var cert, key string
		var e error
		if choice == "self" {
			u.say("自签 HY2 链接包含证书指纹与 insecure=1；仅在客户端验证 pinSHA256 时安全，不支持指纹校验请导出客户端配置")
			u.say("TUIC 自签节点请导出客户端配置以信任证书，普通链接需手动导入证书")
			cert, key, e = GenerateCertificate(sni)
		} else {
			cert, key, e = u.readCertificate()
		}
		if e != nil {
			return next, e
		}
		each([]string{"hy2", "tuic"}, func(p *Profile) {
			p.SNI, p.CertPEM, p.KeyPEM, p.TLSGenerated = sni, cert, key, choice == "self"
		})
	case "credentials":
		each(createProtocols, func(p *Profile) {
			u.printf("配置 %s 的认证凭据\n", ProtocolLabel(p.Protocol))
			if p.Protocol == "vless" || p.Protocol == "tuic" {
				p.UUID = u.ask("UUID", p.UUID)
			}
			if p.Protocol != "vless" {
				if pw := u.secret("密码（SS2022 使用 16 字节 Base64 密钥）"); pw != "" {
					p.Password = pw
				}
			}
		})
		if u.err != nil {
			return next, u.err
		}
	}
	for _, id := range ids {
		p, _ := Find(next, id)
		if e := p.Validate(); e != nil {
			return next, fmt.Errorf("%s: %w", p.Name, e)
		}
	}
	return next, u.err
}
