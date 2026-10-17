package rout

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type UI struct {
	a            *App
	in           *bufio.Reader
	out          io.Writer
	err          error
	detectIP     func() string
	probeProxy   func(Proxy) (string, error)
	checkReality func(string) error
}

func (u *UI) writer() io.Writer {
	if u.out != nil {
		return u.out
	}
	return os.Stdout
}
func (u *UI) say(s string)                 { fmt.Fprintln(u.writer(), u.a.T(s)) }
func (u *UI) printf(s string, args ...any) { fmt.Fprintf(u.writer(), u.a.T(s), args...) }
func (u *UI) ask(prompt, def string) string {
	if u.err != nil {
		return ""
	}
	if def != "" {
		fmt.Fprintf(u.writer(), "%s [%s]: ", u.a.T(prompt), def)
	} else {
		fmt.Fprint(u.writer(), u.a.T(prompt)+": ")
	}
	s, e := u.in.ReadString('\n')
	if e != nil && !(errors.Is(e, io.EOF) && s != "") {
		u.err = e
		return ""
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return def
	}
	return s
}
func (u *UI) secret(prompt string) string {
	if u.err != nil {
		return ""
	}
	st, e := os.Stdin.Stat()
	if e != nil || st.Mode()&os.ModeCharDevice == 0 || u.out != nil {
		return u.ask(prompt, "")
	}
	cmd := exec.Command("stty", "-g")
	cmd.Stdin = os.Stdin
	b, e := cmd.Output()
	if e != nil {
		return u.ask(prompt, "")
	}
	saved := strings.TrimSpace(string(b))
	set := func(arg string) { c := exec.Command("stty", arg); c.Stdin = os.Stdin; _ = c.Run() }
	set("-echo")
	defer set(saved)
	ch := make(chan os.Signal, 1)
	done := make(chan struct{})
	signal.Notify(ch, os.Interrupt)
	defer signal.Stop(ch)
	defer close(done)
	go func() {
		select {
		case <-ch:
			set(saved)
			fmt.Println()
			os.Exit(130)
		case <-done:
		}
	}()
	s := u.ask(u.a.T(prompt)+u.a.T("（输入隐藏）"), "")
	fmt.Fprintln(u.writer())
	return s
}
func (u *UI) choose(prompt string, allowed []string, def string) string {
	for u.err == nil {
		s := u.ask(prompt, def)
		for _, v := range allowed {
			if s == v {
				return s
			}
		}
		u.say("请选择菜单中的编号")
	}
	return ""
}
func (u *UI) yes(prompt string, def bool) bool {
	d := "n"
	if def {
		d = "y"
	}
	for u.err == nil {
		s := strings.ToLower(u.ask(u.a.T(prompt)+" y/n", d))
		if s == "y" || s == "yes" {
			return true
		}
		if s == "n" || s == "no" {
			return false
		}
		u.say("请输入 y 或 n")
	}
	return false
}
func (u *UI) port(prompt string, def int) int {
	for u.err == nil {
		n, e := strconv.Atoi(u.ask(prompt, itoa(def)))
		if e == nil && validPort(n) {
			return n
		}
		u.say("端口应为 1–65535")
	}
	return 0
}
func (u *UI) initLanguage(force bool) error {
	s, e := u.a.LoadSettings()
	if e != nil {
		return e
	}
	if !force && u.a.Language != "" {
		return nil
	}
	if !force && s.Language != "" {
		u.a.Language = s.Language
		return nil
	}
	fmt.Fprintln(u.writer(), "请选择语言 / Select language\n1. 简体中文\n2. English")
	v := u.choose("Language", []string{"1", "2"}, "1")
	if u.err != nil {
		return u.err
	}
	s.Language = map[string]string{"1": "zh-CN", "2": "en"}[v]
	u.a.Language = s.Language
	return u.a.SaveSettings(s)
}

// serverSummary describes saved server defaults on one line.
func (u *UI) serverSummary(s ServerSetup) string {
	kind := u.a.T("普通 VPS")
	if s.NAT {
		kind = u.a.T("NAT VPS")
	}
	line := kind + " · " + u.a.T("公网") + " " + s.PublicHost + " · " + u.a.T("监听") + " " + s.Listen
	if s.NAT {
		line += fmt.Sprintf(" · %d-%d → %d · %s", s.LocalStart, s.LocalEnd, s.PublicStart, ProtocolLabel(s.Network))
	}
	return line
}

// serverSetup asks for the machine type and addresses only when nothing is saved or
// the user wants to change them; saved defaults are reused with a single confirmation.
func (u *UI) serverSetup() (ServerSetup, error) { return u.askServer(true) }
func (u *UI) askServer(reuse bool) (ServerSetup, error) {
	saved, e := u.a.LoadSettings()
	if e != nil {
		return ServerSetup{}, e
	}
	if reuse && saved.Server != nil && saved.Server.Validate() == nil {
		u.printf("服务器设置：%s\n", u.serverSummary(*saved.Server))
		if u.yes("使用已保存的服务器设置", true) {
			return *saved.Server, nil
		}
		if u.err != nil {
			return ServerSetup{}, u.err
		}
	}
	s := ServerSetup{Listen: "0.0.0.0", Network: "both"}
	if saved.Server != nil {
		s = *saved.Server
	}
	def := "vps"
	if s.NAT {
		def = "nat"
	}
	s.NAT = u.option("服务器类型", []menuItem{item("vps", "普通 VPS（端口可自由使用）"), item("nat", "NAT VPS（仅可使用商家分配的端口）")}, def) == "nat"
	if s.PublicHost == "" {
		if u.detectIP != nil {
			s.PublicHost = u.detectIP()
		} else {
			s.PublicHost = DetectPublicIP()
		}
	}
	for u.err == nil {
		s.PublicHost = u.ask("公网连接 IP 或域名", s.PublicHost)
		if validHost(s.PublicHost) {
			break
		}
		u.say("地址或端口无效")
	}
	if ip := net.ParseIP(s.PublicHost); ip != nil && ip.To4() == nil && s.Listen == "0.0.0.0" {
		s.Listen = "::"
	}
	for u.err == nil {
		s.Listen = u.ask("本机监听地址（默认监听所有网卡）", s.Listen)
		if net.ParseIP(s.Listen) != nil {
			break
		}
		u.say("监听地址或公网地址无效")
	}
	if s.NAT {
		u.say("请填写商家已分配的端口；Rout 不会创建或猜测公网映射")
		def := ""
		if s.LocalStart > 0 {
			def = itoa(s.LocalStart) + "-" + itoa(s.LocalEnd)
		}
		for u.err == nil {
			start, end, e := ParsePortRange(u.ask("允许的本地端口范围", def))
			if e != nil {
				u.say(e.Error())
				continue
			}
			s.LocalStart = start
			s.LocalEnd = end
			break
		}
		start := s.PublicStart
		if !validPort(start) {
			start = s.LocalStart
		}
		s.PublicStart = u.port("对应公网起始端口（端口相同则保持默认）", start)
		if s.Network == "" {
			s.Network = "both"
		}
		s.Network = u.option("商家允许的网络", []menuItem{item("both", "TCP＋UDP"), item("tcp", "仅 TCP"), item("udp", "仅 UDP")}, s.Network)
	}
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
func ProtocolLabel(p string) string {
	return map[string]string{"vless": "VLESS", "anytls": "AnyTLS", "ss": "SS", "hy2": "HY2", "tuic": "TUIC", "tcp": "TCP", "udp": "UDP", "both": "TCP+UDP"}[p]
}
func (u *UI) exitLabel(s State, p Profile) string {
	if p.Kind == "relay" {
		return u.a.T("转发到 ") + p.Target
	}
	if p.ExitID != "" {
		if e, er := FindExit(s, p.ExitID); er == nil {
			return e.Name + " (" + strings.ToUpper(e.Proxy.Protocol) + ")"
		}
	}
	if p.Outbound != nil {
		return strings.ToUpper(p.Outbound.Protocol) + " " + net.JoinHostPort(p.Outbound.Host, itoa(p.Outbound.Port))
	}
	return u.a.T("VPS 直连")
}

// nodeCard is a credential-free two-line summary that fits narrow/mobile terminals.
func (u *UI) nodeCard(s State, i int, p Profile) {
	state := u.a.T("启用")
	if !p.Enabled {
		state = u.a.T("停用")
	}
	kind := ProtocolLabel(p.Protocol)
	if p.Kind == "relay" {
		kind = u.a.T("中转") + " " + kind
	}
	fmt.Fprintf(u.writer(), "  %s %s %s\n", u.paint("36", fmt.Sprintf("%2d.", i)), u.bold(p.Name), u.dim("["+p.ID+"]"))
	line := fmt.Sprintf("%s · %s/%s · %s %d · %s %s · %s %s", kind, state, u.a.Running(p), u.a.T("本地"), p.Port, u.a.T("公网"), net.JoinHostPort(p.PublicHost, itoa(p.PublicPort)), u.a.T("出口"), u.exitLabel(s, p))
	fmt.Fprintln(u.writer(), "      "+line)
	if days, ok := p.CertificateDays(time.Now()); ok {
		if days < 0 {
			fmt.Fprintln(u.writer(), "      "+u.paint("31", u.a.T("证书已过期，请在证书管理中更新")))
		} else if days <= certificateWarnDays {
			fmt.Fprintln(u.writer(), "      "+u.paint("33", fmt.Sprintf(u.a.T("证书 %d 天后过期，请在证书管理中更新"), days)))
		}
	}
}
func (u *UI) viewNodes(s State) {
	if len(s.Profiles) == 0 {
		u.say("暂无节点或线路")
		return
	}
	for i, p := range s.Profiles {
		u.nodeCard(s, i+1, p)
	}
}

// list is the explicit `rout list` view: cards plus each complete share link.
func (u *UI) list(s State) {
	if len(s.Profiles) == 0 {
		u.say("暂无节点或线路")
		return
	}
	for i, p := range s.Profiles {
		u.nodeCard(s, i+1, p)
		if uri, e := p.URI(); e == nil {
			fmt.Fprintln(u.writer(), "      "+uri)
		} else {
			fmt.Fprintln(u.writer(), "      "+u.a.T("手动端口转发：使用原客户端的协议和认证信息"))
		}
	}
}

// pick shows credential-free cards; links appear only when explicitly requested.
func (u *UI) pick(s State, nodeOnly bool) (Profile, error) {
	choices := s.Clone()
	choices.Profiles = nil
	for _, p := range s.Profiles {
		if !nodeOnly || p.Kind == "node" {
			choices.Profiles = append(choices.Profiles, p)
		}
	}
	if len(choices.Profiles) == 0 {
		return Profile{}, errors.New("没有可选节点，请先创建节点")
	}
	u.viewNodes(choices)
	for u.err == nil {
		v := u.ask("选择节点编号（0 返回）", "0")
		if v == "0" {
			return Profile{}, nil
		}
		n, e := strconv.Atoi(v)
		if e == nil && n > 0 && n <= len(choices.Profiles) {
			return choices.Profiles[n-1], nil
		}
		u.say("编号无效")
	}
	return Profile{}, u.err
}
func (u *UI) exitUsers(s State, id string) int {
	n := 0
	for _, p := range s.Profiles {
		if p.ExitID == id {
			n++
		}
	}
	return n
}
func (u *UI) exitLine(s State, i int, e Exit) {
	use := u.a.T("未使用")
	if n := u.exitUsers(s, e.ID); n > 0 {
		use = fmt.Sprintf(u.a.T("%d 个节点使用"), n)
	}
	fmt.Fprintf(u.writer(), "  %s %s  %s %s · %s\n", u.paint("36", fmt.Sprintf("%2d.", i)), u.bold(e.Name), strings.ToUpper(e.Proxy.Protocol), net.JoinHostPort(e.Proxy.Host, itoa(e.Proxy.Port)), use)
}

// pickExitIndex selects an existing exit by its displayed number. IDs stay internal.
func (u *UI) pickExitIndex(s State) (Exit, bool) {
	if len(s.Exits) == 0 {
		u.say("暂无出口，请先添加出口")
		return Exit{}, false
	}
	for i, e := range s.Exits {
		u.exitLine(s, i+1, e)
	}
	for u.err == nil {
		n, e := strconv.Atoi(u.ask("选择出口编号（0 返回）", "0"))
		if e == nil && n == 0 {
			return Exit{}, false
		}
		if e == nil && n > 0 && n <= len(s.Exits) {
			return s.Exits[n-1], true
		}
		u.say("编号无效")
	}
	return Exit{}, false
}

// pickExit chooses an outbound for a node; 0 is the direct VPS exit.
func (u *UI) pickExit(s State) (string, error) {
	fmt.Fprintf(u.writer(), "  %s %s\n", u.paint("36", " 0."), u.a.T("VPS 直连"))
	for i, e := range s.Exits {
		u.exitLine(s, i+1, e)
	}
	for u.err == nil {
		v := u.ask("选择出口编号", "0")
		n, e := strconv.Atoi(v)
		if e == nil && n >= 0 && n <= len(s.Exits) {
			if n == 0 {
				return "", nil
			}
			return s.Exits[n-1].ID, nil
		}
		u.say("编号无效")
	}
	return "", u.err
}

// uniqueName keeps generated batch names distinct from every existing node.
func uniqueName(s State, name string) string {
	taken := map[string]bool{}
	for _, p := range s.Profiles {
		taken[strings.ToLower(p.Name)] = true
	}
	candidate := name
	for i := 2; taken[strings.ToLower(candidate)]; i++ {
		candidate = name + "-" + itoa(i)
	}
	return candidate
}
func (u *UI) realityCheck(sni string) error {
	if u.checkReality != nil {
		return u.checkReality(sni)
	}
	return CheckRealityTarget(sni)
}
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
	u.say("可创建的协议：")
	protocols := []string{"vless", "anytls", "ss", "hy2", "tuic"}
	labels := []string{"VLESS Reality", "AnyTLS Reality", "Shadowsocks 2022", "Hysteria2", "TUIC v5"}
	for i, label := range labels {
		fmt.Fprintf(u.writer(), "  %s  %s\n", u.paint("36", fmt.Sprintf("%2d", i+1)), label)
	}
	var selected []string
	for u.err == nil {
		parts := strings.Fields(strings.ReplaceAll(u.ask("选择协议，可多选，如 1 2", "1"), ",", " "))
		ok := len(parts) > 0
		seen := map[string]bool{}
		selected = nil
		for _, v := range parts {
			n, er := strconv.Atoi(v)
			if er != nil || n < 1 || n > len(protocols) || seen[v] {
				ok = false
				break
			}
			seen[v] = true
			selected = append(selected, protocols[n-1])
		}
		if ok {
			break
		}
		u.say("协议编号无效或重复")
	}
	if u.err != nil {
		return u.err
	}
	if setup.NAT && setup.Network == "udp" && contains(selected, "ss") {
		u.warn("仅 UDP 映射下的 Shadowsocks 只能转发 UDP 应用流量，网页等 TCP 应用无法使用")
	}
	manual := u.yes("手动指定各协议端口", false)
	autoCredentials := u.yes("自动生成认证凭据", true)
	realitySNI := "addons.mozilla.org"
	if contains(selected, "vless") || contains(selected, "anytls") {
		for u.err == nil {
			realitySNI = u.ask("Reality SNI（所选协议共用）", realitySNI)
			if !validHost(realitySNI) || net.ParseIP(realitySNI) != nil {
				u.say("Reality SNI 应为有效域名")
				continue
			}
			u.say("正在从本机检查 Reality 目标…")
			if e := u.realityCheck(realitySNI); e != nil {
				u.warn(u.a.Error(e))
				if !u.yes("仍然使用此 SNI", false) {
					continue
				}
			} else {
				u.good("Reality 目标支持 TLS 1.3 和 HTTP/2")
			}
			break
		}
	}
	cert, key, tlsSNI := "", "", setup.PublicHost
	generated := false
	if contains(selected, "hy2") || contains(selected, "tuic") {
		choice := u.option("HY2/TUIC 证书", []menuItem{item("self", "自动生成自签证书（推荐，无需域名）"), item("pem", "使用现有 PEM 证书文件")}, "self")
		tlsSNI = u.ask("TLS 证书域名或 IP", tlsSNI)
		if choice == "self" {
			u.say("自签 HY2 链接包含证书指纹与 insecure=1；仅在客户端验证 pinSHA256 时安全，不支持指纹校验请导出客户端配置")
			if contains(selected, "tuic") {
				u.say("TUIC 自签节点请导出客户端配置以信任证书，普通链接需手动导入证书")
			}
			generated = true
			cert, key, e = GenerateCertificate(tlsSNI)
		} else {
			cert, key, e = u.readCertificate()
		}
		if e != nil {
			return e
		}
	}
	exitID := ""
	if len(old.Exits) > 0 {
		u.say("选择节点出口：")
		exitID, e = u.pickExit(old)
		if e != nil {
			return e
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
		if !autoCredentials {
			u.printf("配置 %s 的认证凭据\n", ProtocolLabel(protocol))
			if protocol == "vless" || protocol == "tuic" {
				p.UUID = u.ask("UUID", "")
			}
			if protocol != "vless" {
				p.Password = u.secret("密码（SS2022 使用 16 字节 Base64 密钥）")
			}
		}
		p.SNI = realitySNI
		if protocol == "hy2" || protocol == "tuic" {
			p.SNI = tlsSNI
			p.CertPEM = cert
			p.KeyPEM = key
			p.TLSGenerated = generated
		}
		p, e = PlanPort(p, setup, next)
		if e != nil {
			return fmt.Errorf("%s: %w", p.Name, e)
		}
		if manual {
			for u.err == nil {
				p.Port = u.port(p.Name+" "+u.a.T("本地端口"), p.Port)
				p.PublicPort = p.Port
				if setup.NAT {
					p.PublicPort = setup.PublicStart + p.Port - setup.LocalStart
				}
				if AllowedPort(p, setup) {
					break
				}
				u.say("端口超出 NAT 分配范围")
			}
		}
		if u.err != nil {
			return u.err
		}
		if e = p.Validate(); e != nil {
			return fmt.Errorf("%s: %w", p.Name, e)
		}
		next = replace(next, p)
		if exitID != "" {
			next, e = BindExit(next, p.ID, exitID)
			if e != nil {
				return e
			}
		}
		created = append(created, p.ID)
	}
	if e = u.a.Commit(old, next, false); e != nil {
		return e
	}
	u.good("节点创建成功")
	for _, id := range created {
		p, _ := Find(next, id)
		uri, er := p.URI()
		if er != nil {
			return er
		}
		fmt.Fprintln(u.writer(), u.bold(p.Name))
		fmt.Fprintln(u.writer(), uri)
	}
	return u.saveServer(setup)
}
func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
func (u *UI) readCertificate() (string, string, error) {
	cert := u.ask("PEM 证书文件路径", "")
	key := u.ask("PEM 私钥文件路径", "")
	if u.err != nil {
		return "", "", u.err
	}
	c, e := os.ReadFile(cert)
	if e != nil {
		return "", "", errors.New("无法读取证书")
	}
	k, e := os.ReadFile(key)
	if e != nil {
		return "", "", errors.New("无法读取私钥")
	}
	return string(c), string(k), nil
}
func (u *UI) relay() error {
	old, e := u.a.Load()
	if e != nil {
		return e
	}
	setup, e := u.serverSetup()
	if e != nil {
		return e
	}
	raw := u.secret("粘贴落地节点链接，或填写目标 IP:端口")
	if u.err != nil {
		return u.err
	}
	target, network, e := ParseTarget(raw)
	if e != nil {
		return e
	}
	p := Profile{ID: RandomHex(6), Name: uniqueName(old, u.ask("线路名称", "Relay")), Kind: "relay", Enabled: true, Target: target, Protocol: network}
	now := time.Now()
	p.CreatedAt = &now
	if strings.Contains(raw, "://") {
		p.TargetURI = raw
	}
	if !strings.Contains(raw, "://") || network == "both" {
		p.Protocol = u.option("转发网络", []menuItem{item("tcp", "TCP"), item("udp", "UDP"), item("both", "TCP＋UDP")}, "tcp")
	}
	p, e = PlanPort(p, setup, old)
	if e != nil {
		return e
	}
	if u.yes("手动指定中转端口", false) {
		for u.err == nil {
			p.Port = u.port("本地端口", p.Port)
			p.PublicPort = p.Port
			if setup.NAT {
				p.PublicPort = setup.PublicStart + p.Port - setup.LocalStart
			}
			if AllowedPort(p, setup) {
				break
			}
			u.say("端口超出 NAT 分配范围")
		}
	}
	if u.err != nil {
		return u.err
	}
	if e = u.a.Commit(old, replace(old, p), false); e != nil {
		return e
	}
	u.good("中转线路已创建")
	if uri, e := p.URI(); e == nil {
		fmt.Fprintln(u.writer(), uri)
	} else {
		u.printf("将原客户端连接地址改为 %s，端口改为 %d，保留原 SNI 等参数\n", p.PublicHost, p.PublicPort)
	}
	return u.saveServer(setup)
}
func (u *UI) bind() error {
	s, e := u.a.Load()
	if e != nil {
		return e
	}
	p, e := u.pick(s, true)
	if e != nil || p.ID == "" {
		return e
	}
	return u.bindProfile(s, p)
}
func (u *UI) bindProfile(old State, p Profile) error {
	if p.Kind != "node" {
		return errors.New("原样转发线路请在落地节点配置出口")
	}
	u.printf("当前出口：%s\n", u.exitLabel(old, p))
	id, e := u.pickExit(old)
	if e != nil {
		return e
	}
	if id == p.ExitID {
		u.say("出口未改变")
		return nil
	}
	if id != "" {
		ex, er := FindExit(old, id)
		if er != nil {
			return er
		}
		ip, er := u.testExit(ex.Proxy)
		if er != nil {
			return er
		}
		u.printf("实际出口 IP：%s\n", ip)
	}
	next, e := BindExit(old, p.ID, id)
	if e != nil {
		return e
	}
	if e = u.a.Commit(old, next, false); e != nil {
		return e
	}
	u.good("出口已更新")
	return nil
}
func (u *UI) proxyInput() (Proxy, error) {
	protocol := u.option("出口协议", []menuItem{item("socks5", "SOCKS5"), item("http", "HTTP CONNECT")}, "socks5")
	for u.err == nil {
		raw := u.secret("输入代理 IP:端口:用户名:密码（IPv6 使用 [地址]:端口:用户名:密码）")
		if u.err != nil {
			return Proxy{}, u.err
		}
		p, e := ParseProxy(protocol, raw)
		if e == nil {
			return *p, nil
		}
		u.say(u.a.Error(e))
	}
	return Proxy{}, u.err
}
func (u *UI) testExit(p Proxy) (string, error) {
	if u.probeProxy != nil {
		return u.probeProxy(p)
	}
	return u.a.ProbeProxy(p)
}

// exits is the outbound manager. Exits are chosen by displayed number; their stable
// IDs remain the persistent references in the configuration.
func (u *UI) exits() error {
	for {
		s, e := u.a.Load()
		if e != nil {
			return e
		}
		u.heading("出口管理")
		if len(s.Exits) == 0 {
			u.say("暂无出口")
		}
		for i, ex := range s.Exits {
			u.exitLine(s, i+1, ex)
		}
		v := u.menu("", []menuItem{item("add", "添加出口"), item("test", "测试出口"), item("edit", "修改出口"), item("delete", "删除出口"), item("bind", "绑定或解绑节点")}, "返回")
		if u.err != nil {
			return u.err
		}
		if v == "" {
			return nil
		}
		if e = u.exitAction(s, v); e != nil {
			return e
		}
	}
}
func (u *UI) exitAction(s State, v string) error {
	switch v {
	case "add":
		name := u.ask("出口名称", "Exit")
		p, e := u.proxyInput()
		if e != nil {
			return e
		}
		if u.err != nil {
			return u.err
		}
		next := UpsertExit(s, Exit{ID: RandomHex(6), Name: name, Proxy: p})
		if e = u.a.Commit(s, next, false); e != nil {
			return e
		}
		u.good("出口已保存，可测试后绑定到多个节点；未改变任何节点出口")
		return nil
	case "bind":
		return u.bind()
	}
	ex, ok := u.pickExitIndex(s)
	if !ok {
		return u.err
	}
	switch v {
	case "test":
		u.say("正在测试出口…")
		ip, e := u.testExit(ex.Proxy)
		if e != nil {
			return e
		}
		u.good(fmt.Sprintf(u.a.T("出口可用，实际出口 IP：%s"), ip))
	case "edit":
		ex.Name = u.ask("出口名称", ex.Name)
		previousProxy := ex.Proxy
		if u.yes("修改代理地址或认证信息", false) {
			var e error
			if ex.Proxy, e = u.proxyInput(); e != nil {
				return e
			}
		}
		if u.err != nil {
			return u.err
		}
		users := u.exitUsers(s, ex.ID)
		if ex.Proxy != previousProxy && users > 0 {
			if _, e := u.testExit(ex.Proxy); e != nil {
				return e
			}
		}
		prompt := "保存出口修改"
		if ex.Proxy != previousProxy && users > 0 {
			prompt = fmt.Sprintf(u.a.T("保存出口修改（将重启使用该出口的 %d 个节点）"), users)
		}
		if !u.yes(prompt, false) {
			return u.err
		}
		if e := u.a.Commit(s, UpsertExit(s, ex), false); e != nil {
			return e
		}
		u.good("出口已更新")
	case "delete":
		next, e := DeleteExit(s, ex.ID)
		if e != nil {
			return e
		}
		if !u.yes(fmt.Sprintf(u.a.T("删除出口 %s"), ex.Name), false) {
			return u.err
		}
		if e = u.a.Commit(s, next, false); e != nil {
			return e
		}
		u.good("出口已删除")
	}
	return nil
}
func (u *UI) copy(p Profile) error {
	uri, e := p.URI()
	if e != nil {
		return e
	}
	fmt.Fprintln(u.writer(), uri)
	if u.out == nil {
		if st, e := os.Stdout.Stat(); e == nil && st.Mode()&os.ModeCharDevice != 0 {
			fmt.Fprintf(u.writer(), "\033]52;c;%s\a", base64.StdEncoding.EncodeToString([]byte(uri)))
			u.say("已发送终端复制请求；若终端不支持，请手动复制以上完整链接")
			return nil
		}
	}
	u.say("请复制以上完整链接")
	return nil
}
func (u *UI) exportClient(p Profile) error {
	c, e := ClientConfig(p, p.PublicHost, p.PublicPort, 2080)
	if e != nil {
		return e
	}
	path := u.ask("保存路径", filepath.Join(u.a.Home, "exports", p.ID+"-client.json"))
	if u.err != nil {
		return u.err
	}
	b, e := JSON(c)
	if e != nil {
		return e
	}
	if e = AtomicWrite(path, b, 0600); e != nil {
		return e
	}
	u.printf("已保存：%s\n", path)
	return nil
}
func (u *UI) export(p Profile) error {
	if e := u.copy(p); e != nil {
		return e
	}
	if !u.yes("同时导出 sing-box 客户端配置", false) {
		return u.err
	}
	return u.exportClient(p)
}

// AllLinks renders every node's name and complete share link (credentials included).
func AllLinks(s State) string {
	var b strings.Builder
	for _, p := range s.Profiles {
		if uri, e := p.URI(); e == nil {
			fmt.Fprintf(&b, "# %s [%s]\n%s\n", p.Name, p.ID, uri)
		}
	}
	return b.String()
}
func (u *UI) exportAll(s State) error {
	links := AllLinks(s)
	if links == "" {
		u.say("暂无可导出的节点链接")
		return nil
	}
	u.warn("以下链接包含客户端凭据，请勿公开分享")
	fmt.Fprint(u.writer(), links)
	if !u.yes("同时保存为文件", false) {
		return u.err
	}
	path := u.ask("保存路径", filepath.Join(u.a.Home, "exports", "links.txt"))
	if u.err != nil {
		return u.err
	}
	if e := AtomicWrite(path, []byte(links), 0600); e != nil {
		return e
	}
	u.printf("已保存：%s\n", path)
	return nil
}
func (u *UI) links() error {
	v := u.menu("导出链接", []menuItem{item("one", "单个节点链接（可复制）"), item("all", "全部节点链接"), item("client", "sing-box 客户端配置")}, "返回")
	if v == "" {
		return u.err
	}
	s, e := u.a.Load()
	if e != nil {
		return e
	}
	if v == "all" {
		return u.exportAll(s)
	}
	p, e := u.pick(s, false)
	if e != nil || p.ID == "" {
		return e
	}
	if v == "client" {
		return u.exportClient(p)
	}
	return u.copy(p)
}

// manage is the node manager: global actions first, per-node actions in a submenu.
func (u *UI) manage() error {
	for {
		v := u.menu("节点管理", []menuItem{item("view", "查看节点"), item("add", "添加节点"), item("edit", "编辑节点"), item("delete", "删除节点"), item("restart", "重启节点"), item("links", "导出链接")}, "返回")
		if u.err != nil {
			return u.err
		}
		var e error
		switch v {
		case "":
			return nil
		case "view":
			var s State
			if s, e = u.a.Load(); e == nil {
				u.viewNodes(s)
			}
		case "add":
			e = u.create()
		case "links":
			e = u.links()
		default:
			var s State
			var p Profile
			if s, e = u.a.Load(); e == nil {
				if p, e = u.pick(s, false); e == nil && p.ID != "" {
					switch v {
					case "edit":
						e = u.nodeMenu(p.ID)
					case "delete":
						if u.yes(fmt.Sprintf(u.a.T("删除 %s 及其服务"), p.Name), false) {
							if e = u.a.Commit(s, removeProfile(s, p.ID), false); e == nil {
								u.good("节点已删除")
							}
						}
					case "restart":
						if e = u.a.Restart(p.ID); e == nil {
							u.good("节点已重启")
						}
					}
				}
			}
		}
		if e != nil {
			if errors.Is(e, io.EOF) {
				return e
			}
			u.fail(u.a.Error(e))
		}
		if u.err != nil {
			return u.err
		}
	}
}

// nodeMenu shows only the operations that apply to the selected entry.
func (u *UI) nodeMenu(id string) error {
	for {
		s, e := u.a.Load()
		if e != nil {
			return e
		}
		p, e := Find(s, id)
		if e != nil {
			return e
		}
		u.heading(p.Name)
		u.nodeCard(s, 0, p)
		toggle := "停用节点"
		if !p.Enabled {
			toggle = "启用节点"
		}
		items := []menuItem{item("link", "查看或复制链接"), item("name", "修改名称"), item("address", "修改端口或地址")}
		if p.Kind == "node" {
			items = append(items, item("exit", "选择出口"))
		}
		items = append(items, item("toggle", toggle), item("test", "测试连接"), item("logs", "查看日志"), item("traffic", "流量管理"))
		if p.Kind == "node" {
			items = append(items, item("credentials", "重置凭据"))
		}
		if _, ok := p.CertificateExpiry(); ok {
			items = append(items, item("cert", "证书管理"))
		}
		v := u.menu("", items, "返回")
		if u.err != nil {
			return u.err
		}
		if v == "" {
			return nil
		}
		if e = u.nodeAction(s, p, v); e != nil {
			if errors.Is(e, io.EOF) {
				return e
			}
			u.fail(u.a.Error(e))
		}
		if u.err != nil {
			return u.err
		}
	}
}
func (u *UI) nodeAction(s State, p Profile, v string) error {
	switch v {
	case "link":
		return u.export(p)
	case "exit":
		return u.bindProfile(s, p)
	case "test":
		return u.a.Probe(p)
	case "logs":
		return u.a.Logs(p)
	case "traffic":
		return u.trafficManage(p)
	case "cert":
		return u.certificate(s, p)
	case "name":
		p.Name = u.ask("节点名称", p.Name)
	case "address":
		p.PublicHost = u.ask("公网连接 IP 或域名", p.PublicHost)
		p.Port = u.port("本地端口", p.Port)
		p.PublicPort = u.port("公网端口", p.PublicPort)
		settings, e := u.a.LoadSettings()
		if e != nil {
			return e
		}
		if p.NAT && settings.Server != nil && settings.Server.NAT && !AllowedPort(p, *settings.Server) {
			return errors.New("端口超出 NAT 分配范围")
		}
	case "toggle":
		p.Enabled = !p.Enabled
	case "credentials":
		if !u.yes("重置后需要重新导入客户端链接", false) {
			return u.err
		}
		fresh, e := NewProfile(p.Protocol)
		if e != nil {
			return e
		}
		p.Password = fresh.Password
		p.UUID = fresh.UUID
		p.PrivateKey = fresh.PrivateKey
		p.PublicKey = fresh.PublicKey
		p.ShortID = fresh.ShortID
	}
	if u.err != nil {
		return u.err
	}
	if e := u.a.Commit(s, replace(s, p), false); e != nil {
		return e
	}
	u.good("已保存")
	if v == "credentials" {
		return u.copy(p)
	}
	return nil
}

// certificate shows validity and replaces a HY2/TUIC certificate on explicit request.
// Rotation is never automatic: every replacement changes what clients must trust.
func (u *UI) certificate(s State, p Profile) error {
	end, _ := p.CertificateExpiry()
	days, _ := p.CertificateDays(time.Now())
	kind := u.a.T("现有 PEM 证书")
	if p.TLSGenerated {
		kind = u.a.T("自签证书（链接含指纹）")
	}
	u.printf("证书：%s · %s · 到期 %s（剩余 %d 天）\n", kind, p.SNI, end.Format("2006-01-02"), days)
	v := u.menu("", []menuItem{item("self", "重新生成自签证书"), item("pem", "改用现有 PEM 证书文件")}, "返回")
	if v == "" {
		return u.err
	}
	var e error
	if v == "self" {
		u.warn("新证书的指纹会改变：所有客户端必须重新导入链接或客户端配置")
		if !u.yes("重新生成证书", false) {
			return u.err
		}
		if p, e = RegenerateCertificate(p); e != nil {
			return e
		}
	} else {
		p.SNI = u.ask("TLS 证书域名或 IP", p.SNI)
		if p.CertPEM, p.KeyPEM, e = u.readCertificate(); e != nil {
			return e
		}
		p.TLSGenerated = false
	}
	if e = u.a.Commit(s, replace(s, p), false); e != nil {
		return e
	}
	u.good("证书已更新；请重新导入以下链接")
	return u.copy(p)
}
func (u *UI) trafficMenu() error {
	s, e := u.a.Load()
	if e != nil {
		return e
	}
	p, e := u.pick(s, false)
	if e != nil || p.ID == "" {
		return e
	}
	return u.trafficManage(p)
}
func (u *UI) settings() error {
	v := u.menu("设置与语言", []menuItem{item("language", "切换语言"), item("server", "服务器默认设置"), item("backups", "自动备份保留数量")}, "返回")
	switch v {
	case "language":
		return u.initLanguage(true)
	case "server":
		s, e := u.askServer(false) // Edit every field, starting from the saved values.
		if e != nil {
			return e
		}
		return u.saveServer(s)
	case "backups":
		saved, e := u.a.LoadSettings()
		if e != nil {
			return e
		}
		keep := saved.BackupKeep
		if keep == 0 {
			keep = defaultBackupKeep
		}
		for u.err == nil {
			n, e := strconv.Atoi(u.ask("保留最近的自动备份数量（1–1000）", itoa(keep)))
			if e == nil && n >= 1 && n <= 1000 {
				saved.BackupKeep = n
				break
			}
			u.say("请输入 1–1000")
		}
		if u.err != nil {
			return u.err
		}
		if saved.Language == "" {
			saved.Language = u.a.Language
		}
		return u.a.SaveSettings(saved)
	}
	return u.err
}

func (u *UI) backupMenu() error {
	v := u.menu("备份与恢复", []menuItem{item("backup", "创建备份"), item("restore", "从备份恢复")}, "返回")
	if v == "" {
		return u.err
	}
	path := u.ask("备份文件路径", filepath.Join(u.a.Home, "rout-backup.json"))
	if u.err != nil {
		return u.err
	}
	if v == "backup" {
		if e := u.a.Backup(path); e != nil {
			return e
		}
		u.good("备份已保存（包含认证信息和私钥，请妥善保管）")
		return nil
	}
	if !u.yes("使用备份替换当前配置", false) {
		return u.err
	}
	if e := u.a.Restore(path); e != nil {
		return e
	}
	u.good("配置已恢复")
	return nil
}

// notices lists conditions that need attention, shown once when the menu opens.
func (u *UI) notices() {
	s, e := u.a.Load()
	if e != nil {
		u.fail(u.a.Error(e))
		return
	}
	now := time.Now()
	limited := false
	for _, p := range s.Profiles {
		if days, ok := p.CertificateDays(now); ok && days <= certificateWarnDays {
			if days < 0 {
				u.warnf("%s 的证书已过期，请在 节点管理 → 编辑节点 → 证书管理 中更新", p.Name)
			} else {
				u.warnf("%s 的证书 %d 天后过期", p.Name, days)
			}
		}
		limited = limited || p.trafficPolicy().LimitBytes > 0
	}
	if !u.a.trafficActive() {
		if limited {
			u.warn("流量监控未启用：有限额节点保持暂停，请运行 rout traffic install")
		}
		return
	}
	if db, e := u.a.loadTraffic(); e == nil {
		for _, p := range s.Profiles {
			switch db.Records[p.ID].Blocked {
			case blockFault:
				u.warnf("%s 因计量缺口暂停，可在流量管理中选择保留已知用量并恢复", p.Name)
			case blockQuota:
				u.warnf("%s 已达流量上限，将在下个账单周期恢复", p.Name)
			}
		}
	}
}
func (u *UI) menu0() []menuItem {
	return []menuItem{item("create", "创建节点"), item("nodes", "节点管理"), item("exits", "出口管理"), item("relay", "节点中转"), item("traffic", "流量管理"), item("doctor", "系统诊断"), item("backup", "备份与恢复"), item("settings", "设置与语言"), item("update", "更新 Rout"), item("uninstall", "卸载")}
}
func (u *UI) mainMenu() error {
	if e := u.initLanguage(false); e != nil {
		if errors.Is(e, io.EOF) {
			return nil
		}
		return e
	}
	if u.a.ServiceMode != "none" && !u.a.trafficActive() {
		if _, e := exec.LookPath("nft"); e == nil {
			if e = u.a.InstallTraffic(); e != nil {
				u.warn(u.a.Error(e))
			}
		}
	}
	u.notices()
	for {
		v := u.menu("Rout "+Version, u.menu0(), "退出")
		if u.err != nil {
			if errors.Is(u.err, io.EOF) {
				return nil
			}
			return u.err
		}
		var e error
		switch v {
		case "":
			return nil
		case "create":
			e = u.create()
		case "nodes":
			e = u.manage()
		case "exits":
			e = u.exits()
		case "relay":
			e = u.relay()
		case "traffic":
			e = u.trafficMenu()
		case "doctor":
			e = u.doctor(false)
		case "backup":
			e = u.backupMenu()
		case "settings":
			e = u.settings()
		case "update":
			e = SelfUpdate(u.a.Language)
		case "uninstall":
			if u.yes("卸载所有 Rout 节点、配置和程序（不影响其他工具）", false) {
				if e = u.a.Uninstall(); e == nil {
					return nil
				}
			}
		}
		if e != nil {
			if errors.Is(e, io.EOF) {
				return nil
			}
			u.fail(u.a.Error(e))
		}
		if u.err != nil {
			if errors.Is(u.err, io.EOF) {
				return nil
			}
			return u.err
		}
	}
}
