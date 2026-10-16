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
)

type UI struct {
	a          *App
	in         *bufio.Reader
	out        io.Writer
	err        error
	detectIP   func() string
	probeProxy func(Proxy) (string, error)
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
func (u *UI) serverSetup() (ServerSetup, error) {
	saved, e := u.a.LoadSettings()
	if e != nil {
		return ServerSetup{}, e
	}
	s := ServerSetup{Listen: "0.0.0.0", Network: "both"}
	if saved.Server != nil {
		s = *saved.Server
	}
	def := "1"
	if s.NAT {
		def = "2"
	}
	s.NAT = u.choose("服务器类型 1.普通 VPS  2.NAT VPS", []string{"1", "2"}, def) == "2"
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
	s.Listen = u.ask("本机监听地址（默认监听所有网卡）", s.Listen)
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
		def = "1"
		if s.Network == "tcp" {
			def = "2"
		} else if s.Network == "udp" {
			def = "3"
		}
		v := u.choose("商家允许的网络 1.TCP＋UDP  2.仅 TCP  3.仅 UDP", []string{"1", "2", "3"}, def)
		s.Network = map[string]string{"1": "both", "2": "tcp", "3": "udp"}[v]
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
func (u *UI) list(s State) {
	if len(s.Profiles) == 0 {
		u.say("暂无节点或线路")
		return
	}
	for i, p := range s.Profiles {
		u.printf("\n%d. %s [%s]\n", i+1, p.Name, p.ID)
		enabled := u.a.T("启用")
		if !p.Enabled {
			enabled = u.a.T("停用")
		}
		u.printf("协议：%s | 状态：%s / %s | 本地：%d | 公网：%s:%d | 出口：%s\n", ProtocolLabel(p.Protocol), enabled, u.a.Running(p), p.Port, p.PublicHost, p.PublicPort, u.exitLabel(s, p))
		if uri, e := p.URI(); e == nil {
			fmt.Fprintln(u.writer(), uri)
		} else {
			u.say("手动端口转发：使用原客户端的协议和认证信息")
		}
	}
}
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
	u.list(choices)
	for u.err == nil {
		v := u.ask("选择编号（0 返回）", "0")
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
func (u *UI) pickExit(s State) (string, error) {
	u.say("0.VPS 直连")
	for i, e := range s.Exits {
		u.printf("%d. %s [%s] %s %s:%d\n", i+1, e.Name, e.ID, strings.ToUpper(e.Proxy.Protocol), e.Proxy.Host, e.Proxy.Port)
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
func (u *UI) create() error {
	old, e := u.a.Load()
	if e != nil {
		return e
	}
	setup, e := u.serverSetup()
	if e != nil {
		return e
	}
	base := u.ask("基础节点名称（仅填写一次）", "Rout")
	u.say("1.VLESS Reality  2.AnyTLS Reality  3.Shadowsocks  4.Hysteria2  5.TUIC")
	protocols := map[string]string{"1": "vless", "2": "anytls", "3": "ss", "4": "hy2", "5": "tuic"}
	var selected []string
	for u.err == nil {
		parts := strings.Fields(u.ask("选择协议，可多选，如 1 2", "1"))
		ok := len(parts) > 0
		seen := map[string]bool{}
		selected = nil
		for _, v := range parts {
			p, yes := protocols[v]
			if !yes || seen[v] {
				ok = false
				break
			}
			seen[v] = true
			selected = append(selected, p)
		}
		if ok {
			break
		}
		u.say("协议编号无效或重复")
	}
	if u.err != nil {
		return u.err
	}
	manual := u.yes("手动指定各协议端口", false)
	autoCredentials := u.yes("自动生成认证凭据", true)
	realitySNI := "addons.mozilla.org"
	if contains(selected, "vless") || contains(selected, "anytls") {
		realitySNI = u.ask("Reality SNI（所选协议共用）", realitySNI)
	}
	cert, key, tlsSNI := "", "", setup.PublicHost
	generated := false
	if contains(selected, "hy2") || contains(selected, "tuic") {
		choice := u.choose("TLS 配置 1.自动生成自签证书  2.使用现有 PEM 证书", []string{"1", "2"}, "1")
		tlsSNI = u.ask("TLS 证书域名或 IP", tlsSNI)
		if choice == "1" {
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
		p.Name = base + "-" + ProtocolLabel(protocol)
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
	u.say("节点创建成功")
	for _, id := range created {
		p, _ := Find(next, id)
		uri, er := p.URI()
		if er != nil {
			return er
		}
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
	p := Profile{ID: RandomHex(6), Name: u.ask("线路名称", "Relay"), Kind: "relay", Enabled: true, Target: target, Protocol: network}
	if strings.Contains(raw, "://") {
		p.TargetURI = raw
	}
	if !strings.Contains(raw, "://") || network == "both" {
		v := u.choose("转发网络 1.TCP  2.UDP  3.TCP＋UDP", []string{"1", "2", "3"}, "1")
		p.Protocol = map[string]string{"1": "tcp", "2": "udp", "3": "both"}[v]
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
	u.say("中转线路已创建")
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
	id, e := u.pickExit(old)
	if e != nil {
		return e
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
		u.printf("实际出口 IPv4：%s\n", ip)
	}
	next, e := BindExit(old, p.ID, id)
	if e != nil {
		return e
	}
	return u.a.Commit(old, next, false)
}
func (u *UI) proxyInput() (Proxy, error) {
	protocol := u.choose("出口协议 1.SOCKS5  2.HTTP", []string{"1", "2"}, "1")
	for u.err == nil {
		raw := u.secret("输入代理 IP:端口:用户名:密码（IPv6 使用 [地址]:端口:用户名:密码）")
		if u.err != nil {
			return Proxy{}, u.err
		}
		p, e := ParseProxy(map[string]string{"1": "socks5", "2": "http"}[protocol], raw)
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
func (u *UI) exits() error {
	s, e := u.a.Load()
	if e != nil {
		return e
	}
	u.say("出口列表（认证信息已隐藏）")
	for _, ex := range s.Exits {
		count := 0
		for _, p := range s.Profiles {
			if p.ExitID == ex.ID {
				count++
			}
		}
		u.printf("%s  %s  %s %s:%d  绑定节点：%d\n", ex.ID, ex.Name, strings.ToUpper(ex.Proxy.Protocol), ex.Proxy.Host, ex.Proxy.Port, count)
	}
	v := u.choose("1.添加出口  2.测试出口  3.修改出口  4.删除出口  5.绑定或解除节点出口  0.返回", []string{"0", "1", "2", "3", "4", "5"}, "0")
	if u.err != nil {
		return u.err
	}
	if v == "0" {
		return nil
	}
	if v == "5" {
		return u.bind()
	}
	if v == "1" {
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
		u.say("出口已保存，可测试后绑定到多个节点；未改变任何节点出口")
		return nil
	}
	id := u.ask("出口 ID", "")
	ex, e := FindExit(s, id)
	if e != nil {
		return e
	}
	switch v {
	case "2":
		ip, e := u.testExit(ex.Proxy)
		if e != nil {
			return e
		}
		u.printf("实际出口 IPv4：%s\n", ip)
		return nil
	case "3":
		ex.Name = u.ask("出口名称", ex.Name)
		previousProxy := ex.Proxy
		if u.yes("修改代理地址或认证信息", false) {
			ex.Proxy, e = u.proxyInput()
			if e != nil {
				return e
			}
		}
		if u.err != nil {
			return u.err
		}
		if ex.Proxy != previousProxy {
			for _, p := range s.Profiles {
				if p.ExitID == ex.ID {
					if _, e := u.testExit(ex.Proxy); e != nil {
						return e
					}
					break
				}
			}
		}
		if !u.yes("更新出口（仅重启使用该出口的节点）", false) {
			return nil
		}
		return u.a.Commit(s, UpsertExit(s, ex), false)
	case "4":
		next, e := DeleteExit(s, id)
		if e != nil {
			return e
		}
		if !u.yes("删除该出口", false) {
			return nil
		}
		return u.a.Commit(s, next, false)
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
func (u *UI) export(p Profile) error {
	if e := u.copy(p); e != nil {
		return e
	}
	if !u.yes("同时导出 sing-box 客户端配置", false) {
		return u.err
	}
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
func (u *UI) manage() error {
	s, e := u.a.Load()
	if e != nil {
		return e
	}
	p, e := u.pick(s, false)
	if e != nil || p.ID == "" {
		return e
	}
	v := u.choose("1.修改名称  2.修改端口或地址  3.选择出口  4.启用或停用  5.日志  6.删除  7.复制或导出链接  8.测试  9.重置凭据  10.更新证书  11.重启  0.返回", []string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11"}, "0")
	if u.err != nil {
		return u.err
	}
	switch v {
	case "0":
		return nil
	case "1":
		p.Name = u.ask("节点名称", p.Name)
	case "2":
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
	case "3":
		return u.bindProfile(s, p)
	case "4":
		p.Enabled = !p.Enabled
	case "5":
		return u.a.Logs(p)
	case "6":
		if !u.yes("删除该节点及其服务", false) {
			return nil
		}
		return u.a.Commit(s, removeProfile(s, p.ID), false)
	case "7":
		return u.export(p)
	case "8":
		return u.a.Probe(p)
	case "9":
		if p.Kind != "node" {
			return errors.New("转发线路的认证由落地节点管理")
		}
		if !u.yes("重置后需要重新导入客户端链接", false) {
			return nil
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
	case "10":
		if p.Kind != "node" || (p.Protocol != "hy2" && p.Protocol != "tuic") {
			return errors.New("该节点未使用文件证书")
		}
		p.SNI = u.ask("TLS 证书域名或 IP", p.SNI)
		p.CertPEM, p.KeyPEM, e = u.readCertificate()
		if e != nil {
			return e
		}
		p.TLSGenerated = false
	case "11":
		return u.a.Restart(p.ID)
	}
	if u.err != nil {
		return u.err
	}
	return u.a.Commit(s, replace(s, p), false)
}
func (u *UI) settings() error {
	v := u.choose("1.切换语言  2.配置服务器默认值  0.返回", []string{"0", "1", "2"}, "0")
	if v == "1" {
		return u.initLanguage(true)
	}
	if v == "2" {
		s, e := u.serverSetup()
		if e != nil {
			return e
		}
		return u.saveServer(s)
	}
	return u.err
}
func (u *UI) menu() error {
	if e := u.initLanguage(false); e != nil {
		if errors.Is(e, io.EOF) {
			return nil
		}
		return e
	}
	for {
		u.printf("\nRout %s\n1.创建节点\n2.节点中转\n3.出口管理\n4.节点管理\n5.检测线路\n6.备份与恢复\n7.更新\n8.卸载\n9.设置与语言\n0.退出\n", Version)
		v := u.choose("选择", []string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9"}, "0")
		if u.err != nil {
			if errors.Is(u.err, io.EOF) {
				return nil
			}
			return u.err
		}
		var e error
		switch v {
		case "0":
			return nil
		case "1":
			e = u.create()
		case "2":
			e = u.relay()
		case "3":
			e = u.exits()
		case "4":
			e = u.manage()
		case "5":
			var s State
			s, e = u.a.Load()
			if e == nil {
				var p Profile
				p, e = u.pick(s, false)
				if e == nil && p.ID != "" {
					e = u.a.Probe(p)
				}
			}
		case "6":
			v := u.choose("1.备份  2.恢复", []string{"1", "2"}, "1")
			path := u.ask("备份文件路径", filepath.Join(u.a.Home, "rout-backup.json"))
			if u.err != nil {
				return u.err
			}
			if v == "1" {
				e = u.a.Backup(path)
				if e == nil {
					u.say("备份已保存（包含认证信息和私钥，请妥善保管）")
				}
			} else if u.yes("使用备份替换当前配置", false) {
				e = u.a.Restore(path)
			}
		case "7":
			e = SelfUpdate(u.a.Language)
		case "8":
			if u.yes("卸载所有 Rout 节点、配置和程序（不影响其他工具）", false) {
				e = u.a.Uninstall()
				if e == nil {
					return nil
				}
			}
		case "9":
			e = u.settings()
		}
		if e != nil {
			if errors.Is(e, io.EOF) {
				return nil
			}
			u.printf("错误：%s\n", u.a.Error(e))
		}
		if u.err != nil {
			if errors.Is(u.err, io.EOF) {
				return nil
			}
			return u.err
		}
	}
}
