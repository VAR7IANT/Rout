package rout

import (
	"bufio"
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
	a   *App
	in  *bufio.Reader
	err error
}

func (u *UI) ask(prompt, def string) string {
	if u.err != nil {
		return ""
	}
	if def != "" {
		fmt.Printf("%s [%s]：", prompt, def)
	} else {
		fmt.Print(prompt + "：")
	}
	s, e := u.in.ReadString('\n')
	if e != nil {
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
	if e != nil || st.Mode()&os.ModeCharDevice == 0 {
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
	s := u.ask(prompt+"（输入隐藏）", "")
	fmt.Println()
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
		fmt.Println("请选择菜单中的编号")
	}
	return ""
}
func (u *UI) yes(prompt string, def bool) bool {
	d := "n"
	if def {
		d = "y"
	}
	s := strings.ToLower(u.choose(prompt+" y/n", []string{"y", "n"}, d))
	return s == "y"
}
func (u *UI) port(prompt string, def int) int {
	for u.err == nil {
		s := u.ask(prompt, itoa(def))
		n, e := strconv.Atoi(s)
		if e == nil && validPort(n) {
			return n
		}
		fmt.Println("端口应为 1–65535")
	}
	return 0
}
func (u *UI) endpoint(p *Profile) {
	p.NAT = u.choose("服务器类型 1.普通 VPS  2.NAT VPS", []string{"1", "2"}, "1") == "2"
	p.PublicHost = u.ask("公网连接 IP 或域名（NAT 填商家提供的地址）", DetectPublicIP())
	p.Listen = u.ask("本机监听地址", "0.0.0.0")
	port, _ := freePort()
	p.Port = u.port("本机监听端口", port)
	p.PublicPort = p.Port
	if p.NAT {
		p.PublicPort = u.port("商家已配置的公网映射端口", p.Port)
	}
}
func (u *UI) list(s State) {
	if len(s.Profiles) == 0 {
		fmt.Println("暂无节点或线路")
		return
	}
	for _, p := range s.Profiles {
		exit := "VPS 直连"
		if p.Kind == "relay" {
			exit = "转发到 " + p.Target
		} else if p.Outbound != nil {
			exit = strings.ToUpper(p.Outbound.Protocol) + " " + net.JoinHostPort(p.Outbound.Host, itoa(p.Outbound.Port))
		}
		enabled := "启用"
		if !p.Enabled {
			enabled = "停用"
		}
		fmt.Printf("%s  %s  %s  本地:%d → 公网:%d  %s  %s\n", p.ID, p.Name, p.Protocol, p.Port, p.PublicPort, enabled, exit)
	}
}
func (u *UI) pick(s State, nodeOnly bool) (Profile, error) {
	var choices []Profile
	for _, p := range s.Profiles {
		if !nodeOnly || p.Kind == "node" {
			choices = append(choices, p)
		}
	}
	if len(choices) == 0 {
		return Profile{}, errors.New("没有可选节点，请先创建节点")
	}
	for i, p := range choices {
		fmt.Printf("%d. %s（%s，%d）\n", i+1, p.Name, p.Protocol, p.PublicPort)
	}
	for u.err == nil {
		v := u.ask("选择编号（0 返回）", "")
		if v == "0" {
			return Profile{}, nil
		}
		n, e := strconv.Atoi(v)
		if e == nil && n > 0 && n <= len(choices) {
			return choices[n-1], nil
		}
		fmt.Println("编号无效")
	}
	return Profile{}, u.err
}
func (u *UI) create() error {
	old, e := u.a.Load()
	if e != nil {
		return e
	}
	fmt.Println("1.VLESS Reality  2.AnyTLS Reality  3.Shadowsocks  4.Hysteria2  5.TUIC")
	protocols := map[string]string{"1": "vless", "2": "anytls", "3": "ss", "4": "hy2", "5": "tuic"}
	var selected []string
	for u.err == nil {
		parts := strings.Fields(u.ask("选择协议，可多选，如 1 2", "1"))
		ok := len(parts) > 0
		seen := map[string]bool{}
		selected = nil
		for _, v := range parts {
			protocol, yes := protocols[v]
			if !yes || seen[v] {
				ok = false
				break
			}
			seen[v] = true
			selected = append(selected, protocol)
		}
		if ok {
			break
		}
		fmt.Println("协议编号无效或重复")
	}
	next := old
	for _, protocol := range selected {
		p, e := NewProfile(protocol)
		if e != nil {
			return e
		}
		fmt.Println("\n配置 " + protocol)
		p.Name = u.ask("节点名称", protocol)
		u.endpoint(&p)
		if protocol == "vless" || protocol == "anytls" {
			p.SNI = u.ask("Reality SNI", p.SNI)
		}
		if protocol == "hy2" || protocol == "tuic" {
			if !u.yes("已确认该端口允许 UDP（NAT 需有 UDP 映射）", false) {
				return errors.New("需要可用的 UDP 端口")
			}
			p.SNI = u.ask("证书对应域名", "")
			cert := u.ask("现有 PEM 证书文件路径", "")
			key := u.ask("PEM 私钥文件路径", "")
			if u.err != nil {
				return u.err
			}
			b, e := os.ReadFile(cert)
			if e != nil {
				return errors.New("无法读取证书")
			}
			p.CertPEM = string(b)
			b, e = os.ReadFile(key)
			if e != nil {
				return errors.New("无法读取私钥")
			}
			p.KeyPEM = string(b)
		}
		if !u.yes("自动生成认证凭据", true) {
			if protocol == "vless" || protocol == "tuic" {
				p.UUID = u.ask("UUID", "")
			}
			if protocol != "vless" {
				p.Password = u.secret("密码（SS2022 使用 16 字节 Base64 密钥）")
			}
		}
		if u.err != nil {
			return u.err
		}
		if e = p.Validate(); e != nil {
			return e
		}
		next = replace(next, p)
	}
	if u.err != nil {
		return u.err
	}
	if e = u.a.Commit(old, next, false); e != nil {
		return e
	}
	fmt.Println("节点创建成功，默认使用 VPS 直连出口")
	for _, p := range next.Profiles {
		if _, e := Find(old, p.ID); e != nil {
			uri, _ := p.URI()
			fmt.Println(p.ID + " " + uri)
			if p.Protocol == "hy2" || p.Protocol == "tuic" {
				fmt.Println("自签或私有 CA 证书请使用导出的 sing-box 客户端配置，其中包含信任证书")
			}
		}
	}
	return nil
}
func (u *UI) relay() error {
	old, e := u.a.Load()
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
	p := Profile{ID: RandomHex(6), Name: "中转线路", Kind: "relay", Enabled: true, Target: target, Protocol: network}
	if strings.Contains(raw, "://") {
		p.TargetURI = raw
		if network == "both" {
			v := u.choose("SS 转发网络 1.TCP  2.TCP＋UDP  3.UDP", []string{"1", "2", "3"}, "1")
			p.Protocol = map[string]string{"1": "tcp", "2": "both", "3": "udp"}[v]
		}
	} else {
		fmt.Println("1.TCP  2.UDP  3.TCP＋UDP")
		v := u.choose("转发网络", []string{"1", "2", "3"}, "1")
		p.Protocol = map[string]string{"1": "tcp", "2": "udp", "3": "both"}[v]
	}
	p.Name = u.ask("线路名称", p.Name)
	u.endpoint(&p)
	if p.Protocol != "tcp" && !u.yes("已确认本地、公网映射和目标均允许 UDP", false) {
		return errors.New("需要 UDP 通路")
	}
	if u.err != nil {
		return u.err
	}
	if e = u.a.Commit(old, replace(old, p), false); e != nil {
		return e
	}
	fmt.Println("中转线路已创建")
	if uri, e := p.URI(); e == nil {
		fmt.Println(uri)
	} else {
		fmt.Printf("将原客户端连接地址改为 %s，端口改为 %d，保留原 SNI 等参数\n", p.PublicHost, p.PublicPort)
	}
	return nil
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
	fmt.Println("1.SOCKS5  2.HTTP  3.恢复 VPS 直连")
	choice := u.choose("选择出口代理协议", []string{"1", "2", "3"}, "1")
	if u.err != nil {
		return u.err
	}
	if choice == "3" {
		p.Outbound = nil
		return u.a.Commit(old, replace(old, p), false)
	}
	protocol := map[string]string{"1": "socks5", "2": "http"}[choice]
	for u.err == nil {
		raw := u.secret("输入代理 IP:端口:用户名:密码（IPv6 使用 [地址]:端口:用户名:密码）")
		if u.err != nil {
			return u.err
		}
		proxy, e := ParseProxy(protocol, raw)
		if e != nil {
			fmt.Println(e)
			continue
		}
		fmt.Println("正在检测认证和实际出口…")
		ip, e := u.a.ProbeProxy(*proxy)
		if e != nil {
			fmt.Println(e)
			if u.yes("重新输入", true) {
				continue
			}
			return nil
		}
		fmt.Println("检测到的出口 IPv4：", ip)
		fmt.Println("该代理出口仅启用 TCP，UDP 请求会被拒绝")
		if !u.yes("使用该代理出口", true) {
			return nil
		}
		p.Outbound = proxy
		if e = u.a.Commit(old, replace(old, p), false); e != nil {
			return e
		}
		fmt.Println("已绑定出口；客户端节点链接保持不变，服务器自身流量保持原出口")
		return nil
	}
	return u.err
}
func (u *UI) export(p Profile) error {
	uri, e := p.URI()
	if e != nil {
		return e
	}
	fmt.Println(uri)
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
	fmt.Println("已保存：", path)
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
	fmt.Println("1.修改名称  2.修改端口／公网地址  3.修改出口  4.启用／停用  5.查看日志  6.删除  7.导出链接  8.检测线路  9.重置认证凭据  10.更新证书  0.返回")
	choice := u.choose("选择操作", []string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10"}, "0")
	if u.err != nil {
		return u.err
	}
	switch choice {
	case "0":
		return nil
	case "1":
		p.Name = u.ask("节点名称", p.Name)
	case "2":
		p.PublicHost = u.ask("公网连接地址", p.PublicHost)
		p.Port = u.port("本地端口", p.Port)
		p.PublicPort = u.port("公网端口", p.PublicPort)
	case "3":
		if p.Kind != "node" {
			return errors.New("原样转发线路请在落地节点配置出口")
		}
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
		p.SNI = u.ask("证书对应域名", p.SNI)
		cert := u.ask("新 PEM 证书路径", "")
		key := u.ask("新 PEM 私钥路径", "")
		if u.err != nil {
			return u.err
		}
		b, e := os.ReadFile(cert)
		if e != nil {
			return errors.New("无法读取证书")
		}
		p.CertPEM = string(b)
		b, e = os.ReadFile(key)
		if e != nil {
			return errors.New("无法读取私钥")
		}
		p.KeyPEM = string(b)
	}
	if u.err != nil {
		return u.err
	}
	return u.a.Commit(s, replace(s, p), false)
}
func (u *UI) menu() error {
	for {
		fmt.Println("\nRout " + Version + "  节点与中转管理\n1.创建节点\n2.节点中转\n3.代理出口\n4.管理节点与线路\n5.检测连接与出口 IP\n6.备份与恢复\n7.更新\n8.卸载\n0.退出")
		choice := u.choose("选择", []string{"0", "1", "2", "3", "4", "5", "6", "7", "8"}, "0")
		if u.err != nil {
			if errors.Is(u.err, io.EOF) {
				return nil
			}
			return u.err
		}
		var e error
		switch choice {
		case "0":
			return nil
		case "1":
			e = u.create()
		case "2":
			e = u.relay()
		case "3":
			e = u.bind()
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
					fmt.Println("备份已保存（含认证信息和私钥，请妥善保管）：", path)
				}
			} else if u.yes("使用备份替换当前配置", false) {
				e = u.a.Restore(path)
			}
		case "7":
			e = SelfUpdate()
		case "8":
			if !u.yes("卸载所有 Rout 节点、配置和程序（不影响其他工具）", false) {
				continue
			}
			e = u.a.Uninstall()
			if e == nil {
				return nil
			}
		}
		if e != nil {
			if errors.Is(e, io.EOF) {
				return nil
			}
			fmt.Println("错误：", e)
		}
		if u.err != nil {
			if errors.Is(u.err, io.EOF) {
				return nil
			}
			return u.err
		}
	}
}
