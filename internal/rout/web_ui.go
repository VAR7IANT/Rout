package rout

import (
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"
	"time"
)

// Main menu 8: Web management panel. Every operation returns to this page; nothing here
// exits Rout. All work is done by the App methods in web_service.go and web_https.go, so the
// commands (`rout web ...`) and the menu behave identically.

// webControl starts, stops, restarts or installs the service (replaceable in tests).
func (u *UI) webControl(action string) error {
	if u.webService != nil {
		return u.webService(action)
	}
	if action == "install" {
		return u.a.InstallWebService()
	}
	if action == "uninstall" {
		return u.a.RemoveWebService()
	}
	return u.a.controlWeb(action)
}

// webAccess is how the panel is reached right now.
func (u *UI) webAccess(st WebStatus) string {
	if st.HTTPSDomain != "" {
		return "https://" + st.HTTPSDomain
	}
	return fmt.Sprintf("ssh -L %d:127.0.0.1:%d user@server\nhttp://127.0.0.1:%d/", st.Port, st.Port, st.Port)
}

func (u *UI) webStatusLines(st WebStatus) {
	yn := func(b bool, yes, no string) string {
		if b {
			return u.paint(colorOK, u.a.T(yes))
		}
		return u.paint(colorWarn, u.a.T(no))
	}
	type row struct{ label, value string }
	rows := []row{{"面板服务", yn(st.Installed, "已安装", "未安装")}}
	if st.Installed {
		rows = append(rows, row{"运行状态", yn(st.Running, "运行中", "未运行")})
	}
	rows = append(rows, row{"管理密码", yn(st.PasswordSet, "已设置", "未设置")}, row{"本机监听", "127.0.0.1:" + itoa(st.Port)})
	if hs, e := u.a.loadWebHTTPSState(); e == nil && hs.Pending && !hs.Removed {
		rows = append(rows, row{"HTTPS", u.paint(colorWarn, u.a.T("已配置，证书待验证"))})
	}
	rows = append(rows, row{"访问方式", u.webAccess(st)})
	u.kvRows(func(add func(string, string)) {
		for _, r := range rows {
			add(r.label, r.value)
		}
	})
}

// kvRows prints aligned "label  value" rows; on a narrow terminal a long value moves to
// its own indented line instead of wrapping mid-word.
func (u *UI) kvRows(fill func(add func(label, value string))) {
	var labels, values []string
	fill(func(l, v string) { labels, values = append(labels, u.a.T(l)), append(values, v) })
	w := 0
	for _, l := range labels {
		if n := displayWidth(l); n > w {
			w = n
		}
	}
	for i, l := range labels {
		if strings.Contains(values[i], "\n") {
			fmt.Fprintf(u.writer(), "  %s\n", l)
			for _, line := range strings.Split(values[i], "\n") {
				fmt.Fprintf(u.writer(), "      %s\n", line)
			}
			continue
		}
		if 2+w+2+displayWidth(values[i]) > u.width()-1 && w+4 < u.width() {
			fmt.Fprintf(u.writer(), "  %s\n      %s\n", l, values[i])
			continue
		}
		fmt.Fprintf(u.writer(), "  %s  %s\n", pad(l, w), values[i])
	}
}

func (u *UI) webMenu() error {
	defer u.enter("Web 管理面板")()
	for {
		st, e := u.a.WebStatus()
		if e != nil {
			return e
		}
		u.heading("Web 管理面板")
		u.webStatusLines(st)
		v := u.menu("", []menuItem{
			itemNote("setup", "一键安装／初始化面板", "部署服务、设置密码、配置域名与 HTTPS；可重复执行"),
			item("control", "开启／停止／重新启动"),
			item("status", "查看面板状态与访问网址"),
			item("domain", "设置／更换管理域名"),
			item("password", "设置／重设管理密码"),
			item("https", "HTTPS 部署与修复"),
			item("diagnose", "查看日志／诊断"),
			item("uninstall", "卸载面板"),
		}, "返回")
		if u.err != nil || v == "" {
			return u.err
		}
		switch v {
		case "setup":
			e = u.webSetup()
		case "control":
			e = u.webControlMenu(st)
		case "status":
			e = u.webShowStatus()
		case "domain":
			e = u.webDomainFlow("")
		case "password":
			e = u.webPasswordFlow(st.PasswordSet)
		case "https":
			e = u.webHTTPSMenu()
		case "diagnose":
			e = u.webDiagnose(true)
		case "uninstall":
			e = u.webUninstall()
		}
		if e != nil {
			if errors.Is(e, errQuit) || errors.Is(e, io.EOF) {
				return e
			}
			if !errors.Is(e, errCancelled) {
				u.fail(u.a.Error(e))
			}
		}
		if u.err != nil {
			return u.err
		}
	}
}

func (u *UI) webControlMenu(st WebStatus) error {
	if !st.Installed {
		return errors.New("管理面板尚未安装，请先选择“一键安装／初始化面板”")
	}
	v := u.option("面板服务", []menuItem{item("start", "启动"), item("stop", "停止"), item("restart", "重新启动")}, "restart")
	if u.err != nil || v == "" {
		return u.err
	}
	if v == "stop" && !u.yes("停止面板服务（节点、中转和订阅不受影响）", true) {
		return u.err
	}
	if e := u.webControl(v); e != nil {
		return e
	}
	u.good("已完成")
	return nil
}

// webSetup is the one-click wizard. Each step reports what it proved; it can be repeated
// safely, and a failure in one step never undoes a previous working step.
func (u *UI) webSetup() error {
	a := u.a
	u.heading("一键安装／初始化面板")
	// 1. Environment
	m, e := a.serviceManager()
	if e != nil {
		return e
	}
	osName := readOSID()
	if osName == "" {
		osName = runtime.GOOS
	}
	u.segments("  ", fmt.Sprintf("%s %s", u.a.T("系统"), osName), fmt.Sprintf("%s %s", u.a.T("架构"), runtime.GOARCH), fmt.Sprintf("%s %s", u.a.T("初始化系统"), m))
	if m == "none" && u.webService == nil {
		return errors.New("当前环境没有受管理的服务（需要 systemd 或 OpenRC）")
	}
	n := a.panelNetwork()
	u.webNetworkLines(n)
	// 2. Password: generated and shown exactly once, or typed twice and never echoed.
	cfg, e := a.LoadWebConfig()
	if e != nil {
		return e
	}
	if cfg.PasswordHash == "" {
		if e = u.webPasswordFlow(false); e != nil {
			return e
		}
	} else {
		u.good("管理密码已设置（保持不变；可在“设置／重设管理密码”中更改）")
	}
	// 3. Service on loopback.
	u.say("正在部署 Rout Web 服务…")
	if e = u.webControl("install"); e != nil {
		return e
	}
	cfg, _ = a.LoadWebConfig()
	if v := a.httpsRuntime().panelVerify("", cfg.port()); !v.LocalService {
		return fmt.Errorf("管理面板未能在 127.0.0.1:%d 保持运行", cfg.port())
	}
	u.good("Rout Web 服务正常（仅监听 127.0.0.1）")
	// 4. Domain and HTTPS (optional).
	domain := cfg.HTTPSDomain
	def := domain
	raw := normalizeInput(u.ask("管理域名（例如 panel.example.com；留空则只通过 SSH 隧道访问）", def))
	if u.err != nil {
		return u.err
	}
	if raw == "" || raw == "0" {
		u.webTunnelHint(cfg.port())
		return nil
	}
	return u.webDomainFlow(raw)
}

func (u *UI) webNetworkLines(n PanelNetwork) {
	switch {
	case n.IPv6Only:
		u.good(fmt.Sprintf(u.a.T("纯 IPv6 网络：%s（不依赖公网 IPv4）"), n.IPv6))
	case n.IPv4 != "" && n.IPv6 != "":
		u.good(fmt.Sprintf(u.a.T("双栈网络：IPv4 %s · IPv6 %s"), n.IPv4, n.IPv6))
	case n.IPv4 != "":
		u.good(fmt.Sprintf(u.a.T("IPv4 网络：%s（未检测到公网 IPv6）"), n.IPv4))
	default:
		u.warn("未能检测到本机公网地址")
	}
	if n.IPv4NAT {
		u.warn("公网 IPv4 由 NAT 映射：需要服务商把公网 TCP 80/443 转发到本机")
	}
}

func (u *UI) webTunnelHint(port int) {
	u.say("未设置域名。可通过 SSH 隧道访问面板：")
	fmt.Fprintf(u.writer(), "  ssh -L %d:127.0.0.1:%d user@server\n  http://127.0.0.1:%d/\n", port, port, port)
}

// webDomainFlow validates the domain (offering an independent sub-domain when the name
// belongs to the subscription site), then deploys HTTPS.
func (u *UI) webDomainFlow(domain string) error {
	a := u.a
	if domain == "" {
		cfg, _ := a.LoadWebConfig()
		domain = normalizeInput(u.ask("管理域名（例如 panel.example.com）", cfg.HTTPSDomain))
		if u.err != nil {
			return u.err
		}
		if domain == "" || domain == "0" {
			return errCancelled
		}
	}
	for {
		d, e := subscriptionDomain(domain)
		if e != nil {
			return e
		}
		var used *DomainInUseError
		if er := a.checkPanelDomain(d); errors.As(er, &used) {
			u.warn(fmt.Sprintf(u.a.T("检测到 %s 已被 Rout 订阅服务使用。"), d))
			u.printf("建议面板域名：%s\n", used.Suggestion)
			v := u.menu("", []menuItem{item("suggest", "使用建议域名"), item("other", "输入其他域名")}, "返回")
			if u.err != nil {
				return u.err
			}
			switch v {
			case "suggest":
				domain = used.Suggestion
				continue
			case "other":
				domain = normalizeInput(u.ask("管理域名", ""))
				if u.err != nil {
					return u.err
				}
				if domain == "" {
					return errCancelled
				}
				continue
			}
			return errCancelled
		}
		return u.webDeploy(d)
	}
}

// webDeploy runs the HTTPS deployment, asking for each consent it needs.
func (u *UI) webDeploy(domain string) error {
	a := u.a
	if e := a.requireHTTPSManagement(); e != nil {
		u.warn(a.Error(e))
		u.say("此系统不支持自动部署 Caddy。请把下面的站点加入你自己的反向代理，然后运行 rout web host add 域名：")
		cfg, _ := a.LoadWebConfig()
		fmt.Fprint(u.writer(), "\n"+caddySnippet(domain, cfg.port())+"\n")
		return nil
	}
	r := a.httpsRuntime()
	opts := WebHTTPSOptions{}
	if !r.installed() {
		u.say("未检测到 Caddy。Caddy 用于自动申请和续期 HTTPS 证书。")
		if !u.yes("从系统软件源安装 Caddy", false) {
			if u.err != nil {
				return u.err
			}
			return errCancelled
		}
		opts.AllowInstall = true
	} else if !r.running() {
		u.warn("Caddy 已安装但未运行；启动它也会启用其 Caddyfile 中的所有站点")
		if !u.yes("启动 Caddy", false) {
			if u.err != nil {
				return u.err
			}
			return errCancelled
		}
		opts.AllowStart = true
	} else {
		u.good("已检测到正在运行的 Caddy：只会新增 Rout 自己的面板站点，不改动其他站点")
	}
	for attempt := 0; attempt < 2; attempt++ {
		u.printf("正在部署 HTTPS（%s）；证书签发最多等待约 %d 秒…\n", domain, int(r.verificationWait/time.Second))
		res, e := a.DeployWebHTTPS(domain, opts)
		var dnsErr *DNSPendingError
		var natErr *NATConfirmError
		switch {
		case e == nil:
			u.webSuccess(res)
			return nil
		case errors.As(e, &natErr):
			u.warn(a.T(natErr.Detail))
			if attempt == 0 && u.yes("我已确认公网 TCP 80 和 443 会转发到本机，继续部署", false) {
				opts.AcceptNAT = true
				continue
			}
			if u.err != nil {
				return u.err
			}
			return errCancelled
		case errors.As(e, &dnsErr):
			u.fail(a.Error(e))
			u.say("请在 DNS 服务商处添加以下记录（Cloudflare 请使用“仅 DNS”）：")
			for _, line := range dnsErr.Records {
				fmt.Fprintln(u.writer(), "  "+a.T(line))
			}
			u.say("DNS 生效前不会申请证书，也没有修改任何配置。生效后选择“HTTPS 部署与修复”或运行 rout web https repair")
			return nil
		case errors.Is(e, ErrPanelHTTPSPending):
			u.warn(a.Error(e))
			u.say("配置已保存并保持生效，Caddy 会继续自动重试签发；现有站点和面板服务不受影响")
			return u.webDiagnose(false)
		default:
			return e
		}
	}
	return nil
}

func (u *UI) webSuccess(res WebHTTPSResult) {
	v := res.Verification
	u.good("Rout Web 安装成功")
	u.good("Web 服务正常")
	n := u.a.panelNetwork()
	if n.IPv6 != "" {
		u.good("IPv6 网络正常")
	}
	u.good("DNS 验证通过")
	if v.LocalTLS || v.PublicFromHost {
		u.good("HTTPS 证书有效")
	}
	u.good("反向代理正常")
	if v.LoginPage {
		u.good("登录页面可存取")
	}
	fmt.Fprintf(u.writer(), "\n%s\n  %s\n%s %s\n", u.a.T("管理面板："), u.bold("https://"+res.Domain), u.a.T("状态："), u.paint(colorOK, u.a.T("运行中")))
}

func (u *UI) webShowStatus() error {
	st, e := u.a.WebStatus()
	if e != nil {
		return e
	}
	u.heading("查看面板状态与访问网址")
	u.webStatusLines(st)
	if len(st.Hosts) > 0 {
		u.kvRows(func(add func(string, string)) { add("允许的访问域名", strings.Join(st.Hosts, ", ")) })
	}
	return nil
}

// webPasswordFlow sets the admin password: generated (shown exactly once) or typed twice.
// The password is never logged and never printed again.
func (u *UI) webPasswordFlow(exists bool) error {
	if exists && !u.yes("重设管理密码（所有已登录的会话都会失效）", false) {
		if u.err != nil {
			return u.err
		}
		return errCancelled
	}
	v := u.option("管理密码", []menuItem{
		itemNote("generate", "自动生成安全密码", "只显示这一次，请立即保存到密码管理器"),
		itemNote("type", "自己输入", "至少 12 个字符，输入时不显示"),
	}, "generate")
	if u.err != nil {
		return u.err
	}
	var pw string
	if v == "generate" {
		pw = GenerateWebPassword()
	} else {
		pw = u.secret("新的管理密码")
		if u.err != nil {
			return u.err
		}
		if u.secret("再次输入新的管理密码") != pw {
			return errors.New("两次输入的密码不一致")
		}
	}
	if e := u.a.SetWebPassword(pw); e != nil {
		return e
	}
	if v == "generate" {
		fmt.Fprintf(u.writer(), "%s: %s\n", u.a.T("新的管理密码（只显示这一次）"), pw)
	}
	u.good("管理密码已更新；已登录的会话将失效")
	return nil
}

func (u *UI) webHTTPSMenu() error {
	hs, e := u.a.loadWebHTTPSState()
	if e != nil {
		return e
	}
	cfg, e := u.a.LoadWebConfig()
	if e != nil {
		return e
	}
	domain := cfg.HTTPSDomain
	if domain == "" && !hs.Removed {
		domain = hs.Domain
	}
	items := []menuItem{item("repair", "部署或修复 HTTPS"), item("diagnose", "HTTPS 诊断"), item("snippet", "显示 Caddy 配置片段（手动部署）")}
	if hs.Ownership == "managed" && !hs.Removed {
		items = append(items, item("remove", "移除面板 HTTPS 站点"))
	}
	v := u.menu("HTTPS 部署与修复", items, "返回")
	if u.err != nil || v == "" {
		return u.err
	}
	switch v {
	case "repair":
		if domain == "" {
			return u.webDomainFlow("")
		}
		return u.webDeploy(domain)
	case "diagnose":
		return u.webDiagnose(false)
	case "snippet":
		if domain == "" {
			return errors.New("尚未设置管理域名")
		}
		fmt.Fprint(u.writer(), "\n"+caddySnippet(domain, cfg.port())+"\n")
		return nil
	case "remove":
		if !u.yes("移除面板的 HTTPS 站点（证书、订阅站点和其他站点保持不变；之后只能通过 SSH 隧道访问）", false) {
			return u.err
		}
		if e = u.a.RemoveWebHTTPS(); e != nil {
			return e
		}
		u.good("面板 HTTPS 站点已移除")
	}
	return nil
}

// webDiagnose prints the layered HTTPS diagnosis and, optionally, the service log.
func (u *UI) webDiagnose(logs bool) error {
	u.heading("面板诊断")
	rep, e := u.a.WebHTTPSDiagnostics()
	if e != nil {
		return e
	}
	for _, c := range rep.Checks {
		switch c.Level {
		case "ok":
			u.good(c.Text)
		case "warn":
			u.warn(c.Text)
		case "fail":
			u.fail(c.Text)
		default:
			fmt.Fprintln(u.writer(), u.dim("· "+c.Text))
		}
	}
	if rep.LastError != "" && rep.Pending {
		u.warn(u.a.T("上次部署：") + rep.LastError)
	}
	if rep.Domain != "" && !rep.Verification.ok() {
		u.say("需要的 DNS 记录：")
		for _, line := range rep.Records {
			fmt.Fprintln(u.writer(), "  "+u.a.T(line))
		}
	}
	if !logs {
		return nil
	}
	st, e := u.a.Load()
	if e != nil {
		return e
	}
	if text, er := u.a.serviceLog(st, "web", 40); er == nil && strings.TrimSpace(text) != "" {
		u.heading("面板服务日志（最近 40 行）")
		fmt.Fprintln(u.writer(), text)
	}
	return nil
}

func (u *UI) webUninstall() error {
	if !u.confirmWord("卸载面板服务（节点、中转、订阅和密码设置都会保留）。输入 UNINSTALL 确认", "UNINSTALL") {
		if u.err != nil {
			return u.err
		}
		return errCancelled
	}
	if hs, e := u.a.loadWebHTTPSState(); e == nil && hs.Ownership == "managed" && !hs.Removed {
		if u.yes("同时移除面板的 HTTPS 站点（证书与其他站点保持不变）", true) {
			if e = u.a.RemoveWebHTTPS(); e != nil {
				return e
			}
			u.good("面板 HTTPS 站点已移除")
		}
	}
	if e := u.webControl("uninstall"); e != nil {
		return e
	}
	u.good("面板服务已卸载")
	return nil
}

// webHTTPSCommand is `rout web https ...`. The historic `rout web https DOMAIN` still only
// records the domain and prints the snippet.
func (u *UI) webHTTPSCommand(rest []string) error {
	usage := errors.New("用法：rout web https [域名 | deploy 域名 [--install-caddy] [--start-caddy] [--accept-nat] | repair | status | remove]")
	if len(rest) == 0 {
		return usage
	}
	opts := WebHTTPSOptions{}
	var positional []string
	for _, arg := range rest[1:] {
		switch arg {
		case "--install-caddy":
			opts.AllowInstall = true
		case "--start-caddy":
			opts.AllowStart = true
		case "--accept-nat":
			opts.AcceptNAT = true
		default:
			if strings.HasPrefix(arg, "--") {
				return usage
			}
			positional = append(positional, arg)
		}
	}
	report := func(res WebHTTPSResult, e error) error {
		var dnsErr *DNSPendingError
		if errors.As(e, &dnsErr) {
			for _, line := range dnsErr.Records {
				fmt.Fprintln(u.writer(), "  "+u.a.T(line))
			}
			return e
		}
		if e != nil {
			return e
		}
		u.webSuccess(res)
		return nil
	}
	switch rest[0] {
	case "deploy":
		if len(positional) != 1 {
			return usage
		}
		return report(u.a.DeployWebHTTPS(positional[0], opts))
	case "repair":
		if len(positional) != 0 {
			return usage
		}
		return report(u.a.RepairWebHTTPS(opts))
	case "status", "diagnose":
		return u.webDiagnose(false)
	case "remove":
		return u.a.RemoveWebHTTPS()
	}
	if len(rest) != 1 {
		return usage
	}
	return u.webHTTPS(rest[0])
}

// webBadge is the main-menu status of the panel: cheap, local reads only.
func (u *UI) webBadge() string {
	st, e := u.a.WebStatus()
	switch {
	case e != nil, !st.Installed:
		return u.a.T("未安装")
	case !st.Running:
		return u.a.T("未运行")
	case st.HTTPSDomain != "":
		return st.HTTPSDomain
	}
	return u.a.T("运行中")
}
