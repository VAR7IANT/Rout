package rout

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"strings"
	"time"
)

func (u *UI) subscriptionHTTPSDiagnostics() error {
	report, e := u.a.HTTPSDiagnostics()
	if e != nil {
		return e
	}
	u.heading("HTTPS 状态与诊断")
	row := func(label, value string) {
		fmt.Fprintf(u.writer(), "  %s\n    %s\n", u.a.T(label), u.a.subscriptionText(value))
	}
	flag := func(value bool) string {
		if value {
			return u.a.T("通过")
		}
		return u.a.T("未通过／未验证")
	}
	row("域名", report.Domain)
	row("DNS A 记录", strings.Join(report.DNS.A, ", "))
	row("DNS AAAA 记录", strings.Join(report.DNS.AAAA, ", "))
	row("本机公网地址", fmt.Sprintf("IPv4: %s; IPv6: %s", report.DNS.Addresses.IPv4, report.DNS.Addresses.IPv6))
	row("DNS 与源站比较", flag(report.DNS.Matched))
	if report.DNS.Cloudflare {
		u.hint("检测到 Cloudflare 代理地址，不能据此认定源站不匹配；首次签发建议 DNS-only，并检查源站与 Full (strict) 设置")
	}
	if report.DNS.Error != "" {
		u.warn(u.a.subscriptionText(report.DNS.Error))
	}
	for _, port := range []int{80, 443} {
		owners := u.a.T("未监听")
		if len(report.Ports[port]) > 0 {
			var lines []string
			for _, l := range report.Ports[port] {
				lines = append(lines, fmt.Sprintf("%s · %s · PID %d", l.Address, l.Owner, l.PID))
			}
			owners = strings.Join(lines, "\n    ")
		}
		row(fmt.Sprintf("TCP %d", port), owners)
	}
	row("本机订阅服务", flag(report.LocalRunning))
	row("本机监听", fmt.Sprintf("127.0.0.1:%d", report.Settings.listenPort()))
	row("本机订阅响应验证", flag(report.Verification.LocalService))
	proxy := "Caddy"
	if !report.Installed {
		proxy = u.a.T("未检测到 Caddy")
	}
	row("反向代理", proxy)
	row("Caddy 服务", flag(report.Running))
	row("配置归属", report.Ownership)
	if report.ConfigFile != "" {
		row("配置文件", report.ConfigFile)
	}
	row("本机 HTTPS 与证书验证", flag(report.Verification.LocalTLS))
	if !report.Verification.Expires.IsZero() {
		row("证书到期时间", report.Verification.Expires.Format(time.RFC3339))
	}
	row("证书续期", report.Renewal)
	row("从本机经公网 DNS 验证订阅响应", flag(report.Verification.PublicFromHost))
	row("独立外部网络验证", flag(report.Verification.External))
	if !report.Verification.External {
		u.hint("本机 HTTPS 成功不代表外网可达；此环境未配置独立外部探测，请从手机网络刷新原订阅")
	}
	if report.Verification.Error != "" {
		u.warn(u.a.subscriptionText(report.Verification.Error))
	}
	if report.LastError != "" {
		row("上次部署错误", report.LastError)
	}
	for _, issue := range report.Issues {
		u.warn(u.a.subscriptionText(issue))
	}
	u.hint("根路径返回 404 是正常行为；诊断使用临时凭据，不读取或更换现有订阅令牌")
	return nil
}

func (u *UI) subscriptionDomainWarning(oldURL, domain string) bool {
	old, e := url.Parse(oldURL)
	if e == nil && old.Hostname() != "" && old.Hostname() != domain {
		u.warn("更换域名后，旧域名必须继续可达，否则客户端需要更新订阅地址；令牌与节点选择保持不变")
		return u.yes("继续设置新的订阅域名", true)
	}
	return true
}

func (u *UI) existingSubscriptionHTTPS(domain string) (bool, error) {
	r := u.a.httpsRuntime()
	cfg, e := u.a.subscriptionSettings()
	if e != nil {
		return false, e
	}
	saved, e := u.a.loadHTTPSState()
	if e != nil {
		return false, e
	}
	if (saved.Ownership == "managed" || saved.Ownership == "adopted") && !saved.Removed {
		return false, nil
	}
	active, activeErr := r.active()
	route := httpsRoute{}
	if activeErr == nil {
		route = inspectCaddyDomain(active, domain, cfg.listenPort())
	}
	configured, _ := url.Parse(cfg.PublicURL)
	if !route.Found && (configured == nil || configured.Hostname() != domain) {
		return false, nil
	}

	// Do not claim that recognizing a domain block proves public availability.
	token, body, cleanup, e := u.a.beginSubscriptionProbe()
	if e != nil {
		return true, e
	}
	base := "https://" + domain
	if old, _ := url.Parse(cfg.PublicURL); old != nil && old.Hostname() == domain {
		base = cfg.PublicURL
	}
	result := r.verify(base, cfg.listenPort(), token, body)
	if e = cleanup(); e != nil {
		return true, e
	}
	if !result.LocalService || !result.PublicFromHost {
		return route.Found, errors.New("existing Caddy site found but its authenticated endpoint is not verified; preserve it and inspect HTTPS diagnostics")
	}
	for u.err == nil {
		u.good("检测到已有 HTTPS 订阅")
		u.printf("域名：%s\n", domain)
		if r.installed() && r.running() {
			u.printf("反向代理：Caddy\n上游：127.0.0.1:%d\n", cfg.listenPort())
		} else {
			u.say("已有 HTTPS 代理（类型未确认），认证订阅响应已验证")
		}

		u.say("归属：外部／已有配置；识别成功不会转移所有权")
		switch u.menu("", []menuItem{item("use", "使用已有 HTTPS 配置"), item("inspect", "查看配置摘要"), item("adopt", "尝试安全接管")}, "返回") {
		case "use":
			return true, u.a.UseExistingSubscriptionHTTPS(domain)
		case "inspect":
			u.printf("配置文件：%s\n", u.a.httpsMain())
			u.say("检测到域名指向正确回环端口；不会打印共享配置中的密钥或订阅令牌")
		case "adopt":
			path, e := u.a.adoptableHTTPSFile(domain, cfg.listenPort())
			if e != nil {
				u.warn(u.a.subscriptionText(u.a.Error(e)))
				u.hint("无法安全接管时，请选择使用已有配置；现有站点保持不变")
				continue
			}
			u.printf("仅接管独立文件：%s\n", path)
			u.warn("接管后 Rout 可修改或移除此文件中的订阅站点；其他 Caddy 配置保持原样")
			if u.yes("确认接管这个独立订阅配置文件", true) {
				return true, u.a.AdoptSubscriptionHTTPS(domain)
			}
		default:
			return true, u.err
		}
	}
	return true, u.err
}

func (u *UI) subscriptionHTTPSDeploy(domain string) (err error) {
	defer func() {
		if err == nil || errors.Is(err, io.EOF) || errors.Is(err, errQuit) {
			return
		}
		// Preflight failures (DNS, ports, install approval) also belong in diagnostics.
		unlock, e := lockFile(filepath.Join(u.a.Home, ".subscription.lock"), trafficLockWait)
		if e != nil {
			err = errors.Join(err, e)
			return
		}
		defer unlock()
		saved, e := u.a.loadHTTPSState()
		if e != nil {
			err = errors.Join(err, e)
			return
		}
		message := sanitizeSubscriptionLogs([]byte(err.Error()))
		if len(message) > 2048 {
			message = message[:2048]
		}
		if saved.LastError != message {
			saved.LastError = message
			if e = u.a.saveHTTPSState(saved); e != nil {
				err = errors.Join(err, e)
			}
		}
	}()
	cfg, e := u.a.subscriptionSettings()
	if e != nil {
		return e
	}
	if domain == "" {
		def := ""
		if parsed, _ := url.Parse(cfg.PublicURL); parsed != nil {
			def = parsed.Hostname()
		}
		domain = u.ask("订阅公网域名（仅域名，不含端口或路径）", def)
		if u.err != nil {
			return u.err
		}
	}
	domain, e = subscriptionDomain(domain)
	if e != nil {
		return e
	}
	if !u.subscriptionDomainWarning(cfg.PublicURL, domain) {
		return u.err
	}
	if !cfg.Enabled {
		u.say("自动 HTTPS 需要先启用回环订阅服务；现有订阅、令牌和节点不会改变")
		if !u.yes("启用本机订阅服务", true) {
			return u.err
		}
		if e = u.a.EnableSubscriptionServer(cfg.listenPort()); e != nil {
			return e
		}
	} else {
		if e = u.a.RefreshSubscriptionServer(); e != nil {
			return e
		}
	}
	if detected, e := u.existingSubscriptionHTTPS(domain); detected || e != nil {
		return e
	}
	dns := u.a.httpsRuntime().dns(domain)
	u.printf("A：%s\nAAAA：%s\n", strings.Join(dns.A, ", "), strings.Join(dns.AAAA, ", "))
	if dns.Error != "" {
		return errors.New(dns.Error)
	}
	if dns.Cloudflare {
		u.hint("检测到 Cloudflare 代理地址，不能据此认定源站不匹配；首次签发建议 DNS-only，并检查源站与 Full (strict) 设置")
	}
	allowInstall := false
	if !u.a.httpsRuntime().installed() {
		u.say("将通过 Debian／Ubuntu 官方软件源安装 Caddy，并启用开机自启；不运行远程安装脚本")
		allowInstall = u.yes("确认安装 Caddy", true)
		if !allowInstall {
			return u.err
		}
	}
	u.say("正在验证配置、自动证书与订阅响应；签发可能需要一些时间")
	if e = u.a.DeploySubscriptionHTTPS(domain, allowInstall); e != nil {
		return e
	}
	u.good("HTTPS 订阅部署已验证；订阅、令牌和节点选择保持不变")
	u.hint("外网可达性仍需从手机网络验证；本机检查不能代替独立外部测试")
	return nil
}

func (u *UI) subscriptionHTTPSRemove() error {
	saved, e := u.a.loadHTTPSState()
	if e != nil {
		return e
	}
	if _, e = u.a.ownedHTTPSFile(saved); e != nil {
		return e
	}
	u.warn("移除后这些域名的订阅 HTTPS 将不可用；订阅、令牌、节点、其他站点和证书保留，Caddy 不会被卸载或停止")
	domains := saved.Domains
	if len(domains) == 0 {
		domains = []string{saved.Domain}
	}
	u.printf("域名：%s\n", strings.Join(domains, ", "))
	if !u.yes("确认移除 Rout 管理的订阅 HTTPS 配置", true) {
		return u.err
	}
	if e = u.a.RemoveSubscriptionHTTPS(); e != nil {
		return e
	}
	u.good("Rout 管理的 HTTPS 配置已移除，订阅数据保留")
	return nil
}

func (u *UI) showExistingSubscriptionURL() {
	cfg, e := u.a.subscriptionSettings()
	if e != nil {
		return
	}
	base := cfg.PublicURL
	if base == "" {
		base = "https://YOUR-DOMAIN"
	}
	u.heading("订阅链接模板")
	u.printf("Base64：%s/s/{access_token}\n", base)
	u.printf("Mihomo：%s/s/{access_token}?format=mihomo\n", base)
	u.printf("Clash：%s/s/{access_token}?format=clash\n", base)
	u.hint("此处仅显示链接模板；完整链接请在“查看订阅”中查看，旧订阅仍可使用之前保存的 URL")
}

// New HTTPS internals return stable English diagnostics for automation. Present
// their catalog translations in the selected CLI language without changing errors.
func (a *App) subscriptionText(s string) string {
	if a.Language == "en" {
		return a.T(s)
	}
	for chinese, english := range messages {
		if english == s {
			return chinese
		}
	}
	return s
}

type subscriptionUIError struct {
	cause   error
	message string
}

func (e subscriptionUIError) Error() string { return e.message }
func (e subscriptionUIError) Unwrap() error { return e.cause }
