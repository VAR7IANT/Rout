package rout

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// caddySnippet is the reverse-proxy site for the panel. Caddy obtains the certificate, sets
// X-Forwarded-For and X-Forwarded-Proto itself, and the panel only ever sees 127.0.0.1.
func caddySnippet(domain string, port int) string {
	return fmt.Sprintf("%s {\n\tencode zstd gzip\n\theader -Server\n\treverse_proxy 127.0.0.1:%d {\n\t\theader_up X-Forwarded-Proto {scheme}\n\t}\n}\n", domain, port)
}

func (u *UI) webCommand(args []string) error {
	a := u.a
	if len(args) < 2 {
		return errors.New("用法：rout web [passwd|install|start|stop|restart|status|logs|uninstall|host|https|serve]")
	}
	rest := args[2:]
	switch args[1] {
	case "serve":
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		return a.ServeWeb(ctx, nil)
	case "passwd":
		return u.webPasswd(rest)
	case "install":
		cfg, e := a.LoadWebConfig()
		if e != nil {
			return e
		}
		port := cfg.port()
		for i := 0; i < len(rest); i++ {
			if rest[i] == "--port" && i+1 < len(rest) {
				n, er := strconv.Atoi(rest[i+1])
				if er != nil || n < 1024 || n > 65535 {
					return errors.New("面板端口应在 1024–65535 之间")
				}
				port = n
				i++
				continue
			}
			return errors.New("用法：rout web install [--port 端口]")
		}
		if port != cfg.port() {
			if e = a.mutateWebConfig(func(c *WebConfig) error { c.Port = port; return nil }); e != nil {
				return e
			}
		}
		if cfg.PasswordHash == "" {
			u.say("尚未设置管理密码：服务将启动，但在运行 rout web passwd 之前任何人都无法登录")
		}
		if e = a.InstallWebService(); e != nil {
			return e
		}
		u.printf("管理面板已在 127.0.0.1:%d 运行（仅本机可访问）\n", port)
		u.say("通过 HTTPS 反向代理对外提供：rout web https 域名")
		return nil
	case "start", "stop", "restart":
		return a.controlWeb(args[1])
	case "uninstall":
		return a.RemoveWebService()
	case "status":
		st, e := a.WebStatus()
		if e != nil {
			return e
		}
		yn := func(b bool, yes, no string) string {
			if b {
				return a.T(yes)
			}
			return a.T(no)
		}
		fmt.Fprintf(u.writer(), "%s: %s\n", a.T("管理面板"), yn(st.Installed, "已安装", "未安装"))
		fmt.Fprintf(u.writer(), "%s: %s\n", a.T("运行状态"), yn(st.Running, "运行中", "未运行"))
		fmt.Fprintf(u.writer(), "%s: 127.0.0.1:%d\n", a.T("监听地址"), st.Port)
		fmt.Fprintf(u.writer(), "%s: %s\n", a.T("管理密码"), yn(st.PasswordSet, "已设置", "未设置"))
		if len(st.Hosts) > 0 {
			fmt.Fprintf(u.writer(), "%s: %s\n", a.T("允许的访问域名"), strings.Join(st.Hosts, ", "))
		}
		if st.HTTPSDomain != "" {
			fmt.Fprintf(u.writer(), "%s: %s\n", a.T("HTTPS 域名"), st.HTTPSDomain)
		}
		return nil
	case "logs":
		st, e := a.Load()
		if e != nil {
			return e
		}
		text, e := a.serviceLog(st, "web", 100)
		if e != nil {
			return e
		}
		fmt.Fprintln(u.writer(), text)
		return nil
	case "host":
		return u.webHost(rest)
	case "https":
		if len(rest) != 1 {
			return errors.New("用法：rout web https 域名")
		}
		return u.webHTTPS(rest[0])
	}
	return errors.New("未知命令，请运行 rout help")
}

func (u *UI) webPasswd(flags []string) error {
	a := u.a
	var gen, fromStdin bool
	for _, f := range flags {
		switch f {
		case "--generate":
			gen = true
		case "--stdin":
			fromStdin = true
		default:
			return errors.New("用法：rout web passwd [--generate | --stdin]")
		}
	}
	if gen && fromStdin {
		return errors.New("用法：rout web passwd [--generate | --stdin]")
	}
	var pw string
	switch {
	case gen:
		pw = GenerateWebPassword()
	case fromStdin:
		line, e := u.in.ReadString('\n')
		if e != nil && line == "" {
			return errors.New("没有读取到密码")
		}
		pw = strings.TrimRight(line, "\r\n")
	default:
		pw = u.secret("新的管理密码")
		if u.err != nil {
			return u.err
		}
		if u.secret("再次输入新的管理密码") != pw {
			return errors.New("两次输入的密码不一致")
		}
	}
	if e := a.SetWebPassword(pw); e != nil {
		return e
	}
	if gen {
		fmt.Fprintf(u.writer(), "%s: %s\n", a.T("新的管理密码（只显示这一次）"), pw)
	}
	u.say("管理密码已更新；已登录的会话将失效")
	return nil
}

func (u *UI) webHost(rest []string) error {
	a := u.a
	if len(rest) == 0 || rest[0] == "list" {
		cfg, e := a.LoadWebConfig()
		if e != nil {
			return e
		}
		for _, h := range cfg.AllowedHosts {
			fmt.Fprintln(u.writer(), h)
		}
		return nil
	}
	if len(rest) != 2 || (rest[0] != "add" && rest[0] != "remove") {
		return errors.New("用法：rout web host [list|add 域名|remove 域名]")
	}
	host, e := normalizeWebHost(rest[1])
	if e != nil {
		return e
	}
	return a.mutateWebConfig(func(c *WebConfig) error {
		var out []string
		for _, h := range c.AllowedHosts {
			if h != host {
				out = append(out, h)
			}
		}
		if rest[0] == "add" {
			out = append(out, host)
		}
		c.AllowedHosts = out
		return nil
	})
}

// webHTTPS records the public domain (allowed Host, Secure cookie) and prints the reverse
// proxy site to add to Caddy. It changes nothing else on the machine.
func (u *UI) webHTTPS(domain string) error {
	a := u.a
	host, e := normalizeWebHost(domain)
	if e != nil || strings.Contains(host, ":") {
		return errors.New("域名无效")
	}
	if ip := parseIPLiteral(host); ip {
		return errors.New("请使用域名，证书无法签发给 IP 地址")
	}
	cfg, e := a.LoadWebConfig()
	if e != nil {
		return e
	}
	if e = a.mutateWebConfig(func(c *WebConfig) error {
		if !contains(c.AllowedHosts, host) {
			c.AllowedHosts = append(c.AllowedHosts, host)
		}
		c.SecureCookie, c.HTTPSDomain = true, host
		return nil
	}); e != nil {
		return e
	}
	u.printf("已允许域名 %s 并强制 Secure Cookie。把下面的站点加入 Caddyfile（或 Rout 管理的 Caddy 配置目录），然后重载 Caddy：\n\n", host)
	fmt.Fprint(u.writer(), caddySnippet(host, cfg.port()))
	fmt.Fprintln(u.writer())
	u.say("请确认域名已解析到本机，且 80/443 端口可从公网访问；之后用 https://域名 登录。面板本身仍只监听 127.0.0.1")
	return nil
}

func parseIPLiteral(h string) bool {
	h = strings.Trim(h, "[]")
	return len(h) > 0 && strings.ContainsAny(h, ":") || isDotted(h)
}

func isDotted(h string) bool {
	parts := strings.Split(h, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if _, e := strconv.Atoi(p); e != nil {
			return false
		}
	}
	return true
}

// ---- third-party sources ----------------------------------------------------------------

func (u *UI) remoteCommand(args []string) error {
	a := u.a
	if len(args) < 2 {
		return errors.New("用法：rout remote [list|refresh [ID|all]|delete ID [--detach]]")
	}
	switch args[1] {
	case "list":
		views, e := a.RemoteSources()
		if e != nil {
			return e
		}
		for _, v := range views {
			last := "-"
			if !v.Status.LastSuccess.IsZero() {
				last = v.Status.LastSuccess.Local().Format("2006-01-02 15:04")
			}
			fmt.Fprintf(u.writer(), "%s  %s  %s  %s %d/%d  %s %s\n", v.ID, pad(v.Name, 24), pad(v.Status.State, 6), a.T("节点"), v.Active, v.Valid, a.T("上次成功"), last)
		}
		return nil
	case "refresh":
		views, e := a.RemoteSources()
		if e != nil {
			return e
		}
		target := "all"
		if len(args) > 2 {
			target = args[2]
		}
		var failed int
		for _, v := range views {
			if target != "all" && target != v.ID {
				continue
			}
			if v.Kind != sourceKindURL {
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			res, er := a.RefreshRemoteSource(ctx, v.ID)
			cancel()
			if er != nil {
				failed++
				fmt.Fprintf(u.writer(), "%s  %s: %s\n", v.ID, v.Name, a.T(redactError(er)))
				continue
			}
			fmt.Fprintf(u.writer(), "%s  %s: %d %s, %d %s, %d %s\n", v.ID, v.Name, res.Valid, a.T("个节点"), res.Errors, a.T("个无法解析"), res.Skipped, a.T("个已跳过"))
		}
		if failed > 0 {
			return fmt.Errorf(a.T("%d 个订阅源刷新失败"), failed)
		}
		return nil
	case "delete":
		if len(args) < 3 {
			return errors.New("用法：rout remote [list|refresh [ID|all]|delete ID [--detach]]")
		}
		if !u.yes(fmt.Sprintf(a.T("删除订阅源 %s"), args[2]), false) {
			if u.err != nil {
				return u.err
			}
			return errors.New("已取消")
		}
		return a.DeleteRemoteSource(args[2], contains(args[3:], "--detach"))
	}
	return errors.New("未知命令，请运行 rout help")
}
