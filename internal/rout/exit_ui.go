package rout

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Outbound (exit) management. An exit is where a node's traffic leaves the Internet from:
//
//	Direct          this server (built in, never stored)
//	SOCKS5 / HTTP   an authenticated proxy
//	Remote Server   another VPS/NAT, through its node protocol or an authenticated proxy
//
// Exits are stored once and reused: nodes only reference them by ID. A Remote Server is
// verified with a real request before it is saved, never shown as working on faith.

func exitDefaultName(e Exit) string {
	p := e.Proxy
	if e.Kind == exitRemote {
		return "Remote-" + p.Host
	}
	return strings.ToUpper(p.Protocol) + "-" + p.Host
}

// classicProxyInput reads "IP:port:user:password" for a SOCKS5/HTTP(S) proxy.
func (u *UI) classicProxyInput(protocol string) (Proxy, error) {
	if warning := proxySecurityWarning(Proxy{Protocol: protocol}); warning != "" {
		u.warn(warning)
	}
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

// exitInput asks which kind of outbound to create and reads its details.
func (u *UI) exitInput() (Exit, error) {
	protocol := u.option("代理协议", []menuItem{
		item("socks5", "SOCKS5"),
		item("http", "HTTP CONNECT"),
		item("https", "HTTPS CONNECT（验证证书）"),
		itemNote("remote", "远程服务器出口", "另一台 VPS / NAT 作为出口：流量从它的公网 IP 出站"),
	}, "socks5")
	if u.err != nil {
		return Exit{}, u.err
	}
	if protocol == "remote" {
		return u.remoteExitInput()
	}
	p, e := u.classicProxyInput(protocol)
	return Exit{Proxy: p}, e
}

// remoteExitInput reads a Remote Server exit. Only forms that can really carry traffic out
// are accepted: a remote node's share link, or an authenticated remote proxy. A bare port
// mapping is explained and refused.
func (u *UI) remoteExitInput() (Exit, error) {
	u.heading("远程服务器出口")
	u.say("流量将从另一台服务器的公网 IP 出站。对方服务器上必须有真正在运行的代理服务；只有端口映射的 NAT 只能做端口转发（中转），不能当出口。")
	mode := u.option("远程服务器上有什么？", []menuItem{
		itemNote("node", "远程节点的分享链接", "例如另一台 VPS 上用 Rout 创建的 VLESS Reality / AnyTLS / Trojan / SS 节点（推荐）"),
		itemNote("proxy", "SOCKS5 / HTTP(S) 代理", "必须有账号密码；不接受无认证的开放代理"),
		itemNote("forward", "只有 TCP/UDP 端口映射", "这是端口转发，不是出口"),
	}, "node")
	if u.err != nil {
		return Exit{}, u.err
	}
	switch mode {
	case "forward":
		return Exit{}, errors.New("端口映射只是把连接送到另一个地址，目标网站看到的仍是本机 IP，不能作为出口。请在远程服务器上运行代理服务（可用 Rout 创建节点），然后选择『远程节点的分享链接』；若只想转发端口，请使用『端口转发』")
	case "proxy":
		protocol := u.option("代理协议", []menuItem{item("socks5", "SOCKS5"), item("http", "HTTP CONNECT"), item("https", "HTTPS CONNECT（验证证书）")}, "https")
		if u.err != nil {
			return Exit{}, u.err
		}
		p, e := u.classicProxyInput(protocol)
		return Exit{Kind: exitRemote, Proxy: p}, e
	}
	for u.err == nil {
		raw := u.secret("粘贴远程节点的分享链接（vless:// anytls:// trojan:// ss:// hysteria2:// tuic://）")
		if u.err != nil {
			return Exit{}, u.err
		}
		p, e := ParseRemoteNode(raw)
		if e != nil {
			u.say(u.a.Error(e))
			continue
		}
		e2 := Exit{Kind: exitRemote, Proxy: *p}
		if exitTransport(*p) == "udp" {
			// A QUIC node is reached over UDP. Many NATs map TCP only; ask rather than assume.
			if u.option("远程服务器的端口映射支持 UDP 吗？", []menuItem{
				itemNote("both", "支持 UDP（或不确定）", "保存前会实际测试"),
				itemNote("tcp", "仅 TCP", "例如只映射了 TCP 端口的 NAT"),
			}, "both") == "tcp" {
				e2.RemoteNetwork = "tcp"
			} else {
				e2.RemoteNetwork = "both"
			}
		}
		if e = e2.validateKind(); e != nil {
			return Exit{}, e
		}
		return e2, u.err
	}
	return Exit{}, u.err
}

// exitCheck tests an exit and prints what each layer proved. The injected probe (tests)
// replaces the engine-based request.
func (u *UI) exitCheck(e Exit) error {
	if u.probeProxy != nil {
		ip, er := u.probeProxy(e.Proxy)
		if er != nil {
			return er
		}
		u.good(fmt.Sprintf(u.a.T("出站代理可用，实际出口 IP：%s"), ip))
		return nil
	}
	u.say("正在分层检测出站代理…")
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	rep := u.a.diagnoseProxy(ctx, e, u.diagEnvOrDefault(), diagOpts{Full: true})
	u.printReport(rep)
	return reportError(rep)
}

// verifyExit is required before a Remote Server is saved: it must really work, or the
// user explicitly chooses to keep it unverified.
func (u *UI) verifyExit(e Exit) bool {
	if e.Kind != exitRemote {
		return true
	}
	if er := u.exitCheck(e); er != nil {
		u.fail(u.a.Error(er))
		u.warn("远程服务器出口未通过检测；保存后使用它的节点可能无法上网")
		return u.yes("仍然保存（尚未验证）", false)
	}
	return true
}

// errCancelled means the user backed out; nothing was stored.
var errCancelled = errors.New("已取消")

// newExit runs the creation flow and commits the exit. It returns the stored exit, or
// errCancelled when the user declined to save an exit that failed its check.
func (u *UI) newExit(s State) (State, Exit, error) {
	e, err := u.exitInput()
	if err != nil {
		return s, Exit{}, err
	}
	e.Name = u.ask("出站代理名称", exitDefaultName(e))
	if u.err != nil {
		return s, Exit{}, u.err
	}
	e.ID = RandomHex(6)
	if er := exitSelfLoop(s, e.Proxy, localIPs()); er != nil {
		return s, Exit{}, er
	}
	if er := e.validateKind(); er != nil {
		return s, Exit{}, er
	}
	if !u.verifyExit(e) {
		if u.err != nil {
			return s, Exit{}, u.err
		}
		return s, Exit{}, errCancelled
	}
	if er := u.a.Commit(s, UpsertExit(s, e), false); er != nil {
		return s, Exit{}, er
	}
	next, er := u.a.Load()
	return next, e, er
}

// exitDetail shows an exit and everything that depends on it. Credentials are never shown.
func (u *UI) exitDetail(s State, e Exit) {
	w := u.writer()
	fmt.Fprintf(w, "  %s %s\n", u.bold(e.Name), u.dim("["+e.ID+"]"))
	kind := u.a.T("代理")
	if e.Kind == exitRemote {
		kind = u.a.T("远程服务器出口")
	}
	fmt.Fprintf(w, "    %s %s · %s\n", u.a.T("类型"), kind, strings.ToUpper(e.Proxy.Kind()))
	fmt.Fprintf(w, "    %s %s\n", u.a.T("地址"), e.Proxy.hostPort())
	caps := e.Capabilities()
	reach := "TCP"
	if caps.Reach == "udp" {
		reach = "UDP"
	}
	fmt.Fprintf(w, "    %s %s\n", u.a.T("连接远程服务器需要"), reach)
	switch e.RemoteNetwork {
	case "tcp":
		fmt.Fprintf(w, "    %s\n", u.a.T("远程端口映射：仅 TCP"))
	case "both":
		fmt.Fprintf(w, "    %s\n", u.a.T("远程端口映射：TCP + UDP"))
	}
	fmt.Fprintf(w, "    %s\n", u.a.T("经此出口：客户端 TCP 流量可以出站；UDP 流量会被拒绝（出站代理只转发 TCP）"))
	if warning := proxySecurityWarning(e.Proxy); warning != "" {
		u.warn(warning)
	}
	refs := exitReferences(s, e.ID)
	if refs.Empty() {
		fmt.Fprintf(w, "    %s\n", u.a.T("引用：没有节点使用它"))
		return
	}
	var names []string
	for _, p := range refs.Nodes {
		names = append(names, p.Name)
	}
	if len(names) > 0 {
		fmt.Fprintf(w, "    %s %s\n", u.a.T("使用它的节点："), strings.Join(names, "、"))
	}
	if refs.AI {
		fmt.Fprintf(w, "    %s\n", u.a.T("AI 智能分流正把它用作 AI 出口"))
	}
}
