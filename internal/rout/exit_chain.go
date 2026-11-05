package rout

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// Relay-chain exits ("转发出口").
//
// A port forward is NOT an exit: it moves a connection to another address, and the
// destination still sees whoever dialed last. A relay chain therefore always ENDS in a real
// proxy or node that carries the traffic out to the Internet:
//
//	bound node (this server) ─► relay (port forward) ─► SOCKS5 / HTTP(S) / remote node ─► Internet
//
// The exit stores the real proxy (Proxy: protocol, credentials, the endpoint as the relay
// reaches it) and the hop that carries the connection there, by a stable reference:
//
//   - ViaRelay: the stable ID of a Rout relay on THIS server. Its target must be exactly the
//     proxy's endpoint. The connection is dialed to the relay's own listener on loopback, an
//     address derived from the relay's current settings whenever the configuration is
//     rendered, so editing the relay's port updates every dependant automatically.
//   - ViaAddress: host:port of a forwarder on ANOTHER server (for example a NAT or IPv6-only
//     box with a port mapping to the proxy). It is dialed directly.
//
// The proxy protocol (and TLS for HTTPS/node links, verified against the REAL proxy host)
// runs end to end through the hop; the hop never sees credentials in a form it can use
// unless the protocol itself is plaintext (SOCKS5/HTTP), which is stated wherever it is
// configured. Chain exits are used by AI Smart Routing only; nodes keep using ordinary exits.

const exitChain = "chain"

// relayDialHost is the loopback address that reaches a relay's own listener on this host.
// "::" always accepts ::1 (dual-stack or IPv6-only), "0.0.0.0" accepts 127.0.0.1 and a
// specific address is dialed as such.
func relayDialHost(p Profile) string {
	ip := net.ParseIP(p.Listen)
	switch {
	case ip == nil:
		return "127.0.0.1"
	case ip.IsUnspecified() && ip.To4() != nil:
		return "127.0.0.1"
	case ip.IsUnspecified():
		return "::1"
	}
	return ip.String()
}

// isChain reports whether the exit is reached through a forwarding hop.
func (e Exit) isChain() bool { return e.Kind == exitChain }

// validateChainShape is the structural check made on every load (no references followed).
func (e Exit) validateChainShape() error {
	if !e.isChain() {
		if e.ViaRelay != "" || e.ViaAddress != "" {
			return errors.New("只有转发出口链路可以指定中转")
		}
		return nil
	}
	if (e.ViaRelay == "") == (e.ViaAddress == "") {
		return errors.New("转发出口链路必须且只能指定一个中转")
	}
	if e.ViaRelay != "" && !idPattern.MatchString(e.ViaRelay) {
		return errors.New("转发出口链路引用的中转 ID 无效")
	}
	if e.ViaAddress != "" {
		if _, _, er := ParseEndpoint(e.ViaAddress); er != nil {
			return errors.New("转发出口链路的中转地址无效")
		}
	}
	switch e.RemoteNetwork {
	case "", "tcp", "udp", "both":
	default:
		return errors.New("远程服务器的网络类型无效")
	}
	return nil
}

// chainRelay returns the relay a chain exit uses, with the reason it cannot be used.
func chainRelay(s State, e Exit) (Profile, error) {
	p, er := Find(s, e.ViaRelay)
	if er != nil || p.Kind != "relay" {
		return Profile{}, errors.New("转发出口链路引用的中转已不存在")
	}
	return p, nil
}

// endpointIsThisHost says whether host:port is one of this server's own Rout entries: a node
// or relay listening on a local address, or the public entry of one of them. Traffic sent
// there would come straight back into Rout and leave from this server. A different local
// service (for example an SSH-forwarded SOCKS5 on 127.0.0.1:11080) is a legitimate hop.
func endpointIsThisHost(s State, host string, port int, local map[string]bool) (string, bool) {
	for _, p := range s.Profiles {
		if p.Port == port && pointsAtThisHost(host, local) {
			return p.Name, true
		}
		if p.PublicPort == port && sameHost(host, p.PublicHost) {
			return p.Name, true
		}
	}
	return "", false
}

// chainProblem is the strict check of a chain exit against the current state. It follows the
// reference, so it is applied to changes and when rendering; a stored chain whose relay was
// later broken still loads, and then fails closed.
func chainProblem(s State, e Exit, local map[string]bool) error {
	if er := e.validateChainShape(); er != nil {
		return er
	}
	if er := e.Proxy.Validate(); er != nil {
		return er
	}
	need := exitTransport(e.Proxy)
	if e.ViaRelay != "" {
		r, er := chainRelay(s, e)
		if er != nil {
			return er
		}
		if !r.Enabled {
			return fmt.Errorf("中转 %s 已停用，转发出口链路不可用", r.Name)
		}
		if !contains(r.Networks(), need) {
			return fmt.Errorf("中转 %s 不转发 %s，无法到达出口代理", r.Name, strings.ToUpper(need))
		}
		if need == "udp" && r.TargetNetwork == "tcp" {
			return fmt.Errorf("中转 %s 的目标只映射了 TCP，无法到达 UDP 节点", r.Name)
		}
		h, port, er := ParseEndpoint(r.Target)
		if er != nil {
			return er
		}
		if !sameHost(h, e.Proxy.Host) || port != e.Proxy.Port {
			return fmt.Errorf("中转 %s 的目标 %s 与出口代理地址 %s 不一致", r.Name, r.Target, e.Proxy.hostPort())
		}
		if name, self := endpointIsThisHost(s, h, port, local); self {
			return fmt.Errorf("中转 %s 的目标是本机的 %s：流量仍会从本机出口离开，不能作为出口", r.Name, name)
		}
		return nil
	}
	h, port, _ := ParseEndpoint(e.ViaAddress)
	if name, self := endpointIsThisHost(s, h, port, local); self {
		return fmt.Errorf("中转地址指向本机的 %s：请改为选择本机的 Rout 中转，或填写另一台服务器的地址", name)
	}
	return nil
}

// chainDialProxy returns the proxy as sing-box must dial it: the connection goes to the hop,
// while TLS (HTTPS proxies and node links) still verifies the real proxy host.
func chainDialProxy(s State, e Exit) (Proxy, error) {
	var host string
	var port int
	if e.ViaRelay != "" {
		r, er := chainRelay(s, e)
		if er != nil {
			return Proxy{}, er
		}
		host, port = relayDialHost(r), r.Port
	} else {
		h, n, er := ParseEndpoint(e.ViaAddress)
		if er != nil {
			return Proxy{}, er
		}
		host, port = h, n
	}
	p := e.Proxy
	switch p.Protocol {
	case proxyNode:
		link, er := RewriteURI(p.Link, host, port, e.Name)
		if er != nil {
			return Proxy{}, er
		}
		p.Link = link
	case "https":
		p.TLSName = e.Proxy.Host
	}
	p.Host, p.Port = host, port
	return p, nil
}

// resolveExit returns the proxy to dial for any exit: the stored proxy, or for a chain the
// hop-dialed proxy after the strict reference check.
func resolveExit(s State, e Exit, local map[string]bool) (Proxy, error) {
	if !e.isChain() {
		return e.Proxy, nil
	}
	if er := chainProblem(s, e, local); er != nil {
		return Proxy{}, er
	}
	return chainDialProxy(s, e)
}

// relayChainUsers lists the chain exits that depend on a relay, sorted by name.
func relayChainUsers(s State, relayID string) []Exit {
	var out []Exit
	for _, e := range s.Exits {
		if e.isChain() && e.ViaRelay == relayID {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// chainChangeError refuses a change that breaks a working chain exit, naming the relay and
// the exit, so deleting or retargeting a relay is never a silent outage. A chain that was
// already broken before the change never blocks unrelated edits.
func chainChangeError(old, next State) error {
	local := localIPs()
	for _, e := range next.Exits {
		if !e.isChain() {
			continue
		}
		prev, er := FindExit(old, e.ID)
		hadProblem := er == nil && chainProblem(old, prev, local) != nil
		if hadProblem {
			continue
		}
		if e.ViaRelay != "" {
			if r, er := Find(old, e.ViaRelay); er == nil && r.Kind == "relay" {
				if _, gone := Find(next, e.ViaRelay); gone != nil {
					return fmt.Errorf("中转 %s 正被出口链路 %s 使用，请先修改或删除该出口", r.Name, e.Name)
				}
			}
		}
		if p := chainProblem(next, e, local); p != nil {
			return fmt.Errorf("%s: %w", e.Name, p)
		}
	}
	return nil
}

// ChainSpec is a relay-chain exit: the real proxy (socks5/http/https with credentials, or a
// remote node link) and exactly one hop.
type ChainSpec struct {
	Name       string `json:"name"`
	ViaRelay   string `json:"via_relay"`
	ViaAddress string `json:"via_address"`
	Protocol   string `json:"protocol"` // socks5, http, https, node
	Host       string `json:"host"`     // the proxy as the hop reaches it; defaults to the relay target
	Port       int    `json:"port"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	Link       string `json:"link"` // node: share link; defaults to the relay's own target link
}

// buildChainExit turns a spec into an exit (not stored). It refuses a hop that cannot carry
// the proxy and never accepts a bare port forward as the end of the chain.
func buildChainExit(s State, spec ChainSpec) (Exit, error) {
	e := Exit{Kind: exitChain, ViaRelay: strings.TrimSpace(spec.ViaRelay), ViaAddress: strings.TrimSpace(spec.ViaAddress)}
	var relay *Profile
	if e.ViaRelay != "" {
		r, er := chainRelay(s, e)
		if er != nil {
			return e, er
		}
		relay = &r
	}
	switch spec.Protocol {
	case "socks5", "http", "https":
		host, port := strings.TrimSpace(spec.Host), spec.Port
		if relay != nil && host == "" && port == 0 {
			h, n, er := ParseEndpoint(relay.Target)
			if er != nil {
				return e, er
			}
			host, port = h, n
		}
		p, er := proxyFromSpec(spec.Protocol, ExitSpec{Host: host, Port: port, Username: spec.Username, Password: spec.Password})
		if er != nil {
			return e, er
		}
		e.Proxy = *p
	case proxyNode, "remote":
		link := strings.TrimSpace(spec.Link)
		if link == "" && relay != nil {
			link = relay.TargetURI
		}
		if link == "" {
			return e, errors.New("请粘贴远程节点的分享链接")
		}
		p, er := ParseRemoteNode(link)
		if er != nil {
			return e, er
		}
		e.Proxy = *p
	case "", "tcp", "forward":
		return e, errors.New("端口转发的末端必须是真正的代理（SOCKS5 / HTTP(S) CONNECT）或远程节点；请选择代理协议并填写认证信息")
	default:
		return e, errors.New("出站类型无效")
	}
	if exitTransport(e.Proxy) == "udp" {
		e.RemoteNetwork = "both"
	}
	e.Name = strings.TrimSpace(spec.Name)
	if e.Name == "" {
		e.Name = chainDefaultName(s, e)
	}
	if er := validDisplayName(e.Name); er != nil {
		return e, er
	}
	return e, nil
}

func chainDefaultName(s State, e Exit) string {
	via := e.ViaAddress
	if r, er := chainRelay(s, e); er == nil {
		via = r.Name
	}
	return boundedChainName("Chain", via, e.Proxy.Host)
}

// boundedChainName preserves the old names for short endpoints. For longer generated names,
// keep a readable prefix and a stable content-derived suffix so similar long hostnames do
// not all collapse to the same name. The display-name validator counts Unicode code points.
func boundedChainName(parts ...string) string {
	name := strings.Join(parts, "-")
	const limit = 60
	if utf8.RuneCountInString(name) <= limit {
		return name
	}
	sum := sha256.Sum256([]byte(name))
	suffix := fmt.Sprintf("-%x", sum[:4])
	return string([]rune(name)[:limit-len(suffix)]) + suffix
}

// CreateChainExit stores a relay-chain exit after the strict check.
func (a *App) CreateChainExit(spec ChainSpec) (Exit, error) {
	var out Exit
	err := a.webMutate(func(old State) (State, error) {
		e, er := buildChainExit(old, spec)
		if er != nil {
			return old, er
		}
		if er = chainProblem(old, e, localIPs()); er != nil {
			return old, er
		}
		for _, other := range old.Exits {
			if strings.EqualFold(other.Name, e.Name) {
				return old, errors.New("名称已被使用")
			}
		}
		e.ID = RandomHex(6)
		out = e
		return UpsertExit(old, e), nil
	})
	return out, err
}

// ChainPath describes the chain hop by hop for display; it never contains credentials.
func chainPath(a *App, s State, e Exit) []string {
	out := []string{a.T("本机入站")}
	if e.isChain() {
		if e.ViaRelay != "" {
			if r, er := chainRelay(s, e); er == nil {
				out = append(out, fmt.Sprintf("%s %s (%s %s)", a.T("中转"), r.Name, strings.ToUpper(r.Protocol), net.JoinHostPort(relayDialHost(r), itoa(r.Port))))
			} else {
				out = append(out, a.T("中转（缺失）"))
			}
		} else {
			out = append(out, a.T("远端中转")+" "+e.ViaAddress)
		}
	}
	out = append(out, strings.ToUpper(e.Proxy.Kind())+" "+e.Proxy.hostPort(), a.T("互联网"))
	return out
}

// diagChainHop runs the layers specific to a chain (relay availability and the relay's own
// connection to the proxy) and returns the proxy to dial through the hop.
func (a *App) diagChainHop(ctx context.Context, d diagger, e Exit, env diagEnv) (Proxy, bool) {
	s, er := a.Load()
	if er != nil {
		d.add(4, diagFail, "%s", a.Error(er))
		return Proxy{}, false
	}
	dial, er := resolveExit(s, e, env.local())
	if er != nil {
		d.add(4, diagFail, "转发出口链路不可用：%s", a.Error(er))
		return Proxy{}, false
	}
	if e.ViaAddress != "" {
		d.add(4, diagInfo, "经由另一台服务器上的中转 %s；它到代理的连通性由下面的代理握手验证", e.ViaAddress)
		return dial, true
	}
	r, _ := chainRelay(s, e)
	if managed, up := env.managed(a, r); managed && !up {
		d.add(4, diagFail, "中转 %s 的服务未运行；运行 rout logs %s 查看原因", r.Name, r.ID)
		return Proxy{}, false
	}
	d.add(4, diagOK, "中转 %s 已启用：%s → %s", r.Name, net.JoinHostPort(dial.Host, itoa(dial.Port)), r.Target)
	// The relay dials the end of the chain from this server, so the same destination is
	// tested here with the relay's own address-family policy, using the transport the end
	// actually needs: TCP for SOCKS5/HTTP(S) and TCP node protocols, a QUIC probe for
	// Hysteria2/TUIC. A refused TCP connection says nothing about a UDP exit, so a UDP end is
	// never tested with TCP.
	hop := env.newDialer(r.outboundPolicy())
	if exitTransport(dial) == "udp" {
		d.add(4, diagInfo, "出口是 UDP/QUIC 协议（%s）：中转必须转发 UDP，下面用 QUIC 探测验证目标和经由中转的往返", strings.ToUpper(dial.Kind()))
		if d.layerQUICTarget(ctx, env, hop, r.Target) {
			return Proxy{}, false
		}
		return dial, true
	}
	start := time.Now()
	conn, rep, er := hop.DialContext(ctx, r.Target)
	if er != nil {
		d.dialFailure(3, er, rep)
		return Proxy{}, false
	}
	conn.Close()
	d.add(3, diagOK, "中转目标 %s 可连通：%s %s（%d ms）", r.Target, ipFamilyLabel(rep.Used.Addr()), rep.Used.String(), time.Since(start).Milliseconds())
	return dial, true
}

// chainProbeExit is a stand-in exit that asks "can this relay be the hop of a chain at all?"
// without knowing the end yet: a SOCKS5 end for a relay that forwards TCP, a QUIC node end for
// one that forwards UDP only. The relay's own settings (enabled, transport, loops) decide.
func chainProbeExit(r Profile) Exit {
	h, port, _ := ParseEndpoint(r.Target)
	ex := Exit{Kind: exitChain, ViaRelay: r.ID, Proxy: Proxy{Protocol: "socks5", Host: h, Port: port, Username: "x", Password: "x"}}
	if !contains(r.Networks(), "tcp") {
		if p, e := ParseRemoteNode("hysteria2://probe@" + net.JoinHostPort(h, itoa(port)) + "?sni=probe.invalid"); e == nil {
			ex.Proxy, ex.RemoteNetwork = *p, "both"
		}
	}
	return ex
}
