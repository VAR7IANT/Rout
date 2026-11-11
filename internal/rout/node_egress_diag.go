package rout

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Egress diagnostics for a node's outbound IP family.
//
// Two kinds of measurement are kept apart, because mixing them is how a test lies:
//
//   - "host" results come from this server's own network stack, without the node. They say what
//     the VPS can do (routes, DNS, its own public addresses). They are labelled as host tests and
//     are never presented as the node's behaviour.
//   - "node" results come through the node's own inbound, using the same client path the protocol
//     test uses (a temporary sing-box client dialing the node on loopback), so the request leaves
//     through the node's real outbound with its real policy.
//
// A policy is only reported as verified when both agree: a family must fail through the node
// while the same kind of request succeeds from the host. If the host cannot do it either, the
// result is "inconclusive", never "pass".

// Result of one verification or of the whole test.
const (
	egressPass         = "pass"
	egressFail         = "fail"
	egressInconclusive = "inconclusive"
	egressInfo         = "info"
)

// EgressCheck is one verification, in the user's language.
type EgressCheck struct {
	Key    string `json:"key"`
	Status string `json:"status"`
	Text   string `json:"text"`
}

// EgressHostFamily is what this server can do for one IP family, measured without the node.
type EgressHostFamily struct {
	Route bool   `json:"route"`
	DNS   bool   `json:"dns"`
	IP    string `json:"ip,omitempty"`
}

// EgressNodeFamily is what a request through the node achieved for one IP family.
type EgressNodeFamily struct {
	IP    string `json:"ip,omitempty"`
	Error string `json:"error,omitempty"`
	// LiteralTried says whether a request to a bare IP address of this family was made through the
	// node, and LiteralOK whether it succeeded. That request is what a resolver strategy alone
	// does not cover.
	LiteralTried bool `json:"literal_tried"`
	LiteralOK    bool `json:"literal_ok"`
}

// EgressReport is the outcome of NodeEgressTest.
type EgressReport struct {
	Policy      string `json:"policy"`
	PolicyLabel string `json:"policy_label"`
	Scope       string `json:"scope"`
	Enforced    bool   `json:"enforced"`
	Note        string `json:"note,omitempty"`
	Quick       bool   `json:"quick"`
	Host        struct {
		V4 EgressHostFamily `json:"v4"`
		V6 EgressHostFamily `json:"v6"`
	} `json:"host"`
	Node struct {
		V4    EgressNodeFamily `json:"v4"`
		V6    EgressNodeFamily `json:"v6"`
		Error string           `json:"error,omitempty"`
	} `json:"node"`
	Checks []EgressCheck `json:"checks"`
	Result string        `json:"result"`
}

// egressProbe is the raw outcome of the requests through the node.
type egressProbe struct {
	V4, V6       string
	ErrV4, ErrV6 error
	Lit4, Lit6   literalProbe
	ClientErr    error
	LogHint      string
	// Aborted is set when the temporary client stopped before every request was made (its
	// lifetime is bounded). A request that failed because the client was gone says nothing about
	// the node, so such a measurement is never used as evidence of anything.
	Aborted bool
}

type literalProbe struct {
	Tried bool
	Err   error
}

// literalTarget is a bare IP address plus the Host header that makes the server answer with the
// caller's address. Port defaults to 80.
type literalTarget struct{ IP, Host, Port string }

// egressEnv is everything the test touches outside plain computation.
type egressEnv struct {
	routes func() familyRoutes
	// hostIP is this server's own public address of a family ("" when it has none).
	hostIP func(network string) string
	// hostDNS says whether the system resolver returns an address of the family for the test name.
	hostDNS func(network string) bool
	// literals returns the bare-address targets, empty when the test names do not resolve.
	literals func() map[string]literalTarget
	// hostLiteral requests a literal target directly from the host (the control).
	hostLiteral func(network string, t literalTarget) error
	// through requests the echo endpoints and the literals through the node.
	through func(a *App, p Profile, host string, port int, quick bool, lit map[string]literalTarget) egressProbe
}

func defaultEgressEnv() egressEnv {
	return egressEnv{
		routes:      hostRoutes,
		hostIP:      detectDirect,
		hostDNS:     hostResolves,
		literals:    resolveLiterals,
		hostLiteral: func(network string, t literalTarget) error { _, e := fetchLiteral("", network, t); return e },
		through:     probeThroughNode,
	}
}

// echoHosts are the names whose DNS records are single-family on purpose.
var echoHosts = map[string]string{"tcp4": "api4.ipify.org", "tcp6": "api6.ipify.org"}

func hostResolves(network string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, e := net.DefaultResolver.LookupIP(ctx, strings.Replace(network, "tcp", "ip", 1), echoHosts[network])
	return e == nil && len(ips) > 0
}

// resolveLiterals resolves the echo names on the host and returns their addresses, so a request to
// the bare address can be made through the node.
func resolveLiterals() map[string]literalTarget {
	out := map[string]literalTarget{}
	for network, name := range echoHosts {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		ips, e := net.DefaultResolver.LookupIP(ctx, strings.Replace(network, "tcp", "ip", 1), name)
		cancel()
		if e == nil && len(ips) > 0 {
			out[network] = literalTarget{IP: ips[0].String(), Host: name}
		}
	}
	return out
}

// fetchLiteral asks a bare IP address for the caller's address. With a proxy address the request
// goes through it; without, directly over the given family.
func fetchLiteral(proxyAddress, network string, t literalTarget) (string, error) {
	transport := &http.Transport{Proxy: nil}
	if proxyAddress != "" {
		u, e := url.Parse(proxyAddress)
		if e != nil {
			return "", e
		}
		transport.Proxy = http.ProxyURL(u)
	} else {
		d := &net.Dialer{Timeout: 5 * time.Second}
		transport.DialContext = func(ctx context.Context, _, addr string) (net.Conn, error) { return d.DialContext(ctx, network, addr) }
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 12 * time.Second}
	port := t.Port
	if port == "" {
		port = "80"
	}
	req, e := http.NewRequest("GET", "http://"+net.JoinHostPort(t.IP, port)+"/", nil)
	if e != nil {
		return "", e
	}
	req.Host = t.Host
	r, e := client.Do(req)
	if e != nil {
		return "", classifyFetch(e)
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return "", &fetchError{Kind: fetchHTTP, Status: r.StatusCode}
	}
	b, e := io.ReadAll(io.LimitReader(r.Body, 128))
	if e != nil {
		return "", e
	}
	ip := strings.TrimSpace(string(b))
	if net.ParseIP(ip) == nil {
		return "", &fetchError{Kind: fetchNotIP}
	}
	return ip, nil
}

// probeThroughNode runs the requests through the node's own inbound with a temporary client.
func probeThroughNode(a *App, p Profile, host string, port int, quick bool, lit map[string]literalTarget) egressProbe {
	var out egressProbe
	local, e := freePort()
	if e != nil {
		out.ClientErr = e
		return out
	}
	conf, e := ClientConfig(p, host, port, local)
	if e != nil {
		out.ClientErr = e
		return out
	}
	out.ClientErr = a.withClientLog(conf, local, func(proxy string, logs func() string) error {
		out = measureThroughProxy(proxy, quick, lit, probeFetchers{
			name:    func(proxy, network string) (string, error) { return fetchEcho(proxy, network) },
			literal: func(proxy, network string, t literalTarget) error { _, e := fetchLiteral(proxy, network, t); return e },
			alive:   func(proxy string) bool { return proxyListening(proxy) },
		})
		out.LogHint = classifyClientLog(logs())
		return nil
	})
	return out
}

// probeFetchers are the requests of a measurement, replaceable in tests.
type probeFetchers struct {
	name    func(proxy, network string) (string, error)
	literal func(proxy, network string, t literalTarget) error
	// alive says whether the temporary client still accepts connections.
	alive func(proxy string) bool
}

func fetchEcho(proxy, network string) (ip string, err error) {
	for _, endpoint := range ipEndpoints[network] {
		if ip, err = fetchIP(proxy, endpoint); err == nil {
			return ip, nil
		}
	}
	return ip, err
}

// proxyListening reports whether the local client still accepts connections.
func proxyListening(proxy string) bool {
	u, e := url.Parse(proxy)
	if e != nil {
		return false
	}
	c, e := net.DialTimeout("tcp", u.Host, time.Second)
	if e != nil {
		return false
	}
	c.Close()
	return true
}

// measureThroughProxy makes the requests, one family after the other. The temporary client lives
// for a bounded time (withClientLog), and the requests together can outlast it: after it is gone
// every request fails with "connection refused", which must not be mistaken for the node refusing
// the family. A success proves the path, so it needs no check; a FAILURE counts as a measurement
// only if the client is verified alive after it. Otherwise the measurement is aborted.
func measureThroughProxy(proxy string, quick bool, lit map[string]literalTarget, f probeFetchers) egressProbe {
	var out egressProbe
	for _, fam := range []struct {
		network string
		ip      *string
		err     *error
		literal *literalProbe
	}{{"tcp4", &out.V4, &out.ErrV4, &out.Lit4}, {"tcp6", &out.V6, &out.ErrV6, &out.Lit6}} {
		ip, er := f.name(proxy, fam.network)
		if er != nil && !f.alive(proxy) {
			out.Aborted = true
			return out
		}
		*fam.ip, *fam.err = ip, er
		if t, ok := lit[fam.network]; ok && !quick {
			le := f.literal(proxy, fam.network, t)
			if le != nil && !f.alive(proxy) {
				out.Aborted = true
				return out
			}
			*fam.literal = literalProbe{Tried: true, Err: le}
		}
	}
	return out
}

// NodeEgressTest measures a running node's outbound path against its policy. quick only reports
// the node's addresses and skips the policy verification.
func (a *App) NodeEgressTest(id string, quick bool) (EgressReport, error) {
	return a.nodeEgressTest(id, quick, defaultEgressEnv())
}

func (a *App) nodeEgressTest(id string, quick bool, env egressEnv) (EgressReport, error) {
	s, e := a.Load()
	if e != nil {
		return EgressReport{}, e
	}
	p, e := Find(s, id)
	if e != nil {
		return EgressReport{}, e
	}
	if p.Kind != "node" {
		return EgressReport{}, errors.New("只有节点有出站网络策略；中转请在『修改网络』中设置")
	}
	if p.snellNode() {
		return EgressReport{}, errNoClientConfig
	}
	if !p.Enabled {
		return EgressReport{}, errors.New("节点已停用")
	}
	var rep EgressReport
	info := p.egressInfo()
	rep.Policy, rep.PolicyLabel, rep.Scope, rep.Enforced, rep.Quick = info.Policy, a.T(outboundLabel(info.Policy)), info.Scope, info.Enforced, quick
	rep.Note = a.T(p.egressScopeNote())

	// Host measurements: what this server itself can do. Not the node.
	routes := env.routes()
	rep.Host.V4.Route, rep.Host.V6.Route = routes.V4, routes.V6
	var wg sync.WaitGroup
	for _, m := range []struct {
		network string
		to      *EgressHostFamily
	}{{"tcp4", &rep.Host.V4}, {"tcp6", &rep.Host.V6}} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.to.DNS, m.to.IP = env.hostDNS(m.network), env.hostIP(m.network)
		}()
	}
	wg.Wait()

	// Node measurements: through the node's own inbound.
	var lit map[string]literalTarget
	if !quick {
		lit = env.literals()
	}
	probe := env.through(a, p, loopbackFor(p), p.Port, quick, lit)
	if probe.ClientErr != nil {
		rep.Node.Error = a.Error(probe.ClientErr)
	}
	rep.Node.V4 = a.nodeFamily(probe.V4, probe.ErrV4, probe.Lit4)
	rep.Node.V6 = a.nodeFamily(probe.V6, probe.ErrV6, probe.Lit6)

	// Controls for the literal checks: the same request made from the host.
	hostLit := map[string]bool{}
	if !quick {
		for network, t := range lit {
			hostLit[network] = env.hostLiteral(network, t) == nil
		}
	}
	rep.Checks = a.egressChecks(p, rep, probe, hostLit)
	if !quick || probe.Aborted {
		// A quick look only lists addresses; it proves nothing, so it carries no verdict (unless
		// it could not even finish, which is worth saying).
		rep.Result = overallEgress(rep.Checks)
	}
	return rep, nil
}

func (a *App) nodeFamily(ip string, err error, lit literalProbe) EgressNodeFamily {
	out := EgressNodeFamily{IP: ip, LiteralTried: lit.Tried, LiteralOK: lit.Tried && lit.Err == nil}
	if err != nil {
		out.IP = ""
		out.Error = a.T(classifyFetch(err).Error())
	}
	return out
}

func overallEgress(checks []EgressCheck) string {
	pass, inconclusive := 0, 0
	for _, c := range checks {
		switch c.Status {
		case egressFail:
			return egressFail
		case egressInconclusive:
			inconclusive++
		case egressPass:
			pass++
		}
	}
	switch {
	case inconclusive > 0:
		return egressInconclusive
	case pass > 0:
		return egressPass
	}
	return egressInconclusive
}

func (a *App) egressText(format string, args ...any) string {
	text := a.T(format)
	if len(args) > 0 {
		text = fmt.Sprintf(text, args...)
	}
	return text
}

// egressChecks turns the measurements into verifications. It is deterministic given its inputs,
// which is what the unit tests exercise.
func (a *App) egressChecks(p Profile, rep EgressReport, probe egressProbe, hostLit map[string]bool) []EgressCheck {
	var out []EgressCheck
	add := func(key, status, format string, args ...any) {
		out = append(out, EgressCheck{Key: key, Status: status, Text: a.egressText(format, args...)})
	}
	n4, n6 := rep.Node.V4, rep.Node.V6
	if probe.ClientErr != nil {
		add("client", egressFail, "无法经由节点发起检测请求：%s", a.Error(probe.ClientErr))
		return out
	}
	if probe.Aborted {
		// What was measured before the client stopped is not enough to say anything, and what
		// failed after it stopped says nothing about the node.
		add("aborted", egressInconclusive, "检测客户端在测量完成前已停止（检测站点响应过慢）；未完成的测量不能作为证据，结果不可靠，请稍后重试")
		return out
	}
	// what the node actually achieved, per family
	for _, f := range []struct {
		key, label string
		n          EgressNodeFamily
	}{{"node_v4", "IPv4", n4}, {"node_v6", "IPv6", n6}} {
		if f.n.IP != "" {
			add(f.key, egressInfo, "经节点的实际出口 %s：%s", f.label, f.n.IP)
		} else {
			add(f.key, egressInfo, "经节点的实际出口 %s：不可用 — %s", f.label, f.n.Error)
		}
	}
	if rep.Quick {
		return out
	}
	if rep.Scope == egressScopeProxy && rep.Policy != outAuto {
		// The family towards the website is the proxy's decision; the policy only governed the
		// connection to the proxy server, and that cannot be observed from here.
		add("scope", egressInconclusive, "该节点使用出站代理：策略只限制本机连接代理服务器的 IP 类型，网站侧使用哪种 IP 由代理决定，Rout 无法验证策略是否被遵守")
		if n4.IP == "" && n6.IP == "" {
			add("reach", egressFail, "经出站代理无法访问互联网")
		} else {
			add("reach", egressPass, "经出站代理可以访问互联网")
		}
		return out
	}
	switch p.outboundPolicy() {
	case outIPv6Only:
		a.onlyChecks(&out, "IPv6", "IPv4", rep.Host.V6, rep.Host.V4, n6, n4, hostLit["tcp4"], probe.Lit4)
	case outIPv4Only:
		a.onlyChecks(&out, "IPv4", "IPv6", rep.Host.V4, rep.Host.V6, n4, n6, hostLit["tcp6"], probe.Lit6)
	default:
		if n4.IP == "" && n6.IP == "" {
			add("reach", egressFail, "两个 IP 类型都无法经由此节点访问互联网")
		} else {
			add("reach", egressPass, "经此节点可以访问互联网")
		}
		if pol := p.outboundPolicy(); pol == outIPv4First || pol == outIPv6First {
			add("preference", egressInfo, "优先策略只决定先尝试哪种 IP，不禁止另一种；不通时会回退")
		}
	}
	return out
}

// onlyChecks verifies an "only" policy: the allowed family works through the node, the forbidden
// family fails through the node while the host can do it, for names and for bare addresses.
func (a *App) onlyChecks(out *[]EgressCheck, allowed, denied string, hostAllowed, hostDenied EgressHostFamily, nodeAllowed, nodeDenied EgressNodeFamily, hostDeniedLiteral bool, deniedLit literalProbe) {
	add := func(key, status, format string, args ...any) {
		*out = append(*out, EgressCheck{Key: key, Status: status, Text: a.egressText(format, args...)})
	}
	switch {
	case nodeAllowed.IP != "":
		add("allowed", egressPass, "%s 连接成功：经节点的实际出口 %s 是 %s", allowed, allowed, nodeAllowed.IP)
	case !hostAllowed.Route:
		add("allowed", egressFail, "本机没有 %s 出站路由，节点无法访问任何站点", allowed)
	default:
		add("allowed", egressFail, "%s 连接失败：%s", allowed, nodeAllowed.Error)
	}
	switch {
	case nodeDenied.IP != "":
		add("denied_name", egressFail, "策略未生效：经节点仍能通过 %s 访问互联网（出口 %s）", denied, nodeDenied.IP)
	case hostDenied.IP != "":
		add("denied_name", egressPass, "%s 回退已禁止：本机直连可以使用 %s，经节点则不能", denied, denied)
	default:
		add("denied_name", egressInconclusive, "无法证明 %s 被策略阻止：本机直连也无法使用 %s", denied, denied)
	}
	if !deniedLit.Tried {
		add("denied_literal", egressInconclusive, "未能验证 %s 地址直连是否被拒绝（测试站点的域名没有解析出 %s 地址）", denied, denied)
		return
	}
	switch {
	case deniedLit.Err == nil:
		add("denied_literal", egressFail, "策略未生效：经节点仍能直接访问 %s 地址", denied)
	case hostDeniedLiteral:
		add("denied_literal", egressPass, "%s 地址直连已被拒绝：本机直连同一地址可以访问，经节点则不能", denied)
	default:
		add("denied_literal", egressInconclusive, "无法证明 %s 地址直连被策略拒绝：本机直连同一地址也不通", denied)
	}
}
