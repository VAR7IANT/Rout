package rout

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strings"
	"syscall"
	"time"
)

// Layered diagnostics.
//
// A relay or an outbound can fail at six different places, and "it did not work" helps
// nobody. Each layer is tested separately, in this order, and reports what it proved:
//
//	1  local listening      the sockets are really bound (read from the kernel), per family
//	2  target resolution    what the name resolves to, and whether the outbound policy fits
//	3  target connectivity  TCP handshake / QUIC probe to the destination itself
//	4  relay availability   a connection through the relay's own entry reaches the target
//	5  proxy protocol       the protocol handshake (TLS camouflage, authentication)
//	6  real exit            a request through the whole chain: IPv4 / IPv6 exit address
//
// A layer is never reported as passed because a lower one passed: an open port proves the
// port, not the protocol.

type diagLevel int

const (
	diagOK diagLevel = iota
	diagWarn
	diagFail
	diagInfo
)

type diagStep struct {
	Layer int
	Level diagLevel
	Text  string // already translated and formatted
}

type diagReport struct{ Steps []diagStep }

var diagLayerNames = map[int]string{1: "本地监听", 2: "目标解析", 3: "目标连通", 4: "中转可用性", 5: "代理协议", 6: "实际出口"}

func (r diagReport) Failed() (layer int, ok bool) {
	for _, s := range r.Steps {
		if s.Level == diagFail {
			return s.Layer, true
		}
	}
	return 0, false
}
func (r diagReport) Has(layer int, level diagLevel) bool {
	for _, s := range r.Steps {
		if s.Layer == layer && s.Level == level {
			return true
		}
	}
	return false
}
func (r diagReport) Count(level diagLevel) int {
	n := 0
	for _, s := range r.Steps {
		if s.Level == level {
			n++
		}
	}
	return n
}
func (r diagReport) Text() string {
	var b strings.Builder
	for _, s := range r.Steps {
		fmt.Fprintf(&b, "L%d %s\n", s.Layer, s.Text)
	}
	return b.String()
}

type diagger struct {
	a   *App
	rep *diagReport
}

// add records a step. tmpl is a translatable template; args fill it after translation.
func (d diagger) add(layer int, level diagLevel, tmpl string, args ...any) {
	text := d.a.T(tmpl)
	if len(args) > 0 {
		text = fmt.Sprintf(text, args...)
	}
	d.rep.Steps = append(d.rep.Steps, diagStep{Layer: layer, Level: level, Text: text})
}

// diagEnv is everything the diagnostics touch outside plain computation, so tests can
// replace any part (the kernel socket table, the dialer, the engine-based probe).
type diagEnv struct {
	sockets   func() ([]sockEntry, error)
	managed   func(a *App, p Profile) (managed, up bool)
	newDialer func(policy string) *PolicyDialer
	local     func() map[string]bool
	hasV6     func() bool
	quicProbe func(ctx context.Context, network, addr string) error
	tlsCheck  func(ctx context.Context, addr, sni string) error
	// full performs the engine-based protocol test through entryAddr; nil skips layers 5-6.
	full func(a *App, p Profile, entryHost string, entryPort int) fullProbe
	// fullProxy requests the exit addresses through an outbound proxy using the engine.
	fullProxy func(a *App, p Proxy) fullProbe
}

func defaultDiagEnv() diagEnv {
	return diagEnv{
		sockets: readSockets,
		managed: func(a *App, p Profile) (bool, bool) {
			m, e := a.serviceManager()
			if e != nil || m == "none" {
				return false, false
			}
			return true, serviceActive(m, serviceName(p))
		},
		newDialer: NewPolicyDialer,
		local:     localIPs,
		hasV6:     ipv6LoopbackWorks,
		quicProbe: quicVersionProbe,
		tlsCheck:  tlsCamouflageCheck,
		full:      func(a *App, p Profile, host string, port int) fullProbe { return a.fullProbeThrough(p, host, port) },
		fullProxy: func(a *App, p Proxy) fullProbe { return a.fullProbeProxy(p) },
	}
}

func ipv6LoopbackWorks() bool {
	l, e := net.Listen("tcp6", "[::1]:0")
	if e != nil {
		return false
	}
	l.Close()
	return true
}

// ---- layer 1: local listening ----------------------------------------------------------------

type expectedSocket struct {
	Network string
	IP      string
	Port    int
}

// expectedSockets are the sockets an entry must have bound. A native relay is explicit;
// for a legacy entry the engine decides, so the expectation follows its listening address.
func expectedSockets(p Profile) []expectedSocket {
	var out []expectedSocket
	if p.nativeRelay() {
		for _, s := range p.bindSpecs() {
			out = append(out, expectedSocket{s.Network, s.IP, s.Port})
		}
		return out
	}
	fam := "4"
	if ip := net.ParseIP(p.Listen); ip != nil && ip.To4() == nil {
		fam = "6"
	}
	for _, n := range p.Networks() {
		out = append(out, expectedSocket{n + fam, p.Listen, p.Port})
	}
	return out
}

func (d diagger) layerListen(env diagEnv, p Profile) (bound bool) {
	managed, up := env.managed(d.a, p)
	if managed && !up {
		d.add(1, diagFail, "中转服务未运行；运行 rout logs %s 查看原因", p.ID)
		return false
	}
	socks, e := env.sockets()
	if e != nil {
		d.add(1, diagWarn, "无法读取内核套接字表，未能核对监听状态")
		return true
	}
	all := true
	for _, want := range expectedSockets(p) {
		var found *sockEntry
		for i := range socks {
			s := socks[i]
			if s.Port != want.Port || s.Network != want.Network {
				continue
			}
			if ip, er := netip.ParseAddr(want.IP); er == nil && (ip.IsUnspecified() == s.IP.IsUnspecified()) && (ip.IsUnspecified() || ip == s.IP) {
				found = &s
				break
			}
		}
		label := strings.ToUpper(want.Network[:3]) + " " + net.JoinHostPort(want.IP, itoa(want.Port)) + " (" + familyName(want.Network) + ")"
		if found == nil {
			// A kernel without IPv6 binds a requested wildcard on IPv4 instead; report what is real.
			d.add(1, diagFail, "%s 没有在监听", label)
			all = false
			continue
		}
		if found.Dual && !p.nativeRelay() {
			d.add(1, diagOK, "%s 已监听（IPv6 通配套接字，可能同时接受 IPv4）", label)
		} else {
			d.add(1, diagOK, "%s 已监听", label)
		}
	}
	// An exclusive mode must not leave the other family's socket open on the same port.
	if p.nativeRelay() {
		v4, v6 := inboundAllows(p.inboundMode())
		for _, s := range socks {
			if s.Port != p.Port || !contains(p.Networks(), s.Network[:3]) {
				continue
			}
			if (s.Network[3] == '4' && !v4) || (s.Network[3] == '6' && !v6) {
				d.add(1, diagWarn, "端口 %d 上存在不属于入站模式「%s」的 %s 套接字：%s", p.Port, inboundLabel(p.inboundMode()), familyName(s.Network), strings.ToUpper(s.Network[:3])+" "+s.Addr())
			}
		}
	}
	return all
}

// ---- layers 2 and 3: the destination ------------------------------------------------------

func familySummary(addrs []netip.Addr) (v4, v6 []string) {
	for _, a := range addrs {
		if a.Is4() {
			v4 = append(v4, a.String())
		} else {
			v6 = append(v6, a.String())
		}
	}
	sort.Strings(v4)
	sort.Strings(v6)
	return
}
func joinOrNone(a *App, list []string) string {
	if len(list) == 0 {
		return a.T("无")
	}
	return strings.Join(list, ", ")
}

// dialFailure explains a failed connect in words, naming the kind and what was tried.
func (d diagger) dialFailure(layer int, err error, rep DialReport) {
	var de *DialError
	if !errors.As(err, &de) {
		d.add(layer, diagFail, "连接失败：%s", err.Error())
		return
	}
	tried := ""
	if len(rep.Attempts) > 0 {
		var parts []string
		for _, at := range rep.Attempts {
			parts = append(parts, at.Addr.String()+" "+d.attemptKind(at.Kind))
		}
		tried = "（" + d.a.T("已尝试：") + strings.Join(parts, "；") + "）"
	}
	switch de.Kind {
	case kindDNS:
		cause := d.a.T("域名不存在或没有记录")
		var dns *net.DNSError
		if errors.As(de.Err, &dns) && (dns.IsTimeout || dns.IsTemporary) {
			cause = d.a.T("DNS 服务器无应答（超时或暂时故障）")
		}
		d.add(layer, diagFail, "域名解析失败：%s — %s", de.Target, cause)
	case kindNoAddress, kindFamily:
		d.add(layer, diagFail, "没有符合出站策略的目标地址：%s", de.Target)
	case kindRefused:
		d.add(layer, diagFail, "目标拒绝连接（端口未开放，或服务未运行）：%s%s", de.Target, tried)
	case kindTimeout:
		d.add(layer, diagFail, "连接超时（目标不可达，或被防火墙丢弃）：%s%s", de.Target, tried)
	case kindUnreachable:
		d.add(layer, diagFail, "本机没有到目标的路由：%s%s", de.Target, tried)
	case kindLoop:
		d.add(layer, diagFail, "目标指向本中转自身，会形成转发循环：%s", de.Target)
	default:
		d.add(layer, diagFail, "无法连接目标：%s%s", de.Target, tried)
	}
}
func (d diagger) attemptKind(kind string) string {
	switch kind {
	case kindRefused:
		return d.a.T("被拒绝")
	case kindTimeout:
		return d.a.T("超时")
	case kindUnreachable:
		return d.a.T("无路由")
	case kindLoop:
		return d.a.T("循环")
	}
	return d.a.T("失败")
}

// layerTarget runs layers 2 and 3 for a remote destination, returning the dialer report of
// a successful TCP connection (zero when TCP was not tested or failed).
func (d diagger) layerTarget(ctx context.Context, env diagEnv, p Profile) (reachedTCP bool, rep DialReport) {
	host, port, e := ParseEndpoint(p.Target)
	if e != nil {
		d.add(2, diagFail, "目标地址无效")
		return false, rep
	}
	policy := p.outboundPolicy()
	dialer := env.newDialer(policy)
	// Layer 2: resolution. Both families are looked up so the report shows what exists,
	// then the policy decides what may be used.
	if ip, er := netip.ParseAddr(host); er == nil {
		ip = ip.Unmap()
		d.add(2, diagInfo, "目标是 %s 地址 %s（出站策略：%s）", ipFamilyLabel(ip), ip.String(), d.a.T(outboundLabel(policy)))
		v4, v6 := outboundAllows(policy)
		if (ip.Is4() && !v4) || (ip.Is6() && !v6) {
			d.add(2, diagFail, "目标地址族与出站策略「%s」不符", d.a.T(outboundLabel(policy)))
			return false, rep
		}
	} else {
		res, er := dialer.Resolver.Resolve(ctx, host, true, true)
		if er != nil {
			d.dialFailure(2, er, DialReport{})
			return false, rep
		}
		v4, v6 := familySummary(res.Addrs)
		d.add(2, diagOK, "域名 %s 解析为 IPv4: %s；IPv6: %s", host, joinOrNone(d.a, v4), joinOrNone(d.a, v6))
		if res.Stale {
			d.add(2, diagWarn, "DNS 暂时不可用，使用了 %d 秒前的解析结果", int(res.Age.Seconds()))
		}
		allow4, allow6 := outboundAllows(policy)
		usable := (allow4 && len(v4) > 0) || (allow6 && len(v6) > 0)
		switch {
		case !usable:
			d.add(2, diagFail, "出站策略「%s」没有可用的地址（该域名没有对应地址族的记录）", d.a.T(outboundLabel(policy)))
			return false, rep
		case policy == outIPv6First && len(v6) == 0, policy == outIPv4First && len(v4) == 0:
			d.add(2, diagWarn, "偏好的地址族没有记录，将使用另一个地址族")
		default:
			d.add(2, diagOK, "地址族策略「%s」与解析结果匹配", d.a.T(outboundLabel(policy)))
		}
		// A destination that resolves to this very host is a forwarding loop in disguise.
		loc := env.local()
		for _, a := range res.Addrs {
			if port == p.Port && (a.IsLoopback() || loc[a.String()]) {
				d.add(3, diagFail, "域名解析到本机地址 %s，目标端口就是本中转的监听端口，会形成转发循环", a.String())
				return false, rep
			}
		}
	}
	// Layer 3: the destination itself.
	for _, n := range p.Networks() {
		if n == "udp" {
			d.layerUDPTarget(ctx, env, p, dialer, host, port)
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, relayDialTimeout+2*time.Second)
		start := time.Now()
		c, r, er := dialer.DialContext(cctx, p.Target)
		cancel()
		if er != nil {
			d.dialFailure(3, er, r)
			continue
		}
		c.Close()
		rep, reachedTCP = r, true
		d.add(3, diagOK, "TCP 连接成功：%s %s（%d ms）", ipFamilyLabel(r.Used.Addr()), r.Used.String(), time.Since(start).Milliseconds())
	}
	return reachedTCP, rep
}

func (d diagger) layerUDPTarget(ctx context.Context, env diagEnv, p Profile, dialer *PolicyDialer, host string, port int) {
	if quicProtocolName(p.TargetURI) == "" {
		d.add(3, diagWarn, "UDP 没有连接握手，无法用连通性测试验证；请用实际客户端确认")
		return
	}
	// Hysteria2 and TUIC are QUIC: any QUIC endpoint answers a long-header packet of an
	// unknown version with a Version Negotiation packet (RFC 9000 §6), which is a real
	// UDP round trip that needs no credentials.
	conn, rep, e := dialer.DialUDP(ctx, p.Target)
	if e != nil {
		d.dialFailure(3, e, rep)
		return
	}
	addr := conn.RemoteAddr().String()
	network := "udp4"
	if rep.Used.Addr().Is6() {
		network = "udp6"
	}
	conn.Close()
	switch er := env.quicProbe(ctx, network, addr); {
	case er == nil:
		d.add(3, diagOK, "UDP 目标响应了 QUIC 版本协商（%s %s，QUIC 服务在线）", ipFamilyLabel(rep.Used.Addr()), addr)
	case errors.Is(er, syscall.ECONNREFUSED):
		d.add(3, diagFail, "UDP 端口无服务（收到 ICMP 端口不可达）：%s", addr)
	case errors.Is(er, errNoQUICAnswer):
		d.add(3, diagWarn, "目标没有响应 QUIC 探测（UDP 被过滤、服务未运行，或启用了混淆）；无法确认 UDP 是否可达")
	default:
		d.add(3, diagWarn, "QUIC 探测出错：%s", er.Error())
	}
}

// ---- layer 4: through the relay ------------------------------------------------------

// entryAddrs are the loopback addresses a test client uses to reach the relay's own entry,
// one per family the relay serves.
func entryAddrs(p Profile, hasV6 bool) []string {
	var out []string
	if p.nativeRelay() {
		v4, v6 := inboundAllows(p.inboundMode())
		if v4 {
			out = append(out, "127.0.0.1")
		}
		if v6 && hasV6 {
			out = append(out, "::1")
		}
		if ip := net.ParseIP(p.Listen); ip != nil && !ip.IsUnspecified() {
			return []string{p.Listen}
		}
		return out
	}
	switch ip := net.ParseIP(p.Listen); {
	case ip == nil, ip.To4() != nil && ip.IsUnspecified():
		return []string{"127.0.0.1"}
	case ip.IsUnspecified():
		return []string{"127.0.0.1", "::1"} // legacy "::" is a dual-stack wildcard
	}
	return []string{p.Listen}
}

func (d diagger) layerRelay(ctx context.Context, env diagEnv, p Profile, target DialReport, targetTCP bool) (okEntry string) {
	for _, host := range entryAddrs(p, env.hasV6()) {
		entry := net.JoinHostPort(host, itoa(p.Port))
		fam := "IPv4"
		if strings.Contains(host, ":") {
			fam = "IPv6"
		}
		for _, n := range p.Networks() {
			if n == "udp" {
				if d.layerRelayUDP(ctx, env, p, entry, fam) {
					okEntry = host
				}
				continue
			}
			if !targetTCP {
				d.add(4, diagInfo, "目标 TCP 不可达，跳过经由中转的测试（%s 入口 %s）", fam, entry)
				continue
			}
			path := fmt.Sprintf(d.a.T("入站 %s"), fam)
			if target.Used.IsValid() {
				path = fmt.Sprintf(d.a.T("入站 %s → 出站 %s"), fam, ipFamilyLabel(target.Used.Addr()))
			}
			switch r := probeThroughTCP(ctx, entry); r.kind {
			case relayRefused:
				d.add(4, diagFail, "中转入口 %s 拒绝连接（%s 入口没有服务）", entry, fam)
			case relayClosedEarly:
				d.add(4, diagFail, "中转接受了连接但目标侧立即关闭（%s 入口 %s）：中转无法连上目标，或目标不是 TCP 服务", fam, entry)
			case relayData:
				d.add(4, diagOK, "经由中转收到目标的数据：%s", path)
				okEntry = host
			case relayHeld:
				d.add(4, diagOK, "经由中转到达目标，连接保持（服务器在等待客户端数据）：%s", path)
				okEntry = host
			default:
				d.add(4, diagWarn, "无法确认经由中转的连接：%s", r.err.Error())
			}
		}
	}
	return okEntry
}

// layerRelayUDP probes a UDP entry. It reports whether the entry may go on to the protocol
// and exit layers: everything except a definite failure does, because a QUIC server that
// does not answer the probe (filtering, obfuscation) is inconclusive, and the engine-based
// test is the real check for it.
func (d diagger) layerRelayUDP(ctx context.Context, env diagEnv, p Profile, entry, fam string) bool {
	if quicProtocolName(p.TargetURI) == "" {
		d.add(4, diagInfo, "UDP 经由中转的转发无法在没有协议信息时验证（%s 入口 %s）", fam, entry)
		return true
	}
	network := "udp4"
	if fam == "IPv6" {
		network = "udp6"
	}
	switch e := env.quicProbe(ctx, network, entry); {
	case e == nil:
		d.add(4, diagOK, "UDP 经由中转得到 QUIC 响应（%s 入口 %s）", fam, entry)
		return true
	case errors.Is(e, errNoQUICAnswer):
		d.add(4, diagWarn, "UDP 经由中转没有得到 QUIC 响应（%s 入口 %s）；目标可能过滤了 UDP 或启用了混淆", fam, entry)
		return true
	default:
		d.add(4, diagFail, "UDP 经由中转的探测失败（%s 入口 %s）：%s", fam, entry, e.Error())
	}
	return false
}

type relayProbeKind int

const (
	relayUnknown relayProbeKind = iota
	relayRefused
	relayClosedEarly
	relayData
	relayHeld
)

type relayProbe struct {
	kind relayProbeKind
	err  error
}

// probeThroughTCP connects to a relay's entry and watches the connection for a short
// time. A relay dials its destination right after accepting; if that fails it closes the
// client at once. A connection that stays open (or that delivers the server's first bytes)
// therefore means the destination really accepted it. This works for any TCP service
// without knowing its protocol, and for any relay engine.
func probeThroughTCP(ctx context.Context, entry string) relayProbe {
	d := net.Dialer{Timeout: 2 * time.Second}
	c, e := d.DialContext(ctx, "tcp", entry)
	if e != nil {
		if errors.Is(e, syscall.ECONNREFUSED) {
			return relayProbe{kind: relayRefused, err: e}
		}
		return relayProbe{err: e}
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	buf := make([]byte, 1)
	n, e := c.Read(buf)
	switch {
	case n > 0:
		return relayProbe{kind: relayData}
	case e == nil:
		return relayProbe{kind: relayUnknown, err: errors.New("empty read")}
	case errors.Is(e, os.ErrDeadlineExceeded):
		return relayProbe{kind: relayHeld}
	case errors.Is(e, io.EOF), errors.Is(e, syscall.ECONNRESET), errors.Is(e, syscall.EPIPE):
		return relayProbe{kind: relayClosedEarly, err: e}
	}
	return relayProbe{err: e}
}

// ---- QUIC and TLS probes ---------------------------------------------------------------

var errNoQUICAnswer = errors.New("no QUIC answer")

// quicVersionProbe sends a 1200-byte QUIC long-header packet with a reserved "greasing"
// version and waits for the Version Negotiation reply that every QUIC server must send. A
// reply proves a QUIC endpoint is alive at that UDP address and that datagrams make the
// round trip. No reply is inconclusive (filtering, obfuscation), never a failure by itself.
func quicVersionProbe(ctx context.Context, network, addr string) error {
	var nd net.Dialer
	c, e := nd.DialContext(ctx, network, addr)
	if e != nil {
		return e
	}
	defer c.Close()
	pkt := make([]byte, 1200)
	dcid := make([]byte, 8)
	scid := make([]byte, 8)
	_, _ = rand.Read(dcid)
	_, _ = rand.Read(scid)
	pkt[0] = 0xC0
	copy(pkt[1:5], []byte{0x1a, 0x2a, 0x3a, 0x4a}) // reserved version 0x?a?a?a?a
	pkt[5] = 8
	copy(pkt[6:14], dcid)
	pkt[14] = 8
	copy(pkt[15:23], scid)
	deadline := time.Now().Add(2 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	for attempt := 0; attempt < 2; attempt++ { // UDP can lose the probe; ask twice
		_ = c.SetWriteDeadline(deadline)
		if _, e = c.Write(pkt); e != nil {
			return e
		}
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 1500)
		n, e := c.Read(buf)
		if e != nil {
			if errors.Is(e, os.ErrDeadlineExceeded) {
				continue
			}
			return e // includes ECONNREFUSED from an ICMP port-unreachable
		}
		if isVersionNegotiation(buf[:n], scid) {
			return nil
		}
	}
	return errNoQUICAnswer
}

// isVersionNegotiation recognizes the reply to our probe: long header, version 0, and our
// source connection ID echoed back as the destination.
func isVersionNegotiation(b []byte, ourSCID []byte) bool {
	if len(b) < 7 || b[0]&0x80 == 0 || b[1] != 0 || b[2] != 0 || b[3] != 0 || b[4] != 0 {
		return false
	}
	l := int(b[5])
	return len(b) >= 6+l+1 && string(b[6:6+l]) == string(ourSCID)
}

// tlsCamouflageCheck makes a normal TLS handshake with a Reality server's camouflage name
// through an address. A genuine Reality server answers an unauthenticated client exactly as
// the real site would, so the site's real certificate verifies. This shows that something
// TLS-capable and consistent with the configured SNI is behind the address; it does not
// prove the credentials.
func tlsCamouflageCheck(ctx context.Context, addr, sni string) error {
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 4 * time.Second}, Config: &tls.Config{ServerName: sni, MinVersion: tls.VersionTLS12}}
	cctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	c, e := d.DialContext(cctx, "tcp", addr)
	if e != nil {
		return e
	}
	return c.Close()
}

// ---- layer 5 and 6: protocol and real exit ----------------------------------------------------

type fullProbe struct {
	V4, V6       string
	ErrV4, ErrV6 error
	ClientErr    error // the local client could not even start
	LogHint      string
}

func (a *App) fullProbeThrough(p Profile, host string, port int) fullProbe {
	var out fullProbe
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
		for _, f := range []struct {
			network string
			ip      *string
			err     *error
		}{{"tcp4", &out.V4, &out.ErrV4}, {"tcp6", &out.V6, &out.ErrV6}} {
			var ip string
			var er error
			for _, endpoint := range ipEndpoints[f.network] {
				if ip, er = fetchIP(proxy, endpoint); er == nil {
					break
				}
			}
			*f.ip, *f.err = ip, er
		}
		out.LogHint = classifyClientLog(logs())
		return nil
	})
	return out
}

func (d diagger) fetchWords(fe *fetchError) string {
	return d.a.T(fe.Error())
}

// layerProtocol runs the credential-free TLS check and, with an engine, the full test.
// It returns whether the protocol handshake was proved.
func (d diagger) layerProtocol(ctx context.Context, env diagEnv, p Profile, entryHost string, full bool) (proved bool) {
	entry := net.JoinHostPort(entryHost, itoa(p.Port))
	if p.TargetURI != "" {
		if u, e := url.Parse(p.TargetURI); e == nil && u.Query().Get("security") == "reality" && env.tlsCheck != nil {
			sni := u.Query().Get("sni")
			if sni == "" {
				sni = u.Hostname()
			}
			if e := env.tlsCheck(ctx, entry, sni); e != nil {
				d.add(5, diagWarn, "经由中转的 TLS 伪装握手失败（SNI %s）：目标可能不是 Reality 服务，或 SNI 与服务器不一致", sni)
			} else {
				d.add(5, diagOK, "经由中转的 TLS 伪装握手成功（SNI %s）；这不验证 UUID 和密钥", sni)
			}
		}
	}
	if !full || env.full == nil || p.TargetURI == "" {
		d.add(5, diagWarn, "尚未验证代理协议握手（端口可达不代表代理可用）")
		return false
	}
	res := env.full(d.a, p, entryHost, p.Port)
	if res.ClientErr != nil {
		d.add(5, diagWarn, "无法启动本地检测客户端：%s", d.a.Error(res.ClientErr))
		return false
	}
	return d.layerExit(res)
}

// layerExit reports layers 5 and 6 from an engine-based probe.
func (d diagger) layerExit(res fullProbe) (proved bool) {
	if res.ErrV4 == nil || res.ErrV6 == nil {
		d.add(5, diagOK, "代理协议握手成功（经由它发出的请求已得到应答）")
	} else {
		fe := classifyFetch(res.ErrV4)
		why := d.hint(res.LogHint, fe)
		d.add(5, diagFail, "协议握手或出站请求失败：%s", why)
	}
	for _, f := range []struct {
		label string
		ip    string
		err   error
	}{{"IPv4", res.V4, res.ErrV4}, {"IPv6", res.V6, res.ErrV6}} {
		if f.err == nil {
			d.add(6, diagOK, "出口 %s：%s", f.label, f.ip)
			continue
		}
		fe := classifyFetch(f.err)
		d.add(6, diagInfo, "出口 %s：不可用 — %s", f.label, d.fetchWords(fe))
	}
	switch {
	case res.ErrV4 == nil && res.ErrV6 == nil:
		d.add(6, diagInfo, "成功使用的地址族：IPv4 和 IPv6")
	case res.ErrV4 == nil:
		d.add(6, diagInfo, "成功使用的地址族：IPv4")
	case res.ErrV6 == nil:
		d.add(6, diagInfo, "成功使用的地址族：IPv6")
	default:
		d.add(6, diagFail, "两个地址族都无法经由此链路访问互联网")
	}
	return res.ErrV4 == nil || res.ErrV6 == nil
}

// hint combines the fetch error with what the client log blamed.
func (d diagger) hint(logKind string, fe *fetchError) string {
	switch logKind {
	case "reality":
		return d.a.T("Reality 握手失败（公钥、Short ID 或 SNI 与服务器不一致，或对端不是 Reality）")
	case "auth":
		return d.a.T("认证失败（UUID、密码或密钥不正确）")
	case "tls":
		return d.a.T("TLS 握手或证书错误")
	case "refused":
		return d.a.T("目标拒绝连接")
	case "timeout":
		return d.a.T("连接超时")
	case "route":
		return d.a.T("没有到目标的路由")
	case "dns":
		return d.a.T("域名解析失败")
	}
	return d.fetchWords(fe)
}

// ---- entry points ----------------------------------------------------------------------------

// diagOpts selects how far a diagnosis goes.
type diagOpts struct {
	Full bool // also run the engine-based protocol and exit test (layers 5-6)
}

// diagnoseRelay runs layers 1-6 for a relay.
func (a *App) diagnoseRelay(ctx context.Context, p Profile, env diagEnv, opts diagOpts) diagReport {
	var rep diagReport
	d := diagger{a: a, rep: &rep}
	bound := d.layerListen(env, p)
	if p.relayMode() == relayLocal || isLoopbackHost(hostOf(p.Target)) {
		d.layerLocalTarget(env, p)
		if bound {
			d.layerRelay(ctx, env, p, DialReport{}, true)
		}
		if entry := firstEntry(p, env); entry != "" && bound {
			d.layerProtocol(ctx, env, p, entry, opts.Full)
		}
		return rep
	}
	reached, tr := d.layerTarget(ctx, env, p)
	var okEntry string
	if bound {
		okEntry = d.layerRelay(ctx, env, p, tr, reached)
	} else {
		d.add(4, diagInfo, "本地监听未就绪，跳过中转可用性测试")
	}
	if okEntry != "" {
		d.layerProtocol(ctx, env, p, okEntry, opts.Full)
	} else if p.TargetURI != "" || opts.Full {
		d.add(5, diagInfo, "中转入口不可用，跳过协议测试")
	}
	if !rep.Has(5, diagOK) && !rep.Has(5, diagWarn) && !rep.Has(5, diagFail) && reached {
		d.add(5, diagWarn, "尚未验证代理协议握手（端口可达不代表代理可用）")
	}
	return rep
}

func hostOf(target string) string {
	h, _, _ := net.SplitHostPort(target)
	return h
}
func firstEntry(p Profile, env diagEnv) string {
	if e := entryAddrs(p, env.hasV6()); len(e) > 0 {
		return e[0]
	}
	return ""
}

// layerLocalTarget checks a destination on this machine against the kernel socket table.
func (d diagger) layerLocalTarget(env diagEnv, p Profile) {
	_, port, e := ParseEndpoint(p.Target)
	if e != nil {
		return
	}
	d.add(2, diagInfo, "目标是本机服务 %s", p.Target)
	socks, er := env.sockets()
	if er != nil {
		d.add(3, diagWarn, "无法读取内核套接字表")
		return
	}
	for _, n := range p.Networks() {
		var hits []string
		for _, s := range socks {
			if s.Port == port && s.Network[:3] == n && (s.IP.IsUnspecified() || s.IP.IsLoopback()) {
				hits = append(hits, s.Addr())
			}
		}
		if len(hits) == 0 {
			d.add(3, diagFail, "本机 %s 端口 %d 没有服务在监听", strings.ToUpper(n), port)
			continue
		}
		d.add(3, diagOK, "本机 %s 端口 %d 有服务在监听：%s", strings.ToUpper(n), port, strings.Join(hits, ", "))
	}
}

// ---- proxy (exit) diagnosis -----------------------------------------------------------------

// proxyHandshake performs the SOCKS5 or HTTP CONNECT handshake with credentials against a
// proxy (without the engine), so a rejected password is reported as such and not as a
// generic failure. It returns nil when the proxy accepts the credentials.
type proxyHandshakeResult int

const (
	proxyAccepted proxyHandshakeResult = iota
	proxyAuthRejected
	proxyBadReply
	proxyNoSupport
)

func proxyHandshake(ctx context.Context, conn net.Conn, p Proxy) (proxyHandshakeResult, error) {
	_ = conn.SetDeadline(time.Now().Add(6 * time.Second))
	switch p.Protocol {
	case "socks5":
		if _, e := conn.Write([]byte{5, 2, 0, 2}); e != nil { // methods: none, user/pass
			return proxyBadReply, e
		}
		rep := make([]byte, 2)
		if _, e := io.ReadFull(conn, rep); e != nil {
			return proxyBadReply, e
		}
		if rep[0] != 5 {
			return proxyBadReply, errors.New("not a SOCKS5 server")
		}
		switch rep[1] {
		case 0xFF:
			return proxyAuthRejected, errors.New("no acceptable authentication method")
		case 0:
			return proxyNoSupport, errors.New("server accepts anonymous use")
		case 2:
		default:
			return proxyBadReply, fmt.Errorf("unexpected method %d", rep[1])
		}
		req := []byte{1, byte(len(p.Username))}
		req = append(req, p.Username...)
		req = append(req, byte(len(p.Password)))
		req = append(req, p.Password...)
		if _, e := conn.Write(req); e != nil {
			return proxyBadReply, e
		}
		if _, e := io.ReadFull(conn, rep); e != nil {
			return proxyBadReply, e
		}
		if rep[1] != 0 {
			return proxyAuthRejected, errors.New("username or password rejected")
		}
		return proxyAccepted, nil
	case "http", "https":
		auth := base64.StdEncoding.EncodeToString([]byte(p.Username + ":" + p.Password))
		req := "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic " + auth + "\r\n\r\n"
		if _, e := conn.Write([]byte(req)); e != nil {
			return proxyBadReply, e
		}
		buf := make([]byte, 256)
		n, e := conn.Read(buf)
		if n == 0 && e != nil {
			return proxyBadReply, e
		}
		line, _, _ := strings.Cut(string(buf[:n]), "\r\n")
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.HasPrefix(fields[0], "HTTP/") {
			return proxyBadReply, errors.New("not an HTTP proxy")
		}
		switch fields[1] {
		case "407", "401", "403":
			return proxyAuthRejected, errors.New("HTTP " + fields[1])
		}
		// Any answer but an authentication rejection shows the credentials were accepted (the
		// CONNECT target is a placeholder, so 502/403 from an upstream policy is expected).
		return proxyAccepted, nil
	}
	return proxyNoSupport, nil
}

// diagnoseProxy tests an outbound proxy or remote server layer by layer.
func (a *App) diagnoseProxy(ctx context.Context, e Exit, env diagEnv, opts diagOpts) diagReport {
	var rep diagReport
	d := diagger{a: a, rep: &rep}
	p := e.Proxy
	host, port := p.Host, p.Port
	dialer := env.newDialer(outAuto)
	// layer 2: the proxy's address
	if _, er := netip.ParseAddr(host); er != nil {
		res, er := dialer.Resolver.Resolve(ctx, host, true, true)
		if er != nil {
			d.dialFailure(2, er, DialReport{})
			return rep
		}
		v4, v6 := familySummary(res.Addrs)
		d.add(2, diagOK, "域名 %s 解析为 IPv4: %s；IPv6: %s", host, joinOrNone(a, v4), joinOrNone(a, v6))
	} else {
		d.add(2, diagInfo, "出口地址是 IP：%s", host)
	}
	// layer 3: reach the remote endpoint
	target := net.JoinHostPort(host, itoa(port))
	udpOnly := exitTransport(p) == "udp"
	if udpOnly {
		conn, r, er := dialer.DialUDP(ctx, target)
		if er != nil {
			d.dialFailure(3, er, r)
			return rep
		}
		network := "udp4"
		if r.Used.Addr().Is6() {
			network = "udp6"
		}
		addr := conn.RemoteAddr().String()
		conn.Close()
		switch qe := env.quicProbe(ctx, network, addr); {
		case qe == nil:
			d.add(3, diagOK, "远程服务器的 UDP 端口响应了 QUIC 版本协商（%s）", addr)
		case errors.Is(qe, errNoQUICAnswer):
			d.add(3, diagWarn, "远程服务器没有响应 QUIC 探测（UDP 被过滤，或 NAT 没有映射 UDP）；无法确认")
		default:
			d.add(3, diagFail, "远程服务器 UDP 探测失败：%s", qe.Error())
			return rep
		}
	} else {
		start := time.Now()
		conn, r, er := dialer.DialContext(ctx, target)
		if er != nil {
			d.dialFailure(3, er, r)
			return rep
		}
		d.add(3, diagOK, "TCP 连接成功：%s %s（%d ms）", ipFamilyLabel(r.Used.Addr()), r.Used.String(), time.Since(start).Milliseconds())
		// layer 5, credential-level handshake for SOCKS5/HTTP(S)
		if p.Protocol == "socks5" || p.Protocol == "http" || p.Protocol == "https" {
			res, he := a.proxyAuthCheck(ctx, conn, p)
			switch res {
			case proxyAccepted:
				d.add(5, diagOK, "代理接受了账号密码（%s 握手成功）", strings.ToUpper(p.Protocol))
			case proxyAuthRejected:
				d.add(5, diagFail, "代理拒绝了账号或密码（认证失败）")
				return rep
			case proxyNoSupport:
				d.add(5, diagWarn, "代理允许匿名使用：这是一个不受保护的开放代理，强烈建议启用认证")
			default:
				d.add(5, diagFail, "对端不是预期的 %s 代理：%s", strings.ToUpper(p.Protocol), he.Error())
				return rep
			}
		} else {
			conn.Close()
			if u, er := url.Parse(p.Link); er == nil && u.Query().Get("security") == "reality" && env.tlsCheck != nil {
				sni := u.Query().Get("sni")
				if sni == "" {
					sni = u.Hostname()
				}
				if te := env.tlsCheck(ctx, target, sni); te != nil {
					d.add(5, diagWarn, "TLS 伪装握手失败（SNI %s）：对端可能不是 Reality 服务", sni)
				} else {
					d.add(5, diagOK, "TLS 伪装握手成功（SNI %s）；这不验证 UUID 和密钥", sni)
				}
			}
		}
	}
	if !opts.Full || env.fullProxy == nil {
		d.add(5, diagWarn, "尚未验证完整代理链路（未请求出口地址）")
		return rep
	}
	res := env.fullProxy(a, p)
	if res.ClientErr != nil {
		d.add(6, diagFail, "无法启动本地检测客户端：%s", a.Error(res.ClientErr))
		return rep
	}
	d.layerExit(res)
	return rep
}

// proxyAuthCheck wraps TLS for HTTPS proxies (certificate verified), then runs the handshake.
func (a *App) proxyAuthCheck(ctx context.Context, conn net.Conn, p Proxy) (proxyHandshakeResult, error) {
	defer conn.Close()
	if p.Protocol == "https" {
		tc := tls.Client(conn, &tls.Config{ServerName: p.Host, MinVersion: tls.VersionTLS12})
		hctx, cancel := context.WithTimeout(ctx, 6*time.Second)
		defer cancel()
		if e := tc.HandshakeContext(hctx); e != nil {
			return proxyBadReply, e
		}
		return proxyHandshake(ctx, tc, p)
	}
	return proxyHandshake(ctx, conn, p)
}

// fullProbeProxy requests the exit addresses through a proxy using the engine.
func (a *App) fullProbeProxy(p Proxy) fullProbe {
	var out fullProbe
	port, e := freePort()
	if e != nil {
		out.ClientErr = e
		return out
	}
	conf := M{"log": M{"level": "error"}, "inbounds": []any{M{"type": "mixed", "listen": "127.0.0.1", "listen_port": port}}, "outbounds": []any{proxyConfig(p)}, "route": M{"final": "egress"}}
	out.ClientErr = a.withClientLog(conf, port, func(proxy string, logs func() string) error {
		for _, f := range []struct {
			network string
			ip      *string
			err     *error
		}{{"tcp4", &out.V4, &out.ErrV4}, {"tcp6", &out.V6, &out.ErrV6}} {
			var ip string
			var er error
			for _, endpoint := range ipEndpoints[f.network] {
				if ip, er = fetchIP(proxy, endpoint); er == nil {
					break
				}
			}
			*f.ip, *f.err = ip, er
		}
		out.LogHint = classifyClientLog(logs())
		return nil
	})
	return out
}
