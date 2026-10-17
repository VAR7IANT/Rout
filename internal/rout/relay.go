package rout

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// Relay destinations. "local" forwards to a service on THIS server; "remote" forwards
// to another server. Relays created before v0.3 carry no mode; it is inferred.
const (
	relayLocal  = "local"
	relayRemote = "remote"
)

func isLoopbackHost(h string) bool {
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// relayMode returns the stored destination type, inferring it for older relays.
func (p Profile) relayMode() string {
	if p.RelayMode != "" {
		return p.RelayMode
	}
	if h, _, e := ParseEndpoint(p.Target); e == nil && isLoopbackHost(h) {
		return relayLocal
	}
	return relayRemote
}

// localIPs lists this machine's interface addresses (best effort).
func localIPs() map[string]bool {
	out := map[string]bool{}
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			out[n.IP.String()] = true
		}
	}
	return out
}

// pointsAtThisHost reports whether a destination host is definitely this machine.
// A shared public IP (common on NAT VPS) is NOT proof: other customers use it too.
func pointsAtThisHost(h string, local map[string]bool) bool {
	if isLoopbackHost(h) {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && (ip.IsUnspecified() || local[ip.String()])
}

// relayLoop rejects relays that would forward into themselves, directly or through a
// chain of local relays. Forwarding to ANOTHER port on the same host is legitimate.
func relayLoop(s State, p Profile, local map[string]bool) error {
	h, port, e := ParseEndpoint(p.Target)
	if e != nil {
		return e
	}
	if strings.EqualFold(h, p.PublicHost) && port == p.PublicPort {
		return errors.New("目标就是本中转的公网入口，会形成转发循环")
	}
	if !pointsAtThisHost(h, local) {
		return nil
	}
	// Follow local hops: target port -> relay listening there -> its target ...
	seen := map[string]bool{p.ID: true}
	current, currentPort := p, port
	for {
		if currentPort == p.Port && sharesNetwork(current.Networks(), p.Networks()) {
			return errors.New("目标端口就是本中转的监听端口，会形成转发循环")
		}
		var next *Profile
		for i, other := range s.Profiles {
			if other.Kind == "relay" && other.Enabled && other.ID != p.ID && other.Port == currentPort && sharesNetwork(other.Networks(), current.Networks()) {
				next = &s.Profiles[i]
				break
			}
		}
		if next == nil {
			return nil
		}
		if seen[next.ID] {
			return nil
		}
		seen[next.ID] = true
		nh, np, e := ParseEndpoint(next.Target)
		if e != nil || !pointsAtThisHost(nh, local) {
			return nil
		}
		if np == p.Port {
			return fmt.Errorf("目标经由中转 %s 又回到本中转，会形成转发循环", next.Name)
		}
		current, currentPort = *next, np
	}
}

// localNodeForPublicPort finds a managed entry on this server published at a port,
// so a relay aimed at our own public address can be pointed at 127.0.0.1 instead.
func localNodeForPublicPort(s State, host string, port int) (Profile, bool) {
	for _, p := range s.Profiles {
		if strings.EqualFold(p.PublicHost, host) && p.PublicPort == port {
			return p, true
		}
	}
	return Profile{}, false
}

type relayCheck struct {
	ok      bool
	warning bool
	text    string
}

var relayDialTimeout = 4 * time.Second

// checkRelayDestination tests what can honestly be tested from this server. TCP gets a
// real connection attempt; UDP has no handshake, so it is never claimed as verified.
// Even a successful TCP connection proves reachability, not that the protocol works.
func checkRelayDestination(p Profile) []relayCheck {
	var out []relayCheck
	h, port, e := ParseEndpoint(p.Target)
	if e != nil {
		return []relayCheck{{text: e.Error()}}
	}
	if p.relayMode() == relayLocal || isLoopbackHost(h) {
		for _, n := range p.Networks() {
			if socketBound(n, port) {
				out = append(out, relayCheck{ok: true, text: fmt.Sprintf("本机 %s 端口 %d 已有服务在监听", strings.ToUpper(n), port)})
			} else {
				out = append(out, relayCheck{warning: true, text: fmt.Sprintf("本机 %s 端口 %d 目前没有服务在监听，中转创建后连接会失败", strings.ToUpper(n), port)})
			}
		}
		return out
	}
	if net.ParseIP(h) == nil {
		ctx, cancel := context.WithTimeout(context.Background(), relayDialTimeout)
		addrs, e := net.DefaultResolver.LookupHost(ctx, h)
		cancel()
		if e != nil || len(addrs) == 0 {
			return append(out, relayCheck{warning: true, text: fmt.Sprintf("无法从本机解析域名 %s", h)})
		}
		out = append(out, relayCheck{ok: true, text: fmt.Sprintf("域名 %s 解析为 %s", h, strings.Join(addrs, ", "))})
	}
	for _, n := range p.Networks() {
		if n == "udp" {
			out = append(out, relayCheck{warning: true, text: "UDP 没有连接握手，无法用连通性测试验证；请用实际客户端确认"})
			continue
		}
		c, e := net.DialTimeout("tcp", p.Target, relayDialTimeout)
		if e != nil {
			out = append(out, relayCheck{warning: true, text: fmt.Sprintf("本机无法建立到 %s 的 TCP 连接，请确认远程端口已开放", p.Target)})
			continue
		}
		c.Close()
		out = append(out, relayCheck{ok: true, text: fmt.Sprintf("本机可以建立到 %s 的 TCP 连接（仅证明端口可达，不代表代理协议可用）", p.Target)})
	}
	return out
}
