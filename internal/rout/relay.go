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

// relayLoop rejects relays that would forward into a local cycle. Follow TCP and UDP
// independently: forwarding preserves its transport, and different relays can share a
// port when one is TCP-only and the other is UDP-only.
func relayLoop(s State, p Profile, local map[string]bool) error {
	if _, _, e := ParseEndpoint(p.Target); e != nil {
		return e
	}
	for _, network := range p.Networks() {
		seen := map[string]bool{p.ID: true}
		current := p
		for {
			host, port, e := ParseEndpoint(current.Target)
			if e != nil {
				break // An existing invalid destination cannot be followed.
			}
			if sameHost(host, p.PublicHost) && port == p.PublicPort {
				if current.ID == p.ID {
					return errors.New("目标就是本中转的公网入口，会形成转发循环")
				}
				return fmt.Errorf("目标经由中转 %s 又回到本中转，会形成转发循环", current.Name)
			}
			if !pointsAtThisHost(host, local) {
				break
			}
			if port == p.Port {
				if current.ID == p.ID {
					return errors.New("目标端口就是本中转的监听端口，会形成转发循环")
				}
				return fmt.Errorf("目标经由中转 %s 又回到本中转，会形成转发循环", current.Name)
			}
			var next *Profile
			for i, other := range s.Profiles {
				// During UI edits s may still contain this relay's previous listener.
				if other.Kind == "relay" && other.Enabled && other.ID != p.ID && other.Port == port && contains(other.Networks(), network) {
					next = &s.Profiles[i]
					break
				}
			}
			if next == nil {
				break
			}
			if seen[next.ID] {
				return fmt.Errorf("目标经由中转 %s 陷入转发循环", next.Name)
			}
			seen[next.ID] = true
			current = *next
		}
	}
	return nil
}

// localNodeForPublicPort finds a managed entry on this server published at a port,
// so a relay aimed at our own public address can be pointed at 127.0.0.1 instead.
func localNodeForPublicPort(s State, host string, port int) (Profile, bool) {
	for _, p := range s.Profiles {
		if sameHost(p.PublicHost, host) && p.PublicPort == port {
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
	dialer := NewPolicyDialer(p.outboundPolicy())
	dialer.Timeout = relayDialTimeout
	if net.ParseIP(h) == nil {
		ctx, cancel := context.WithTimeout(context.Background(), relayDialTimeout)
		res, e := dialer.Resolver.Resolve(ctx, h, true, true)
		cancel()
		if e != nil {
			return append(out, relayCheck{warning: true, text: fmt.Sprintf("无法从本机解析域名 %s", h)})
		}
		v4, v6 := familySummary(res.Addrs)
		out = append(out, relayCheck{ok: true, text: fmt.Sprintf("域名 %s 解析为 IPv4: %s；IPv6: %s", h, noneIfEmpty(v4), noneIfEmpty(v6))})
	}
	for _, n := range p.Networks() {
		if n == "udp" {
			out = append(out, relayCheck{warning: true, text: "UDP 没有连接握手，无法用连通性测试验证；请用实际客户端确认"})
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), relayDialTimeout+2*time.Second)
		c, rep, e := dialer.DialContext(ctx, p.Target)
		cancel()
		if e != nil {
			out = append(out, relayCheck{warning: true, text: dialCheckText(p.Target, e)})
			continue
		}
		c.Close()
		out = append(out, relayCheck{ok: true, text: fmt.Sprintf("本机可以建立到 %s 的 TCP 连接（%s，仅证明端口可达，不代表代理协议可用）", p.Target, ipFamilyLabel(rep.Used.Addr()))})
	}
	return out
}

func noneIfEmpty(list []string) string {
	if len(list) == 0 {
		return "-"
	}
	return strings.Join(list, ", ")
}

// dialCheckText says why a connection check failed, by kind.
func dialCheckText(target string, err error) string {
	var de *DialError
	if !errors.As(err, &de) {
		return fmt.Sprintf("本机无法建立到 %s 的 TCP 连接，请确认远程端口已开放", target)
	}
	switch de.Kind {
	case kindRefused:
		return fmt.Sprintf("目标 %s 拒绝连接：端口未开放或服务未运行", target)
	case kindTimeout:
		return fmt.Sprintf("连接 %s 超时：目标不可达或被防火墙丢弃", target)
	case kindUnreachable:
		return fmt.Sprintf("本机没有到 %s 的路由", target)
	case kindDNS:
		return fmt.Sprintf("无法从本机解析 %s 的域名", target)
	case kindFamily, kindNoAddress:
		return fmt.Sprintf("目标 %s 没有符合出站策略的地址", target)
	case kindLoop:
		return fmt.Sprintf("目标 %s 指向本中转自身，会形成转发循环", target)
	}
	return fmt.Sprintf("本机无法建立到 %s 的 TCP 连接，请确认远程端口已开放", target)
}
