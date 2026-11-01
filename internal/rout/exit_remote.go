package rout

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
)

// Remote Server exits.
//
// A Remote Server exit makes another VPS/NAT the place where traffic leaves for the
// Internet. That only works when something on the remote side actually carries the traffic
// out, so Rout accepts exactly two forms, both reusing what it already has:
//
//   - a share link of a node protocol running on the remote server (for example a Rout
//     node: VLESS Reality, AnyTLS, Trojan, Shadowsocks). sing-box dials it as an outbound,
//     the remote server forwards the traffic, and its public IP is the exit IP;
//   - an authenticated SOCKS5/HTTP(S) proxy on the remote server.
//
// A bare TCP/UDP port mapping is a relay, not an exit: it moves the connection to another
// address but the destination server still sees THIS server's IP, so it is refused as an
// exit. No form opens a listener on this server or an unauthenticated proxy anywhere.

// remoteNodeSchemes are the links a remote exit may use. Traffic through a node exit is TCP
// (UDP is rejected on nodes that use an outbound, unchanged from SOCKS5/HTTP exits).
var remoteNodeSchemes = map[string]bool{"vless": true, "anytls": true, "trojan": true, "ss": true, "hy2": true, "hysteria2": true, "tuic": true}

// ParseRemoteNode turns a remote node's share link into an outbound endpoint.
func ParseRemoteNode(link string) (*Proxy, error) {
	link = strings.TrimSpace(link)
	if link == "" || strings.ContainsAny(link, "\r\n\x00 ") {
		return nil, errors.New("请粘贴远程节点的分享链接")
	}
	scheme := linkScheme(link)
	if !remoteNodeSchemes[scheme] {
		return nil, errors.New("远程节点链接应为 vless://、anytls://、trojan://、ss://、hysteria2:// 或 tuic://")
	}
	target, _, e := ParseTarget(link)
	if e != nil {
		return nil, e
	}
	// The link must be convertible to a working outbound (this rejects, for instance,
	// certificate-pinned HY2 links that the pinned engine cannot verify).
	if _, e = URIOutbound(link); e != nil {
		return nil, e
	}
	host, port, e := ParseEndpoint(target)
	if e != nil {
		return nil, e
	}
	return &Proxy{Protocol: proxyNode, Host: host, Port: port, Link: link}, nil
}

// exitTransport is the transport the exit's CONNECTION to the remote server needs.
func exitTransport(p Proxy) string {
	if p.Protocol == proxyNode {
		if info, ok := schemeTable[linkScheme(p.Link)]; ok && len(info.Networks) == 1 {
			return info.Networks[0]
		}
	}
	return "tcp"
}

// ExitCaps says what an exit can do, stated conservatively.
type ExitCaps struct {
	// Reach is the transport needed to reach the remote server ("tcp" or "udp").
	Reach string
	// TCP: client TCP traffic can leave through it. UDP: client UDP traffic can; Rout
	// rejects UDP on every node that uses an outbound, so this is always false today.
	TCP, UDP bool
}

func (e Exit) Capabilities() ExitCaps {
	return ExitCaps{Reach: exitTransport(e.Proxy), TCP: true}
}

// remoteCompatibility refuses a remote exit whose connection needs a transport the remote
// server is known not to provide (a QUIC node behind a TCP-only NAT).
func (e Exit) remoteCompatibility() error {
	if e.Kind != exitRemote {
		return nil
	}
	if !networkAllowed(e.RemoteNetwork, exitTransport(e.Proxy)) {
		name := schemeTable[linkScheme(e.Proxy.Link)].Label
		if name == "" {
			name = "Hysteria2 / TUIC"
		}
		return errTCPOnlyTarget(name)
	}
	return nil
}

func (e Exit) validateKind() error {
	switch e.Kind {
	case "":
		if e.RemoteNetwork != "" || e.Proxy.Protocol == proxyNode {
			return errors.New("远程服务器出口必须标记为远程服务器")
		}
	case exitRemote:
		switch e.RemoteNetwork {
		case "", "tcp", "udp", "both":
		default:
			return errors.New("远程服务器的网络类型无效")
		}
	default:
		return errors.New("出站代理类型无效")
	}
	return e.remoteCompatibility()
}

// KindLabel names the exit type for lists ("SOCKS5", "HTTP", "VLESS", ...).
func (e Exit) KindLabel() string {
	label := strings.ToUpper(e.Proxy.Kind())
	if e.Kind == exitRemote {
		return "REMOTE·" + label
	}
	return label
}

// ExitRefs lists everything that depends on an exit, so deleting or editing one is never a
// surprise. Nodes are returned sorted by name.
type ExitRefs struct {
	Nodes []Profile
	AI    bool
}

func (r ExitRefs) Empty() bool { return len(r.Nodes) == 0 && !r.AI }

func exitReferences(s State, id string) ExitRefs {
	var refs ExitRefs
	for _, p := range s.Profiles {
		if p.ExitID == id {
			refs.Nodes = append(refs.Nodes, p)
		}
	}
	sort.Slice(refs.Nodes, func(i, j int) bool { return refs.Nodes[i].Name < refs.Nodes[j].Name })
	refs.AI = s.AI != nil && s.AI.AIOutboundID == id
	return refs
}

// exitSelfLoop refuses an exit that points back at an entry of this server: traffic would
// leave through Rout and arrive at Rout again.
func exitSelfLoop(s State, proxy Proxy, local map[string]bool) error {
	for _, p := range s.Profiles {
		if p.Port == proxy.Port && pointsAtThisHost(proxy.Host, local) {
			return fmt.Errorf("出站指向本机上的 %s，会形成路由循环", p.Name)
		}
		if p.PublicPort == proxy.Port && sameHost(proxy.Host, p.PublicHost) {
			return fmt.Errorf("出站指向本机上的 %s，会形成路由循环", p.Name)
		}
	}
	return nil
}

// secretsOf lists the strings that must never reach a log or a screen.
func (p Proxy) secretsOf() []string {
	out := []string{p.Username, p.Password}
	if p.Link != "" {
		out = append(out, p.Link)
		if u, e := url.Parse(p.Link); e == nil && u.User != nil {
			out = append(out, u.User.Username())
			if pw, ok := u.User.Password(); ok {
				out = append(out, pw)
			}
			if raw := u.User.String(); raw != "" {
				out = append(out, raw)
			}
		}
	}
	return out
}

// hostPort is the printable endpoint of an exit (credentials excluded).
func (p Proxy) hostPort() string { return net.JoinHostPort(p.Host, itoa(p.Port)) }
