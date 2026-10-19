package rout

import (
	"encoding/json"
	"net"
	"path/filepath"
)

type M = map[string]any

func proxyConfig(p Proxy) M {
	t := p.Protocol
	if t == "socks5" {
		t = "socks"
	}
	out := M{"type": t, "tag": "egress", "server": p.Host, "server_port": p.Port, "username": p.Username, "password": p.Password}
	if t == "socks" {
		out["version"] = "5"
		out["network"] = "tcp"
	}
	return out
}

// HTTP and unverified third-party SOCKS UDP are TCP-only. No direct fallback exists.
func serverConfig(p Profile, dir string) (M, error) {
	if p.Kind == "relay" {
		services := []any{}
		for _, n := range p.Networks() {
			s := M{"name": p.ID + "-" + n, "addr": net.JoinHostPort(p.Listen, itoa(p.Port)), "handler": M{"type": n}, "listener": M{"type": n}, "forwarder": M{"nodes": []any{M{"name": "target", "addr": p.Target}}}}
			if n == "udp" {
				s["listener"] = M{"type": "udp", "metadata": M{"keepAlive": true, "ttl": "60s"}}
			}
			services = append(services, s)
		}
		return M{"services": services, "log": M{"level": "warn", "format": "json"}}, nil
	}
	in := M{"tag": "entry", "listen": p.Listen, "listen_port": p.Port}
	switch p.Protocol {
	case "vless", "anytls":
		in["type"] = p.Protocol
		in["tls"] = M{"enabled": true, "server_name": p.SNI, "reality": M{"enabled": true, "handshake": M{"server": p.SNI, "server_port": 443}, "private_key": p.PrivateKey, "short_id": []string{p.ShortID}}}
		if p.Protocol == "vless" {
			in["users"] = []any{M{"uuid": p.UUID, "flow": "xtls-rprx-vision"}}
		} else {
			in["users"] = []any{M{"name": p.ID, "password": p.Password}}
		}
	case "ss":
		in["type"] = "shadowsocks"
		in["method"] = p.Method
		in["password"] = p.Password
		if p.Network != "" {
			in["network"] = p.Network
		}
	case "hy2", "tuic":
		in["tls"] = M{"enabled": true, "server_name": p.SNI, "certificate_path": filepath.Join(dir, "tls.crt"), "key_path": filepath.Join(dir, "tls.key")}
		if p.Protocol == "hy2" {
			in["type"] = "hysteria2"
			in["users"] = []any{M{"password": p.Password}}
		} else {
			in["type"] = "tuic"
			in["users"] = []any{M{"uuid": p.UUID, "password": p.Password}}
			in["congestion_control"] = "bbr"
			in["tls"].(M)["alpn"] = []string{"h3"}
		}
	}
	out := M{"type": "direct", "tag": "egress"}
	rules := []any{}
	if p.Outbound != nil {
		out = proxyConfig(*p.Outbound)
		rules = append(rules, M{"network": "udp", "action": "reject"})
	}
	rules = append(rules, M{"inbound": []string{"entry"}, "action": "route", "outbound": "egress"})
	outbounds := []any{out}
	if p.AIRoute != nil {
		// AI rules come first so they win over the node's ordinary routing; they are scoped to
		// this node's own inbound. The AI exit is a separate outbound next to "egress".
		aiRules, aiOut := aiRouteRules(*p.AIRoute)
		rules = append(aiRules, rules...)
		if aiOut != nil {
			outbounds = append(outbounds, aiOut)
		}
	}
	return M{"log": M{"level": "warn", "timestamp": true}, "inbounds": []any{in}, "outbounds": outbounds, "route": M{"rules": rules, "final": "egress"}}, nil
}

// ClientConfig exports a complete, portable sing-box configuration without server secrets.
func ClientConfig(p Profile, host string, port, localPort int) (M, error) {
	var out M
	if p.Kind == "relay" {
		u, e := RewriteURI(p.TargetURI, host, port, p.Name)
		if e != nil {
			return nil, e
		}
		out, e = URIOutbound(u)
		if e != nil {
			return nil, e
		}
		return M{"log": M{"level": "warn"}, "inbounds": []any{M{"type": "mixed", "listen": "127.0.0.1", "listen_port": localPort}}, "outbounds": []any{out}, "route": M{"final": "node"}}, nil
	}
	out = M{"tag": "node", "server": host, "server_port": port}
	switch p.Protocol {
	case "vless", "anytls":
		out["type"] = p.Protocol
		out["tls"] = M{"enabled": true, "server_name": p.SNI, "utls": M{"enabled": true, "fingerprint": "chrome"}, "reality": M{"enabled": true, "public_key": p.PublicKey, "short_id": p.ShortID}}
		if p.Protocol == "vless" {
			out["uuid"] = p.UUID
			out["flow"] = "xtls-rprx-vision"
		} else {
			out["password"] = p.Password
		}
	case "ss":
		out["type"] = "shadowsocks"
		out["method"] = p.Method
		out["password"] = p.Password
	case "hy2", "tuic":
		out["password"] = p.Password
		out["tls"] = M{"enabled": true, "server_name": p.SNI, "certificate": []string{p.CertPEM}}
		if p.Protocol == "hy2" {
			out["type"] = "hysteria2"
		} else {
			out["type"] = "tuic"
			out["uuid"] = p.UUID
			out["congestion_control"] = "bbr"
			out["tls"].(M)["alpn"] = []string{"h3"}
		}
	}
	return M{"log": M{"level": "warn"}, "inbounds": []any{M{"type": "mixed", "tag": "local", "listen": "127.0.0.1", "listen_port": localPort}}, "outbounds": []any{out}, "route": M{"final": "node"}}, nil
}

func JSON(v any) ([]byte, error) { return json.MarshalIndent(v, "", "  ") }
