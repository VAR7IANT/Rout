package rout

import (
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"unicode/utf8"
)

const (
	mihomoProxyGroup     = "🚀 Proxy"
	mihomoAutoGroup      = "⚡ Auto"
	mihomoFallbackGroup  = "🛡️ Fallback"
	mihomoInfoGroup      = "📊 Info"
	mihomoDefaultTestURL = "https://www.gstatic.com/generate_204"
)

func (s SubscriptionSettings) mihomoTestURL() string {
	if s.MihomoTestURL != "" {
		return s.MihomoTestURL
	}
	return mihomoDefaultTestURL
}

func validateMihomoTestURL(raw string) error {
	u, e := url.Parse(raw)
	if e != nil || len(raw) > 2048 || u.Scheme != "https" || !validHostStrict(u.Hostname()) || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(raw, " \t\r\n") || (u.Port() != "" && !validMihomoPort(u.Port())) {
		return errors.New("Mihomo 测试地址必须是无账号、参数或片段的 HTTPS URL")
	}
	return nil
}

// This optional setting is changed explicitly, never initialized by an upgrade.
// It controls client health checks; the Rout server never fetches this URL.
func (a *App) SetMihomoTestURL(raw string) error {
	unlock, e := lockFile(a.Home+"/.subscription.lock", trafficLockWait)
	if e != nil {
		return e
	}
	defer unlock()
	cfg, e := a.subscriptionSettings()
	if e != nil {
		return e
	}
	raw = strings.TrimSpace(raw)
	if raw != "" {
		if e = validateMihomoTestURL(raw); e != nil {
			return e
		}
	}
	if cfg.MihomoTestURL == raw {
		return nil
	}
	if _, e = a.backupSubscriptionFiles("mihomo-settings", a.Home+"/settings.json"); e != nil {
		return e
	}
	cfg.MihomoTestURL = raw
	return a.saveSubscriptionSettings(cfg)
}

// Flow mappings and quoted scalars are YAML 1.2. encoding/json safely serializes
// every dynamic value, including names and credentials; only fixed section
// keys and list markers are written here. No handwritten string interpolation
// can turn a node name into a YAML key, alias, tag or additional document.
func renderMihomo(proxies []M, warnings []string, testURL string) string {
	return renderMihomoInfo(proxies, warnings, testURL, nil)
}

// renderMihomoInfo adds the subscription plan's informational entries (remaining data,
// days to reset, expiry) as inert placeholder proxies in their own selectable group.
// They are never members of the manual, automatic or fallback groups, so no rule or
// health check can route traffic to them or pick them by default.
func renderMihomoInfo(proxies []M, warnings []string, testURL string, info []string) string {
	var b strings.Builder
	b.WriteString("# Rout native Mihomo subscription\n")
	for _, w := range warnings {
		v, _ := json.Marshal(w)
		fmt.Fprintf(&b, "# Rout diagnostic: %s\n", v)
	}
	names := make([]string, 0, len(proxies))
	for _, p := range proxies {
		names = append(names, p["name"].(string))
	}
	manual := append(append([]string{}, names...), mihomoAutoGroup, mihomoFallbackGroup, "DIRECT")
	groups := []M{
		{"name": mihomoProxyGroup, "type": "select", "proxies": manual},
		{"name": mihomoAutoGroup, "type": "url-test", "proxies": names, "url": testURL, "interval": 600, "lazy": true, "tolerance": 50},
		{"name": mihomoFallbackGroup, "type": "fallback", "proxies": names, "url": testURL, "interval": 600, "lazy": true},
	}
	var infoNames []string
	if len(info) > 0 {
		used := map[string]bool{"DIRECT": true, "REJECT": true, mihomoProxyGroup: true, mihomoAutoGroup: true, mihomoFallbackGroup: true, mihomoInfoGroup: true}
		for _, n := range names {
			used[n] = true
		}
		for _, line := range info {
			for used[line] {
				line += " ·"
			}
			used[line] = true
			infoNames = append(infoNames, line)
		}
		proxies = append([]M(nil), proxies...)
		for _, n := range infoNames {
			proxies = append(proxies, infoProxy(n))
		}
		groups = append(groups, M{"name": mihomoInfoGroup, "type": "select", "proxies": infoNames})
	}
	write := func(key string, values []M) {
		b.WriteString(key + ":\n")
		for _, v := range values {
			data, _ := json.Marshal(v)
			fmt.Fprintf(&b, "  - %s\n", data)
		}
	}
	write("proxies", proxies)
	write("proxy-groups", groups)
	b.WriteString("rules:\n")
	rule, _ := json.Marshal("MATCH," + mihomoProxyGroup)
	fmt.Fprintf(&b, "  - %s\n", rule)
	return b.String()
}

// Keep original names when unique. Reserve ALL current names before allocating
// suffixes so an adversarial literal "name [id]" cannot collide with a generated
// name. IDs make duplicates stable across reordering and enable/disable changes.
func mihomoNames(s State) map[string]string {
	counts := map[string]int{}
	originals := map[string]bool{}
	reserved := map[string]bool{"DIRECT": true, "REJECT": true, "REJECT-DROP": true, "PASS": true, "COMPATIBLE": true, "GLOBAL": true, mihomoProxyGroup: true, mihomoAutoGroup: true, mihomoFallbackGroup: true, mihomoInfoGroup: true}
	for _, p := range s.Profiles {
		counts[p.Name]++
		originals[p.Name] = true
	}
	names := map[string]string{}
	used := map[string]bool{}
	for _, p := range s.Profiles {
		name := p.Name
		if counts[name] > 1 || reserved[name] {
			name += " [" + p.ID + "]"
			for originals[name] || used[name] || reserved[name] {
				name += " [" + p.ID + "]"
			}
		}
		names[p.ID] = name
		used[name] = true
	}
	return names
}

// Diagnostics use IDs and fixed reasons, never raw links, keys or node names.
// Unsupported selections remain in state.json; only this format omits them.
func (s State) exportMihomo(sub Subscription) (proxies []M, warnings []string) {
	byID := map[string]Profile{}
	for _, p := range s.Profiles {
		byID[p.ID] = p
	}
	names := mihomoNames(s)
	for _, id := range sub.NodeIDs {
		p, ok := byID[id]
		if !ok {
			warnings = append(warnings, fmt.Sprintf("节点 %s 已删除，已跳过", id))
			continue
		}
		if !p.Enabled {
			warnings = append(warnings, fmt.Sprintf("节点 %s 已停用，已跳过", id))
			continue
		}
		proxy, e := mihomoNode(p)
		if e != nil {
			warnings = append(warnings, fmt.Sprintf("节点 %s 无法生成 Mihomo：%s", id, e.Error()))
			continue
		}
		proxy["name"] = names[id]
		proxies = append(proxies, proxy)
	}
	return
}

func mihomoNode(p Profile) (M, error) {
	if !utf8.ValidString(p.Name) {
		return nil, errors.New("节点名称不是有效的 UTF-8，请修改节点名称")
	}
	if e := p.Validate(); e != nil {
		return nil, errors.New("节点配置无效，请检查节点设置")
	}
	if p.Kind == "relay" {
		return mihomoRelay(p)
	}
	if p.Protocol == "anytls" {
		return nil, errors.New("Mihomo 不支持 AnyTLS Reality，请使用 Base64 或支持的节点")
	}
	if e := p.Ready(); e != nil {
		return nil, errors.New("节点证书尚未生效或已过期，请更新证书")
	}
	// ClientConfig is the canonical model for the configured transport, flow,
	// fingerprint, SNI, ALPN and authentication. Do not invent independent defaults.
	config, e := ClientConfig(p, p.PublicHost, p.PublicPort, 1080)
	if e != nil {
		return nil, errors.New("无法生成节点客户端设置")
	}
	out := config["outbounds"].([]any)[0].(M)
	proxy, e := mihomoOutbound(out)
	if e == nil && p.Protocol == "ss" {
		if p.Network == "udp" {
			return nil, errors.New("仅 UDP 的 Shadowsocks 无法完整表示为 Mihomo 节点，请使用 Base64")
		}
		proxy["udp"] = p.Network != "tcp"
	}
	return proxy, e
}

func mihomoOutbound(out M) (M, error) {
	kind, _ := out["type"].(string)
	proxy := M{"type": kind, "server": out["server"], "port": out["server_port"], "udp": true}
	switch kind {
	case "vless":
		proxy["uuid"] = out["uuid"]
		proxy["network"] = "tcp"
		if flow, ok := out["flow"]; ok {
			proxy["flow"] = flow
		}
	case "shadowsocks":
		proxy["type"] = "ss"
		proxy["cipher"] = out["method"]
		proxy["password"] = out["password"]
	case "hysteria2", "trojan", "anytls":
		proxy["password"] = out["password"]
	case "tuic":
		proxy["uuid"] = out["uuid"]
		proxy["password"] = out["password"]
		if cc, ok := out["congestion_control"]; ok {
			proxy["congestion-controller"] = cc
		}
	default:
		return nil, errors.New("此协议没有可靠的 Mihomo 映射，请使用 Base64")
	}
	if tls, ok := out["tls"].(M); ok {
		if kind == "vless" {
			proxy["tls"] = true
			proxy["servername"] = tls["server_name"]
		} else {
			proxy["sni"] = tls["server_name"]
		}
		if alpn, ok := tls["alpn"]; ok {
			proxy["alpn"] = alpn
		}
		if utls, ok := tls["utls"].(M); ok {
			proxy["client-fingerprint"] = utls["fingerprint"]
		}
		if reality, ok := tls["reality"].(M); ok {
			if kind == "anytls" {
				return nil, errors.New("Mihomo 不支持 AnyTLS Reality，请使用 Base64 或支持的节点")
			}
			// Preserve modern Chrome key shares used by Rout's pinned sing-box.
			// Mihomo otherwise strips ML-KEM and fails against modern Reality targets.
			proxy["reality-opts"] = M{"public-key": reality["public_key"], "short-id": reality["short_id"], "support-x25519mlkem768": true}
		}
		if tls["insecure"] == true {
			return nil, errors.New("拒绝导出未验证的 TLS 节点，请提供有效证书或证书指纹")
		}
		if certs, ok := tls["certificate"].([]string); ok {
			// Mihomo's per-proxy certificate field is a CLIENT certificate, not
			// a CA. Pin the actual server leaf certificate instead. Never emit
			// PEM private keys or replace verification with skip-cert-verify.
			if len(certs) != 1 {
				return nil, errors.New("节点公钥证书无效")
			}
			for rest := []byte(certs[0]); len(rest) > 0; {
				block, next := pem.Decode(rest)
				if block == nil {
					break
				}
				rest = next
				if block.Type != "CERTIFICATE" {
					continue
				}
				pin, e := CertificatePin(string(pem.EncodeToMemory(block)))
				if e != nil {
					return nil, errors.New("节点公钥证书无效")
				}
				proxy["fingerprint"] = pin
				break
			}
			if proxy["fingerprint"] == nil {
				return nil, errors.New("节点公钥证书无效")
			}
		}

	}
	if transport, ok := out["transport"].(M); ok {
		proxy["network"] = transport["type"]
		switch transport["type"] {
		case "ws":
			proxy["ws-opts"] = M{"path": transport["path"], "headers": transport["headers"]}
		case "grpc":
			proxy["grpc-opts"] = M{"grpc-service-name": transport["service_name"]}
		default:
			return nil, errors.New("此传输没有可靠的 Mihomo 映射，请使用 Base64")
		}
	}
	return proxy, nil
}
