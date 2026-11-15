package remote

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Surge node lists.
//
// A Surge source is either a whole profile (only its [Proxy] section is read) or bare
// [Proxy] lines, as served to a Surge policy-path:
//
//	Name = type, server, port, key=value, key=value
//
// Each line is turned into the equivalent Mihomo/Clash proxy mapping and imported exactly
// like a Clash entry, so the same checks, identities and outputs apply. Every Surge key is
// either mapped, known to be client-side tuning (left out), or the line is refused with a
// reason: nothing that changes which server is reached or how is dropped silently.

// surgeMarker recognises a Surge source: a [Proxy] section header, or a line of the form
// "Name = type, …" with a proxy type Surge uses.
var surgeMarker = regexp.MustCompile(`(?mi)^[ \t]*(\[Proxy\][ \t]*$|[^=#;\r\n]+=[ \t]*(ss|snell|trojan|vless|vmess|anytls|hysteria2|tuic|tuic-v5|socks5|socks5-tls|https?|wireguard|ssh|direct|reject)[ \t]*,)`)

// surgeTuning are client-side keys with no effect on which server is reached or how it is
// authenticated; they are left out of the imported node.
var surgeTuning = map[string]bool{
	"tfo": true, "test-url": true, "test-udp": true, "test-timeout": true, "no-error-alert": true,
	"block-quic": true, "ecn": true, "reuse": true, "download-bandwidth": true, "upload-bandwidth": true,
	"ip-version": true, "hybrid": true, "allow-other-interface": true, "always-use-connect": true,
}

// surgeRefused are keys that make a line reach outside its own entry or depend on the Surge
// device; such a line is refused, like the equivalent Clash keys.
var surgeRefused = map[string]string{
	"underlying-proxy":    "指向其他代理",
	"interface":           "绑定本机网卡",
	"shadow-tls-password": "使用 ShadowTLS",
	"port-hopping":        "使用端口跳跃",
}

// ParseSurge reads a Surge profile or a list of Surge [Proxy] lines.
func ParseSurge(text string) (Parsed, error) {
	p := Parsed{Format: "surge"}
	seen := map[string]bool{}
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	sectioned := false
	for _, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), "[") {
			sectioned = true
			break
		}
	}
	inProxy := !sectioned
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			inProxy = strings.EqualFold(line, "[Proxy]")
			continue
		}
		if !inProxy || line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "//") {
			continue
		}
		p.Entries++
		name, kind, m, err := surgeToClash(line)
		if err == nil {
			var n Node
			if n, err = nodeFromClash(m); err == nil {
				n.deriveIdentity()
				if seen[n.dedupeKey()] {
					p.Duplicates++
					continue
				}
				seen[n.dedupeKey()] = true
				p.Nodes = append(p.Nodes, n)
				if len(p.Nodes) > MaxNodes {
					return Parsed{}, fmt.Errorf("节点数量超过上限 %d", MaxNodes)
				}
				continue
			}
		}
		level := "error"
		if IsPlaceholder(err) {
			level = "skip"
		}
		p.Issues = append(p.Issues, Issue{Level: level, Line: i + 1, Name: cleanName(name), Protocol: truncate(kind, 20), Reason: err.Error()})
	}
	return p, nil
}

// surgeValue removes the quotes Surge allows around a value.
func surgeValue(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		v = v[1 : len(v)-1]
	}
	return v
}

// surgeSplit splits a Surge line at the commas that are outside quotes.
func surgeSplit(s string) []string {
	var out []string
	var b strings.Builder
	quoted := false
	for _, r := range s {
		switch {
		case r == '"':
			quoted = !quoted
			b.WriteRune(r)
		case r == ',' && !quoted:
			out = append(out, strings.TrimSpace(b.String()))
			b.Reset()
		default:
			b.WriteRune(r)
		}
	}
	return append(out, strings.TrimSpace(b.String()))
}

func surgeBool(v string) (bool, error) {
	switch strings.ToLower(v) {
	case "true", "1":
		return true, nil
	case "false", "0":
		return false, nil
	}
	return false, fmt.Errorf("开关值 %s 无效", truncate(v, 20))
}

// surgeToClash converts one Surge [Proxy] line into a Mihomo/Clash proxy mapping.
func surgeToClash(line string) (name, kind string, m map[string]any, err error) {
	if len(line) > maxLinkBytes {
		return "", "", nil, fmt.Errorf("这一行过长")
	}
	name, rest, ok := strings.Cut(line, "=")
	name = strings.TrimSpace(name)
	if !ok || name == "" {
		return name, "", nil, fmt.Errorf("不是 Surge 节点行")
	}
	parts := surgeSplit(rest)
	kind = strings.ToLower(parts[0])
	switch kind {
	case "ss", "snell", "trojan", "vless", "anytls", "hysteria2", "tuic-v5":
	case "tuic":
		return name, kind, nil, unsupportedError{"暂不支持 TUIC v4（token 认证）"}
	case "direct", "reject", "reject-tinygif", "reject-drop":
		return name, kind, nil, placeholderError{}
	default:
		return name, kind, nil, unsupportedError{fmt.Sprintf("暂不支持 %s 协议", truncate(kind, 20))}
	}
	if len(parts) < 3 {
		return name, kind, nil, fmt.Errorf("缺少服务器地址或端口")
	}
	port, perr := strconv.Atoi(parts[2])
	if perr != nil {
		return name, kind, nil, fmt.Errorf("端口无效")
	}
	m = map[string]any{"name": name, "type": kind, "server": surgeValue(parts[1]), "port": int64(port)}
	if kind == "tuic-v5" {
		m["type"] = "tuic"
	}
	ws := map[string]any{}
	reality := map[string]any{}
	network := ""
	obfs := map[string]any{}
	for _, kv := range parts[3:] {
		if kv == "" {
			continue
		}
		k, v, ok := strings.Cut(kv, "=")
		k, v = strings.ToLower(strings.TrimSpace(k)), surgeValue(v)
		if !ok {
			return name, kind, nil, fmt.Errorf("参数 %s 缺少值", truncate(k, 30))
		}
		if why, bad := surgeRefused[k]; bad {
			return name, kind, nil, fmt.Errorf("含有被拒绝的参数 %s（%s）", k, why)
		}
		if surgeTuning[k] {
			continue
		}
		switch {
		case k == "udp-relay" && (kind == "ss" || kind == "snell"):
			b, e := surgeBool(v)
			if e != nil {
				return name, kind, nil, e
			}
			m["udp"] = b
		case k == "encrypt-method" && kind == "ss":
			m["cipher"] = v
		case k == "password" && kind != "snell" && kind != "vless":
			m["password"] = v
		case k == "psk" && kind == "snell":
			m["psk"] = v
		case k == "version" && kind == "snell":
			n, e := strconv.Atoi(v)
			if e != nil {
				return name, kind, nil, fmt.Errorf("Snell 版本无效")
			}
			m["version"] = int64(n)
		case k == "obfs" && kind == "snell":
			if v != "http" && v != "tls" && v != "off" {
				return name, kind, nil, fmt.Errorf("Snell 混淆方式 %s 无效", truncate(v, 20))
			}
			if v != "off" {
				obfs["mode"] = v
			}
		case k == "obfs-host" && kind == "snell":
			obfs["host"] = v
		case k == "uuid" && kind == "tuic-v5":
			m["uuid"] = v
		case k == "username" && kind == "vless":
			m["uuid"] = v
		case k == "flow" && kind == "vless":
			m["flow"] = v
		case k == "tls" && kind == "vless":
			b, e := surgeBool(v)
			if e != nil {
				return name, kind, nil, e
			}
			m["tls"] = b
		case k == "reality-public-key" && kind == "vless":
			reality["public-key"] = v
			m["tls"] = true
		case k == "reality-short-id" && kind == "vless":
			reality["short-id"] = v
		case k == "salamander-password" && kind == "hysteria2":
			m["obfs"], m["obfs-password"] = "salamander", v
		case k == "sni" && kind != "ss" && kind != "snell":
			if strings.EqualFold(v, "off") {
				return name, kind, nil, fmt.Errorf("不支持关闭 SNI")
			}
			m["sni"] = v
		case k == "skip-cert-verify" && kind != "ss" && kind != "snell":
			b, e := surgeBool(v)
			if e != nil {
				return name, kind, nil, e
			}
			m["skip-cert-verify"] = b
		case k == "server-cert-fingerprint-sha256" && kind != "ss" && kind != "snell":
			m["fingerprint"] = strings.ToLower(v)
		case k == "alpn" && kind != "ss" && kind != "snell":
			var list []any
			for _, a := range strings.Split(v, ",") {
				if a = strings.TrimSpace(a); a != "" {
					list = append(list, a)
				}
			}
			m["alpn"] = list
		case k == "ws" && (kind == "vless" || kind == "trojan"):
			b, e := surgeBool(v)
			if e != nil {
				return name, kind, nil, e
			}
			if b {
				network = "ws"
			}
		case k == "ws-path" && (kind == "vless" || kind == "trojan"):
			ws["path"] = v
		case k == "ws-headers" && (kind == "vless" || kind == "trojan"):
			hk, hv, ok := strings.Cut(v, ":")
			if !ok || !strings.EqualFold(strings.TrimSpace(hk), "host") || strings.Contains(hv, "|") {
				return name, kind, nil, fmt.Errorf("只支持 Host 一个 WebSocket 请求头")
			}
			ws["headers"] = map[string]any{"Host": strings.Trim(strings.TrimSpace(hv), `"`)}
		case k == "grpc" && kind == "vless":
			b, e := surgeBool(v)
			if e != nil {
				return name, kind, nil, e
			}
			if b {
				network = "grpc"
			}
		case k == "grpc-service-name" && kind == "vless":
			m["grpc-opts"] = map[string]any{"grpc-service-name": v}
		default:
			return name, kind, nil, fmt.Errorf("Surge 参数 %s 无法导入", truncate(k, 30))
		}
	}
	if network != "" {
		m["network"] = network
		if network == "ws" && len(ws) > 0 {
			m["ws-opts"] = ws
		}
	} else if len(ws) > 0 {
		return name, kind, nil, fmt.Errorf("WebSocket 参数缺少 ws=true")
	}
	if _, grpc := m["grpc-opts"]; grpc && network != "grpc" {
		return name, kind, nil, fmt.Errorf("gRPC 参数缺少 grpc=true")
	}
	if len(reality) > 0 {
		m["reality-opts"] = reality
	}
	if len(obfs) > 0 {
		if obfs["mode"] == nil {
			return name, kind, nil, fmt.Errorf("obfs-host 缺少 obfs")
		}
		m["obfs-opts"] = obfs
	}
	if kind == "snell" && m["version"] == nil {
		return name, kind, nil, fmt.Errorf("Snell 节点行缺少 version")
	}
	return name, kind, m, nil
}
