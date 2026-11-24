package rout

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/VAR7IANT/Rout/internal/remote"
)

// Surge proxy lines for every node Surge can run.
//
// Surge reads the same "Name = type, host, port, key=value, ..." syntax in a profile's [Proxy]
// section and in an external policy list (policy-path). Rout writes one line per node:
//
//   - Snell nodes: written directly (snell.go, SnellSurgeLine).
//   - Every other node, relay and imported node: first converted by the strict Mihomo
//     converter Rout already uses (it validates links, refuses unverified TLS, pins
//     self-signed certificates), then mapped key by key to the Surge manual's parameters.
//     A key Surge has no equivalent for is refused, never dropped silently, unless it only
//     tunes the client (fingerprint emulation, congestion control, packet encoding).
//
// Protocols and the Surge release that introduced them (manual.nssurge.com/policies):
// ss (incl. 2022), trojan, tuic-v5, hysteria2 (iOS 5.8 / Mac 5.4), anytls with plain TLS
// (iOS 5.17 / Mac 6.4.3), vless incl. REALITY and Vision (iOS 6.0 / Mac 6.12). AnyTLS over
// REALITY has no Surge syntax and is refused.

// surgeKindVLESS marks lines that need Surge iOS 6.0+ / Mac 6.12+; the subscription leaves
// them out unless asked (?format=surge&vless=1), because an older Surge may not read a list
// containing a type it does not know.
const surgeKindVLESS = "vless"

// errSurgeAnyTLSReality is the reason an AnyTLS Reality node has no Surge line.
var errSurgeAnyTLSReality = errors.New("Surge 不支持 AnyTLS Reality，请改用标准 TLS 的 AnyTLS 节点")

// surgeReserved are Surge's built-in policy names; a proxy may not take one of them.
var surgeReserved = map[string]bool{"direct": true, "reject": true, "reject-tinygif": true, "reject-drop": true, "reject-no-drop": true, "cellular": true, "cellular-only": true, "hybrid": true, "no-hybrid": true}

// SurgeLine is the Surge [Proxy] line of a node or relay at the given address.
func (p Profile) SurgeLine(host string, port int) (string, error) {
	line, _, e := p.surgeLine(host, port)
	return line, e
}

// surgeLine also returns the Surge type of the line (for version gating).
func (p Profile) surgeLine(host string, port int) (string, string, error) {
	if p.classicProxyNode() {
		return "", "", errClassicProxyShare
	}
	if p.mtpNode() {
		return "", "", errMTPClient
	}
	if p.snellNode() {
		line, e := p.SnellSurgeLine(host, port)
		return line, protoSnell, e
	}
	if host == "" || strings.ContainsAny(host, ", =\"\r\n") || !validPort(port) {
		return "", "", errors.New("Surge 配置的地址或端口无效")
	}
	q := p
	q.PublicHost, q.PublicPort = host, port
	m, e := mihomoNode(q)
	if e != nil {
		return "", "", surgeReason(e)
	}
	return surgeFromMihomo(surgeName(p.Name, nodeLabel(p)), m)
}

// surgeRemote is the Surge line of an imported node.
func surgeRemote(n remote.Node, name string, allowInsecure bool) (string, string, error) {
	if n.Protocol == "anytls" && strings.EqualFold(n.Security, "reality") {
		return "", "", errSurgeAnyTLSReality
	}
	if n.Protocol == "snell" {
		// Snell is Surge's own protocol: the imported mapping goes straight to a Surge line,
		// without the Mihomo-only limits (Mihomo has no Snell v6).
		m, ok := n.ClashNamed(name)
		if !ok {
			return "", "", errors.New("Snell 节点缺少参数")
		}
		return surgeFromMihomo(surgeName(name, n.Protocol), M(m))
	}
	m, e := mihomoRemote(n, name, allowInsecure)
	if e != nil {
		return "", "", surgeReason(e)
	}
	return surgeFromMihomo(surgeName(name, n.Protocol), m)
}

// surgeReason rewords the Mihomo converter's reasons where they name the wrong client. The
// relay reasons ("…，请使用 Base64") stay as they are: Base64 is still a working choice.
func surgeReason(e error) error {
	msg := e.Error()
	if strings.Contains(msg, "AnyTLS Reality") {
		return errSurgeAnyTLSReality
	}
	if r, ok := surgeReasons[msg]; ok {
		return errors.New(r)
	}
	if strings.Contains(msg, "Mihomo") {
		return errors.New("此节点无法转换为 Surge")
	}
	return e
}

var surgeReasons = map[string]string{
	"此协议没有可靠的 Mihomo 映射，请使用 Base64":                    "Surge 不支持此协议",
	"此传输没有可靠的 Mihomo 映射，请使用 Base64":                    "Surge 不支持此传输方式",
	"headerType 伪装头无法转换为 Mihomo，请使用 Base64":            "Surge 不支持此传输方式",
	"Mihomo 无法保留独立的 gRPC authority，请使用 Base64":         "gRPC 参数无法转换为 Surge",
	"gRPC 模式无法转换为 Mihomo，请使用 Base64":                   "gRPC 参数无法转换为 Surge",
	"packetEncoding 值无法转换为 Mihomo，请使用 Base64":          "Surge 不支持此传输方式",
	"仅 UDP 的 Shadowsocks 无法完整表示为 Mihomo 节点，请使用 Base64": "仅 UDP 的 Shadowsocks 无法表示为 Surge 节点",
}

// surgeName makes a name safe as the left-hand side of a Surge line. fallback is used when
// nothing is left.
func surgeName(name, fallback string) string {
	r := strings.NewReplacer("=", "-", ",", " ", "\"", "'", "\r", " ", "\n", " ", "\t", " ", "\x00", "")
	name = strings.TrimSpace(r.Replace(name))
	for strings.HasPrefix(name, "#") || strings.HasPrefix(name, ";") || strings.HasPrefix(name, "[") || strings.HasPrefix(name, "//") {
		name = strings.TrimSpace(name[1:])
	}
	if name == "" {
		name = strings.TrimSpace(r.Replace(fallback))
	}
	if name == "" {
		name = "Proxy"
	}
	return name
}

// uniqueSurgeName keeps policy names distinct inside one list (Surge requires it, and
// sanitising a name can make two different names equal) and away from built-in policies.
func uniqueSurgeName(taken map[string]bool, name string) string {
	candidate := name
	for i := 2; taken[strings.ToLower(candidate)] || surgeReserved[strings.ToLower(candidate)]; i++ {
		candidate = fmt.Sprintf("%s %d", name, i)
	}
	taken[strings.ToLower(candidate)] = true
	return candidate
}

// renameSurgeLine replaces the policy name of a line produced here.
func renameSurgeLine(line, name string) string {
	if i := strings.Index(line, " = "); i >= 0 {
		return name + line[i:]
	}
	return line
}

// ---- Mihomo proxy -> Surge line ----------------------------------------------------------

type surgeParams struct {
	keys []string
	vals map[string]string
}

func (sp *surgeParams) set(k, v string) {
	if sp.vals == nil {
		sp.vals = map[string]string{}
	}
	if _, ok := sp.vals[k]; !ok {
		sp.keys = append(sp.keys, k)
	}
	sp.vals[k] = v
}

// surgeIgnored are client-side tuning keys with no Surge parameter; leaving them out does not
// change which server is reached or how it is authenticated.
var surgeIgnored = map[string]bool{"name": true, "client-fingerprint": true, "packet-encoding": true, "congestion-controller": true, "udp-relay-mode": true, "support-x25519mlkem768": true, "encryption": true}

func surgeFromMihomo(name string, m M) (string, string, error) {
	kind := mstr(m["type"])
	host := mstr(m["server"])
	port, ok := mint(m["port"])
	if host == "" || strings.ContainsAny(host, ", =\"\r\n[]") || !ok || !validPort(port) {
		return "", "", errors.New("Surge 配置的地址或端口无效")
	}
	allowed := map[string]bool{"type": true, "server": true, "port": true, "udp": true, "tfo": true}
	allow := func(keys string) {
		for _, k := range strings.Fields(keys) {
			allowed[k] = true
		}
	}
	tlsKeys := "sni servername skip-cert-verify fingerprint alpn"
	var sp surgeParams
	surgeType := kind
	switch kind {
	case "ss":
		allow("cipher password")
		cipher := mstr(m["cipher"])
		switch cipher {
		case "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305":
		default:
			return "", "", errors.New("Surge 不支持此 Shadowsocks 加密方式")
		}
		sp.set("encrypt-method", cipher)
		sp.set("password", mstr(m["password"]))
		if mbool(m["udp"]) {
			sp.set("udp-relay", "true")
		}
	case "trojan":
		allow("password network ws-opts " + tlsKeys)
		sp.set("password", mstr(m["password"]))
	case "anytls":
		allow("password " + tlsKeys)
		sp.set("password", mstr(m["password"]))
	case "hysteria2":
		allow("password obfs obfs-password " + tlsKeys)
		sp.set("password", mstr(m["password"]))
		if obfs := mstr(m["obfs"]); obfs != "" {
			if obfs != "salamander" || mstr(m["obfs-password"]) == "" {
				return "", "", errors.New("Surge 不支持此 Hysteria2 混淆方式")
			}
			sp.set("salamander-password", mstr(m["obfs-password"]))
		} else if m["obfs-password"] != nil {
			return "", "", errors.New("Surge 不支持此 Hysteria2 混淆方式")
		}
	case "tuic":
		allow("uuid password token " + tlsKeys)
		if uuid := mstr(m["uuid"]); uuid != "" {
			surgeType = "tuic-v5"
			sp.set("uuid", uuid)
			sp.set("password", mstr(m["password"]))
		} else if token := mstr(m["token"]); token != "" {
			sp.set("token", token)
		} else {
			return "", "", errors.New("TUIC 认证设置无效")
		}
	case "snell":
		// Only imported nodes reach here: Rout's own Snell nodes have their own line.
		allow("psk version obfs-opts")
		v, ok := mint(m["version"])
		if !ok || v < 1 || v > 6 {
			return "", "", errors.New("Snell 版本无效")
		}
		sp.set("psk", mstr(m["psk"]))
		if sp.vals["psk"] == "" {
			return "", "", errors.New("节点认证信息无效")
		}
		sp.set("version", strconv.Itoa(v))
		if opts, ok := asMap(m["obfs-opts"]); ok {
			for k := range opts {
				if k != "mode" && k != "host" {
					return "", "", errors.New("Snell 混淆参数无法转换为 Surge")
				}
			}
			switch mode := mstr(opts["mode"]); mode {
			case "http", "tls":
				sp.set("obfs", mode)
			default:
				return "", "", errors.New("Snell 混淆参数无法转换为 Surge")
			}
			if h := mstr(opts["host"]); h != "" {
				sp.set("obfs-host", h)
			}
		}
	case "vless":
		allow("uuid flow tls network ws-opts grpc-opts reality-opts " + tlsKeys)
		sp.set("username", mstr(m["uuid"]))
		if flow := mstr(m["flow"]); flow != "" {
			if flow != "xtls-rprx-vision" && flow != "xtls-rprx-vision-udp443" {
				return "", "", errors.New("Surge 不支持此 VLESS flow")
			}
			sp.set("flow", flow)
		}
	default:
		return "", "", errors.New("Surge 不支持此协议")
	}
	for k, v := range m {
		if surgeIgnored[k] || v == nil {
			continue
		}
		if !allowed[k] {
			return "", "", fmt.Errorf("节点参数 %s 无法转换为 Surge", truncateKey(k))
		}
	}
	for _, k := range []string{"password", "username", "uuid"} {
		if v, ok := sp.vals[k]; ok && v == "" {
			return "", "", errors.New("节点认证信息无效")
		}
	}

	// Transport.
	network := mstr(m["network"])
	switch network {
	case "", "tcp":
	case "ws":
		if kind != "vless" && kind != "trojan" {
			return "", "", errors.New("Surge 不支持此传输方式")
		}
		sp.set("ws", "true")
		opts, _ := asMap(m["ws-opts"])
		for k := range opts {
			if k != "path" && k != "headers" {
				return "", "", errors.New("WebSocket 参数无法转换为 Surge")
			}
		}
		if path := mstr(opts["path"]); path != "" {
			sp.set("ws-path", path)
		}
		if hdr, ok := asMap(opts["headers"]); ok {
			for k, v := range hdr {
				if !strings.EqualFold(k, "host") {
					return "", "", errors.New("WebSocket 请求头无法转换为 Surge")
				}
				if h := mstr(v); h != "" {
					sp.set("ws-headers", "Host:"+h)
				}
			}
		}
	case "grpc":
		if kind != "vless" {
			return "", "", errors.New("Surge 不支持此传输方式")
		}
		sp.set("grpc", "true")
		opts, _ := asMap(m["grpc-opts"])
		for k := range opts {
			if k != "grpc-service-name" {
				return "", "", errors.New("gRPC 参数无法转换为 Surge")
			}
		}
		if svc := mstr(opts["grpc-service-name"]); svc != "" {
			sp.set("grpc-service-name", svc)
		}
	default:
		return "", "", errors.New("Surge 不支持此传输方式")
	}

	// TLS / REALITY.
	if kind == "vless" {
		if reality, ok := asMap(m["reality-opts"]); ok && strings.TrimSpace(mstr(reality["public-key"])) != "" {
			for k := range reality {
				if k != "public-key" && k != "short-id" && k != "support-x25519mlkem768" {
					return "", "", errors.New("Reality 参数无法转换为 Surge")
				}
			}
			if network == "ws" {
				return "", "", errors.New("Surge 的 REALITY 不支持 WebSocket")
			}
			sp.set("reality-public-key", mstr(reality["public-key"]))
			if sid := mstr(reality["short-id"]); sid != "" {
				sp.set("reality-short-id", sid)
			}
		} else if mbool(m["tls"]) {
			sp.set("tls", "true")
		} else if mstr(m["flow"]) != "" {
			return "", "", errors.New("VLESS Vision 需要 TLS 或 REALITY")
		} else if network == "grpc" {
			return "", "", errors.New("Surge 的 gRPC 需要 TLS 或 REALITY")
		}
		surgeType = surgeKindVLESS
	}
	tls := kind != "ss" && kind != "snell" && (kind != "vless" || mbool(m["tls"]) || sp.vals["reality-public-key"] != "")
	if tls {
		sni := mstr(m["sni"])
		if sni == "" {
			sni = mstr(m["servername"])
		}
		if sni != "" {
			sp.set("sni", sni)
		}
		alpn := mstrings(m["alpn"])
		for _, a := range alpn {
			if !surgeSafe(a) {
				return "", "", errors.New("ALPN 无法转换为 Surge")
			}
		}
		if len(alpn) == 1 {
			sp.set("alpn", alpn[0])
		} else if len(alpn) > 1 {
			// The only value written in quotes, built from checked parts.
			sp.set("alpn", "\""+strings.Join(alpn, ",")+"\"")
		} else if surgeType == "tuic-v5" || surgeType == "tuic" {
			sp.set("alpn", "h3")
		}
		if sp.vals["reality-public-key"] == "" {
			if fp := strings.ToLower(strings.ReplaceAll(mstr(m["fingerprint"]), ":", "")); fp != "" {
				if !pinnedCertificate(fp) {
					return "", "", errors.New("证书指纹无效")
				}
				sp.set("server-cert-fingerprint-sha256", fp)
			} else if mbool(m["skip-cert-verify"]) {
				// The Mihomo converter only lets this through when the subscription allows
				// unverified imported nodes.
				sp.set("skip-cert-verify", "true")
			}
		}
	}
	if mbool(m["tfo"]) {
		sp.set("tfo", "true")
	}

	parts := []string{name + " = " + surgeType, host, strconv.Itoa(port)}
	for _, k := range sp.keys {
		v := sp.vals[k]
		if !surgeSafe(v) && !(k == "alpn" && strings.HasPrefix(v, "\"")) {
			return "", "", fmt.Errorf("节点参数 %s 含有 Surge 配置无法表示的字符", k)
		}
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, ", "), surgeType, nil
}

// surgeSafe reports a value that keeps its meaning in a comma-separated Surge line.
func surgeSafe(v string) bool {
	return v != "" && v == strings.TrimSpace(v) && !strings.ContainsAny(v, ",\"\r\n\x00")
}

func truncateKey(k string) string {
	if len(k) > 32 {
		return k[:32] + "…"
	}
	return k
}

func mstr(v any) string {
	switch s := v.(type) {
	case string:
		return s
	case fmt.Stringer:
		return s.String()
	}
	return ""
}

func mbool(v any) bool {
	b, _ := v.(bool)
	return b
}

func mint(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case uint64:
		return int(n), true
	case float64:
		if n == math.Trunc(n) {
			return int(n), true
		}
	case string:
		i, e := strconv.Atoi(n)
		return i, e == nil
	}
	return 0, false
}

func mstrings(v any) []string {
	switch s := v.(type) {
	case []string:
		return s
	case []any:
		out := make([]string, 0, len(s))
		for _, x := range s {
			if str := mstr(x); str != "" {
				out = append(out, str)
			}
		}
		return out
	case string:
		if s != "" {
			return []string{s}
		}
	}
	return nil
}

func asMap(v any) (map[string]any, bool) {
	switch m := v.(type) {
	case map[string]any:
		return m, true
	}
	return nil, false
}

// ---- subscription output -------------------------------------------------------------------

// surgeOptions select what a Surge list may contain.
type surgeOptions struct {
	VLESS bool // include VLESS lines (Surge iOS 6.0+ / Mac 6.12+)
}

const surgeVLESSHint = "VLESS 需要 Surge iOS 6.0+ / Mac 6.12+，默认不输出；在订阅链接后加 &vless=1 可包含"

// exportSurge resolves a subscription's local nodes into Surge lines (every node type).
func (s State) exportSurge(sub Subscription) (lines []string, warnings []string) {
	return s.exportSurgeWith(sub, nil, surgeOptions{VLESS: true})
}

// exportSurgeWith is the subscription's Surge list; aggregate subscriptions also carry their
// imported nodes.
func (s State) exportSurgeWith(sub Subscription, lookup remoteLookup, opts surgeOptions) (lines []string, warnings []string) {
	if sub.aggregate() {
		agg := s.exportAggregate(sub, lookup)
		return filterSurge(agg.Surge, opts, agg.SurgeWarnings)
	}
	byID := make(map[string]Profile, len(s.Profiles))
	for _, p := range s.Profiles {
		byID[p.ID] = p
	}
	var out []surgeEntry
	taken := map[string]bool{}
	for _, id := range sub.localIDs() {
		p, ok := byID[id]
		switch {
		case !ok:
			warnings = append(warnings, fmt.Sprintf("节点 %s 已删除，已跳过", id))
			continue
		case !p.Enabled:
			warnings = append(warnings, fmt.Sprintf("节点 %s 已停用，已跳过", p.Name))
			continue
		}
		line, kind, e := p.surgeLine(p.PublicHost, p.PublicPort)
		if e != nil {
			warnings = append(warnings, fmt.Sprintf("节点 %s 无法生成 Surge 配置：%s", p.Name, e.Error()))
			continue
		}
		name := uniqueSurgeName(taken, line[:strings.Index(line, " = ")])
		out = append(out, surgeEntry{Line: renameSurgeLine(line, name), Kind: kind, Label: p.Name})
	}
	return filterSurge(out, opts, warnings)
}

// surgeEntry is one Surge line with what the version gate needs.
type surgeEntry struct {
	Line  string
	Kind  string
	Label string
}

func filterSurge(entries []surgeEntry, opts surgeOptions, warnings []string) ([]string, []string) {
	var lines []string
	gated := []string{}
	for _, en := range entries {
		if en.Kind == surgeKindVLESS && !opts.VLESS {
			gated = append(gated, en.Label)
			continue
		}
		lines = append(lines, en.Line)
	}
	if len(gated) > 0 {
		sort.Strings(gated)
		warnings = append(warnings, fmt.Sprintf("已跳过 %d 个 VLESS 节点：%s", len(gated), surgeVLESSHint))
	}
	return lines, warnings
}

// allSurge is every node's and relay's Surge line, names made unique, ready to paste into a
// profile's [Proxy] section.
func allSurge(s State) string {
	taken := map[string]bool{}
	var b strings.Builder
	for _, p := range s.Profiles {
		line, e := p.SurgeLine(p.PublicHost, p.PublicPort)
		if e != nil {
			continue
		}
		fmt.Fprintln(&b, renameSurgeLine(line, uniqueSurgeName(taken, line[:strings.Index(line, " = ")])))
	}
	return b.String()
}

func renderSurge(lines []string) string { return strings.Join(lines, "\n") + "\n" }
