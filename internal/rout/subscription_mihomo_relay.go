package rout

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

func validMihomoPort(raw string) bool { p, e := strconv.Atoi(raw); return e == nil && validPort(p) }

// Relay links are already part of Rout's model. Refuse unknown/duplicate options
// instead of discarding transport or TLS settings while claiming compatibility.
func mihomoRelay(p Profile) (M, error) {
	raw, e := p.URI()
	if e != nil {
		return nil, errors.New("中转缺少可转换的目标分享链接，请使用 Base64 或补充目标链接")
	}
	u, e := url.Parse(raw)
	if e != nil || u.User == nil {
		return nil, errors.New("中转分享链接无效")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	password, _ := u.User.Password()
	if !utf8.ValidString(u.User.Username()) || !utf8.ValidString(password) || !utf8.ValidString(u.Path) {
		return nil, errors.New("中转参数不是有效的 UTF-8，请检查分享链接")
	}
	q, e := url.ParseQuery(u.RawQuery)
	if e != nil {
		return nil, errors.New("中转链接参数无效")
	}
	allowed := map[string]bool{}
	allow := func(keys string) {
		for _, key := range strings.Fields(keys) {
			allowed[key] = true
		}
	}
	switch u.Scheme {
	case "vless":
		allow("security sni peer type flow encryption pbk sid fp alpn host path serviceName authority allowInsecure insecure")
	case "trojan":
		allow("security sni peer type fp alpn pbk sid host path serviceName authority allowInsecure insecure")
	case "anytls":
		allow("security sni peer fp alpn allowInsecure insecure")
	case "ss":
	case "hysteria2", "hy2":
		allow("sni peer alpn insecure allowInsecure pinSHA256 obfs obfs-password")
	case "tuic":
		allow("sni peer alpn insecure allowInsecure pinSHA256 congestion_control udp_relay_mode")
	default:
		return nil, errors.New("此协议没有可靠的 Mihomo 映射，请使用 Base64")
	}
	for _, values := range q {
		for _, value := range values {
			if !utf8.ValidString(value) {
				return nil, errors.New("中转参数不是有效的 UTF-8，请检查分享链接")
			}
		}
	}
	for key, values := range q {
		if !allowed[key] || len(values) != 1 {
			return nil, errors.New("中转含有未支持或重复的参数，请使用 Base64 并检查传输与 TLS 设置")
		}
	}
	if u.Path != "" && u.Path != "/" {
		return nil, errors.New("中转链接路径无法安全转换，请使用 Base64")
	}
	if q.Get("sni") != "" && q.Get("peer") != "" && q.Get("sni") != q.Get("peer") {
		return nil, errors.New("中转 TLS 名称冲突，请检查 SNI 设置")
	}
	for _, key := range []string{"insecure", "allowInsecure"} {
		if q.Has(key) && q.Get(key) != "0" && q.Get(key) != "1" {
			return nil, errors.New("中转 TLS 验证参数无效")
		}
	}
	security := q.Get("security")
	if security != "" && security != "none" && security != "tls" && security != "reality" {
		return nil, errors.New("中转 TLS 类型无法安全转换，请使用 Base64")
	}
	if (u.Scheme == "trojan" || u.Scheme == "anytls") && security == "none" {
		return nil, errors.New("中转 TLS 类型无法安全转换，请使用 Base64")
	}
	if u.Scheme == "anytls" && security == "reality" {
		return nil, errors.New("Mihomo 不支持 AnyTLS Reality，请使用 Base64 或支持的节点")
	}
	if encryption := q.Get("encryption"); encryption != "" && encryption != "none" {
		return nil, errors.New("中转 VLESS 加密参数无法安全转换，请使用 Base64")
	}
	if flow := q.Get("flow"); flow != "" && (flow != "xtls-rprx-vision" || (q.Get("type") != "" && q.Get("type") != "tcp") || (security != "tls" && security != "reality")) {
		return nil, errors.New("中转 VLESS flow 与传输或 TLS 不兼容")
	}
	if u.Scheme == "vless" && !uuidPattern.MatchString(u.User.Username()) {
		return nil, errors.New("中转 UUID 无效")
	}
	if u.Scheme == "tuic" {
		if _, ok := u.User.Password(); !ok || !uuidPattern.MatchString(u.User.Username()) {
			return nil, errors.New("中转 TUIC 认证设置无效")
		}
	}
	if security == "reality" {
		key, e := base64.RawURLEncoding.DecodeString(q.Get("pbk"))
		if e != nil || len(key) != 32 {
			return nil, errors.New("中转 Reality 公钥无效")
		}
		sid, e := hex.DecodeString(q.Get("sid"))
		if e != nil || len(sid) > 8 {
			return nil, errors.New("中转 Reality Short ID 无效")
		}
	}
	if fp := q.Get("fp"); fp != "" {
		switch fp {
		case "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized", "chrome120", "firefox120", "safari16":
		default:
			return nil, errors.New("中转浏览器指纹尚未验证，请使用 Base64")
		}
	}
	// Existing URIOutbound deliberately rejects certificate pins for its diagnostic
	// client. Validate and preserve the pin here, removing it only from a temporary
	// parse copy. A pin never becomes skip-cert-verify without verification.
	pin := q.Get("pinSHA256")
	if pin != "" {
		b, e := hex.DecodeString(pin)
		if e != nil || len(b) != 32 {
			return nil, errors.New("中转证书指纹无效")
		}
	}
	insecure := q.Get("insecure") == "1" || q.Get("allowInsecure") == "1"
	if insecure && pin == "" {
		return nil, errors.New("拒绝导出未验证的 TLS 节点，请提供有效证书或证书指纹")
	}
	copied := *u
	copiedQuery := copied.Query()
	copiedQuery.Del("pinSHA256")
	copiedQuery.Del("insecure")
	copiedQuery.Del("allowInsecure")
	copied.RawQuery = copiedQuery.Encode()
	out, e := URIOutbound(copied.String())
	if e != nil {
		return nil, errors.New("中转协议或传输无法安全转换，请使用 Base64")
	}
	if tls, ok := out["tls"].(M); ok {
		if fp := q.Get("fp"); fp != "" {
			tls["utls"] = M{"enabled": true, "fingerprint": fp}
		}
		if q.Get("type") == "grpc" && q.Get("authority") != "" && q.Get("authority") != tls["server_name"] {
			return nil, errors.New("Mihomo 无法保留独立的 gRPC authority，请使用 Base64")
		}
	} else if q.Get("type") == "grpc" && q.Get("authority") != "" {
		return nil, errors.New("Mihomo 无法保留独立的 gRPC authority，请使用 Base64")
	} else if q.Get("fp") != "" || q.Get("alpn") != "" || pin != "" {
		return nil, errors.New("中转 TLS 参数与协议不兼容")
	}
	if u.Scheme != "ss" && u.Scheme != "vless" && u.Scheme != "tuic" {
		password := u.User.Username()
		if part, ok := u.User.Password(); ok {
			password += ":" + part
		}
		if password == "" {
			return nil, errors.New("中转认证信息无效")
		}
		out["password"] = password
	}
	if u.Scheme == "vless" {
		if _, hasPassword := u.User.Password(); hasPassword {
			return nil, errors.New("中转认证信息无效")
		}
	}
	if u.Scheme == "ss" {
		method, _ := out["method"].(string)
		password, _ := out["password"].(string)
		if password == "" {
			return nil, errors.New("中转认证信息无效")
		}
		keyLength := 0
		switch method {
		case "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305":
		case "2022-blake3-aes-128-gcm":
			keyLength = 16
		case "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
			keyLength = 32
		default:
			return nil, errors.New("中转 Shadowsocks 加密方式尚未验证，请使用 Base64")
		}
		if keyLength > 0 {
			for _, part := range strings.Split(password, ":") {
				key, e := base64.StdEncoding.DecodeString(part)
				if e != nil || len(key) != keyLength {
					return nil, errors.New("中转 Shadowsocks 密钥无效")
				}
			}
		}
	}
	proxy, e := mihomoOutbound(out)
	if e != nil {
		return nil, e
	}
	if pin != "" {
		proxy["fingerprint"] = strings.ToLower(pin)
	}
	if cc := q.Get("congestion_control"); cc != "" && cc != "bbr" && cc != "cubic" && cc != "new_reno" {
		return nil, errors.New("中转拥塞控制参数尚未验证，请使用 Base64")
	}
	if mode := q.Get("udp_relay_mode"); mode != "" {
		if mode != "native" && mode != "quic" {
			return nil, errors.New("中转 UDP 转发模式无效")
		}
		proxy["udp-relay-mode"] = mode
	}
	if obfs := q.Get("obfs"); obfs != "" {
		if obfs != "salamander" || q.Get("obfs-password") == "" {
			return nil, errors.New("中转混淆参数无法安全转换，请使用 Base64")
		}
		proxy["obfs"] = obfs
		proxy["obfs-password"] = q.Get("obfs-password")
	} else if q.Has("obfs-password") {
		return nil, errors.New("中转混淆参数无法安全转换，请使用 Base64")
	}
	// A TCP-only relay cannot carry a QUIC protocol; a UDP-only Shadowsocks
	// entry cannot be represented as a general Mihomo TCP+UDP proxy.
	kind := proxy["type"]
	if (kind == "tuic" || kind == "hysteria2") && !sharesNetwork(p.Networks(), []string{"udp"}) {
		return nil, errors.New("中转网络不支持目标节点协议")
	}
	if kind == "ss" && p.Protocol == "udp" {
		return nil, errors.New("仅 UDP 的 Shadowsocks 无法完整表示为 Mihomo 节点，请使用 Base64")
	}
	if kind == "ss" && !sharesNetwork(p.Networks(), []string{"udp"}) {
		proxy["udp"] = false
	}
	return proxy, nil
}
