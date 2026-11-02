package remote

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$`)

// ssMethods are the Shadowsocks ciphers a subscription may use. Legacy stream ciphers are
// refused: they are broken, and silently relaying them would give a false sense of safety.
var ssMethods = map[string]bool{
	"aes-128-gcm": true, "aes-192-gcm": true, "aes-256-gcm": true,
	"chacha20-ietf-poly1305": true, "xchacha20-ietf-poly1305": true,
	"2022-blake3-aes-128-gcm": true, "2022-blake3-aes-256-gcm": true, "2022-blake3-chacha20-poly1305": true,
}

type unsupportedError struct{ reason string }

func (e unsupportedError) Error() string { return e.reason }

// IsUnsupported reports whether err means "recognised but not importable" (as opposed to
// malformed input).
func IsUnsupported(err error) bool { var u unsupportedError; return errors.As(err, &u) }

func decodeB64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("Base64 无效")
}

// ParseLink reads one share link. The returned node keeps the original link (with a
// canonical form for legacy Shadowsocks), so nothing the source specified is dropped.
func ParseLink(raw string) (Node, error) {
	n, err := parseLinkNode(raw)
	if err == nil {
		n.deriveIdentity()
	}
	return n, err
}

func parseLinkNode(raw string) (Node, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > maxLinkBytes || strings.ContainsAny(raw, "\r\n\x00") {
		return Node{}, errors.New("链接为空或过长")
	}
	scheme, _, ok := strings.Cut(raw, "://")
	if !ok {
		return Node{}, errors.New("不是分享链接")
	}
	switch strings.ToLower(scheme) {
	case "vless":
		return parseURLNode(raw, "vless")
	case "trojan":
		return parseURLNode(raw, "trojan")
	case "anytls":
		return parseURLNode(raw, "anytls")
	case "hysteria2", "hy2":
		return parseURLNode(raw, "hysteria2")
	case "tuic":
		return parseURLNode(raw, "tuic")
	case "ss":
		return parseSS(raw)
	case "vmess", "ssr", "hysteria", "wireguard", "socks", "socks5", "http", "https", "naive+https", "snell", "ssh":
		return Node{}, unsupportedError{fmt.Sprintf("暂不支持 %s 协议", strings.ToLower(scheme))}
	}
	return Node{}, unsupportedError{fmt.Sprintf("未知协议 %s", truncate(strings.ToLower(scheme), 20))}
}

func truncate(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

func parseURLNode(raw, protocol string) (Node, error) {
	u, err := url.Parse(raw)
	if err != nil {
		if protocol == "hysteria2" && strings.Contains(raw, ",") {
			return Node{}, unsupportedError{"Hysteria2 多端口（端口跳跃）暂不支持导入"}
		}
		return Node{}, errors.New("链接格式无效")
	}
	host := u.Hostname()
	port, perr := strconv.Atoi(u.Port())
	if !validHost(host) || perr != nil || port < 1 || port > 65535 {
		return Node{}, errors.New("服务器地址或端口无效")
	}
	if u.User == nil || u.User.Username() == "" {
		return Node{}, errors.New("链接缺少认证信息")
	}
	q := u.Query()
	n := Node{Protocol: protocol, Server: host, Port: port, Name: cleanName(u.Fragment), Link: raw, Security: "none", Transport: "tcp"}
	if n.Name == "" {
		n.Name = net.JoinHostPort(host, strconv.Itoa(port))
	}
	n.SNI = first(q.Get("sni"), q.Get("peer"))
	cred := u.User.Username()
	switch protocol {
	case "vless":
		if !uuidRe.MatchString(cred) {
			return Node{}, errors.New("VLESS UUID 无效")
		}
		if enc := q.Get("encryption"); enc != "" && enc != "none" {
			return Node{}, unsupportedError{fmt.Sprintf("VLESS 加密参数 %s 暂不支持", truncate(enc, 20))}
		}
		if _, has := u.User.Password(); has {
			return Node{}, errors.New("VLESS 链接认证信息无效")
		}
		n.Security = securityOf(q.Get("security"))
		n.Transport = transportOf(q.Get("type"))
	case "trojan":
		if pw, has := u.User.Password(); has {
			cred += ":" + pw
		}
		n.Security = securityOf(first(q.Get("security"), "tls"))
		n.Transport = transportOf(q.Get("type"))
	case "anytls":
		if pw, has := u.User.Password(); has {
			cred += ":" + pw
		}
		n.Security = securityOf(first(q.Get("security"), "tls"))
	case "hysteria2":
		if pw, has := u.User.Password(); has {
			cred += ":" + pw
		}
		n.Security, n.UDP = "tls", true
	case "tuic":
		pw, has := u.User.Password()
		if !has || pw == "" || !uuidRe.MatchString(cred) {
			return Node{}, errors.New("TUIC 认证信息无效")
		}
		cred += ":" + pw
		n.Security, n.UDP = "tls", true
	}
	if n.Security == "?" {
		return Node{}, unsupportedError{fmt.Sprintf("无法识别的 TLS 类型 %s", truncate(q.Get("security"), 20))}
	}
	if n.SNI == "" && n.Security != "none" {
		n.SNI = host
	}
	if placeholderHost(host) {
		return Node{}, placeholderError{}
	}
	n.seal(cred)
	return n, nil
}

type placeholderError struct{}

func (placeholderError) Error() string {
	return "信息占位条目（地址为本机或示例域名），已忽略"
}

// IsPlaceholder reports an informational pseudo-entry rather than a real proxy.
func IsPlaceholder(err error) bool { _, ok := err.(placeholderError); return ok }

func first(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func securityOf(s string) string {
	switch strings.ToLower(s) {
	case "", "none":
		return "none"
	case "tls", "xtls":
		return "tls"
	case "reality":
		return "reality"
	}
	return "?"
}

func transportOf(t string) string {
	if t == "" {
		return "tcp"
	}
	return strings.ToLower(truncate(t, 20))
}

// parseSS reads both SIP002 (ss://userinfo@host:port) and the legacy all-Base64 form, and
// stores the SIP002 spelling Rout itself produces.
func parseSS(raw string) (Node, error) {
	body := raw[len("ss://"):]
	frag := ""
	if i := strings.IndexByte(body, '#'); i >= 0 {
		frag, body = body[i+1:], body[:i]
	}
	name, _ := url.PathUnescape(frag)
	query := ""
	if i := strings.IndexByte(body, '?'); i >= 0 {
		query, body = body[i+1:], body[:i]
	}
	body = strings.TrimSuffix(body, "/")
	var method, password, hostport string
	if at := strings.LastIndexByte(body, '@'); at >= 0 {
		userinfo, hp := body[:at], body[at+1:]
		hostport = hp
		if strings.Contains(userinfo, ":") {
			m, p, _ := strings.Cut(userinfo, ":")
			var e1, e2 error
			method, e1 = url.QueryUnescape(m)
			password, e2 = url.QueryUnescape(p)
			if e1 != nil || e2 != nil {
				return Node{}, errors.New("Shadowsocks 凭据编码无效")
			}
		} else {
			dec, err := decodeB64(userinfo)
			if err != nil {
				return Node{}, errors.New("Shadowsocks 凭据无效")
			}
			m, p, ok := strings.Cut(string(dec), ":")
			if !ok {
				return Node{}, errors.New("Shadowsocks 凭据无效")
			}
			method, password = m, p
		}
	} else {
		dec, err := decodeB64(body)
		if err != nil {
			return Node{}, errors.New("Shadowsocks 链接无效")
		}
		// The host:port is last; a password may itself contain '@'.
		i := strings.LastIndex(string(dec), "@")
		if i < 0 {
			return Node{}, errors.New("Shadowsocks 链接无效")
		}
		cred, hp := string(dec)[:i], string(dec)[i+1:]
		m, p, ok := strings.Cut(cred, ":")
		if !ok {
			return Node{}, errors.New("Shadowsocks 凭据无效")
		}
		method, password, hostport = m, p, hp
	}
	host, portStr, err := net.SplitHostPort(hostport)
	port, perr := strconv.Atoi(portStr)
	if err != nil || perr != nil || !validHost(host) || port < 1 || port > 65535 {
		return Node{}, errors.New("服务器地址或端口无效")
	}
	if !ssMethods[method] {
		return Node{}, unsupportedError{fmt.Sprintf("不支持的 Shadowsocks 加密方式 %s", truncate(method, 30))}
	}
	if password == "" {
		return Node{}, errors.New("Shadowsocks 密码为空")
	}
	n := Node{Protocol: "ss", Server: host, Port: port, Name: cleanName(name), Security: "none", Transport: "tcp", UDP: true}
	if n.Name == "" {
		n.Name = net.JoinHostPort(host, portStr)
	}
	var userinfo string
	if strings.HasPrefix(method, "2022-") {
		userinfo = url.QueryEscape(method) + ":" + url.QueryEscape(password)
	} else {
		userinfo = base64.RawURLEncoding.EncodeToString([]byte(method + ":" + password))
	}
	n.Link = "ss://" + userinfo + "@" + net.JoinHostPort(host, portStr)
	if query != "" {
		q, qerr := url.ParseQuery(query)
		if qerr != nil {
			return Node{}, errors.New("Shadowsocks 参数无效")
		}
		if p := q.Get("plugin"); p != "" {
			n.Notes = append(n.Notes, fmt.Sprintf("Shadowsocks 插件 %s：仅 Base64 输出可保留", truncate(strings.SplitN(p, ";", 2)[0], 30)))
		}
		n.Link += "/?" + query
	}
	if placeholderHost(host) {
		return Node{}, placeholderError{}
	}
	n.Link = SetName(n.Link, n.Name)
	n.seal(method + ":" + password)
	return n, nil
}

// ParseLinks reads newline-separated share links.
func ParseLinks(text string) (Parsed, error) {
	p := Parsed{Format: "links"}
	seen := map[string]bool{}
	for i, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p.Entries++
		n, err := ParseLink(line)
		if err != nil {
			level := "error"
			if IsPlaceholder(err) {
				level = "skip"
			}
			scheme, _, _ := strings.Cut(line, "://")
			p.Issues = append(p.Issues, Issue{Level: level, Line: i + 1, Protocol: truncate(strings.ToLower(scheme), 20), Reason: err.Error()})
			continue
		}
		if seen[n.dedupeKey()] {
			p.Duplicates++
			continue
		}
		seen[n.dedupeKey()] = true
		p.Nodes = append(p.Nodes, n)
		if len(p.Nodes) > MaxNodes {
			return Parsed{}, fmt.Errorf("节点数量超过上限 %d", MaxNodes)
		}
	}
	return p, nil
}
