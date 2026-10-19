package rout

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const Version = "0.3.2"

type State struct {
	Schema   int       `json:"schema"`
	Profiles []Profile `json:"profiles"`
	Exits    []Exit    `json:"exits,omitempty"`
	// AI Smart Routing settings (see ai_routing.go); absent until first configured.
	AI *AIRouting `json:"ai_routing,omitempty"`
}

type Proxy struct {
	Protocol string `json:"protocol"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type Profile struct {
	ID           string         `json:"id"`
	Name         string         `json:"name"`
	Kind         string         `json:"kind"`
	Enabled      bool           `json:"enabled"`
	Protocol     string         `json:"protocol"`
	Listen       string         `json:"listen"`
	Port         int            `json:"port"`
	PublicHost   string         `json:"public_host"`
	PublicPort   int            `json:"public_port"`
	NAT          bool           `json:"nat"`
	SNI          string         `json:"sni,omitempty"`
	UUID         string         `json:"uuid,omitempty"`
	Password     string         `json:"password,omitempty"`
	PrivateKey   string         `json:"private_key,omitempty"`
	PublicKey    string         `json:"public_key,omitempty"`
	ShortID      string         `json:"short_id,omitempty"`
	Method       string         `json:"method,omitempty"`
	CertPEM      string         `json:"certificate_pem,omitempty"`
	KeyPEM       string         `json:"key_pem,omitempty"`
	Target       string         `json:"target,omitempty"`
	TargetURI    string         `json:"target_uri,omitempty"`
	Outbound     *Proxy         `json:"outbound,omitempty"`
	ExitID       string         `json:"exit_id,omitempty"`
	Network      string         `json:"network,omitempty"`
	RelayMode    string         `json:"relay_mode,omitempty"` // relay destination: "local"/"remote"; inferred when empty (pre-v0.3)
	TLSGenerated bool           `json:"tls_generated,omitempty"`
	Traffic      *TrafficPolicy `json:"traffic,omitempty"`
	CreatedAt    *time.Time     `json:"created_at,omitempty"`
	// AIRoute is derived from State.AI, never stored: see State.withAIRoutes.
	AIRoute *AIRoute `json:"-"`
}

var idPattern = regexp.MustCompile(`^[a-f0-9]{12}$`)
var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$`)

func RandomHex(n int) string {
	b := make([]byte, n)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b)
}
func RandomPassword(n int) string {
	b := make([]byte, n)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return base64.StdEncoding.EncodeToString(b)
}
func NewProfile(protocol string) (Profile, error) {
	p := Profile{ID: RandomHex(6), Name: protocol, Kind: "node", Enabled: true, Protocol: protocol, Listen: "0.0.0.0", Password: RandomPassword(24), Method: "2022-blake3-aes-128-gcm", SNI: "addons.mozilla.org"}
	now := time.Now()
	p.CreatedAt = &now
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		return p, e
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	h := hex.EncodeToString(b)
	p.UUID = h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
	if protocol == "vless" || protocol == "anytls" {
		key, e := ecdh.X25519().GenerateKey(rand.Reader)
		if e != nil {
			return p, e
		}
		p.PrivateKey = base64.RawURLEncoding.EncodeToString(key.Bytes())
		p.PublicKey = base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
		p.ShortID = RandomHex(4)
	}
	if protocol == "ss" {
		p.Password = RandomPassword(16)
	}
	return p, nil
}

func validPort(p int) bool { return p > 0 && p <= 65535 }
func validHost(h string) bool {
	if net.ParseIP(h) != nil {
		return true
	}
	if len(h) == 0 || len(h) > 253 {
		return false
	}
	for _, part := range strings.Split(strings.TrimSuffix(h, "."), ".") {
		if len(part) == 0 || len(part) > 63 || part[0] == '-' || part[len(part)-1] == '-' {
			return false
		}
		for _, c := range part {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// sameHost compares two host strings; IP literals compare by value, so differently written
// IPv6 forms (case, zero compression) of one address are equal. Names compare
// case-insensitively.
func sameHost(a, b string) bool {
	if x, y := net.ParseIP(a), net.ParseIP(b); x != nil && y != nil {
		return x.Equal(y)
	}
	return strings.EqualFold(strings.TrimSuffix(a, "."), strings.TrimSuffix(b, "."))
}

// validHostStrict is validHost for newly typed addresses: a name whose last label is all
// digits (999.1.1.1, 1.2.3) is a malformed IPv4 literal, never a domain. Stored state keeps
// the looser validHost so a configuration written by an older version always loads.
func validHostStrict(h string) bool {
	if !validHost(h) {
		return false
	}
	if net.ParseIP(h) != nil {
		return true
	}
	parts := strings.Split(strings.TrimSuffix(h, "."), ".")
	return strings.Trim(parts[len(parts)-1], "0123456789") != ""
}

// validPublicHost is the stricter check for the address clients are told to connect to:
// an address no client on the Internet can use (unspecified, multicast, link-local such as
// fe80::/10 or 169.254/16) is refused. Stored state keeps the looser validHost so an old
// configuration always stays loadable.
func validPublicHost(h string) bool {
	if !validHostStrict(h) {
		return false
	}
	if ip := net.ParseIP(h); ip != nil {
		return !ip.IsUnspecified() && !ip.IsMulticast() && !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast()
	}
	return true
}
func ParseEndpoint(s string) (string, int, error) {
	h, p, e := net.SplitHostPort(strings.TrimSpace(s))
	if e != nil {
		return "", 0, errors.New("地址格式应为 IP或域名:端口，IPv6 使用 [地址]:端口")
	}
	n, e := strconv.Atoi(p)
	if e != nil || !validPort(n) || !validHost(h) {
		return "", 0, errors.New("地址或端口无效")
	}
	return h, n, nil
}

// The protocol is selected before input. SplitN preserves colons in passwords.
func ParseProxy(protocol, input string) (*Proxy, error) {
	if protocol != "socks5" && protocol != "http" && protocol != "https" {
		return nil, errors.New("请选择 SOCKS5、HTTP 或 HTTPS")
	}
	s := strings.TrimSpace(input)
	var fields []string
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]:")
		if end < 0 {
			return nil, errors.New("IPv6 格式错误")
		}
		fields = append([]string{s[1:end]}, strings.SplitN(s[end+2:], ":", 3)...)
	} else {
		fields = strings.SplitN(s, ":", 4)
	}
	if len(fields) != 4 {
		return nil, errors.New("请输入 IP:端口:用户名:密码 四项")
	}
	n, e := strconv.Atoi(fields[1])
	if e != nil || !validPort(n) || !validHost(fields[0]) || fields[2] == "" || fields[3] == "" {
		return nil, errors.New("地址、端口、用户名或密码无效")
	}
	for _, v := range fields {
		if strings.ContainsAny(v, "\r\n\x00") {
			return nil, errors.New("输入包含无效字符")
		}
	}
	return &Proxy{protocol, fields[0], n, fields[2], fields[3]}, nil
}
func (p Proxy) Validate() error {
	if strings.Contains(p.Username, ":") {
		return errors.New("用户名不能包含冒号")
	}
	_, e := ParseProxy(p.Protocol, net.JoinHostPort(p.Host, strconv.Itoa(p.Port))+":"+p.Username+":"+p.Password)
	return e
}

// Formatting a proxy must never disclose credentials, including in diagnostics.
func (p Proxy) String() string {
	return p.Protocol + "://" + net.JoinHostPort(p.Host, strconv.Itoa(p.Port))
}
func (p Proxy) GoString() string { return p.String() }

func proxySecurityWarning(p Proxy) string {
	if p.Protocol == "https" {
		return ""
	}
	return "SOCKS5/HTTP 出站链路未加密，账号密码可能被窃听；旧配置保持原样。请显式改用验证证书的 HTTPS CONNECT，或将 SOCKS5 放入 SSH 隧道（见 docs/AI_ROUTING.md）"
}
func (p Profile) Networks() []string {
	if p.Kind == "relay" {
		if p.Protocol == "both" {
			return []string{"tcp", "udp"}
		}
		return []string{p.Protocol}
	}
	if p.Protocol == "hy2" || p.Protocol == "tuic" {
		return []string{"udp"}
	}
	if p.Protocol == "ss" {
		if p.Network != "" {
			return []string{p.Network}
		}
		return []string{"tcp", "udp"}
	}
	return []string{"tcp"}
}

func (p Profile) Validate() error {
	if p.Traffic != nil {
		if e := p.Traffic.Validate(); e != nil {
			return e
		}
	}
	if p.Network != "" && (p.Protocol != "ss" || (p.Network != "tcp" && p.Network != "udp")) {
		return errors.New("节点网络限制无效")
	}
	if !idPattern.MatchString(p.ID) {
		return errors.New("节点 ID 无效")
	}
	if strings.TrimSpace(p.Name) == "" || len(p.Name) > 160 || strings.ContainsAny(p.Name, "\r\n\x00") {
		return errors.New("节点名称无效")
	}
	if net.ParseIP(p.Listen) == nil || !validPort(p.Port) || !validPort(p.PublicPort) || !validHost(p.PublicHost) {
		return errors.New("监听地址、公网地址或端口无效")
	}
	if p.Kind == "relay" {
		if p.Protocol != "tcp" && p.Protocol != "udp" && p.Protocol != "both" {
			return errors.New("转发类型无效")
		}
		if p.RelayMode != "" && p.RelayMode != relayLocal && p.RelayMode != relayRemote {
			return errors.New("中转目标类型无效")
		}
		h, n, e := ParseEndpoint(p.Target)
		if e != nil {
			return e
		}
		localIP := net.ParseIP(h)
		if (sameHost(h, p.PublicHost) && n == p.PublicPort) || (n == p.Port && (h == p.Listen || h == "localhost" || (localIP != nil && localIP.IsLoopback()))) {
			return errors.New("目标地址指向本中转自身，会形成转发循环")
		}
		if p.TargetURI != "" {
			target, network, e := ParseTarget(p.TargetURI)
			if e != nil {
				return e
			}
			// A local relay may reuse a managed node's link only to build its share link;
			// the target is then 127.0.0.1, not the address inside that link.
			if target != p.Target && p.RelayMode != relayLocal {
				return errors.New("目标与节点链接不一致")
			}
			if network != "both" && p.Protocol != network {
				return errors.New("转发网络与节点协议不匹配")
			}
		}
		if p.Outbound != nil {
			return errors.New("中转节点不能使用出站代理")
		}
		return nil
	}
	if p.Kind != "node" {
		return errors.New("节点类型无效")
	}
	if p.Outbound != nil {
		if e := p.Outbound.Validate(); e != nil {
			return e
		}
	}
	switch p.Protocol {
	case "vless", "anytls":
		if !validHost(p.SNI) || net.ParseIP(p.SNI) != nil {
			return errors.New("Reality SNI 应为有效域名")
		}
		priv, e := base64.RawURLEncoding.DecodeString(p.PrivateKey)
		if e != nil {
			return errors.New("Reality 私钥无效")
		}
		key, e := ecdh.X25519().NewPrivateKey(priv)
		if e != nil || base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()) != p.PublicKey {
			return errors.New("Reality 密钥不匹配")
		}
		sid, e := hex.DecodeString(p.ShortID)
		if e != nil || len(sid) == 0 || len(sid) > 8 {
			return errors.New("Reality Short ID 无效")
		}
		if p.Protocol == "vless" && !uuidPattern.MatchString(p.UUID) {
			return errors.New("UUID 无效")
		}
	case "ss":
		if p.Method != "2022-blake3-aes-128-gcm" {
			return errors.New("不支持的 SS 加密方式")
		}
		b, e := base64.StdEncoding.DecodeString(p.Password)
		if e != nil || len(b) != 16 {
			return errors.New("SS2022 密钥应为 16 字节 Base64")
		}
	case "hy2", "tuic":
		if !validHost(p.SNI) {
			return errors.New("TLS SNI 无效")
		}
		pair, e := tls.X509KeyPair([]byte(p.CertPEM), []byte(p.KeyPEM))
		if e != nil || len(pair.Certificate) == 0 {
			return errors.New("证书和私钥无效或不匹配")
		}
		leaf, e := x509.ParseCertificate(pair.Certificate[0])
		if e != nil || leaf.VerifyHostname(p.SNI) != nil {
			return errors.New("证书域名不匹配")
		}
		if p.Protocol == "tuic" && !uuidPattern.MatchString(p.UUID) {
			return errors.New("UUID 无效")
		}
	default:
		return errors.New("不支持的节点协议")
	}
	if p.Password == "" {
		return errors.New("密码不能为空")
	}
	return nil
}

// Combinations that are structurally valid but cannot carry traffic. Checked for new or
// edited entries only, so an existing state file always stays loadable and repairable.
func (p Profile) CheckCompatibility() error {
	if p.Kind == "node" && p.Protocol == "ss" && p.Network == "udp" && p.Outbound != nil {
		return errors.New("仅 UDP 的 Shadowsocks 不能使用出站代理（出站代理只转发 TCP），请使用 TCP＋UDP 映射或改为直连")
	}
	return nil
}

func (p Profile) Ready() error {
	if p.Kind != "node" || (p.Protocol != "hy2" && p.Protocol != "tuic") || !p.Enabled {
		return nil
	}
	pair, e := tls.X509KeyPair([]byte(p.CertPEM), []byte(p.KeyPEM))
	if e != nil {
		return errors.New("证书无效")
	}
	leaf, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil || time.Now().Before(leaf.NotBefore) || time.Now().After(leaf.NotAfter) {
		return errors.New("证书尚未生效或已过期，请更新证书后启用")
	}
	return nil
}

func (s State) Validate() error {
	if s.Schema != 1 && s.Schema != 2 {
		return errors.New("不支持的配置版本")
	}
	if e := s.validateExits(); e != nil {
		return e
	}
	if e := s.validateAI(); e != nil {
		return e
	}
	ids := map[string]bool{}
	ports := map[string]string{}
	for _, p := range s.Profiles {
		if p.trafficPolicy().LimitBytes > 0 && s.Schema != 2 {
			return errors.New("有限额配置必须使用保护版本，不能降级绕过限额")
		}
		if e := p.Validate(); e != nil {
			return fmt.Errorf("%s: %w", p.Name, e)
		}
		if ids[p.ID] {
			return errors.New("节点 ID 重复")
		}
		ids[p.ID] = true
		// Reserve the same network/port across addresses: conservative and portable.
		if p.Enabled {
			for _, network := range p.Networks() {
				key := network + ":" + strconv.Itoa(p.Port)
				if prev, ok := ports[key]; ok {
					return fmt.Errorf("%s 与 %s 占用相同 %s 端口", prev, p.Name, network)
				}
				ports[key] = p.Name
			}
		}
	}
	return nil
}

func ParseTarget(input string) (string, string, error) {
	s := strings.TrimSpace(input)
	if !strings.Contains(s, "://") {
		h, p, e := ParseEndpoint(s)
		return net.JoinHostPort(h, strconv.Itoa(p)), "tcp", e
	}
	u, e := url.Parse(s)
	if e != nil {
		return "", "", errors.New("节点链接解析失败")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme == "ss" && u.Hostname() == "" {
		return "", "", errors.New("请使用 SIP002 格式 SS 链接：ss://凭据@地址:端口")
	}
	network := "tcp"
	switch scheme {
	case "vless", "anytls", "trojan":
	case "ss":
		network = "both"
	case "hy2", "hysteria2", "tuic":
		network = "udp"
	default:
		return "", "", errors.New("暂不支持此链接，请手动填写目标地址和端口")
	}
	if scheme == "ss" && u.Query().Get("plugin") != "" {
		return "", "", errors.New("首版不支持 SS 插件链接")
	}
	h, p, e := ParseEndpoint(u.Host)
	if e != nil {
		return "", "", e
	}
	if u.User == nil || u.User.String() == "" {
		return "", "", errors.New("节点链接缺少认证信息")
	}
	return net.JoinHostPort(h, strconv.Itoa(p)), network, nil
}

func RewriteURI(raw, host string, port int, name string) (string, error) {
	if _, _, e := ParseTarget(raw); e != nil {
		return "", e
	}
	u, _ := url.Parse(raw)
	oldHost := u.Hostname()
	q := u.Query()
	// Preserve the original TLS identity and HTTP virtual host after moving the socket.
	if u.Scheme != "ss" && q.Get("sni") == "" && q.Get("peer") == "" {
		q.Set("sni", oldHost)
	}
	if q.Get("type") == "ws" && q.Get("host") == "" {
		q.Set("host", oldHost)
	}
	if q.Get("type") == "grpc" && q.Get("authority") == "" {
		q.Set("authority", oldHost)
	}
	u.Host = net.JoinHostPort(host, strconv.Itoa(port))
	u.RawQuery = q.Encode()
	u.Fragment = name
	// Keep the credentials exactly as written: re-encoding would drop SIP002's
	// required percent-encoding of "+", "/" and "=" in AEAD-2022 keys.
	return withRawUserinfo(u.String(), raw), nil
}

// userinfoSpan locates the userinfo inside scheme://userinfo@host/...
func userinfoSpan(s string) (start, end int, ok bool) {
	i := strings.Index(s, "://")
	if i < 0 {
		return 0, 0, false
	}
	rest := s[i+3:]
	stop := strings.IndexAny(rest, "/?#")
	if stop < 0 {
		stop = len(rest)
	}
	at := strings.LastIndex(rest[:stop], "@")
	if at < 0 {
		return 0, 0, false
	}
	return i + 3, i + 3 + at, true
}
func withRawUserinfo(out, original string) string {
	from, to, ok1 := userinfoSpan(original)
	start, end, ok2 := userinfoSpan(out)
	if !ok1 || !ok2 {
		return out
	}
	return out[:start] + original[from:to] + out[end:]
}

func (p Profile) URI() (string, error) { return p.URIAt(p.PublicHost, p.PublicPort) }

// URIAt builds the share link for another address of the same node (for example its IPv6
// address when the primary link uses IPv4). Credentials and parameters are identical; only
// the endpoint changes. IPv6 literals are bracketed by net.JoinHostPort.
func (p Profile) URIAt(host string, port int) (string, error) {
	if p.Kind == "relay" {
		if p.TargetURI == "" {
			return "", errors.New("此中转没有目标节点的分享链接；客户端请直接连接中转入口")
		}
		return RewriteURI(p.TargetURI, host, port, p.Name)
	}
	u := &url.URL{Host: net.JoinHostPort(host, strconv.Itoa(port)), Fragment: p.Name}
	q := url.Values{}
	switch p.Protocol {
	case "vless", "anytls":
		q.Set("security", "reality")
		q.Set("sni", p.SNI)
		q.Set("pbk", p.PublicKey)
		q.Set("sid", p.ShortID)
		q.Set("fp", "chrome")
		u.Scheme = p.Protocol
		if p.Protocol == "vless" {
			u.User = url.User(p.UUID)
			q.Set("encryption", "none")
			q.Set("flow", "xtls-rprx-vision")
			q.Set("type", "tcp")
		} else {
			u.User = url.User(p.Password)
		}
	case "ss":
		// SIP002: AEAD-2022 userinfo MUST NOT be Base64URL-encoded; method and password
		// are percent-encoded instead ("+", "/" and "=" of the key included).
		fragment := (&url.URL{Fragment: p.Name}).String()
		return "ss://" + url.QueryEscape(p.Method) + ":" + url.QueryEscape(p.Password) + "@" + u.Host + fragment, nil
	case "hy2":
		u.Scheme = "hysteria2"
		u.User = url.User(p.Password)
		q.Set("sni", p.SNI)
		if p.TLSGenerated {
			pin, e := CertificatePin(p.CertPEM)
			if e != nil {
				return "", e
			}
			q.Set("insecure", "1")
			q.Set("pinSHA256", pin)
		}
	case "tuic":
		u.Scheme = "tuic"
		u.User = url.UserPassword(p.UUID, p.Password)
		q.Set("sni", p.SNI)
		q.Set("congestion_control", "bbr")
		q.Set("alpn", "h3")
	default:
		return "", errors.New("不支持的协议")
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}
