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

const Version = "0.1.0"

type State struct {
	Schema   int       `json:"schema"`
	Profiles []Profile `json:"profiles"`
}

type Proxy struct {
	Protocol string `json:"protocol"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type Profile struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Enabled    bool   `json:"enabled"`
	Protocol   string `json:"protocol"`
	Listen     string `json:"listen"`
	Port       int    `json:"port"`
	PublicHost string `json:"public_host"`
	PublicPort int    `json:"public_port"`
	NAT        bool   `json:"nat"`
	SNI        string `json:"sni,omitempty"`
	UUID       string `json:"uuid,omitempty"`
	Password   string `json:"password,omitempty"`
	PrivateKey string `json:"private_key,omitempty"`
	PublicKey  string `json:"public_key,omitempty"`
	ShortID    string `json:"short_id,omitempty"`
	Method     string `json:"method,omitempty"`
	CertPEM    string `json:"certificate_pem,omitempty"`
	KeyPEM     string `json:"key_pem,omitempty"`
	Target     string `json:"target,omitempty"`
	TargetURI  string `json:"target_uri,omitempty"`
	Outbound   *Proxy `json:"outbound,omitempty"`
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
	if protocol != "socks5" && protocol != "http" {
		return nil, errors.New("请选择 SOCKS5 或 HTTP")
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
		return []string{"tcp", "udp"}
	}
	return []string{"tcp"}
}

func (p Profile) Validate() error {
	if !idPattern.MatchString(p.ID) {
		return errors.New("线路 ID 无效")
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
		h, n, e := ParseEndpoint(p.Target)
		if e != nil {
			return e
		}
		localIP := net.ParseIP(h)
		if (strings.EqualFold(h, p.PublicHost) && n == p.PublicPort) || (n == p.Port && (h == p.Listen || h == "localhost" || (localIP != nil && localIP.IsLoopback()))) {
			return errors.New("目标地址指向本线路，会形成循环")
		}
		if p.TargetURI != "" {
			target, network, e := ParseTarget(p.TargetURI)
			if e != nil {
				return e
			}
			if target != p.Target {
				return errors.New("目标与节点链接不一致")
			}
			if network != "both" && p.Protocol != network {
				return errors.New("转发网络与节点协议不匹配")
			}
		}
		if p.Outbound != nil {
			return errors.New("原样转发线路不能绑定代理出口")
		}
		return nil
	}
	if p.Kind != "node" {
		return errors.New("线路类型无效")
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
	if s.Schema != 1 {
		return errors.New("不支持的配置版本")
	}
	ids := map[string]bool{}
	ports := map[string]string{}
	for _, p := range s.Profiles {
		if e := p.Validate(); e != nil {
			return fmt.Errorf("%s: %w", p.Name, e)
		}
		if ids[p.ID] {
			return errors.New("线路 ID 重复")
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
	return u.String(), nil
}

func (p Profile) URI() (string, error) {
	if p.Kind == "relay" {
		if p.TargetURI == "" {
			return "", errors.New("此线路使用手动目标地址，没有原始协议链接")
		}
		return RewriteURI(p.TargetURI, p.PublicHost, p.PublicPort, p.Name)
	}
	u := &url.URL{Host: net.JoinHostPort(p.PublicHost, strconv.Itoa(p.PublicPort)), Fragment: p.Name}
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
		u.Scheme = "ss"
		u.User = url.User(base64.RawURLEncoding.EncodeToString([]byte(p.Method + ":" + p.Password)))
	case "hy2":
		u.Scheme = "hysteria2"
		u.User = url.User(p.Password)
		q.Set("sni", p.SNI)
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
