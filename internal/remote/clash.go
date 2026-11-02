package remote

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Bounds on untrusted YAML. A subscription is attacker-influenced input, so parsing is capped
// in size, depth and the number of nodes visited (which also defeats alias expansion bombs).
const (
	MaxYAMLBytes  = 3 << 20
	maxYAMLLine   = 64 << 10
	maxYAMLLines  = 100_000
	maxYAMLVisits = 400_000
	maxYAMLDepth  = 20
	maxScalar     = 8 << 10
	maxProxyKeys  = 64
	maxProxyBytes = 32 << 10
)

var (
	errTooComplex = errors.New("YAML 结构过于复杂，已拒绝")
	errYAMLCycle  = errors.New("YAML 含有循环引用，已拒绝")
)

var proxiesKey = regexp.MustCompile(`^proxies[ \t]*:`)

// proxiesBlock returns only the top-level `proxies:` section, so a multi-megabyte rule list
// is never parsed. ok is false when the section cannot be isolated safely.
func proxiesBlock(data []byte) ([]byte, bool) {
	lines := bytes.Split(data, []byte("\n"))
	start := -1
	for i, l := range lines {
		if proxiesKey.Match(l) {
			if start >= 0 {
				return nil, false // two top-level proxies keys: let the full parser decide
			}
			start = i
		}
	}
	if start < 0 {
		return nil, false
	}
	rest := bytes.TrimSpace(bytes.TrimPrefix(bytes.TrimSpace(lines[start]), []byte("proxies")))
	rest = bytes.TrimSpace(bytes.TrimPrefix(rest, []byte(":")))
	if len(rest) > 0 && rest[0] != '#' {
		return nil, false // inline flow value: not isolated line by line
	}
	end := len(lines)
	for i := start + 1; i < len(lines); i++ {
		l := lines[i]
		if len(l) == 0 || l[0] == ' ' || l[0] == '\t' || l[0] == '#' || l[0] == '-' || l[0] == '\r' {
			continue
		}
		end = i
		break
	}
	return bytes.Join(lines[start:end], []byte("\n")), true
}

func checkYAMLShape(data []byte) error {
	if len(data) > MaxYAMLBytes {
		return fmt.Errorf("YAML 过大（上限 %d MiB）", MaxYAMLBytes>>20)
	}
	if bytes.IndexByte(data, 0) >= 0 {
		return errors.New("YAML 含有非法字符")
	}
	n := 0
	for _, l := range bytes.Split(data, []byte("\n")) {
		n++
		if len(l) > maxYAMLLine {
			return errTooComplex
		}
	}
	if n > maxYAMLLines {
		return errTooComplex
	}
	return nil
}

// converter turns yaml nodes into plain values under one shared budget: every node visited,
// alias followed and merge source expanded costs a visit, a node can never be entered while it
// is still being converted (which rejects cyclic aliases and merge sequences), and the context
// is polled so a cancelled or timed-out refresh stops promptly.
type converter struct {
	ctx    context.Context
	visits int
	active map[*yaml.Node]struct{}
}

func newConverter(ctx context.Context) *converter {
	if ctx == nil {
		ctx = context.Background()
	}
	return &converter{ctx: ctx, active: map[*yaml.Node]struct{}{}}
}

func (c *converter) tick() error {
	c.visits++
	if c.visits > maxYAMLVisits {
		return errTooComplex
	}
	if c.visits&0x3ff == 0 {
		if err := c.ctx.Err(); err != nil {
			return err
		}
	}
	return nil
}

// enter marks a container as being converted; it fails if the node is already on the path.
func (c *converter) enter(n *yaml.Node) error {
	if _, busy := c.active[n]; busy {
		return errYAMLCycle
	}
	c.active[n] = struct{}{}
	return nil
}

func (c *converter) leave(n *yaml.Node) { delete(c.active, n) }

func (c *converter) value(n *yaml.Node, depth int) (any, error) {
	if err := c.tick(); err != nil {
		return nil, err
	}
	if depth > maxYAMLDepth {
		return nil, errTooComplex
	}
	switch n.Kind {
	case yaml.AliasNode:
		if n.Alias == nil {
			return nil, errors.New("YAML 别名无效")
		}
		return c.value(n.Alias, depth+1)
	case yaml.DocumentNode:
		if len(n.Content) != 1 {
			return nil, errors.New("YAML 文档无效")
		}
		return c.value(n.Content[0], depth+1)
	case yaml.ScalarNode:
		if len(n.Value) > maxScalar {
			return nil, errTooComplex
		}
		var v any
		if err := n.Decode(&v); err != nil {
			return n.Value, nil
		}
		switch t := v.(type) {
		case nil, bool, string, float64:
			return t, nil
		case int:
			return int64(t), nil
		case int64:
			return t, nil
		case uint64:
			if t > 1<<62 {
				return n.Value, nil
			}
			return int64(t), nil
		case time.Time:
			return n.Value, nil
		}
		return n.Value, nil
	case yaml.SequenceNode:
		if err := c.enter(n); err != nil {
			return nil, err
		}
		defer c.leave(n)
		out := make([]any, 0, len(n.Content))
		for _, item := range n.Content {
			v, err := c.value(item, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case yaml.MappingNode:
		return c.mapping(n, depth)
	}
	return nil, errors.New("YAML 节点类型不支持")
}

func (c *converter) scalarKey(k *yaml.Node, depth int) (string, error) {
	for k.Kind == yaml.AliasNode {
		if k.Alias == nil || depth > maxYAMLDepth {
			return "", errTooComplex
		}
		k, depth = k.Alias, depth+1
	}
	if k.Kind != yaml.ScalarNode || len(k.Value) > 256 {
		return "", errors.New("YAML 键必须是短文本")
	}
	return k.Value, nil
}

func (c *converter) mapping(n *yaml.Node, depth int) (map[string]any, error) {
	if depth > maxYAMLDepth {
		return nil, errTooComplex
	}
	if err := c.enter(n); err != nil {
		return nil, err
	}
	defer c.leave(n)
	out := map[string]any{}
	var merges []*yaml.Node
	for i := 0; i+1 < len(n.Content); i += 2 {
		if err := c.tick(); err != nil {
			return nil, err
		}
		k, v := n.Content[i], n.Content[i+1]
		if k.ShortTag() == "!!merge" {
			merges = append(merges, v)
			continue
		}
		key, err := c.scalarKey(k, depth)
		if err != nil {
			return nil, err
		}
		if _, dup := out[key]; dup {
			return nil, errors.New("YAML 含有重复的键")
		}
		val, err := c.value(v, depth+1)
		if err != nil {
			return nil, err
		}
		out[key] = val
		if len(out) > 256 {
			return nil, errTooComplex
		}
	}
	for _, m := range merges {
		if err := c.mergeInto(out, m, depth+1); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// mergeInto applies one `<<` value: a mapping, an alias to one, or a (possibly nested)
// sequence of them. Earlier sources win over later ones and never over the node's own keys.
func (c *converter) mergeInto(out map[string]any, s *yaml.Node, depth int) error {
	if err := c.tick(); err != nil {
		return err
	}
	if depth > maxYAMLDepth {
		return errTooComplex
	}
	switch s.Kind {
	case yaml.AliasNode:
		if s.Alias == nil {
			return errors.New("YAML 别名无效")
		}
		return c.mergeInto(out, s.Alias, depth+1)
	case yaml.MappingNode:
		sub, err := c.mapping(s, depth+1)
		if err != nil {
			return err
		}
		for k, v := range sub {
			if _, has := out[k]; !has {
				out[k] = v
			}
		}
		return nil
	case yaml.SequenceNode:
		if err := c.enter(s); err != nil {
			return err
		}
		defer c.leave(s)
		for _, item := range s.Content {
			if err := c.mergeInto(out, item, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	return errors.New("YAML 合并键无效")
}

// clashProxies extracts the raw proxy mappings of a Clash/Mihomo document.
func clashProxies(ctx context.Context, data []byte) ([]map[string]any, error) {
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	if err := checkYAMLShape(data); err != nil {
		return nil, err
	}
	var seq *yaml.Node
	if block, ok := proxiesBlock(data); ok {
		var doc yaml.Node
		if err := yaml.Unmarshal(block, &doc); err == nil && len(doc.Content) == 1 && doc.Content[0].Kind == yaml.MappingNode {
			m := doc.Content[0]
			for i := 0; i+1 < len(m.Content); i += 2 {
				if m.Content[i].Value == "proxies" {
					seq = m.Content[i+1]
				}
			}
		}
	}
	if seq == nil {
		var doc yaml.Node
		if err := yaml.Unmarshal(data, &doc); err != nil {
			return nil, errors.New("YAML 解析失败")
		}
		if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
			return nil, errors.New("不是 Clash/Mihomo 配置（顶层必须是映射）")
		}
		m := doc.Content[0]
		for i := 0; i+1 < len(m.Content); i += 2 {
			if m.Content[i].Value == "proxies" {
				seq = m.Content[i+1]
			}
		}
	}
	if seq == nil {
		return nil, errors.New("配置中没有 proxies 列表")
	}
	c := newConverter(ctx)
	for seq.Kind == yaml.AliasNode && seq.Alias != nil {
		seq = seq.Alias
	}
	if seq.Kind != yaml.SequenceNode {
		return nil, errors.New("proxies 必须是列表")
	}
	if len(seq.Content) > MaxNodes*2 {
		return nil, fmt.Errorf("节点数量超过上限 %d", MaxNodes)
	}
	var out []map[string]any
	for _, item := range seq.Content {
		v, err := c.value(item, 0)
		if err != nil {
			if errors.Is(err, errTooComplex) || errors.Is(err, errYAMLCycle) || ctx.Err() != nil {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				return nil, err
			}
			out = append(out, nil)
			continue
		}
		m, ok := v.(map[string]any)
		if !ok {
			out = append(out, nil)
			continue
		}
		out = append(out, m)
	}
	return out, nil
}

// ParseClash reads a Clash/Mihomo YAML document.
func ParseClash(data []byte) (Parsed, error) { return ParseClashContext(context.Background(), data) }

// ParseClashContext is ParseClash that stops when ctx ends.
func ParseClashContext(ctx context.Context, data []byte) (Parsed, error) {
	maps, err := clashProxies(ctx, data)
	if err != nil {
		return Parsed{}, err
	}
	p := Parsed{Format: "clash"}
	seen := map[string]bool{}
	for i, m := range maps {
		p.Entries++
		if m == nil {
			p.Issues = append(p.Issues, Issue{Level: "error", Line: i + 1, Reason: "代理条目不是映射"})
			continue
		}
		n, err := nodeFromClash(m)
		if err != nil {
			level := "error"
			if IsPlaceholder(err) {
				level = "skip"
			}
			p.Issues = append(p.Issues, Issue{Level: level, Line: i + 1, Name: cleanName(asString(m["name"])), Protocol: truncate(strings.ToLower(asString(m["type"])), 20), Reason: err.Error()})
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
	separateVariants(p.Nodes)
	return p, nil
}

// Keys that make a proxy reach outside its own entry (other proxies, local files, network
// interfaces) are refused: a third-party list must not steer the client's other settings.
var clashForbidden = map[string]string{
	"dialer-proxy":   "指向其他代理组",
	"interface-name": "绑定本机网卡",
	"routing-mark":   "设置路由标记",
	"ca":             "引用本地文件",
	"certificate":    "引用本地文件",
	"private-key":    "引用本地文件",
	"key":            "引用本地文件",
}

func asString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case int64:
		return strconv.FormatInt(t, 10)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	}
	return ""
}

func asInt(v any) (int, bool) {
	switch t := v.(type) {
	case int64:
		return int(t), t == int64(int(t))
	case float64:
		return int(t), t == float64(int(t))
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(t))
		return n, err == nil
	}
	return 0, false
}

func asBool(v any) (val, set bool) {
	switch t := v.(type) {
	case bool:
		return t, true
	case string:
		b, err := strconv.ParseBool(t)
		return b, err == nil
	}
	return false, false
}

func nodeFromClash(m map[string]any) (Node, error) {
	if len(m) > maxProxyKeys {
		return Node{}, errors.New("代理条目字段过多")
	}
	kind := strings.ToLower(asString(m["type"]))
	switch kind {
	case "ss", "vless", "trojan", "tuic", "anytls":
	case "hysteria2", "hy2":
		kind = "hysteria2"
	case "":
		return Node{}, errors.New("代理缺少 type")
	default:
		return Node{}, unsupportedError{fmt.Sprintf("暂不支持 %s 协议", truncate(kind, 20))}
	}
	for k, why := range clashForbidden {
		if _, has := m[k]; has {
			return Node{}, fmt.Errorf("含有被拒绝的字段 %s（%s）", k, why)
		}
	}
	server := asString(m["server"])
	port, ok := asInt(m["port"])
	if !validHost(server) || !ok || port < 1 || port > 65535 {
		return Node{}, errors.New("服务器地址或端口无效")
	}
	cp := deepCopy(m).(map[string]any)
	cp["type"] = kind
	if size := estimateSize(cp); size > maxProxyBytes {
		return Node{}, errors.New("代理条目过大")
	}
	n := Node{Protocol: kind, Server: server, Port: port, Name: cleanName(asString(m["name"])), Clash: cp, Security: "none", Transport: "tcp"}
	if n.Name == "" {
		n.Name = net.JoinHostPort(server, strconv.Itoa(port))
	}
	cred := ""
	switch kind {
	case "vless":
		uuid := asString(m["uuid"])
		if !uuidRe.MatchString(uuid) {
			return Node{}, errors.New("VLESS UUID 无效")
		}
		cred = uuid
		if nw := asString(m["network"]); nw != "" {
			n.Transport = strings.ToLower(truncate(nw, 20))
		}
		if _, has := m["reality-opts"]; has {
			n.Security = "reality"
		} else if t, _ := asBool(m["tls"]); t {
			n.Security = "tls"
		}
		n.SNI = first(asString(m["servername"]), asString(m["sni"]))
	case "trojan":
		cred = asString(m["password"])
		n.Security = "tls"
		if nw := asString(m["network"]); nw != "" {
			n.Transport = strings.ToLower(truncate(nw, 20))
		}
		n.SNI = first(asString(m["sni"]), asString(m["servername"]))
	case "ss":
		method := asString(m["cipher"])
		if !ssMethods[method] {
			return Node{}, unsupportedError{fmt.Sprintf("不支持的 Shadowsocks 加密方式 %s", truncate(method, 30))}
		}
		cred = method + ":" + asString(m["password"])
		if asString(m["password"]) == "" {
			return Node{}, errors.New("Shadowsocks 密码为空")
		}
		n.UDP = true
		if u, set := asBool(m["udp"]); set {
			n.UDP = u
		}
	case "hysteria2":
		cred = asString(m["password"])
		n.Security, n.UDP = "tls", true
		n.SNI = first(asString(m["sni"]), asString(m["servername"]))
	case "tuic":
		uuid, pw := asString(m["uuid"]), asString(m["password"])
		if !uuidRe.MatchString(uuid) || pw == "" {
			return Node{}, errors.New("TUIC 认证信息无效")
		}
		cred = uuid + ":" + pw
		n.Security, n.UDP = "tls", true
		n.SNI = first(asString(m["sni"]), asString(m["servername"]))
	case "anytls":
		cred = asString(m["password"])
		n.Security = "tls"
		n.SNI = first(asString(m["sni"]), asString(m["servername"]))
	}
	if cred == "" || strings.HasSuffix(cred, ":") {
		return Node{}, errors.New("缺少认证信息")
	}
	if placeholderHost(server) {
		return Node{}, placeholderError{}
	}
	n.seal(cred)
	n.Link, n.LinkIssue = clashToLink(n, cp)
	if n.Link == "" && n.LinkIssue == "" {
		n.LinkIssue = "分享链接转换后校验不一致，已放弃转换"
	}
	return n, nil
}

func estimateSize(v any) int {
	switch t := v.(type) {
	case string:
		return len(t) + 2
	case map[string]any:
		n := 2
		for k, x := range t {
			n += len(k) + 3 + estimateSize(x)
		}
		return n
	case []any:
		n := 2
		for _, x := range t {
			n += estimateSize(x) + 1
		}
		return n
	}
	return 8
}

// Fields that never change what a share link would connect to, or that links cannot carry
// and clients treat as local preferences.
var linkIgnorable = map[string]bool{
	"name": true, "type": true, "server": true, "port": true, "udp": true, "tfo": true, "mptcp": true,
	"ip-version": true, "smux": true,
}

type linkBuilder struct {
	m    map[string]any
	used map[string]bool
	q    url.Values
	bad  []string
}

func newLinkBuilder(m map[string]any) *linkBuilder {
	return &linkBuilder{m: m, used: map[string]bool{}, q: url.Values{}}
}

func (b *linkBuilder) str(key string) string { b.used[key] = true; return asString(b.m[key]) }
func (b *linkBuilder) flag(key string) bool {
	b.used[key] = true
	v, _ := asBool(b.m[key])
	return v
}
func (b *linkBuilder) sub(key string, allowed ...string) map[string]any {
	b.used[key] = true
	sub, _ := b.m[key].(map[string]any)
	if sub == nil {
		return nil
	}
	ok := map[string]bool{}
	for _, a := range allowed {
		ok[a] = true
	}
	for k := range sub {
		if !ok[k] {
			b.bad = append(b.bad, key+"."+k)
		}
	}
	return sub
}
func (b *linkBuilder) alpn() {
	b.used["alpn"] = true
	switch t := b.m["alpn"].(type) {
	case []any:
		var parts []string
		for _, x := range t {
			parts = append(parts, asString(x))
		}
		if len(parts) > 0 {
			b.q.Set("alpn", strings.Join(parts, ","))
		}
	case string:
		if t != "" {
			b.q.Set("alpn", t)
		}
	}
}

// transport writes ws/grpc settings and reports anything else as unrepresentable.
func (b *linkBuilder) transport() {
	nw := strings.ToLower(b.str("network"))
	switch nw {
	case "", "tcp":
		b.q.Set("type", "tcp")
	case "ws":
		b.q.Set("type", "ws")
		if o := b.sub("ws-opts", "path", "headers"); o != nil {
			if p := asString(o["path"]); p != "" {
				b.q.Set("path", p)
			}
			if h, ok := o["headers"].(map[string]any); ok {
				for k, v := range h {
					if strings.EqualFold(k, "host") {
						b.q.Set("host", asString(v))
					} else {
						b.bad = append(b.bad, "ws-opts.headers."+k)
					}
				}
			}
		}
	case "grpc":
		b.q.Set("type", "grpc")
		if o := b.sub("grpc-opts", "grpc-service-name"); o != nil {
			b.q.Set("serviceName", asString(o["grpc-service-name"]))
		}
	default:
		b.bad = append(b.bad, "network="+truncate(nw, 12))
	}
}

func (b *linkBuilder) leftover(extra map[string]bool) []string {
	var left []string
	for k := range b.m {
		if !b.used[k] && !linkIgnorable[k] && !extra[k] {
			left = append(left, k)
		}
	}
	left = append(left, b.bad...)
	sort.Strings(left)
	return left
}

// clashToLink writes a share link carrying every parameter of the proxy, or explains why it
// cannot. A link that would silently drop a parameter is never produced.
func clashToLink(n Node, m map[string]any) (link, issue string) {
	b := newLinkBuilder(m)
	host := net.JoinHostPort(n.Server, strconv.Itoa(n.Port))
	var userinfo, scheme string
	extra := map[string]bool{}
	switch n.Protocol {
	case "vless":
		scheme = "vless"
		userinfo = url.PathEscape(b.str("uuid"))
		b.q.Set("encryption", "none")
		if v := b.str("encryption"); v != "" && v != "none" {
			b.bad = append(b.bad, "encryption")
		}
		b.str("flow")
		if f := asString(m["flow"]); f != "" {
			b.q.Set("flow", f)
		}
		b.tlsPart(true)
		b.transport()
		switch pe := strings.ToLower(b.str("packet-encoding")); pe {
		case "":
		case "xudp", "packet":
			b.q.Set("packetEncoding", pe)
		default:
			b.bad = append(b.bad, "packet-encoding")
		}
		if b.flag("xudp") && b.q.Get("packetEncoding") == "" {
			b.q.Set("packetEncoding", "xudp")
		}
	case "trojan":
		scheme = "trojan"
		userinfo = url.PathEscape(b.str("password"))
		b.tlsPart(false)
		b.transport()
	case "ss":
		if m["plugin"] != nil || m["plugin-opts"] != nil {
			return "", "Shadowsocks 插件无法写入分享链接"
		}
		b.used["plugin"], b.used["plugin-opts"] = true, true
		method, pw := b.str("cipher"), b.str("password")
		if left := b.leftover(map[string]bool{}); len(left) > 0 {
			return "", fmt.Sprintf("含无法写入分享链接的字段：%s", strings.Join(left, ", "))
		}
		var ui string
		if strings.HasPrefix(method, "2022-") {
			ui = url.QueryEscape(method) + ":" + url.QueryEscape(pw)
		} else {
			ui = base64RawURL([]byte(method + ":" + pw))
		}
		return finishLink("ss://"+ui+"@"+host, n), ""
	case "hysteria2":
		scheme = "hysteria2"
		userinfo = url.PathEscape(b.str("password"))
		if s := b.str("sni"); s != "" {
			b.q.Set("sni", s)
		} else if s := b.str("servername"); s != "" {
			b.q.Set("sni", s)
		}
		if b.flag("skip-cert-verify") {
			b.q.Set("insecure", "1")
		}
		if o := b.str("obfs"); o != "" {
			b.q.Set("obfs", o)
			b.q.Set("obfs-password", b.str("obfs-password"))
		}
		b.used["obfs-password"] = true
		if fp := b.str("fingerprint"); fp != "" {
			b.q.Set("pinSHA256", strings.ToLower(strings.ReplaceAll(fp, ":", "")))
		}
		b.alpn()
		extra["up"], extra["down"], extra["hop-interval"] = true, true, true
	case "tuic":
		scheme = "tuic"
		userinfo = url.PathEscape(b.str("uuid")) + ":" + url.PathEscape(b.str("password"))
		if s := first(b.str("sni"), b.str("servername")); s != "" {
			b.q.Set("sni", s)
		}
		if b.flag("skip-cert-verify") {
			b.q.Set("insecure", "1")
		}
		if cc := b.str("congestion-controller"); cc != "" {
			b.q.Set("congestion_control", cc)
		}
		if mode := b.str("udp-relay-mode"); mode != "" {
			b.q.Set("udp_relay_mode", mode)
		}
		b.alpn()
		extra["reduce-rtt"], extra["heartbeat-interval"], extra["request-timeout"] = true, true, true
	case "anytls":
		scheme = "anytls"
		userinfo = url.PathEscape(b.str("password"))
		b.tlsPart(false)
		extra["idle-session-check-interval"], extra["idle-session-timeout"], extra["min-idle-session"] = true, true, true
	}
	if left := b.leftover(extra); len(left) > 0 {
		return "", fmt.Sprintf("含无法写入分享链接的字段：%s", strings.Join(left, ", "))
	}
	link = scheme + "://" + userinfo + "@" + host
	if enc := b.q.Encode(); enc != "" {
		link += "/?" + enc
	}
	return finishLink(link, n), ""
}

// tlsPart writes the TLS/Reality settings of vless/trojan/anytls proxies.
func (b *linkBuilder) tlsPart(optionalTLS bool) {
	tls := true
	if optionalTLS {
		tls = b.flag("tls")
	} else {
		b.used["tls"] = true
	}
	servername := first(b.str("servername"), b.str("sni"))
	fp := b.str("client-fingerprint")
	if ro := b.sub("reality-opts", "public-key", "short-id", "support-x25519mlkem768"); ro != nil {
		b.q.Set("security", "reality")
		b.q.Set("pbk", asString(ro["public-key"]))
		b.q.Set("sid", asString(ro["short-id"]))
		if fp == "" {
			fp = "chrome"
		}
	} else if tls {
		b.q.Set("security", "tls")
	} else {
		b.q.Set("security", "none")
	}
	if servername != "" && b.q.Get("security") != "none" {
		b.q.Set("sni", servername)
	}
	if fp != "" && b.q.Get("security") != "none" {
		b.q.Set("fp", fp)
	}
	if b.flag("skip-cert-verify") {
		b.q.Set("allowInsecure", "1")
	}
	b.alpn()
}

func base64RawURL(b []byte) string {
	const tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	var sb strings.Builder
	for i := 0; i < len(b); i += 3 {
		var v uint32
		rem := len(b) - i
		switch {
		case rem >= 3:
			v = uint32(b[i])<<16 | uint32(b[i+1])<<8 | uint32(b[i+2])
			sb.WriteByte(tbl[v>>18&63])
			sb.WriteByte(tbl[v>>12&63])
			sb.WriteByte(tbl[v>>6&63])
			sb.WriteByte(tbl[v&63])
		case rem == 2:
			v = uint32(b[i])<<16 | uint32(b[i+1])<<8
			sb.WriteByte(tbl[v>>18&63])
			sb.WriteByte(tbl[v>>12&63])
			sb.WriteByte(tbl[v>>6&63])
		default:
			v = uint32(b[i]) << 16
			sb.WriteByte(tbl[v>>18&63])
			sb.WriteByte(tbl[v>>12&63])
		}
	}
	return sb.String()
}

// finishLink appends the display name and proves the link reads back as the same endpoint
// and account; a conversion that does not is reported instead of being published.
func finishLink(link string, n Node) string {
	link = SetName(link, n.Name)
	back, err := ParseLink(link)
	if err != nil || back.Fingerprint != n.Fingerprint {
		return ""
	}
	return link
}
