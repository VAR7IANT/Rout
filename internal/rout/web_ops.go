package rout

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
	"unicode/utf8"
)

// Operations used by the web panel. They compose the same primitives as the interactive
// menus (NewProfile, PlanPort, Validate, BindExit, Commit) without prompting, so a node or
// relay created in the browser is byte-for-byte the kind the CLI would create.

// webMutate loads the state, applies change to a copy and commits it. Commit refuses to
// write when the file changed since the load; the operation is then retried on the new
// state a few times so two administrators (or the CLI) do not collide spuriously.
func (a *App) webMutate(change func(old State) (State, error)) error {
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		old, e := a.Load()
		if e != nil {
			return e
		}
		next, e := change(old.Clone())
		if e != nil {
			return e
		}
		if last = a.Commit(old, next, false); last == nil {
			return nil
		}
		if !strings.Contains(last.Error(), "配置已被其他操作修改") {
			return last
		}
		time.Sleep(100 * time.Millisecond)
	}
	return last
}

// headlessUI gives access to the host-inspection helpers of the interactive UI.
func (a *App) headlessUI() *UI {
	u := &UI{a: a, in: bufio.NewReader(strings.NewReader("")), out: io.Discard}
	if a.webHooks != nil && a.webHooks.ui != nil {
		a.webHooks.ui(u)
	}
	return u
}

// webTestHooks replace the parts of the host the panel inspects, so tests do not depend on
// the machine they run on.
type webTestHooks struct {
	ui   func(*UI)
	diag *diagEnv
	now  func() time.Time
}

func (a *App) diagEnvironment() diagEnv {
	if a.webHooks != nil && a.webHooks.diag != nil {
		return *a.webHooks.diag
	}
	return defaultDiagEnv()
}

func validDisplayName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" || utf8.RuneCountInString(name) > 60 || strings.ContainsAny(name, "\r\n\x00\t") || !utf8.ValidString(name) {
		return errors.New("名称无效（1–60 个字符，不含换行）")
	}
	return nil
}

// ---- server defaults -------------------------------------------------------------------

// webServerSetup returns the saved server defaults, detecting and saving them on first use
// exactly as the first run of the interactive menu does.
func (a *App) webServerSetup(u *UI) (ServerSetup, error) {
	saved, e := a.LoadSettings()
	if e != nil {
		return ServerSetup{}, e
	}
	if s := saved.Server; s != nil && s.PublicHost != "" && s.Validate() == nil {
		return *s, nil
	}
	addrs := u.detectAddresses()
	s := ServerSetup{Network: "both", IPv4: addrs.IPv4, IPv6: addrs.IPv6}
	switch {
	case addrs.IPv4 != "":
		s.Family, s.PublicHost = "ipv4", addrs.IPv4
	case addrs.IPv6 != "":
		s.Family, s.PublicHost = "ipv6", addrs.IPv6
	default:
		return s, errors.New("无法自动检测服务器公网地址，请先在命令行运行 rout 完成『服务器地址』设置")
	}
	s.Listen = chooseListen(s.Family, addrs, u.listenCapabilities(), "")
	if e = s.Validate(); e != nil {
		return s, e
	}
	if saved.Language == "" {
		saved.Language = a.Language
		if saved.Language == "" {
			saved.Language = "zh-CN"
		}
	}
	saved.Server = &s
	return s, a.SaveSettings(saved)
}

// listenSetup applies an inbound choice to a copy of the server defaults, as the node
// creation menu does for one batch.
func (u *UI) webListenSetup(setup ServerSetup, inbound string, protocols ...string) (ServerSetup, error) {
	if setup.NAT || (setup.Listen != "0.0.0.0" && setup.Listen != "::" && net.ParseIP(setup.Listen) != nil) {
		return setup, nil
	}
	var networks []string
	for _, protocol := range protocols {
		for _, n := range (Profile{Protocol: protocol}).Networks() {
			if !contains(networks, n) {
				networks = append(networks, n)
			}
		}
	}
	caps := u.listenCapabilities(networks...)
	items := nodeListenOptions(caps)
	if len(items) == 0 {
		return setup, errors.New("本机没有可用的监听地址")
	}
	selected := items[0].key
	if inbound != "" {
		found := false
		for _, it := range items {
			found = found || it.key == inbound
		}
		if !found {
			return setup, errors.New("本机不支持所选的监听方式")
		}
		selected = inbound
	}
	setup.inbound = selected
	switch selected {
	case inIPv4:
		setup.Listen = "0.0.0.0"
	case inDual, inIPv6:
		setup.Listen = "::"
		mapped := selected == inDual && caps.DualStack
		setup.ipv4Mapped = &mapped
	}
	return webAlignPublicHost(setup, selected)
}

// webAlignPublicHost keeps the advertised address consistent with the inbound mode, using
// the addresses detected on this host; it never invents one.
func webAlignPublicHost(setup ServerSetup, selected string) (ServerSetup, error) {
	family := familyOf(setup.PublicHost)
	if selected == inDual || family == "" || family == selected {
		return setup, nil
	}
	host := setup.IPv4
	if selected == inIPv6 {
		host = setup.IPv6
	}
	if host == "" {
		return setup, errors.New("所选监听方式需要对应的公网地址，请先在命令行的『设置 → 服务器地址』中配置")
	}
	setup.PublicHost = host
	setup.Family = familyOf(host)
	return setup, nil
}

// ---- nodes -----------------------------------------------------------------------------

// NodeSpec describes nodes to create: one per protocol, sharing a base name and exit.
type NodeSpec struct {
	BaseName   string   `json:"base_name"`
	Protocols  []string `json:"protocols"`
	Inbound    string   `json:"inbound"` // "", ipv4, ipv6 or dual
	RealitySNI string   `json:"reality_sni"`
	ExitID     string   `json:"exit_id"`
	Port       int      `json:"port"` // only with a single protocol; 0 picks a free port
}

// CreateNodes creates the nodes and returns them as stored.
func (a *App) CreateNodes(spec NodeSpec) ([]Profile, error) {
	if len(spec.Protocols) == 0 || len(spec.Protocols) > len(createProtocols) {
		return nil, errors.New("请选择至少一种协议")
	}
	seen := map[string]bool{}
	for _, p := range spec.Protocols {
		if !contains(createProtocols, p) || seen[p] {
			return nil, errors.New("协议无效或重复")
		}
		seen[p] = true
	}
	if spec.Port != 0 && (len(spec.Protocols) != 1 || !validPort(spec.Port)) {
		return nil, errors.New("只有创建单个节点时才能指定端口")
	}
	base := strings.TrimSpace(spec.BaseName)
	if base == "" {
		base = "Rout"
	}
	if e := validDisplayName(base); e != nil {
		return nil, e
	}
	switch spec.Inbound {
	case "", inIPv4, inIPv6, inDual:
	default:
		return nil, errors.New("监听方式无效")
	}
	sni := strings.TrimSpace(spec.RealitySNI)
	if sni == "" {
		sni = "addons.mozilla.org"
	}
	if !validHostStrict(sni) || net.ParseIP(sni) != nil {
		return nil, errors.New("Reality SNI 应为有效域名")
	}
	u := a.headlessUI()
	setup, e := a.webServerSetup(u)
	if e != nil {
		return nil, e
	}
	setup, e = u.webListenSetup(setup, spec.Inbound, spec.Protocols...)
	if e != nil {
		return nil, e
	}
	cert, key := "", ""
	for _, p := range spec.Protocols {
		if p == "hy2" || p == "tuic" {
			if cert, key, e = GenerateCertificate(setup.PublicHost); e != nil {
				return nil, e
			}
			break
		}
	}
	var created []Profile
	e = a.webMutate(func(old State) (State, error) {
		created = nil
		next := old
		if spec.ExitID != "" {
			if _, e := FindExit(next, spec.ExitID); e != nil {
				return old, e
			}
		}
		for _, protocol := range spec.Protocols {
			p, e := NewProfile(protocol)
			if e != nil {
				return old, e
			}
			p.Name = uniqueName(next, base+"-"+ProtocolLabel(protocol))
			p.SNI = sni
			if protocol == "hy2" || protocol == "tuic" {
				p.SNI, p.CertPEM, p.KeyPEM, p.TLSGenerated = setup.PublicHost, cert, key, true
			}
			if p, e = PlanPort(p, setup, next); e != nil {
				return old, fmt.Errorf("%s: %w", p.Name, e)
			}
			if spec.Port != 0 {
				p.Port, p.PublicPort = spec.Port, spec.Port
				if setup.NAT {
					return old, errors.New("旧版 NAT 主机请使用自动分配的端口")
				}
				if e = portConflict(next, p); e != nil {
					return old, e
				}
			}
			if e = p.Validate(); e != nil {
				return old, fmt.Errorf("%s: %w", p.Name, e)
			}
			next = replace(next, p)
			if spec.ExitID != "" {
				if next, e = BindExit(next, p.ID, spec.ExitID); e != nil {
					return old, e
				}
			}
			created = append(created, p)
		}
		return next, nil
	})
	if e != nil {
		return nil, e
	}
	st, e := a.Load()
	if e != nil {
		return nil, e
	}
	out := make([]Profile, 0, len(created))
	for _, p := range created {
		if sp, er := Find(st, p.ID); er == nil {
			out = append(out, sp)
		}
	}
	return out, nil
}

// SetNodesEnabled starts (true) or stops (false) nodes and relays. Stopping is a state
// change in the configuration, like `rout off`, so it survives reboots.
func (a *App) SetNodesEnabled(ids []string, enabled bool) error {
	if len(ids) == 0 || len(ids) > 200 {
		return errors.New("请选择 1–200 个对象")
	}
	return a.webMutate(func(old State) (State, error) {
		next := old
		for _, id := range ids {
			p, e := Find(next, id)
			if e != nil {
				return old, e
			}
			if p.Enabled != enabled {
				p.Enabled = enabled
				next = replace(next, p)
			}
		}
		return next, nil
	})
}

// DeleteProfiles removes nodes or relays (and their service units) in one commit.
func (a *App) DeleteProfiles(ids []string) error {
	if len(ids) == 0 || len(ids) > 200 {
		return errors.New("请选择 1–200 个对象")
	}
	return a.webMutate(func(old State) (State, error) {
		next := old
		for _, id := range ids {
			if _, e := Find(next, id); e != nil {
				return old, e
			}
			next = removeProfile(next, id)
		}
		return next, nil
	})
}

// RenameProfile changes a node's or relay's display name.
func (a *App) RenameProfile(id, name string) error {
	name = strings.TrimSpace(name)
	if e := validDisplayName(name); e != nil {
		return e
	}
	return a.webMutate(func(old State) (State, error) {
		p, e := Find(old, id)
		if e != nil {
			return old, e
		}
		for _, other := range old.Profiles {
			if other.ID != id && strings.EqualFold(other.Name, name) {
				return old, errors.New("名称已被使用")
			}
		}
		p.Name = name
		return replace(old, p), nil
	})
}

// BindNodesToExit sets (exitID != "") or clears the outbound of nodes.
func (a *App) BindNodesToExit(nodeIDs []string, exitID string) error {
	return a.webMutate(func(old State) (State, error) {
		next := old
		for _, id := range nodeIDs {
			var e error
			if next, e = BindExit(next, id, exitID); e != nil {
				return old, e
			}
		}
		return next, nil
	})
}

// ---- relays ----------------------------------------------------------------------------

// RelaySpec describes a relay (port forward). Mode "local" forwards to a node or port on
// this server; "remote" to Target, a host:port or a remote node's share link.
type RelaySpec struct {
	Name          string `json:"name"`
	Mode          string `json:"mode"`
	LocalNodeID   string `json:"local_node_id"`
	LocalPort     int    `json:"local_port"`
	Target        string `json:"target"`
	Protocol      string `json:"protocol"`       // tcp, udp, both; "" follows the target or defaults to tcp
	Inbound       string `json:"inbound"`        // ipv4, ipv6, dual; "" picks the best this host supports
	Outbound      string `json:"outbound"`       // outbound address-family policy; "" = auto
	ListenPort    int    `json:"listen_port"`    // 0 picks a free port
	TargetNetwork string `json:"target_network"` // "tcp" marks a TCP-only NAT destination
}

// relayDestinationFrom fills Target, TargetURI and Protocol from a spec.
func relayDestinationFrom(p *Profile, spec RelaySpec, s State) error {
	switch p.RelayMode {
	case relayLocal:
		p.TargetURI = ""
		if spec.LocalNodeID != "" {
			n, e := Find(s, spec.LocalNodeID)
			if e != nil || n.Kind != "node" {
				return errors.New("找不到所选的本机节点")
			}
			host := "127.0.0.1"
			if n.InboundMode == inIPv6 {
				host = "::1"
			}
			p.Target = net.JoinHostPort(host, itoa(n.Port))
			if uri, e := n.URI(); e == nil {
				p.TargetURI = uri
			}
			if spec.Protocol == "" {
				p.Protocol = networkProtocol(n.Networks())
			}
			return nil
		}
		if !validPort(spec.LocalPort) {
			return errors.New("请选择本机节点或填写有效的目标端口")
		}
		p.Target = net.JoinHostPort("127.0.0.1", itoa(spec.LocalPort))
		return nil
	case relayRemote:
		raw := strings.TrimSpace(spec.Target)
		if raw == "" {
			return errors.New("必须填写远程服务器地址")
		}
		if strings.Contains(raw, "://") {
			target, network, e := ParseTarget(raw)
			if e != nil {
				return e
			}
			p.Target, p.TargetURI = target, raw
			if network != "both" && spec.Protocol == "" {
				p.Protocol = network
			}
			return nil
		}
		h, port, e := ParseEndpoint(raw)
		if e != nil || !validHostStrict(strings.Trim(h, "[]")) {
			return errors.New("请输入有效的 地址:端口，或粘贴远程节点的分享链接")
		}
		p.Target, p.TargetURI = net.JoinHostPort(h, itoa(port)), ""
		return nil
	}
	return errors.New("转发目标类型无效")
}

// CreateRelay creates a relay served by Rout's built-in forwarder.
func (a *App) CreateRelay(spec RelaySpec) (Profile, error) {
	var zero Profile
	if spec.Mode != relayLocal && spec.Mode != relayRemote {
		return zero, errors.New("转发目标类型无效")
	}
	switch spec.Protocol {
	case "", "tcp", "udp", "both":
	default:
		return zero, errors.New("传输协议无效")
	}
	switch spec.Inbound {
	case "", inIPv4, inIPv6, inDual:
	default:
		return zero, errors.New("入站网络无效")
	}
	if spec.Outbound != "" && !validOutboundPolicy(spec.Outbound) {
		return zero, errors.New("出站策略无效")
	}
	if spec.ListenPort != 0 && !validPort(spec.ListenPort) {
		return zero, errors.New("监听端口无效")
	}
	if spec.Name != "" {
		if e := validDisplayName(spec.Name); e != nil {
			return zero, e
		}
	}
	u := a.headlessUI()
	setup, e := a.webServerSetup(u)
	if e != nil {
		return zero, e
	}
	var created Profile
	e = a.webMutate(func(old State) (State, error) {
		p := Profile{ID: RandomHex(6), Kind: "relay", Enabled: true, RelayMode: spec.Mode}
		now := time.Now()
		p.CreatedAt = &now
		setupLocal := setup
		p.Engine = engineNative
		if setup.NAT {
			// Legacy NAT host: the listen address and the provider's port mapping come from
			// the saved defaults, and the port is picked inside the mapped range.
			p.Listen, p.InboundMode = setup.Listen, modeOfListen(setup.Listen)
			if p.InboundMode == inDual {
				p.Listen = "::"
			}
		} else {
			caps := u.listenCapabilities("tcp")
			items := relayInboundOptions(caps)
			if len(items) == 0 {
				return old, errors.New("本机没有可用的监听地址")
			}
			mode := items[0].key
			if spec.Inbound != "" {
				ok := false
				for _, it := range items {
					ok = ok || it.key == spec.Inbound
				}
				if !ok {
					return old, errors.New("本机不支持所选的入站网络")
				}
				mode = spec.Inbound
			}
			p.InboundMode, p.Listen = mode, listenAddrFor(mode, "")
			var e error
			if setupLocal, e = webAlignPublicHost(setupLocal, mode); e != nil {
				return old, e
			}
		}
		p.PublicHost, p.NAT = setupLocal.PublicHost, setupLocal.NAT
		p.Protocol = spec.Protocol
		if e := relayDestinationFrom(&p, spec, old); e != nil {
			return old, e
		}
		if p.Protocol == "" {
			p.Protocol = "tcp"
		}
		if spec.Protocol != "" && p.TargetURI != "" && p.relayMode() == relayRemote {
			if _, network, e := ParseTarget(p.TargetURI); e == nil && network != "both" && network != spec.Protocol {
				return old, fmt.Errorf("目标链接使用 %s，与所选传输协议不一致", strings.ToUpper(network))
			}
		}
		if setup.NAT && setup.Network != "both" && p.Protocol != setup.Network {
			return old, errors.New("所选协议需要的网络不在 NAT 允许范围内")
		}
		p.TargetNetwork = ""
		if spec.TargetNetwork == "tcp" && p.relayMode() == relayRemote && contains(p.Networks(), "udp") {
			p.TargetNetwork = "tcp"
		}
		p.OutboundPolicy = outAuto
		if p.relayMode() == relayRemote && spec.Outbound != "" {
			p.OutboundPolicy = spec.Outbound
		}
		// Port: free one by default; an explicit one must be free on every network used.
		planned, e := PlanPort(p, setupLocal, old)
		if e != nil {
			return old, e
		}
		p.Port, p.PublicPort = planned.Port, planned.PublicPort
		if spec.ListenPort != 0 {
			if setupLocal.NAT {
				return old, errors.New("旧版 NAT 主机请使用自动分配的端口")
			}
			p.Port, p.PublicPort = spec.ListenPort, spec.ListenPort
			if e = portConflict(old, p); e != nil {
				return old, e
			}
		}
		name := strings.TrimSpace(spec.Name)
		if name == "" {
			name = "Relay"
			if h, port, er := ParseEndpoint(p.Target); er == nil {
				if p.relayMode() == relayRemote {
					name = "Relay-" + h
				}
				for _, n := range old.Profiles {
					if n.Kind == "node" && n.Port == port && isLoopbackHost(h) {
						name = "Relay-" + n.Name
					}
				}
			}
		}
		p.Name = uniqueName(old, name)
		if e = p.Validate(); e != nil {
			return old, e
		}
		if e = relayLoop(replace(old, p), p, localIPs()); e != nil {
			return old, e
		}
		if e = p.checkTargetNetwork(); e != nil {
			return old, e
		}
		created = p
		return replace(old, p), nil
	})
	if e != nil {
		return zero, e
	}
	return created, nil
}

// RelayPatch lists what may change on an existing relay; nil leaves a field alone.
type RelayPatch struct {
	Name     *string `json:"name"`
	Target   *string `json:"target"` // remote relays only
	Protocol *string `json:"protocol"`
	Outbound *string `json:"outbound"`
	Enabled  *bool   `json:"enabled"`
}

func (a *App) UpdateRelay(id string, patch RelayPatch) error {
	return a.webMutate(func(old State) (State, error) {
		p, e := Find(old, id)
		if e != nil {
			return old, e
		}
		if p.Kind != "relay" {
			return old, errors.New("该对象不是中转")
		}
		if patch.Name != nil {
			name := strings.TrimSpace(*patch.Name)
			if e = validDisplayName(name); e != nil {
				return old, e
			}
			for _, other := range old.Profiles {
				if other.ID != id && strings.EqualFold(other.Name, name) {
					return old, errors.New("名称已被使用")
				}
			}
			p.Name = name
		}
		if patch.Protocol != nil {
			switch *patch.Protocol {
			case "tcp", "udp", "both":
				p.Protocol = *patch.Protocol
			default:
				return old, errors.New("传输协议无效")
			}
		}
		if patch.Target != nil {
			if p.relayMode() != relayRemote {
				return old, errors.New("本机中转的目标请删除后重新创建")
			}
			spec := RelaySpec{Target: *patch.Target}
			keep := p.Protocol
			if e = relayDestinationFrom(&p, spec, old); e != nil {
				return old, e
			}
			if patch.Protocol != nil || p.TargetURI == "" {
				p.Protocol = keep
			}
		}
		if patch.Outbound != nil {
			if !validOutboundPolicy(*patch.Outbound) || !p.nativeRelay() {
				return old, errors.New("出站策略无效")
			}
			p.OutboundPolicy = *patch.Outbound
		}
		if patch.Enabled != nil {
			p.Enabled = *patch.Enabled
		}
		if e = p.Validate(); e != nil {
			return old, e
		}
		next := replace(old, p)
		if e = relayLoop(next, p, localIPs()); e != nil {
			return old, e
		}
		if e = p.checkTargetNetwork(); e != nil {
			return old, e
		}
		return next, nil
	})
}

// ---- exits (outbound proxies) -----------------------------------------------------------

// ExitSpec describes an outbound. Protocol is socks5, http, https, or remote (a remote node
// share link in Link, or an authenticated proxy in Host/Port/Username/Password with
// ProxyProtocol).
type ExitSpec struct {
	Name          string `json:"name"`
	Protocol      string `json:"protocol"`
	Host          string `json:"host"`
	Port          int    `json:"port"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	Link          string `json:"link"`
	ProxyProtocol string `json:"proxy_protocol"` // for remote exits that are plain proxies
	RemoteNetwork string `json:"remote_network"` // "tcp" for a TCP-only NAT
}

func buildExit(spec ExitSpec) (Exit, error) {
	var e Exit
	switch spec.Protocol {
	case "socks5", "http", "https":
		p, er := proxyFromSpec(spec.Protocol, spec)
		if er != nil {
			return e, er
		}
		e.Proxy = *p
	case "remote":
		e.Kind = exitRemote
		if strings.TrimSpace(spec.Link) != "" {
			p, er := ParseRemoteNode(spec.Link)
			if er != nil {
				return e, er
			}
			e.Proxy = *p
			if exitTransport(*p) == "udp" {
				e.RemoteNetwork = "both"
				if spec.RemoteNetwork == "tcp" {
					e.RemoteNetwork = "tcp"
				}
			}
		} else {
			switch spec.ProxyProtocol {
			case "socks5", "http", "https":
			default:
				return e, errors.New("请粘贴远程节点的分享链接，或选择代理协议并填写账号密码")
			}
			p, er := proxyFromSpec(spec.ProxyProtocol, spec)
			if er != nil {
				return e, er
			}
			e.Proxy = *p
		}
	default:
		return e, errors.New("出站类型无效")
	}
	return e, nil
}

// proxyFromSpec builds the proxy from the structured fields exactly as entered. Going through
// the colon-delimited input of ParseProxy would trim the password's trailing blanks and move
// anything after a ':' in the user name into the password, so the outbound would authenticate
// with other credentials than the ones given; invalid values are refused instead.
func proxyFromSpec(protocol string, spec ExitSpec) (*Proxy, error) {
	if protocol != "socks5" && protocol != "http" && protocol != "https" {
		return nil, errors.New("请选择 SOCKS5、HTTP 或 HTTPS")
	}
	if strings.Contains(spec.Username, ":") {
		return nil, errors.New("用户名不能包含冒号")
	}
	host := strings.TrimSpace(spec.Host)
	if !validPort(spec.Port) || !validHost(host) || spec.Username == "" || spec.Password == "" {
		return nil, errors.New("地址、端口、用户名或密码无效")
	}
	for _, v := range []string{host, spec.Username, spec.Password} {
		if strings.ContainsAny(v, "\r\n\x00") {
			return nil, errors.New("输入包含无效字符")
		}
	}
	return &Proxy{Protocol: protocol, Host: host, Port: spec.Port, Username: spec.Username, Password: spec.Password}, nil
}

// CreateExit stores a new outbound after checking it cannot loop back to this server.
func (a *App) CreateExit(spec ExitSpec) (Exit, error) {
	e, err := buildExit(spec)
	if err != nil {
		return Exit{}, err
	}
	e.Name = strings.TrimSpace(spec.Name)
	if e.Name == "" {
		e.Name = exitDefaultName(e)
	}
	if err = validDisplayName(e.Name); err != nil {
		return Exit{}, err
	}
	e.ID = RandomHex(6)
	err = a.webMutate(func(old State) (State, error) {
		if er := exitSelfLoop(old, e.Proxy, localIPs()); er != nil {
			return old, er
		}
		if er := e.validateKind(); er != nil {
			return old, er
		}
		for _, other := range old.Exits {
			if strings.EqualFold(other.Name, e.Name) {
				return old, errors.New("名称已被使用")
			}
		}
		return UpsertExit(old, e), nil
	})
	return e, err
}

// ExitPatch changes an outbound. An empty Password keeps the stored one, so editing the
// name or host never requires re-entering a secret.
type ExitPatch struct {
	Name     *string `json:"name"`
	Host     *string `json:"host"`
	Port     *int    `json:"port"`
	Username *string `json:"username"`
	Password *string `json:"password"`
	Link     *string `json:"link"`
}

func (a *App) UpdateExit(id string, patch ExitPatch) error {
	return a.webMutate(func(old State) (State, error) {
		e, err := FindExit(old, id)
		if err != nil {
			return old, err
		}
		if patch.Name != nil {
			name := strings.TrimSpace(*patch.Name)
			if err = validDisplayName(name); err != nil {
				return old, err
			}
			for _, other := range old.Exits {
				if other.ID != id && strings.EqualFold(other.Name, name) {
					return old, errors.New("名称已被使用")
				}
			}
			e.Name = name
		}
		if e.Proxy.Protocol == proxyNode {
			if patch.Link != nil && strings.TrimSpace(*patch.Link) != "" {
				p, er := ParseRemoteNode(*patch.Link)
				if er != nil {
					return old, er
				}
				e.Proxy = *p
			}
		} else if patch.Host != nil || patch.Port != nil || patch.Username != nil || patch.Password != nil {
			spec := ExitSpec{Protocol: e.Proxy.Protocol, Host: e.Proxy.Host, Port: e.Proxy.Port, Username: e.Proxy.Username, Password: e.Proxy.Password}
			if patch.Host != nil {
				spec.Host = *patch.Host
			}
			if patch.Port != nil {
				spec.Port = *patch.Port
			}
			if patch.Username != nil {
				spec.Username = *patch.Username
			}
			if patch.Password != nil && *patch.Password != "" {
				spec.Password = *patch.Password
			}
			p, er := proxyFromSpec(spec.Protocol, spec)
			if er != nil {
				return old, er
			}
			e.Proxy = *p
		}
		if err = e.Proxy.Validate(); err != nil {
			return old, err
		}
		if err = exitSelfLoop(old, e.Proxy, localIPs()); err != nil {
			return old, err
		}
		if err = e.validateKind(); err != nil {
			return old, err
		}
		return UpsertExit(old, e), nil
	})
}

func (a *App) DeleteExitByID(id string) error {
	return a.webMutate(func(old State) (State, error) { return DeleteExit(old, id) })
}

// ---- tests -----------------------------------------------------------------------------

// DiagStepView is one line of a layered test.
type DiagStepView struct {
	Layer     int    `json:"layer"`
	LayerName string `json:"layer_name"`
	Level     string `json:"level"`
	Text      string `json:"text"`
}

type DiagView struct {
	OK    bool           `json:"ok"`
	Steps []DiagStepView `json:"steps"`
}

func diagView(a *App, rep diagReport) DiagView {
	v := DiagView{OK: true, Steps: []DiagStepView{}}
	for _, s := range rep.Steps {
		lv := "info"
		switch s.Level {
		case diagFail:
			lv, v.OK = "fail", false
		case diagWarn:
			lv = "warn"
		case diagOK:
			lv = "ok"
		}
		v.Steps = append(v.Steps, DiagStepView{Layer: s.Layer, LayerName: a.T(diagLayerNames[s.Layer]), Level: lv, Text: s.Text})
	}
	return v
}

// TestProfile runs the layered diagnosis of a node or relay.
func (a *App) TestProfile(ctx context.Context, id string, full bool) (DiagView, error) {
	s, e := a.Load()
	if e != nil {
		return DiagView{}, e
	}
	p, e := Find(s, id)
	if e != nil {
		return DiagView{}, e
	}
	if !p.Enabled {
		return DiagView{}, errors.New("节点已停用")
	}
	return diagView(a, a.diagnose(ctx, p, a.diagEnvironment(), diagOpts{Full: full})), nil
}

// TestExit runs the layered diagnosis of an outbound.
func (a *App) TestExit(ctx context.Context, id string) (DiagView, error) {
	s, e := a.Load()
	if e != nil {
		return DiagView{}, e
	}
	ex, e := FindExit(s, id)
	if e != nil {
		return DiagView{}, e
	}
	return diagView(a, a.diagnoseProxy(ctx, ex, a.diagEnvironment(), diagOpts{Full: true})), nil
}
