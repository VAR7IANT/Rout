package rout

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// Native Snell support.
//
// Snell is Surge's own proxy protocol. It has exactly one server implementation, the
// closed-source snell-server that Surge publishes, so a Snell node cannot run on Rout's
// sing-box engine: it runs the official binary, one systemd service per node, like every
// other Rout node. Everything else (state, ports, NAT, quota metering, subscriptions,
// backups) is the ordinary node machinery.
//
// What the official documentation and the pinned binaries establish (docs/SNELL.md):
//
//   - v5 (5.0.1) is the stable release. v6 (6.0.0) is published as a beta whose wire format
//     may still change incompatibly, and only exists as a glibc build.
//   - Surge's client line is `Name = snell, host, port, psk=..., version=N`; the server
//     version must match the client's `version` (a v5 server also accepts v4 clients).
//   - snell-server -c reads an INI file with a [snell-server] section. Keys written here:
//     listen, psk, and per version ipv6 (v5) or mode and dns-ip-preference (v6).
//   - Snell has no upstream-proxy, routing-rule or TLS features, so Rout does not offer an
//     outbound proxy, AI routing or relay-by-link for it.
const (
	protoSnell = "snell"
	// snell6Alias is the create-menu / panel id of a Snell v6 node. It exists only as input
	// of NewProfile: a stored profile is always Protocol "snell" with SnellVersion "6".
	snell6Alias = "snell6"

	snellV5 = "5"
	snellV6 = "6"

	snellSection = "snell-server"
	snellConf    = "snell-server.conf"

	snellPSKLength = 32
	snellPSKMin    = 12
	snellPSKMax    = 255
)

// snellPSKPattern is deliberately narrower than what snell-server accepts: the PSK goes into
// an INI file and a Surge profile line, where "=", ",", "#", ";" and white space would change
// the meaning of the line.
var snellPSKPattern = regexp.MustCompile(`^[A-Za-z0-9._~+-]+$`)

const pskAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// NewSnellPSK returns a 32 character random PSK, the length snell-server's own wizard
// recommends. Characters are drawn without modulo bias.
func NewSnellPSK() (string, error) {
	out := make([]byte, 0, snellPSKLength)
	buf := make([]byte, 64)
	limit := 256 - 256%len(pskAlphabet)
	for len(out) < snellPSKLength {
		if _, e := rand.Read(buf); e != nil {
			return "", e
		}
		for _, b := range buf {
			if int(b) >= limit {
				continue
			}
			out = append(out, pskAlphabet[int(b)%len(pskAlphabet)])
			if len(out) == snellPSKLength {
				break
			}
		}
	}
	return string(out), nil
}

func validSnellPSK(psk string) error {
	if len(psk) < snellPSKMin || len(psk) > snellPSKMax {
		return fmt.Errorf("Snell PSK 长度应为 %d–%d 个字符", snellPSKMin, snellPSKMax)
	}
	if !snellPSKPattern.MatchString(psk) {
		return errors.New("Snell PSK 只能包含字母、数字和 . _ ~ + -")
	}
	return nil
}

// snellNode reports whether p is a Snell node (never a relay).
func (p Profile) snellNode() bool { return p.Kind == "node" && p.Protocol == protoSnell }

// snellVersion is the effective Snell version; a profile that does not say is v5.
func (p Profile) snellVersion() string {
	if p.SnellVersion == snellV6 {
		return snellV6
	}
	return snellV5
}

// snellEngine is the lock-file name of the engine that serves p: one pinned engine per Snell
// version, so a v5 and a v6 node can run side by side from different binaries.
func snellEngine(version string) string {
	if version == snellV6 {
		return "snell-v6"
	}
	return "snell-v5"
}

// isSnellEngine tells the engine installer which downloads are Snell builds.
func isSnellEngine(name string) bool { return strings.HasPrefix(name, "snell-") }

// snellLabel is the short name used in menus and node names.
func snellLabel(version string) string {
	if version == snellV6 {
		return "Snell6"
	}
	return "Snell"
}

// nodeLabel is the protocol label of a stored profile: ProtocolLabel plus the Snell version,
// which is part of what a Snell node is.
func nodeLabel(p Profile) string {
	if p.snellNode() {
		return snellLabel(p.snellVersion())
	}
	return ProtocolLabel(p.Protocol)
}

// meterNetworks are the networks quota metering and port reservation cover. Snell v5's
// QUIC Proxy Mode relays QUIC over UDP on the node's own port; counting it keeps a hard
// quota hard. Everything else meters exactly the networks it serves.
func (p Profile) meterNetworks() []string {
	n := p.Networks()
	if p.snellNode() && p.snellVersion() == snellV5 && !contains(n, "udp") {
		n = append(append([]string{}, n...), "udp")
	}
	return n
}

// checkSnell is the Snell part of Profile.Validate.
func (p Profile) checkSnell() error {
	if p.SnellVersion != "" && p.SnellVersion != snellV5 && p.SnellVersion != snellV6 {
		return errors.New("Snell 版本只能是 5 或 6")
	}
	if e := validSnellPSK(p.Password); e != nil {
		return e
	}
	if p.Outbound != nil || p.ExitID != "" {
		return errors.New("Snell 引擎不支持出站代理")
	}
	if p.Network != "" {
		return errors.New("节点网络限制无效")
	}
	if p.OutboundPolicy != "" {
		if _, e := snellDNSPreference(p.snellVersion(), p.OutboundPolicy); e != nil {
			return e
		}
	}
	return nil
}

// snellDNSPreference maps Rout's outbound IP-family policy to the one setting the engine
// has. The first result is v6's dns-ip-preference; for v5 it is "ipv6 = false" ("ipv4-only")
// or "ipv6 = true" ("default"). "Only" policies are a preference over DNS answers: the engine
// documents no rule for destinations that are IP literals, and Rout does not claim one.
func snellDNSPreference(version, policy string) (string, error) {
	if version == snellV6 {
		switch policy {
		case "", outAuto:
			return "default", nil
		case outIPv4First:
			return "prefer-ipv4", nil
		case outIPv6First:
			return "prefer-ipv6", nil
		case outIPv4Only:
			return "ipv4-only", nil
		case outIPv6Only:
			return "ipv6-only", nil
		}
		return "", errors.New("出站网络策略无效")
	}
	switch policy {
	case "", outAuto:
		return "default", nil
	case outIPv4Only:
		return "ipv4-only", nil
	}
	return "", errors.New("Snell v5 只支持出站策略「自动」和「仅 IPv4」；其他策略请使用 Snell v6")
}

// snellListen renders the listen address. v6 documents `host:port` and `[ipv6]:port` and may
// list several addresses. v5 documents the dual-stack wildcard as `::0:port`, with the
// port after the last colon and no brackets; its IPv6 form is written the same way.
func snellListen(p Profile) string {
	port := strconv.Itoa(p.Port)
	ip := net.ParseIP(p.Listen)
	if ip == nil || ip.To4() != nil {
		return p.Listen + ":" + port
	}
	if p.snellVersion() == snellV6 {
		return "[" + p.Listen + "]:" + port
	}
	if ip.IsUnspecified() {
		return "::0:" + port
	}
	return p.Listen + ":" + port
}

// snellServerConf is the content of snell-server.conf for a node. It contains the PSK and
// is written with mode 0600.
func snellServerConf(p Profile) (string, error) {
	if !p.snellNode() {
		return "", errors.New("不是 Snell 节点")
	}
	if e := p.checkSnell(); e != nil {
		return "", e
	}
	pref, e := snellDNSPreference(p.snellVersion(), p.OutboundPolicy)
	if e != nil {
		return "", e
	}
	var b strings.Builder
	b.WriteString("[" + snellSection + "]\n")
	b.WriteString("listen = " + snellListen(p) + "\n")
	b.WriteString("psk = " + p.Password + "\n")
	if p.snellVersion() == snellV6 {
		b.WriteString("mode = default\n")
		b.WriteString("dns-ip-preference = " + pref + "\n")
	} else {
		b.WriteString("ipv6 = " + strconv.FormatBool(pref != "ipv4-only") + "\n")
	}
	return b.String(), nil
}

// parseSnellConf reads back the generated INI (sections, key = value, nothing else).
func parseSnellConf(s string) (map[string]string, error) {
	out := map[string]string{}
	in := false
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "":
		case strings.HasPrefix(line, "["):
			if line != "["+snellSection+"]" || in {
				return nil, errors.New("Snell 配置段无效")
			}
			in = true
		case !in:
			return nil, errors.New("Snell 配置缺少 [snell-server] 段")
		default:
			k, v, ok := strings.Cut(line, "=")
			k, v = strings.TrimSpace(k), strings.TrimSpace(v)
			if !ok || k == "" || v == "" {
				return nil, errors.New("Snell 配置行无效")
			}
			if _, dup := out[k]; dup {
				return nil, errors.New("Snell 配置键重复")
			}
			out[k] = v
		}
	}
	if !in {
		return nil, errors.New("Snell 配置缺少 [snell-server] 段")
	}
	return out, nil
}

// checkSnellConf validates the written file for p: it must parse, carry exactly the expected
// keys and values and nothing the engine of that version does not know. snell-server has no
// dry-run mode, so this is Rout's own check; the real verdict is the post-start health
// check (service, listening socket, no restart).
func checkSnellConf(path string, p Profile) error {
	b, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	got, e := parseSnellConf(string(b))
	if e != nil {
		return e
	}
	want, e := snellServerConf(p)
	if e != nil {
		return e
	}
	exp, e := parseSnellConf(want)
	if e != nil {
		return e
	}
	if len(got) != len(exp) {
		return errors.New("Snell 配置包含不受支持的参数")
	}
	for k, v := range exp {
		if got[k] != v {
			return errors.New("Snell 配置与节点设置不一致")
		}
	}
	return nil
}

// ---- Surge ------------------------------------------------------------------------------------

// surgeName makes a node name safe as the left-hand side of a Surge profile line.
func surgeName(name string) string {
	r := strings.NewReplacer("=", "-", ",", " ", "\r", " ", "\n", " ", "\x00", "")
	name = strings.TrimSpace(r.Replace(name))
	for strings.HasPrefix(name, "#") || strings.HasPrefix(name, ";") || strings.HasPrefix(name, "[") || strings.HasPrefix(name, "//") {
		name = strings.TrimSpace(name[1:])
	}
	if name == "" {
		name = "Snell"
	}
	return name
}

// SurgeLine is the Surge [Proxy] line of a Snell node at the given address. The host is
// written as is (an IPv6 literal without brackets: the field is comma separated); version is
// always explicit, the Surge manual advises it because Surge assumes Snell v1 otherwise.
func (p Profile) SurgeLine(host string, port int) (string, error) {
	if !p.snellNode() {
		return "", errors.New("只有 Snell 节点有 Surge 配置")
	}
	if e := p.checkSnell(); e != nil {
		return "", e
	}
	if host == "" || strings.ContainsAny(host, ", =\r\n") || !validPort(port) {
		return "", errors.New("Surge 配置的地址或端口无效")
	}
	return fmt.Sprintf("%s = snell, %s, %d, psk=%s, version=%s", surgeName(p.Name), host, port, p.Password, p.snellVersion()), nil
}

// errNoShareLink is what URI returns for a protocol with no standard share link.
var errNoShareLink = errors.New("Snell 没有标准分享链接，请使用 Surge 配置或订阅的 Surge 格式")

// errNoClientConfig is returned wherever a sing-box client would be built for a Snell node.
var errNoClientConfig = errors.New("Snell 没有可导出的 sing-box 客户端配置，请使用 Surge")

// Share is what a person imports into a client: the share link, or for Snell the Surge
// profile line (Snell has no standard link).
func (p Profile) Share() (string, error) { return p.ShareAt(p.PublicHost, p.PublicPort) }

// ShareAt is Share for another address of the same node (for example its IPv6).
func (p Profile) ShareAt(host string, port int) (string, error) {
	if p.snellNode() {
		return p.SurgeLine(host, port)
	}
	return p.URIAt(host, port)
}
