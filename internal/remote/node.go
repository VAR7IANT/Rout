package remote

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Limits on what a single source may contribute.
const (
	MaxNodes     = 2000
	maxNameRunes = 120
	maxLinkBytes = 8 << 10
)

// Node is one proxy taken from a third-party source. It is stored exactly as the source
// described it: Link is the original share link (when the source used links) and Clash is the
// original Mihomo/Clash proxy mapping (when it used YAML). Nothing here is Rout's own node.
type Node struct {
	// ID is stable for a given endpoint and credential, independent of the display name,
	// so aggregate subscriptions keep pointing at the node when the provider renames it.
	ID       string `json:"id"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"` // vless, ss, trojan, hysteria2, tuic, anytls
	Server   string `json:"server"`
	Port     int    `json:"port"`
	// Informational summary of what the node uses.
	Transport string `json:"transport,omitempty"` // tcp, ws, grpc, ...
	Security  string `json:"security,omitempty"`  // none, tls, reality
	SNI       string `json:"sni,omitempty"`
	UDP       bool   `json:"udp,omitempty"`
	// Link is a share link that carries every parameter the source gave. Empty when the
	// node cannot be written as a share link without losing something; LinkIssue says why.
	Link      string `json:"link,omitempty"`
	LinkIssue string `json:"link_issue,omitempty"`
	// Clash is the original Mihomo/Clash proxy mapping, when the source was YAML.
	Clash map[string]any `json:"clash,omitempty"`
	// Notes list parameters that were recognised but cannot be carried into some output.
	Notes       []string `json:"notes,omitempty"`
	Fingerprint string   `json:"fp"`
}

// Loose is a coarser identity (protocol, host, port) used to re-find a node after a
// provider rotated its credentials.
func (n Node) Loose() string {
	return n.Protocol + "|" + strings.ToLower(n.Server) + "|" + itoa(n.Port)
}

// Issue describes something in a source that was not imported as a node.
type Issue struct {
	Level    string `json:"level"` // "error" (unparseable/unsupported) or "skip" (placeholder entry)
	Line     int    `json:"line,omitempty"`
	Name     string `json:"name,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	Reason   string `json:"reason"`
}

// Parsed is the outcome of reading one source body.
type Parsed struct {
	Format string  `json:"format"` // "links", "base64", "clash"
	Nodes  []Node  `json:"nodes"`
	Issues []Issue `json:"issues,omitempty"`
	// Entries is the number of entries the source listed (nodes + issues + duplicates).
	Entries    int `json:"entries"`
	Duplicates int `json:"duplicates,omitempty"`
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// fingerprintOf hashes what makes two entries the same endpoint with the same account.
func fingerprintOf(protocol, server string, port int, credential string) string {
	h := sha256.Sum256([]byte(strings.Join([]string{protocol, strings.ToLower(strings.TrimSuffix(server, ".")), itoa(port), credential}, "\x00")))
	return hex.EncodeToString(h[:])
}

func (n *Node) seal(credential string) {
	n.Fingerprint = fingerprintOf(n.Protocol, n.Server, n.Port, credential)
	n.ID = n.Fingerprint[:12]
}

// cleanName makes a display name safe for every output: valid UTF-8, no control characters,
// bounded length. Emoji and flags are kept.
func cleanName(s string) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "")
	}
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == ' ' || r == ' ' {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > maxNameRunes {
		s = string(r[:maxNameRunes])
	}
	return s
}

func decodeProfileTitle(h string) string {
	h = strings.TrimSpace(h)
	if rest, ok := strings.CutPrefix(h, "base64:"); ok {
		if b, err := base64.StdEncoding.DecodeString(rest); err == nil {
			return cleanName(string(b))
		}
		return ""
	}
	return cleanName(h)
}

// validHost accepts an IP literal or a DNS name; the strict check rejects the all-digit
// "last label" that would be a malformed IPv4 literal.
func validHost(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	if net.ParseIP(h) != nil {
		return true
	}
	parts := strings.Split(strings.TrimSuffix(h, "."), ".")
	for _, part := range parts {
		if len(part) == 0 || len(part) > 63 || part[0] == '-' || part[len(part)-1] == '-' {
			return false
		}
		for _, c := range part {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return strings.Trim(parts[len(parts)-1], "0123456789") != ""
}

// placeholderHost reports servers that providers use for informational pseudo-entries
// ("Remaining data: 20 GB") rather than real proxies.
func placeholderHost(h string) bool {
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsUnspecified() || ip.IsLoopback()
	}
	l := strings.ToLower(strings.TrimSuffix(h, "."))
	return l == "localhost" || l == "example.com" || l == "example.org" || l == "example.net" || l == "invalid"
}

// SetName returns the share link with its display name replaced.
func SetName(link, name string) string {
	if i := strings.IndexByte(link, '#'); i >= 0 {
		link = link[:i]
	}
	return link + "#" + (&url.URL{Fragment: name}).EscapedFragment()
}

// LinkNamed returns the node's share link under the given display name.
func (n Node) LinkNamed(name string) (string, bool) {
	if n.Link == "" {
		return "", false
	}
	return SetName(n.Link, name), true
}

// ClashNamed returns a deep copy of the original Clash mapping under the given name. The
// second result is false for nodes that did not come from YAML.
func (n Node) ClashNamed(name string) (map[string]any, bool) {
	if n.Clash == nil {
		return nil, false
	}
	cp := deepCopy(n.Clash).(map[string]any)
	cp["name"] = name
	return cp, true
}

func deepCopy(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[k] = deepCopy(x)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = deepCopy(x)
		}
		return out
	}
	return v
}

// canonLink writes a share link in a canonical spelling: no #fragment, host in lower case,
// query sorted, the default transport and an empty path left out. keepUser keeps the
// credential (for comparing whole links); connSig drops it because the credential is already
// part of the node's base identity.
func canonLink(raw string, keepUser bool) string {
	u, err := url.Parse(raw)
	if err != nil {
		l, _, _ := strings.Cut(raw, "#")
		return l
	}
	u.Fragment = ""
	if !keepUser {
		u.User = nil
	}
	q := u.Query()
	if q.Get("type") == "tcp" || q.Get("type") == "" {
		q.Del("type") // the default transport is written explicitly by some producers
	}
	if q.Get("headerType") == "none" {
		q.Del("headerType")
	}
	u.RawQuery = q.Encode()
	u.Host = strings.ToLower(u.Host)
	if u.Path == "/" {
		u.Path = ""
	}
	return u.String()
}

// CanonicalLink is canonLink with the credential kept, for de-duplicating whole links.
func CanonicalLink(raw string) string { return canonLink(raw, true) }

// connSig is the node's complete connection configuration without its display name. It is
// the share link in canonical form, so the same account written as a link or as a Clash
// mapping gets the same signature; only when no link can be written does it fall back to the
// original Mihomo mapping.
func (n Node) connSig() string {
	if n.Link != "" {
		return "l:" + canonLink(n.Link, false)
	}
	if n.Clash != nil {
		m := make(map[string]any, len(n.Clash))
		for k, v := range n.Clash {
			if k != "name" {
				m[k] = v
			}
		}
		b, _ := json.Marshal(m) // map keys are sorted: canonical
		return "c:" + string(b)
	}
	return "-"
}

// dedupeKey identifies an exact repeat: same endpoint, credential and connection settings.
func (n Node) dedupeKey() string { return n.Fingerprint + "\x00" + n.connSig() }

// deriveIdentity sets the node's identity from its endpoint, credential AND complete connection
// settings. The identity therefore depends only on the node itself: not on the order the
// provider lists it in, and not on whether siblings with the same endpoint and credential
// exist, so adding or removing a sibling never changes another node's ID. When a provider edits
// a node's own settings its ID changes; saved references to a node whose endpoint is still
// unique are re-found by the loose (protocol, host, port) lookup.
func (n *Node) deriveIdentity() {
	h := sha256.Sum256([]byte(n.Fingerprint + "\x00" + n.connSig()))
	n.Fingerprint = hex.EncodeToString(h[:])
	n.ID = n.Fingerprint[:12]
}
