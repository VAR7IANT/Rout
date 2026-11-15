package rout

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Snell as a Remote Server exit.
//
// Snell has no share link, but its Surge line says everything an outbound needs. A person
// pastes the Surge line of a Snell node on the remote server (for example the line another
// Rout prints for its Snell node); Rout keeps it as an internal snell:// link
// (snell://PSK@host:port?version=N[&obfs=http|tls&obfs-host=…]) so it travels like every other
// remote-node link, and sing-box's built-in Snell client dials it. sing-box speaks Snell v4
// and v6; a v5 server is reached as v4 (v5 without its QUIC mode is the v4 protocol), and
// v1-v3 are refused.

// snellLink is a parsed snell:// link.
type snellLink struct {
	host     string
	port     int
	psk      string
	version  int
	obfs     string
	obfsHost string
	name     string
}

// snellLinkFromSurge turns a Surge "Name = snell, host, port, psk=…, version=…" line into the
// internal snell:// link.
func snellLinkFromSurge(line string) (string, error) {
	name, rest, ok := strings.Cut(strings.TrimSpace(line), "=")
	if !ok {
		return "", errors.New("请粘贴 Snell 节点的 Surge 配置行")
	}
	parts := strings.Split(rest, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	if len(parts) < 3 || !strings.EqualFold(parts[0], "snell") {
		return "", errors.New("请粘贴 Snell 节点的 Surge 配置行")
	}
	port, e := strconv.Atoi(parts[2])
	if e != nil {
		return "", errors.New("Snell 节点的端口无效")
	}
	l := snellLink{host: strings.Trim(parts[1], "[]"), port: port, name: strings.TrimSpace(name)}
	for _, kv := range parts[3:] {
		k, v, ok := strings.Cut(kv, "=")
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.Trim(strings.TrimSpace(v), `"`)
		if !ok {
			return "", errors.New("Snell 配置行的参数无效")
		}
		switch k {
		case "psk":
			l.psk = v
		case "version":
			if l.version, e = strconv.Atoi(v); e != nil {
				return "", errors.New("Snell 版本无效")
			}
		case "obfs":
			if v != "off" {
				l.obfs = v
			}
		case "obfs-host":
			l.obfsHost = v
		case "tfo", "reuse", "udp-relay", "test-url", "test-timeout", "no-error-alert", "ecn", "block-quic", "ip-version":
			// Client-side tuning: it does not change which server is reached or how.
		default:
			return "", fmt.Errorf("Snell 配置行含有无法用于出口的参数：%s", truncateKey(k))
		}
	}
	if e := l.check(); e != nil {
		return "", e
	}
	return l.String(), nil
}

func (l snellLink) check() error {
	if !validHostStrict(l.host) || !validPort(l.port) {
		return errors.New("Snell 节点的地址或端口无效")
	}
	if l.psk == "" || strings.ContainsAny(l.psk, " \t\r\n\x00") {
		return errors.New("Snell PSK 无效")
	}
	switch l.version {
	case 4, 5, 6:
	case 0:
		return errors.New("Snell 配置行缺少 version")
	default:
		return errors.New("出口只支持 Snell v4、v5 和 v6")
	}
	switch l.obfs {
	case "":
		if l.obfsHost != "" {
			return errors.New("obfs-host 需要同时设置 obfs")
		}
	case "http", "tls":
		if l.version == 6 {
			return errors.New("Snell v6 没有 obfs 混淆")
		}
	default:
		return errors.New("Snell 混淆方式无效")
	}
	return nil
}

func (l snellLink) String() string {
	q := url.Values{}
	q.Set("version", strconv.Itoa(l.version))
	if l.obfs != "" {
		q.Set("obfs", l.obfs)
		if l.obfsHost != "" {
			q.Set("obfs-host", l.obfsHost)
		}
	}
	u := url.URL{Scheme: "snell", User: url.User(l.psk), Host: net.JoinHostPort(l.host, strconv.Itoa(l.port)), RawQuery: q.Encode(), Fragment: l.name}
	return u.String()
}

func parseSnellLink(raw string) (snellLink, error) {
	u, e := url.Parse(strings.TrimSpace(raw))
	if e != nil || !strings.EqualFold(u.Scheme, "snell") || u.User == nil {
		return snellLink{}, errors.New("Snell 链接无效")
	}
	port, e := strconv.Atoi(u.Port())
	if e != nil {
		return snellLink{}, errors.New("Snell 节点的端口无效")
	}
	q := u.Query()
	for k := range q {
		if k != "version" && k != "obfs" && k != "obfs-host" {
			return snellLink{}, errors.New("Snell 链接含有未知参数")
		}
	}
	v, _ := strconv.Atoi(q.Get("version"))
	l := snellLink{host: u.Hostname(), port: port, psk: u.User.Username(), version: v, obfs: q.Get("obfs"), obfsHost: q.Get("obfs-host"), name: u.Fragment}
	return l, l.check()
}

// outbound is the sing-box Snell outbound for the link.
func (l snellLink) outbound() M {
	out := M{"type": "snell", "tag": "node", "server": l.host, "server_port": l.port, "psk": l.psk, "version": 4}
	if l.version == 6 {
		out["version"] = 6
	}
	if l.obfs != "" {
		out["obfs_mode"] = l.obfs
		if l.obfsHost != "" {
			out["obfs_host"] = l.obfsHost
		}
	}
	return out
}
