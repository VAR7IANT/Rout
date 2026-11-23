package rout

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const (
	protoMTP     = "mtp"
	mtpEngine    = "mtg"
	mtpConf      = "mtg.toml"
	mtpAllowlist = "mtg-allowlist.txt"
	mtpCoverHost = "www.cloudflare.com"
	mtpKeyBytes  = 16
)

var errMTPClient = errors.New("MTP 仅供 Telegram 使用，请用 Telegram 导入链接")
var errMTPOutbound = errors.New("MTP 不支持 Rout 出站代理、出站网络策略或 AI 分流")

func (p Profile) mtpNode() bool { return p.Kind == "node" && p.Protocol == protoMTP }

// An ee secret encodes the FakeTLS mode, a 128-bit key and the cover hostname.
// The same complete hex value goes into mtg's configuration and Telegram's links.
func newMTPSecret() string {
	return "ee" + RandomHex(mtpKeyBytes) + hex.EncodeToString([]byte(mtpCoverHost))
}

func (p Profile) checkMTPSecret() error {
	raw, e := hex.DecodeString(p.Password)
	// Telegram Desktop requires at least 21 bytes for an ee secret.
	if e != nil || len(raw) < 1+mtpKeyBytes+4 || raw[0] != 0xee ||
		bytes.Equal(raw[1:1+mtpKeyBytes], make([]byte, mtpKeyBytes)) {
		return errors.New("MTP Secret 必须是包含域名的有效 FakeTLS 十六进制密钥")
	}
	host := string(raw[1+mtpKeyBytes:])
	if !validHostStrict(host) || net.ParseIP(host) != nil || !strings.Contains(host, ".") {
		return errors.New("MTP Secret 中的 FakeTLS 域名无效")
	}
	return nil
}

func (p Profile) checkMTP() error {
	if e := p.checkMTPSecret(); e != nil {
		return e
	}
	if p.Outbound != nil || p.ExitID != "" || p.AIRoute != nil || p.outboundPolicy() != outAuto {
		return errMTPOutbound
	}
	family := familyOf(p.PublicHost)
	if !validPublicHost(p.PublicHost) || (family != "" && p.inboundMode() != inDual && family != p.inboundMode()) {
		return errors.New("公网连接地址与所选监听模式不匹配")
	}
	return nil
}

func (p Profile) telegramLinks(host string, port int) (web, deep string, err error) {
	if !p.mtpNode() {
		return "", "", errMTPClient
	}
	if e := p.checkMTPSecret(); e != nil {
		return "", "", e
	}
	if !validPublicHost(host) || !validPort(port) {
		return "", "", errors.New("地址或端口无效")
	}
	query := "server=" + url.QueryEscape(host) + "&port=" + itoa(port) + "&secret=" + p.Password
	return "https://t.me/proxy?" + query, "tg://proxy?" + query, nil
}

// mtg uses Go's generic TCP listener, which may open a dual-stack socket for
// either wildcard. Match Rout's inbound family (and its nftables rules) at the
// application layer using mtg's local client allowlist.
func (p Profile) mtpAllowedCIDR() string {
	if !net.ParseIP(p.Listen).IsUnspecified() {
		return ""
	}
	switch p.inboundMode() {
	case inIPv4:
		return "0.0.0.0/0\n"
	case inIPv6:
		return "::/0\n"
	}
	return ""
}

func mtpServerConf(p Profile, dir string) (string, error) {
	if e := p.Validate(); e != nil {
		return "", e
	}
	conf := fmt.Sprintf("debug = false\nsecret = %q\nbind-to = %q\n", p.Password, net.JoinHostPort(p.Listen, itoa(p.Port)))
	// mtg checks the cover domain at startup. Limit its public-IP HTTP lookup so
	// an unavailable echo endpoint does not delay service startup indefinitely.
	conf += "prefer-ip = \"prefer-ipv4\"\n\n[network.timeout]\nhttp = \"2s\"\n"
	if p.mtpAllowedCIDR() != "" {
		path, e := filepath.Abs(filepath.Join(dir, mtpAllowlist))
		if e != nil {
			return "", e
		}
		conf += fmt.Sprintf("\n[defense.allowlist]\nenabled = true\nurls = [%q]\n", path)
	}
	return conf, nil
}

func checkMTPConf(p Profile, dir string) error {
	conf, e := mtpServerConf(p, dir)
	if e != nil {
		return e
	}
	files := map[string]string{mtpConf: conf}
	if cidr := p.mtpAllowedCIDR(); cidr != "" {
		files[mtpAllowlist] = cidr
	}
	for name, want := range files {
		path := filepath.Join(dir, name)
		b, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		if string(b) != want {
			return errors.New("MTP 运行配置与节点设置不一致，请运行 rout apply 修复")
		}
	}
	return nil
}
