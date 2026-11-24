package rout

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"unicode"
)

var errClassicProxyShare = errors.New("SOCKS5/HTTP 入口请使用 IP:端口:用户名:密码 格式")

func (p Profile) classicProxyNode() bool {
	return p.Kind == "node" && (p.Protocol == "socks5" || p.Protocol == "http")
}

func (p Profile) classicProxyAt(host string, port int) (Proxy, error) {
	proxy := Proxy{Protocol: p.Protocol, Host: host, Port: port, Username: p.Username, Password: p.Password}
	if err := proxy.Validate(); err != nil {
		return Proxy{}, err
	}
	// SOCKS5 stores credential lengths in one byte. The text import trims trailing
	// whitespace, so refuse a password that would change on the receiving side.
	if (p.Protocol == "socks5" && (len(p.Username) > 255 || len(p.Password) > 255)) ||
		strings.TrimRightFunc(p.Password, unicode.IsSpace) != p.Password {
		return Proxy{}, errors.New("代理用户名或密码无法按添加格式完整导入")
	}
	return proxy, nil
}

func newClassicCredentials() (username, password string, err error) {
	var random [42]byte
	if _, err = rand.Read(random[:]); err != nil {
		return "", "", err
	}
	return base64.RawURLEncoding.EncodeToString(random[:18]), base64.RawURLEncoding.EncodeToString(random[18:]), nil
}

// inputLine is explicitly credential-bearing and is used only to reveal or import a proxy.
func (p Proxy) inputLine() string {
	return p.hostPort() + ":" + p.Username + ":" + p.Password
}
