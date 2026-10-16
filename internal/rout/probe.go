package rout

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func fetchIP(proxyAddress, endpoint string) (string, error) {
	transport := &http.Transport{Proxy: nil}
	if proxyAddress != "" {
		u, e := url.Parse(proxyAddress)
		if e != nil {
			return "", e
		}
		transport.Proxy = http.ProxyURL(u)
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 12 * time.Second}
	r, e := client.Get(endpoint)
	if e != nil {
		return "", errors.New("请求失败（连接、认证、TLS 或网络不可用）")
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return "", fmt.Errorf("IP 检测 HTTP %d", r.StatusCode)
	}
	b, e := io.ReadAll(io.LimitReader(r.Body, 128))
	if e != nil {
		return "", e
	}
	ip := strings.TrimSpace(string(b))
	if net.ParseIP(ip) == nil {
		return "", errors.New("检测站返回的不是有效 IP")
	}
	return ip, nil
}
func DetectPublicIP() string { ip, _ := fetchIP("", "https://api4.ipify.org"); return ip }
func freePort() (int, error) {
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		return 0, e
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func (a *App) withClient(config M, port int, fn func(string) error) error {
	if e := a.EnsureEngine("sing-box"); e != nil {
		return e
	}
	dir, e := os.MkdirTemp("", "rout-probe-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(dir)
	b, e := JSON(config)
	if e != nil {
		return e
	}
	path := filepath.Join(dir, "config.json")
	if e = AtomicWrite(path, b, 0600); e != nil {
		return e
	}
	if e = a.checkConfig(path); e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, a.enginePath("sing-box"), "run", "-c", path)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if e = cmd.Start(); e != nil {
		return e
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	defer func() {
		_ = cmd.Process.Kill()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	}()
	address := net.JoinHostPort("127.0.0.1", itoa(port))
	ready := false
	for i := 0; i < 60; i++ {
		select {
		case <-done:
			return errors.New("临时检测进程启动失败")
		default:
		}
		c, er := net.DialTimeout("tcp", address, 50*time.Millisecond)
		if er == nil {
			c.Close()
			ready = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		return errors.New("临时检测入口未就绪")
	}
	return fn("socks5://" + address)
}

func (a *App) ProbeProxy(p Proxy) (string, error) {
	if e := p.Validate(); e != nil {
		return "", e
	}
	port, e := freePort()
	if e != nil {
		return "", e
	}
	conf := M{"log": M{"level": "error"}, "inbounds": []any{M{"type": "mixed", "listen": "127.0.0.1", "listen_port": port}}, "outbounds": []any{proxyConfig(p)}, "route": M{"final": "egress"}}
	var ip string
	e = a.withClient(conf, port, func(proxy string) error { var er error; ip, er = fetchIP(proxy, "https://api4.ipify.org"); return er })
	return ip, e
}
func (a *App) Probe(p Profile) error {
	if !p.Enabled {
		return errors.New("线路未启用")
	}
	fmt.Println("VPS 直连 IPv4：", DetectPublicIP())
	fmt.Println("正在通过本地节点入口测试完整线路…")
	port, e := freePort()
	if e != nil {
		return e
	}
	host := p.Listen
	if host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	if host == "::" {
		host = "::1"
	}
	conf, e := ClientConfig(p, host, p.Port, port)
	if e != nil {
		return e
	}
	e = a.withClient(conf, port, func(proxy string) error {
		ip, e := fetchIP(proxy, "https://api4.ipify.org")
		if e != nil {
			return e
		}
		fmt.Println("线路出口 IPv4：", ip)
		ip6, e := fetchIP(proxy, "https://api6.ipify.org")
		if e != nil {
			fmt.Println("线路出口 IPv6：不可用（该项不影响 IPv4 结果）")
		} else {
			fmt.Println("线路出口 IPv6：", ip6)
		}
		return nil
	})
	if e == nil {
		fmt.Println("本地入口、协议握手与出口请求通过；公网端口仍需在外部客户端验证")
	}
	return e
}
