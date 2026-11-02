package rout

import (
	"context"
	"crypto/tls"
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
	"sync"
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
		return "", classifyFetch(e)
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return "", &fetchError{Kind: fetchHTTP, Status: r.StatusCode}
	}
	b, e := io.ReadAll(io.LimitReader(r.Body, 128))
	if e != nil {
		return "", e
	}
	ip := strings.TrimSpace(string(b))
	if net.ParseIP(ip) == nil {
		return "", &fetchError{Kind: fetchNotIP}
	}
	return ip, nil
}

// Each family has independent endpoints, so an IPv6-only host is never forced to
// depend on IPv4 (and vice versa).
var ipEndpoints = map[string][]string{
	"tcp4": {"https://api4.ipify.org", "https://ipv4.icanhazip.com"},
	"tcp6": {"https://api6.ipify.org", "https://ipv6.icanhazip.com"},
}

// detectDirect finds this host's public address of one family without any proxy.
func detectDirect(network string) string {
	for _, endpoint := range ipEndpoints[network] {
		d := &net.Dialer{Timeout: 5 * time.Second}
		transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) { return d.DialContext(ctx, network, addr) }}
		client := &http.Client{Transport: transport, Timeout: 8 * time.Second}
		r, e := client.Get(endpoint)
		if e == nil {
			b, _ := io.ReadAll(io.LimitReader(r.Body, 128))
			r.Body.Close()
			ip := net.ParseIP(strings.TrimSpace(string(b)))
			transport.CloseIdleConnections()
			if r.StatusCode == 200 && ip != nil && (ip.To4() != nil) == (network == "tcp4") {
				return ip.String()
			}
		}
		transport.CloseIdleConnections()
	}
	return ""
}

// DetectPublicIPs queries both families concurrently.
func DetectPublicIPs() (string, string) {
	v6 := make(chan string, 1)
	go func() { v6 <- detectDirect("tcp6") }()
	v4 := detectDirect("tcp4")
	return v4, <-v6
}

// DetectPublicIP prefers IPv4 for compatibility but falls back to IPv6-only hosts.
func DetectPublicIP() string {
	v4, v6 := DetectPublicIPs()
	if v4 != "" {
		return v4
	}
	return v6
}

// CheckRealityTarget verifies from THIS server that the borrowed handshake target
// answers TLS 1.3 with a valid certificate for the SNI, as Reality requires.
func CheckRealityTarget(sni string) error {
	d := &net.Dialer{Timeout: 6 * time.Second}
	c, e := tls.DialWithDialer(d, "tcp", net.JoinHostPort(sni, "443"), &tls.Config{ServerName: sni, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"}})
	if e != nil {
		return fmt.Errorf("本机无法与 %s:443 建立有效的 TLS 1.3 连接（%v）", sni, e)
	}
	defer c.Close()
	if c.ConnectionState().NegotiatedProtocol != "h2" {
		return fmt.Errorf("%s 未协商 HTTP/2，Reality 伪装效果可能较差", sni)
	}
	return nil
}
func orUnavailable(a *App, ip string) string {
	if ip == "" {
		return a.T("不可用")
	}
	return ip
}
func freePort() (int, error) {
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		// An IPv6-only host has no IPv4 loopback address to borrow a port from.
		var e6 error
		if l, e6 = net.Listen("tcp", "[::1]:0"); e6 != nil {
			return 0, e
		}
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// tailBuffer keeps the last bytes written to it (the end of an engine's log).
type tailBuffer struct {
	mu  sync.Mutex
	buf []byte
	max int
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	if len(t.buf) > t.max {
		t.buf = t.buf[len(t.buf)-t.max:]
	}
	return len(p), nil
}
func (t *tailBuffer) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(t.buf)
}

func (a *App) withClient(config M, port int, fn func(string) error) error {
	return a.withClientLog(config, port, func(proxy string, _ func() string) error { return fn(proxy) })
}

// withClientLog is withClient that also hands fn the tail of the client's error log, so a
// failed request can be explained. The log can name hosts; it is never shown verbatim.
func (a *App) withClientLog(config M, port int, fn func(string, func() string) error) error {
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
	logs := &tailBuffer{max: 16 << 10}
	cmd.Stdout = io.Discard
	cmd.Stderr = logs
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
	return fn("socks5://"+address, logs.String)
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
	e = a.withClient(conf, port, func(proxy string) error {
		var er error
		for _, endpoint := range append(append([]string{}, ipEndpoints["tcp4"]...), ipEndpoints["tcp6"]...) {
			if ip, er = fetchIP(proxy, endpoint); er == nil {
				return nil
			}
		}
		return er
	})
	return ip, e
}
