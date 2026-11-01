package rout

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"syscall"
)

// A request made through a proxy can fail at several different places. fetchError names
// the place instead of one catch-all sentence.
const (
	fetchDNS      = "dns"      // the target (or the proxy) did not resolve
	fetchRefused  = "refused"  // connection refused
	fetchTimeout  = "timeout"  // no answer in time
	fetchRoute    = "route"    // no route / host or network unreachable
	fetchTLS      = "tls"      // TLS handshake or certificate
	fetchAuth     = "auth"     // proxy or protocol authentication rejected
	fetchProxy    = "proxy"    // the proxy chain failed without saying why
	fetchHTTP     = "http"     // the answer was an HTTP error
	fetchNotIP    = "not_ip"   // the checker answered something that is not an IP
	fetchInternal = "internal" // anything else
)

type fetchError struct {
	Kind   string
	Detail string // technical detail, never containing credentials
	Status int    // HTTP status for fetchHTTP / fetchAuth
}

func (e *fetchError) Error() string {
	switch e.Kind {
	case fetchDNS:
		return "请求失败：域名解析失败"
	case fetchRefused:
		return "请求失败：连接被拒绝"
	case fetchTimeout:
		return "请求失败：连接超时"
	case fetchRoute:
		return "请求失败：没有到目标的路由"
	case fetchTLS:
		return "请求失败：TLS 握手或证书错误"
	case fetchAuth:
		return "请求失败：代理或协议认证被拒绝"
	case fetchProxy:
		return "请求失败：代理链路失败（握手、认证或出口不可用，详见日志）"
	case fetchHTTP:
		return fmt.Sprintf("IP 检测 HTTP %d", e.Status)
	case fetchNotIP:
		return "检测站返回的不是有效 IP"
	}
	return "请求失败"
}

// classifyFetch turns an error from an HTTP client that goes through a local proxy into a
// fetchError. The SOCKS client reports the reply code of the proxy as text, which is the
// only place that distinguishes "target refused" from "proxy chain failed".
func classifyFetch(err error) *fetchError {
	var fe *fetchError
	if errors.As(err, &fe) {
		return fe
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	text := strings.ToLower(err.Error())
	detail := sanitizeFetchDetail(err.Error())
	var dns *net.DNSError
	var cert *tls.CertificateVerificationError
	var unknown x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	var tlsRecord tls.RecordHeaderError
	switch {
	case errors.As(err, &dns) || strings.Contains(text, "no such host"):
		return &fetchError{Kind: fetchDNS, Detail: detail}
	case errors.As(err, &cert) || errors.As(err, &unknown) || errors.As(err, &hostErr) || errors.As(err, &tlsRecord) || strings.Contains(text, "tls:") || strings.Contains(text, "x509:"):
		return &fetchError{Kind: fetchTLS, Detail: detail}
	case strings.Contains(text, "authentication failed") || strings.Contains(text, "407") || strings.Contains(text, "unauthorized") || strings.Contains(text, "not accepted"):
		return &fetchError{Kind: fetchAuth, Detail: detail, Status: 407}
	case strings.Contains(text, "connection refused") || errors.Is(err, syscall.ECONNREFUSED):
		return &fetchError{Kind: fetchRefused, Detail: detail}
	case strings.Contains(text, "host unreachable") || strings.Contains(text, "network unreachable") || strings.Contains(text, "no route") || errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH):
		return &fetchError{Kind: fetchRoute, Detail: detail}
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) || strings.Contains(text, "timeout") || strings.Contains(text, "deadline exceeded") || strings.Contains(text, "ttl expired"):
		return &fetchError{Kind: fetchTimeout, Detail: detail}
	case strings.Contains(text, "general socks server failure") || strings.Contains(text, "socks"):
		return &fetchError{Kind: fetchProxy, Detail: detail}
	}
	return &fetchError{Kind: fetchInternal, Detail: detail}
}

// sanitizeFetchDetail drops anything that could carry a credential (URLs with userinfo).
func sanitizeFetchDetail(s string) string {
	if i := strings.Index(s, "://"); i >= 0 {
		if at := strings.Index(s[i:], "@"); at > 0 && at < 200 {
			s = s[:i+3] + "***" + s[i+at:]
		}
	}
	if len(s) > 240 {
		s = s[:240] + "…"
	}
	return s
}

// classifyClientLog reads a sing-box client's error log after a failed request and says
// which stage the log blames. It is a hint, not a proof: sing-box does not expose the
// stage in any structured form.
func classifyClientLog(log string) (kind string) {
	l := strings.ToLower(log)
	switch {
	case strings.Contains(l, "reality") && (strings.Contains(l, "verif") || strings.Contains(l, "handshake") || strings.Contains(l, "fail")):
		return "reality"
	case strings.Contains(l, "authentication failed") || strings.Contains(l, "unauthorized") || strings.Contains(l, "invalid user") || strings.Contains(l, "auth fail"):
		return "auth"
	case strings.Contains(l, "tls:") || strings.Contains(l, "x509") || strings.Contains(l, "certificate"):
		return "tls"
	case strings.Contains(l, "connection refused"):
		return "refused"
	case strings.Contains(l, "i/o timeout") || strings.Contains(l, "deadline exceeded") || strings.Contains(l, "timeout"):
		return "timeout"
	case strings.Contains(l, "no route") || strings.Contains(l, "unreachable"):
		return "route"
	case strings.Contains(l, "no such host") || strings.Contains(l, "lookup"):
		return "dns"
	}
	return ""
}
