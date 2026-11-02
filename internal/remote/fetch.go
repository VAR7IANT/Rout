package remote

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Limits applied to every download. The caller may lower them, never raise them past the hard caps.
const (
	DefaultMaxBytes = 8 << 20
	HardMaxBytes    = 32 << 20
	DefaultTimeout  = 30 * time.Second
	maxRedirects    = 5
	maxURLLength    = 4096
)

// FetchOptions bounds a single download.
type FetchOptions struct {
	UserAgent string
	MaxBytes  int64
	Timeout   time.Duration
}

// UserInfo is the provider's quota report (the Subscription-Userinfo header). Zero values
// mean "not reported".
type UserInfo struct {
	Upload   int64 `json:"upload"`
	Download int64 `json:"download"`
	Total    int64 `json:"total"`
	Expire   int64 `json:"expire"` // Unix seconds
}

// Result is a downloaded body plus the response metadata worth showing.
type Result struct {
	Body []byte
	// UserInfo is nil when the provider sent no quota header.
	UserInfo *UserInfo
	// Title is the provider's Profile-Title, decoded.
	Title string
	// IntervalHours is the provider's Profile-Update-Interval hint (0 when absent).
	IntervalHours int
	// Host is the final host that answered (never the path or query, which may hold a token).
	Host string
}

// Fetcher downloads subscriptions through an SSRF-safe transport.
type Fetcher struct {
	g        *guard
	validate func(string) (*url.URL, error)
	tlsConf  *tls.Config
}

// NewFetcher returns a Fetcher that refuses every non-public destination.
func NewFetcher() *Fetcher { return &Fetcher{g: newGuard(), validate: ValidateURL} }

// ValidateURL checks a subscription URL without connecting to it.
func ValidateURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > maxURLLength || strings.ContainsAny(raw, "\r\n\x00 \t") || !utf8.ValidString(raw) {
		return nil, errors.New("订阅地址无效")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, errors.New("订阅地址无效")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, errors.New("订阅地址只能使用 http:// 或 https://")
	}
	if u.User != nil {
		return nil, errors.New("订阅地址不能包含用户名和密码，请使用地址中的令牌参数")
	}
	host := u.Hostname()
	if host == "" || !isASCII(host) {
		return nil, errors.New("订阅域名无效（国际化域名请使用 Punycode 形式）")
	}
	if p := u.Port(); p != "" {
		if n, e := strconv.Atoi(p); e != nil || n < 1 || n > 65535 {
			return nil, errors.New("订阅地址端口无效")
		}
	}
	if ip, e := netip.ParseAddr(host); e == nil {
		if e := CheckIP(ip); e != nil {
			return nil, e
		}
	} else {
		if sensitiveHost(host) || numericHost(host) {
			return nil, ErrBlockedAddress
		}
	}
	return u, nil
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func (f *Fetcher) tlsConfig() *tls.Config {
	if f.tlsConf != nil {
		return f.tlsConf
	}
	return &tls.Config{MinVersion: tls.VersionTLS12}
}

func (f *Fetcher) client(timeout time.Duration) *http.Client {
	tr := &http.Transport{
		Proxy:                  nil, // never route through an environment proxy: the guard must see the real peer
		DialContext:            f.g.DialContext,
		TLSClientConfig:        f.tlsConfig(),
		TLSHandshakeTimeout:    10 * time.Second,
		ResponseHeaderTimeout:  15 * time.Second,
		MaxResponseHeaderBytes: 64 << 10,
		DisableKeepAlives:      true,
		ForceAttemptHTTP2:      true,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return userError("重定向次数过多")
			}
			if _, e := f.validate(req.URL.String()); e != nil {
				return userError(fmt.Sprintf("重定向目标无效：%s", e))
			}
			if via[len(via)-1].URL.Scheme == "https" && req.URL.Scheme != "https" {
				return userError("拒绝从 HTTPS 重定向到明文 HTTP")
			}
			return nil
		},
	}
}

// Fetch downloads rawURL and returns the body (never more than the byte limit).
func (f *Fetcher) Fetch(ctx context.Context, rawURL string, opt FetchOptions) (*Result, error) {
	u, err := f.validate(rawURL)
	if err != nil {
		return nil, err
	}
	max := opt.MaxBytes
	if max <= 0 {
		max = DefaultMaxBytes
	}
	if max > HardMaxBytes {
		max = HardMaxBytes
	}
	timeout := opt.Timeout
	if timeout <= 0 || timeout > 2*DefaultTimeout {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, errors.New("订阅地址无效")
	}
	ua := opt.UserAgent
	if ua == "" || len(ua) > 200 || strings.ContainsAny(ua, "\r\n\x00") {
		ua = "Rout-subscription-import"
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "*/*")
	resp, err := f.client(timeout).Do(req)
	if err != nil {
		return nil, describeFetchError(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("订阅服务器返回 HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > max {
		return nil, fmt.Errorf("订阅内容过大（上限 %d MiB）", max>>20)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, describeFetchError(err)
	}
	if int64(len(body)) > max {
		return nil, fmt.Errorf("订阅内容过大（上限 %d MiB）", max>>20)
	}
	res := &Result{Body: body, Host: resp.Request.URL.Hostname()}
	res.UserInfo = parseUserInfo(resp.Header.Get("Subscription-Userinfo"))
	res.Title = decodeProfileTitle(resp.Header.Get("Profile-Title"))
	if n, e := strconv.Atoi(strings.TrimSpace(resp.Header.Get("Profile-Update-Interval"))); e == nil && n > 0 && n <= 24*30 {
		res.IntervalHours = n
	}
	return res, nil
}

// userError is a failure whose text is already safe and meant for the administrator (it
// never contains the URL), as opposed to a transport error that must be summarised.
type userError string

func (e userError) Error() string { return string(e) }

// describeFetchError turns transport errors into messages that never echo the URL
// (which may contain a token) and keep the useful cause.
func describeFetchError(err error) error {
	switch {
	case errors.Is(err, ErrBlockedAddress):
		return ErrBlockedAddress
	case errors.Is(err, context.DeadlineExceeded):
		return errors.New("下载超时")
	case errors.Is(err, context.Canceled):
		return errors.New("下载已取消")
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return errors.New("域名解析失败")
	}
	var cert *tls.CertificateVerificationError
	if errors.As(err, &cert) {
		return errors.New("TLS 证书验证失败")
	}
	var user userError
	if errors.As(err, &user) {
		return errors.New(string(user))
	}
	if strings.Contains(err.Error(), ErrBlockedAddress.Error()) {
		return ErrBlockedAddress
	}
	return errors.New("无法连接订阅服务器")
}

func parseUserInfo(h string) *UserInfo {
	if strings.TrimSpace(h) == "" {
		return nil
	}
	var ui UserInfo
	seen := false
	for _, part := range strings.Split(h, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		if err != nil || n < 0 {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "upload":
			ui.Upload, seen = n, true
		case "download":
			ui.Download, seen = n, true
		case "total":
			ui.Total, seen = n, true
		case "expire":
			ui.Expire, seen = n, true
		}
	}
	if !seen {
		return nil
	}
	return &ui
}

// numericHost reports names whose last label is a number (2130706433, 0x7f.1, 017.0.0.1):
// forms some resolvers read as an IPv4 address in disguise. A real domain never ends in one.
func numericHost(host string) bool {
	h := strings.TrimSuffix(host, ".")
	last := h[strings.LastIndexByte(h, '.')+1:]
	if last == "" {
		return true
	}
	if strings.HasPrefix(strings.ToLower(last), "0x") {
		return true
	}
	return strings.Trim(last, "0123456789") == ""
}
