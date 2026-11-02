package remote

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// testFetcher reaches loopback test servers only; production code always uses NewFetcher.
func testFetcher() *Fetcher {
	f := NewFetcher()
	f.g.check = func(ip netip.Addr) error {
		if ip.IsLoopback() {
			return nil
		}
		return CheckIP(ip)
	}
	f.validate = func(raw string) (*url.URL, error) {
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return nil, errors.New("订阅地址无效")
		}
		switch u.Hostname() {
		case "127.0.0.1", "localhost":
			return u, nil
		}
		return ValidateURL(raw)
	}
	return f
}

func TestFetchReturnsBodyAndMetadata(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != "clash.meta" {
			t.Errorf("user agent = %q", r.Header.Get("User-Agent"))
		}
		w.Header().Set("Subscription-Userinfo", "upload=10; download=20; total=1000; expire=1893456000")
		w.Header().Set("Profile-Title", "base64:"+base64.StdEncoding.EncodeToString([]byte("我的订阅 🚀")))
		w.Header().Set("Profile-Update-Interval", "12")
		_, _ = w.Write([]byte("hello"))
	}))
	defer srv.Close()
	res, err := testFetcher().Fetch(context.Background(), srv.URL, FetchOptions{UserAgent: "clash.meta"})
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Body) != "hello" || res.Title != "我的订阅 🚀" || res.IntervalHours != 12 {
		t.Fatalf("unexpected result %+v", res)
	}
	if res.UserInfo == nil || res.UserInfo.Total != 1000 || res.UserInfo.Expire != 1893456000 || res.UserInfo.Download != 20 {
		t.Fatalf("userinfo %+v", res.UserInfo)
	}
	if res.Host != "127.0.0.1" {
		t.Fatalf("host %q", res.Host)
	}
}

func TestFetchEnforcesSizeLimits(t *testing.T) {
	big := bytes.Repeat([]byte("A"), 2<<20)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/chunked" {
			// No Content-Length: the limit must hold while streaming.
			w.(http.Flusher).Flush()
		}
		_, _ = w.Write(big)
	}))
	defer srv.Close()
	for _, path := range []string{"/declared", "/chunked"} {
		_, err := testFetcher().Fetch(context.Background(), srv.URL+path, FetchOptions{MaxBytes: 1 << 20})
		if err == nil || !strings.Contains(err.Error(), "过大") {
			t.Errorf("%s: want size error, got %v", path, err)
		}
	}
	res, err := testFetcher().Fetch(context.Background(), srv.URL, FetchOptions{MaxBytes: 4 << 20})
	if err != nil || len(res.Body) != len(big) {
		t.Fatalf("within-limit download failed: %v", err)
	}
}

func TestFetchDefeatsCompressionBombs(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zero := make([]byte, 1<<20)
	for i := 0; i < 64; i++ { // 64 MiB of zeros compresses to a few tens of KiB
		_, _ = zw.Write(zero)
	}
	_ = zw.Close()
	if buf.Len() > 200<<10 {
		t.Fatalf("test bomb not small enough: %d", buf.Len())
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(buf.Bytes())
	}))
	defer srv.Close()
	_, err := testFetcher().Fetch(context.Background(), srv.URL, FetchOptions{MaxBytes: 1 << 20})
	if err == nil || !strings.Contains(err.Error(), "过大") {
		t.Fatalf("decompressed size must be limited, got %v", err)
	}
}

func TestFetchStatusTimeoutAndErrorsHideTheURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/slow":
			time.Sleep(2 * time.Second)
		case "/forbidden":
			w.WriteHeader(http.StatusForbidden)
		case "/partial":
			w.WriteHeader(http.StatusPartialContent)
		}
		_, _ = w.Write([]byte("x"))
	}))
	defer srv.Close()
	f := testFetcher()
	if _, err := f.Fetch(context.Background(), srv.URL+"/forbidden?token=SECRET", FetchOptions{}); err == nil || !strings.Contains(err.Error(), "403") || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("status error: %v", err)
	}
	if _, err := f.Fetch(context.Background(), srv.URL+"/partial", FetchOptions{}); err == nil {
		t.Fatal("only 200 is accepted")
	}
	start := time.Now()
	_, err := f.Fetch(context.Background(), srv.URL+"/slow?token=SECRET", FetchOptions{Timeout: 300 * time.Millisecond})
	if err == nil || strings.Contains(err.Error(), "SECRET") || time.Since(start) > 1500*time.Millisecond {
		t.Fatalf("timeout must be enforced without leaking the URL: %v after %v", err, time.Since(start))
	}
	srv.Close()
	if _, err := f.Fetch(context.Background(), srv.URL+"/x?token=SECRET", FetchOptions{}); err == nil || strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("connection error must not leak the URL: %v", err)
	}
}

func TestFetchRedirects(t *testing.T) {
	var hits atomic.Int32
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch r.URL.Path {
		case "/ok":
			http.Redirect(w, r, "/final", http.StatusFound)
		case "/final":
			_, _ = w.Write([]byte("done"))
		case "/loop":
			http.Redirect(w, r, "/loop", http.StatusFound)
		case "/metadata":
			http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
		case "/private":
			http.Redirect(w, r, "http://10.0.0.1/admin", http.StatusFound)
		case "/scheme":
			http.Redirect(w, r, "file:///etc/passwd", http.StatusFound)
		case "/localhost":
			http.Redirect(w, r, "http://localhost.localdomain/x", http.StatusFound)
		}
	}))
	defer srv.Close()
	f := testFetcher()
	if res, err := f.Fetch(context.Background(), srv.URL+"/ok", FetchOptions{}); err != nil || string(res.Body) != "done" {
		t.Fatalf("safe redirect failed: %v", err)
	}
	for _, path := range []string{"/loop", "/metadata", "/private", "/scheme", "/localhost"} {
		hits.Store(0)
		if _, err := f.Fetch(context.Background(), srv.URL+path, FetchOptions{}); err == nil {
			t.Errorf("%s: redirect must be refused", path)
		}
		if path != "/loop" && hits.Load() != 1 {
			t.Errorf("%s: the redirect target must never be requested (hits=%d)", path, hits.Load())
		}
	}
	// A real fetcher refuses a loopback origin outright.
	if _, err := NewFetcher().Fetch(context.Background(), srv.URL+"/final", FetchOptions{}); err == nil {
		t.Fatal("production fetcher must refuse a loopback URL")
	}
}

func TestRedirectNeverDowngradesFromHTTPS(t *testing.T) {
	f := testFetcher()
	check := f.client(time.Second).CheckRedirect
	from, _ := http.NewRequest("GET", "https://example.org/a", nil)
	to, _ := http.NewRequest("GET", "http://example.org/b", nil)
	if err := check(to, []*http.Request{from}); err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("https -> http must be refused, got %v", err)
	}
	same, _ := http.NewRequest("GET", "https://example.org/b", nil)
	if err := check(same, []*http.Request{from}); err != nil {
		t.Fatalf("https -> https must be allowed: %v", err)
	}
	via := make([]*http.Request, maxRedirects)
	for i := range via {
		via[i] = from
	}
	if err := check(same, via); err == nil {
		t.Fatal("redirect count must be limited")
	}
}

func TestFetchIgnoresEnvironmentProxy(t *testing.T) {
	// A proxy variable would make the guard see the proxy's address instead of the real peer.
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("http_proxy", "http://127.0.0.1:1")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("direct")) }))
	defer srv.Close()
	res, err := testFetcher().Fetch(context.Background(), srv.URL, FetchOptions{})
	if err != nil || string(res.Body) != "direct" {
		t.Fatalf("must connect directly: %v", err)
	}
}

func TestFetchVerifiesTLSCertificates(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("secure")) }))
	defer srv.Close()
	f := testFetcher()
	_, err := f.Fetch(context.Background(), srv.URL, FetchOptions{})
	if err == nil || !strings.Contains(err.Error(), "证书") {
		t.Fatalf("untrusted certificate must fail verification, got %v", err)
	}
	pool := srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	f.tlsConf = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	res, err := f.Fetch(context.Background(), srv.URL, FetchOptions{})
	if err != nil || string(res.Body) != "secure" {
		t.Fatalf("trusted certificate failed: %v", err)
	}
}

func TestUserInfoParsing(t *testing.T) {
	if parseUserInfo("") != nil || parseUserInfo("garbage") != nil {
		t.Fatal("no usable fields must give nil")
	}
	ui := parseUserInfo("upload=1;download=2;total=3;expire=4;bogus=5;total2=x")
	if ui == nil || ui.Upload != 1 || ui.Download != 2 || ui.Total != 3 || ui.Expire != 4 {
		t.Fatalf("%+v", ui)
	}
	if parseUserInfo("total=-5") != nil {
		t.Fatal("negative values are ignored")
	}
}
