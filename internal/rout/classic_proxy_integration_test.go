package rout

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestIntegrationAuthenticatedProxyEntries(t *testing.T) {
	a := integrationApp(t)
	// Each engine runs a real, separately authenticated inbound. The third entry
	// uses the first one as its upstream, with its own independent credentials.
	start := func(t *testing.T, protocol string, upstream *Proxy) Proxy {
		t.Helper()
		p := fixture(t, protocol)
		p.PublicHost = p.Listen
		p.Outbound = upstream
		port, err := freeNodePort(p)
		if err != nil {
			t.Fatal(err)
		}
		p.Port, p.PublicPort = port, port
		if err := a.writeProfile(p); err != nil {
			t.Fatal(err)
		}
		conf := filepath.Join(a.profileDir(p.ID), "config.json")
		if err := a.checkConfig(conf); err != nil {
			t.Fatal(err)
		}
		engineLog := startEngine(t, profileSockets(p), a.enginePath("sing-box"), "run", "-c", conf)
		t.Cleanup(func() {
			log, err := os.ReadFile(engineLog)
			if err != nil {
				t.Error(err)
			} else if bytes.Contains(log, []byte(p.Username)) || bytes.Contains(log, []byte(p.Password)) {
				t.Error("proxy credentials were recorded in the engine log")
			}
		})
		line, err := p.Share()
		if err != nil {
			t.Fatal(err)
		}
		proxy, err := ParseProxy(protocol, line)
		if err != nil {
			t.Fatal(err)
		}
		return *proxy
	}

	t.Run("SOCKS5", func(t *testing.T) {
		verifyClassicProxyAuth(t, start(t, "socks5", nil), false)
	})
	t.Run("HTTP and CONNECT", func(t *testing.T) {
		p := start(t, "http", nil)
		verifyClassicProxyAuth(t, p, false)
		verifyClassicProxyAuth(t, p, true)
	})
	t.Run("HTTP forwarded via SOCKS5", func(t *testing.T) {
		upstream := start(t, "socks5", nil)
		entry := start(t, "http", &upstream)
		verifyClassicProxyAuth(t, entry, true)
		upstream.Password = "wrong-upstream-password"
		broken := start(t, "http", &upstream)
		verifyClassicProxyRequest(t, broken, false, true)
	})
}

func verifyClassicProxyAuth(t *testing.T, p Proxy, tls bool) {
	t.Helper()
	verifyClassicProxyRequest(t, p, true, tls)
	wrong := p
	wrong.Password = "wrong-password"
	verifyClassicProxyRequest(t, wrong, false, tls)
	anonymous := p
	anonymous.Username, anonymous.Password = "", ""
	verifyClassicProxyRequest(t, anonymous, false, tls)
}

func verifyClassicProxyRequest(t *testing.T, p Proxy, wantOK bool, useTLS bool) {
	t.Helper()
	var reached atomic.Int32
	var leaked atomic.Bool
	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		reached.Add(1)
		leaked.Store(req.Header.Get("Proxy-Authorization") != "")
		io.WriteString(w, "through proxy")
	})
	var origin *httptest.Server
	if useTLS {
		origin = httptest.NewTLSServer(handler)
	} else {
		origin = httptest.NewServer(handler)
	}
	defer origin.Close()

	proxyURL := &url.URL{Scheme: p.Protocol, Host: p.hostPort()}
	if p.Username != "" {
		proxyURL.User = url.UserPassword(p.Username, p.Password)
	}
	transport := &http.Transport{}
	if base, ok := origin.Client().Transport.(*http.Transport); ok {
		transport = base.Clone()
	}
	transport.Proxy = http.ProxyURL(proxyURL)
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	defer client.CloseIdleConnections()
	resp, err := client.Get(origin.URL)
	ok := false
	if err == nil {
		defer resp.Body.Close()
		b, readErr := io.ReadAll(resp.Body)
		ok = readErr == nil && resp.StatusCode == http.StatusOK && string(b) == "through proxy"
	}
	if wantOK && (!ok || reached.Load() != 1 || leaked.Load()) {
		t.Fatalf("%s failed to relay the authenticated request safely: %v", p.Protocol, err)
	}
	if !wantOK && (ok || reached.Load() != 0) {
		t.Fatal("request with missing or incorrect credentials reached the origin")
	}
}
