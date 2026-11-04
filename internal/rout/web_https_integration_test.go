package rout

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// Real Caddy, real TLS (Caddy's local CA), the real panel server: the panel site generated
// by Rout must validate, reload, serve the API and the login page through Caddy, coexist
// with the subscription site and an unrelated site, and be removable without touching them.
// Runs in CI inside a disposable Debian container (scripts/test-subscription-https.sh).
func TestIntegrationPanelCaddyDeployment(t *testing.T) {
	f := newSubscriptionCaddyFixture(t, false)
	a := f.sc.a
	if e := a.DeploySubscriptionHTTPS("sub.rout.test", false); e != nil {
		t.Fatal(e)
	}
	port, _ := freePort()
	if e := a.mutateWebConfig(func(c *WebConfig) error { c.Port = port; return nil }); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	ready := make(chan net.Addr, 1)
	go func() { done <- a.serveWeb(ctx, net.JoinHostPort("127.0.0.1", itoa(port)), func(string, ...any) {}, func(n net.Addr) { ready <- n }) }()
	select {
	case <-ready:
	case e := <-done:
		t.Fatal(e)
	case <-time.After(5 * time.Second):
		t.Fatal("panel did not start")
	}
	t.Cleanup(func() { cancel(); <-done })
	f.runtime.panelProbe = func(domain string, p int) panelVerification {
		v := panelVerification{}
		plain := &http.Client{Timeout: 2 * time.Second}
		if code, _, e := panelHealth(plain, "http://127.0.0.1:"+itoa(p), ""); e != nil || code != 200 {
			return v
		}
		v.LocalService = true
		code, _, e := panelHealth(plain, "http://127.0.0.1:"+itoa(p), domain)
		v.HostAllowed = e == nil && code == 200
		client, e := f.tlsClient()
		if e != nil {
			return v
		}
		if code, st, e := panelHealth(client, "https://"+domain, ""); e == nil && code == 200 {
			v.LocalTLS, v.PublicFromHost = true, true
			if st != nil && len(st.PeerCertificates) > 0 {
				v.Expires = st.PeerCertificates[0].NotAfter
			}
		}
		if resp, e := client.Get("https://" + domain + "/"); e == nil {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			// Without an embedded build the panel answers 503 "not built"; that still
			// proves Caddy forwarded the page request to the panel.
			v.LoginPage = resp.StatusCode == 200 && strings.Contains(string(b), `id="root"`) || resp.StatusCode == 503 && os.Getenv("ROUT_TEST_REQUIRE_WEBUI") != "1"
		}
		return v
	}
	if _, e := a.DeployWebHTTPS("sub.rout.test", WebHTTPSOptions{}); e == nil {
		t.Fatal("subscription domain reused for the panel")
	}
	res, e := a.DeployWebHTTPS("panel.sub.rout.test", WebHTTPSOptions{})
	if e != nil {
		t.Fatal(e)
	}
	if !res.Verification.ok() {
		t.Fatalf("not verified: %+v", res.Verification)
	}
	// Security headers survive the proxy and the panel still refuses unknown hosts.
	client, _ := f.tlsClient()
	resp, e := client.Get("https://panel.sub.rout.test/api/health")
	if e != nil {
		t.Fatal(e)
	}
	resp.Body.Close()
	if resp.Header.Get("Strict-Transport-Security") == "" || resp.Header.Get("Content-Security-Policy") == "" || resp.Header.Get("Server") != "" {
		t.Fatalf("headers %v", resp.Header)
	}
	if code, _ := f.request(t, "unrelated.rout.test", "/"); code != 200 {
		t.Fatal("unrelated site changed")
	}
	if code, _ := f.request(t, "sub.rout.test", "/"); code != 404 {
		t.Fatal("subscription site changed")
	}
	// Repeat: idempotent, still one import line.
	if _, e = a.DeployWebHTTPS("panel.sub.rout.test", WebHTTPSOptions{}); e != nil {
		t.Fatal(e)
	}
	main, _ := os.ReadFile(a.httpsMain())
	if strings.Count(string(main), "import ") != 1 {
		t.Fatalf("Caddyfile:\n%s", main)
	}
	if e = a.RemoveWebHTTPS(); e != nil {
		t.Fatal(e)
	}
	if code, _ := f.request(t, "unrelated.rout.test", "/"); code != 200 {
		t.Fatal("removal damaged another site")
	}
	if code, _ := f.request(t, "sub.rout.test", "/"); code != 404 {
		t.Fatal("removal damaged the subscription site")
	}
}
