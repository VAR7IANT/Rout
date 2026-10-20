package rout

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Real Caddy, private test CA, private ports, no system trust changes, no production
// DNS/ACME requests and no unrelated init units. The fresh-install CI container
// starts without Caddy; only the package-manager boundary uses its real apt source.
type subscriptionCaddyFixture struct {
	sc                           *subScene
	runtime                      *subscriptionHTTPSRuntime
	cmd                          *exec.Cmd
	done                         chan error
	running                      atomic.Bool
	logPath, dataDir             string
	httpPort, tlsPort, adminPort int
	enabled, installed           bool
	actualInstall                bool
	failVerification             bool
}

func newSubscriptionCaddyFixture(t *testing.T, fresh bool) *subscriptionCaddyFixture {
	t.Helper()
	if os.Getenv("ROUT_TEST_CADDY") != "1" {
		t.Skip("set ROUT_TEST_CADDY=1 in a disposable Caddy test environment")
	}
	sc := newSubScene(t)
	port, _ := freePort()
	if e := sc.a.SaveSettings(Settings{Language: "en", Subscription: &SubscriptionSettings{Enabled: true, Port: port}}); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	ready := make(chan net.Addr, 1)
	go func() { done <- sc.a.ServeSubscriptionsWithReady(ctx, func(a net.Addr) { ready <- a }) }()
	select {
	case <-ready:
	case e := <-done:
		t.Fatal(e)
	case <-time.After(5 * time.Second):
		t.Fatal("subscription fixture did not start")
	}
	t.Cleanup(func() {
		cancel()
		select {
		case e := <-done:
			if e != nil {
				t.Error(e)
			}
		case <-time.After(7 * time.Second):
			t.Error("subscription fixture did not stop")
		}
	})
	f := &subscriptionCaddyFixture{sc: sc, installed: !fresh, enabled: !fresh, dataDir: t.TempDir(), logPath: filepath.Join(t.TempDir(), "caddy.log")}
	f.httpPort, _ = freePort()
	f.tlsPort, _ = freePort()
	f.adminPort, _ = freePort()
	t.Setenv("XDG_DATA_HOME", f.dataDir)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	r := &subscriptionHTTPSRuntime{root: t.TempDir(), verificationWait: 10 * time.Second, osID: func() string { return "debian" }, manager: func() (string, error) { return "systemd", nil }}
	f.runtime = r
	sc.a.subscriptionHTTPS = r
	r.installed = func() bool { return f.installed }
	r.running = func() bool { return f.running.Load() }
	r.lookup = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("198.51.100.9")}, nil }
	r.addresses = func() Addresses { return Addresses{IPv4: "198.51.100.9"} }
	r.listeners = func(int) ([]httpsListener, error) { return nil, nil }
	r.active = func() ([]byte, error) {
		client := &http.Client{Timeout: time.Second}
		resp, e := client.Get("http://127.0.0.1:" + itoa(f.adminPort) + "/config/")
		if e != nil {
			return nil, e
		}
		defer resp.Body.Close()
		return io.ReadAll(resp.Body)
	}
	r.run = func(input, name string, args ...string) ([]byte, error) {
		if name == "apt-get" {
			if os.Getenv("ROUT_TEST_CADDY_INSTALL") == "1" {
				if _, e := exec.LookPath("caddy"); e != nil {
					f.actualInstall = true
					b, e := httpsExec(input, name, args...)
					if e == nil && args[0] == "install" {
						f.installed = true
					}
					return b, e
				}
			}
			if args[0] == "install" {
				f.installed = true
				if _, e := exec.LookPath("caddy"); e != nil {
					return nil, errors.New("Caddy missing; run the installation integration in a disposable Debian container")
				}
			}
			return nil, nil
		}
		if name != "systemctl" {
			return httpsExec(input, name, args...)
		}
		switch args[0] {
		case "show":
			if strings.Contains(strings.Join(args, " "), "MainPID") {
				pid := 0
				if f.cmd != nil {
					pid = f.cmd.Process.Pid
				}
				return []byte(itoa(pid)), nil
			}
			return []byte("caddy run --config " + sc.a.httpsMain()), nil
		case "is-enabled":
			if f.enabled {
				return nil, nil
			}
			return nil, errors.New("disabled")
		case "enable":
			f.enabled = true
		case "disable":
			f.enabled = false
		case "start":
			return nil, f.start()
		case "stop":
			return nil, f.stop()
		case "reload":
			return httpsExec("", "caddy", "reload", "--config", sc.a.httpsMain(), "--adapter", "caddyfile", "--address", "127.0.0.1:"+itoa(f.adminPort))
		default:
			return nil, fmt.Errorf("unexpected init command in isolated fixture: %s", args[0])
		}
		return nil, nil
	}
	r.verify = func(base string, port int, token, body string) httpsVerification {
		if f.failVerification {
			return httpsVerification{Error: "injected certificate failure"}
		}
		out := httpsVerification{}
		plainClient := &http.Client{Timeout: time.Second}
		if _, e := probeHTTP(plainClient, "http://127.0.0.1:"+itoa(port), token, body); e != nil {
			return out
		}
		out.LocalService = true
		client, e := f.tlsClient()
		if e != nil {
			return out
		}
		expiry, e := probeHTTP(client, base, token, body)
		if e == nil {
			out.LocalTLS = true
			out.PublicFromHost = true
			out.Expires = expiry
		}
		return out
	}
	main := fmt.Sprintf("{\n admin 127.0.0.1:%d\n http_port %d\n https_port %d\n default_bind 127.0.0.1\n local_certs\n skip_install_trust\n}\nunrelated.rout.test {\n respond \"unrelated site\" 200\n}\n", f.adminPort, f.httpPort, f.tlsPort)
	if e := os.WriteFile(sc.a.httpsMain(), []byte(main), 0644); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := f.stop(); e != nil {
			t.Error(e)
		}
	})
	if !fresh {
		if _, e := exec.LookPath("caddy"); e != nil {
			t.Fatal("real Caddy is required")
		}
		if e := f.start(); e != nil {
			t.Fatal(e)
		}
	}
	return f
}
func (a *App) ServeSubscriptionsWithReady(ctx context.Context, ready func(net.Addr)) error {
	cfg, e := a.subscriptionSettings()
	if e != nil {
		return e
	}
	return a.serveSubscriptions(ctx, net.JoinHostPort("127.0.0.1", itoa(cfg.listenPort())), func(string, ...any) {}, ready)
}
func (f *subscriptionCaddyFixture) start() error {
	if f.running.Load() {
		return nil
	}
	log, e := os.OpenFile(f.logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	cmd := exec.Command("caddy", "run", "--config", f.sc.a.httpsMain(), "--adapter", "caddyfile")
	cmd.Stdout, cmd.Stderr = log, log
	if e = cmd.Start(); e != nil {
		log.Close()
		return e
	}
	f.cmd = cmd
	f.done = make(chan error, 1)
	f.running.Store(true)
	go func() { e := cmd.Wait(); log.Close(); f.running.Store(false); f.done <- e }()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, e = f.runtime.active(); e == nil {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return errors.New("real Caddy did not start; inspect isolated fixture log")
}
func (f *subscriptionCaddyFixture) stop() error {
	if f.cmd == nil {
		return nil
	}
	if f.running.Load() {
		_ = f.cmd.Process.Signal(os.Interrupt)
	}
	select {
	case <-f.done:
		f.cmd = nil
		return nil
	case <-time.After(5 * time.Second):
		_ = f.cmd.Process.Kill()
		<-f.done
		f.cmd = nil
		return errors.New("isolated Caddy required forced shutdown")
	}
}
func (f *subscriptionCaddyFixture) tlsClient() (*http.Client, error) {
	b, e := os.ReadFile(filepath.Join(f.dataDir, "caddy", "pki", "authorities", "local", "root.crt"))
	if e != nil {
		return nil, e
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(b) {
		return nil, errors.New("test CA unavailable")
	}
	tr := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", itoa(f.tlsPort)))
	}}
	return &http.Client{Transport: tr, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}
func (f *subscriptionCaddyFixture) request(t *testing.T, domain, path string) (int, []byte) {
	t.Helper()
	client, e := f.tlsClient()
	if e != nil {
		t.Fatal(e)
	}
	resp, e := client.Get("https://" + domain + path)
	if e != nil {
		t.Fatal("isolated HTTPS request failed (URL withheld)")
	}
	defer resp.Body.Close()
	b, e := io.ReadAll(resp.Body)
	if e != nil {
		t.Fatal(e)
	}
	return resp.StatusCode, b
}

func TestIntegrationSubscriptionCaddyFreshDeployment(t *testing.T) {
	f := newSubscriptionCaddyFixture(t, true)
	a := f.sc.a
	_, token := f.sc.create(t, "Existing Shadowrocket", 2, 0, 1)
	before, _ := os.ReadFile(filepath.Join(a.Home, "state.json"))
	if e := a.DeploySubscriptionHTTPS("sub.rout.test", true); e != nil {
		t.Fatal(e)
	}
	if os.Getenv("ROUT_TEST_CADDY_INSTALL") == "1" && !f.actualInstall {
		t.Fatal("fresh-install CI must start without Caddy and actually install the package")
	}
	t.Logf("Real Caddy fresh deployment; package manager actually executed: %v", f.actualInstall)
	code, body := f.request(t, "sub.rout.test", "/s/"+token)
	if code != 200 {
		t.Fatal(code)
	}
	if yamlCode, yamlBody := f.request(t, "sub.rout.test", "/s/"+token+"?format=mihomo"); yamlCode != 200 || !strings.Contains(string(yamlBody), "proxy-groups:") {
		t.Fatal("Caddy did not forward the Mihomo query")
	}
	decoded := decodeBody(t, string(body))
	if len(decoded) != 3 {
		t.Fatal("subscription format/order lost")
	}
	if code, _ = f.request(t, "sub.rout.test", "/"); code != 404 {
		t.Fatal("root path exposed an unintended endpoint", code)
	}
	if code, _ = f.request(t, "unrelated.rout.test", "/"); code != 200 {
		t.Fatal("unrelated site changed")
	}
	if e := a.DeploySubscriptionHTTPS("sub.rout.test", false); e != nil {
		t.Fatal("repair", e)
	}
	if e := f.stop(); e != nil {
		t.Fatal(e)
	}
	if e := f.start(); e != nil {
		t.Fatal(e)
	}
	code, after := f.request(t, "sub.rout.test", "/s/"+token)
	if code != 200 || string(body) != string(after) {
		t.Fatal("Caddy restart changed an existing subscription")
	}
	// Proxy error handling must not put a token-shaped client URL in Caddy logs.
	// Stop only this fixture's subscription listener by sending the request to an
	// owned repair upstream which is deliberately unavailable, then restore it.
	cfg, _ := a.subscriptionSettings()
	saved, _ := os.ReadFile(a.httpsFile())
	broken := strings.ReplaceAll(string(saved), "127.0.0.1:"+itoa(cfg.listenPort()), "127.0.0.1:1")
	if e := os.WriteFile(a.httpsFile(), []byte(broken), 0644); e != nil {
		t.Fatal(e)
	}
	if _, e := f.runtime.run("", "systemctl", "reload", "caddy"); e != nil {
		t.Fatal(e)
	}
	f.request(t, "sub.rout.test", "/s/"+token)
	os.WriteFile(a.httpsFile(), saved, 0644)
	if _, e := f.runtime.run("", "systemctl", "reload", "caddy"); e != nil {
		t.Fatal(e)
	}
	log, _ := os.ReadFile(f.logPath)
	if strings.Contains(string(log), token) {
		t.Fatal("Caddy error logging exposed an access token")
	}
	if e := a.RemoveSubscriptionHTTPS(); e != nil {
		t.Fatal(e)
	}
	if code, _ = f.request(t, "unrelated.rout.test", "/"); code != 200 {
		t.Fatal("removal damaged another Caddy site")
	}
	assertSubscriptionStorage(t, a, before, token)
}
func TestIntegrationSubscriptionExistingCaddyZeroLoss(t *testing.T) {
	f := newSubscriptionCaddyFixture(t, false)
	a := f.sc.a
	_, token := f.sc.create(t, "Saved client", 2, 0)
	port := func() int { cfg, _ := a.subscriptionSettings(); return cfg.listenPort() }()
	fragment := filepath.Join(f.runtime.root, "external.caddy")
	if e := os.WriteFile(fragment, []byte(fmt.Sprintf("existing.rout.test {\n reverse_proxy 127.0.0.1:%d\n}\n", port)), 0644); e != nil {
		t.Fatal(e)
	}
	main, _ := os.ReadFile(a.httpsMain())
	main = append(main, []byte("import "+fragment+"\n")...)
	os.WriteFile(a.httpsMain(), main, 0644)
	if _, e := f.runtime.run("", "systemctl", "reload", "caddy"); e != nil {
		t.Fatal(e)
	}
	if e := a.SetSubscriptionPublicURL("https://existing.rout.test"); e != nil {
		t.Fatal(e)
	}
	raw, _ := os.ReadFile(filepath.Join(a.Home, "state.json"))
	original, _ := os.ReadFile(fragment)
	if e := a.UseExistingSubscriptionHTTPS("existing.rout.test"); e != nil {
		t.Fatal(e)
	}
	if e := a.RemoveSubscriptionHTTPS(); e == nil {
		t.Fatal("external site became removable")
	}
	code, body := f.request(t, "existing.rout.test", "/s/"+token)
	if code != 200 {
		t.Fatal(code)
	}
	if yamlCode, yamlBody := f.request(t, "existing.rout.test", "/s/"+token+"?format=mihomo"); yamlCode != 200 || !strings.Contains(string(yamlBody), "proxy-groups:") {
		t.Fatal("external Caddy did not preserve the format query")
	}
	if after, _ := os.ReadFile(fragment); string(after) != string(original) {
		t.Fatal("Mihomo request changed external Caddy configuration")
	}
	if e := a.PrepareSubscriptionUpgrade(); e != nil {
		t.Fatal(e)
	}
	if e := a.PrepareSubscriptionUpgrade(); e != nil {
		t.Fatal(e)
	}
	backups, _ := filepath.Glob(filepath.Join(a.Home, "backups", "subscription-upgrade-v*"))
	if len(backups) != 1 {
		t.Fatal("upgrade snapshot is not idempotent")
	}
	if e := a.AdoptSubscriptionHTTPS("existing.rout.test"); e != nil {
		t.Fatal(e)
	}
	if after, _ := os.ReadFile(fragment); string(after) != string(original) {
		t.Fatal("adoption rewrote an existing working site")
	}
	if e := a.DeploySubscriptionHTTPS("existing.rout.test", false); e != nil {
		t.Fatal(e)
	}
	code, after := f.request(t, "existing.rout.test", "/s/"+token)
	if code != 200 || string(after) != string(body) {
		t.Fatal("HTTPS repair changed subscription behavior")
	}
	// A genuine verification failure restores the old active Caddy configuration.
	f.failVerification = true
	f.runtime.verificationWait = 0
	if e := a.DeploySubscriptionHTTPS("replacement.rout.test", false); e == nil {
		t.Fatal("failed verification accepted")
	}
	f.failVerification = false
	code, after = f.request(t, "existing.rout.test", "/s/"+token)
	if code != 200 || string(after) != string(body) {
		t.Fatal("failed replacement broke the original URL")
	}
	assertSubscriptionStorage(t, a, raw, token)
}
