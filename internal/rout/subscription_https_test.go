package rout

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Deterministic orchestration fixture. Caddy syntax, real TLS, reloads and
// subscription responses are additionally tested with the real executable.
type fakeSubscriptionHTTPS struct {
	a                           *App
	runtime                     *subscriptionHTTPSRuntime
	installed, running, enabled bool
	activeJSON                  []byte
	calls                       []string
	fail                        string
	verifyOK                    bool
	ports                       map[int][]httpsListener
}

func newFakeSubscriptionHTTPS(t *testing.T) (*subScene, *fakeSubscriptionHTTPS) {
	t.Helper()
	sc := newSubScene(t)
	if e := sc.a.SaveSettings(Settings{Language: "en", Subscription: &SubscriptionSettings{Enabled: true, Port: 8787}}); e != nil {
		t.Fatal(e)
	}
	f := &fakeSubscriptionHTTPS{a: sc.a, installed: true, running: true, enabled: true, verifyOK: true, ports: map[int][]httpsListener{}}
	r := &subscriptionHTTPSRuntime{root: t.TempDir(), verificationWait: 0}
	r.installed = func() bool { return f.installed }
	r.running = func() bool { return f.running }
	r.osID = func() string { return "debian" }
	r.manager = func() (string, error) { return "systemd", nil }
	r.run = func(input, name string, args ...string) ([]byte, error) {
		call := name + " " + strings.Join(args, " ")
		f.calls = append(f.calls, call)
		if f.fail != "" && strings.Contains(call, f.fail) {
			f.fail = ""
			return nil, errors.New("injected failure")
		}
		switch name {
		case "apt-get":
			if len(args) > 0 && args[0] == "install" {
				f.installed = true
			}
			return nil, nil
		case "caddy":
			if args[0] == "version" {
				return []byte("2.6.2"), nil
			}
			if args[0] == "adapt" {
				return f.adapt(args[2]), nil
			}
			return nil, nil
		case "systemctl":
			switch args[0] {
			case "show":
				if strings.Contains(call, "MainPID") {
					return []byte("4242\n"), nil
				}
				return []byte("/usr/bin/caddy run --config " + f.a.httpsMain()), nil
			case "is-enabled":
				if f.enabled {
					return nil, nil
				}
				return nil, errors.New("disabled")
			case "enable":
				f.enabled = true
			case "disable":
				f.enabled = false
			case "start", "reload":
				f.running = true
				f.activeJSON = f.adapt(f.a.httpsMain())
			case "stop":
				f.running = false
			}
		}
		return nil, nil
	}
	r.lookup = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("198.51.100.9")}, nil }
	r.addresses = func() Addresses { return Addresses{IPv4: "198.51.100.9"} }
	r.listeners = func(port int) ([]httpsListener, error) { return f.ports[port], nil }
	r.active = func() ([]byte, error) { return append([]byte(nil), f.activeJSON...), nil }
	r.verify = func(base string, port int, token, body string) httpsVerification {
		if !tokenPattern.MatchString(token) || body == "" {
			t.Fatal("verification weakened token requirements")
		}
		// The diagnostic capability is hash-only and grants no real node access.
		raw, _ := os.ReadFile(f.a.subscriptionProbeFile())
		if bytes.Contains(raw, []byte(token)) {
			t.Fatal("probe persisted plaintext")
		}
		return httpsVerification{LocalService: f.verifyOK, LocalTLS: f.verifyOK, PublicFromHost: f.verifyOK, Expires: time.Now().Add(30 * 24 * time.Hour)}
	}
	f.runtime = r
	sc.a.subscriptionHTTPS = r
	if e := os.WriteFile(sc.a.httpsMain(), []byte("# existing root configuration\n"), 0644); e != nil {
		t.Fatal(e)
	}
	f.activeJSON = f.adapt(sc.a.httpsMain())
	return sc, f
}
func (f *fakeSubscriptionHTTPS) adapt(path string) []byte {
	var routes []any
	var read func(string)
	read = func(path string) {
		b, _ := os.ReadFile(path)
		for _, line := range strings.Split(string(b), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 2 && fields[0] == "import" {
				pattern := fields[1]
				if !filepath.IsAbs(pattern) {
					pattern = filepath.Join(filepath.Dir(path), pattern)
				}
				files, _ := filepath.Glob(pattern)
				for _, file := range files {
					read(file)
				}
			}
		}
		hostPattern := regexp.MustCompile(`(?m)^([a-z0-9][a-z0-9., :-]*)\s*\{`)
		portPattern := regexp.MustCompile(`reverse_proxy\s+127\.0\.0\.1:([0-9]+)`)
		upstream := 8787
		if m := portPattern.FindStringSubmatch(string(b)); len(m) > 0 {
			fmt.Sscan(m[1], &upstream)
		}
		for _, m := range hostPattern.FindAllStringSubmatch(string(b), -1) {
			var hosts []any
			for _, host := range strings.Split(strings.TrimSpace(m[1]), ",") {
				hosts = append(hosts, strings.TrimSpace(host))
			}
			routes = append(routes, map[string]any{"match": []any{map[string]any{"host": hosts}}, "handle": []any{map[string]any{"handler": "reverse_proxy", "upstreams": []any{map[string]any{"dial": "127.0.0.1:" + itoa(upstream)}}}}})
		}
	}
	read(path)
	b, _ := json.Marshal(map[string]any{"apps": map[string]any{"http": map[string]any{"servers": map[string]any{"srv0": map[string]any{"listen": []string{":443"}, "routes": routes}}}}})
	return b
}
func (f *fakeSubscriptionHTTPS) external(t *testing.T, domain string, isolated bool) string {
	t.Helper()
	site := []byte(domain + " {\n reverse_proxy 127.0.0.1:8787\n}\n")
	path := f.a.httpsMain()
	if isolated {
		path = filepath.Join(f.runtime.root, "existing.caddy")
		if e := os.WriteFile(f.a.httpsMain(), []byte("# shared Caddyfile\nimport "+path+"\n"), 0644); e != nil {
			t.Fatal(e)
		}
	}
	if e := os.WriteFile(path, site, 0644); e != nil {
		t.Fatal(e)
	}
	f.activeJSON = f.adapt(f.a.httpsMain())
	return path
}
func assertSubscriptionStorage(t *testing.T, a *App, before []byte, token string) {
	t.Helper()
	after, _ := os.ReadFile(filepath.Join(a.Home, "state.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("HTTPS operation rewrote subscription/node/AI/traffic configuration")
	}
	s, e := a.Load()
	if e != nil {
		t.Fatal(e)
	}
	h := newSubscriptionHandler(func() (State, error) { return s, nil }, func(string, ...any) {})
	if get(h, "GET", "/s/"+token).Code != 200 {
		t.Fatal("previously issued subscription token stopped authenticating")
	}
}

func TestSubscriptionHTTPSFreshInstallRepairRemovePreservesState(t *testing.T) {
	sc, f := newFakeSubscriptionHTTPS(t)
	_, token := sc.create(t, "Shadowrocket", 2, 0)
	before, _ := os.ReadFile(filepath.Join(sc.a.Home, "state.json"))
	main, _ := os.ReadFile(sc.a.httpsMain())
	f.installed, f.running, f.enabled = false, false, false
	if e := sc.a.DeploySubscriptionHTTPS("sub.example.com", false); e == nil {
		t.Fatal("installation lacked explicit approval")
	}
	if e := sc.a.DeploySubscriptionHTTPS("sub.example.com", true); e != nil {
		t.Fatal(e)
	}
	cfg, _ := sc.a.subscriptionSettings()
	if cfg.PublicURL != "https://sub.example.com" || cfg.listenPort() != 8787 {
		t.Fatal(cfg)
	}
	saved, e := sc.a.loadHTTPSState()
	if e != nil || saved.Ownership != "managed" {
		t.Fatal(saved, e)
	}
	updated, _ := os.ReadFile(sc.a.httpsMain())
	if !bytes.HasPrefix(updated, main) {
		t.Fatal("shared Caddyfile replaced")
	}
	for i := 0; i < 2; i++ {
		if e = sc.a.DeploySubscriptionHTTPS("sub.example.com", false); e != nil {
			t.Fatal(e)
		}
	}
	updated, _ = os.ReadFile(sc.a.httpsMain())
	if strings.Count(string(updated), sc.a.httpsImport()) != 1 {
		t.Fatal("duplicate imports")
	}
	if e = sc.a.RemoveSubscriptionHTTPS(); e != nil {
		t.Fatal(e)
	}
	if !f.running {
		t.Fatal("removal stopped shared Caddy")
	}
	cfg, _ = sc.a.subscriptionSettings()
	if cfg.PublicURL != "https://sub.example.com" {
		t.Fatal("removal erased saved URL")
	}
	assertSubscriptionStorage(t, sc.a, before, token)
	if _, e = os.Stat(sc.a.subscriptionProbeFile()); !os.IsNotExist(e) {
		t.Fatal("temporary diagnostic capability leaked")
	}
}

func TestSubscriptionHTTPSExistingExternalDetectionAndAdoption(t *testing.T) {
	for _, isolated := range []bool{false, true} {
		t.Run(fmt.Sprint(isolated), func(t *testing.T) {
			sc, f := newFakeSubscriptionHTTPS(t)
			_, token := sc.create(t, "Existing", 2, 1)
			path := f.external(t, "xhx.oioio.uk", isolated)
			before, _ := os.ReadFile(filepath.Join(sc.a.Home, "state.json"))
			config, _ := os.ReadFile(path)
			main, _ := os.ReadFile(sc.a.httpsMain())
			if e := sc.a.DeploySubscriptionHTTPS("xhx.oioio.uk", false); !errors.Is(e, errSubscriptionExternalHTTPS) {
				t.Fatal("external site was not recognized", e)
			}
			if e := sc.a.UseExistingSubscriptionHTTPS("xhx.oioio.uk"); e != nil {
				t.Fatal(e)
			}
			if e := sc.a.RemoveSubscriptionHTTPS(); e == nil {
				t.Fatal("recognition granted deletion rights")
			}
			if e := sc.a.AdoptSubscriptionHTTPS("xhx.oioio.uk"); (e == nil) != isolated {
				t.Fatal("adoption ignored isolation", e)
			}
			after, _ := os.ReadFile(path)
			afterMain, _ := os.ReadFile(sc.a.httpsMain())
			if !bytes.Equal(config, after) || !bytes.Equal(main, afterMain) {
				t.Fatal("detection/adoption changed proxy bytes")
			}
			for _, call := range f.calls {
				if strings.Contains(call, "apt-get") || strings.Contains(call, "systemctl reload") || strings.Contains(call, "systemctl restart") {
					t.Fatal("existing endpoint was unnecessarily modified", call)
				}
			}
			if isolated {
				if e := sc.a.RemoveSubscriptionHTTPS(); e != nil {
					t.Fatal(e)
				}
			}
			assertSubscriptionStorage(t, sc.a, before, token)
		})
	}
}

func TestSubscriptionHTTPSRollbackAndForeignConfigPreservation(t *testing.T) {
	for _, failure := range []string{"caddy validate", "systemctl reload", "verify"} {
		t.Run(failure, func(t *testing.T) {
			sc, f := newFakeSubscriptionHTTPS(t)
			_, token := sc.create(t, "Phone", 0, 2)
			if e := sc.a.SetSubscriptionPublicURL("https://old.example.com"); e != nil {
				t.Fatal(e)
			}
			before, _ := os.ReadFile(filepath.Join(sc.a.Home, "state.json"))
			main, _ := os.ReadFile(sc.a.httpsMain())
			if failure == "verify" {
				f.verifyOK = false
			} else {
				f.fail = failure
			}
			if e := sc.a.DeploySubscriptionHTTPS("new.example.com", false); e == nil {
				t.Fatal("injected failure ignored")
			}
			restored, _ := os.ReadFile(sc.a.httpsMain())
			if !bytes.Equal(main, restored) {
				t.Fatal("shared configuration not restored")
			}
			cfg, _ := sc.a.subscriptionSettings()
			if cfg.PublicURL != "https://old.example.com" {
				t.Fatal("failed deployment changed URL")
			}
			if _, e := os.Stat(sc.a.httpsFile()); !os.IsNotExist(e) {
				t.Fatal("partial fragment left behind")
			}
			assertSubscriptionStorage(t, sc.a, before, token)
		})
	}
}
func TestSubscriptionHTTPSRejectsInvalidDomainDNSAndPortConflicts(t *testing.T) {
	for _, domain := range []string{"", "localhost", "127.0.0.1", "https://sub.example.com", "sub.example.com/path", "a.example:443", "*.example.com", "x;id.example", "x$(id).example", "foo..example", "-foo.example", "x\n.example", "x.example?token=bad"} {
		if _, e := subscriptionDomain(domain); e == nil {
			t.Fatal("unsafe domain accepted", domain)
		}
	}
	sc, f := newFakeSubscriptionHTTPS(t)
	f.runtime.lookup = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("198.51.100.10")}, nil }
	if e := sc.a.DeploySubscriptionHTTPS("sub.example.com", false); e == nil {
		t.Fatal("DNS mismatch accepted")
	}
	f.runtime.lookup = func(string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("104.16.1.1"), net.ParseIP("2606:4700::1")}, nil
	}
	dns := f.runtime.dns("sub.example.com")
	if dns.Error != "" || !dns.Cloudflare || dns.Matched {
		t.Fatal("CDN misclassified as an origin mismatch", dns)
	}
	for _, port := range []int{80, 443} {
		f.ports = map[int][]httpsListener{port: {{Owner: "nginx", PID: 99}}}
		before := len(f.calls)
		if e := sc.a.DeploySubscriptionHTTPS("sub.example.com", false); e == nil {
			t.Fatal("foreign port owner ignored")
		}
		for _, call := range f.calls[before:] {
			if strings.Contains(call, "stop") || strings.Contains(call, "apt-get") {
				t.Fatal("conflict modified existing service")
			}
		}
	}
	f.ports = map[int][]httpsListener{}
	f.runtime.osID = func() string { return "alpine" }
	if e := sc.a.DeploySubscriptionHTTPS("sub.example.com", true); e == nil {
		t.Fatal("unsupported installer path accepted")
	}
}
func TestSubscriptionHTTPSNewDomainKeepsOldDomainAndToken(t *testing.T) {
	sc, f := newFakeSubscriptionHTTPS(t)
	_, token := sc.create(t, "Phone", 0, 2)
	before, _ := os.ReadFile(filepath.Join(sc.a.Home, "state.json"))
	if e := sc.a.DeploySubscriptionHTTPS("old.example.com", false); e != nil {
		t.Fatal(e)
	}
	if e := sc.a.DeploySubscriptionHTTPS("new.example.com", false); e != nil {
		t.Fatal(e)
	}
	for _, domain := range []string{"old.example.com", "new.example.com"} {
		route := inspectCaddyDomain(f.activeJSON, domain, 8787)
		if !route.Found || !route.Correct {
			t.Fatal("domain replacement removed a working endpoint", domain)
		}
	}
	assertSubscriptionStorage(t, sc.a, before, token)
}
func TestSubscriptionHTTPSRefusesModifiedOwnedFragment(t *testing.T) {
	sc, _ := newFakeSubscriptionHTTPS(t)
	if e := sc.a.DeploySubscriptionHTTPS("sub.example.com", false); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(sc.a.httpsFile(), []byte("# externally modified\n"), 0644); e != nil {
		t.Fatal(e)
	}
	if e := sc.a.RemoveSubscriptionHTTPS(); e == nil {
		t.Fatal("external edits erased")
	}
	if e := sc.a.DeploySubscriptionHTTPS("sub.example.com", false); e == nil {
		t.Fatal("external edits overwritten")
	}
}
func TestSubscriptionProbeAuthenticationExpiryAndNoRealNodes(t *testing.T) {
	sc := newSubScene(t)
	_, existing := sc.create(t, "Phone", 0)
	token, body, cleanup, e := sc.a.beginSubscriptionProbe()
	if e != nil {
		t.Fatal(e)
	}
	defer cleanup()
	cache := &stateCache{a: sc.a}
	h := sc.a.subscriptionHTTPHandler(cache.load, func(string, ...any) {})
	if get(h, "GET", subscriptionProbePath).Code != 404 {
		t.Fatal("unauthenticated probe available")
	}
	req := httptest.NewRequest(http.MethodGet, subscriptionProbePath, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 200 || strings.TrimSpace(w.Body.String()) != body {
		t.Fatal(w.Code, w.Body)
	}
	if get(h, "GET", "/s/"+existing).Code != 200 {
		t.Fatal("probe affected old tokens")
	}
	b, _ := os.ReadFile(sc.a.subscriptionProbeFile())
	var p subscriptionProbe
	json.Unmarshal(b, &p)
	p.Expires = time.Now().Add(-time.Second)
	b, _ = json.Marshal(p)
	os.WriteFile(sc.a.subscriptionProbeFile(), b, 0600)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 404 {
		t.Fatal("expired capability accepted")
	}
}
func TestSubscriptionHTTPSBilingualMenuAndDefaultConfirm(t *testing.T) {
	for _, lang := range []string{"en", "zh-CN"} {
		sc, _ := newFakeSubscriptionHTTPS(t)
		sc.a.Language = lang
		u, out := testUI(sc.a, "0\n")
		if e := u.subscriptionServer(); e != nil {
			t.Fatal(e)
		}
		text := out.String()
		if lang == "en" && hasHan(text) {
			t.Fatal("English settings menu contains untranslated text", text)
		}
		for _, n := range []string{"1", "2", "3", "4", "5", "6", "7", "0"} {
			if !strings.Contains(text, n) {
				t.Fatal("missing stable mobile menu number", n)
			}
		}
	}
	sc, f := newFakeSubscriptionHTTPS(t)
	f.external(t, "xhx.oioio.uk", false)
	u, out := testUI(sc.a, "1\n")
	if e := u.subscriptionHTTPSDeploy("xhx.oioio.uk"); e != nil {
		t.Fatal(e)
	}
	saved, _ := sc.a.loadHTTPSState()
	if saved.Ownership != "external" {
		t.Fatal("use existing transferred ownership")
	}
	if strings.Contains(out.String(), "/s/") {
		t.Fatal("adoption screen leaked a token URL")
	}
	// The existing uppercase/lowercase/default-yes parser is reused unchanged.
	u, _ = testUI(sc.a, "\n")
	if !u.yes("Continue", true) {
		t.Fatal("default confirmation is not yes")
	}
}
func TestSubscriptionHTTPSRoutingAndTrafficFieldsUnchanged(t *testing.T) {
	sc, _ := newFakeSubscriptionHTTPS(t)
	ex := aiTestExit(t, sc.a, "AI exit", "198.51.100.4", 1080)
	state := sc.state(t)
	state.Schema = 2
	state.Profiles[0].Traffic = &TrafficPolicy{LimitBytes: 1000000, BillingDay: 7, Timezone: "UTC"}
	state.AI = &AIRouting{Enabled: true, AIOutboundID: ex.ID, BoundInboundIDs: []string{state.Profiles[0].ID}, RuleSetVersion: AIRuleSetCurrent}
	port, _ := freePort()
	state.Profiles = append(state.Profiles, Profile{ID: RandomHex(6), Name: "NAT relay", Kind: "relay", Enabled: true, Protocol: "tcp", NAT: true, Listen: "127.0.0.1", Port: port, PublicHost: "198.51.100.9", PublicPort: 40001, Target: "198.51.100.5:443", RelayMode: relayRemote})
	if e := state.Validate(); e != nil {
		t.Fatal(e)
	}
	b, _ := JSON(state)
	if e := AtomicWrite(filepath.Join(sc.a.Home, "state.json"), b, 0600); e != nil {
		t.Fatal(e)
	}
	_, token := sc.create(t, "Stable selection", 2, 0)
	before := sc.state(t)
	raw, _ := os.ReadFile(filepath.Join(sc.a.Home, "state.json"))
	record := newTrafficRecord(before.Profiles[0], time.Now(), "existing-boot")
	record.RawUp, record.RawDown, record.Consumed = 100, 200, 300
	if e := sc.a.saveTraffic(TrafficState{Version: 1, Records: map[string]TrafficRecord{before.Profiles[0].ID: record}, Updated: time.Now()}); e != nil {
		t.Fatal(e)
	}
	traffic, _ := os.ReadFile(filepath.Join(sc.a.Home, "traffic.json"))
	configs := map[string][]byte{}
	for _, p := range before.Profiles {
		path := filepath.Join(sc.a.profileDir(p.ID), "config.json")
		configs[path], _ = os.ReadFile(path)
	}
	if e := sc.a.DeploySubscriptionHTTPS("sub.example.com", false); e != nil {
		t.Fatal(e)
	}
	after := sc.state(t)
	if !reflect.DeepEqual(before.Profiles, after.Profiles) || !reflect.DeepEqual(before.Exits, after.Exits) || !reflect.DeepEqual(before.AI, after.AI) || !reflect.DeepEqual(before.Subscriptions, after.Subscriptions) {
		t.Fatal("HTTPS modified Reality/proxy/AI/traffic/relay/subscription state")
	}
	afterTraffic, _ := os.ReadFile(filepath.Join(sc.a.Home, "traffic.json"))
	if !bytes.Equal(traffic, afterTraffic) {
		t.Fatal("traffic counters changed")
	}
	for path, original := range configs {
		now, _ := os.ReadFile(path)
		if !bytes.Equal(original, now) {
			t.Fatal("node config rewritten", path)
		}
	}
	assertSubscriptionStorage(t, sc.a, raw, token)
}

func TestSubscriptionHTTPSRollbackFailureIsExplicit(t *testing.T) {
	sc, f := newFakeSubscriptionHTTPS(t)
	run := f.runtime.run
	f.runtime.run = func(input, name string, args ...string) ([]byte, error) {
		if name == "systemctl" && len(args) > 0 && args[0] == "reload" {
			return nil, errors.New("reload unavailable")
		}
		return run(input, name, args...)
	}
	e := sc.a.DeploySubscriptionHTTPS("sub.example.com", false)
	if e == nil || !strings.Contains(e.Error(), "rollback incomplete") || !strings.Contains(e.Error(), sc.a.httpsMain()) {
		t.Fatal("rollback failure was hidden or claimed complete", e)
	}
}
func TestSubscriptionHTTPSPortChangeUpdatesOnlyOwnedUpstream(t *testing.T) {
	sc, f := newFakeSubscriptionHTTPS(t)
	_, token := sc.create(t, "Phone", 2, 0)
	raw, _ := os.ReadFile(filepath.Join(sc.a.Home, "state.json"))
	if e := sc.a.DeploySubscriptionHTTPS("sub.example.com", false); e != nil {
		t.Fatal(e)
	}
	port, _ := freePort()
	if e := sc.a.EnableSubscriptionServer(port); e != nil {
		t.Fatal(e)
	}
	cfg, _ := sc.a.subscriptionSettings()
	route := inspectCaddyDomain(f.activeJSON, "sub.example.com", port)
	if cfg.listenPort() != port || !route.Correct || route.Conflict {
		t.Fatal("owned upstream did not follow actual configured port", cfg, route)
	}
	f.verifyOK = false
	next, _ := freePort()
	if e := sc.a.EnableSubscriptionServer(next); e == nil {
		t.Fatal("failed port verification accepted")
	}
	cfg, _ = sc.a.subscriptionSettings()
	if cfg.listenPort() != port || !inspectCaddyDomain(f.activeJSON, "sub.example.com", port).Correct {
		t.Fatal("failed port change lost old working state")
	}
	assertSubscriptionStorage(t, sc.a, raw, token)
}
func TestSubscriptionHTTPSExternalPortChangeRefused(t *testing.T) {
	sc, _ := newFakeSubscriptionHTTPS(t)
	if e := sc.a.SetSubscriptionPublicURL("https://xhx.oioio.uk"); e != nil {
		t.Fatal(e)
	}
	before, _ := os.ReadFile(filepath.Join(sc.a.Home, "settings.json"))
	port, _ := freePort()
	if e := sc.a.EnableSubscriptionServer(port); e == nil {
		t.Fatal("external upstream would silently become stale")
	}
	after, _ := os.ReadFile(filepath.Join(sc.a.Home, "settings.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("refused port change rewrote settings")
	}
}
func TestSubscriptionHTTPSDNSFamiliesAndMultipleAddresses(t *testing.T) {
	_, f := newFakeSubscriptionHTTPS(t)
	for _, tc := range []struct {
		name      string
		addresses Addresses
		extra     []net.IP
		records   []string
		valid     bool
	}{
		{"IPv4", Addresses{IPv4: "198.51.100.1"}, nil, []string{"198.51.100.1"}, true},
		{"IPv6", Addresses{IPv6: "2001:db8::1"}, nil, []string{"2001:db8::1"}, true},
		{"dual", Addresses{IPv4: "198.51.100.1", IPv6: "2001:db8::1"}, nil, []string{"198.51.100.1", "2001:db8::1"}, true},
		{"extra address", Addresses{IPv4: "198.51.100.1"}, []net.IP{net.ParseIP("198.51.100.2")}, []string{"198.51.100.1", "198.51.100.2"}, true},
		{"stale AAAA", Addresses{IPv4: "198.51.100.1"}, nil, []string{"198.51.100.1", "2001:db8::9"}, false},
		{"mixed origin", Addresses{IPv4: "198.51.100.1"}, nil, []string{"198.51.100.1", "198.51.100.9"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f.runtime.addresses = func() Addresses { return tc.addresses }
			f.runtime.extraAddresses = func() []net.IP { return tc.extra }
			f.runtime.lookup = func(string) ([]net.IP, error) {
				var ips []net.IP
				for _, s := range tc.records {
					ips = append(ips, net.ParseIP(s))
				}
				return ips, nil
			}
			got := f.runtime.dns("sub.example.com")
			if (got.Error == "") != tc.valid {
				t.Fatal(got)
			}
		})
	}
}
func TestSubscriptionHTTPSConfiguredURLSurvivesMetadataError(t *testing.T) {
	sc, _ := newFakeSubscriptionHTTPS(t)
	if e := sc.a.SetSubscriptionPublicURL("https://old.example.com"); e != nil {
		t.Fatal(e)
	}
	if e := os.Mkdir(sc.a.httpsStatePath(), 0700); e != nil {
		t.Fatal(e)
	}
	if e := sc.a.UseExistingSubscriptionHTTPS("new.example.com"); e == nil {
		t.Fatal("broken metadata ignored")
	}
	cfg, _ := sc.a.subscriptionSettings()
	if cfg.PublicURL != "https://old.example.com" {
		t.Fatal("metadata failure lost the previous URL")
	}
}

func TestSubscriptionHTTPSPackageVerificationFailureRestoresServiceState(t *testing.T) {
	sc, f := newFakeSubscriptionHTTPS(t)
	f.installed, f.running, f.enabled = false, false, false
	original := f.runtime.run
	f.runtime.run = func(input, name string, args ...string) ([]byte, error) {
		b, e := original(input, name, args...)
		if name == "apt-get" && len(args) > 0 && args[0] == "install" {
			// Debian packages can start their service before Rout can verify them.
			f.running, f.enabled = true, true
		}
		if name == "caddy" && args[0] == "version" {
			return nil, errors.New("injected executable verification failure")
		}
		return b, e
	}
	before, _ := os.ReadFile(sc.a.httpsMain())
	if e := sc.a.DeploySubscriptionHTTPS("sub.example.com", true); e == nil {
		t.Fatal("package verification failure ignored")
	}
	if f.running || f.enabled || !f.installed {
		t.Fatal("failed installation did not retain package and restore stopped/disabled state")
	}
	after, _ := os.ReadFile(sc.a.httpsMain())
	if !bytes.Equal(before, after) {
		t.Fatal("failed verification changed Caddy configuration")
	}
}

func TestSubscriptionHTTPSLocalizedDomainError(t *testing.T) {
	for _, lang := range []string{"en", "zh-CN"} {
		sc, _ := newFakeSubscriptionHTTPS(t)
		sc.a.Language = lang
		u, _ := testUI(sc.a, "")
		e := u.subscriptionCommand([]string{"subscription", "https", "deploy", "https://invalid.example/path"})
		if e == nil || hasHan(e.Error()) != (lang != "en") {
			t.Fatalf("wrong error language %s: %v", lang, e)
		}
	}
}

func TestSubscriptionHTTPSRejectsWritableProxyDirectory(t *testing.T) {
	sc, _ := newFakeSubscriptionHTTPS(t)
	if e := os.Chmod(sc.a.httpsRuntime().root, 0777); e != nil {
		t.Fatal(e)
	}
	defer os.Chmod(sc.a.httpsRuntime().root, 0700)
	if e := sc.a.DeploySubscriptionHTTPS("sub.example.com", false); e == nil {
		t.Fatal("unsafe proxy directory accepted")
	}
}

func TestSubscriptionHTTPSRejectsDifferentSystemdConfigPath(t *testing.T) {
	sc, f := newFakeSubscriptionHTTPS(t)
	original := f.runtime.run
	f.runtime.run = func(input, name string, args ...string) ([]byte, error) {
		if name == "systemctl" && args[0] == "show" && strings.Contains(strings.Join(args, " "), "ExecStart") {
			return []byte("/usr/bin/caddy run --config " + sc.a.httpsMain() + "-external"), nil
		}
		return original(input, name, args...)
	}
	if e := sc.a.DeploySubscriptionHTTPS("sub.example.com", false); e == nil {
		t.Fatal("different systemd configuration path accepted")
	}
}
