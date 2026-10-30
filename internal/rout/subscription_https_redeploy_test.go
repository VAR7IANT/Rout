package rout

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Regression tests for automatic HTTPS deployment when a public URL was saved by an
// earlier deployment. The production incident: Rout kept https://xhx.oioio.uk, Caddy had
// been removed, nothing listened on TCP 80/443, DNS was correct and the loopback
// subscription service worked. "Deploy / repair HTTPS" refused with
// "existing Caddy site found but its authenticated endpoint is not verified".
//
// These run against the deterministic fixture (no real Caddy, systemd or network). They
// prove the orchestration and its safety rules, not a real VPS.

const staleDomain = "xhx.oioio.uk"

// staleScene is a host that once served staleDomain: the URL is saved, nothing serves it.
func staleScene(t *testing.T) (*subScene, *fakeSubscriptionHTTPS, string) {
	t.Helper()
	sc, f := newFakeSubscriptionHTTPS(t)
	f.verifyByCaddy = true
	_, token := sc.create(t, "Shadowrocket", 2, 0)
	if e := sc.a.SetSubscriptionPublicURL("https://" + staleDomain); e != nil {
		t.Fatal(e)
	}
	return sc, f, token
}

func stateBytes(t *testing.T, a *App) []byte {
	t.Helper()
	b, e := os.ReadFile(filepath.Join(a.Home, "state.json"))
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func called(f *fakeSubscriptionHTTPS, parts ...string) bool {
	for _, call := range f.calls {
		ok := true
		for _, part := range parts {
			ok = ok && strings.Contains(call, part)
		}
		if ok {
			return true
		}
	}
	return false
}

func publicURL(a *App) string {
	cfg, _ := a.subscriptionSettings()
	return cfg.PublicURL
}

// The reproducer: fails before the fix, passes after it.
func TestStaleHTTPSURLWithoutCaddyCanBeRedeployed(t *testing.T) {
	sc, f, token := staleScene(t)
	f.installed, f.running, f.enabled = false, false, false
	before := stateBytes(t, sc.a)

	// "y" confirms the Caddy installation, the only prompt this flow may show.
	u, out := testUI(sc.a, "y\n")
	if e := u.subscriptionHTTPSDeploy(staleDomain); e != nil {
		t.Fatalf("a stale saved URL blocked redeployment: %v\n%s", e, out.String())
	}
	if !f.installed || !f.running {
		t.Fatal("Caddy was not reinstalled and started")
	}
	if publicURL(sc.a) != "https://"+staleDomain {
		t.Fatal("public URL changed:", publicURL(sc.a))
	}
	saved, _ := sc.a.loadHTTPSState()
	if saved.Ownership != "managed" || saved.Domain != staleDomain || saved.LastError != "" {
		t.Fatalf("%+v", saved)
	}
	text := out.String()
	if strings.Contains(text, "authenticated endpoint is not verified") {
		t.Fatal("misleading 'existing site' message shown when no site exists")
	}
	if !strings.Contains(text, "no usable reverse proxy") || !strings.Contains(text, "Caddy is not installed") {
		t.Fatalf("the user is not told what was found and what happens next:\n%s", text)
	}
	assertSubscriptionStorage(t, sc.a, before, token)
}

// A fresh host, no saved URL: nothing to explain, nothing historical to mention.
func TestFreshHTTPSDeploymentWithoutSavedURL(t *testing.T) {
	sc, f := newFakeSubscriptionHTTPS(t)
	f.verifyByCaddy = true
	_, token := sc.create(t, "Phone", 0)
	f.installed, f.running, f.enabled = false, false, false
	before := stateBytes(t, sc.a)
	u, out := testUI(sc.a, "y\n")
	if e := u.subscriptionHTTPSDeploy("sub.example.com"); e != nil {
		t.Fatal(e, out.String())
	}
	if strings.Contains(out.String(), "previously saved") || publicURL(sc.a) != "https://sub.example.com" {
		t.Fatal("fresh deployment mentioned history or lost the URL:", out.String())
	}
	assertSubscriptionStorage(t, sc.a, before, token)
}

// Caddy runs (for other sites) but has no site for the saved domain; HTTPS does not answer.
func TestStaleHTTPSURLWithRunningCaddyWithoutSiteIsAdded(t *testing.T) {
	sc, f, token := staleScene(t)
	other := f.external(t, "other.example.net", true)
	otherBefore, _ := os.ReadFile(other)
	before := stateBytes(t, sc.a)
	u, out := testUI(sc.a, "")
	if e := u.subscriptionHTTPSDeploy(staleDomain); e != nil {
		t.Fatal(e, out.String())
	}
	if !strings.Contains(out.String(), "Caddy is running but has no site for this domain") {
		t.Fatalf("wrong diagnosis:\n%s", out.String())
	}
	otherAfter, _ := os.ReadFile(other)
	if !bytes.Equal(otherBefore, otherAfter) {
		t.Fatal("an unrelated site was modified")
	}
	if !inspectCaddyDomain(f.activeJSON, "other.example.net", 8787).Found || !inspectCaddyDomain(f.activeJSON, staleDomain, 8787).Correct {
		t.Fatal("the unrelated site must stay and the new site must be added")
	}
	if called(f, "apt-get") || called(f, "systemctl stop") {
		t.Fatal("running Caddy was installed over or stopped")
	}
	assertSubscriptionStorage(t, sc.a, before, token)
}

// Caddy is installed but stopped: starting it activates its whole Caddyfile, so it needs
// its own explicit confirmation. Without it nothing changes.
func TestStaleHTTPSURLWithStoppedCaddyNeedsExplicitStart(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled at boot", true: "enabled at boot"}[enabled], func(t *testing.T) {
			sc, f, token := staleScene(t)
			f.running, f.enabled = false, enabled
			main, _ := os.ReadFile(sc.a.httpsMain())
			before := stateBytes(t, sc.a)

			// Library: no consent, no change at all.
			if e := sc.a.DeploySubscriptionHTTPS(staleDomain, true); e == nil || e.Error() != msgConfirmStartCaddy {
				t.Fatalf("a stopped Caddy was started without confirmation: %v", e)
			}
			if f.running || called(f, "systemctl start") || called(f, "apt-get") {
				t.Fatal("service state changed without consent")
			}

			// UI: the default answer to the start prompt is "no".
			u, out := testUI(sc.a, "\n")
			if e := u.subscriptionHTTPSDeploy(staleDomain); e != nil {
				t.Fatal(e)
			}
			if f.running || called(f, "systemctl start") {
				t.Fatalf("declining (default) must not start Caddy:\n%s", out.String())
			}
			afterMain, _ := os.ReadFile(sc.a.httpsMain())
			if !bytes.Equal(main, afterMain) {
				t.Fatal("Caddyfile changed without consent")
			}

			// UI: explicit consent repairs it.
			u, out = testUI(sc.a, "y\n")
			if e := u.subscriptionHTTPSDeploy(staleDomain); e != nil {
				t.Fatal(e, out.String())
			}
			if !f.running || !f.enabled || !strings.Contains(out.String(), "Caddy is installed but not running") {
				t.Fatalf("not repaired or not explained:\n%s", out.String())
			}
			assertSubscriptionStorage(t, sc.a, before, token)
		})
	}
}

// A failed repair must leave a Caddy that was stopped before exactly as it was.
func TestFailedRepairRestoresStoppedCaddy(t *testing.T) {
	for _, wasEnabled := range []bool{false, true} {
		for _, failure := range []string{"caddy validate", "systemctl start", "verify"} {
			name := failure
			if wasEnabled {
				name += " (enabled at boot)"
			}
			t.Run(name, func(t *testing.T) {
				sc, f, token := staleScene(t)
				f.running, f.enabled = false, wasEnabled
				main, _ := os.ReadFile(sc.a.httpsMain())
				before := stateBytes(t, sc.a)
				if failure == "verify" {
					// The service starts but no certificate/response ever arrives.
					f.runtime.verify = func(string, int, string, string) httpsVerification {
						return httpsVerification{LocalService: true}
					}
				} else {
					f.fail = failure
				}
				u, _ := testUI(sc.a, "y\n")
				e := u.subscriptionHTTPSDeploy(staleDomain)
				if e == nil {
					t.Fatal("injected failure ignored")
				}
				if f.running {
					t.Fatal("Caddy left running although it was stopped before and the repair failed")
				}
				if f.enabled != wasEnabled {
					t.Fatalf("boot setting not restored: enabled=%v want %v", f.enabled, wasEnabled)
				}
				restored, _ := os.ReadFile(sc.a.httpsMain())
				if !bytes.Equal(main, restored) {
					t.Fatal("Caddyfile not restored")
				}
				if _, er := os.Stat(sc.a.httpsFile()); !os.IsNotExist(er) {
					t.Fatal("partial fragment left behind")
				}
				if publicURL(sc.a) != "https://"+staleDomain {
					t.Fatal("failed repair changed the saved URL")
				}
				if strings.Contains(e.Error(), "rollback incomplete") {
					t.Fatal("rollback reported incomplete:", e)
				}
				assertSubscriptionStorage(t, sc.a, before, token)
			})
		}
	}
}

// A failure after installing Caddy keeps the package but not a running, enabled service,
// and a saved URL stays as it was.
func TestFailedReinstallRollsBackAndRecordsTheError(t *testing.T) {
	sc, f, token := staleScene(t)
	f.installed, f.running, f.enabled = false, false, false
	main, _ := os.ReadFile(sc.a.httpsMain())
	before := stateBytes(t, sc.a)
	f.fail = "caddy validate"
	u, _ := testUI(sc.a, "y\n")
	if e := u.subscriptionHTTPSDeploy(staleDomain); e == nil {
		t.Fatal("injected failure ignored")
	}
	if !f.installed || f.running || f.enabled {
		t.Fatalf("installed=%v running=%v enabled=%v", f.installed, f.running, f.enabled)
	}
	if after, _ := os.ReadFile(sc.a.httpsMain()); !bytes.Equal(main, after) {
		t.Fatal("Caddyfile not restored")
	}
	saved, _ := sc.a.loadHTTPSState()
	if saved.LastError == "" {
		t.Fatal("the failure was not recorded for diagnostics")
	}
	if publicURL(sc.a) != "https://"+staleDomain {
		t.Fatal("saved URL changed")
	}
	// The next attempt, without the failure, succeeds: the failed one left nothing behind.
	u, out := testUI(sc.a, "y\n")
	if e := u.subscriptionHTTPSDeploy(staleDomain); e != nil {
		t.Fatal(e, out.String())
	}
	assertSubscriptionStorage(t, sc.a, before, token)
}

// Another service owns TCP 443: refuse before asking for any consent, stop nothing.
func TestStaleHTTPSURLWithForeignPortOwnerIsRefusedSafely(t *testing.T) {
	for _, port := range []int{80, 443} {
		sc, f, token := staleScene(t)
		f.installed, f.running, f.enabled = false, false, false
		f.ports = map[int][]httpsListener{port: {{Owner: "nginx", PID: 99}}}
		main, _ := os.ReadFile(sc.a.httpsMain())
		before := stateBytes(t, sc.a)
		// No answers are provided: any consent prompt would hit end of input.
		u, out := testUI(sc.a, "")
		e := u.subscriptionHTTPSDeploy(staleDomain)
		if e == nil || !strings.Contains(e.Error(), "nginx") || !strings.Contains(e.Error(), "will not be stopped") {
			t.Fatalf("port %d: wrong or missing refusal: %v", port, e)
		}
		if strings.Contains(out.String(), "Confirm Caddy installation") {
			t.Fatal("consent was asked for an installation that cannot proceed")
		}
		if f.installed || called(f, "apt-get") || called(f, "systemctl") {
			t.Fatalf("a refused deployment touched the system: %v", f.calls)
		}
		if after, _ := os.ReadFile(sc.a.httpsMain()); !bytes.Equal(main, after) {
			t.Fatal("Caddyfile changed")
		}
		assertSubscriptionStorage(t, sc.a, before, token)
	}
}

// A working HTTPS endpoint that Rout does not manage (another proxy) is kept and reused.
func TestWorkingExternalProxyWithSavedURLIsReusedNotRedeployed(t *testing.T) {
	sc, f, token := staleScene(t)
	f.installed, f.running = false, false
	f.verifyByCaddy = false
	f.verifyOK = true // an nginx on 443 answers the authenticated probe
	f.ports = map[int][]httpsListener{443: {{Owner: "nginx", PID: 99}}}
	before := stateBytes(t, sc.a)
	u, out := testUI(sc.a, "1\n")
	if e := u.subscriptionHTTPSDeploy(staleDomain); e != nil {
		t.Fatal(e, out.String())
	}
	saved, _ := sc.a.loadHTTPSState()
	if saved.Ownership != "external" || saved.Domain != staleDomain {
		t.Fatalf("%+v", saved)
	}
	if f.installed || len(f.calls) != 0 {
		t.Fatalf("an endpoint that already works was modified: %v", f.calls)
	}
	if strings.Contains(out.String(), "no usable reverse proxy") {
		t.Fatal("a working endpoint was described as stale")
	}
	assertSubscriptionStorage(t, sc.a, before, token)
}

// A Rout-independent Caddy site that works is preserved byte for byte.
func TestWorkingExistingCaddySiteWithSavedURLIsPreserved(t *testing.T) {
	sc, f, token := staleScene(t)
	path := f.external(t, staleDomain, true)
	config, _ := os.ReadFile(path)
	main, _ := os.ReadFile(sc.a.httpsMain())
	before := stateBytes(t, sc.a)
	u, out := testUI(sc.a, "1\n")
	if e := u.subscriptionHTTPSDeploy(staleDomain); e != nil {
		t.Fatal(e, out.String())
	}
	for _, call := range f.calls {
		for _, forbidden := range []string{"apt-get", "reload", "restart", "start", "stop", "enable", "disable"} {
			if strings.Contains(call, forbidden) {
				t.Fatalf("a working site was disturbed: %s", call)
			}
		}
	}
	if a, _ := os.ReadFile(path); !bytes.Equal(a, config) {
		t.Fatal("existing site changed")
	}
	if a, _ := os.ReadFile(sc.a.httpsMain()); !bytes.Equal(a, main) {
		t.Fatal("Caddyfile changed")
	}
	assertSubscriptionStorage(t, sc.a, before, token)
}

// A Caddy site exists for the domain but does not authenticate: never overwrite it, and
// say which layer failed. Each case is a different thing to fix.
func TestExistingCaddySiteThatFailsVerificationIsProtected(t *testing.T) {
	for _, tc := range []struct {
		name string
		v    httpsVerification
		want string
	}{
		{"certificate refused", httpsVerification{LocalService: true, CertificateError: true}, "HTTPS certificate is not valid"},
		{"site answers but is not Rout", httpsVerification{LocalService: true, LocalTLS: true, Answered: true}, "does not forward the authenticated subscription probe"},
		{"works on the server, not publicly", httpsVerification{LocalService: true, LocalTLS: true}, "not through public DNS"},
		{"no answer at all", httpsVerification{LocalService: true}, "authenticated endpoint is not verified"},
		{"local subscription service down", httpsVerification{}, "local subscription service did not answer"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sc, f, token := staleScene(t)
			path := f.external(t, staleDomain, true)
			config, _ := os.ReadFile(path)
			main, _ := os.ReadFile(sc.a.httpsMain())
			before := stateBytes(t, sc.a)
			f.runtime.verify = func(string, int, string, string) httpsVerification { return tc.v }
			u, out := testUI(sc.a, "")
			e := u.subscriptionHTTPSDeploy(staleDomain)
			if e == nil || !strings.Contains(e.Error(), tc.want) {
				t.Fatalf("want an error containing %q, got %v", tc.want, e)
			}
			if strings.Contains(out.String(), "will try to redeploy") {
				t.Fatal("an existing site must not be redeployed over")
			}
			if len(f.calls) != 0 {
				t.Fatalf("a protected site was touched: %v", f.calls)
			}
			if a, _ := os.ReadFile(path); !bytes.Equal(a, config) {
				t.Fatal("site config changed")
			}
			if a, _ := os.ReadFile(sc.a.httpsMain()); !bytes.Equal(a, main) {
				t.Fatal("Caddyfile changed")
			}
			assertSubscriptionStorage(t, sc.a, before, token)
		})
	}
}

// The site is in the Caddyfile but Caddy is stopped: that is neither "absent" nor "working".
func TestSiteInStoppedCaddyfileIsPreservedAndExplained(t *testing.T) {
	sc, f, token := staleScene(t)
	path := f.external(t, staleDomain, true)
	f.running = false
	config, _ := os.ReadFile(path)
	before := stateBytes(t, sc.a)
	u, _ := testUI(sc.a, "")
	e := u.subscriptionHTTPSDeploy(staleDomain)
	if e == nil || e.Error() != msgSiteStopped {
		t.Fatalf("wrong diagnosis: %v", e)
	}
	if called(f, "apt-get") || called(f, "systemctl start") || called(f, "systemctl reload") {
		t.Fatalf("a stopped Caddy with a configured site was modified: %v", f.calls)
	}
	if a, _ := os.ReadFile(path); !bytes.Equal(a, config) {
		t.Fatal("site config changed")
	}
	assertSubscriptionStorage(t, sc.a, before, token)
}

// Rout's own subscription service is down: reinstalling Caddy cannot fix that, so say it
// before installing anything.
func TestDownLocalServiceIsReportedBeforeInstallingAnything(t *testing.T) {
	sc, f, _ := staleScene(t)
	f.installed, f.running, f.enabled = false, false, false
	f.runtime.verify = func(string, int, string, string) httpsVerification { return httpsVerification{} }
	u, _ := testUI(sc.a, "")
	e := u.subscriptionHTTPSDeploy(staleDomain)
	if e == nil || e.Error() != msgLocalServiceDown {
		t.Fatalf("%v", e)
	}
	if f.installed || called(f, "apt-get") {
		t.Fatal("Caddy was installed although the local service was the problem")
	}
}

// Caddy was deployed by Rout and then uninstalled, taking its configuration with it. The
// recorded ownership must not block the repair, and the recorded domains stay reachable.
func TestRoutManagedHTTPSCanBeRebuiltAfterCaddyIsUninstalled(t *testing.T) {
	sc, f := newFakeSubscriptionHTTPS(t)
	f.verifyByCaddy = true
	_, token := sc.create(t, "Shadowrocket", 2, 0)
	for _, domain := range []string{"old.example.com", staleDomain} {
		if e := sc.a.DeploySubscriptionHTTPS(domain, false); e != nil {
			t.Fatal(e)
		}
	}
	saved, _ := sc.a.loadHTTPSState()
	if saved.Ownership != "managed" || len(saved.Domains) != 2 {
		t.Fatalf("%+v", saved)
	}
	before := stateBytes(t, sc.a)

	// apt purge caddy: the executable, the service, the Caddyfile and our fragment are gone.
	if e := os.Remove(sc.a.httpsFile()); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(sc.a.httpsMain(), []byte("# default Caddyfile of a fresh package\n"), 0644); e != nil {
		t.Fatal(e)
	}
	f.installed, f.running, f.enabled = false, false, false
	f.activeJSON = nil

	u, out := testUI(sc.a, "y\n")
	if e := u.subscriptionHTTPSDeploy(staleDomain); e != nil {
		t.Fatalf("recorded ownership blocked the repair: %v\n%s", e, out.String())
	}
	if !strings.Contains(out.String(), "the Rout-managed HTTPS configuration file no longer exists") {
		t.Fatalf("the rebuild was not explained:\n%s", out.String())
	}
	saved, _ = sc.a.loadHTTPSState()
	if saved.Ownership != "managed" || len(saved.Domains) != 2 || !contains(saved.Domains, "old.example.com") {
		t.Fatalf("recorded domains were lost: %+v", saved)
	}
	for _, domain := range []string{"old.example.com", staleDomain} {
		if r := inspectCaddyDomain(f.activeJSON, domain, 8787); !r.Found || !r.Correct {
			t.Fatalf("%s is not served again", domain)
		}
	}
	main, _ := os.ReadFile(sc.a.httpsMain())
	if strings.Count(string(main), sc.a.httpsImport()) != 1 {
		t.Fatal("import line missing or duplicated")
	}
	assertSubscriptionStorage(t, sc.a, before, token)
}

// An edited fragment is not a vanished one: it stays protected.
func TestEditedRoutFragmentIsNotMistakenForAMissingOne(t *testing.T) {
	sc, f := newFakeSubscriptionHTTPS(t)
	f.verifyByCaddy = true
	if e := sc.a.DeploySubscriptionHTTPS(staleDomain, false); e != nil {
		t.Fatal(e)
	}
	saved, _ := sc.a.loadHTTPSState()
	if e := os.WriteFile(sc.a.httpsFile(), []byte("# edited by the administrator\n"), 0644); e != nil {
		t.Fatal(e)
	}
	if sc.a.ownedFragmentMissing(saved) {
		t.Fatal("an edited fragment was treated as missing")
	}
	if e := sc.a.DeploySubscriptionHTTPS(staleDomain, false); e == nil {
		t.Fatal("an edited fragment was overwritten")
	}
	if b, _ := os.ReadFile(sc.a.httpsFile()); string(b) != "# edited by the administrator\n" {
		t.Fatal("the edit was lost")
	}
}

// Running the repair again changes nothing.
func TestRepeatedRepairIsIdempotent(t *testing.T) {
	sc, f, token := staleScene(t)
	f.installed, f.running, f.enabled = false, false, false
	before := stateBytes(t, sc.a)
	u, out := testUI(sc.a, "y\n")
	if e := u.subscriptionHTTPSDeploy(staleDomain); e != nil {
		t.Fatal(e, out.String())
	}
	fragment, _ := os.ReadFile(sc.a.httpsFile())
	main, _ := os.ReadFile(sc.a.httpsMain())
	calls := len(f.calls)
	for i := 0; i < 3; i++ {
		u, out = testUI(sc.a, "") // no prompt may appear
		if e := u.subscriptionHTTPSDeploy(staleDomain); e != nil {
			t.Fatalf("repeat %d: %v\n%s", i, e, out.String())
		}
	}
	if a, _ := os.ReadFile(sc.a.httpsFile()); !bytes.Equal(a, fragment) {
		t.Fatal("fragment changed on repeat")
	}
	if a, _ := os.ReadFile(sc.a.httpsMain()); !bytes.Equal(a, main) || strings.Count(string(a), sc.a.httpsImport()) != 1 {
		t.Fatal("Caddyfile changed or import duplicated")
	}
	for _, call := range f.calls[calls:] {
		if strings.Contains(call, "apt-get") || strings.Contains(call, "reload") || strings.Contains(call, "restart") || strings.Contains(call, "start") {
			t.Fatalf("an already working deployment was restarted: %s", call)
		}
	}
	assertSubscriptionStorage(t, sc.a, before, token)
}

// The precheck itself never changes anything and never leaves its capability behind.
func TestPrecheckClassifiesTheFiveSituations(t *testing.T) {
	type want struct {
		state httpsSiteState
		stale bool
		note  string
	}
	cases := []struct {
		name  string
		setup func(*testing.T, *App, *fakeSubscriptionHTTPS)
		want  want
	}{
		{"fresh host, no URL", func(t *testing.T, a *App, f *fakeSubscriptionHTTPS) {
			if e := a.SetSubscriptionPublicURL(""); e != nil {
				t.Fatal(e)
			}
		}, want{httpsSiteNone, false, ""}},
		{"URL saved for another domain", func(t *testing.T, a *App, f *fakeSubscriptionHTTPS) {
			if e := a.SetSubscriptionPublicURL("https://other.example.org"); e != nil {
				t.Fatal(e)
			}
		}, want{httpsSiteNone, false, ""}},
		{"stale URL, Caddy not installed", func(t *testing.T, a *App, f *fakeSubscriptionHTTPS) {
			f.installed, f.running = false, false
		}, want{httpsSiteNone, true, msgHTTPSNoCaddy}},
		{"stale URL, Caddy stopped", func(t *testing.T, a *App, f *fakeSubscriptionHTTPS) {
			f.running = false
		}, want{httpsSiteNone, true, msgHTTPSCaddyStopped}},
		{"stale URL, Caddy running without the site", func(t *testing.T, a *App, f *fakeSubscriptionHTTPS) {}, want{httpsSiteNone, true, msgHTTPSCaddyNoSite}},
		{"working site", func(t *testing.T, a *App, f *fakeSubscriptionHTTPS) {
			f.external(t, staleDomain, true)
		}, want{httpsSiteWorking, false, ""}},
		{"site present but failing", func(t *testing.T, a *App, f *fakeSubscriptionHTTPS) {
			f.external(t, staleDomain, true)
			f.runtime.verify = func(string, int, string, string) httpsVerification {
				return httpsVerification{LocalService: true}
			}
		}, want{httpsSiteBroken, false, ""}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sc, f, token := staleScene(t)
			tc.setup(t, sc.a, f)
			before := stateBytes(t, sc.a)
			got, e := sc.a.precheckSubscriptionHTTPS(staleDomain)
			if e != nil {
				t.Fatal(e)
			}
			if got.State != tc.want.state || got.Stale != tc.want.stale || got.Absence != tc.want.note {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
			if _, er := os.Stat(sc.a.subscriptionProbeFile()); !os.IsNotExist(er) {
				t.Fatal("the verification capability was left behind")
			}
			assertSubscriptionStorage(t, sc.a, before, token)
		})
	}
}

// Both languages: the explanation is localized and never claims a site exists.
func TestStaleHTTPSMessagesAreBilingual(t *testing.T) {
	for _, lang := range []string{"en", "zh-CN"} {
		sc, f, _ := staleScene(t)
		sc.a.Language = lang
		f.installed, f.running, f.enabled = false, false, false
		u, out := testUI(sc.a, "y\n")
		if e := u.subscriptionHTTPSDeploy(staleDomain); e != nil {
			t.Fatal(lang, e)
		}
		text := out.String()
		if hasHan(text) != (lang != "en") {
			t.Fatalf("%s output has the wrong language:\n%s", lang, text)
		}
		if lang == "zh-CN" && (!strings.Contains(text, "历史 HTTPS 域名设置") || !strings.Contains(text, "未安装 Caddy") || strings.Contains(text, "已有 Caddy 站点")) {
			t.Fatalf("Chinese explanation missing or misleading:\n%s", text)
		}
	}
	for _, lang := range []string{"en", "zh-CN"} {
		sc, f, _ := staleScene(t)
		sc.a.Language = lang
		f.external(t, staleDomain, true)
		f.runtime.verify = func(string, int, string, string) httpsVerification {
			return httpsVerification{LocalService: true, LocalTLS: true, Answered: true}
		}
		u, _ := testUI(sc.a, "")
		e := u.subscriptionHTTPSDeploy(staleDomain)
		if e == nil {
			t.Fatal("expected a protected-site error")
		}
		if shown := sc.a.subscriptionText(e.Error()); hasHan(shown) != (lang != "en") {
			t.Fatalf("%s: error shown in the wrong language: %s", lang, shown)
		}
	}
}

// The verification helpers tell a refused certificate from a wrong answer.
func TestHTTPSVerificationFailureClassification(t *testing.T) {
	for _, tc := range []struct {
		v          httpsVerification
		site, depl string
	}{
		{httpsVerification{}, msgLocalServiceDown, msgLocalServiceDown},
		{httpsVerification{LocalService: true, CertificateError: true}, msgSiteCertificate, msgDeployCertificate},
		{httpsVerification{LocalService: true, Answered: true}, msgSiteAuthentication, msgDeployAuthentication},
		{httpsVerification{LocalService: true, LocalTLS: true}, msgSitePublicPath, msgDeployPublicPath},
		{httpsVerification{LocalService: true}, msgSiteUnverified, msgDeployNoResponse},
	} {
		if got := siteFailure(tc.v); got != tc.site {
			t.Fatalf("%+v: site failure %q", tc.v, got)
		}
		if got := deployFailure(tc.v); got != tc.depl {
			t.Fatalf("%+v: deploy failure %q", tc.v, got)
		}
	}
	for _, m := range []string{msgHTTPSNoCaddy, msgHTTPSCaddyStopped, msgHTTPSCaddyNoSite, msgHTTPSCaddyUninspectable, msgHTTPSNoEndpoint, msgHTTPSOwnedMissing, msgSiteStopped, msgSiteCertificate, msgSiteAuthentication, msgSitePublicPath, msgSiteUnverified, msgLocalServiceDown, msgDeployCertificate, msgDeployAuthentication, msgDeployPublicPath, msgDeployNoResponse, msgConfirmStartCaddy} {
		found := false
		for _, english := range messages {
			found = found || english == m
		}
		if !found {
			t.Fatalf("diagnostic has no Chinese catalog entry: %q", m)
		}
	}
}

// A deployment that fails its final verification says which layer failed, then rolls back.
func TestDeploymentFailureNamesTheFailingLayer(t *testing.T) {
	for _, tc := range []struct {
		name string
		v    httpsVerification
		want string
	}{
		{"certificate", httpsVerification{LocalService: true, CertificateError: true}, "certificate is not valid for this domain yet"},
		{"authentication", httpsVerification{LocalService: true, LocalTLS: true, Answered: true}, "did not reach Rout"},
		{"public path", httpsVerification{LocalService: true, LocalTLS: true}, "not through public DNS"},
		{"no response", httpsVerification{LocalService: true}, "inbound TCP 80/443"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sc, f := newFakeSubscriptionHTTPS(t)
			_, token := sc.create(t, "Phone", 0)
			before := stateBytes(t, sc.a)
			main, _ := os.ReadFile(sc.a.httpsMain())
			f.runtime.verify = func(string, int, string, string) httpsVerification { return tc.v }
			e := sc.a.DeploySubscriptionHTTPS("sub.example.com", false)
			if e == nil || !strings.Contains(e.Error(), tc.want) || !strings.Contains(e.Error(), "previous configuration restored and verified") {
				t.Fatalf("want %q with a verified rollback, got %v", tc.want, e)
			}
			if after, _ := os.ReadFile(sc.a.httpsMain()); !bytes.Equal(main, after) {
				t.Fatal("Caddyfile not restored")
			}
			assertSubscriptionStorage(t, sc.a, before, token)
		})
	}
}

// Caddy is reinstalled with a pristine Caddyfile while Rout's own fragment survived: the
// import line that pulls the fragment in is gone, so rewriting the fragment alone would
// "succeed" without serving anything.
func TestRoutFragmentSurvivesButItsImportIsGone(t *testing.T) {
	sc, f := newFakeSubscriptionHTTPS(t)
	f.verifyByCaddy = true
	_, token := sc.create(t, "Shadowrocket", 2, 0)
	if e := sc.a.DeploySubscriptionHTTPS(staleDomain, false); e != nil {
		t.Fatal(e)
	}
	fragment, _ := os.ReadFile(sc.a.httpsFile())
	before := stateBytes(t, sc.a)
	if e := os.WriteFile(sc.a.httpsMain(), []byte("# default Caddyfile of a fresh package\n"), 0644); e != nil {
		t.Fatal(e)
	}
	f.installed, f.running, f.enabled = false, false, false
	f.activeJSON = nil

	u, out := testUI(sc.a, "y\n")
	if e := u.subscriptionHTTPSDeploy(staleDomain); e != nil {
		t.Fatalf("%v\n%s", e, out.String())
	}
	main, _ := os.ReadFile(sc.a.httpsMain())
	if strings.Count(string(main), sc.a.httpsImport()) != 1 {
		t.Fatal("the import line was not restored")
	}
	if r := inspectCaddyDomain(f.activeJSON, staleDomain, 8787); !r.Found || !r.Correct {
		t.Fatal("the site is not served")
	}
	if after, _ := os.ReadFile(sc.a.httpsFile()); !bytes.Equal(after, fragment) {
		t.Fatal("the intact fragment was rewritten differently")
	}
	assertSubscriptionStorage(t, sc.a, before, token)
}

// Running but not inspectable is not the same as "has no site": the deployment refuses
// (it cannot prove what it would change), and the user is told why.
func TestRunningCaddyWithoutAdminAPIIsReportedAsUninspectable(t *testing.T) {
	sc, f, token := staleScene(t)
	f.runtime.active = func() ([]byte, error) { return nil, errors.New("Caddy's loopback admin configuration is unavailable") }
	main, _ := os.ReadFile(sc.a.httpsMain())
	before := stateBytes(t, sc.a)
	check, e := sc.a.precheckSubscriptionHTTPS(staleDomain)
	if e != nil || !check.Stale || check.Absence != msgHTTPSCaddyUninspectable {
		t.Fatalf("%+v %v", check, e)
	}
	u, _ := testUI(sc.a, "")
	if e = u.subscriptionHTTPSDeploy(staleDomain); e == nil {
		t.Fatal("a Caddy that cannot be inspected was reconfigured")
	}
	if after, _ := os.ReadFile(sc.a.httpsMain()); !bytes.Equal(main, after) || called(f, "reload") || called(f, "apt-get") {
		t.Fatalf("an uninspectable Caddy was touched: %v", f.calls)
	}
	assertSubscriptionStorage(t, sc.a, before, token)
}
