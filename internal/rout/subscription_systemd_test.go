package rout

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// A v0.3.4 release or pinned v0.3.5 source-built helper is started by real systemd.
// The v0.3.5 tag has no published binary assets. The new manager then
// refreshes only that helper, without recreating the database or touching Caddy.
// This test is opt-in on a disposable root/systemd runner, never a production VPS.
func TestIntegrationSubscriptionV034SystemdUpgrade(t *testing.T) {
	if os.Getenv("ROUT_TEST_SUBSCRIPTION_SYSTEMD") != "1" {
		t.Skip("disposable root/systemd host required")
	}
	manager, previous := os.Getenv("ROUT_TEST_MANAGER"), os.Getenv("ROUT_TEST_PREVIOUS_SUBSCRIPTION_MANAGER")
	if manager == "" || previous == "" {
		t.Fatal("new manager and checksum-verified previous manager required")
	}
	previousVersion := os.Getenv("ROUT_TEST_PREVIOUS_SUBSCRIPTION_VERSION")
	if previousVersion == "" {
		previousVersion = "0.3.4"
	}
	if out, er := runOutput(5*time.Second, previous, "version"); er != nil || strings.TrimSpace(string(out)) != "rout "+previousVersion {
		t.Fatal("previous subscription helper version mismatch")
	}
	t.Log("Previous helper upgrade from v" + previousVersion)
	if os.Geteuid() != 0 {
		t.Fatal("root required")
	}
	root, e := os.MkdirTemp("/var/lib", "rout-subscription-upgrade-")
	if e != nil {
		t.Fatal(e)
	}
	a := &App{Home: filepath.Join(root, "config"), BinDir: filepath.Join(root, "bin"), ServiceMode: "auto", Language: "en"}
	port, _ := freePort()
	state, token := subscriptionV034SystemdFixture(t)
	data, _ := JSON(state)
	if e = AtomicWrite(filepath.Join(a.Home, "state.json"), data, 0600); e != nil {
		t.Fatal(e)
	}
	if e = a.SaveSettings(Settings{Language: "en", Subscription: &SubscriptionSettings{Enabled: true, Port: port, PublicURL: "https://xhx.oioio.uk"}}); e != nil {
		t.Fatal(e)
	}
	// No Caddy command is authorized by helper refresh. Keep a representative manual
	// configuration as evidence alongside the real HTTPS preservation fixture.
	manual := filepath.Join(root, "manual-Caddyfile")
	caddy := []byte(fmt.Sprintf("xhx.oioio.uk { reverse_proxy 127.0.0.1:%d }\n", port))
	os.WriteFile(manual, caddy, 0644)
	a.subscriptionHTTPS = &subscriptionHTTPSRuntime{run: func(string, string, ...string) ([]byte, error) {
		t.Error("upgrade attempted Caddy management")
		return nil, fmt.Errorf("Caddy must not be changed")
	}}
	if e = os.MkdirAll(a.BinDir, 0755); e != nil {
		t.Fatal(e)
	}
	if e = copyFileAtomic(previous, a.subscriptionHelper(), 0755); e != nil {
		t.Fatal(e)
	}
	if e = AtomicWrite(a.subscriptionUnitPath("systemd"), []byte(a.subscriptionUnit()), 0644); e != nil {
		t.Fatal(e)
	}
	name := a.subscriptionService() + ".service"
	t.Cleanup(func() {
		_ = command("systemctl", "disable", "--now", name)
		_ = os.Remove(a.subscriptionUnitPath("systemd"))
		_ = command("systemctl", "daemon-reload")
		_ = os.RemoveAll(root)
	})
	if e = command("systemctl", "daemon-reload"); e != nil {
		t.Fatal(e)
	}
	if e = command("systemctl", "enable", "--now", name); e != nil {
		t.Fatal(e)
	}
	fetch := func() []byte {
		deadline := time.Now().Add(6 * time.Second)
		for time.Now().Before(deadline) {
			response, er := http.Get("http://127.0.0.1:" + itoa(port) + "/s/" + token)
			if er == nil {
				body, _ := io.ReadAll(response.Body)
				response.Body.Close()
				if response.StatusCode == 200 {
					return body
				}
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatal("previous subscription token did not authenticate (URL withheld)")
		return nil
	}
	baseline, e := a.Load()
	if e != nil {
		t.Fatal(e)
	}
	beforeBody := fetch()
	beforeState, _ := os.ReadFile(filepath.Join(a.Home, "state.json"))
	beforeSettings, _ := os.ReadFile(filepath.Join(a.Home, "settings.json"))
	for i := 0; i < 2; i++ {
		if out, er := runOutput(45*time.Second, manager, "--home", a.Home, "--bin-dir", a.BinDir, "subscription", "refresh"); er != nil {
			t.Fatalf("helper upgrade failed: %v %s", er, sanitizeSubscriptionLogs(out))
		}
		if body := fetch(); !bytes.Equal(beforeBody, body) {
			t.Fatal("upgrade changed the selected node output or ordering")
		}
		mihomoResponse, er := http.Get("http://127.0.0.1:" + itoa(port) + "/s/" + token + "?format=mihomo")
		if er != nil {
			t.Fatal("Mihomo response unavailable (URL withheld)")
		}
		mihomoBody, _ := io.ReadAll(mihomoResponse.Body)
		mihomoResponse.Body.Close()
		if mihomoResponse.StatusCode != 200 || mihomoResponse.Header.Get("Content-Type") != "application/yaml; charset=utf-8" || !strings.Contains(string(mihomoBody), "proxy-groups:") {
			t.Fatal("original token did not authenticate the new format")
		}
		current, _ := a.Load()
		if !reflect.DeepEqual(baseline, current) {
			t.Fatal("upgrade changed IDs, hashes, Reality, AI bindings, traffic policy or relay")
		}
		raw, _ := os.ReadFile(filepath.Join(a.Home, "state.json"))
		settings, _ := os.ReadFile(filepath.Join(a.Home, "settings.json"))
		if !bytes.Equal(beforeState, raw) || !bytes.Equal(beforeSettings, settings) {
			t.Fatal("upgrade rewrote persistent subscription settings")
		}
	}
	if out, er := runOutput(5*time.Second, a.subscriptionHelper(), "version"); er != nil || strings.TrimSpace(string(out)) != "rout "+Version {
		t.Fatal("helper version mismatch")
	}
	// Restart persistence and explicit startup state survive another refresh.
	if out, er := runOutput(45*time.Second, manager, "--home", a.Home, "--bin-dir", a.BinDir, "subscription", "restart"); er != nil {
		t.Fatalf("restart new helper: %v %s", er, out)
	}
	if !bytes.Equal(beforeBody, fetch()) {
		t.Fatal("restart changed the original subscription")
	}
	if e = a.SubscriptionStartup(false); e != nil {
		t.Fatal(e)
	}
	if out, er := runOutput(45*time.Second, manager, "--home", a.Home, "--bin-dir", a.BinDir, "subscription", "refresh"); er != nil {
		t.Fatalf("refresh disabled-startup service: %v %s", er, out)
	}
	if a.subscriptionStartupEnabled("systemd") {
		t.Fatal("upgrade changed explicit disabled startup state")
	}
	if e = a.StopSubscriptionServer(); e != nil {
		t.Fatal(e)
	}
	if out, er := runOutput(45*time.Second, manager, "--home", a.Home, "--bin-dir", a.BinDir, "subscription", "refresh"); er != nil {
		t.Fatalf("refresh stopped service: %v %s", er, out)
	}
	if serviceActive("systemd", a.subscriptionService()) {
		t.Fatal("upgrade started an explicitly stopped service")
	}
	if after, _ := os.ReadFile(manual); !bytes.Equal(caddy, after) {
		t.Fatal("upgrade changed the manual Caddy configuration")
	}
}

// Validate the populated upgrade fixture even on hosts without systemd.
func subscriptionV034SystemdFixture(t *testing.T) (State, string) {
	t.Helper()
	node := fixture(t, "vless")
	node.Name = "Existing Reality"
	node.Traffic = &TrafficPolicy{LimitBytes: 12345678, BillingDay: 7, Timezone: "UTC"}
	other := fixture(t, "ss")
	other.Name = "Existing SS"
	other.Port, other.PublicPort = 24682, 34682
	relayPort := 24683
	relay := Profile{ID: RandomHex(6), Name: "Existing relay", Kind: "relay", Enabled: true, Protocol: "tcp", Listen: "127.0.0.1", Port: relayPort, PublicHost: "198.51.100.1", PublicPort: relayPort, Target: "198.51.100.2:443", RelayMode: relayRemote}
	ex := Exit{ID: RandomHex(6), Name: "Existing AI exit", Proxy: Proxy{Protocol: "socks5", Host: "198.51.100.3", Port: 1080, Username: "fixture-user", Password: "fixture-password"}}
	token, hash, e := newSubscriptionToken()
	if e != nil {
		t.Fatal(e)
	}
	sub := Subscription{ID: RandomHex(6), Name: "Existing Shadowrocket", NodeIDs: []string{other.ID, node.ID}, TokenHash: hash, Enabled: true, CreatedAt: time.Now().UTC()}
	state := State{Schema: 2, Profiles: []Profile{node, other, relay}, Exits: []Exit{ex}, AI: &AIRouting{Enabled: true, AIOutboundID: ex.ID, BoundInboundIDs: []string{node.ID}, RuleSetVersion: AIRuleSetCurrent}, Subscriptions: []Subscription{sub}}
	if e = state.Validate(); e != nil {
		t.Fatal(e)
	}
	return state, token
}
func TestSubscriptionV034SystemdFixture(t *testing.T) {
	state, token := subscriptionV034SystemdFixture(t)
	sub, ok := state.matchSubscription(token)
	if !ok || len(sub.NodeIDs) != 2 || len(state.exportSubscription(sub).URIs) != 2 {
		t.Fatal("invalid upgrade baseline")
	}
}
