package rout

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProxyTransportSecurityAndLegacyCompatibility(t *testing.T) {
	for _, protocol := range []string{"socks5", "http", "https"} {
		p, err := ParseProxy(protocol, "[2001:db8::1]:443:private-user:private:p@ss%")
		if err != nil {
			t.Fatal(err)
		}
		if err = p.Validate(); err != nil {
			t.Fatal(err)
		}
		cfg := proxyConfig(*p)
		if protocol == "https" {
			tls := cfg["tls"].(M)
			if cfg["type"] != "http" || tls["enabled"] != true || tls["server_name"] != p.Host || tls["insecure"] == true {
				t.Fatal("HTTPS must verify host and certificates")
			}
		} else if _, ok := cfg["tls"]; ok {
			t.Fatal("legacy proxy transport silently changed")
		}
		if (proxySecurityWarning(*p) == "") != (protocol == "https") {
			t.Fatal("unencrypted transport not identified")
		}
		for _, format := range []string{"%v", "%+v", "%#v"} {
			text := fmt.Sprintf(format, *p)
			if strings.Contains(text, p.Username) || strings.Contains(text, p.Password) {
				t.Fatal("proxy formatting disclosed credentials")
			}
		}
	}
}

func TestProxyLogRedaction(t *testing.T) {
	p := Proxy{"https", "proxy.example", 443, "private-user", "secret:@/?%&\""}
	auth := base64.StdEncoding.EncodeToString([]byte(p.Username + ":" + p.Password))
	encoded, _ := json.Marshal(p.Password)
	escaped := string(encoded[1 : len(encoded)-1])
	text := strings.Join([]string{p.Username, p.Password, url.QueryEscape(p.Password), url.PathEscape(p.Password), auth, escaped}, " ")
	got := redactProxySecrets(text, State{Exits: []Exit{{ID: "abcdef012345", Name: "Canada", Proxy: p}}})
	for _, secret := range []string{p.Username, p.Password, url.QueryEscape(p.Password), url.PathEscape(p.Password), auth, escaped} {
		if strings.Contains(got, secret) {
			t.Fatal("log leaked a credential")
		}
	}
}

func TestAIEnableAndApplyRejectPreexistingBrokenReferences(t *testing.T) {
	sc := newAIScene(t)
	if err := sc.a.SetAIExit(sc.exit.ID); err != nil {
		t.Fatal(err)
	}
	if err := sc.a.SetAIBindings([]string{sc.reality.ID}); err != nil {
		t.Fatal(err)
	}
	s, err := sc.a.Load()
	if err != nil {
		t.Fatal(err)
	}
	s.Exits = nil
	raw, err := JSON(s)
	if err != nil {
		t.Fatal(err)
	}
	if err = AtomicWrite(filepath.Join(sc.a.Home, "state.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	for _, operation := range []func() error{func() error { return sc.a.SetAIEnabled(true) }, sc.a.ApplyAI} {
		if err = operation(); err == nil {
			t.Fatal("invalid AI exit accepted because it was already invalid")
		}
		after, err := os.ReadFile(filepath.Join(sc.a.Home, "state.json"))
		if err != nil || string(after) != string(raw) {
			t.Fatal("failed validation changed saved settings", err)
		}
	}
}

func TestAIChangesPreserveQuotaAndBilling(t *testing.T) {
	sc := newAIScene(t)
	a := sc.a
	a.bootID = func() (string, error) { return "ai-test-boot", nil }
	meter := &fakeMeter{values: map[string]MeterSnapshot{}, frozen: map[string]bool{}}
	a.trafficMeter = meter
	if err := AtomicWrite(filepath.Join(a.Home, "traffic.enabled"), []byte("1"), 0600); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := a.TrafficSync(now, false); err != nil {
		t.Fatal(err)
	}
	snap := meter.values[sc.reality.ID]
	snap.Up = 1234
	snap.Down = 5678
	meter.values[sc.reality.ID] = snap
	if err := a.TrafficSync(now, false); err != nil {
		t.Fatal(err)
	}
	policy := TrafficPolicy{LimitBytes: 1000000, BillingDay: 19, Timezone: "America/Toronto"}
	if err := a.ConfigureTraffic(sc.reality.ID, policy, false, now); err != nil {
		t.Fatal(err)
	}
	before, err := a.loadTraffic()
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range []func() error{func() error { return a.SetAIExit(sc.exit.ID) }, func() error { return a.SetAIBindings([]string{sc.reality.ID}) }, func() error { return a.SetAIEnabled(true) }, func() error { return a.SetAIEnabled(false) }} {
		if err = operation(); err != nil {
			t.Fatal(err)
		}
		state, err := a.Load()
		if err != nil {
			t.Fatal(err)
		}
		p, err := Find(state, sc.reality.ID)
		if err != nil {
			t.Fatal(err)
		}
		if p.trafficPolicy() != policy {
			t.Fatal("AI change altered quota/billing policy")
		}
		after, err := a.loadTraffic()
		if err != nil {
			t.Fatal(err)
		}
		b := before.Records[sc.reality.ID]
		r := after.Records[sc.reality.ID]
		if r.RawUp != b.RawUp || r.RawDown != b.RawDown || r.Consumed != b.Consumed || r.Start != b.Start || r.Next != b.Next {
			t.Fatal("AI change reset accounting or billing cycle")
		}
	}
}
