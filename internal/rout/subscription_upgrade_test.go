package rout

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// v0.3.4's schema is deliberately not migrated. Opening the state with a new App
// must keep byte-for-byte storage and previously issued token behavior.
func TestSubscriptionV034ZeroLossRepeatedOpen(t *testing.T) {
	sc := newSubScene(t)
	first, token := sc.create(t, "Existing Shadowrocket", 2, 0, 1)
	disabled, disabledToken := sc.create(t, "Disabled", 1, 0)
	if e := sc.a.SetSubscriptionEnabled(disabled.ID, false); e != nil {
		t.Fatal(e)
	}
	if e := sc.a.SaveSettings(Settings{Language: "en", Subscription: &SubscriptionSettings{Enabled: true, Port: 8787, PublicURL: "https://xhx.oioio.uk"}}); e != nil {
		t.Fatal(e)
	}
	before := sc.state(t)
	rawState, _ := os.ReadFile(filepath.Join(sc.a.Home, "state.json"))
	rawSettings, _ := os.ReadFile(filepath.Join(sc.a.Home, "settings.json"))
	handler, _ := sc.handler()
	response := get(handler, http.MethodGet, "/s/"+token)
	if response.Code != 200 {
		t.Fatal(response.Code)
	}
	body := response.Body.Bytes()
	for i := 0; i < 5; i++ {
		a := &App{Home: sc.a.Home, BinDir: sc.a.BinDir, ServiceMode: "none", Language: "en"}
		after, e := a.Load()
		if e != nil {
			t.Fatal(e)
		}
		cfg, e := a.subscriptionSettings()
		if e != nil {
			t.Fatal(e)
		}
		if !reflect.DeepEqual(before, after) || cfg.listenPort() != 8787 || !cfg.Enabled || cfg.PublicURL != "https://xhx.oioio.uk" {
			t.Fatal("upgrade/restart changed persisted behavior")
		}
		sub, ok := after.matchSubscription(token)
		if !ok || !reflect.DeepEqual(sub, first) {
			t.Fatal("previous token or ordered selection changed")
		}
		h := newSubscriptionHandler(func() (State, error) { return a.Load() }, func(string, ...any) {})
		got := get(h, http.MethodGet, "/s/"+token)
		if got.Code != 200 || !bytes.Equal(body, got.Body.Bytes()) || get(h, http.MethodGet, "/s/"+disabledToken).Code != 404 {
			t.Fatal("client subscription response changed")
		}
		currentState, _ := os.ReadFile(filepath.Join(a.Home, "state.json"))
		currentSettings, _ := os.ReadFile(filepath.Join(a.Home, "settings.json"))
		if !bytes.Equal(rawState, currentState) || !bytes.Equal(rawSettings, currentSettings) {
			t.Fatal("opening v0.3.4 storage rewrote it")
		}
	}
	if bytes.Contains(rawState, []byte(token)) || bytes.Contains(rawSettings, []byte(token)) {
		t.Fatal("plaintext token persisted")
	}
}

func TestSubscriptionPublicURLChangeKeepsIssuedTokenAndNodes(t *testing.T) {
	sc := newSubScene(t)
	_, token := sc.create(t, "Phone", 2, 0)
	before := sc.state(t)
	raw, _ := os.ReadFile(filepath.Join(sc.a.Home, "state.json"))
	for _, base := range []string{"https://xhx.oioio.uk", "https://new.example.com", "https://xhx.oioio.uk"} {
		if e := sc.a.SetSubscriptionPublicURL(base); e != nil {
			t.Fatal(e)
		}
		after := sc.state(t)
		if !reflect.DeepEqual(before, after) {
			t.Fatal("URL update changed subscriptions or node configuration")
		}
		h, _ := sc.handler()
		if get(h, http.MethodGet, "/s/"+token).Code != 200 {
			t.Fatal("URL update revoked old token")
		}
	}
	after, _ := os.ReadFile(filepath.Join(sc.a.Home, "state.json"))
	if !bytes.Equal(raw, after) {
		t.Fatal("URL setting rewrote node/subscription database")
	}
}
