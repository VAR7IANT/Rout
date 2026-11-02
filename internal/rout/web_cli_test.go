package rout

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func cliWeb(t *testing.T, a *App, input string, args ...string) (string, error) {
	t.Helper()
	u, out := testUI(a, input)
	e := u.webCommand(append([]string{"web"}, args...))
	return out.String(), e
}

func TestWebCLIPassword(t *testing.T) {
	old := webPBKDF2Iterations
	webPBKDF2Iterations = 1000
	defer func() { webPBKDF2Iterations = old }()
	a := testApp(t)
	if _, e := cliWeb(t, a, "short\n", "passwd", "--stdin"); e == nil {
		t.Fatal("a short password was accepted")
	}
	if _, e := cliWeb(t, a, webTestPassword+"\n", "passwd", "--stdin"); e != nil {
		t.Fatal(e)
	}
	cfg, _ := a.LoadWebConfig()
	if !verifyPassword(cfg.PasswordHash, webTestPassword) {
		t.Fatal("password not stored")
	}
	out, e := cliWeb(t, a, "", "passwd", "--generate")
	if e != nil {
		t.Fatal(e)
	}
	var generated string
	for _, line := range strings.Split(out, "\n") {
		if i := strings.LastIndex(line, ": "); i >= 0 && strings.Contains(line, "only once") {
			generated = strings.TrimSpace(line[i+2:])
		}
	}
	cfg, _ = a.LoadWebConfig()
	if generated == "" || !verifyPassword(cfg.PasswordHash, generated) || verifyPassword(cfg.PasswordHash, webTestPassword) {
		t.Fatalf("generated password not usable: %q\n%s", generated, out)
	}
	if _, e := cliWeb(t, a, "", "passwd", "--generate", "--stdin"); e == nil {
		t.Fatal("conflicting flags accepted")
	}
	if _, e := cliWeb(t, a, "", "passwd", "--bogus"); e == nil {
		t.Fatal("unknown flag accepted")
	}
}

func TestWebCLIHostsAndHTTPS(t *testing.T) {
	a := testApp(t)
	if _, e := cliWeb(t, a, "", "host", "add", "Panel.Example.com"); e != nil {
		t.Fatal(e)
	}
	if out, _ := cliWeb(t, a, "", "host", "list"); strings.TrimSpace(out) != "panel.example.com" {
		t.Fatalf("hosts: %q", out)
	}
	if _, e := cliWeb(t, a, "", "host", "add", "bad host"); e == nil {
		t.Fatal("invalid host accepted")
	}
	if _, e := cliWeb(t, a, "", "host", "remove", "panel.example.com"); e != nil {
		t.Fatal(e)
	}
	if cfg, _ := a.LoadWebConfig(); len(cfg.AllowedHosts) != 0 {
		t.Fatalf("host not removed: %v", cfg.AllowedHosts)
	}
	for _, bad := range []string{"203.0.113.5", "[2001:db8::1]", "localhost:8790", "a b"} {
		if _, e := cliWeb(t, a, "", "https", bad); e == nil {
			t.Errorf("%q accepted as an HTTPS domain", bad)
		}
	}
	out, e := cliWeb(t, a, "", "https", "panel.example.com")
	if e != nil {
		t.Fatal(e)
	}
	cfg, _ := a.LoadWebConfig()
	if !cfg.SecureCookie || cfg.HTTPSDomain != "panel.example.com" || !contains(cfg.AllowedHosts, "panel.example.com") {
		t.Fatalf("config after https: %+v", cfg)
	}
	for _, want := range []string{"panel.example.com {", "reverse_proxy 127.0.0.1:8790", "X-Forwarded-Proto"} {
		if !strings.Contains(out, want) {
			t.Errorf("snippet lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "0.0.0.0") {
		t.Error("the snippet exposes a wildcard address")
	}
	// Re-running is idempotent.
	if _, e := cliWeb(t, a, "", "https", "panel.example.com"); e != nil {
		t.Fatal(e)
	}
	if cfg, _ := a.LoadWebConfig(); len(cfg.AllowedHosts) != 1 {
		t.Fatalf("duplicate host: %v", cfg.AllowedHosts)
	}
}

func TestWebCLIStatusAndUnits(t *testing.T) {
	a := testApp(t)
	out, e := cliWeb(t, a, "", "status")
	if e != nil || !strings.Contains(out, "127.0.0.1:8790") || !strings.Contains(out, "not set") {
		t.Fatalf("status: %v\n%s", e, out)
	}
	if _, e := cliWeb(t, a, "", "install"); e == nil {
		t.Fatal("installing without an init system should fail")
	}
	if _, e := cliWeb(t, a, "", "restart"); e == nil {
		t.Fatal("restart without a service should fail")
	}
	if _, e := cliWeb(t, a, "", "install", "--port", "80"); e == nil {
		t.Fatal("privileged port accepted")
	}
	if _, e := cliWeb(t, a, "", "nonsense"); e == nil {
		t.Fatal("unknown subcommand accepted")
	}
	// The unit files bind nothing themselves, run the dedicated helper copy, and keep the
	// hardening that does not interfere with managing services.
	unit := a.webUnit()
	for _, want := range []string{"ExecStart=", "rout-web-v1", "web\" \"serve", "NoNewPrivileges=true", "PrivateTmp=true", "ProtectHome=true", "UMask=0077", "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK", "WantedBy=multi-user.target"} {
		if !strings.Contains(unit, want) {
			t.Errorf("unit lacks %q:\n%s", want, unit)
		}
	}
	if strings.Contains(unit, "0.0.0.0") || strings.Contains(unit, "--listen") {
		t.Error("the unit configures a listen address")
	}
	rc := a.webOpenRC()
	for _, want := range []string{"supervise-daemon", "rout-web-v1", "chmod 600"} {
		if !strings.Contains(rc, want) {
			t.Errorf("OpenRC script lacks %q", want)
		}
	}
	if a.webService() == (&App{Home: "/etc/rout"}).webService() || (&App{Home: "/etc/rout"}).webService() != "rout-web" {
		t.Error("service naming")
	}
}

func TestRemoteCLI(t *testing.T) {
	sc := newAggScene(t)
	u, out := testUI(sc.a, "")
	if e := u.remoteCommand([]string{"remote", "list"}); e != nil || !strings.Contains(out.String(), "Links") || !strings.Contains(out.String(), "Clash") {
		t.Fatalf("list: %v\n%s", e, out)
	}
	if strings.Contains(out.String(), "provider.test") {
		t.Fatal("the source list shows addresses")
	}
	sc.fsLinks.set(linkList(linkVless), nil)
	out.Reset()
	if e := u.remoteCommand([]string{"remote", "refresh", sc.links.ID}); e != nil || !strings.Contains(out.String(), "1 nodes") {
		t.Fatalf("refresh: %v\n%s", e, out)
	}
	sc.fsLinks.set("", context.DeadlineExceeded)
	out.Reset()
	if e := u.remoteCommand([]string{"remote", "refresh", "all"}); e == nil || strings.Contains(out.String(), "provider.test") {
		t.Fatalf("a failing refresh should report an error without the address: %v\n%s", e, out)
	}
	u2, _ := testUI(sc.a, "n\n")
	if e := u2.remoteCommand([]string{"remote", "delete", sc.links.ID}); e == nil {
		t.Fatal("deleted without confirmation")
	}
	if views, _ := sc.a.RemoteSources(); len(views) != 2 {
		t.Fatal("source deleted despite the refusal")
	}
	u3, _ := testUI(sc.a, "y\n")
	if e := u3.remoteCommand([]string{"remote", "delete", sc.links.ID}); e != nil {
		t.Fatal(e)
	}
	if views, _ := sc.a.RemoteSources(); len(views) != 1 {
		t.Fatal("source not deleted")
	}
}

func TestFullBackupCLIAndRestoreOfBothFormats(t *testing.T) {
	sc := newAggScene(t)
	if _, _, e := sc.a.CreateAggregateSubscription("mix", AggregateSpec{Items: []SubItem{sc.local(0), sc.rnode(t, sc.links, "HK Reality")}}); e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	full, plain := filepath.Join(dir, "full.json"), filepath.Join(dir, "plain.json")
	args := []string{"--home", sc.a.Home, "--bin-dir", sc.a.BinDir, "--service", "none"}
	if e := Run(append(args, "backup", "--full", full)); e != nil {
		t.Fatal(e)
	}
	if e := Run(append(args, "backup", plain)); e != nil {
		t.Fatal(e)
	}
	for _, f := range []string{full, plain} {
		if st, e := os.Stat(f); e != nil || st.Mode().Perm() != 0600 {
			t.Fatalf("%s: %v %v", f, e, st)
		}
	}
	raw, _ := os.ReadFile(full)
	var b BackupBundle
	if e := json.Unmarshal(raw, &b); e != nil || b.Remote == nil || len(b.Remote.Sources) != 2 {
		t.Fatalf("bundle: %v", e)
	}
	// The plain file is exactly what v0.4.0 wrote: no envelope.
	pr, _ := os.ReadFile(plain)
	if strings.Contains(string(pr), `"format"`) || strings.Contains(string(pr), "rout-backup") {
		t.Fatal("the plain backup gained an envelope")
	}
	// Remove everything, then restore the full backup through the CLI.
	st, _ := sc.a.Load()
	for _, s := range st.Subscriptions {
		_ = sc.a.DeleteSubscription(s.ID)
	}
	for _, v := range []string{sc.links.ID, sc.clash.ID} {
		if e := sc.a.DeleteRemoteSource(v, true); e != nil {
			t.Fatal(e)
		}
	}
	if e := Run(append(args, "restore", full)); e != nil {
		t.Fatal(e)
	}
	after, _ := sc.a.Load()
	if len(after.Subscriptions) != 1 {
		t.Fatal("subscription not restored")
	}
	if views, _ := sc.a.RemoteSources(); len(views) != 2 || views[0].Valid == 0 {
		t.Fatalf("sources not restored with their data: %+v", views)
	}
	if exp := sc.a.ExportAggregate(after, after.Subscriptions[0]); len(exp.URIs) != 2 {
		t.Fatalf("aggregate export after restore: %d", len(exp.URIs))
	}
	// Garbage and foreign files are refused without touching anything.
	bad := filepath.Join(dir, "bad.json")
	for name, content := range map[string]string{"garbage": "not json", "foreign": `{"format":"other"}`, "future": `{"format":"rout-backup","version":9,"state":{}}`, "empty": ""} {
		_ = os.WriteFile(bad, []byte(content), 0600)
		if e := Run(append(args, "restore", bad)); e == nil {
			t.Errorf("%s backup accepted", name)
		}
	}
	// A bundle that refers to a source it does not contain is refused.
	var dangling BackupBundle
	_ = json.Unmarshal(raw, &dangling)
	dangling.Remote = nil
	rawD, _ := json.Marshal(dangling)
	_ = os.WriteFile(bad, rawD, 0600)
	if e := Run(append(args, "restore", bad)); e == nil {
		t.Fatal("an aggregate without its sources was restored")
	}
	if now, _ := sc.a.Load(); len(now.Subscriptions) != 1 {
		t.Fatal("a refused restore changed the configuration")
	}
}

// A state written by this version must stay readable by v0.4.0, which ignores fields it does
// not know: aggregates then appear as plain subscriptions of their local nodes.
func TestRollbackStateIsReadableByTheOldSchema(t *testing.T) {
	sc := newAggScene(t)
	plainSub, _ := sc.create(t, "plain", 0, 1)
	agg, _, e := sc.a.CreateAggregateSubscription("mix", AggregateSpec{Items: []SubItem{sc.local(2), sc.rnode(t, sc.links, "HK Reality"), sc.local(0)}, Dedupe: true})
	if e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(filepath.Join(sc.a.Home, "state.json"))
	if e != nil {
		t.Fatal(e)
	}
	type oldSubscription struct {
		ID        string   `json:"id"`
		Name      string   `json:"name"`
		NodeIDs   []string `json:"node_ids"`
		TokenHash string   `json:"token_hash"`
		Enabled   bool     `json:"enabled"`
	}
	var old struct {
		Schema        int               `json:"schema"`
		Subscriptions []oldSubscription `json:"subscriptions"`
	}
	if e := json.Unmarshal(raw, &old); e != nil {
		t.Fatal(e)
	}
	got := map[string]oldSubscription{}
	for _, s := range old.Subscriptions {
		got[s.ID] = s
	}
	if g := got[plainSub.ID]; len(g.NodeIDs) != 2 || g.NodeIDs[0] != sc.nodes[0].ID || g.TokenHash != plainSub.TokenHash {
		t.Fatalf("plain subscription as the old schema sees it: %+v", g)
	}
	if g := got[agg.ID]; len(g.NodeIDs) != 2 || g.NodeIDs[0] != sc.nodes[2].ID || g.NodeIDs[1] != sc.nodes[0].ID || g.TokenHash != agg.TokenHash {
		t.Fatalf("aggregate as the old schema sees it: %+v", g)
	}
	// The plain subscription's JSON has no key that v0.4.0 did not write.
	var generic struct {
		Subscriptions []map[string]json.RawMessage `json:"subscriptions"`
	}
	_ = json.Unmarshal(raw, &generic)
	for _, s := range generic.Subscriptions {
		var id string
		_ = json.Unmarshal(s["id"], &id)
		if id != plainSub.ID {
			continue
		}
		for _, k := range []string{"items", "dedupe", "allow_insecure"} {
			if _, present := s[k]; present {
				t.Errorf("a plain subscription gained the key %q", k)
			}
		}
	}
}
