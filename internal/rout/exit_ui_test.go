package rout

import (
	"errors"
	"strings"
	"testing"
)

// Scripted tests of the outbound (exit) screens: Remote Server creation, verification,
// reuse, view, delete protection. Output is checked in English: no untranslated text.

func exitsOf(t *testing.T, a *App) []Exit {
	t.Helper()
	s, e := a.Load()
	if e != nil {
		t.Fatal(e)
	}
	return s.Exits
}

func noHan(t *testing.T, text string) {
	t.Helper()
	if hasHan(text) {
		t.Fatalf("untranslated text:\n%s", text)
	}
}

func TestAddRemoteServerExitFromANodeLink(t *testing.T) {
	a := testApp(t)
	link := remoteLink(t, "vless", "us-vps.example.net", 44275)
	probed := 0
	// add · remote server · node link · the link · default name · back
	u, out := testUI(a, "1\n4\n1\n"+link+"\n\n0\n")
	u.probeProxy = func(p Proxy) (string, error) {
		probed++
		if p.Protocol != proxyNode {
			t.Errorf("probed %+v", p)
		}
		return "198.51.100.77", nil
	}
	if e := u.outbounds(); e != nil {
		t.Fatal(e, out.String())
	}
	ex := exitsOf(t, a)
	if len(ex) != 1 || ex[0].Kind != exitRemote || ex[0].Proxy.Protocol != proxyNode || ex[0].Name != "Remote-us-vps.example.net" || ex[0].Proxy.Link != link {
		t.Fatalf("stored %+v", ex)
	}
	if probed != 1 {
		t.Fatalf("a remote server must be verified exactly once before saving, probed %d times", probed)
	}
	text := out.String()
	for _, want := range []string{"Remote server exit", "real proxy service", "outbound IP: 198.51.100.77", "REMOTE·VLESS"} {
		if !strings.Contains(text, want) {
			t.Errorf("output misses %q:\n%s", want, text)
		}
	}
	noHan(t, text)
	if strings.Contains(text, "11111111") || strings.Contains(text, strings.SplitN(strings.TrimPrefix(link, "vless://"), "@", 2)[0]) {
		t.Fatal("the link's credentials were echoed")
	}
}

func TestAddRemoteServerExitFromAnAuthenticatedProxy(t *testing.T) {
	a := testApp(t)
	// add · remote server · proxy · SOCKS5 · account line · default name · back
	u, out := testUI(a, "1\n4\n2\n1\n198.51.100.8:1080:remote-user:remote-pass\n\n0\n")
	u.probeProxy = func(p Proxy) (string, error) { return "198.51.100.8", nil }
	if e := u.outbounds(); e != nil {
		t.Fatal(e, out.String())
	}
	ex := exitsOf(t, a)
	if len(ex) != 1 || ex[0].Kind != exitRemote || ex[0].Proxy.Protocol != "socks5" || ex[0].Proxy.Username != "remote-user" {
		t.Fatalf("%+v", ex)
	}
	noHan(t, out.String())
	if strings.Contains(out.String(), "remote-pass") {
		t.Fatal("password echoed")
	}
}

func TestPortMappingIsNotAnExit(t *testing.T) {
	a := testApp(t)
	u, out := testUI(a, "1\n4\n3\n0\n")
	u.probeProxy = func(Proxy) (string, error) { t.Fatal("nothing to probe"); return "", nil }
	if e := u.outbounds(); e != nil {
		t.Fatal(e)
	}
	text := out.String()
	if len(exitsOf(t, a)) != 0 {
		t.Fatal("a bare port mapping was stored as an exit")
	}
	for _, want := range []string{"cannot be an exit", "still sees this machine's IP", "Port forwarding"} {
		if !strings.Contains(text, want) {
			t.Errorf("explanation misses %q:\n%s", want, text)
		}
	}
	noHan(t, text)
}

func TestQUICRemoteServerBehindATCPOnlyNATIsRefused(t *testing.T) {
	a := testApp(t)
	link := remoteLink(t, "hy2", "nat.example.net", 27001)
	// add · remote server · node link · the link · "TCP only"
	u, out := testUI(a, "1\n4\n1\n"+link+"\n2\n0\n")
	u.probeProxy = func(Proxy) (string, error) { t.Fatal("must be refused before any probe"); return "", nil }
	if e := u.outbounds(); e != nil {
		t.Fatal(e)
	}
	if len(exitsOf(t, a)) != 0 {
		t.Fatal("stored")
	}
	text := out.String()
	for _, want := range []string{"The destination currently supports TCP only", "Hysteria2 needs UDP transport", "cannot be used through a plain TCP port relay", "compatible tunnel that can encapsulate UDP"} {
		if !strings.Contains(text, want) {
			t.Errorf("message misses %q:\n%s", want, text)
		}
	}
	noHan(t, text)
	// Declaring UDP support lets it through to verification.
	u, out = testUI(a, "1\n4\n1\n"+link+"\n1\n\n0\n")
	u.probeProxy = func(Proxy) (string, error) { return "198.51.100.9", nil }
	if e := u.outbounds(); e != nil {
		t.Fatal(e)
	}
	if ex := exitsOf(t, a); len(ex) != 1 || ex[0].RemoteNetwork != "both" {
		t.Fatalf("%+v\n%s", ex, out.String())
	}
}

func TestUnverifiedRemoteServerIsNeverShownAsWorking(t *testing.T) {
	link := remoteLink(t, "vless", "dead.example.net", 44275)
	fail := func(Proxy) (string, error) { return "", errors.New("authentication failed") }

	// Declined: nothing stored.
	a := testApp(t)
	u, out := testUI(a, "1\n4\n1\n"+link+"\n\nn\n0\n")
	u.probeProxy = fail
	if e := u.outbounds(); e != nil {
		t.Fatal(e)
	}
	if len(exitsOf(t, a)) != 0 {
		t.Fatalf("a failed exit was stored without consent\n%s", out.String())
	}
	text := out.String()
	for _, want := range []string{"did not pass the check", "Save anyway (not verified)", "Cancelled"} {
		if !strings.Contains(text, want) {
			t.Errorf("output misses %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "saved") && !strings.Contains(text, "Cancelled") {
		t.Fatalf("a failed exit was reported saved:\n%s", text)
	}
	noHan(t, text)

	// Accepted knowingly: stored, with the warning shown first.
	a = testApp(t)
	u, out = testUI(a, "1\n4\n1\n"+link+"\n\ny\n0\n")
	u.probeProxy = fail
	if e := u.outbounds(); e != nil {
		t.Fatal(e)
	}
	if len(exitsOf(t, a)) != 1 {
		t.Fatalf("explicitly accepted exit not stored\n%s", out.String())
	}
	if !strings.Contains(out.String(), "may have no Internet access") {
		t.Fatalf("no warning before saving an unverified exit:\n%s", out.String())
	}
}

func TestExitCannotBeCreatedPointingAtThisServer(t *testing.T) {
	a := testApp(t)
	node := fixture(t, "vless")
	node.Port, _ = freePort()
	node.PublicPort = node.Port
	s, _ := a.Load()
	if e := a.Commit(s, replace(s, node), false); e != nil {
		t.Fatal(e)
	}
	// add · SOCKS5 · 127.0.0.1 on the node's port
	u, out := testUI(a, "1\n1\n127.0.0.1:"+itoa(node.Port)+":u:p\n\n0\n")
	if e := u.outbounds(); e != nil {
		t.Fatal(e)
	}
	if len(exitsOf(t, a)) != 0 || !strings.Contains(out.String(), "routing loop") {
		t.Fatalf("loop exit stored or not explained:\n%s", out.String())
	}
}

func commitNodesOnExit(t *testing.T, a *App, ex Exit, names ...string) State {
	t.Helper()
	s, _ := a.Load()
	s = UpsertExit(s, ex)
	for _, name := range names {
		n := fixture(t, "vless")
		n.ID, n.Name = RandomHex(6), name
		n.Port, _ = freePort()
		n.PublicPort = n.Port
		s = replace(s, n)
		var e error
		if s, e = BindExit(s, n.ID, ex.ID); e != nil {
			t.Fatal(e)
		}
	}
	old, _ := a.Load()
	if e := a.Commit(old, s, false); e != nil {
		t.Fatal(e)
	}
	got, _ := a.Load()
	return got
}

func TestViewExitShowsReferencesAndNoSecrets(t *testing.T) {
	a := testApp(t)
	ex := remoteExit(t, "vless", "us-vps.example.net", 44275)
	s := commitNodesOnExit(t, a, ex, "Tokyo", "Osaka")
	u, out := testUI(a, "1\n")
	if e := u.outboundAction(s, "view"); e != nil {
		t.Fatal(e)
	}
	text := out.String()
	for _, want := range []string{ex.Name, "Remote server exit", "VLESS", "us-vps.example.net:44275", "needs TCP", "Nodes using it: Osaka、Tokyo", "UDP traffic is rejected"} {
		if !strings.Contains(text, want) {
			t.Errorf("view misses %q:\n%s", want, text)
		}
	}
	uuid := strings.TrimPrefix(strings.SplitN(ex.Proxy.Link, "@", 2)[0], "vless://")
	if strings.Contains(text, uuid) || strings.Contains(text, "pbk=") {
		t.Fatalf("view leaks the link:\n%s", text)
	}
	noHan(t, text)
	// An unused exit says so.
	a2 := testApp(t)
	s2, _ := a2.Load()
	if e := a2.Commit(s2, UpsertExit(s2, remoteExit(t, "ss", "b.example.net", 8388)), false); e != nil {
		t.Fatal(e)
	}
	s2, _ = a2.Load()
	u, out = testUI(a2, "1\n")
	if e := u.outboundAction(s2, "view"); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(out.String(), "no node uses it") {
		t.Fatalf("%s", out.String())
	}
}

func TestDeleteReferencedExitIsRefusedByTheScreen(t *testing.T) {
	a := testApp(t)
	ex := remoteExit(t, "vless", "us-vps.example.net", 44275)
	s := commitNodesOnExit(t, a, ex, "Tokyo")
	u, _ := testUI(a, "1\ny\n")
	e := u.outboundAction(s, "delete")
	if e == nil || !strings.Contains(a.Error(e), "Tokyo") {
		t.Fatalf("got %v", e)
	}
	if len(exitsOf(t, a)) != 1 {
		t.Fatal("the exit was deleted")
	}
	// Unreferenced: confirmed delete works and leaves everything else alone.
	b := testApp(t)
	other := remoteExit(t, "ss", "b.example.net", 8388)
	s2, _ := b.Load()
	s2 = UpsertExit(UpsertExit(s2, ex), other)
	if err := b.Commit(mustLoad(t, b), s2, false); err != nil {
		t.Fatal(err)
	}
	s2, _ = b.Load()
	u, _ = testUI(b, "1\ny\n")
	if err := u.outboundAction(s2, "delete"); err != nil {
		t.Fatal(err)
	}
	left := exitsOf(t, b)
	if len(left) != 1 || left[0].ID != other.ID {
		t.Fatalf("%+v", left)
	}
}

func TestPickOutboundCanCreateAnExitOnTheSpot(t *testing.T) {
	a := testApp(t)
	first := Exit{ID: RandomHex(6), Name: "US-SOCKS5", Proxy: Proxy{Protocol: "socks5", Host: "198.51.100.5", Port: 1080, Username: "u", Password: "p"}}
	s := mustLoad(t, a)
	if e := a.Commit(s, UpsertExit(s, first), false); e != nil {
		t.Fatal(e)
	}
	s = mustLoad(t, a)
	// 1 US-SOCKS5 · 2 Direct · 3 New outbound proxy → SOCKS5 → account line → default name
	u, out := testUI(a, "3\n1\n198.51.100.6:1080:u2:p2\n\n")
	next, id, ok := u.pickOutbound(s, "")
	if !ok || id == "" || id == first.ID {
		t.Fatalf("ok=%v id=%q\n%s", ok, id, out.String())
	}
	if len(next.Exits) != 2 {
		t.Fatalf("returned state is stale: %d exits", len(next.Exits))
	}
	got, e := FindExit(next, id)
	if e != nil || got.Proxy.Host != "198.51.100.6" {
		t.Fatalf("%+v %v", got, e)
	}
	// It is committed: a later transaction starting from the returned state works.
	if e = a.Commit(next, next, false); e != nil {
		t.Fatal(e)
	}
	text := out.String()
	for _, want := range []string{"New outbound proxy", "Direct connection (no outbound proxy)", "US-SOCKS5"} {
		if !strings.Contains(text, want) {
			t.Errorf("menu misses %q:\n%s", want, text)
		}
	}
	noHan(t, text)
	// Direct is still the entry right after the stored exits, so existing numbering holds.
	u, _ = testUI(a, "3\n")
	if _, id, ok := u.pickOutbound(next, ""); ok == false || id != "" {
		t.Fatalf("direct is not entry %d (id=%q ok=%v)", len(next.Exits)+1, id, ok)
	}
}

func TestEditRenamingAnExitKeepsItsReferences(t *testing.T) {
	a := testApp(t)
	ex := remoteExit(t, "vless", "us-vps.example.net", 44275)
	s := commitNodesOnExit(t, a, ex, "Tokyo", "Osaka")
	// pick exit 1 · new name · do not change the endpoint
	u, out := testUI(a, "1\nUS-VPS\nn\n")
	if e := u.outboundAction(s, "edit"); e != nil {
		t.Fatal(e, out.String())
	}
	after := mustLoad(t, a)
	got, _ := FindExit(after, ex.ID)
	if got.Name != "US-VPS" || got.Proxy != ex.Proxy || got.Kind != exitRemote {
		t.Fatalf("%+v", got)
	}
	if refs := exitReferences(after, ex.ID); len(refs.Nodes) != 2 {
		t.Fatalf("references lost: %+v", refs)
	}
}
