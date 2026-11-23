package rout

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMTPSecretAndLinks(t *testing.T) {
	p := fixture(t, protoMTP)
	p.NAT = true
	decoded, e := hex.DecodeString(p.Password)
	if e != nil || len(decoded) != 1+mtpKeyBytes+len(mtpCoverHost) || decoded[0] != 0xee ||
		string(decoded[1+mtpKeyBytes:]) != mtpCoverHost || p.Password == newMTPSecret() {
		t.Fatal("invalid or repeated FakeTLS secret")
	}
	for _, host := range []string{p.PublicHost, "proxy.example", "2001:db8::123"} {
		web, deep, e := p.telegramLinks(host, p.PublicPort)
		if e != nil {
			t.Fatal(e)
		}
		assertMTPLinks(t, p, host, web, deep)
	}
	bad := p
	for _, secret := range []string{"", "dd" + p.Password[2:], p.Password[:34], "ee" + strings.Repeat("0", 32) + p.Password[34:], p.Password[:34] + "20"} {
		bad.Password = secret
		if e := bad.Validate(); e == nil {
			t.Fatal("invalid secret was accepted")
		}
	}
	bad = p
	bad.PublicHost = "2001:db8::123"
	if e := bad.Validate(); e == nil {
		t.Fatal("advertised an IPv6 address for an IPv4 listener")
	}
	st := replace(State{Schema: 1}, p)
	raw := p.Password + " " + base64.RawURLEncoding.EncodeToString(decoded)
	if redactProxySecrets(raw, st) != "[REDACTED] [REDACTED]" {
		t.Fatal("MTP secret was not redacted")
	}
}

func assertMTPLinks(t *testing.T, p Profile, host, web, deep string) {
	t.Helper()
	for _, tc := range []struct{ link, scheme, authority, path string }{
		{web, "https", "t.me", "/proxy"}, {deep, "tg", "proxy", ""},
	} {
		u, e := url.Parse(tc.link)
		if e != nil || u.Scheme != tc.scheme || u.Host != tc.authority || u.Path != tc.path || u.Fragment != "" {
			t.Fatal("invalid Telegram import URL")
		}
		q := u.Query()
		if len(q) != 3 || q.Get("server") != host || q.Get("port") != itoa(p.PublicPort) || q.Get("secret") != p.Password {
			t.Fatal("Telegram import URL did not round-trip the public endpoint and complete secret")
		}
	}
}

func TestMTPWizardMappedPortAndManagement(t *testing.T) {
	a := testApp(t)
	occupied, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer occupied.Close()
	busy := occupied.Addr().(*net.TCPAddr).Port
	free, e := freePort()
	if e != nil {
		t.Fatal(e)
	}
	local, public := itoa(free), itoa(18443)
	wizard := strings.Join([]string{"US", "9", "2", itoa(busy), local, "3", "1", "US-MTP", "3", "2", public, "1", ""}, "\n")
	u, out := testUI(a, wizard)
	if e = u.create(); e != nil {
		t.Fatal(e)
	}
	s, e := a.Load()
	if e != nil || len(s.Profiles) != 1 {
		t.Fatalf("load created node: %v", e)
	}
	p := s.Profiles[0]
	if p.Name != "US-MTP" || !p.mtpNode() || p.Port != free || p.PublicPort != 18443 || !p.NAT || p.PublicHost != "203.0.113.10" {
		t.Fatal("wizard did not save the selected node name and mapped endpoint")
	}
	web, deep, e := p.telegramLinks(p.PublicHost, p.PublicPort)
	if e != nil {
		t.Fatal(e)
	}
	for _, expected := range []string{"MTP node created", "Protocol: MTProto", "Name: US-MTP", "Port: " + public, "Secret: " + p.Password, web, deep, "unavailable"} {
		if !strings.Contains(out.String(), expected) {
			t.Fatal("wizard omitted the translated success, conflict or link output")
		}
	}
	u, out = testUI(a, "1\n0\n0\n")
	if e = u.manage(); e != nil || !strings.Contains(out.String(), web) || !strings.Contains(out.String(), deep) {
		t.Fatalf("managed node did not show both links: %v", e)
	}
	if e = a.RenameProfile(p.ID, "Renamed"); e != nil {
		t.Fatal(e)
	}
	reopened := &App{Home: a.Home, BinDir: a.BinDir, ServiceMode: "none"}
	s, e = reopened.Load()
	if e != nil {
		t.Fatal(e)
	}
	q, e := Find(s, p.ID)
	if e != nil {
		t.Fatal(e)
	}
	link, e := q.Share()
	if e != nil || q.Name != "Renamed" || link != web {
		t.Fatal("rename or reload changed the saved link")
	}
	for _, file := range []string{mtpConf, mtpAllowlist} {
		st, e := os.Stat(filepath.Join(a.profileDir(p.ID), file))
		if e != nil || st.Mode().Perm() != 0600 {
			t.Fatalf("runtime file %s must be private: %v", file, e)
		}
	}
	if e = reopened.Restart(q.ID); e != nil {
		t.Fatal(e)
	}
	if e = reopened.DeleteProfiles([]string{q.ID}); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(reopened.profileDir(q.ID)); !os.IsNotExist(e) {
		t.Fatal("deleted node left a runtime configuration")
	}
}

func TestMTPUsesExistingNATPlannerAndTrafficMeter(t *testing.T) {
	p := fixture(t, protoMTP)
	port, e := freePort()
	if e != nil {
		t.Fatal(e)
	}
	setup := ServerSetup{Listen: p.Listen, PublicHost: "proxy.example", NAT: true, Network: "tcp",
		LocalStart: port, LocalEnd: port, PublicStart: 443}
	p, e = PlanPort(p, setup, State{Schema: 1})
	if e != nil || p.Port != port || p.PublicPort != 443 || p.PublicHost != "proxy.example" {
		t.Fatalf("NAT planner: %v", e)
	}
	cfg := (nftMeter{}).tableRules(p, TrafficRecord{})
	if !strings.Contains(cfg, "tcp dport "+itoa(port)+" jump up_gate") ||
		!strings.Contains(cfg, "tcp sport "+itoa(port)+" jump down_gate") || strings.Contains(cfg, "udp ") {
		t.Fatal("MTP meter must track client-side TCP bytes on the internal port")
	}
	setup.Network = "udp"
	if _, e = PlanPort(p, setup, State{Schema: 1}); e == nil {
		t.Fatal("allowed MTP over UDP-only NAT")
	}
}

func TestMTPRejectsGenericProxyAndSubscriptionExports(t *testing.T) {
	p := fixture(t, protoMTP)
	st := replace(State{Schema: 1}, p)
	if err := checkSubscriptionNodes(st, []string{p.ID}); !errors.Is(err, errMTPClient) {
		t.Fatal(err)
	}
	if ps, warns := st.SubscriptionCandidates(); len(ps) != 0 || len(warns) != 1 {
		t.Fatal("MTP was offered in the subscription picker")
	}
	sub := Subscription{NodeIDs: []string{p.ID}}
	if got := st.exportSubscription(sub); len(got.URIs) != 0 || len(got.Warnings) != 1 {
		t.Fatal("MTP appeared in a generic subscription")
	}
	if _, e := mihomoNode(p); !errors.Is(e, errMTPClient) {
		t.Fatal(e)
	}
	if _, e := p.SurgeLine(p.PublicHost, p.PublicPort); !errors.Is(e, errMTPClient) {
		t.Fatal(e)
	}
	if _, e := ClientConfig(p, p.PublicHost, p.PublicPort, 1080); !errors.Is(e, errMTPClient) {
		t.Fatal(e)
	}
	link, _ := p.Share()
	if _, e := URIOutbound(link); !errors.Is(e, errMTPClient) {
		t.Fatal(e)
	}
	if _, e := BindExit(st, p.ID, "0123456789ab"); !errors.Is(e, errMTPOutbound) {
		t.Fatal(e)
	}
	if e := aiEligible(p); !errors.Is(e, errMTPOutbound) {
		t.Fatal(e)
	}
	unit := (&App{Home: "/etc/rout", BinDir: "/opt/rout/bin"}).systemdUnit(p)
	if strings.Contains(unit, p.Password) || !strings.Contains(unit, mtpConf) || !strings.Contains(unit, "WantedBy=multi-user.target") ||
		!strings.Contains(unit, "Restart=on-failure") {
		t.Fatal("invalid or credential-bearing MTP service unit")
	}
}
