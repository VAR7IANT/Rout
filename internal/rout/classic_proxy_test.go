package rout

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func TestClassicProxyShareRoundTrip(t *testing.T) {
	for _, protocol := range []string{"socks5", "http"} {
		t.Run(protocol, func(t *testing.T) {
			p := fixture(t, protocol)
			second := fixture(t, protocol)
			if len(p.Username) != 24 || len(p.Password) != 32 || second.Username == p.Username || second.Password == p.Password {
				t.Fatal("expected independently generated proxy credentials")
			}
			for _, host := range []string{"203.0.113.9", "proxy.example.com", "2001:db8::9"} {
				line, err := p.ShareAt(host, 18443)
				if err != nil {
					t.Fatal(err)
				}
				got, err := ParseProxy(protocol, line)
				if err != nil || got.Host != host || got.Port != 18443 || got.Username != p.Username || got.Password != p.Password {
					t.Fatalf("CLI failed to import %s:%d: %v", host, 18443, err)
				}
				exit, err := buildExit(ExitSpec{Protocol: protocol, ProxyLine: line})
				if err != nil || exit.Proxy != *got {
					t.Fatalf("panel did not parse the same connection details: %v", err)
				}
			}
			if _, err := p.subscriptionShare(); !errors.Is(err, errClassicProxyShare) {
				t.Fatal("connection details must stay out of subscription enrollment")
			}
			if _, err := p.URI(); !errors.Is(err, errClassicProxyShare) {
				t.Fatal("a paste line must not be exported as a subscription URI")
			}
			auth := base64.StdEncoding.EncodeToString([]byte(p.Username + ":" + p.Password))
			payload := strings.Join([]string{p.Username, p.Password, auth}, " ")
			if got := redactProxySecrets(payload, replace(State{Schema: 1}, p)); got != "[REDACTED] [REDACTED] [REDACTED]" {
				t.Error("proxy node credentials were not redacted")
			}
		})
	}
	if _, err := buildExit(ExitSpec{Protocol: "http", Host: "proxy.example.org", ProxyLine: "proxy.example.org:80:alice:pw"}); err == nil {
		t.Fatal("ambiguous proxy input was accepted")
	}
}

func TestClassicProxyRequiresImportableAuthentication(t *testing.T) {
	for _, protocol := range []string{"socks5", "http"} {
		p := fixture(t, protocol)
		for _, fields := range [][2]string{{"", p.Password}, {p.Username, ""}, {"a:b", p.Password}, {p.Username, "password "}} {
			bad := p
			bad.Username, bad.Password = fields[0], fields[1]
			if err := bad.Validate(); err == nil {
				t.Fatal("invalid authentication was accepted")
			}
			if _, err := serverConfig(bad, "/config"); err == nil {
				t.Fatal("invalid authentication reached the server config")
			}
		}
		p.Password = "password:with:colons"
		if err := p.Validate(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestClassicProxyQuickCreateAndReset(t *testing.T) {
	a := relayTestApp(t, ServerSetup{Listen: "127.0.0.1", PublicHost: "proxy.example.org", Network: "both"})
	u, out := testUI(a, "US\n10 11\n\n")
	if err := u.create(); err != nil {
		t.Fatal(err)
	}
	st, err := a.Load()
	if err != nil || len(st.Profiles) != 2 {
		t.Fatalf("expected two persisted proxy nodes: %v", err)
	}
	for _, p := range st.Profiles {
		line, err := p.Share()
		if err != nil || !strings.Contains(out.String(), line+"\n") {
			t.Fatalf("create did not print pasteable %s credentials: %v", p.Protocol, err)
		}
	}
	p := st.Profiles[0]
	u, _ = testUI(a, "yes\n")
	if err := u.nodeAction(st, p, "credentials"); err != nil {
		t.Fatal(err)
	}
	st, err = a.Load()
	if err != nil {
		t.Fatal(err)
	}
	updated, err := Find(st, p.ID)
	if err != nil || updated.Username == p.Username || updated.Password == p.Password ||
		updated.Port != p.Port || updated.PublicPort != p.PublicPort {
		t.Fatalf("reset did not rotate both credentials while preserving the endpoint: %v", err)
	}
}
