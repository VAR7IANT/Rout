package rout

import (
	"bytes"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNodeManagementListsCompleteProtocolLinks(t *testing.T) {
	for _, host := range []string{"203.0.113.10", "2001:db8::10", "nodes.example"} {
		for _, lang := range []string{"en", "zh-CN"} {
			t.Run(host+"/"+lang, func(t *testing.T) {
				a := testApp(t)
				a.Language = lang
				state := State{Schema: 1}
				for i, protocol := range []string{"vless", "anytls", "ss", "hy2", "tuic"} {
					p := linkFixture(t, protocol, host)
					p.Name = "🇯🇵 Long node name with spaces " + protocol
					p.Port, p.PublicPort = 24000+i, 24000+i
					if host == "2001:db8::10" {
						p.Listen = "::"
					}
					state.Profiles = append(state.Profiles, p)
				}
				old, _ := a.Load()
				if e := a.Commit(old, state, false); e != nil {
					t.Fatal("cannot prepare node fixture")
				}
				before, _ := os.ReadFile(filepath.Join(a.Home, "state.json"))
				configs := map[string][]byte{}
				for _, p := range state.Profiles {
					configs[p.ID], _ = os.ReadFile(filepath.Join(a.profileDir(p.ID), "config.json"))
				}
				u, out := testUI(a, "0\n")
				u.termWidth = 32
				if e := u.manage(); e != nil {
					t.Fatal("node management failed")
				}
				text := out.String()
				for i, p := range state.Profiles {
					uri, e := p.URI()
					if e != nil {
						t.Fatal("fixture link invalid")
					}
					start := strings.Index(text, p.Name)
					end := len(text)
					if i+1 < len(state.Profiles) {
						end = strings.Index(text, state.Profiles[i+1].Name)
					}
					if start < 0 || end <= start || !strings.Contains(text[start:end], "\n"+uri+"\n") {
						t.Fatal("complete protocol link missing or displayed under another node")
					}
					if p.Protocol == "vless" && (!strings.Contains(uri, "flow=xtls-rprx-vision") || !strings.Contains(uri, "pbk="+p.PublicKey) || !strings.Contains(uri, "sid="+p.ShortID)) {
						t.Fatal("Reality parameters missing")
					}
					if p.Protocol == "hy2" && !strings.Contains(uri, "pinSHA256=") {
						t.Fatal("TLS certificate pin missing")
					}
					parsed, _ := url.Parse(uri)
					if p.Protocol != "ss" && parsed.Query().Get("sni") != p.SNI {
						t.Fatal("TLS/Reality SNI changed")
					}
					current, _ := os.ReadFile(filepath.Join(a.profileDir(p.ID), "config.json"))
					if !bytes.Equal(current, configs[p.ID]) {
						t.Fatal("listing links changed a node configuration")
					}
				}
				after, _ := os.ReadFile(filepath.Join(a.Home, "state.json"))
				if !bytes.Equal(before, after) || (lang == "en" && hasHan(text)) {
					t.Fatal("node view modified state or contains untranslated messages")
				}
			})
		}
	}
}

func TestNodeManagementListsDualStackLinksWithoutChangingCommandOutput(t *testing.T) {
	a := testApp(t)
	p := linkFixture(t, "vless", "203.0.113.10")
	p.Listen = "::"
	setup := ServerSetup{Family: "ipv4", IPv4: p.PublicHost, IPv6: "2001:db8::10", PublicHost: p.PublicHost, Listen: "::"}
	if e := a.SaveSettings(Settings{Language: "en", Server: &setup}); e != nil {
		t.Fatal(e)
	}
	old, _ := a.Load()
	s := replace(old, p)
	if e := a.Commit(old, s, false); e != nil {
		t.Fatal(e)
	}
	u, out := testUI(a, "0\n")
	if e := u.manage(); e != nil {
		t.Fatal(e)
	}
	primary, _ := p.URI()
	alternate, _ := p.URIAt(setup.IPv6, p.PublicPort)
	if !strings.Contains(out.String(), primary) || !strings.Contains(out.String(), alternate) {
		t.Fatal("dual-stack node did not show both complete links")
	}
	// Preserve the pre-v0.3.7 explicit command layout; no added URL labels/menus.
	oldView, expected := testUI(a, "")
	oldView.nodeCard(s, 1, p, nil)
	expected.WriteString("      " + primary + "\n")
	label, alt, ok := altLink(setup, p)
	if !ok {
		t.Fatal("dual-stack fixture invalid")
	}
	expected.WriteString("      " + label + ": " + alt + "\n")
	commandView, actual := testUI(a, "")
	commandView.list(s)
	if actual.String() != expected.String() {
		t.Fatal("rout list output changed")
	}
}
