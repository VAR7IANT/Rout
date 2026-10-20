package rout

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestCreateListeningDefaultsToIPv4(t *testing.T) {
	a := relayTestApp(t, ServerSetup{PublicHost: v4Addr, Listen: "::", IPv4: v4Addr, IPv6: v6Addr, Network: "both"})
	u, out := testUI(a, "IPv4-default\n3\n\n\n")
	u.caps = func() listenCaps { return listenCaps{V4: true, V6: true, DualStack: true} }
	if e := u.create(); e != nil {
		t.Fatal(e, out.String())
	}
	s, e := a.Load()
	if e != nil || len(s.Profiles) != 1 {
		t.Fatal(s, e)
	}
	if s.Profiles[0].Listen != "0.0.0.0" {
		t.Fatalf("default listen = %q, want IPv4 0.0.0.0", s.Profiles[0].Listen)
	}
}

func TestNodeListeningSelection(t *testing.T) {
	dual := listenCaps{V4: true, V6: true, DualStack: true}
	for _, tc := range []struct {
		name, input, want string
		caps              listenCaps
		options           []string
		invalid           int
	}{
		{"IPv4-only", "", "0.0.0.0", listenCaps{V4: true}, []string{"ipv4"}, 0},
		{"IPv6-only", "", "::", listenCaps{V6: true}, []string{"ipv6"}, 0},
		{"dual default Enter", "\n", "0.0.0.0", dual, []string{"ipv4", "dual", "ipv6"}, 0},
		{"explicit IPv4", "1\n", "0.0.0.0", dual, []string{"ipv4", "dual", "ipv6"}, 0},
		{"explicit dual", "2\n", "::", dual, []string{"ipv4", "dual", "ipv6"}, 0},
		{"explicit IPv6", "3\n", "::", dual, []string{"ipv4", "dual", "ipv6"}, 0},
		{"invalid input", "0\n4\nabc\n-1\n\n", "0.0.0.0", dual, []string{"ipv4", "dual", "ipv6"}, 4},
		{"V6ONLY defaults to IPv4", "\n", "0.0.0.0", listenCaps{V4: true, V6: true}, []string{"ipv4", "ipv6"}, 0},
		{"V6ONLY explicit IPv6", "3\n2\n", "::", listenCaps{V4: true, V6: true}, []string{"ipv4", "ipv6"}, 1},
	} {
		for _, lang := range []string{"en", "zh-CN"} {
			t.Run(tc.name+"/"+lang, func(t *testing.T) {
				var keys []string
				for _, it := range nodeListenOptions(tc.caps) {
					keys = append(keys, it.key)
				}
				if !reflect.DeepEqual(keys, tc.options) {
					t.Fatalf("options %v, want %v", keys, tc.options)
				}
				a := testApp(t)
				a.Language = lang
				u, out := testUI(a, tc.input)
				u.caps = func() listenCaps { return tc.caps }
				// Public IPv4 detection is deliberately absent: local IPv4 behind NAT is sufficient.
				saved := ServerSetup{PublicHost: "vpn.example.com", Listen: "::", Family: "custom", IPv6: v6Addr}
				setup, e := u.nodeListeningSetup(saved)
				if e != nil || setup.Listen != tc.want {
					t.Fatalf("%+v %v\n%s", setup, e, out)
				}
				if saved.Listen != "::" {
					t.Fatal("mutated saved defaults")
				}
				text := out.String()
				if len(tc.options) > 1 {
					if strings.Count(text, a.T("选择")+" [1]:") != tc.invalid+1 {
						t.Fatalf("input retries/default missing:\n%s", text)
					}
					for _, label := range []string{"IPv4 (0.0.0.0)", "双栈 (IPv4 + IPv6)", "IPv6 (::)"} {
						key := map[string]string{"IPv4 (0.0.0.0)": "ipv4", "双栈 (IPv4 + IPv6)": "dual", "IPv6 (::)": "ipv6"}[label]
						if strings.Contains(text, a.T(label)) != contains(tc.options, key) {
							t.Fatalf("unavailable/missing option %s:\n%s", key, text)
						}
					}
				} else if strings.Contains(text, a.T("选择监听地址")) {
					t.Fatalf("unnecessary selection:\n%s", text)
				}
				if !strings.Contains(text, a.T(" [推荐]")) {
					t.Fatalf("missing recommendation:\n%s", text)
				}
				if lang == "en" && hasHan(text) {
					t.Fatalf("untranslated:\n%s", text)
				}
			})
		}
	}
}

func TestNodeListeningNoCapabilitiesAndCancellation(t *testing.T) {
	setup := ServerSetup{PublicHost: v4Addr, Listen: "::"}
	for _, tc := range []struct {
		input string
		caps  listenCaps
		want  error
	}{
		{"", listenCaps{}, nil},
		{"", listenCaps{V4: true, V6: true, DualStack: true}, io.EOF},
		{"q\n", listenCaps{V4: true, V6: true, DualStack: true}, errQuit},
	} {
		u, _ := testUI(testApp(t), tc.input)
		u.caps = func() listenCaps { return tc.caps }
		_, e := u.nodeListeningSetup(setup)
		if e == nil || (tc.want != nil && !errors.Is(e, tc.want)) {
			t.Fatalf("error %v, want %v", e, tc.want)
		}
	}
}

func TestNodeListeningPreservesExplicitAndLegacyNATBinds(t *testing.T) {
	for _, setup := range []ServerSetup{
		{PublicHost: v4Addr, Listen: "127.0.0.1"},
		{PublicHost: v6Addr, Listen: "2001:db8::7"},
		{PublicHost: v4Addr, Listen: "::", NAT: true, LocalStart: 20000, LocalEnd: 20019, PublicStart: 40000, Network: "both"},
	} {
		u, out := testUI(testApp(t), "")
		u.caps = func() listenCaps { t.Fatal("explicit bind must be preserved"); return listenCaps{} }
		got, e := u.nodeListeningSetup(setup)
		if e != nil || got != setup || out.Len() != 0 {
			t.Fatalf("changed explicit setup: %+v %v %s", got, e, out)
		}
	}
}

func TestNodeListeningProtocolConfiguration(t *testing.T) {
	for _, proto := range createProtocols {
		for _, choice := range []struct{ input, listen string }{{"\n", "0.0.0.0"}, {"1\n", "0.0.0.0"}, {"2\n", "::"}, {"3\n", "::"}} {
			t.Run(proto+"/"+choice.input, func(t *testing.T) {
				u, _ := testUI(testApp(t), choice.input)
				u.caps = func() listenCaps { return listenCaps{V4: true, V6: true, DualStack: true} }
				setup, e := u.nodeListeningSetup(ServerSetup{Listen: "::", PublicHost: v4Addr, IPv4: v4Addr, IPv6: v6Addr})
				if e != nil {
					t.Fatal(e)
				}
				p := fixture(t, proto)
				p.Listen = setup.Listen
				before, _ := serverConfig(fixture(t, proto), "/config")
				cfg, e := serverConfig(p, "/config")
				if e != nil {
					t.Fatal(e)
				}
				inbound := cfg["inbounds"].([]any)[0].(M)
				if inbound["listen"] != choice.listen || inbound["listen_port"] != p.Port {
					t.Fatal(inbound)
				}
				// Selecting a listening mode does not change routing or outbounds.
				if !reflect.DeepEqual(cfg["route"], before["route"]) || !reflect.DeepEqual(cfg["outbounds"], before["outbounds"]) {
					t.Fatal("changed outbound routing")
				}
			})
		}
	}
}

func TestNodeCreationPreservesExistingNodesAndServerDefaults(t *testing.T) {
	a := relayTestApp(t, ServerSetup{PublicHost: v4Addr, Listen: "::", IPv4: v4Addr, IPv6: v6Addr, Network: "both"})
	old, _ := a.Load()
	for i, listen := range []string{"0.0.0.0", "::", "127.0.0.1"} {
		p := fixture(t, "ss")
		p.ID = RandomHex(6)
		p.Name = "existing-" + itoa(i)
		p.Listen = listen
		p.Port = 21000 + i
		p.PublicPort = p.Port
		p.Enabled = i != 2
		if i == 2 {
			p.NAT = true
			p.PublicPort = 41002
		}
		old = replace(old, p)
	}
	empty, _ := a.Load()
	if e := a.Commit(empty, old, false); e != nil {
		t.Fatal(e)
	}
	old, _ = a.Load()
	// Poison the old generated files; any rewrite, even with identical state, is detected.
	for _, p := range old.Profiles {
		if e := os.WriteFile(filepath.Join(a.profileDir(p.ID), "config.json"), []byte("existing config must stay untouched"), 0600); e != nil {
			t.Fatal(e)
		}
	}
	settingsBefore, e := os.ReadFile(filepath.Join(a.Home, "settings.json"))
	if e != nil {
		t.Fatal(e)
	}
	u, out := testUI(a, "New\n1 2 3 4 5\n\n\n")
	u.caps = func() listenCaps { return listenCaps{V4: true, V6: true, DualStack: true} }
	if e := u.create(); e != nil {
		t.Fatal(e, out.String())
	}
	next, e := a.Load()
	if e != nil {
		t.Fatal(e)
	}
	if len(next.Profiles) != len(old.Profiles)+len(createProtocols) {
		t.Fatal("incorrect batch size")
	}
	for _, p := range old.Profiles {
		got, e := Find(next, p.ID)
		if e != nil || !reflect.DeepEqual(got, p) {
			t.Fatalf("existing node changed: %+v %v", got, e)
		}
		b, e := os.ReadFile(filepath.Join(a.profileDir(p.ID), "config.json"))
		if e != nil || string(b) != "existing config must stay untouched" {
			t.Fatal("existing configuration rewritten", e)
		}
	}
	for _, p := range next.Profiles[len(old.Profiles):] {
		if p.Listen != "0.0.0.0" {
			t.Fatalf("%s has listen %s", p.Protocol, p.Listen)
		}
	}
	settingsAfter, e := os.ReadFile(filepath.Join(a.Home, "settings.json"))
	if e != nil || !bytes.Equal(settingsBefore, settingsAfter) {
		t.Fatal("saved server defaults changed", e)
	}
}

// Fully injected socket probes: no dependence on the CI runner's network stack.
type probeListener struct{ addr *net.TCPAddr }

func (p probeListener) Accept() (net.Conn, error) { return nil, io.EOF }
func (p probeListener) Close() error              { return nil }
func (p probeListener) Addr() net.Addr            { return p.addr }

type probePacket struct {
	addr    *net.UDPAddr
	receive bool
}

func (p probePacket) ReadFrom(b []byte) (int, net.Addr, error) {
	if !p.receive {
		return 0, nil, errors.New("IPv4-mapped UDP refused")
	}
	return copy(b, "rout"), p.addr, nil
}
func (p probePacket) WriteTo(b []byte, _ net.Addr) (int, error) { return len(b), nil }
func (p probePacket) Close() error                              { return nil }
func (p probePacket) LocalAddr() net.Addr                       { return p.addr }
func (p probePacket) SetDeadline(time.Time) error               { return nil }
func (p probePacket) SetReadDeadline(time.Time) error           { return nil }
func (p probePacket) SetWriteDeadline(time.Time) error          { return nil }

type probeConn struct{ net.Conn }

func (probeConn) Write(b []byte) (int, error)      { return len(b), nil }
func (probeConn) Close() error                     { return nil }
func (probeConn) SetWriteDeadline(time.Time) error { return nil }

func TestListeningCapabilityProbes(t *testing.T) {
	for _, tc := range []struct {
		name, fail                     string
		tcpMapped, udpMapped, fallback bool
		want                           listenCaps
	}{
		{"IPv4-only", "6", true, true, false, listenCaps{V4: true}},
		{"IPv6-only", "4", true, true, false, listenCaps{V6: true}},
		{"dual-stack", "", true, true, false, listenCaps{V4: true, V6: true, DualStack: true}},
		{"V6ONLY TCP", "", false, true, false, listenCaps{V4: true, V6: true}},
		{"V6ONLY UDP", "", true, false, false, listenCaps{V4: true, V6: true}},
		{"Go wildcard fallback is not IPv6", "", true, true, true, listenCaps{V4: true, V6: true}},
		{"TCP4 unavailable", "tcp4", true, true, false, listenCaps{V6: true}},
		{"UDP4 unavailable", "udp4", true, true, false, listenCaps{V6: true}},
		{"UDP6 unavailable", "udp6", true, true, false, listenCaps{V4: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fail := func(network string) bool { return tc.fail != "" && strings.HasSuffix(network, tc.fail) }
			listen := func(n, a string) (net.Listener, error) {
				if fail(n) {
					return nil, errors.New("unsupported family")
				}
				ip := net.IPv6unspecified
				if n == "tcp4" || (n == "tcp" && tc.fallback) {
					ip = net.IPv4zero
				}
				return probeListener{&net.TCPAddr{IP: ip, Port: 12345}}, nil
			}
			packet := func(n, a string) (net.PacketConn, error) {
				if fail(n) {
					return nil, errors.New("unsupported family")
				}
				ip := net.IPv6unspecified
				if n == "udp4" {
					ip = net.IPv4zero
				}
				return probePacket{&net.UDPAddr{IP: ip, Port: 12345}, tc.udpMapped}, nil
			}
			dial := func(n, a string, _ time.Duration) (net.Conn, error) {
				if n == "tcp4" && !tc.tcpMapped {
					return nil, errors.New("mapped TCP refused")
				}
				return probeConn{}, nil
			}
			if got := probeListenCapsWith(listen, packet, dial); got != tc.want {
				t.Fatalf("caps %+v, want %+v", got, tc.want)
			}
			// A transport the selected protocol never uses must not hide IPv4 listening.
			network := ""
			if tc.fail == "udp4" {
				network = "tcp"
			}
			if tc.fail == "tcp4" {
				network = "udp"
			}
			if network != "" {
				want := listenCaps{V4: true, V6: true, DualStack: true}
				if got := probeListenCapsWith(listen, packet, dial, network); got != want {
					t.Fatalf("%s-only caps %+v, want %+v", network, got, want)
				}
			}
		})
	}
}

func TestNodeListeningPublicEndpointIsSeparate(t *testing.T) {
	for _, tc := range []struct{ name, input, host, v4, v6, want string }{
		{"public IPv6 with private IPv4", "1\nvpn.example.com\n", v6Addr, "", "", "vpn.example.com"},
		{"known IPv4 endpoint", "1\n", v6Addr, v4Addr, v6Addr, v4Addr},
		{"known IPv6 endpoint", "3\n", v4Addr, v4Addr, v6Addr, v6Addr},
		{"custom domain is retained", "3\n", "vpn.example.com", v4Addr, v6Addr, "vpn.example.com"},
		{"mismatched input retried", "1\n2001:db8::8\n0.0.0.0\n203.0.113.8\n", v6Addr, "", "", "203.0.113.8"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u, out := testUI(testApp(t), tc.input)
			u.caps = func() listenCaps { return listenCaps{V4: true, V6: true, DualStack: true} }
			got, e := u.nodeListeningSetup(ServerSetup{Listen: "::", PublicHost: tc.host, IPv4: tc.v4, IPv6: tc.v6})
			if e != nil || got.PublicHost != tc.want {
				t.Fatalf("%+v %v\n%s", got, e, out)
			}
			if tc.input[0] == '1' && got.Listen != "0.0.0.0" {
				t.Fatal("public IPv6 detection overrode local IPv4 capability")
			}
		})
	}
}

func TestIPv6WildcardDoesNotImplyDualStackLinks(t *testing.T) {
	for _, mapped := range []bool{false, true} {
		choice := "2\n"
		if mapped {
			choice = "3\n"
		}
		u, _ := testUI(testApp(t), choice)
		u.caps = func() listenCaps { return listenCaps{V4: true, V6: true, DualStack: mapped} }
		setup, e := u.nodeListeningSetup(ServerSetup{Listen: "::", PublicHost: v4Addr, IPv4: v4Addr, IPv6: v6Addr})
		if e != nil {
			t.Fatal(e)
		}
		p := fixture(t, "ss")
		p.Listen = setup.Listen
		p.PublicHost = setup.PublicHost
		p.IPv4Mapped = setup.ipv4Mapped
		b, e := json.Marshal(p)
		if e != nil {
			t.Fatal(e)
		}
		var loaded Profile
		if e = json.Unmarshal(b, &loaded); e != nil {
			t.Fatal(e)
		}
		_, _, ok := setup.AltAddress(loaded)
		if ok != mapped {
			t.Fatalf("mapped=%v: alternate link offered=%v", mapped, ok)
		}
		// Optional metadata must not restart an existing service when only link information changes.
		legacy := p
		legacy.IPv4Mapped = nil
		if !runtimeEqual(p, legacy) {
			t.Fatal("capability metadata changed runtime configuration")
		}
	}
}
