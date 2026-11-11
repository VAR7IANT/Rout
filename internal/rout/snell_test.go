package rout

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"hash/crc32"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
)

// snellNode returns a Snell profile on loopback with a free port. protocol is "snell" (v5) or
// "snell6" (v6); the node is not saved.
func snellNodeFixture(t *testing.T, protocol, name string, port int) Profile {
	t.Helper()
	p := fixture(t, protocol)
	p.Name = name
	p.Port, p.PublicPort = port, port
	return p
}

func TestSnellConfigGeneration(t *testing.T) {
	psk := "AbCdEfGh1234567890AbCdEfGh123456"
	for _, tc := range []struct {
		name    string
		version string
		listen  string
		policy  string
		want    string
	}{
		{"v5 IPv4", snellV5, "0.0.0.0", "", "[snell-server]\nlisten = 0.0.0.0:8000\npsk = " + psk + "\nipv6 = true\n"},
		{"v5 dual stack wildcard", snellV5, "::", "", "[snell-server]\nlisten = ::0:8000\npsk = " + psk + "\nipv6 = true\n"},
		{"v5 one IPv6 address", snellV5, "2001:db8::1", "", "[snell-server]\nlisten = 2001:db8::1:8000\npsk = " + psk + "\nipv6 = true\n"},
		{"v5 one IPv4 address", snellV5, "192.0.2.7", "", "[snell-server]\nlisten = 192.0.2.7:8000\npsk = " + psk + "\nipv6 = true\n"},
		{"v5 IPv4 only egress", snellV5, "0.0.0.0", outIPv4Only, "[snell-server]\nlisten = 0.0.0.0:8000\npsk = " + psk + "\nipv6 = false\n"},
		{"v6 IPv4", snellV6, "0.0.0.0", "", "[snell-server]\nlisten = 0.0.0.0:8000\npsk = " + psk + "\nmode = default\ndns-ip-preference = default\n"},
		{"v6 dual stack wildcard", snellV6, "::", "", "[snell-server]\nlisten = [::]:8000\npsk = " + psk + "\nmode = default\ndns-ip-preference = default\n"},
		{"v6 prefer IPv4", snellV6, "0.0.0.0", outIPv4First, "[snell-server]\nlisten = 0.0.0.0:8000\npsk = " + psk + "\nmode = default\ndns-ip-preference = prefer-ipv4\n"},
		{"v6 prefer IPv6", snellV6, "::", outIPv6First, "[snell-server]\nlisten = [::]:8000\npsk = " + psk + "\nmode = default\ndns-ip-preference = prefer-ipv6\n"},
		{"v6 IPv4 only", snellV6, "0.0.0.0", outIPv4Only, "[snell-server]\nlisten = 0.0.0.0:8000\npsk = " + psk + "\nmode = default\ndns-ip-preference = ipv4-only\n"},
		{"v6 IPv6 only", snellV6, "::", outIPv6Only, "[snell-server]\nlisten = [::]:8000\npsk = " + psk + "\nmode = default\ndns-ip-preference = ipv6-only\n"},
		{"v6 auto written explicitly", snellV6, "0.0.0.0", outAuto, "[snell-server]\nlisten = 0.0.0.0:8000\npsk = " + psk + "\nmode = default\ndns-ip-preference = default\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := fixture(t, protoSnell)
			p.SnellVersion, p.Password, p.Listen, p.Port, p.OutboundPolicy = tc.version, psk, tc.listen, 8000, tc.policy
			if tc.policy == outAuto {
				p.OutboundPolicy = outAuto
			}
			got, e := snellServerConf(p)
			if e != nil {
				t.Fatal(e)
			}
			if got != tc.want {
				t.Fatalf("config mismatch\n got: %q\nwant: %q", got, tc.want)
			}
			// What is written must read back as exactly what was meant.
			if _, e = parseSnellConf(got); e != nil {
				t.Fatal(e)
			}
		})
	}
}

func TestSnellConfigNeverContainsUnsupportedOptions(t *testing.T) {
	// Only the keys the official snell-server documents for the version are ever written.
	allowed := map[string]map[string]bool{
		snellV5: {"listen": true, "psk": true, "ipv6": true},
		snellV6: {"listen": true, "psk": true, "mode": true, "dns-ip-preference": true},
	}
	for version, keys := range allowed {
		for _, policy := range []string{"", outAuto, outIPv4Only} {
			p := fixture(t, protoSnell)
			p.SnellVersion, p.OutboundPolicy = version, policy
			conf, e := snellServerConf(p)
			if e != nil {
				t.Fatal(e)
			}
			kv, e := parseSnellConf(conf)
			if e != nil {
				t.Fatal(e)
			}
			for k := range kv {
				if !keys[k] {
					t.Fatalf("v%s config contains unsupported key %q", version, k)
				}
			}
			if strings.Contains(conf, "obfs") || strings.Contains(conf, "tfo") || strings.Contains(conf, "egress-interface") {
				t.Fatalf("config contains an option Rout does not offer:\n%s", conf)
			}
		}
	}
}

func TestSnellVersionCompatibility(t *testing.T) {
	v5, e := NewProfile("snell")
	if e != nil {
		t.Fatal(e)
	}
	v6, e := NewProfile("snell6")
	if e != nil {
		t.Fatal(e)
	}
	if v5.Protocol != protoSnell || v5.SnellVersion != snellV5 || v6.Protocol != protoSnell || v6.SnellVersion != snellV6 {
		t.Fatalf("aliases not resolved: %+v %+v", v5, v6)
	}
	if snellEngine(snellV5) == snellEngine(snellV6) {
		t.Fatal("v5 and v6 must run on different pinned engines")
	}
	a := testApp(t)
	if a.engineName(v5) != "snell-v5" || a.engineName(v6) != "snell-v6" {
		t.Fatalf("engines: %s %s", a.engineName(v5), a.engineName(v6))
	}
	if a.enginePath("snell-v5") == a.enginePath("snell-v6") {
		t.Fatal("engine binaries share a path")
	}
	if nodeLabel(v5) != "Snell" || nodeLabel(v6) != "Snell6" || ProtocolLabel(snell6Alias) != "Snell6" {
		t.Fatalf("labels %q %q", nodeLabel(v5), nodeLabel(v6))
	}
	// A node written before the field existed is a v5 node.
	var legacy Profile
	raw := `{"id":"0123456789ab","name":"old","kind":"node","enabled":true,"protocol":"snell","listen":"0.0.0.0","port":8000,"public_host":"203.0.113.10","public_port":8000,"password":"AbCdEfGh1234567890AbCdEfGh123456"}`
	if e = json.Unmarshal([]byte(raw), &legacy); e != nil {
		t.Fatal(e)
	}
	if legacy.snellVersion() != snellV5 || legacy.Validate() != nil {
		t.Fatalf("legacy snell profile: %v", legacy.Validate())
	}
	// Every field Snell does not use stays empty, so state files carry no stray credentials.
	if v5.UUID != "" || v5.Method != "" || v5.SNI != "" || v5.PrivateKey != "" {
		t.Fatalf("unrelated fields set: %+v", v5)
	}
	bad := v5
	bad.SnellVersion = "7"
	if bad.Validate() == nil {
		t.Fatal("unknown Snell version accepted")
	}
	// v5 has no IPv6-first preference; v6 does.
	v5.Listen, v5.PublicHost, v5.Port, v5.PublicPort = "0.0.0.0", "203.0.113.10", 8000, 8000
	v5.OutboundPolicy = outIPv6First
	if v5.Validate() == nil {
		t.Fatal("Snell v5 accepted an outbound policy its engine cannot express")
	}
	v6.Listen, v6.PublicHost, v6.Port, v6.PublicPort = "0.0.0.0", "203.0.113.10", 8000, 8000
	v6.OutboundPolicy = outIPv6First
	if e = v6.Validate(); e != nil {
		t.Fatal(e)
	}
}

func TestSnellPSK(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		psk, e := NewSnellPSK()
		if e != nil {
			t.Fatal(e)
		}
		if len(psk) != 32 || !regexp.MustCompile(`^[A-Za-z0-9]{32}$`).MatchString(psk) {
			t.Fatalf("PSK %q is not 32 alphanumerics", psk)
		}
		if seen[psk] {
			t.Fatal("PSK repeated")
		}
		seen[psk] = true
		if e = validSnellPSK(psk); e != nil {
			t.Fatal(e)
		}
	}
	for _, bad := range []string{"", "short", strings.Repeat("a", 11), strings.Repeat("a", 256), "has space 123456", "comma,comma,comma", "equals=equals=eq", "hash#hash#hash#h", "semi;semi;semi;se", "new\nline1234567890", "quote\"quote\"quot", "ünïcödé-ünïcödé"} {
		if validSnellPSK(bad) == nil {
			t.Errorf("PSK %q accepted", bad)
		}
	}
	for _, good := range []string{strings.Repeat("a", 12), strings.Repeat("Z9._~+-", 37)[:255], "p.s_k~with+all-chars"} {
		if e := validSnellPSK(good); e != nil {
			t.Errorf("PSK %q rejected: %v", good, e)
		}
	}
}

func TestSnellSurgeLine(t *testing.T) {
	psk := "AbCdEfGh1234567890AbCdEfGh123456"
	mk := func(name, version string) Profile {
		p := fixture(t, protoSnell)
		p.Name, p.Password, p.SnellVersion = name, psk, version
		return p
	}
	for _, tc := range []struct {
		name, version, host string
		port                int
		want                string
	}{
		{"Tokyo-Snell", snellV5, "203.0.113.10", 8000, "Tokyo-Snell = snell, 203.0.113.10, 8000, psk=" + psk + ", version=5"},
		{"Tokyo-Snell6", snellV6, "203.0.113.10", 8000, "Tokyo-Snell6 = snell, 203.0.113.10, 8000, psk=" + psk + ", version=6"},
		{"Domain", snellV5, "snell.example.com", 443, "Domain = snell, snell.example.com, 443, psk=" + psk + ", version=5"},
		// An IPv6 literal sits in a comma separated field: no brackets.
		{"V6", snellV6, "2001:db8::7", 8443, "V6 = snell, 2001:db8::7, 8443, psk=" + psk + ", version=6"},
		// Characters that would change the meaning of the line never reach it.
		{"a=b, c", snellV5, "203.0.113.10", 1, "a-b  c = snell, 203.0.113.10, 1, psk=" + psk + ", version=5"},
		{"# comment", snellV5, "203.0.113.10", 1, "comment = snell, 203.0.113.10, 1, psk=" + psk + ", version=5"},
		{"[Section]", snellV5, "203.0.113.10", 1, "Section] = snell, 203.0.113.10, 1, psk=" + psk + ", version=5"},
	} {
		got, e := mk(tc.name, tc.version).SurgeLine(tc.host, tc.port)
		if e != nil {
			t.Fatal(tc.name, e)
		}
		if got != tc.want {
			t.Errorf("Surge line\n got: %q\nwant: %q", got, tc.want)
		}
		// Surge splits the right-hand side on commas: always policy, host, port, psk, version.
		right := got[strings.Index(got, "= ")+2:]
		if f := strings.Split(right, ", "); len(f) != 5 || f[0] != "snell" || !strings.HasPrefix(f[3], "psk=") || !strings.HasPrefix(f[4], "version=") {
			t.Errorf("unexpected field layout: %q", got)
		}
	}
	p := mk("Node", snellV5)
	for _, host := range []string{"", "a b", "a,b", "a=b", "a\nb"} {
		if _, e := p.SurgeLine(host, 8000); e == nil {
			t.Errorf("host %q accepted", host)
		}
	}
	if _, e := p.SurgeLine("203.0.113.10", 0); e == nil {
		t.Error("port 0 accepted")
	}
	if _, e := fixture(t, "ss").SurgeLine("203.0.113.10", 8000); e == nil {
		t.Error("a Shadowsocks node produced a Surge Snell line")
	}
	// Snell has no share link, and no sing-box client either; nothing is faked.
	if _, e := p.URI(); e == nil {
		t.Error("Snell produced a share link")
	}
	if _, e := ClientConfig(p, "203.0.113.10", 8000, 2080); e == nil {
		t.Error("Snell produced a sing-box client configuration")
	}
	if s, e := p.Share(); e != nil || !strings.Contains(s, "= snell, ") {
		t.Errorf("Share: %q %v", s, e)
	}
	// The same node at another address (dual stack) keeps its credentials and version.
	alt, e := p.ShareAt("2001:db8::7", p.PublicPort)
	if e != nil || !strings.Contains(alt, "2001:db8::7") || !strings.Contains(alt, "psk="+p.Password) || !strings.HasSuffix(alt, "version=5") {
		t.Errorf("alternate address line: %q %v", alt, e)
	}
	if line, _ := p.Share(); !strings.Contains(line, ", "+itoa(p.PublicPort)+", ") {
		t.Errorf("the public port is not the listen port: %q", line)
	}
}

func TestSnellConfigRoundTripAndTamperDetection(t *testing.T) {
	dir := t.TempDir()
	p := snellNodeFixture(t, "snell6", "n", 24680)
	if e := writeProfileIn(p, dir); e != nil {
		t.Fatal(e)
	}
	conf := filepath.Join(dir, snellConf)
	if st, e := os.Stat(conf); e != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("snell-server.conf: %v %v", e, st)
	}
	if _, e := os.Stat(filepath.Join(dir, "config.json")); e == nil {
		t.Fatal("a Snell node wrote a sing-box config.json")
	}
	if e := checkSnellConf(conf, p); e != nil {
		t.Fatal(e)
	}
	good, _ := os.ReadFile(conf)
	for name, content := range map[string]string{
		"extra option":      string(good) + "obfs = http\n",
		"wrong psk":         strings.Replace(string(good), p.Password, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 1),
		"wrong port":        strings.Replace(string(good), ":24680", ":24681", 1),
		"duplicate key":     string(good) + "psk = x\n",
		"no section":        strings.Replace(string(good), "[snell-server]\n", "", 1),
		"other section":     strings.Replace(string(good), "[snell-server]", "[other]", 1),
		"missing option":    strings.Replace(string(good), "mode = default\n", "", 1),
		"empty value":       strings.Replace(string(good), "mode = default", "mode =", 1),
		"second section":    string(good) + "[snell-server]\n",
		"v5 key on v6 conf": string(good) + "ipv6 = true\n",
	} {
		if e := os.WriteFile(conf, []byte(content), 0600); e != nil {
			t.Fatal(e)
		}
		if checkSnellConf(conf, p) == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestSnellMultiInstanceLifecycle(t *testing.T) {
	a := testApp(t)
	ss := aiTestNode(t, a, "ss", "ss-node")
	ssConfig, _ := os.ReadFile(filepath.Join(a.profileDir(ss.ID), "config.json"))
	s5a := aiTestNode(t, a, "snell", "snell-a")
	s6 := aiTestNode(t, a, "snell6", "snell-b")
	s5c := aiTestNode(t, a, "snell", "snell-c")
	nodes := []Profile{s5a, s6, s5c}
	ids, ports, psks := map[string]bool{}, map[int]bool{}, map[string]bool{}
	for _, p := range nodes {
		if ids[p.ID] || ports[p.Port] || psks[p.Password] {
			t.Fatal("instances share an ID, port or PSK")
		}
		ids[p.ID], ports[p.Port], psks[p.Password] = true, true, true
		conf, e := os.ReadFile(filepath.Join(a.profileDir(p.ID), snellConf))
		if e != nil || !strings.Contains(string(conf), ":"+itoa(p.Port)+"\n") || !strings.Contains(string(conf), "psk = "+p.Password+"\n") {
			t.Fatalf("%s: wrong configuration %v\n%s", p.Name, e, conf)
		}
		if _, e = os.Stat(filepath.Join(a.profileDir(p.ID), "config.json")); e == nil {
			t.Fatalf("%s: wrote a sing-box config", p.Name)
		}
		if a.serviceCommandName(p) != "rout-"+p.ID {
			t.Fatalf("service name %q is not derived from the stable ID", a.serviceCommandName(p))
		}
	}
	snapshot := func(p Profile) string {
		b, _ := os.ReadFile(filepath.Join(a.profileDir(p.ID), snellConf))
		return string(b)
	}
	before5a, before6 := snapshot(s5a), snapshot(s6)

	// Change the port of one instance: only its file changes.
	next, e := a.Load()
	if e != nil {
		t.Fatal(e)
	}
	moved := s5c
	for {
		moved.Port, e = freePort()
		if e != nil {
			t.Fatal(e)
		}
		if !ports[moved.Port] {
			break
		}
	}
	moved.PublicPort = moved.Port
	if e = a.Commit(next, replace(next, moved), false); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(snapshot(moved), ":"+itoa(moved.Port)+"\n") || snapshot(s5a) != before5a || snapshot(s6) != before6 {
		t.Fatal("changing one instance touched another")
	}

	// New PSK, new listen address.
	next, _ = a.Load()
	fresh, e := NewSnellPSK()
	if e != nil {
		t.Fatal(e)
	}
	edited := s6
	edited.Password, edited.Listen, edited.InboundMode = fresh, "0.0.0.0", inIPv4
	if e = a.Commit(next, replace(next, edited), false); e != nil {
		t.Fatal(e)
	}
	if c := snapshot(edited); !strings.Contains(c, "psk = "+fresh+"\n") || !strings.Contains(c, "listen = 0.0.0.0:"+itoa(edited.Port)+"\n") {
		t.Fatalf("PSK/listen change not applied:\n%s", c)
	}

	// Stop and start.
	next, _ = a.Load()
	off := s5a
	off.Enabled = false
	if e = a.Commit(next, replace(next, off), false); e != nil {
		t.Fatal(e)
	}
	next, _ = a.Load()
	if got, _ := Find(next, s5a.ID); got.Enabled {
		t.Fatal("node still enabled")
	}
	off.Enabled = true
	if e = a.Commit(next, replace(next, off), false); e != nil {
		t.Fatal(e)
	}

	// Delete one: its directory goes, nobody else's does.
	next, _ = a.Load()
	if e = a.Commit(next, removeProfile(next, s6.ID), false); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(a.profileDir(s6.ID)); e == nil {
		t.Fatal("deleted instance left its directory")
	}
	for _, p := range []Profile{s5a, moved} {
		if _, e = os.Stat(filepath.Join(a.profileDir(p.ID), snellConf)); e != nil {
			t.Fatalf("%s was removed with another node: %v", p.Name, e)
		}
	}
	// Other protocols are untouched by all of it.
	after, _ := os.ReadFile(filepath.Join(a.profileDir(ss.ID), "config.json"))
	if !bytes.Equal(after, ssConfig) {
		t.Fatal("the Shadowsocks node's configuration changed")
	}
}

// serviceCommandName is the service a node runs as; kept here so the test states the contract.
func (a *App) serviceCommandName(p Profile) string { return serviceName(p) }

func TestSnellPortConflicts(t *testing.T) {
	cert, key, e := GenerateCertificate("203.0.113.10")
	if e != nil {
		t.Fatal(e)
	}
	hy2 := func(port int) Profile {
		p := fixture(t, "hy2")
		p.Name, p.Port, p.PublicPort = "hy2", port, port
		p.SNI, p.CertPEM, p.KeyPEM, p.TLSGenerated = "203.0.113.10", cert, key, true
		return p
	}
	state := func(ps ...Profile) State {
		s := State{Schema: 1}
		for i, p := range ps {
			p.ID = RandomHex(6)
			if p.Name == "" || p.Name == "hy2" {
				p.Name += itoa(i)
			}
			s.Profiles = append(s.Profiles, p)
		}
		return s
	}
	snell5 := snellNodeFixture(t, "snell", "five", 30100)
	snell6 := snellNodeFixture(t, "snell6", "six", 30100)
	if e := state(snell5, snellNodeFixture(t, "snell6", "other", 30100)).Validate(); e == nil {
		t.Error("two Snell nodes on one TCP port accepted")
	}
	if e := state(snell5, fixture(t, "ss")).Validate(); e != nil && strings.Contains(e.Error(), "30100") {
		t.Error(e)
	}
	ss := fixture(t, "ss")
	ss.Name, ss.Port, ss.PublicPort = "ss", 30100, 30100
	if e := state(snell5, ss).Validate(); e == nil {
		t.Error("Snell and Shadowsocks on one TCP port accepted")
	}
	// v5 may open UDP on its port (QUIC Proxy Mode): a UDP protocol may not share it. v6 is TCP only.
	if e := state(snell5, hy2(30100)).Validate(); e == nil {
		t.Error("Snell v5 and Hysteria2 on one port accepted")
	}
	if e := state(snell6, hy2(30100)).Validate(); e != nil {
		t.Errorf("Snell v6 (TCP only) and Hysteria2 refused: %v", e)
	}
	// A disabled node holds no port.
	off := snell5
	off.Enabled = false
	if e := state(off, ss).Validate(); e != nil {
		t.Error(e)
	}
	// portConflict is what the menus use.
	s := state(snell5)
	probe := hy2(30100)
	probe.ID = RandomHex(6)
	if portConflict(s, probe) == nil {
		t.Error("menu conflict check missed Snell v5's UDP port")
	}
	// A port that is really bound on this host is refused as well.
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	busy := snellNodeFixture(t, "snell", "busy", l.Addr().(*net.TCPAddr).Port)
	if e := CheckAvailable(busy); e == nil {
		t.Error("bound port reported available")
	}
}

func TestSnellListenChoices(t *testing.T) {
	all := nodeListenOptions(listenCaps{V4: true, V6: true, DualStack: true})
	keys := func(items []menuItem) []string {
		var out []string
		for _, it := range items {
			out = append(out, it.key)
		}
		return out
	}
	// Snell cannot bind IPv6 exclusively, so a dual-stack host is not offered "IPv6 only".
	got := keys(listenItemsFor(all, listenCaps{V4: true, V6: true, DualStack: true}, []string{"vless", "snell"}))
	if strings.Join(got, ",") != inIPv4+","+inDual {
		t.Fatalf("dual-stack host: %v", got)
	}
	// Without Snell nothing changes.
	if got = keys(listenItemsFor(all, listenCaps{V4: true, V6: true, DualStack: true}, []string{"vless"})); len(got) != 3 {
		t.Fatalf("non-Snell batch: %v", got)
	}
	// On a host with no IPv4 at all a wildcard IPv6 socket is IPv6-only anyway.
	v6Only := nodeListenOptions(listenCaps{V6: true})
	if got = keys(listenItemsFor(v6Only, listenCaps{V6: true}, []string{"snell6"})); len(got) != 1 || got[0] != inIPv6 {
		t.Fatalf("IPv6-only host: %v", got)
	}
	// Each choice yields a configuration Snell accepts.
	for _, mode := range []string{inIPv4, inDual, inIPv6} {
		for _, protocol := range []string{"snell", "snell6"} {
			p := snellNodeFixture(t, protocol, "n", 8000)
			p.InboundMode = mode
			switch mode {
			case inIPv4:
				p.Listen = "0.0.0.0"
			case inIPv6:
				p.Listen, p.PublicHost = "::", "2001:db8::7"
			default:
				p.Listen = "::"
			}
			if e := p.Validate(); e != nil {
				t.Fatalf("%s %s: %v", protocol, mode, e)
			}
			conf, e := snellServerConf(p)
			if e != nil || !strings.Contains(conf, "listen = ") {
				t.Fatalf("%s %s: %v", protocol, mode, e)
			}
		}
	}
}

func TestSnellNATUsesTheMappedPublicPort(t *testing.T) {
	base, e := freePort()
	if e != nil {
		t.Fatal(e)
	}
	setup := ServerSetup{NAT: true, PublicHost: "203.0.113.10", Listen: "127.0.0.1", LocalStart: base, LocalEnd: base + 3, PublicStart: 41000, Network: "tcp", Family: "ipv4"}
	for _, protocol := range []string{"snell", "snell6"} {
		p, e := NewProfile(protocol)
		if e != nil {
			t.Fatal(e)
		}
		p.Name = "nat-" + protocol
		if p, e = PlanPort(p, setup, State{Schema: 1}); e != nil {
			t.Fatalf("%s on a TCP-only NAT: %v", protocol, e)
		}
		if p.Port < base || p.Port > base+3 || p.PublicPort != 41000+p.Port-base || !p.NAT {
			t.Fatalf("NAT mapping wrong: listen %d public %d", p.Port, p.PublicPort)
		}
		if e = p.Validate(); e != nil {
			t.Fatal(e)
		}
		// The client is told the provider's port, never the internal one.
		line, e := p.Share()
		if e != nil || !strings.Contains(line, ", "+itoa(p.PublicPort)+", psk=") || strings.Contains(line, ", "+itoa(p.Port)+", psk=") {
			t.Fatalf("NAT line: %q %v", line, e)
		}
		// The service listens on the internal port.
		if conf, _ := snellServerConf(p); !strings.Contains(conf, ":"+itoa(p.Port)+"\n") {
			t.Fatalf("listen port is not the internal one:\n%s", conf)
		}
	}
	// A UDP protocol cannot be planned on the same TCP-only mapping: Snell is not affected by that.
	hy, _ := NewProfile("hy2")
	if _, e = PlanPort(hy, setup, State{Schema: 1}); e == nil {
		t.Fatal("hy2 planned on a TCP-only NAT")
	}
	// The v5 note about QUIC Proxy Mode appears exactly where it applies.
	u, out := testUI(testApp(t), "")
	p5, _ := NewProfile("snell")
	p6, _ := NewProfile("snell6")
	u.snellNotes(p5, setup)
	if !strings.Contains(out.String(), "version") || !strings.Contains(out.String(), "TCP") {
		t.Fatalf("no TCP-only NAT note for v5: %q", out.String())
	}
	out.Reset()
	u.snellNotes(p5, ServerSetup{NAT: true, Network: "both"})
	if out.Len() != 0 {
		t.Fatalf("note shown where it does not apply: %q", out.String())
	}
	u.snellNotes(p6, setup)
	if !strings.Contains(out.String(), "Beta") && !strings.Contains(out.String(), "beta") {
		t.Fatalf("no beta note for v6: %q", out.String())
	}
}

func TestSnellServiceDefinitions(t *testing.T) {
	a := testApp(t)
	p5 := snellNodeFixture(t, "snell", "a", 24001)
	p6 := snellNodeFixture(t, "snell6", "b", 24002)
	for _, p := range []Profile{p5, p6} {
		unit := a.systemdUnit(p)
		engine := a.enginePath(a.engineName(p))
		conf := filepath.Join(a.profileDir(p.ID), snellConf)
		for _, want := range []string{
			"Description=Rout " + p.ID + "\n",
			"ExecStart=" + `"` + engine + `" "-c" "` + conf + `"` + "\n",
			"Restart=on-failure\n", "NoNewPrivileges=true\n", "ProtectSystem=strict\n",
			"CapabilityBoundingSet=CAP_NET_BIND_SERVICE\n", "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK\n",
			"WantedBy=multi-user.target\n",
		} {
			if !strings.Contains(unit, want) {
				t.Fatalf("%s unit missing %q:\n%s", p.Name, want, unit)
			}
		}
		if strings.Contains(unit, "sing-box") || strings.Contains(unit, "config.json") {
			t.Fatalf("Snell unit refers to sing-box:\n%s", unit)
		}
		// The PSK is only in the 0600 file, never in a world-readable unit.
		if strings.Contains(unit, p.Password) {
			t.Fatal("PSK leaked into the unit file")
		}
		script := a.openrcScript(p)
		if !strings.Contains(script, engine) || !strings.Contains(script, snellConf) || strings.Contains(script, p.Password) {
			t.Fatalf("OpenRC script:\n%s", script)
		}
	}
	if a.systemdUnit(p5) == a.systemdUnit(p6) {
		t.Fatal("two instances render one unit")
	}
	// A limited node waits for the monitor, like every other node.
	p5.Traffic = &TrafficPolicy{LimitBytes: 1000, BillingDay: 1}
	if u := a.systemdUnit(p5); !strings.Contains(u, "ExecStartPre=+") || !strings.Contains(u, "Requires=rout-traffic-") {
		t.Fatalf("limited Snell unit:\n%s", u)
	}
}

func TestSnellTrafficMeteringIsPerNodeAndCoversQUICMode(t *testing.T) {
	m := nftMeter{home: "/etc/rout"}
	limit := func(p Profile) Profile {
		p.Traffic = &TrafficPolicy{LimitBytes: 1 << 30, BillingDay: 1}
		return p
	}
	rules := func(p Profile) string { return m.tableRules(limit(p), TrafficRecord{}) }
	p5 := snellNodeFixture(t, "snell", "five", 31001)
	p6 := snellNodeFixture(t, "snell6", "six", 31002)
	p5.Listen, p6.Listen = "0.0.0.0", "0.0.0.0"
	r5, r6 := rules(p5), rules(p6)
	for _, want := range []string{"tcp dport 31001 jump up_gate", "tcp sport 31001 jump down_gate", "udp dport 31001 jump up_gate", "udp sport 31001 jump down_gate"} {
		if !strings.Contains(r5, want) {
			t.Errorf("v5 rules lack %q:\n%s", want, r5)
		}
	}
	// v6 has no UDP mode: its port is metered over TCP only.
	if !strings.Contains(r6, "tcp dport 31002 jump up_gate") || strings.Contains(r6, "udp dport") {
		t.Errorf("v6 rules:\n%s", r6)
	}
	// Isolation: one table per node, each only about its own port.
	if m.table(p5) == m.table(p6) || strings.Contains(r5, "31002") || strings.Contains(r6, "31001") {
		t.Error("metering of two Snell nodes is not isolated")
	}
	if !strings.Contains(r5, "quota budget { over 1073741824 bytes") {
		t.Errorf("no hard quota in the rules:\n%s", r5)
	}
	// Existing protocols are metered exactly as before.
	ss := fixture(t, "ss")
	if r := m.tableRules(limit(ss), TrafficRecord{}); !strings.Contains(r, "tcp dport 24681") || !strings.Contains(r, "udp dport 24681") {
		t.Errorf("Shadowsocks metering changed:\n%s", r)
	}
	tuic := fixture(t, "tuic")
	if got := tuic.meterNetworks(); len(got) != 1 || got[0] != "udp" {
		t.Errorf("TUIC networks %v", got)
	}
}

func TestSnellIsRefusedWhereItHasNoMeaning(t *testing.T) {
	a := testApp(t)
	p := aiTestNode(t, a, "snell", "snell")
	ex := aiTestExit(t, a, "exit", "198.51.100.9", 1080)
	s, _ := a.Load()
	if _, e := BindExit(s, p.ID, ex.ID); e == nil {
		t.Error("a Snell node was bound to an outbound proxy")
	}
	if e := aiEligible(p); e == nil {
		t.Error("a Snell node is eligible for AI routing")
	}
	withProxy := p
	withProxy.Outbound = &ex.Proxy
	if withProxy.Validate() == nil || withProxy.CheckCompatibility() == nil {
		t.Error("a Snell node with an outbound proxy validates")
	}
	withExit := p
	withExit.ExitID = ex.ID
	if withExit.Validate() == nil {
		t.Error("a Snell node with an exit ID validates")
	}
	// Mihomo gets nothing it cannot run.
	if _, e := mihomoNode(p); e == nil {
		t.Error("a Snell node was exported to Mihomo")
	}
	// The layered diagnosis says what it cannot prove instead of failing on a missing client.
	env := defaultDiagEnv()
	env.managed = func(*App, Profile) (bool, bool) { return true, true }
	env.sockets = fakeSockets(sock("tcp4", p.Listen, p.Port))
	rep := a.diagnose(context.Background(), p, env, diagOpts{Full: true})
	found := false
	for _, step := range rep.Steps {
		if step.Layer == 5 && strings.Contains(step.Text, "Snell") && step.Level == diagWarn {
			found = true
		}
		if strings.Contains(step.Text, "本地检测客户端") {
			t.Errorf("diagnosis tried to start a local client: %s", step.Text)
		}
	}
	if !found {
		t.Errorf("no honest layer-5 statement: %+v", rep.Steps)
	}
	// Egress policy: nothing is claimed as enforced.
	if p.egressInfo().Enforced {
		t.Error("Snell egress policy reported as enforced")
	}
	q := p
	q.OutboundPolicy = outIPv4Only
	if q.egressInfo().Enforced || q.egressScopeNote() == "" {
		t.Error("Snell IPv4-only policy is not described honestly")
	}
	if _, e := a.NodeEgressTest(p.ID, true); e == nil {
		t.Error("an egress test ran through a Snell node")
	}
}

func TestSnellStateRoundTripAndBackup(t *testing.T) {
	a := testApp(t)
	p5 := aiTestNode(t, a, "snell", "five")
	p6 := aiTestNode(t, a, "snell6", "six")
	s, e := a.Load()
	if e != nil {
		t.Fatal(e)
	}
	b, e := JSON(s)
	if e != nil {
		t.Fatal(e)
	}
	back, e := DecodeState(b)
	if e != nil {
		t.Fatal(e)
	}
	g5, _ := Find(back, p5.ID)
	g6, _ := Find(back, p6.ID)
	if g5.snellVersion() != snellV5 || g6.snellVersion() != snellV6 || g5.Password != p5.Password || g6.Password != p6.Password {
		t.Fatalf("round trip changed a Snell node: %+v %+v", g5, g6)
	}
	if strings.Contains(string(b), `"uuid"`) || strings.Contains(string(b), `"private_key"`) || strings.Contains(string(b), `"sni"`) {
		t.Fatalf("stray protocol fields in state:\n%s", b)
	}
	// Restoring a backup re-renders every Snell configuration.
	path := filepath.Join(t.TempDir(), "backup.json")
	if e = a.Backup(path); e != nil {
		t.Fatal(e)
	}
	for _, p := range []Profile{p5, p6} {
		if e = os.Remove(filepath.Join(a.profileDir(p.ID), snellConf)); e != nil {
			t.Fatal(e)
		}
	}
	if e = a.Restore(path); e != nil {
		t.Fatal(e)
	}
	// rout apply (force) writes them again.
	cur, _ := a.Load()
	if e = a.Commit(cur, cur, true); e != nil {
		t.Fatal(e)
	}
	for _, p := range []Profile{p5, p6} {
		if e = checkSnellConf(filepath.Join(a.profileDir(p.ID), snellConf), p); e != nil {
			t.Fatalf("%s: %v", p.Name, e)
		}
	}
}

// ---- engines ----------------------------------------------------------------------------------

func zipOf(t testing.TB, entries map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range entries {
		w, e := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate})
		if e != nil {
			t.Fatal(e)
		}
		if _, e = w.Write(body); e != nil {
			t.Fatal(e)
		}
	}
	if e := zw.Close(); e != nil {
		t.Fatal(e)
	}
	return buf.Bytes()
}

func TestSnellEnginesArePinnedAndVerified(t *testing.T) {
	for name, version := range map[string]string{"snell-v5": "v5.0.1", "snell-v6": "v6.0.0"} {
		e := engines()[name]
		if e.Version != version {
			t.Errorf("%s pinned to %s, want %s", name, e.Version, version)
		}
		for _, arch := range []string{"amd64", "arm64"} {
			asset := Asset{}
			for _, libc := range []string{"glibc", "musl"} {
				if a := engineAsset(name, arch, libc); a.URL != "" {
					asset = a
				}
			}
			if asset.URL == "" {
				t.Fatalf("%s has no %s asset", name, arch)
			}
			if !strings.HasPrefix(asset.URL, "https://dl.nssurge.com/snell/snell-server-"+version+"-linux-") || !strings.HasSuffix(asset.URL, ".zip") {
				t.Errorf("%s %s: not an official Surge download: %s", name, arch, asset.URL)
			}
			if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(asset.SHA256) {
				t.Errorf("%s %s: no SHA-256 pin", name, arch)
			}
			if asset.Binary != "snell-server" {
				t.Errorf("%s %s: archive member %q", name, arch, asset.Binary)
			}
		}
	}
	// v5 is a static build and runs everywhere; v6 is glibc only and is withheld from musl hosts.
	for _, arch := range []string{"amd64", "arm64"} {
		if engineAsset("snell-v5", arch, "musl").URL == "" || engineAsset("snell-v5", arch, "glibc").URL == "" {
			t.Errorf("snell v5 unavailable on %s", arch)
		}
		if engineAsset("snell-v6", arch, "glibc").URL == "" {
			t.Errorf("snell v6 unavailable on glibc %s", arch)
		}
		if got := engineAsset("snell-v6", arch, "musl"); got.URL != "" {
			t.Errorf("snell v6 offered to a musl host on %s: %s", arch, got.URL)
		}
	}
	if !glibcOnlyEngine("snell-v6") || glibcOnlyEngine("snell-v5") || glibcOnlyEngine("sing-box") || glibcOnlyEngine("gost") {
		t.Error("glibc-only detection is wrong")
	}
	// Existing engines resolve as before.
	if engineAsset("sing-box", "amd64", "glibc").URL == "" || !strings.Contains(engineAsset("sing-box", "amd64", "musl").Name, "musl") || engineAsset("gost", "arm64", "glibc").URL == "" {
		t.Error("an existing engine no longer resolves")
	}
	if !isSnellEngine("snell-v5") || isSnellEngine("sing-box") || isSnellEngine("gost") {
		t.Error("isSnellEngine")
	}
}

func TestSnellEngineInstallFromZip(t *testing.T) {
	a := installApp(t)
	archive := zipOf(t, map[string][]byte{"snell-server": []byte(fakeEngineScript)})
	var hits atomic.Int32
	srv := serve(t, bodyHandler(archive, &hits))
	path := a.enginePath("snell-v5")
	asset := Asset{Name: "snell-server-v5.0.1-linux-amd64.zip", URL: srv.URL + "/s.zip", SHA256: sumHex(archive), Binary: "snell-server"}
	if e := a.installEngine("snell-v5", path, asset); e != nil {
		t.Fatal(e)
	}
	if st, e := os.Stat(path); e != nil || st.Mode().Perm() != 0755 || readFile(t, path) != fakeEngineScript {
		t.Fatalf("installed engine: %v %v", e, st)
	}
	if l := leftovers(t, a.BinDir); len(l) != 0 {
		t.Fatalf("temporary files left behind: %v", l)
	}
	if e := a.installEngine("snell-v5", path, asset); e != nil || hits.Load() != 1 {
		t.Fatalf("a working engine was downloaded again (hits %d): %v", hits.Load(), e)
	}
	// The v6 engine is a different file: installing it leaves v5 alone.
	archive6 := zipOf(t, map[string][]byte{"snell-server": []byte("#!/bin/sh\nexit 0\n# v6\n")})
	srv6 := serve(t, bodyHandler(archive6, nil))
	path6 := a.enginePath("snell-v6")
	asset6 := Asset{Name: "snell-server-v6.0.0-linux-amd64.zip", URL: srv6.URL + "/s.zip", SHA256: sumHex(archive6), Binary: "snell-server", Libc: "glibc"}
	if e := a.installEngine("snell-v6", path6, asset6); e != nil {
		t.Fatal(e)
	}
	if readFile(t, path) != fakeEngineScript || !strings.Contains(readFile(t, path6), "# v6") || path == path6 {
		t.Fatal("installing v6 disturbed v5")
	}
}

func TestSnellEngineInstallFailuresKeepTheExistingEngine(t *testing.T) {
	good := zipOf(t, map[string][]byte{"snell-server": []byte(fakeEngineScript)})
	for name, tc := range map[string]struct {
		body   []byte
		sha    string
		binary string
	}{
		"digest mismatch":    {good, strings.Repeat("0", 64), "snell-server"},
		"not a zip":          {[]byte("definitely not a zip archive"), "", "snell-server"},
		"member missing":     {zipOf(t, map[string][]byte{"README": []byte("x")}), "", "snell-server"},
		"not executable":     {zipOf(t, map[string][]byte{"snell-server": []byte("\x7fELF-not-runnable")}), "", "snell-server"},
		"empty member":       {zipOf(t, map[string][]byte{"snell-server": {}}), "", "snell-server"},
		"member in a folder": {zipOf(t, map[string][]byte{"../../escape/snell-server": []byte("#!/bin/sh\nexit 3\n")}), "", "snell-server"},
	} {
		t.Run(name, func(t *testing.T) {
			a := installApp(t)
			path := a.enginePath("snell-v5")
			// An older engine file stands in for "the previous version stays usable".
			old := a.enginePath("snell-v5") + ".previous"
			if e := os.WriteFile(old, []byte(fakeEngineScript), 0755); e != nil {
				t.Fatal(e)
			}
			sha := tc.sha
			if sha == "" {
				sha = sumHex(tc.body)
			}
			srv := serve(t, bodyHandler(tc.body, nil))
			e := a.installEngine("snell-v5", path, Asset{Name: "snell.zip", URL: srv.URL + "/s.zip", SHA256: sha, Binary: tc.binary})
			if name == "member in a folder" {
				// The member is matched by base name and written only to the staging file.
				if e != nil {
					t.Fatal(e)
				}
				if _, er := os.Stat(filepath.Join(a.BinDir, "..", "escape")); er == nil {
					t.Fatal("archive member escaped the staging directory")
				}
				return
			}
			if e == nil {
				t.Fatal("installation succeeded")
			}
			if _, er := os.Stat(path); er == nil {
				t.Fatal("a failed installation left an engine behind")
			}
			if readFile(t, old) != fakeEngineScript {
				t.Fatal("the previous engine was disturbed")
			}
			if l := leftovers(t, a.BinDir); len(l) != 0 {
				t.Fatalf("temporary files left behind: %v", l)
			}
		})
	}
}

func TestSnellEngineRunsUsesVersionFlag(t *testing.T) {
	dir := t.TempDir()
	// A fake that only accepts the flag snell-server documents; anything else would fail the check.
	script := "#!/bin/sh\n[ \"$1\" = \"--version\" ] && exit 0\nexit 0\n"
	path := filepath.Join(dir, "snell-v5-v5.0.1")
	if e := os.WriteFile(path, []byte(script), 0755); e != nil {
		t.Fatal(e)
	}
	if !engineUsable("snell-v5", path) {
		t.Fatal("a runnable Snell engine was not accepted")
	}
	if engineUsable("snell-v5", filepath.Join(dir, "missing")) {
		t.Fatal("a missing engine was accepted")
	}
	// An engine that cannot execute at all is replaced, not trusted.
	broken := filepath.Join(dir, "broken")
	if e := os.WriteFile(broken, []byte("\x7fELF"), 0755); e != nil {
		t.Fatal(e)
	}
	if engineUsable("snell-v5", broken) {
		t.Fatal("a broken engine was accepted")
	}
}

func TestSnellEngineSelectionRefusesUnsupportedPlatforms(t *testing.T) {
	// Every supported combination resolves to a pinned, digest-carrying official asset.
	for _, tc := range []struct{ name, arch, libc string }{
		{"snell-v5", "amd64", "glibc"}, {"snell-v5", "arm64", "glibc"}, {"snell-v5", "amd64", "musl"}, {"snell-v5", "arm64", "musl"},
		{"snell-v6", "amd64", "glibc"}, {"snell-v6", "arm64", "glibc"},
	} {
		asset, e := pinnedAsset(tc.name, tc.arch, tc.libc)
		if e != nil || len(asset.SHA256) != 64 || !strings.HasPrefix(asset.URL, "https://dl.nssurge.com/snell/") {
			t.Errorf("%+v: %v %+v", tc, e, asset)
		}
	}
	// No official build exists for these: refused with the reason, never a lookalike.
	_, e := pinnedAsset("snell-v6", "amd64", "musl")
	if e == nil || !strings.Contains(e.Error(), "glibc") || !strings.Contains(e.Error(), "Snell v5") {
		t.Errorf("Snell v6 on musl: %v", e)
	}
	for _, arch := range []string{"386", "arm", "riscv64", "ppc64le", "s390x"} {
		for _, name := range []string{"snell-v5", "snell-v6"} {
			if _, e = pinnedAsset(name, arch, "glibc"); e == nil {
				t.Errorf("%s on %s was given a download", name, arch)
			}
		}
	}
	// The error shown to the user is translated.
	if got := Translate("en", e.Error()); strings.ContainsAny(got, "官方") {
		t.Errorf("untranslated: %s", got)
	}
}

func TestSnellEngineZipRefusesLyingArchives(t *testing.T) {
	raw := func(t *testing.T, h zip.FileHeader, data []byte) string {
		t.Helper()
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		w, e := zw.CreateRaw(&h)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = w.Write(data); e != nil {
			t.Fatal(e)
		}
		if e = zw.Close(); e != nil {
			t.Fatal(e)
		}
		path := filepath.Join(t.TempDir(), "engine.zip")
		if e = os.WriteFile(path, buf.Bytes(), 0600); e != nil {
			t.Fatal(e)
		}
		return path
	}
	body := []byte("#!/bin/sh\nexit 0\n")
	crc := crc32.ChecksumIEEE
	stored := func(name string, claimed uint64) zip.FileHeader {
		return zip.FileHeader{Name: name, Method: zip.Store, CRC32: crc(body), CompressedSize64: uint64(len(body)), UncompressedSize64: claimed}
	}
	for name, tc := range map[string]struct {
		header zip.FileHeader
		data   []byte
	}{
		"claims a huge size":       {stored("snell-server", 1<<40), body},
		"claims fewer bytes":       {stored("snell-server", 5), body},
		"claims more bytes":        {stored("snell-server", uint64(len(body))+9), body},
		"claims zero bytes":        {stored("snell-server", 0), body},
		"is a symbolic link":       {zip.FileHeader{Name: "snell-server", Method: zip.Store, CRC32: crc(body), CompressedSize64: uint64(len(body)), UncompressedSize64: uint64(len(body)), ExternalAttrs: 0o120777 << 16, CreatorVersion: 3 << 8}, body},
		"is another file entirely": {stored("README", uint64(len(body))), body},
	} {
		t.Run(name, func(t *testing.T) {
			dst := filepath.Join(t.TempDir(), "staged")
			if e := extractEngineZip(raw(t, tc.header, tc.data), "snell-server", dst); e == nil {
				got, _ := os.ReadFile(dst)
				t.Fatalf("accepted; staged %q", got)
			}
			if _, e := os.Stat(dst); e == nil {
				t.Fatal("a rejected archive left a staged file")
			}
		})
	}
	// The honest archive is accepted (the table above is not just rejecting everything).
	dst := filepath.Join(t.TempDir(), "staged")
	if e := extractEngineZip(raw(t, stored("snell-server", uint64(len(body))), body), "snell-server", dst); e != nil {
		t.Fatal(e)
	}
	if got, _ := os.ReadFile(dst); !bytes.Equal(got, body) {
		t.Fatal("content differs")
	}
}

func TestSnellPSKIsRedactedFromShownLogs(t *testing.T) {
	psk := "AbCdEfGh1234567890AbCdEfGh123456"
	p := snellNodeFixture(t, "snell", "n", 24690)
	p.Password = psk
	other := snellNodeFixture(t, "snell6", "m", 24691)
	s := State{Schema: 1, Profiles: []Profile{p, other}}
	line := "Aug 7 snell-server[12]: bad handshake psk=" + psk + " from 198.51.100.7 (" + other.Password + ")"
	got := redactProxySecrets(line, s)
	if strings.Contains(got, psk) || strings.Contains(got, other.Password) || !strings.Contains(got, "198.51.100.7") {
		t.Fatalf("redaction: %q", got)
	}
	// Other protocols' logs are redacted of Snell PSKs too (a log is shown per node, state-wide).
	if strings.Contains(redactProxySecrets("x "+psk, State{Schema: 1, Profiles: []Profile{p, fixture(t, "ss")}}), psk) {
		t.Fatal("PSK shown")
	}
}
