package rout

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Remote Server exits and exit management (model level). Interactive flows are in
// exit_ui_test.go, real-engine behavior in the integration tests.

// remoteLink is the share link a node on another server would give out.
func remoteLink(t *testing.T, protocol, host string, port int) string {
	t.Helper()
	p, e := NewProfile(protocol)
	if e != nil {
		t.Fatal(e)
	}
	p.PublicHost, p.PublicPort, p.Name = host, port, "remote-"+protocol
	uri, e := p.URIAt(host, port)
	if e != nil {
		t.Fatal(e)
	}
	return uri
}

func remoteExit(t *testing.T, protocol, host string, port int) Exit {
	t.Helper()
	p, e := ParseRemoteNode(remoteLink(t, protocol, host, port))
	if e != nil {
		t.Fatalf("%s: %v", protocol, e)
	}
	return Exit{ID: RandomHex(6), Name: "R-" + protocol, Kind: exitRemote, Proxy: *p}
}

func TestParseRemoteNodeAcceptsRoutNodeLinks(t *testing.T) {
	for _, protocol := range []string{"vless", "anytls", "ss", "hy2", "tuic"} {
		p, e := ParseRemoteNode(remoteLink(t, protocol, "us-vps.example.net", 44275))
		if e != nil {
			t.Errorf("%s: %v", protocol, e)
			continue
		}
		if p.Protocol != proxyNode || p.Host != "us-vps.example.net" || p.Port != 44275 || p.Username != "" || p.Password != "" {
			t.Errorf("%s: %+v", protocol, p)
		}
		if e = p.Validate(); e != nil {
			t.Errorf("%s: %v", protocol, e)
		}
	}
	// IPv6 endpoints and a Trojan link.
	p, e := ParseRemoteNode("trojan://pw@[2001:db8::7]:443?sni=x.example#t")
	if e != nil || p.Host != "2001:db8::7" || p.Port != 443 {
		t.Fatalf("%+v %v", p, e)
	}
}

func TestParseRemoteNodeRefusesWhatCannotCarryTraffic(t *testing.T) {
	for name, link := range map[string]string{
		"empty":                 "",
		"spaces":                "vless://id@host.example:443 extra",
		"newline":               "vless://id@host.example:443\nvless://other@h:1",
		"http proxy url":        "http://host.example:3128",
		"socks":                 "socks5://u:p@host.example:1080",
		"bare host":             "host.example:443",
		"no credentials":        "vless://host.example:443?security=reality&pbk=k&sid=ab",
		"reality without key":   "vless://id@host.example:443?security=reality&sid=ab",
		"unsupported transport": "vless://id@host.example:443?security=tls&type=quic",
		"pinned hy2":            "hysteria2://pw@host.example:443?sni=x.example&insecure=1&pinSHA256=abcdef",
		"ss plugin":             "ss://2022-blake3-aes-128-gcm:key@host.example:8388?plugin=v2ray",
		"bad port":              "vless://id@host.example:70000?security=reality&pbk=k&sid=ab",
	} {
		if p, e := ParseRemoteNode(link); e == nil {
			t.Errorf("%s accepted: %+v", name, p)
		}
	}
}

func TestRemoteNodeProxyValidationAndConfiguration(t *testing.T) {
	e := remoteExit(t, "vless", "us-vps.example.net", 44275)
	// A node exit carries its credentials in the link, nowhere else.
	bad := e.Proxy
	bad.Username = "u"
	if bad.Validate() == nil {
		t.Error("account fields on a node exit accepted")
	}
	bad = e.Proxy
	bad.Host = "other.example"
	if bad.Validate() == nil {
		t.Error("host that disagrees with the link accepted")
	}
	plain := Proxy{Protocol: "socks5", Host: "h.example", Port: 1080, Username: "u", Password: "p", Link: "vless://x"}
	if plain.Validate() == nil {
		t.Error("a link on a SOCKS5 proxy accepted")
	}
	// The sing-box outbound is the link's own, tagged for routing, and nothing leaks into String.
	out := proxyConfig(e.Proxy)
	if out["tag"] != "egress" || out["type"] != "vless" || out["server"] != "us-vps.example.net" || out["server_port"] != 44275 {
		t.Fatalf("%v", out)
	}
	if got := e.Proxy.String(); got != "vless://us-vps.example.net:44275" || strings.Contains(got, "uuid") {
		t.Fatalf("String leaks or is wrong: %s", got)
	}
	if strings.Contains(fmtSprint(e.Proxy), e.Proxy.Link) || strings.Contains(fmt.Sprintf("%#v %+v %v", e.Proxy, e.Proxy, e.Proxy), e.Proxy.Link) {
		t.Fatal("a formatted proxy leaks the link")
	}
	// A stored link that no longer converts must fail closed, never fall back to direct.
	broken := e.Proxy
	broken.Link = "vless://@@"
	closed := proxyConfig(broken)
	if closed["type"] == "direct" || closed["server"] != "127.0.0.1" || closed["server_port"] != 1 {
		t.Fatalf("fail-closed outbound: %v", closed)
	}
}

func fmtSprint(p Proxy) string { return strings.Join([]string{p.String(), p.GoString()}, "|") }

func TestNodeWithRemoteExitRoutesEverythingThroughIt(t *testing.T) {
	e := remoteExit(t, "vless", "us-vps.example.net", 44275)
	node := fixture(t, "ss")
	proxy := e.Proxy
	node.Outbound, node.ExitID = &proxy, e.ID
	c, err := serverConfig(node, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	outs := c["outbounds"].([]any)
	if len(outs) != 1 || outs[0].(M)["type"] != "vless" || outs[0].(M)["tag"] != "egress" {
		t.Fatalf("outbounds %v", outs)
	}
	// Client UDP is rejected, TCP follows the exit, and final is the exit: no direct path.
	rules := c["route"].(M)["rules"].([]any)
	if rules[0].(M)["network"] != "udp" || rules[0].(M)["action"] != "reject" || c["route"].(M)["final"] != "egress" {
		t.Fatalf("rules %v final %v", rules, c["route"].(M)["final"])
	}
	for _, o := range outs {
		if o.(M)["type"] == "direct" {
			t.Fatal("a direct outbound exists next to the exit")
		}
	}
}

func TestRemoteExitKindAndTransportRules(t *testing.T) {
	vless := remoteExit(t, "vless", "us-vps.example.net", 443)
	hy2 := remoteExit(t, "hy2", "us-vps.example.net", 443)
	if vless.Capabilities().Reach != "tcp" || hy2.Capabilities().Reach != "udp" {
		t.Fatalf("reach %v / %v", vless.Capabilities(), hy2.Capabilities())
	}
	if !vless.Capabilities().TCP || vless.Capabilities().UDP {
		t.Fatal("capabilities must say TCP only (UDP is rejected on nodes with an outbound)")
	}
	s := State{Schema: 1, Exits: []Exit{vless}}
	if e := s.Validate(); e != nil {
		t.Fatal(e)
	}
	// A QUIC node behind a TCP-only NAT can never work.
	hy2.RemoteNetwork = "tcp"
	s.Exits = []Exit{hy2}
	e := s.Validate()
	if e == nil || !strings.Contains(e.Error(), "目前目标仅支持 TCP") {
		t.Fatalf("TCP-only NAT with a QUIC node: %v", e)
	}
	hy2.RemoteNetwork = "both"
	s.Exits = []Exit{hy2}
	if e = s.Validate(); e != nil {
		t.Fatal(e)
	}
	// Kind and declaration must agree.
	for name, ex := range map[string]Exit{
		"node link, plain kind":    {ID: "aaaaaaaaaaaa", Name: "x", Proxy: vless.Proxy},
		"network on a plain proxy": {ID: "aaaaaaaaaaaa", Name: "x", RemoteNetwork: "tcp", Proxy: Proxy{Protocol: "socks5", Host: "h.example", Port: 1080, Username: "u", Password: "p"}},
		"unknown kind":             {ID: "aaaaaaaaaaaa", Name: "x", Kind: "mirror", Proxy: vless.Proxy},
		"unknown network":          {ID: "aaaaaaaaaaaa", Name: "x", Kind: exitRemote, RemoteNetwork: "icmp", Proxy: vless.Proxy},
	} {
		if (State{Schema: 1, Exits: []Exit{ex}}).Validate() == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// Remote servers reached through an authenticated proxy are fine too.
	ok := Exit{ID: "aaaaaaaaaaaa", Name: "remote-socks", Kind: exitRemote, Proxy: Proxy{Protocol: "socks5", Host: "198.51.100.8", Port: 1080, Username: "u", Password: "p"}}
	if e = (State{Schema: 1, Exits: []Exit{ok}}).Validate(); e != nil {
		t.Fatal(e)
	}
	if ok.KindLabel() != "REMOTE·SOCKS5" || vless.KindLabel() != "REMOTE·VLESS" {
		t.Fatalf("labels %s %s", ok.KindLabel(), vless.KindLabel())
	}
	// An open proxy cannot be created: ParseProxy demands both account fields.
	for _, raw := range []string{"198.51.100.8:1080", "198.51.100.8:1080::", "198.51.100.8:1080:u:"} {
		if _, e := ParseProxy("socks5", raw); e == nil {
			t.Errorf("proxy without credentials accepted: %q", raw)
		}
	}
}

func TestLegacyExitsLoadAndStayPlainProxies(t *testing.T) {
	a := testApp(t)
	node := fixture(t, "ss")
	node.Port, _ = freePort()
	node.PublicPort = node.Port
	node.Outbound = &Proxy{Protocol: "http", Host: "192.0.2.1", Port: 80, Username: "u", Password: "p"}
	b, _ := json.Marshal(State{Schema: 1, Profiles: []Profile{node}})
	if e := AtomicWrite(filepath.Join(a.Home, "state.json"), b, 0600); e != nil {
		t.Fatal(e)
	}
	s, e := a.Load()
	if e != nil {
		t.Fatal(e)
	}
	if len(s.Exits) != 1 || s.Exits[0].Kind != "" || s.Exits[0].RemoteNetwork != "" || s.Exits[0].Proxy.Link != "" {
		t.Fatalf("migrated exit %+v", s.Exits)
	}
	n, _ := Find(s, node.ID)
	if n.ExitID != s.Exits[0].ID || n.Outbound == nil || *n.Outbound != s.Exits[0].Proxy {
		t.Fatal("node not linked to the migrated exit")
	}
	// Saved again, the file contains no field a previous version could not read.
	if e = a.Commit(s, s, true); e != nil {
		t.Fatal(e)
	}
	raw, _ := os.ReadFile(filepath.Join(a.Home, "state.json"))
	for _, f := range []string{`"kind": "remote"`, `"remote_network"`, `"link"`} {
		if strings.Contains(string(raw), f) {
			t.Errorf("legacy exit gained %s", f)
		}
	}
}

func TestEditingOneExitChangesOnlyItsOwnNodes(t *testing.T) {
	a := remoteExit(t, "vless", "a.example.net", 443)
	b := remoteExit(t, "ss", "b.example.net", 443)
	var s State
	s.Schema = 1
	for i, ex := range []Exit{a, b} {
		_ = i
		s = UpsertExit(s, ex)
	}
	next := 24700
	mk := func(name string, exit string) Profile {
		p := fixture(t, "ss")
		next++
		p.ID, p.Name, p.Port, p.PublicPort = RandomHex(6), name, next, next
		s = replace(s, p)
		if exit != "" {
			var e error
			if s, e = BindExit(s, p.ID, exit); e != nil {
				t.Fatal(e)
			}
		}
		return p
	}
	na, nb, nd := mk("on-a", a.ID), mk("on-b", b.ID), mk("direct", "")
	before := s.Clone()

	edited := a
	edited.Name = "A renamed"
	edited.Proxy = remoteExit(t, "anytls", "a2.example.net", 8443).Proxy
	after := UpsertExit(s, edited)

	gotA, _ := Find(after, na.ID)
	if gotA.Outbound == nil || *gotA.Outbound != edited.Proxy || gotA.ExitID != a.ID {
		t.Fatal("the node using the edited exit did not follow it")
	}
	for _, id := range []string{nb.ID, nd.ID} {
		was, _ := Find(before, id)
		now, _ := Find(after, id)
		if !reflect.DeepEqual(was, now) || !runtimeEqual(was, now) {
			t.Errorf("editing exit A touched unrelated node %s", was.Name)
		}
	}
	if !reflect.DeepEqual(before.Exits[1], after.Exits[1]) {
		t.Error("editing exit A touched exit B")
	}
	if e := after.Validate(); e != nil {
		t.Fatal(e)
	}
}

func TestDeletingAReferencedExitIsRefusedAndExplained(t *testing.T) {
	ex := remoteExit(t, "vless", "us-vps.example.net", 443)
	var s State
	s.Schema = 1
	s = UpsertExit(s, ex)
	n1, n2 := fixture(t, "ss"), fixture(t, "ss")
	n1.ID, n1.Name, n1.Port, n1.PublicPort = RandomHex(6), "tokyo", 24001, 24001
	n2.ID, n2.Name, n2.Port, n2.PublicPort = RandomHex(6), "osaka", 24002, 24002
	s = replace(replace(s, n1), n2)
	var e error
	if s, e = BindExit(s, n1.ID, ex.ID); e != nil {
		t.Fatal(e)
	}
	if s, e = BindExit(s, n2.ID, ex.ID); e != nil {
		t.Fatal(e)
	}
	refs := exitReferences(s, ex.ID)
	if len(refs.Nodes) != 2 || refs.Nodes[0].Name != "osaka" || refs.Nodes[1].Name != "tokyo" || refs.AI || refs.Empty() {
		t.Fatalf("references %+v", refs)
	}
	if _, e = DeleteExit(s, ex.ID); e == nil {
		t.Fatal("a referenced exit was deleted")
	}
	// Nothing was modified by the refusal.
	if len(s.Exits) != 1 {
		t.Fatal("exit list changed")
	}
	// AI routing counts as a reference too.
	s.AI = &AIRouting{Enabled: true, AIOutboundID: ex.ID}
	if !exitReferences(s, ex.ID).AI {
		t.Fatal("AI reference not reported")
	}
	// Unbind both nodes and drop the AI binding: now it can go.
	s.AI = nil
	for _, id := range []string{n1.ID, n2.ID} {
		if s, e = BindExit(s, id, ""); e != nil {
			t.Fatal(e)
		}
	}
	after, e := DeleteExit(s, ex.ID)
	if e != nil || len(after.Exits) != 0 || !exitReferences(after, ex.ID).Empty() {
		t.Fatalf("%v %+v", e, after.Exits)
	}
	// And the nodes still exist, running direct.
	if len(after.Profiles) != 2 {
		t.Fatal("deleting the exit removed nodes")
	}
}

func TestExitCredentialsAreRedactedEverywhere(t *testing.T) {
	ex := remoteExit(t, "vless", "us-vps.example.net", 443)
	uuid := strings.TrimPrefix(strings.SplitN(ex.Proxy.Link, "@", 2)[0], "vless://")
	s := State{Schema: 1, Exits: []Exit{ex}}
	text := "dial failed for " + ex.Proxy.Link + " user " + uuid + " via " + ex.Proxy.String()
	got := redactProxySecrets(text, s)
	if strings.Contains(got, uuid) || strings.Contains(got, ex.Proxy.Link) {
		t.Fatalf("not redacted: %s", got)
	}
	// The printable forms of an exit never contain the link.
	for _, v := range []string{ex.Proxy.String(), ex.Proxy.GoString(), ex.KindLabel(), ex.Proxy.hostPort()} {
		if strings.Contains(v, uuid) {
			t.Errorf("secret in %q", v)
		}
	}
	// The state file keeps it only in the 0600 state; the diagnostics text never prints it.
	rep := (diagReport{Steps: []diagStep{{Layer: 3, Text: ex.Proxy.hostPort()}}}).Text()
	if strings.Contains(rep, uuid) {
		t.Fatal("diagnostic report leaks the link")
	}
}

func TestExitCannotPointBackAtThisServer(t *testing.T) {
	node := fixture(t, "vless")
	node.Port, node.PublicHost, node.PublicPort = 24100, "203.0.113.10", 443
	s := State{Schema: 1, Profiles: []Profile{node}}
	local := map[string]bool{"10.0.0.5": true}
	for name, p := range map[string]Proxy{
		"loopback on a node port":    {Protocol: "socks5", Host: "127.0.0.1", Port: 24100, Username: "u", Password: "p"},
		"own interface address":      {Protocol: "socks5", Host: "10.0.0.5", Port: 24100, Username: "u", Password: "p"},
		"own public endpoint":        {Protocol: "http", Host: "203.0.113.10", Port: 443, Username: "u", Password: "p"},
		"remote link at own address": {Protocol: proxyNode, Host: "127.0.0.1", Port: 24100, Link: "vless://x@127.0.0.1:24100"},
	} {
		if exitSelfLoop(s, p, local) == nil {
			t.Errorf("%s not detected", name)
		}
	}
	if e := exitSelfLoop(s, Proxy{Protocol: "socks5", Host: "198.51.100.8", Port: 24100, Username: "u", Password: "p"}, local); e != nil {
		t.Errorf("a remote server on the same port number is fine: %v", e)
	}
}
