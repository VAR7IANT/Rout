package rout

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

func anytlsTLSFixture(t *testing.T, host string) Profile {
	t.Helper()
	p := fixture(t, protoAnyTLSTLS)
	cert, key, e := GenerateCertificate(host)
	if e != nil {
		t.Fatal(e)
	}
	p.PublicHost, p.SNI, p.CertPEM, p.KeyPEM, p.TLSGenerated = host, host, cert, key, true
	if e := p.Validate(); e != nil {
		t.Fatal(e)
	}
	return p
}

func TestAnyTLSTLSNodeModel(t *testing.T) {
	p := anytlsTLSFixture(t, "203.0.113.10")
	if p.PrivateKey != "" || p.PublicKey != "" || p.ShortID != "" {
		t.Fatal("a standard-TLS AnyTLS node got Reality keys")
	}
	if !p.certNode() || len(p.Networks()) != 1 || p.Networks()[0] != "tcp" {
		t.Fatal("AnyTLS TLS is a TCP node with a certificate file")
	}
	if _, ok := p.CertificateDays(time.Now()); !ok {
		t.Fatal("certificate expiry not tracked")
	}
	if _, e := RegenerateCertificate(p); e != nil {
		t.Fatal(e)
	}
	bad := p
	bad.SNI = "other.example"
	if bad.Validate() == nil {
		t.Fatal("certificate that does not match the SNI accepted")
	}
	bad = p
	bad.CertPEM = ""
	if bad.Validate() == nil {
		t.Fatal("missing certificate accepted")
	}

	cfg, e := serverConfig(p, "/etc/rout/n")
	if e != nil {
		t.Fatal(e)
	}
	in := cfg["inbounds"].([]any)[0].(M)
	tls := in["tls"].(M)
	if in["type"] != "anytls" || tls["certificate_path"] != "/etc/rout/n/tls.crt" || tls["key_path"] != "/etc/rout/n/tls.key" || tls["reality"] != nil || tls["server_name"] != p.SNI {
		t.Fatalf("server inbound: %v", in)
	}
	if users := in["users"].([]any); len(users) != 1 || users[0].(M)["password"] != p.Password {
		t.Fatal("server user")
	}

	client, e := ClientConfig(p, p.PublicHost, p.PublicPort, 2080)
	if e != nil {
		t.Fatal(e)
	}
	out := client["outbounds"].([]any)[0].(M)
	if out["type"] != "anytls" || out["password"] != p.Password || out["tls"].(M)["reality"] != nil || out["tls"].(M)["certificate"].([]string)[0] != p.CertPEM {
		t.Fatalf("client outbound: %v", out)
	}

	pin, _ := CertificatePin(p.CertPEM)
	link, e := p.URI()
	if e != nil {
		t.Fatal(e)
	}
	u, _ := url.Parse(link)
	q := u.Query()
	if u.Scheme != "anytls" || u.User.Username() != p.Password || q.Get("security") != "tls" || q.Get("sni") != p.SNI || q.Get("pinSHA256") != pin || q.Get("pbk") != "" {
		t.Fatalf("share link: %s", link)
	}
	if label, transport, ok := identifyLink(link); !ok || label != "AnyTLS" || transport != "tcp" {
		t.Fatalf("relay recognition: %s %s", label, transport)
	}
}

func TestAnyTLSTLSInMihomoAndSurge(t *testing.T) {
	p := anytlsTLSFixture(t, "2001:db8::7")
	pin, _ := CertificatePin(p.CertPEM)
	m, e := mihomoNode(p)
	if e != nil {
		t.Fatal(e)
	}
	if m["type"] != "anytls" || m["password"] != p.Password || m["sni"] != p.SNI || m["fingerprint"] != pin || m["skip-cert-verify"] == true || m["reality-opts"] != nil {
		t.Fatalf("Mihomo: %v", m)
	}
	line, e := p.SurgeLine(p.PublicHost, p.PublicPort)
	if e != nil {
		t.Fatal(e)
	}
	_, typ, host, port, kv := surgeFields(t, line)
	if typ != "anytls" || host != "2001:db8::7" || port != itoa(p.PublicPort) || kv["password"] != p.Password || kv["sni"] != p.SNI || kv["server-cert-fingerprint-sha256"] != pin || kv["skip-cert-verify"] == "true" {
		t.Fatalf("Surge: %s", line)
	}
	// The Reality variant is still refused, with the way out named.
	r := fixture(t, "anytls")
	if _, e := r.SurgeLine(r.PublicHost, r.PublicPort); e == nil || !strings.Contains(e.Error(), "标准 TLS") {
		t.Fatalf("AnyTLS Reality: %v", e)
	}
}

// A relay to a self-signed AnyTLS (TLS) node keeps the certificate pin in Mihomo and Surge.
func TestAnyTLSTLSRelayKeepsThePin(t *testing.T) {
	p := anytlsTLSFixture(t, "2001:db8::7")
	pin, _ := CertificatePin(p.CertPEM)
	raw, e := p.URI()
	if e != nil {
		t.Fatal(e)
	}
	target, _, e := ParseTarget(raw)
	if e != nil {
		t.Fatal(e)
	}
	relay := Profile{ID: RandomHex(6), Name: "Relay", Kind: "relay", Protocol: "tcp", Enabled: true, Listen: "127.0.0.1", Port: 24000, PublicHost: "198.51.100.9", PublicPort: 34000, Target: target, TargetURI: raw, RelayMode: relayRemote}
	m, e := mihomoRelay(relay)
	if e != nil {
		t.Fatal(e)
	}
	if m["type"] != "anytls" || m["server"] != "198.51.100.9" || m["fingerprint"] != pin || m["skip-cert-verify"] == true {
		t.Fatalf("Mihomo relay: %v", m)
	}
	line, e := relay.SurgeLine(relay.PublicHost, relay.PublicPort)
	if e != nil {
		t.Fatal(e)
	}
	_, typ, host, _, kv := surgeFields(t, line)
	if typ != "anytls" || host != "198.51.100.9" || kv["server-cert-fingerprint-sha256"] != pin || kv["skip-cert-verify"] == "true" {
		t.Fatalf("Surge relay: %s", line)
	}
}

func TestWebCreatesAnyTLSTLSNode(t *testing.T) {
	s := newAPIScene(t)
	list := jsonOf(t, s.c.get("/api/nodes"))
	var offered bool
	for _, p := range listOf(t, list, "protocols") {
		offered = offered || p["id"] == protoAnyTLSTLS
	}
	if !offered {
		t.Fatal("the panel does not offer AnyTLS TLS")
	}
	w := s.c.do("POST", "/api/nodes", map[string]any{"base_name": "Surge", "protocols": []string{protoAnyTLSTLS}})
	mustOK(t, w.Code, w.Body.String())
	nodes := listOf(t, jsonOf(t, w), "nodes")
	if len(nodes) != 1 || nodes[0]["protocol"] != protoAnyTLSTLS || nodes[0]["has_surge"] != true || nodes[0]["cert"] == nil {
		t.Fatalf("created: %v", nodes)
	}
	st := s.state(t)
	p, e := Find(st, nodes[0]["id"].(string))
	if e != nil || !p.TLSGenerated || p.SNI != p.PublicHost || p.Validate() != nil {
		t.Fatalf("stored node: %+v %v", p, e)
	}
}
