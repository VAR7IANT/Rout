package rout

import (
	"encoding/json"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixture(t *testing.T, protocol string) Profile {
	t.Helper()
	p, e := NewProfile(protocol)
	if e != nil {
		t.Fatal(e)
	}
	p.Listen = "127.0.0.1"
	p.PublicHost = "203.0.113.10"
	p.Port = 24681
	p.PublicPort = 34681
	return p
}

func TestParseProxy(t *testing.T) {
	for _, tc := range []struct{ input, host, password string }{{"192.0.2.1:6719:user:p@ss:/?#%&$", "192.0.2.1", "p@ss:/?#%&$"}, {"[2001:db8::1]:1080:u:p:a:ss", "2001:db8::1", "p:a:ss"}, {"proxy.example:80:u:p", "proxy.example", "p"}} {
		p, e := ParseProxy("socks5", tc.input)
		if e != nil || p.Host != tc.host || p.Password != tc.password {
			t.Fatalf("parse mismatch: %v", e)
		}
		if e = p.Validate(); e != nil {
			t.Fatal(e)
		}
	}
	for _, bad := range []string{"host:0:u:p", "host:65536:u:p", "host:80::p", "host:80:u:", "host:80:u", "http://host:80:u:p", "[::1:80:u:p", "bad/host:80:u:p", "host:80:u:p\nextra"} {
		if _, e := ParseProxy("http", bad); e == nil {
			t.Errorf("accepted malformed input %q", bad)
		}
	}
	if _, e := ParseProxy("unknown", "host:80:u:p"); e == nil {
		t.Fatal("accepted unknown protocol")
	}
}
func TestRewritePreservesIdentity(t *testing.T) {
	raw := "vless://id@origin.example:443?security=reality&pbk=key&sid=abcd&type=ws&path=%2Fhello%3Fx%3D1#old"
	s, e := RewriteURI(raw, "2001:db8::1", 12345, "my node")
	if e != nil {
		t.Fatal(e)
	}
	u, _ := url.Parse(s)
	q := u.Query()
	if u.Host != "[2001:db8::1]:12345" || q.Get("sni") != "origin.example" || q.Get("host") != "origin.example" || q.Get("pbk") != "key" || q.Get("path") != "/hello?x=1" || u.Fragment != "my node" {
		t.Fatal("lost URI parameters")
	}
	raw = "trojan://password@origin.example:443?sni=cert.example&type=grpc&authority=service.example"
	s, e = RewriteURI(raw, "192.0.2.1", 30000, "name")
	if e != nil {
		t.Fatal(e)
	}
	u, _ = url.Parse(s)
	if u.Query().Get("sni") != "cert.example" || u.Query().Get("authority") != "service.example" {
		t.Fatal("changed explicit identity")
	}
}
func TestTargetNetwork(t *testing.T) {
	for _, tc := range []struct{ uri, network string }{{"vless://u@host:443?security=reality", "tcp"}, {"ss://abc@host:123", "both"}, {"hysteria2://p@host:123", "udp"}, {"tuic://u:p@[::1]:123", "udp"}} {
		_, n, e := ParseTarget(tc.uri)
		if e != nil || n != tc.network {
			t.Fatalf("wrong network: %v %s", e, n)
		}
	}
	if _, _, e := ParseTarget("ss://abc@host:123?plugin=v2ray-plugin"); e == nil {
		t.Fatal("accepted unsupported plugin")
	}
}
func TestStatePortsAndCredentials(t *testing.T) {
	p := fixture(t, "vless")
	if e := p.Validate(); e != nil {
		t.Fatal(e)
	}
	q := fixture(t, "ss")
	q.Port = p.Port
	if e := (State{1, []Profile{p, q}}).Validate(); e == nil {
		t.Fatal("missed conflict")
	}
	q.Enabled = false
	if e := (State{1, []Profile{p, q}}).Validate(); e != nil {
		t.Fatal(e)
	}
	p.PublicKey = "invalid"
	if e := p.Validate(); e == nil {
		t.Fatal("accepted wrong key")
	}
}
func TestNoDirectFallback(t *testing.T) {
	p := fixture(t, "vless")
	p.Outbound = &Proxy{"socks5", "192.0.2.99", 1080, "u", "secret"}
	c, e := serverConfig(p, t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	b, _ := JSON(c)
	if strings.Contains(string(b), `"type": "direct"`) {
		t.Fatal("proxy has direct fallback")
	}
	rules := c["route"].(M)["rules"].([]any)
	if rules[0].(M)["action"] != "reject" || rules[0].(M)["network"] != "udp" {
		t.Fatal("UDP not rejected")
	}
	in := c["inbounds"].([]any)[0].(M)
	if in["tag"] != "entry" {
		t.Fatal("missing inbound tag")
	}
}
func TestExportExcludesServerSecrets(t *testing.T) {
	p := fixture(t, "vless")
	p.Outbound = &Proxy{"http", "192.0.2.1", 80, "proxy-user", "proxy-password"}
	c, e := ClientConfig(p, p.PublicHost, p.PublicPort, 2080)
	if e != nil {
		t.Fatal(e)
	}
	b, _ := JSON(c)
	for _, s := range []string{p.PrivateKey, "proxy-user", "proxy-password"} {
		if strings.Contains(string(b), s) {
			t.Fatal("export leaked server credentials")
		}
	}
	uri, e := p.URI()
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(uri, p.PrivateKey) {
		t.Fatal("URI leaked key")
	}
}
func TestAtomicWritePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if e := os.WriteFile(path, []byte("old"), 0644); e != nil {
		t.Fatal(e)
	}
	if e := AtomicWrite(path, []byte("new"), 0600); e != nil {
		t.Fatal(e)
	}
	s, e := os.Stat(path)
	if e != nil || s.Mode().Perm() != 0600 {
		t.Fatal("unsafe permissions")
	}
}
func TestRollbackAndConflict(t *testing.T) {
	a := &App{Home: filepath.Join(t.TempDir(), "config"), BinDir: t.TempDir(), ServiceMode: "none"}
	path := a.enginePath("sing-box")
	if e := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0755); e != nil {
		t.Fatal(e)
	}
	p := fixture(t, "vless")
	p.Port, _ = freePort()
	p.PublicPort = p.Port
	old, _ := a.Load()
	next := replace(old, p)
	if e := a.Commit(old, next, false); e != nil {
		t.Fatal(e)
	}
	old, e := a.Load()
	if e != nil {
		t.Fatal(e)
	}
	before, _ := os.ReadFile(filepath.Join(a.profileDir(p.ID), "config.json"))
	p.Outbound = &Proxy{"http", "192.0.2.1", 80, "u", "p"}
	if e := os.WriteFile(path, []byte("#!/bin/sh\nexit 1\n"), 0755); e != nil {
		t.Fatal(e)
	}
	if e := a.Commit(old, replace(old, p), false); e == nil {
		t.Fatal("expected validator failure")
	}
	actual, e := a.Load()
	if e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(old)
	c, _ := json.Marshal(actual)
	if string(b) != string(c) {
		t.Fatal("state not rolled back")
	}
	after, _ := os.ReadFile(filepath.Join(a.profileDir(p.ID), "config.json"))
	if string(before) != string(after) {
		t.Fatal("config not rolled back")
	}
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	q := fixture(t, "vless")
	q.Port = l.Addr().(*net.TCPAddr).Port
	q.PublicPort = q.Port
	if e := a.Commit(old, replace(old, q), false); e == nil {
		t.Fatal("accepted occupied port")
	}
	if e := a.Commit(State{Schema: 1, Profiles: []Profile{}}, old, false); e == nil {
		t.Fatal("accepted stale state")
	}
}
