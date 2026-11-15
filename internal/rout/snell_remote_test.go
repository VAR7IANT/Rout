package rout

import (
	"strings"
	"testing"
)

func TestSnellRemoteExitFromSurgeLine(t *testing.T) {
	// A line as another Rout prints it for its Snell v5 node.
	p, e := ParseRemoteNode("Tokyo-Snell = snell, 198.51.100.7, 30001, psk=Q0123456789abcdefghijklmnopqrstu, version=5")
	if e != nil {
		t.Fatal(e)
	}
	if p.Protocol != proxyNode || p.Host != "198.51.100.7" || p.Port != 30001 || p.Kind() != "snell" || !strings.HasPrefix(p.Link, "snell://") {
		t.Fatalf("proxy: %#v %s", p, p.Link)
	}
	if e = p.Validate(); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(p.String(), "Q0123456789") {
		t.Fatal("the PSK leaked into the proxy's display form")
	}
	out := proxyConfig(*p)
	if out["type"] != "snell" || out["tag"] != "egress" || out["version"] != 4 || out["psk"] != "Q0123456789abcdefghijklmnopqrstu" || out["server"] != "198.51.100.7" || out["server_port"] != 30001 {
		t.Fatalf("a v5 server is reached as v4: %v", out)
	}

	// v6, IPv6, and obfs for v4.
	p6, e := ParseRemoteNode("JP = snell, 2001:db8::7, 30002, psk=Q0123456789abcdefghijklmnopqrstu, version=6, reuse=true")
	if e != nil {
		t.Fatal(e)
	}
	if out := proxyConfig(*p6); out["version"] != 6 || out["server"] != "2001:db8::7" {
		t.Fatalf("v6: %v", out)
	}
	p4, e := ParseRemoteNode("O = snell, 198.51.100.8, 30003, psk=Q0123456789abcdefghijklmnopqrstu, version=4, obfs=http, obfs-host=bing.com")
	if e != nil {
		t.Fatal(e)
	}
	if out := proxyConfig(*p4); out["obfs_mode"] != "http" || out["obfs_host"] != "bing.com" {
		t.Fatalf("obfs: %v", out)
	}
	// The link survives a relay rewrite (exit chains) with its credentials.
	re, e := RewriteURI(p4.Link, "203.0.113.1", 40000, "via relay")
	if e != nil {
		t.Fatal(e)
	}
	got, e := ParseRemoteNode(re)
	if e != nil || got.Host != "203.0.113.1" || got.Port != 40000 || proxyConfig(*got)["obfs_host"] != "bing.com" {
		t.Fatalf("rewrite: %s %v", re, e)
	}

	for _, bad := range []string{
		"X = snell, 198.51.100.7, 30001, psk=abc",                           // no version
		"X = snell, 198.51.100.7, 30001, psk=abc, version=3",                // sing-box has no v3 client
		"X = snell, 198.51.100.7, 30001, version=4",                         // no PSK
		"X = snell, 198.51.100.7, 30001, psk=abc, version=6, obfs=http",     // v6 has no obfs
		"X = snell, 198.51.100.7, 30001, psk=abc, version=4, obfs-host=a.b", // host without mode
		"X = snell, 198.51.100.7, 30001, psk=abc, version=4, underlying-proxy=Y",
		"X = ss, 198.51.100.7, 30001, encrypt-method=aes-128-gcm, password=p", // only Snell lines
		"snell://abc@198.51.100.7:30001?version=4&evil=1",
	} {
		if _, e := ParseRemoteNode(bad); e == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestWebCreatesSnellRemoteExit(t *testing.T) {
	s := newAPIScene(t)
	w := s.c.do("POST", "/api/exits", map[string]any{"name": "far-snell", "protocol": "remote", "link": "Far = snell, 198.51.100.9, 30001, psk=Q0123456789abcdefghijklmnopqrstu, version=6"})
	mustOK(t, w.Code, w.Body.String())
	ex := jsonOf(t, w)["exit"].(map[string]any)
	if ex["protocol"] != "snell" || strings.Contains(w.Body.String(), "Q0123456789") {
		t.Fatalf("exit view: %s", w.Body.String())
	}
}
