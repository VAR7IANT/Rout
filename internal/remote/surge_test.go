package remote

import (
	"strings"
	"testing"
)

const surgeProfile = `[General]
loglevel = notify

[Proxy]
# comment
Direct = direct
HK Snell = snell, 203.0.113.5, 8443, psk=AbcdEfgh1234567890, version=4, reuse=true, tfo=true
JP Snell6 = snell, 2001:db8::5, 9443, psk=AbcdEfgh1234567890, version=6
Obfs Snell = snell, 203.0.113.6, 8444, psk=AbcdEfgh1234567890, version=3, obfs=http, obfs-host=bing.com
SS = ss, 203.0.113.7, 8388, encrypt-method=2022-blake3-aes-128-gcm, password=YWJjZGVmZ2hpamtsbW5vcA==, udp-relay=true
Trojan WS = trojan, t.example, 443, password=pw, sni=t.example, ws=true, ws-path=/ray, ws-headers=Host:t.example
HY2 = hysteria2, 203.0.113.8, 443, password=pw, sni=h.example, server-cert-fingerprint-sha256=AA00000000000000000000000000000000000000000000000000000000000000
TUIC = tuic-v5, 203.0.113.9, 443, uuid=00000000-0000-4000-8000-000000000001, password=pw, sni=t.example, alpn=h3
VLESS = vless, 203.0.113.10, 443, username=00000000-0000-4000-8000-000000000002, flow=xtls-rprx-vision, reality-public-key=PUBKEY, reality-short-id=abcd, sni=www.example.com
AnyTLS = anytls, 203.0.113.11, 443, password=pw, sni=a.example
Old TUIC = tuic, 203.0.113.12, 443, token=t
VMess = vmess, 203.0.113.13, 443, username=00000000-0000-4000-8000-000000000003
Chained = ss, 203.0.113.14, 8388, encrypt-method=aes-128-gcm, password=pw, underlying-proxy=HK Snell
Strange = trojan, 203.0.113.15, 443, password=pw, some-new-key=1

[Proxy Group]
Proxy = select, HK Snell, SS
`

func TestParseSurgeProfile(t *testing.T) {
	p, err := Parse([]byte(surgeProfile))
	if err != nil {
		t.Fatal(err)
	}
	if p.Format != "surge" {
		t.Fatalf("format %q", p.Format)
	}
	byName := map[string]Node{}
	for _, n := range p.Nodes {
		byName[n.Name] = n
	}
	want := []string{"HK Snell", "JP Snell6", "Obfs Snell", "SS", "Trojan WS", "HY2", "TUIC", "VLESS", "AnyTLS"}
	if len(p.Nodes) != len(want) {
		t.Fatalf("nodes: %d %+v\nissues: %+v", len(p.Nodes), p.Nodes, p.Issues)
	}
	for _, name := range want {
		if _, ok := byName[name]; !ok {
			t.Fatalf("missing %s", name)
		}
	}
	snell := byName["HK Snell"]
	if snell.Protocol != "snell" || snell.Link != "" || snell.LinkIssue == "" || snell.Clash["psk"] != "AbcdEfgh1234567890" || snell.Clash["version"] != int64(4) {
		t.Fatalf("snell: %+v", snell)
	}
	if _, kept := snell.Clash["reuse"]; kept {
		t.Fatal("tuning key carried over")
	}
	if o := byName["Obfs Snell"].Clash["obfs-opts"].(map[string]any); o["mode"] != "http" || o["host"] != "bing.com" {
		t.Fatalf("snell obfs: %v", o)
	}
	if n := byName["JP Snell6"]; n.Server != "2001:db8::5" || n.Clash["version"] != int64(6) {
		t.Fatalf("IPv6 snell6: %+v", n)
	}
	if n := byName["SS"]; n.Link == "" || !n.UDP || n.Clash["cipher"] != "2022-blake3-aes-128-gcm" {
		t.Fatalf("ss: %+v", n)
	}
	if n := byName["Trojan WS"]; n.Transport != "ws" || n.Clash["ws-opts"].(map[string]any)["path"] != "/ray" {
		t.Fatalf("trojan ws: %+v", n)
	}
	if n := byName["HY2"]; n.Clash["fingerprint"] != strings.ToLower("AA00000000000000000000000000000000000000000000000000000000000000") {
		t.Fatalf("hy2 pin: %+v", n)
	}
	if n := byName["TUIC"]; n.Protocol != "tuic" || n.Link == "" {
		t.Fatalf("tuic: %+v", n)
	}
	if n := byName["VLESS"]; n.Security != "reality" || n.Clash["uuid"] != "00000000-0000-4000-8000-000000000002" {
		t.Fatalf("vless: %+v", n)
	}
	reasons := map[string]string{}
	for _, is := range p.Issues {
		reasons[is.Name] = is.Level + ":" + is.Reason
	}
	for name, part := range map[string]string{"Direct": "skip:", "Old TUIC": "TUIC v4", "VMess": "vmess", "Chained": "underlying-proxy", "Strange": "some-new-key"} {
		if !strings.Contains(reasons[name], part) {
			t.Errorf("%s: %q", name, reasons[name])
		}
	}
	if _, grouped := reasons["Proxy"]; grouped {
		t.Error("a proxy group line was read as a node")
	}
}

func TestParseSurgeBareLines(t *testing.T) {
	// What Rout's own ?format=surge serves: bare lines, no section header.
	body := "Tokyo-Snell = snell, 198.51.100.1, 30001, psk=Q0123456789abcdefghijklmnopqrstu, version=5\nTokyo-SS = ss, 198.51.100.1, 30002, encrypt-method=2022-blake3-aes-128-gcm, password=YWJjZGVmZ2hpamtsbW5vcA==\n"
	p, err := Parse([]byte(body))
	if err != nil || p.Format != "surge" || len(p.Nodes) != 2 {
		t.Fatalf("%v %+v", err, p)
	}
	for _, bad := range []string{
		"X = snell, 198.51.100.1, 30001, psk=abc", // no version
		"X = snell, 198.51.100.1, 30001, psk=abc, version=9",
		"X = snell, 198.51.100.1, 30001, psk=abc, version=4, obfs-host=a.example",
		"X = trojan, 198.51.100.1, 443, password=p, ws-path=/x",
		"X = trojan, 198.51.100.1, 443, password=p, sni=off",
		"X = trojan, 198.51.100.1, 443, password=p, ws=true, ws-headers=Host:a|X-A:b",
	} {
		if q, err := Parse([]byte(bad)); err == nil && len(q.Nodes) != 0 {
			t.Errorf("accepted %q: %+v", bad, q.Nodes)
		}
	}
	// A share-link list is not mistaken for Surge.
	if q, err := Parse([]byte("trojan://pw@198.51.100.1:443?sni=a.example#A")); err != nil || q.Format != "links" {
		t.Fatalf("links: %v %+v", err, q)
	}
}
