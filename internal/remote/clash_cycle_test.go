package remote

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// parseWithin fails the test (instead of hanging the suite) when parsing does not return.
func parseWithin(t *testing.T, d time.Duration, doc string) (Parsed, error) {
	t.Helper()
	type res struct {
		p   Parsed
		err error
	}
	ch := make(chan res, 1)
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	go func() {
		p, err := ParseClashContext(ctx, []byte(doc))
		ch <- res{p, err}
	}()
	select {
	case r := <-ch:
		return r.p, r.err
	case <-time.After(d + 5*time.Second):
		t.Fatalf("parser did not return for %.40q", doc)
		return Parsed{}, nil
	}
}

func TestYAMLMergeCycleRejected(t *testing.T) {
	cases := map[string]string{
		"reported loop":      "proxies: [{<<: &loop [*loop]}]\n",
		"loop in block form": "proxies:\n  - <<: &a\n      - *a\n",
		"nested sequences":   "proxies:\n  - <<: &a [[*a]]\n",
		"self mapping":       "proxies:\n  - &m {name: x, <<: *m}\n",
		"two node cycle":     "x: &a [&b [*a]]\nproxies:\n  - <<: *b\n",
		"self sequence item": "proxies: &p [*p]\n",
		"map holds itself":   "proxies:\n  - &m {name: n, self: *m}\n",
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			p, err := parseWithin(t, 3*time.Second, doc)
			if err == nil && len(p.Nodes) != 0 {
				t.Fatalf("cyclic document produced nodes: %+v", p.Nodes)
			}
			if err != nil && !errors.Is(err, errYAMLCycle) && !errors.Is(err, errTooComplex) {
				// A readable diagnostic is fine; it must not be a panic or a timeout.
				if errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("parser ran into the deadline: %v", err)
				}
			}
			if time.Since(start) > 2*time.Second {
				t.Fatalf("took %v", time.Since(start))
			}
		})
	}
}

func TestYAMLMergeCycleDiagnostic(t *testing.T) {
	_, err := parseWithin(t, 3*time.Second, "proxies: [{<<: &loop [*loop]}]\n")
	if !errors.Is(err, errYAMLCycle) {
		t.Fatalf("want cycle diagnostic, got %v", err)
	}
	if !strings.Contains(err.Error(), "循环") {
		t.Fatalf("diagnostic not readable: %v", err)
	}
}

func TestYAMLDeepNestingRejected(t *testing.T) {
	var b strings.Builder
	b.WriteString("proxies:\n  - name: x\n    deep: ")
	b.WriteString(strings.Repeat("[", 500))
	b.WriteString(strings.Repeat("]", 500))
	b.WriteString("\n")
	_, err := parseWithin(t, 3*time.Second, b.String())
	if !errors.Is(err, errTooComplex) {
		t.Fatalf("want complexity rejection, got %v", err)
	}
}

func TestYAMLAliasExpansionBombRejected(t *testing.T) {
	// Each level references the previous one ten times: 10^9 nodes if expanded.
	var b strings.Builder
	b.WriteString("a0: &a0 [x]\n")
	for i := 1; i <= 9; i++ {
		fmt.Fprintf(&b, "a%d: &a%d [%s]\n", i, i, strings.TrimSuffix(strings.Repeat(fmt.Sprintf("*a%d, ", i-1), 10), ", "))
	}
	b.WriteString("proxies:\n  - {name: bomb, data: *a9}\n")
	start := time.Now()
	_, err := parseWithin(t, 5*time.Second, b.String())
	if !errors.Is(err, errTooComplex) {
		t.Fatalf("want complexity rejection, got %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("bomb took %v", time.Since(start))
	}
}

func TestYAMLManyMergeSourcesBounded(t *testing.T) {
	var b strings.Builder
	b.WriteString("base: &b {k: v}\nproxies:\n  - <<: [")
	for i := 0; i < 600_000; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString("*b")
	}
	b.WriteString("]\n")
	if b.Len() > MaxYAMLBytes {
		t.Skip("document larger than the byte cap is rejected earlier")
	}
	if _, err := parseWithin(t, 5*time.Second, b.String()); err == nil {
		t.Fatal("expected rejection of an oversized merge expansion")
	}
}

func TestYAMLLegitMergeStillWorks(t *testing.T) {
	doc := `
base: &base {type: trojan, port: 443, sni: us.example.org}
more: &more {udp: true}
proxies:
  - {<<: *base, name: A, server: a.example.org, password: pw1}
  - {<<: [*base, *more], name: B, server: b.example.org, password: pw2, port: 8443}
  - {<<: [*more, [*base]], name: C, server: c.example.org, password: pw3}
`
	p, err := parseWithin(t, 3*time.Second, doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Nodes) != 3 {
		t.Fatalf("nodes=%d issues=%+v", len(p.Nodes), p.Issues)
	}
	if !strings.Contains(p.Nodes[1].Link, ":8443") {
		t.Fatalf("own key must override merged key: %s", p.Nodes[1].Link)
	}
}

func TestYAMLSharedAliasNotACycle(t *testing.T) {
	doc := "tpl: &t {type: ss, cipher: aes-128-gcm, password: x, port: 1}\nproxies:\n  - {<<: *t, name: a, server: a.example.org}\n  - {<<: *t, name: b, server: b.example.org}\n"
	p, err := parseWithin(t, 3*time.Second, doc)
	if err != nil || len(p.Nodes) != 2 {
		t.Fatalf("err=%v nodes=%d", err, len(p.Nodes))
	}
}

func TestParseContextCancelled(t *testing.T) {
	var b strings.Builder
	b.WriteString("proxies:\n")
	for i := 0; i < 1500; i++ {
		fmt.Fprintf(&b, "  - {name: n%d, type: ss, server: h%d.example.org, port: 1, cipher: aes-128-gcm, password: p}\n", i, i)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// Visits are only polled periodically; 1500 nodes cost well over one polling interval.
	_, err := ParseContext(ctx, []byte(b.String()))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	if _, err := ParseContext(context.Background(), []byte(b.String())); err != nil {
		t.Fatalf("uncancelled parse failed: %v", err)
	}
}

func TestImportKeepsDistinctConnectionConfigurations(t *testing.T) {
	uuid := "11111111-1111-4111-8111-111111111111"
	a := "vless://" + uuid + "@a.example.org:443?security=tls&sni=a.example.org&type=ws&path=%2Fone#A"
	b := "vless://" + uuid + "@a.example.org:443?security=tls&sni=a.example.org&type=ws&path=%2Ftwo#B"
	exact := "vless://" + uuid + "@a.example.org:443?security=tls&sni=a.example.org&type=ws&path=%2Fone#Renamed"
	p, err := Parse([]byte(a + "\n" + b + "\n" + exact + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Nodes) != 2 || p.Duplicates != 1 {
		t.Fatalf("nodes=%d duplicates=%d", len(p.Nodes), p.Duplicates)
	}
	if p.Nodes[0].ID == p.Nodes[1].ID || p.Nodes[0].Fingerprint == p.Nodes[1].Fingerprint {
		t.Fatal("variants must have their own identity")
	}
	// Identity depends on the connection settings, not on the order the provider lists them.
	r, _ := Parse([]byte(b + "\n" + a + "\n"))
	byPath := func(p Parsed) map[string]string {
		m := map[string]string{}
		for _, n := range p.Nodes {
			if strings.Contains(n.Link, "%2Fone") {
				m["one"] = n.ID
			} else {
				m["two"] = n.ID
			}
		}
		return m
	}
	if x, y := byPath(p), byPath(r); x["one"] != y["one"] || x["two"] != y["two"] || x["one"] == x["two"] {
		t.Fatalf("identities changed with provider order: %v vs %v", x, y)
	}
	plain := fingerprintOf("vless", "a.example.org", 443, uuid)
	for _, n := range p.Nodes {
		if n.Fingerprint == plain {
			t.Fatal("variants of one endpoint must not share the plain identity")
		}
	}
	// A node with a unique endpoint keeps the plain identity whatever its settings.
	u, _ := Parse([]byte(a + "\n"))
	if u.Nodes[0].Fingerprint != plain {
		t.Fatal("unique node lost its plain identity")
	}

	y := `
proxies:
  - {name: x1, type: trojan, server: t.example.org, port: 443, password: pw, network: ws, ws-opts: {path: /one}, sni: t.example.org}
  - {name: x2, type: trojan, server: t.example.org, port: 443, password: pw, network: ws, ws-opts: {path: /two}, sni: t.example.org}
  - {name: x3, type: trojan, server: t.example.org, port: 443, password: pw, network: ws, ws-opts: {path: /one}, sni: t.example.org}
`
	c, err := Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Nodes) != 2 || c.Duplicates != 1 || c.Nodes[0].ID == c.Nodes[1].ID {
		t.Fatalf("clash: nodes=%d dup=%d", len(c.Nodes), c.Duplicates)
	}
}
