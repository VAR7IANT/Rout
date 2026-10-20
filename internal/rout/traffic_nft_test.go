package rout

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

func TestNFTTextOwnership(t *testing.T) {
	name := "rout_01234567_0123456789ab"
	for _, tc := range []struct {
		text  string
		valid bool
	}{
		{"table inet " + name + " {\n comment \"Rout traffic v1\"\n counter up { packets 0 bytes 0 }\n}", true},
		{"table inet " + name + " { comment \"Rout traffic v1\"; chain input { comment \"} comment \\\"Rout traffic v1\\\" {\"; } }", true},
		{"table inet " + name + " { chain input { comment \"Rout traffic v1\"; } }", false},
		{"table inet " + name + " { comment \"Rout traffic v10\"; }", false},
		{"table inet " + name + " { comment \"Rout traffic v1\"; comment \"other\"; }", false},
		{"table inet other { comment \"Rout traffic v1\"; }", false},
		{"table ip " + name + " { comment \"Rout traffic v1\"; }", false},
		{"table inet " + name + " { comment \"Rout traffic v1\"; } table inet other {}", false},
		{"table inet " + name + " { comment \"Rout traffic v1\";", false},
		{"table inet " + name + " { comment \"Rout traffic v1\n\"; }", false},
	} {
		if e := verifyNFTText([]byte(tc.text), name); (e == nil) != tc.valid {
			t.Fatalf("valid=%v error=%v text=%s", tc.valid, e, tc.text)
		}
	}
}

// Captured from real Debian 12 nft 1.0.6, not a hand-written approximation.
func TestNFTBookwormFixture(t *testing.T) {
	b, e := os.ReadFile("testdata/nft-1.0.6.json")
	if e != nil {
		t.Fatal(e)
	}
	text, e := os.ReadFile("testdata/nft-1.0.6.txt")
	if e != nil {
		t.Fatal(e)
	}
	entries, e := decodeNFT(b)
	if e != nil {
		t.Fatal(e)
	}
	name := entryTable(entries[1])
	if e = verifyNFTText(text, name); e != nil {
		t.Fatal(e)
	}
	if _, e = parseNFT(b); e == nil {
		t.Fatal("unattested JSON was trusted")
	}
	entries[1]["table"].(map[string]any)["comment"] = trafficTableComment
	canonical, _ := json.Marshal(map[string]any{"nftables": entries})
	first, e := parseNFT(canonical)
	if e != nil {
		t.Fatal(e)
	}
	// Normalization must be idempotent, retain quota SIZE, and ignore only state.
	second, e := parseEntries(entries)
	if e != nil || first != second {
		t.Fatal(first, second, e)
	}
	for _, entry := range entries {
		if c, ok := entry["counter"].(map[string]any); ok {
			c["bytes"] = json.Number("999")
			c["packets"] = json.Number("8")
		}
		if q, ok := entry["quota"].(map[string]any); ok {
			q["used"] = json.Number("999")
		}
	}
	third, e := parseEntries(entries)
	if e != nil || third.Hash != first.Hash || third.Up != 999 || third.Consumed != 999 {
		t.Fatal(third, first, e)
	}
	for _, entry := range entries {
		if q, ok := entry["quota"].(map[string]any); ok {
			q["bytes"] = json.Number("999999")
		}
	}
	resized, e := parseEntries(entries)
	if e != nil || resized.Hash == first.Hash {
		t.Fatal("quota size omitted from hash", e)
	}
	for _, word := range []string{"hook", "prio", "policy", "expr", "set", "quota"} {
		if !bytes.Contains(canonical, []byte(`"`+word+`"`)) {
			t.Fatal("fixture lost structure", word)
		}
	}
	for _, kind := range []string{"table", "counter", "chain", "rule", "quota", "set"} {
		t.Run("missing "+kind, func(t *testing.T) {
			es, _ := decodeNFT(canonical)
			var kept []map[string]any
			for _, entry := range es {
				if _, ok := entry[kind]; !ok {
					kept = append(kept, entry)
				}
			}
			es = kept
			if _, e := parseEntries(es); e == nil {
				t.Fatal("missing structure accepted", kind)
			}
		})
	}
	if _, e = decodeNFT(append(b, []byte(` {}`)...)); e == nil {
		t.Fatal("trailing JSON accepted")
	}
}
