package rout

import (
	"encoding/base64"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

func titleOf(t *testing.T, h map[string][]string) (profile, filename string) {
	t.Helper()
	pt := h["Profile-Title"]
	cd := h["Content-Disposition"]
	if len(pt) != 1 || len(cd) != 1 {
		t.Fatal("title headers missing")
	}
	raw, ok := strings.CutPrefix(pt[0], "base64:")
	if !ok {
		t.Fatal("Profile-Title not base64-prefixed")
	}
	b, e := base64.StdEncoding.DecodeString(raw)
	if e != nil {
		t.Fatal(e)
	}
	_, params, e := mime.ParseMediaType(cd[0])
	if e != nil {
		t.Fatal(e)
	}
	for _, v := range cd[0] {
		if v < 0x20 || v > 0x7e {
			t.Fatal("non-ASCII byte in header")
		}
	}
	rest := cd[0][strings.Index(cd[0], "filename*=UTF-8''")+len("filename*=UTF-8''"):]
	name, e := url.PathUnescape(rest)
	if e != nil || params["filename*"] == "" && name == "" {
		t.Fatal("bad filename*")
	}
	return string(b), name
}

func TestSubscriptionTitleHeaders(t *testing.T) {
	sc := newSubScene(t)
	h := sc.a.subscriptionHTTPHandler(sc.a.Load, func(string, ...any) {})
	sub, token := sc.create(t, "我的 订阅 ✈ \"x\";y", 0, 1)
	for _, q := range []string{"", "?format=base64", "?format=mihomo", "?format=clash"} {
		w := get(h, "GET", "/s/"+token+q)
		if w.Code != 200 {
			t.Fatal(q, w.Code)
		}
		p, f := titleOf(t, w.Header())
		if p != sub.Name || f != sub.Name {
			t.Fatalf("%q: title %q / %q", q, p, f)
		}
		hd := get(h, "HEAD", "/s/"+token+q)
		for _, k := range []string{"Profile-Title", "Content-Disposition", "Content-Length", "Content-Type"} {
			if hd.Header().Get(k) != w.Header().Get(k) {
				t.Fatal("HEAD differs for", k)
			}
		}
	}
	// Existing subscription is renamed: same token, new title, no rotation.
	if e := sc.a.RenameSubscription(sub.ID, "Renamed"); e != nil {
		t.Fatal(e)
	}
	w := get(h, "GET", "/s/"+token)
	if w.Code != 200 {
		t.Fatal("token changed by rename")
	}
	if p, _ := titleOf(t, w.Header()); p != "Renamed" {
		t.Fatal("rename not reflected")
	}
	// Error responses carry no title.
	if get(h, "GET", "/s/"+strings.Repeat("A", 43)).Header().Get("Profile-Title") != "" {
		t.Fatal("title leaked on 404")
	}
}

func TestSubscriptionTitleHeaderSafety(t *testing.T) {
	hdr := httpHeader()
	setSubscriptionTitle(hdr, "ok\r\nInjected: 1")
	for _, v := range hdr {
		for _, s := range v {
			if strings.ContainsAny(s, "\r\n") {
				t.Fatal("control char in header")
			}
		}
	}
	if len(hdr.Values("Injected")) != 0 {
		t.Fatal("header injection")
	}
}

func httpHeader() http.Header { return http.Header{} }

func TestCompactBannerKeepsCredit(t *testing.T) {
	for _, w := range []int{10, 20, 30, 38} {
		for _, color := range []bool{false, true} {
			out := renderLogo(w, color, false)
			plainOut := stripANSI(out)
			if !strings.Contains(plainOut, "VAR7IANT") {
				t.Fatalf("width %d lost credit: %q", w, plainOut)
			}
			for _, line := range strings.Split(strings.TrimRight(plainOut, "\n"), "\n") {
				if displayWidth(line) > w && w >= 20 {
					t.Fatalf("width %d overflows: %q", w, line)
				}
			}
		}
	}
	if !strings.Contains(renderLogo(30, false, false), "Support by VAR7IANT") {
		t.Fatal("full credit missing at 30 columns")
	}
}

var ansiSeq = regexp.MustCompile("\x1b\\[[0-9;]*m")

func stripANSI(s string) string { return ansiSeq.ReplaceAllString(s, "") }
