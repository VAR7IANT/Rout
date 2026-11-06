package rout

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var hanRe = regexp.MustCompile(`[\x{3400}-\x{9fff}]`)

func dualRoutes() familyRoutes { return familyRoutes{V4: true, V6: true} }

// egressFake is a controlled environment for the egress test: what the host can do and what a
// request through the node achieved.
type egressFake struct {
	routes         familyRoutes
	hostV4, hostV6 string
	lit            map[string]literalTarget
	hostLitErr     map[string]error
	probe          egressProbe
}

func (f egressFake) env() egressEnv {
	return egressEnv{
		routes:   func() familyRoutes { return f.routes },
		hostIP:   func(n string) string { return map[string]string{"tcp4": f.hostV4, "tcp6": f.hostV6}[n] },
		hostDNS:  func(n string) bool { return map[string]string{"tcp4": f.hostV4, "tcp6": f.hostV6}[n] != "" },
		literals: func() map[string]literalTarget { return f.lit },
		hostLiteral: func(n string, _ literalTarget) error {
			return f.hostLitErr[n]
		},
		through: func(*App, Profile, string, int, bool, map[string]literalTarget) egressProbe { return f.probe },
	}
}

var (
	litTargets = map[string]literalTarget{"tcp4": {IP: "203.0.113.50", Host: "api4.example.test"}, "tcp6": {IP: "2001:db8::50", Host: "api6.example.test"}}
	errBlocked = errors.New("connection refused")
)

func blocked() literalProbe { return literalProbe{Tried: true, Err: errBlocked} }
func allowed() literalProbe { return literalProbe{Tried: true} }

func egressNode(t *testing.T, a *App, policy string, proxy *Proxy) Profile {
	t.Helper()
	n := aiTestNode(t, a, "vless", "Turkey-VLESS")
	s := mustLoad(t, a)
	n.OutboundPolicy, n.Outbound = policy, proxy
	if e := a.Commit(s, replace(s, n), false); e != nil {
		t.Fatal(e)
	}
	return n
}

func checkOf(rep EgressReport, key string) (EgressCheck, bool) {
	for _, c := range rep.Checks {
		if c.Key == key {
			return c, true
		}
	}
	return EgressCheck{}, false
}

// ---- the evaluation of a measurement ---------------------------------------------------------------

func TestEgressTestVerdicts(t *testing.T) {
	v4err := errors.New("refused")
	cases := []struct {
		name   string
		policy string
		proxy  *Proxy
		fake   egressFake
		want   string            // overall result
		checks map[string]string // key -> status
	}{
		{
			name:   "IPv6 only holds: IPv6 works, IPv4 fails through the node while the host can use it",
			policy: outIPv6Only,
			fake: egressFake{routes: dualRoutes(), hostV4: "203.0.113.10", hostV6: "2001:db8::10", lit: litTargets,
				probe: egressProbe{V6: "2001:db8::10", ErrV4: v4err, Lit4: blocked(), Lit6: allowed()}},
			want:   egressPass,
			checks: map[string]string{"allowed": egressPass, "denied_name": egressPass, "denied_literal": egressPass},
		},
		{
			name:   "IPv6 only is NOT holding: the node still egresses over IPv4",
			policy: outIPv6Only,
			fake: egressFake{routes: dualRoutes(), hostV4: "203.0.113.10", hostV6: "2001:db8::10", lit: litTargets,
				probe: egressProbe{V4: "203.0.113.10", V6: "2001:db8::10", Lit4: allowed(), Lit6: allowed()}},
			want:   egressFail,
			checks: map[string]string{"allowed": egressPass, "denied_name": egressFail, "denied_literal": egressFail},
		},
		{
			name:   "only the literal leaks (resolver strategy without the family rule)",
			policy: outIPv6Only,
			fake: egressFake{routes: dualRoutes(), hostV4: "203.0.113.10", hostV6: "2001:db8::10", lit: litTargets,
				probe: egressProbe{V6: "2001:db8::10", ErrV4: v4err, Lit4: allowed(), Lit6: allowed()}},
			want:   egressFail,
			checks: map[string]string{"denied_name": egressPass, "denied_literal": egressFail},
		},
		{
			name:   "unprovable: the host cannot use IPv4 either, so a failure through the node proves nothing",
			policy: outIPv6Only,
			fake: egressFake{routes: familyRoutes{V6: true}, hostV6: "2001:db8::10", lit: litTargets,
				hostLitErr: map[string]error{"tcp4": errBlocked},
				probe:      egressProbe{V6: "2001:db8::10", ErrV4: v4err, Lit4: blocked(), Lit6: allowed()}},
			want:   egressInconclusive,
			checks: map[string]string{"allowed": egressPass, "denied_name": egressInconclusive, "denied_literal": egressInconclusive},
		},
		{
			name:   "unprovable: the test site gave no IPv4 address to try",
			policy: outIPv6Only,
			fake: egressFake{routes: dualRoutes(), hostV4: "203.0.113.10", hostV6: "2001:db8::10", lit: map[string]literalTarget{"tcp6": litTargets["tcp6"]},
				probe: egressProbe{V6: "2001:db8::10", ErrV4: v4err}},
			want:   egressInconclusive,
			checks: map[string]string{"denied_name": egressPass, "denied_literal": egressInconclusive},
		},
		{
			name:   "IPv6 only on a host without IPv6: reported, not hidden",
			policy: outIPv6Only,
			fake: egressFake{routes: familyRoutes{V4: true}, hostV4: "203.0.113.10", lit: litTargets,
				probe: egressProbe{ErrV4: v4err, ErrV6: v4err, Lit4: blocked(), Lit6: blocked()}},
			want:   egressFail,
			checks: map[string]string{"allowed": egressFail},
		},
		{
			name:   "IPv4 only holds",
			policy: outIPv4Only,
			fake: egressFake{routes: dualRoutes(), hostV4: "203.0.113.10", hostV6: "2001:db8::10", lit: litTargets,
				probe: egressProbe{V4: "203.0.113.10", ErrV6: v4err, Lit4: allowed(), Lit6: blocked()}},
			want:   egressPass,
			checks: map[string]string{"allowed": egressPass, "denied_name": egressPass, "denied_literal": egressPass},
		},
		{
			name:   "IPv4 only is NOT holding",
			policy: outIPv4Only,
			fake: egressFake{routes: dualRoutes(), hostV4: "203.0.113.10", hostV6: "2001:db8::10", lit: litTargets,
				probe: egressProbe{V4: "203.0.113.10", V6: "2001:db8::10", Lit4: allowed(), Lit6: allowed()}},
			want:   egressFail,
			checks: map[string]string{"denied_name": egressFail, "denied_literal": egressFail},
		},
		{
			name:   "IPv6 first needs no proof of exclusion; both families may work",
			policy: outIPv6First,
			fake: egressFake{routes: dualRoutes(), hostV4: "203.0.113.10", hostV6: "2001:db8::10", lit: litTargets,
				probe: egressProbe{V4: "203.0.113.10", V6: "2001:db8::10"}},
			want:   egressPass,
			checks: map[string]string{"reach": egressPass, "preference": egressInfo},
		},
		{
			name:   "auto: the node reaches the Internet",
			policy: "",
			fake: egressFake{routes: familyRoutes{V4: true}, hostV4: "203.0.113.10", lit: litTargets,
				probe: egressProbe{V4: "203.0.113.10", ErrV6: v4err}},
			want:   egressPass,
			checks: map[string]string{"reach": egressPass},
		},
		{
			name:   "no family works through the node",
			policy: "",
			fake: egressFake{routes: dualRoutes(), hostV4: "203.0.113.10", lit: litTargets,
				probe: egressProbe{ErrV4: v4err, ErrV6: v4err}},
			want:   egressFail,
			checks: map[string]string{"reach": egressFail},
		},
		{
			name:   "outbound proxy: connectivity is shown, the policy is NOT claimed",
			policy: outIPv6Only,
			proxy:  &Proxy{Protocol: "socks5", Host: "proxy.example.net", Port: 1080, Username: "u", Password: "p"},
			fake: egressFake{routes: dualRoutes(), hostV4: "203.0.113.10", hostV6: "2001:db8::10", lit: litTargets,
				probe: egressProbe{V4: "198.51.100.77", ErrV6: v4err}},
			want:   egressInconclusive,
			checks: map[string]string{"scope": egressInconclusive, "reach": egressPass},
		},
		{
			name:   "outbound proxy that does not work is a failure, not 'inconclusive'",
			policy: outIPv4Only,
			proxy:  &Proxy{Protocol: "socks5", Host: "proxy.example.net", Port: 1080, Username: "u", Password: "p"},
			fake: egressFake{routes: dualRoutes(), hostV4: "203.0.113.10", lit: litTargets,
				probe: egressProbe{ErrV4: v4err, ErrV6: v4err}},
			want:   egressFail,
			checks: map[string]string{"scope": egressInconclusive, "reach": egressFail},
		},
		{
			name:   "the test client could not start",
			policy: outIPv6Only,
			fake:   egressFake{routes: dualRoutes(), probe: egressProbe{ClientErr: errors.New("engine missing")}},
			want:   egressFail,
			checks: map[string]string{"client": egressFail},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := testApp(t)
			n := egressNode(t, a, c.policy, c.proxy)
			rep, e := a.nodeEgressTest(n.ID, false, c.fake.env())
			if e != nil {
				t.Fatal(e)
			}
			if rep.Result != c.want {
				t.Fatalf("result %q, want %q\n%+v", rep.Result, c.want, rep.Checks)
			}
			for key, status := range c.checks {
				got, ok := checkOf(rep, key)
				if !ok || got.Status != status {
					t.Errorf("check %s: %+v (present=%v), want status %s\nall: %+v", key, got, ok, status, rep.Checks)
				}
			}
			if rep.Policy != normPolicy(c.policy) {
				t.Errorf("policy %q", rep.Policy)
			}
		})
	}
}

func normPolicy(p string) string {
	if p == "" {
		return outAuto
	}
	return p
}

func TestEgressTestKeepsHostAndNodeMeasurementsApart(t *testing.T) {
	a := testApp(t)
	n := egressNode(t, a, outIPv6Only, nil)
	f := egressFake{routes: dualRoutes(), hostV4: "203.0.113.10", hostV6: "2001:db8::10", lit: litTargets,
		probe: egressProbe{V6: "2001:db8::77", ErrV4: errBlocked, Lit4: blocked(), Lit6: allowed()}}
	rep, e := a.nodeEgressTest(n.ID, false, f.env())
	if e != nil {
		t.Fatal(e)
	}
	// the host's own addresses and the node's exit addresses are different fields with different values
	if rep.Host.V6.IP != "2001:db8::10" || rep.Node.V6.IP != "2001:db8::77" {
		t.Fatalf("host %q / node %q", rep.Host.V6.IP, rep.Node.V6.IP)
	}
	if rep.Node.V4.IP != "" || rep.Node.V4.Error == "" {
		t.Fatalf("a failed IPv4 request must carry its error and no address: %+v", rep.Node.V4)
	}
	if !rep.Enforced || rep.Scope != egressScopeDirect {
		t.Fatalf("%+v", rep)
	}
	// quick: addresses only, no verdict, no literal requests
	quick, e := a.nodeEgressTest(n.ID, true, f.env())
	if e != nil {
		t.Fatal(e)
	}
	if quick.Result != "" || !quick.Quick {
		t.Fatalf("a quick look must not carry a verdict: %+v", quick)
	}
	for _, c := range quick.Checks {
		if c.Status != egressInfo {
			t.Fatalf("quick check %+v", c)
		}
	}
}

func TestEgressTestRefusesWhatIsNotARunningNode(t *testing.T) {
	a := testApp(t)
	n := egressNode(t, a, "", nil)
	f := egressFake{routes: dualRoutes()}
	if _, e := a.nodeEgressTest("ffffffffffff", false, f.env()); e == nil {
		t.Fatal("unknown id accepted")
	}
	s := mustLoad(t, a)
	p, _ := Find(s, n.ID)
	p.Enabled = false
	if e := a.Commit(s, replace(s, p), false); e != nil {
		t.Fatal(e)
	}
	if _, e := a.nodeEgressTest(n.ID, false, f.env()); e == nil {
		t.Fatal("a disabled node cannot be tested through")
	}
}

// ---- the terminal ----------------------------------------------------------------------------------------

func TestQuickCreateAsksNothingAboutTheOutboundFamilyAndStoresAuto(t *testing.T) {
	a := testApp(t)
	u, out := testUI(a, "Edge\n1\n\n")
	u.routes = dualRoutes
	if e := u.create(); e != nil {
		t.Fatal(e, out.String())
	}
	if strings.Contains(out.String(), "Outbound IP family") {
		t.Fatalf("the quick path must not ask:\n%s", out.String())
	}
	if n := createdNodes(t, a); len(n) != 1 || n[0].OutboundPolicy != "" {
		t.Fatalf("%+v", n)
	}
}

func TestCreateAdvancedOutboundFamily(t *testing.T) {
	a := testApp(t)
	// name · VLESS · Advanced · Outbound IP family · 5 IPv6 only · Create
	u, out := testUI(a, "Edge\n1\n3\n3\n5\n1\n")
	u.routes = dualRoutes
	if e := u.create(); e != nil {
		t.Fatal(e, out.String())
	}
	for _, want := range []string{`1\s+Auto\n`, `2\s+IPv4 first\n`, `3\s+IPv6 first\n`, `4\s+IPv4 only\n`, `5\s+IPv6 only\n`} {
		if !regexp.MustCompile(want).MatchString(out.String()) {
			t.Fatalf("the five choices must be numbered 1-5 (%q):\n%s", want, out.String())
		}
	}
	n := createdNodes(t, a)[0]
	if n.OutboundPolicy != outIPv6Only {
		t.Fatalf("policy %q", n.OutboundPolicy)
	}
	// independent of the inbound listen mode, which keeps its IPv4 default
	if n.Listen != "0.0.0.0" || n.inboundMode() != inIPv4 {
		t.Fatalf("the outbound choice changed the listen mode: %q %q", n.Listen, n.inboundMode())
	}
	if b, _ := os.ReadFile(filepath.Join(a.profileDir(n.ID), "config.json")); !strings.Contains(string(b), `"strategy": "ipv6_only"`) {
		t.Fatalf("config.json carries no policy:\n%s", b)
	}
	if hanRe.MatchString(out.String()) {
		t.Fatalf("untranslated Chinese in the English interface:\n%s", out.String())
	}
}

func TestCreateAdvancedOutboundFamilyOnAnIPv4OnlyVPS(t *testing.T) {
	a := testApp(t)
	// IPv6 only on a host without IPv6: warned, declined → nothing stored, menu continues; then confirmed
	u, out := testUI(a, "Edge\n1\n3\n3\n5\nn\n1\n")
	u.routes = func() familyRoutes { return familyRoutes{V4: true} }
	if e := u.create(); e != nil {
		t.Fatal(e, out.String())
	}
	if !strings.Contains(out.String(), "This server has no IPv6 route") {
		t.Fatalf("the missing family is not explained:\n%s", out.String())
	}
	if n := createdNodes(t, a)[0]; n.OutboundPolicy != "" {
		t.Fatalf("a declined policy was stored: %q", n.OutboundPolicy)
	}
	// IPv6 first is allowed without any confirmation (it simply behaves like IPv4)
	b := testApp(t)
	u, out = testUI(b, "Edge\n1\n3\n3\n3\n1\n")
	u.routes = func() familyRoutes { return familyRoutes{V4: true} }
	if e := u.create(); e != nil {
		t.Fatal(e, out.String())
	}
	if n := createdNodes(t, b)[0]; n.OutboundPolicy != outIPv6First {
		t.Fatalf("policy %q", n.OutboundPolicy)
	}
	// IPv6 only, confirmed
	c := testApp(t)
	u, out = testUI(c, "Edge\n1\n3\n3\n5\ny\n1\n")
	u.routes = func() familyRoutes { return familyRoutes{V4: true} }
	if e := u.create(); e != nil {
		t.Fatal(e, out.String())
	}
	if n := createdNodes(t, c)[0]; n.OutboundPolicy != outIPv6Only {
		t.Fatalf("policy %q", n.OutboundPolicy)
	}
}

func TestManageNodeMenuKeepsItsNumbersAndAddsTheEgressEntryLast(t *testing.T) {
	a := testApp(t)
	n := aiTestNode(t, a, "vless", "Turkey-VLESS")
	u, out := testUI(a, "0\n")
	if e := u.nodeMenu(n.ID); e != nil {
		t.Fatal(e)
	}
	order := []string{"Rename", "Change port or public address", "Choose outbound proxy", "Test connection", "View logs", "Traffic and limits", "Reset credentials", "Outbound IP family"}
	last := -1
	for i, label := range order {
		at := strings.Index(out.String(), label)
		if at < 0 || at < last {
			t.Fatalf("entry %d %q missing or out of order:\n%s", i+1, label, out.String())
		}
		last = at
	}
	if !regexp.MustCompile(`8\s+Outbound IP family`).MatchString(out.String()) {
		t.Fatalf("the new entry must be number 8 and the earlier ones unchanged:\n%s", out.String())
	}
}

func TestManageNodeChangesThePolicyAndKeepsEverythingElse(t *testing.T) {
	withHostRoutes(t, dualRoutes())
	a := testApp(t)
	n := aiTestNode(t, a, "vless", "Turkey-VLESS")
	other := aiTestNode(t, a, "ss", "Other-SS")
	otherCfg, _ := os.ReadFile(filepath.Join(a.profileDir(other.ID), "config.json"))
	link, _ := n.URI()

	// Outbound IP family → Change → 5 IPv6 only → back → back
	u, out := testUI(a, "8\n1\n5\n0\n0\n")
	u.routes = dualRoutes
	if e := u.nodeMenu(n.ID); e != nil {
		t.Fatal(e, out.String())
	}
	if !strings.Contains(out.String(), "Outbound IP family saved") {
		t.Fatalf("no confirmation:\n%s", out.String())
	}
	s := mustLoad(t, a)
	got, _ := Find(s, n.ID)
	if got.OutboundPolicy != outIPv6Only {
		t.Fatalf("policy %q", got.OutboundPolicy)
	}
	if got.UUID != n.UUID || got.Port != n.Port || got.PrivateKey != n.PrivateKey || got.ShortID != n.ShortID {
		t.Fatal("credentials or port changed")
	}
	if l2, _ := got.URI(); l2 != link {
		t.Fatalf("the share link changed:\n%s\n%s", link, l2)
	}
	if b, _ := os.ReadFile(filepath.Join(a.profileDir(other.ID), "config.json")); string(b) != string(otherCfg) {
		t.Fatal("another node's configuration was rewritten")
	}
	// the card and the submenu show the new policy
	u, out = testUI(a, "8\n0\n0\n")
	u.routes = dualRoutes
	if e := u.nodeMenu(n.ID); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(out.String(), "Current policy: IPv6 only") || !strings.Contains(out.String(), "IP family: IPv6 only") {
		t.Fatalf("policy not shown:\n%s", out.String())
	}
	// a node left on Auto shows no extra line
	u, out = testUI(a, "0\n")
	if e := u.nodeMenu(other.ID); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(out.String(), "IP family:") {
		t.Fatalf("an Auto node must look as before:\n%s", out.String())
	}
}

func TestManageNodeEgressTestShowsHostAndNodeResultsSeparately(t *testing.T) {
	a := testApp(t)
	n := egressNode(t, a, outIPv6Only, nil)
	for _, c := range []struct {
		name string
		f    egressFake
		want []string
	}{
		{"pass", egressFake{routes: dualRoutes(), hostV4: "203.0.113.10", hostV6: "2001:db8::10", lit: litTargets,
			probe: egressProbe{V6: "2001:db8::77", ErrV4: errBlocked, Lit4: blocked(), Lit6: allowed()}},
			[]string{"Host network test", "Node egress test", "2001:db8::77", "IPv4 fallback is blocked", "Result: passed"}},
		{"fail", egressFake{routes: dualRoutes(), hostV4: "203.0.113.10", hostV6: "2001:db8::10", lit: litTargets,
			probe: egressProbe{V4: "203.0.113.10", V6: "2001:db8::77", Lit4: allowed(), Lit6: allowed()}},
			[]string{"The policy is not in effect", "Result: failed"}},
		{"unprovable", egressFake{routes: familyRoutes{V6: true}, hostV6: "2001:db8::10", lit: litTargets, hostLitErr: map[string]error{"tcp4": errBlocked},
			probe: egressProbe{V6: "2001:db8::77", ErrV4: errBlocked, Lit4: blocked(), Lit6: allowed()}},
			[]string{"Cannot prove", "could not be fully verified"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			env := c.f.env()
			// Outbound IP family → Test IPv6 egress → back → back
			u, out := testUI(a, "8\n2\n0\n0\n")
			u.egress = &env
			if e := u.nodeMenu(n.ID); e != nil {
				t.Fatal(e, out.String())
			}
			s := out.String()
			for _, want := range c.want {
				if !strings.Contains(s, want) {
					t.Errorf("missing %q:\n%s", want, s)
				}
			}
			if c.name != "pass" && strings.Contains(s, "Result: passed") {
				t.Errorf("a %s must never print a pass:\n%s", c.name, s)
			}
			if hanRe.MatchString(s) {
				t.Errorf("untranslated Chinese in the English interface:\n%s", s)
			}
		})
	}
	// "Show outbound IPs" is a look, not a verdict
	env := egressFake{routes: dualRoutes(), hostV4: "203.0.113.10", probe: egressProbe{V4: "203.0.113.99", ErrV6: errBlocked}}.env()
	u, out := testUI(a, "8\n3\n0\n0\n")
	u.egress = &env
	if e := u.nodeMenu(n.ID); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(out.String(), "203.0.113.99") || strings.Contains(out.String(), "Result:") {
		t.Fatalf("quick view:\n%s", out.String())
	}
}

func TestTheOutboundFamilyReadsInChineseToo(t *testing.T) {
	a := testApp(t)
	a.Language = "zh-CN"
	n := aiTestNode(t, a, "vless", "Turkey-VLESS")
	u, out := testUI(a, "8\n0\n0\n")
	if e := u.nodeMenu(n.ID); e != nil {
		t.Fatal(e)
	}
	for _, want := range []string{"出站网络策略", "修改出站网络策略", "测试 IPv6 出站", "查看出站 IP"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q:\n%s", want, out.String())
		}
	}
	a.Language = "zh-TW"
	u, out = testUI(a, "8\n0\n0\n")
	if e := u.nodeMenu(n.ID); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(out.String(), "出站網路策略") {
		t.Fatalf("zh-TW:\n%s", out.String())
	}
}

func TestDiagnosisNamesThePolicyOfANode(t *testing.T) {
	a := testApp(t)
	for _, c := range []struct {
		name   string
		policy string
		want   []string
		absent []string
	}{
		{"direct only policy", outIPv6Only, []string{"Outbound IP family: IPv6 only", "IPv6 only: IPv4 addresses and names with only an A record are refused explicitly"}, nil},
		{"first policy", outIPv4First, []string{"Outbound IP family: IPv4 first", "falls back to IPv6 when it fails"}, nil},
		{"auto adds nothing", "", nil, []string{"Outbound IP family"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			n := egressNode(t, a, c.policy, nil)
			env := diagEnvFor(map[string][]string{}, nil)
			env.sockets = func() ([]sockEntry, error) { return nil, errors.New("not readable") }
			env.managed = func(*App, Profile) (bool, bool) { return false, false }
			env.full = func(*App, Profile, string, int) fullProbe {
				return fullProbe{V6: "2001:db8::77", ErrV4: errBlocked}
			}
			rep := a.diagnoseNode(context.Background(), n, env, diagOpts{Full: true})
			text := rep.Text()
			for _, w := range c.want {
				if !strings.Contains(text, w) {
					t.Errorf("missing %q:\n%s", w, text)
				}
			}
			for _, w := range c.absent {
				if strings.Contains(text, w) {
					t.Errorf("unexpected %q:\n%s", w, text)
				}
			}
			// a family the policy forbids being unavailable is not a failure of the node
			if rep.Count(diagFail) > 0 {
				t.Errorf("a blocked family must not fail the diagnosis:\n%s", text)
			}
		})
	}
}
