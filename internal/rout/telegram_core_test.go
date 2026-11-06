package rout

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTelegramConfigIsPrivateAndValidated(t *testing.T) {
	a := testApp(t)
	if _, e := a.LoadTelegram(); e != errTelegramUnbound {
		t.Fatalf("fresh install should be unbound, got %v", e)
	}
	id, e := newTelegramIdentity("0123456789abcdef")
	if e != nil {
		t.Fatal(e)
	}
	cfg := TelegramConfig{Token: testBotToken, ChatID: 111, ServerID: "0123456789abcdef", Name: "US-GIA", Role: tgRoleHub, CertPEM: id.CertPEM, KeyPEM: id.KeyPEM, Hub: &TelegramHub{}}
	if e = a.saveTelegram(cfg); e != nil {
		t.Fatal(e)
	}
	st, e := os.Stat(a.telegramPath())
	if e != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("telegram.json must be 0600, got %v %v", st, e)
	}
	got, e := a.LoadTelegram()
	if e != nil || got.Token != testBotToken || got.ChatID != 111 {
		t.Fatalf("round trip: %+v %v", got, e)
	}
	// fmt of the config must never print secrets
	if s := got.String(); strings.Contains(s, testBotToken) || strings.Contains(s, "PRIVATE KEY") || strings.Contains(s, "111") {
		t.Fatalf("String leaks secrets: %s", s)
	}
	// the bot token never lands in state.json or in a backup
	s, _ := a.Load()
	if e = a.Commit(s, s, false); e != nil {
		t.Fatal(e)
	}
	if b, _ := os.ReadFile(filepath.Join(a.Home, "state.json")); strings.Contains(string(b), testBotToken) {
		t.Fatal("token found in state.json")
	}

	bad := []TelegramConfig{}
	for _, mut := range []func(c *TelegramConfig){
		func(c *TelegramConfig) { c.Token = "nope" },
		func(c *TelegramConfig) { c.ChatID = -100123 }, // groups and channels are refused
		func(c *TelegramConfig) { c.ChatID = 0 },
		func(c *TelegramConfig) { c.ServerID = "xyz" },
		func(c *TelegramConfig) { c.Name = "a\nb" },
		func(c *TelegramConfig) { c.Role = "root" },
		func(c *TelegramConfig) { c.Hub.Port = 80 },
		func(c *TelegramConfig) { c.Hub.Advertise = []string{"no-port"} },
	} {
		c := cfg
		h := *cfg.Hub
		c.Hub = &h
		mut(&c)
		bad = append(bad, c)
	}
	for i, c := range bad {
		c.Version = telegramConfigVersion
		if c.Validate() == nil {
			t.Errorf("config %d should be invalid", i)
		}
	}
	if e = a.removeTelegramFiles(); e != nil {
		t.Fatal(e)
	}
	if _, e = a.LoadTelegram(); e != errTelegramUnbound {
		t.Fatal("files not removed")
	}
}

func TestTelegramBackupDoesNotCarryCredentials(t *testing.T) {
	sc := newAIScene(t)
	id, _ := newTelegramIdentity("0123456789abcdef")
	cfg := TelegramConfig{Token: testBotToken, ChatID: 111, ServerID: "0123456789abcdef", Name: "x", Role: tgRoleHub, CertPEM: id.CertPEM, KeyPEM: id.KeyPEM, Hub: &TelegramHub{}}
	if e := sc.a.saveTelegram(cfg); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(t.TempDir(), "backup.json")
	if e := sc.a.Backup(path); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(path)
	bundle, e := sc.a.EncodeBackup(time.Now())
	if e != nil {
		t.Fatal(e)
	}
	for _, blob := range [][]byte{b, bundle} {
		// (the node fixtures legitimately carry their own TLS keys; only Telegram's must be absent)
		if strings.Contains(string(blob), testBotToken) || strings.Contains(string(blob), strings.Split(id.KeyPEM, "\n")[1]) {
			t.Fatal("a backup carries the Telegram credentials")
		}
	}
}

func TestTelegramClientNeverLeaksTheToken(t *testing.T) {
	// 1) a server that kills the connection: net/http puts the URL (and token) in its error
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			c.Close()
		}
	}()
	t.Cleanup(func() { l.Close() })
	a := testApp(t)
	a.telegram = &telegramHooks{base: "http://" + l.Addr().String()}
	cl := a.tgClient(testBotToken)
	_, e := cl.getMe(context.Background())
	if e == nil || strings.Contains(e.Error(), testBotToken) || strings.Contains(e.Error(), "AAHtest") {
		t.Fatalf("transport error leaks the token: %v", e)
	}
	// 2) Telegram echoing the token in a description
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		w.Write([]byte(`{"ok":false,"error_code":400,"description":"bad token ` + testBotToken + `"}`))
	}))
	t.Cleanup(srv.Close)
	a.telegram = &telegramHooks{base: srv.URL}
	_, e = a.tgClient(testBotToken).getMe(context.Background())
	if e == nil || strings.Contains(e.Error(), testBotToken) || strings.Contains(tgFriendly(e), testBotToken) {
		t.Fatalf("API error leaks the token: %v", e)
	}
}

func TestTelegramFriendlyErrors(t *testing.T) {
	cases := map[int]string{401: "Token", 403: "/start", 409: "同时", 429: "频繁"}
	for code, want := range cases {
		if m := tgFriendly(&tgAPIError{Method: "x", Code: code, Desc: "d"}); !strings.Contains(m, want) {
			t.Errorf("%d -> %q", code, m)
		}
	}
	if m := tgFriendly(&tgAPIError{Code: 400, Desc: "Bad Request: chat not found"}); !strings.Contains(m, "Chat ID") {
		t.Errorf("chat not found -> %q", m)
	}
}

func TestTelegramAnnouncementIsAuthenticatedAndTokenBound(t *testing.T) {
	k := deriveTelegramKeys(testBotToken)
	an := tgAnnouncement{HubID: "aaaaaaaaaaaaaaaa", Name: "hub", Endpoints: []string{"203.0.113.9:28443"}, FP: strings.Repeat("ab", 32), TS: 1}
	sealed, e := k.sealAnnouncement(an)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(sealed, "203.0.113.9") || strings.Contains(sealed, "hub") {
		t.Fatal("announcement must be opaque in the chat")
	}
	got, e := k.openAnnouncement(announcementText(sealed))
	if e != nil || got.HubID != an.HubID || got.Endpoints[0] != an.Endpoints[0] || got.FP != an.FP {
		t.Fatalf("open: %+v %v", got, e)
	}
	// someone with a different token cannot read or forge it
	other := deriveTelegramKeys("7000000002:AAHotherTokenForRoutTelegramBBBBBBBBBBBB")
	if _, e = other.openAnnouncement(announcementText(sealed)); e == nil {
		t.Fatal("announcement opened with the wrong token")
	}
	// tampering fails
	b := []byte(sealed)
	b[len(b)-3] ^= 1
	if _, e = k.openAnnouncement(string(b)); e == nil {
		t.Fatal("tampered announcement accepted")
	}
	// the text around the sealed value is irrelevant but a missing value is an error
	if _, e = k.openAnnouncement("hello"); e == nil {
		t.Fatal("no announcement should be an error")
	}
	// two seals of the same content differ (random nonce)
	s2, _ := k.sealAnnouncement(an)
	if s2 == sealed {
		t.Fatal("seal is deterministic")
	}
}

func TestTelegramCallbackMACBindsChatAndData(t *testing.T) {
	k := deriveTelegramKeys(testBotToken)
	tag := k.cbTag(111, "S:abc")
	if !k.cbCheck(111, "S:abc", tag) {
		t.Fatal("valid tag rejected")
	}
	if k.cbCheck(112, "S:abc", tag) || k.cbCheck(111, "S:abd", tag) || k.cbCheck(111, "S:abc", "AAAAAAAAAAA") || k.cbCheck(111, "S:abc", "") {
		t.Fatal("forged callback accepted")
	}
	if deriveTelegramKeys("7000000002:AAHotherTokenForRoutTelegramBBBBBBBBBBBB").cbCheck(111, "S:abc", tag) {
		t.Fatal("tag valid under another token")
	}
	// a rendered callback fits Telegram's 64-byte limit with the longest verbs
	long := "X:0123456789abcdef:" + strings.Repeat("e", 24)
	if n := len(long + "~" + k.cbTag(111, long)); n > 64 {
		t.Fatalf("callback too long: %d", n)
	}
}

func TestTelegramEnrollProofBindsEverything(t *testing.T) {
	k := deriveTelegramKeys(testBotToken)
	p := k.enrollProof("nonce", "0123456789abcdef", "fp1")
	if !k.checkEnrollProof("nonce", "0123456789abcdef", "fp1", p) {
		t.Fatal("valid proof rejected")
	}
	for _, c := range [][3]string{{"other", "0123456789abcdef", "fp1"}, {"nonce", "fedcba9876543210", "fp1"}, {"nonce", "0123456789abcdef", "fp2"}} {
		if k.checkEnrollProof(c[0], c[1], c[2], p) {
			t.Fatalf("proof accepted for %v", c)
		}
	}
	if k.checkEnrollProof("nonce", "0123456789abcdef", "fp1", "zz") || deriveTelegramKeys("7000000002:AAHotherTokenForRoutTelegramBBBBBBBBBBBB").checkEnrollProof("nonce", "0123456789abcdef", "fp1", p) {
		t.Fatal("proof accepted for garbage / another token")
	}
}

func TestTelegramFingerprintComparison(t *testing.T) {
	id, _ := newTelegramIdentity("0123456789abcdef")
	fp := id.fingerprint()
	if len(fp) != 64 {
		t.Fatalf("fingerprint: %q", fp)
	}
	if !sameFingerprint(fp, fingerprintGroups(fp)) || !sameFingerprint(fp, strings.ToUpper(fp)) || !sameFingerprint(fp, fp) {
		t.Fatal("same fingerprint not recognised")
	}
	other, _ := newTelegramIdentity("fedcba9876543210")
	if sameFingerprint(fp, fingerprintGroups(other.fingerprint())) || sameFingerprint(fp, "") || sameFingerprint(fp, fp[:8]) {
		t.Fatal("different/short fingerprint accepted")
	}
}

func TestTelegramScrubRemovesSecretsFromOutgoingText(t *testing.T) {
	in := "dial socks5://user:hunter2@203.0.113.5:1080 failed; password=hunter2 key: " + strings.Repeat("A", 43) + " token " + testBotToken
	out := tgScrub(in, 400, testBotToken)
	for _, bad := range []string{"hunter2", "203.0.113.5", strings.Repeat("A", 43), testBotToken, "socks5://"} {
		if strings.Contains(out, bad) {
			t.Errorf("scrub left %q in %q", bad, out)
		}
	}
	if long := tgScrub(strings.Repeat("字", 1000), 50); len([]rune(long)) > 51 {
		t.Fatal("scrub did not bound the length")
	}
	if got := tgScrub("a\x00b\x1bc", 10); strings.ContainsAny(got, "\x00\x1b") {
		t.Fatal("control characters survived")
	}
}

func TestTelegramCommandValidation(t *testing.T) {
	now := time.Now()
	ok := tgCommand{ID: "abcdef0123456789", Kind: tgCmdSetEnabled, Expires: now.Add(time.Minute).Unix()}
	if e := tgCommandValid(ok, now); e != nil {
		t.Fatal(e)
	}
	for name, c := range map[string]tgCommand{
		"expired":     {ID: ok.ID, Kind: tgCmdStatus, Expires: now.Add(-time.Second).Unix()},
		"no expiry":   {ID: ok.ID, Kind: tgCmdStatus},
		"far future":  {ID: ok.ID, Kind: tgCmdStatus, Expires: now.Add(24 * time.Hour).Unix()},
		"short id":    {ID: "x", Kind: tgCmdStatus, Expires: ok.Expires},
		"shell":       {ID: ok.ID, Kind: "exec", Expires: ok.Expires},
		"empty kind":  {ID: ok.ID, Expires: ok.Expires},
		"bad creds":   {ID: ok.ID, Kind: tgCmdCredentials, Token: "x", ChatID: 1, Expires: ok.Expires},
		"neg chat":    {ID: ok.ID, Kind: tgCmdCredentials, Token: testBotToken, ChatID: -5, Expires: ok.Expires},
		"unknown one": {ID: ok.ID, Kind: "set_exit ", Expires: ok.Expires},
	} {
		if tgCommandValid(c, now) == nil {
			t.Errorf("%s should be rejected", name)
		}
	}
	if s := (tgCommand{ID: "abcdef0123456789", Kind: tgCmdCredentials, Token: testBotToken}).String(); strings.Contains(s, testBotToken) {
		t.Fatal("command String leaks the token")
	}
}
