package rout

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

func TestSubscriptionSavedURLsAndPermissions(t *testing.T) {
	sc := newSubScene(t)
	first, token := sc.create(t, "Phone", 2, 0, 1)
	_, other := sc.create(t, "Laptop", 1)
	if e := sc.a.SetSubscriptionPublicURL("https://sub.example/prefix"); e != nil {
		t.Fatal(e)
	}
	state, _ := os.ReadFile(filepath.Join(sc.a.Home, "state.json"))
	private, _ := os.ReadFile(sc.a.subscriptionTokensPath())
	for _, path := range []string{filepath.Dir(sc.a.subscriptionTokensPath()), sc.a.subscriptionTokensPath()} {
		st, e := os.Stat(path)
		want := os.FileMode(0600)
		if path == filepath.Dir(sc.a.subscriptionTokensPath()) {
			want = 0700
		}
		if e != nil || st.Mode().Perm() != want {
			t.Fatal("private token permissions incorrect")
		}
	}
	for _, lang := range []string{"en", "zh-CN"} {
		fresh := &App{Home: sc.a.Home, BinDir: sc.a.BinDir, ServiceMode: "none", Language: lang}
		s, e := fresh.Load()
		if e != nil {
			t.Fatal(e)
		}
		u, out := testUI(fresh, "1\n0\n")
		if e = u.subscriptions(); e != nil {
			t.Fatal(e)
		}
		text := out.String()
		for _, raw := range []string{token, other} {
			base := "https://sub.example/prefix/s/" + raw
			for _, suffix := range []string{"", "?format=mihomo", "?format=clash"} {
				if !strings.Contains(text, "\n"+base+suffix+"\n") {
					t.Fatal("complete, selectable subscription URL missing")
				}
			}
		}
		if strings.Contains(text, "{access_token}") || (lang == "en" && hasHan(text)) {
			t.Fatal("saved URL replaced by a template or untranslated output")
		}
		if got, ok := s.matchSubscription(token); !ok || got.ID != first.ID || !reflect.DeepEqual(got.NodeIDs, sc.ids(2, 0, 1)) {
			t.Fatal("saved token changed authentication or node ordering")
		}
	}
	after, _ := os.ReadFile(filepath.Join(sc.a.Home, "state.json"))
	afterPrivate, _ := os.ReadFile(sc.a.subscriptionTokensPath())
	if !bytes.Equal(state, after) || !bytes.Equal(private, afterPrivate) {
		t.Fatal("viewing URLs wrote persistent data")
	}
}

func TestSubscriptionLegacyHashOnlyURLsAndExplicitRotation(t *testing.T) {
	sc := newSubScene(t)
	sub, old := sc.create(t, "Legacy", 0, 1)
	if e := os.RemoveAll(filepath.Dir(sc.a.subscriptionTokensPath())); e != nil {
		t.Fatal(e)
	}
	before, _ := os.ReadFile(filepath.Join(sc.a.Home, "state.json"))
	h, _ := sc.handler()
	body := get(h, "GET", "/s/"+old).Body.String()
	for _, lang := range []string{"en", "zh-CN"} {
		sc.a.Language = lang
		u, out := testUI(sc.a, "1\n0\n")
		if e := u.subscriptions(); e != nil {
			t.Fatal(e)
		}
		if strings.Contains(out.String(), old) || !strings.Contains(out.String(), "{access_token}?format=clash") || (lang == "en" && (hasHan(out.String()) || !strings.Contains(out.String(), "cannot be recovered"))) {
			t.Fatal("legacy URL guidance is missing, unsafe or untranslated")
		}
	}
	sc.a.Language = "en"
	for _, input := range []string{"5\n1\n\n0\n", "5\n1\nN\n0\n"} {
		u, _ := testUI(sc.a, input)
		if e := u.subscriptions(); e != nil {
			t.Fatal(e)
		}
	}
	after, _ := os.ReadFile(filepath.Join(sc.a.Home, "state.json"))
	if !bytes.Equal(before, after) || get(h, "GET", "/s/"+old).Body.String() != body {
		t.Fatal("legacy display or declined rotation changed the existing subscription")
	}
	if _, e := os.Stat(sc.a.subscriptionTokensPath()); !os.IsNotExist(e) {
		t.Fatal("legacy read silently initialized private storage")
	}
	u, out := testUI(sc.a, "5\n1\nYES\n0\n")
	if e := u.subscriptions(); e != nil {
		t.Fatal(e)
	}
	s := sc.state(t)
	saved, e := sc.a.loadSubscriptionTokens()
	if e != nil {
		t.Fatal(e)
	}
	fresh := saved[s.Subscriptions[0].TokenHash]
	if fresh == "" || fresh == old || s.Subscriptions[0].ID != sub.ID || !reflect.DeepEqual(s.Subscriptions[0].NodeIDs, sub.NodeIDs) || get(h, "GET", "/s/"+old).Code != 404 || get(h, "GET", "/s/"+fresh).Body.String() != body {
		t.Fatal("explicit rotation did not preserve selection/body and revoke only the old token")
	}
	if !strings.Contains(out.String(), "needs the new link") || !strings.Contains(out.String(), "/s/"+fresh+"?format=clash") {
		t.Fatal("rotation warning or saved URL missing")
	}
}

func TestSubscriptionTokensInterruptedWriteAndPruning(t *testing.T) {
	sc := newSubScene(t)
	sub, old := sc.create(t, "Original", 0)
	s := sc.state(t)
	unpublished, _, e := newSubscriptionToken()
	if e != nil {
		t.Fatal(e)
	}
	unlock, e := sc.a.lock()
	if e != nil {
		t.Fatal(e)
	}
	// Exact durable state after an interruption between private write and hash commit.
	e = sc.a.saveSubscriptionTokens(s, []string{unpublished})
	unlock()
	if e != nil {
		t.Fatal(e)
	}
	a := &App{Home: sc.a.Home, BinDir: sc.a.BinDir, ServiceMode: "none"}
	saved, e := a.loadSubscriptionTokens()
	h, _ := sc.handler()
	if e != nil || saved[sub.TokenHash] != old || get(h, "GET", "/s/"+old).Code != 200 || get(h, "GET", "/s/"+unpublished).Code != 404 {
		t.Fatal("interrupted write lost the valid token or authenticated an unpublished token")
	}
	for i := 0; i < 5; i++ {
		token, e := a.RotateSubscriptionToken(sub.ID)
		if e != nil {
			t.Fatal(e)
		}
		saved, e = a.loadSubscriptionTokens()
		if e != nil || saved[hashToken(token)] != token || len(saved) > 2 || saved[hashToken(unpublished)] != "" {
			t.Fatal("token writes lost the current token or accumulated obsolete entries")
		}
		if get(h, "GET", "/s/"+token).Code != 200 || get(h, "GET", "/s/"+old).Code != 404 {
			t.Fatal("rotation bypassed hash verification")
		}
		old = token
	}
}

func TestSubscriptionTokenStorageFailuresKeepExistingAuthentication(t *testing.T) {
	for _, fault := range []string{"file permissions", "directory permissions", "symlink", "corrupt JSON", "wrong hash"} {
		t.Run(fault, func(t *testing.T) {
			sc := newSubScene(t)
			sub, token := sc.create(t, "Original", 0)
			before, _ := os.ReadFile(filepath.Join(sc.a.Home, "state.json"))
			path := sc.a.subscriptionTokensPath()
			switch fault {
			case "file permissions":
				os.Chmod(path, 0644)
			case "directory permissions":
				os.Chmod(filepath.Dir(path), 0755)
			case "symlink":
				os.Remove(path)
				os.Symlink(filepath.Join(sc.a.Home, "state.json"), path)
			case "corrupt JSON":
				os.WriteFile(path, []byte("{invalid "+token), 0600)
			case "wrong hash":
				data, _ := JSON(map[string]string{strings.Repeat("0", 64): token})
				os.WriteFile(path, data, 0600)
			}
			if _, _, e := sc.a.CreateSubscription("Must not exist", sc.ids(0)); e == nil || strings.Contains(e.Error(), token) {
				t.Fatal("unsafe token storage accepted or exposed a token")
			}
			if _, e := sc.a.RotateSubscriptionToken(sub.ID); e == nil || strings.Contains(e.Error(), token) {
				t.Fatal("failed rotation accepted or exposed a token")
			}
			after, _ := os.ReadFile(filepath.Join(sc.a.Home, "state.json"))
			h, _ := sc.handler()
			if !bytes.Equal(before, after) || get(h, "GET", "/s/"+token).Code != 200 {
				t.Fatal("token-file failure changed authentication or subscription state")
			}
		})
	}
}

func TestSubscriptionTokensExcludedFromBackupsDiagnosticsAndHTTP(t *testing.T) {
	sc := newSubScene(t)
	_, token := sc.create(t, "Original", 0)
	if e := sc.a.RenameSubscription(sc.state(t).Subscriptions[0].ID, "Renamed"); e != nil {
		t.Fatal(e)
	}
	if e := sc.a.Backup(filepath.Join(sc.a.Home, "shared-backup.json")); e != nil {
		t.Fatal(e)
	}
	if e := sc.a.PrepareSubscriptionUpgrade(); e != nil {
		t.Fatal(e)
	}
	if _, e := sc.a.backupSubscriptionFiles("token-regression", filepath.Join(sc.a.Home, "state.json")); e != nil {
		t.Fatal(e)
	}
	filepath.Walk(sc.a.Home, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			t.Fatal(err)
		}
		if !info.IsDir() && path != sc.a.subscriptionTokensPath() {
			data, e := os.ReadFile(path)
			if e != nil || bytes.Contains(data, []byte(token)) {
				t.Fatal("plaintext token escaped private storage")
			}
		}
		return nil
	})
	u, out := testUI(sc.a, "")
	u.showExistingSubscriptionURL()
	if strings.Contains(out.String(), token) {
		t.Fatal("diagnostic template exposed a token")
	}
	h, logs := sc.handler()
	for _, suffix := range []string{"", "?format=mihomo", "?format=clash"} {
		w := get(h, "GET", "/s/"+token+suffix)
		if w.Code != 200 || strings.Contains(w.Body.String(), token) {
			t.Fatal("HTTP format failed or exposed an access token")
		}
	}
	for _, path := range []string{"/secrets/subscription-tokens.json", "/subscription-tokens.json", "/state.json", "/admin"} {
		if get(h, "GET", path).Code != 404 {
			t.Fatal("unauthenticated management endpoint exposed private storage")
		}
	}
	if strings.Contains(strings.Join(*logs, "\n"), token) || strings.Contains(sanitizeSubscriptionLogs([]byte("failed /s/"+token+"?format=clash")), token) {
		t.Fatal("token leaked through logs")
	}
}

func TestSubscriptionTokensAcrossProcessesAndFailedStateWrite(t *testing.T) {
	for _, scenario := range []string{"restart", "failed-state-write"} {
		t.Run(scenario, func(t *testing.T) {
			sc := newSubScene(t)
			if scenario == "restart" {
				sc.create(t, "Persisted", 0)
			}
			child := exec.Command(os.Args[0], "-test.run=^TestSubscriptionTokensChild$")
			child.Env = append(os.Environ(), "ROUT_TEST_TOKEN_HOME="+sc.a.Home, "ROUT_TEST_TOKEN_SCENARIO="+scenario)
			if _, e := child.CombinedOutput(); e != nil {
				t.Fatal("isolated token persistence/write-failure check failed; output withheld")
			}
		})
	}
}

func TestSubscriptionTokensChild(t *testing.T) {
	home := os.Getenv("ROUT_TEST_TOKEN_HOME")
	if home == "" {
		t.Skip("run by the isolated parent test")
	}
	a := &App{Home: home, BinDir: home + "-unused", ServiceMode: "none", Language: "en"}
	s, e := a.Load()
	if e != nil {
		t.Fatal("cannot load child state")
	}
	if os.Getenv("ROUT_TEST_TOKEN_SCENARIO") == "failed-state-write" {
		before, _ := os.ReadFile(filepath.Join(home, "state.json"))
		backup, _ := JSON(s)
		limit := len(before)
		if len(backup) > limit {
			limit = len(backup)
		}
		var previous syscall.Rlimit
		if e = syscall.Getrlimit(syscall.RLIMIT_FSIZE, &previous); e != nil {
			t.Fatal("cannot read file-size limit")
		}
		defer syscall.Setrlimit(syscall.RLIMIT_FSIZE, &previous)
		if e = syscall.Setrlimit(syscall.RLIMIT_FSIZE, &syscall.Rlimit{Cur: uint64(limit + 8), Max: previous.Max}); e != nil {
			t.Fatal("cannot set file-size limit")
		}
		_, _, e = a.CreateSubscription("Failed creation", []string{s.Profiles[0].ID})
		after, _ := os.ReadFile(filepath.Join(home, "state.json"))
		saved, loadError := a.loadSubscriptionTokens()
		if e == nil || !bytes.Equal(before, after) || loadError != nil || len(saved) != 1 {
			t.Fatal("state-write failure did not preserve state and private token recovery")
		}
		return
	}
	saved, e := a.loadSubscriptionTokens()
	if e != nil || len(s.Subscriptions) != 1 || saved[s.Subscriptions[0].TokenHash] == "" {
		t.Fatal("token was not persisted across processes")
	}
	token := saved[s.Subscriptions[0].TokenHash]
	if _, ok := s.matchSubscription(token); !ok {
		t.Fatal("persisted token does not authenticate")
	}
	u, out := testUI(a, "")
	u.subscriptionList(s)
	for _, suffix := range []string{"", "?format=mihomo", "?format=clash"} {
		if !strings.Contains(out.String(), "/s/"+token+suffix+"\n") {
			t.Fatal("restart did not preserve displayable subscription URLs")
		}
	}
}
