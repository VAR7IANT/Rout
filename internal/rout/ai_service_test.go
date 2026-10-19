package rout

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Only disposable Linux hosts: exercises actual service restarts, health-check
// failure and rollback. Never enable these variables on a production VPS.
func TestIntegrationAIServiceIsolation(t *testing.T) {
	if os.Getenv("ROUT_TEST_SYSTEMD") != "1" && os.Getenv("ROUT_TEST_OPENRC") != "1" {
		t.Skip("requires disposable root systemd/OpenRC host")
	}
	verified := integrationApp(t)
	root, err := os.MkdirTemp("/var/lib", "rout-ai-")
	if err != nil {
		t.Fatal(err)
	}
	a := &App{Home: filepath.Join(root, "config"), BinDir: filepath.Join(root, "bin"), ServiceMode: "auto"}
	t.Cleanup(func() {
		s, err := a.Load()
		if err == nil {
			if err = a.Commit(s, State{Schema: 1, Profiles: []Profile{}}, false); err != nil {
				t.Error(err)
			}
		}
		os.RemoveAll(root)
	})
	binary, err := os.ReadFile(verified.enginePath("sing-box"))
	if err != nil {
		t.Fatal(err)
	}
	realBinary := filepath.Join(root, "real-sing-box")
	if err = AtomicWrite(realBinary, binary, 0755); err != nil {
		t.Fatal(err)
	}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "controlled-origin") }))
	defer origin.Close()
	ca, _, _, _ := aiProxyFixture(t, strings.TrimPrefix(origin.URL, "http://"), "tcp4", false)
	otherCA, _, _, _ := aiProxyFixture(t, strings.TrimPrefix(origin.URL, "http://"), "tcp4", false)
	// 'check' succeeds; 'run' of the replacement exit fails. The previous exit's
	// process can still start during rollback. No test hooks in production code.
	wrapper := "#!/bin/sh\nif [ \"$1\" = run ] && grep -q '" + fmt.Sprintf(`"server_port": %d`, otherCA.Port) + "' \"$3\"; then exit 42; fi\nexec " + shellQuote(realBinary) + " \"$@\"\n"
	if err = AtomicWrite(a.enginePath("sing-box"), []byte(wrapper), 0755); err != nil {
		t.Fatal(err)
	}
	var nodes []Profile
	for i := 0; i < 2; i++ {
		p := fixture(t, "ss")
		p.Port, _ = freePort()
		p.PublicPort = p.Port
		s, err := a.Load()
		if err != nil {
			t.Fatal(err)
		}
		if err = a.Commit(s, replace(s, p), false); err != nil {
			t.Fatal(err)
		}
		nodes = append(nodes, p)
	}
	manager, err := a.serviceManager()
	if err != nil {
		t.Fatal(err)
	}
	pid := func(p Profile) string { return servicePID(manager, serviceName(p)) }
	bPID := pid(nodes[1])
	if bPID == "" || bPID == "0" {
		t.Fatal("unbound service has no PID")
	}
	ex := Exit{ID: RandomHex(6), Name: "Canada", Proxy: ca}
	s, err := a.Load()
	if err != nil {
		t.Fatal(err)
	}
	if err = a.Commit(s, UpsertExit(s, ex), false); err != nil {
		t.Fatal(err)
	}
	if err = a.SetAIExit(ex.ID); err != nil {
		t.Fatal(err)
	}
	if err = a.SetAIBindings([]string{nodes[0].ID}); err != nil {
		t.Fatal(err)
	}
	aPID := pid(nodes[0])
	if err = a.SetAIEnabled(true); err != nil {
		t.Fatal(err)
	}
	if pid(nodes[0]) == aPID || pid(nodes[1]) != bPID {
		t.Fatal("enable restarted wrong nodes")
	}
	// An actual outbound edit restarts A alone, without rebuilding its credentials.
	aPID = pid(nodes[0])
	ex.Proxy.Username = "changed-user"
	s, err = a.Load()
	if err != nil {
		t.Fatal(err)
	}
	if err = a.Commit(s, UpsertExit(s, ex), false); err != nil {
		t.Fatal(err)
	}
	if pid(nodes[0]) == aPID || pid(nodes[1]) != bPID {
		t.Fatal("outbound edit restarted wrong nodes")
	}
	ex.Proxy = ca
	s, err = a.Load()
	if err != nil {
		t.Fatal(err)
	}
	if err = a.Commit(s, UpsertExit(s, ex), false); err != nil {
		t.Fatal(err)
	}
	beforeState, err := os.ReadFile(filepath.Join(a.Home, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	beforeConfig, _ := readConfigFile(t, a, nodes[0])
	ex.Proxy = otherCA
	s, err = a.Load()
	if err != nil {
		t.Fatal(err)
	}
	if err = a.Commit(s, UpsertExit(s, ex), false); err == nil {
		t.Fatal("crashing AI configuration accepted")
	}
	afterState, err := os.ReadFile(filepath.Join(a.Home, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	afterConfig, _ := readConfigFile(t, a, nodes[0])
	if string(beforeState) != string(afterState) || string(beforeConfig) != string(afterConfig) || !listening(nodes[0]) || pid(nodes[1]) != bPID {
		t.Fatal("AI service rollback failed or touched unbound node")
	}
	port, _ := freePort()
	client, err := ClientConfig(nodes[0], "127.0.0.1", nodes[0].Port, port)
	if err != nil {
		t.Fatal(err)
	}
	aiProcess(t, realBinary, configFile(t, client), port)
	if err = aiRequest(port, origin.URL, "chat.openai.com", nil); err != nil {
		t.Fatal("rolled-back AI service cannot carry traffic", err)
	}
	if err = a.SetAIEnabled(false); err != nil {
		t.Fatal(err)
	}
	if pid(nodes[1]) != bPID {
		t.Fatal("disable restarted unbound service")
	}
	if err = aiRequest(port, origin.URL, "chat.openai.com", nil); err != nil {
		t.Fatal("disabled AI routing did not restore direct traffic", err)
	}
}
