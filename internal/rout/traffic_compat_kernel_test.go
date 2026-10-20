package rout

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestKernelNFTCompatibility(t *testing.T) {
	a := kernelApp(t)
	p := fixture(t, "ss")
	p.Port, _ = freePort()
	p.Traffic = &TrafficPolicy{LimitBytes: 1000000, BillingDay: 1}
	m := nftMeter{home: a.Home}
	want := TrafficRecord{RawUp: 123, RawDown: 456, Consumed: 579}
	if _, e := m.Replace(p, want); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = m.Delete(p) })
	version, e := nftRun("", "--version")
	if e != nil {
		t.Fatal(e)
	}
	raw, e := nftRun("", "-j", "list", "table", "inet", m.table(p))
	if e != nil {
		t.Fatal(e)
	}
	text, e := nftRun("", "list", "table", "inet", m.table(p))
	if e != nil {
		t.Fatal(e)
	}
	t.Logf("Real nft output:\n%sJSON:\n%s\nTEXT:\n%s", version, raw, text)
	es, e := decodeNFT(raw)
	if e != nil {
		t.Fatal(e)
	}
	if os.Getenv("ROUT_TEST_NFT_VERSION") == "1.0.6" {
		if !strings.Contains(string(version), "v1.0.6 ") {
			t.Fatal("Debian 12 test ran the wrong nft", string(version))
		}
		for _, entry := range es {
			if tab, ok := entry["table"].(map[string]any); ok {
				if _, exists := tab["comment"]; exists {
					t.Fatal("1.0.6 unexpectedly included JSON table comment")
				}
			}
		}
	}
	if e = verifyNFTText(text, m.table(p)); e != nil {
		t.Fatal(e)
	}
	single, e := m.Read(p)
	if e != nil || single.Up != 123 || single.Down != 456 || single.Consumed != 579 {
		t.Fatal(single, e)
	}
	// Simulate a warm upgrade from a version which included the JSON comment.
	for _, entry := range es {
		if tab, ok := entry["table"].(map[string]any); ok {
			tab["comment"] = trafficTableComment
		}
	}
	previousJSON, _ := json.Marshal(map[string]any{"nftables": es})
	previous, e := parseNFT(previousJSON)
	if e != nil || previous != single {
		t.Fatal("upgrade changed counters/hash", previous, single, e)
	}
	all, _ := m.ReadAll([]Profile{p})
	if all[p.ID].err != nil || all[p.ID].snap != single {
		t.Fatal("batch mismatch", all, single)
	}
	// Missing hook rules cannot be read as a healthy generation.
	if e = nftApply("flush chain inet " + m.table(p) + " input\n"); e != nil {
		t.Fatal(e)
	}
	if _, e = m.Read(p); e == nil {
		t.Fatal("missing rules accepted")
	}
	all, _ = m.ReadAll([]Profile{p})
	if all[p.ID].err == nil {
		t.Fatal("batch accepted damaged rules")
	}
	// Rebuilding from a known journal keeps recorded bytes and quota consumption.
	if _, e = m.Replace(p, want); e != nil {
		t.Fatal(e)
	}
	restored, e := m.Read(p)
	if e != nil || restored != single {
		t.Fatal("replacement lost recorded usage", restored, single, e)
	}
}

func TestKernelForeignTableNeverOverwritten(t *testing.T) {
	a := kernelApp(t)
	m := nftMeter{home: a.Home}
	p := fixture(t, "ss")
	name := m.table(p)
	// Even an exact Rout comment in a RULE is not evidence of table ownership.
	if e := nftApply("table inet " + name + " {\nchain input {\ncounter comment \"Rout traffic v1\"\n}\n}\n"); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = nftApply("delete table inet " + name + "\n") })
	before, _ := nftRun("", "-j", "list", "table", "inet", name)
	if _, e := m.Read(p); e == nil {
		t.Fatal("foreign table accepted")
	}
	if _, e := m.Replace(p, TrafficRecord{}); e == nil {
		t.Fatal("foreign table overwritten")
	}
	if e := m.Delete(p); e == nil {
		t.Fatal("foreign table deleted")
	}
	if e := m.Freeze(p); e == nil {
		t.Fatal("foreign table mutated")
	}
	if e := m.DeleteTables([]string{name}); e == nil {
		t.Fatal("legacy name treated as disposable probe")
	}
	after, _ := nftRun("", "-j", "list", "table", "inet", name)
	if !bytes.Equal(before, after) {
		t.Fatal("foreign firewall changed")
	}
}

func nftWrapper(t *testing.T, body string) {
	t.Helper()
	real, e := exec.LookPath("nft")
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	script := "#!/bin/sh\nreal=" + shellQuote(real) + "\n" + body + "\nexec " + shellQuote(real) + " \"$@\"\n"
	if e = os.WriteFile(filepath.Join(dir, "nft"), []byte(script), 0755); e != nil {
		t.Fatal(e)
	}
	// Lets InstallTraffic reach the probe on a container without an init manager.
	if e = os.WriteFile(filepath.Join(dir, "rc-service"), []byte("#!/bin/sh\nexit 1\n"), 0755); e != nil {
		t.Fatal(e)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
}

func TestKernelInstallProbeFailuresCleanUp(t *testing.T) {
	a := kernelApp(t)
	// These failures happen before any service/helper/marker mutation.
	a.ServiceMode = "auto"
	if e := os.Remove(filepath.Join(a.Home, "traffic.enabled")); e != nil {
		t.Fatal(e)
	}
	old := []byte("previous helper")
	if e := AtomicWrite(a.trafficHelper(), old, 0755); e != nil {
		t.Fatal(e)
	}
	m := nftMeter{home: a.Home}
	live := fixture(t, "ss")
	if _, e := m.Replace(live, TrafficRecord{RawUp: 100, RawDown: 200}); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = m.Delete(live) })
	before, e := nftRun("", "-j", "list", "ruleset")
	if e != nil {
		t.Fatal(e)
	}
	for _, failure := range []string{"echo '{'; exit 0", "echo 'Operation not permitted' >&2; exit 1", "echo '{\"nftables\":[]}'; exit 0"} {
		t.Run(failure, func(t *testing.T) {
			nftWrapper(t, "if [ \"$1\" = -j ] && [ \"$2\" = list ] && [ \"$3\" = table ]; then "+failure+"; fi")
			for i := 0; i < 3; i++ {
				if e := a.InstallTraffic(); e == nil {
					t.Fatal("injected read failure was ignored")
				}
			}
			helper, _ := os.ReadFile(a.trafficHelper())
			if !bytes.Equal(helper, old) {
				t.Fatal("failed probe replaced helper")
			}
			if a.trafficActive() {
				t.Fatal("failed install left success marker")
			}
		})
	}
	after, e := nftRun("", "-j", "list", "ruleset")
	if e != nil || !bytes.Equal(before, after) {
		t.Fatal("failed install leaked a table or changed another firewall", e, string(after))
	}
}

func TestKernelProbeCleanupErrorAndCollision(t *testing.T) {
	a := kernelApp(t)
	m := nftMeter{home: a.Home}
	p := fixture(t, "ss")
	p.ID = "probe_" + p.ID
	if _, e := m.Replace(p, TrafficRecord{RawUp: 999}); e != nil {
		t.Fatal(e)
	}
	before, _ := m.Read(p)
	if e := m.probe(p); e == nil {
		t.Fatal("exclusive probe overwrote existing table")
	}
	after, e := m.Read(p)
	if e != nil || after != before {
		t.Fatal("probe collision changed previous resource", after, e)
	}
	if e = m.Delete(p); e != nil {
		t.Fatal(e)
	}
	t.Run("cleanup failure", func(t *testing.T) {
		nftWrapper(t, "if [ \"$1\" = -f ]; then input=$(cat); case \"$input\" in 'delete table inet '*) echo 'Operation not permitted' >&2; exit 1;; esac; printf '%s\\n' \"$input\" | "+`"$real"`+" \"$@\"; exit $?; fi")
		e := m.probe(p)
		if e == nil || !strings.Contains(e.Error(), m.table(p)) || !strings.Contains(e.Error(), "清理") {
			t.Fatal("cleanup failure hidden", e)
		}
	})
	if e = m.Delete(p); e != nil {
		t.Fatal(e)
	}
}

// Real nft transactions with a stub init manager, so failed activation can be
// injected deterministically. Real systemd lifecycle is covered separately.
func TestKernelInstallFileTransaction(t *testing.T) {
	a := kernelApp(t)
	a.ServiceMode = "auto"
	if e := os.Remove(filepath.Join(a.Home, "traffic.enabled")); e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	t.Setenv("ROUT_INSTALL_STATE", filepath.Join(dir, "active"))
	t.Setenv("ROUT_INSTALL_FAIL", filepath.Join(dir, "fail"))
	script := `#!/bin/sh
case "$*" in
 *is-active*|*status) test -f "$ROUT_INSTALL_STATE"; exit $?;;
 *daemon-reload*|*disable*|*default) exit 0;;
 *stop*) rm -f "$ROUT_INSTALL_STATE"; exit 0;;
esac
if test -f "$ROUT_INSTALL_FAIL"; then rm -f "$ROUT_INSTALL_FAIL"; exit 1; fi
touch "$ROUT_INSTALL_STATE"
`
	for _, name := range []string{"systemctl", "rc-service", "rc-update"} {
		if e := os.WriteFile(filepath.Join(dir, name), []byte(script), 0755); e != nil {
			t.Fatal(e)
		}
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	manager, e := a.serviceManager()
	if e != nil {
		t.Fatal(e)
	}
	unit := filepath.Join("/etc/init.d", a.trafficService())
	if manager == "systemd" {
		unit = filepath.Join("/etc/systemd/system", a.trafficService()+".service")
	}
	t.Cleanup(func() { _ = os.Remove(unit) })
	oldHelper, oldUnit := []byte("old helper"), []byte("old service")
	if e = AtomicWrite(a.trafficHelper(), oldHelper, 0755); e != nil {
		t.Fatal(e)
	}
	if e = AtomicWrite(unit, oldUnit, 0644); e != nil {
		t.Fatal(e)
	}
	// A failed first activation restores files and leaves no success marker.
	if e = os.WriteFile(os.Getenv("ROUT_INSTALL_FAIL"), nil, 0600); e != nil {
		t.Fatal(e)
	}
	if e = a.InstallTraffic(); e == nil {
		t.Fatal("activation failure was ignored")
	}
	helper, _ := os.ReadFile(a.trafficHelper())
	savedUnit, _ := os.ReadFile(unit)
	if !bytes.Equal(helper, oldHelper) || !bytes.Equal(savedUnit, oldUnit) || a.trafficActive() {
		t.Fatal("failed install did not restore previous files")
	}
	for i := 0; i < 3; i++ {
		if e = a.InstallTraffic(); e != nil {
			t.Fatal(e)
		}
	}
	before, _ := os.ReadFile(a.trafficHelper())
	marker, _ := os.ReadFile(filepath.Join(a.Home, "traffic.enabled"))
	// Force a helper update followed by a failed restart; restore the previous
	// helper, definition and marker, and restart the previous monitor.
	if e = AtomicWrite(a.trafficHelper(), oldHelper, 0755); e != nil {
		t.Fatal(e)
	}
	currentUnit, _ := os.ReadFile(unit)
	if e = os.WriteFile(os.Getenv("ROUT_INSTALL_FAIL"), nil, 0600); e != nil {
		t.Fatal(e)
	}
	if e = a.InstallTraffic(); e == nil {
		t.Fatal("restart failure ignored")
	}
	helper, _ = os.ReadFile(a.trafficHelper())
	savedUnit, _ = os.ReadFile(unit)
	afterMarker, _ := os.ReadFile(filepath.Join(a.Home, "traffic.enabled"))
	if !bytes.Equal(helper, oldHelper) || !bytes.Equal(savedUnit, currentUnit) || !bytes.Equal(marker, afterMarker) {
		t.Fatal("failed update changed existing files")
	}
	if _, e = os.Stat(os.Getenv("ROUT_INSTALL_STATE")); e != nil {
		t.Fatal("previous monitor was not restored", e)
	}
	if e = AtomicWrite(a.trafficHelper(), before, 0755); e != nil {
		t.Fatal(e)
	}
	_, orphans := (nftMeter{home: a.Home}).ReadAll(nil)
	if len(orphans) != 0 {
		t.Fatal("repeated installation leaked probes", orphans)
	}
}

func TestKernelMissingJournalKeepsCountersAndQuotaClosed(t *testing.T) {
	a := kernelApp(t)
	p := kernelProfile(t, a, "127.0.0.1", "udp")
	c, got := udpEcho(t, p, false)
	if e := a.ConfigureTraffic(p.ID, TrafficPolicy{LimitBytes: 10000, BillingDay: 1}, false, time.Now()); e != nil {
		t.Fatal(e)
	}
	sendUDP(t, c, got, 72, true)
	if e := os.Remove(filepath.Join(a.Home, "traffic.json")); e != nil {
		t.Fatal(e)
	}
	if e := a.TrafficSync(time.Now(), false); e != nil {
		t.Fatal(e)
	}
	r := record(t, a, p.ID)
	if r.RawUp != 100 || r.RawDown != 0 || r.Consumed != 100 || !r.Incomplete || r.Blocked != blockFault {
		t.Fatal("missing journal discarded kernel usage or opened quota", r)
	}
	snap, e := a.meter().Read(p)
	if e != nil || snap.Up != 100 || snap.Consumed != 100 {
		t.Fatal(snap, e)
	}
	sendUDP(t, c, got, 72, false)
}
