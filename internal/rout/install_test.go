package rout

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallerChecksumAndAtomicReplacement(t *testing.T) {
	dir := t.TempDir()
	fixtures := filepath.Join(dir, "fixtures")
	bin := filepath.Join(dir, "bin")
	dest := filepath.Join(dir, "install")
	for _, p := range []string{fixtures, bin, dest} {
		if e := os.MkdirAll(p, 0700); e != nil {
			t.Fatal(e)
		}
	}
	payload := []byte("#!/bin/sh\nprintf 'rout 0.1.0\\n'\n")
	sum := fmt.Sprintf("%x", sha256.Sum256(payload))
	for _, arch := range []string{"amd64", "arm64"} {
		if e := os.WriteFile(filepath.Join(fixtures, "rout-linux-"+arch), payload, 0600); e != nil {
			t.Fatal(e)
		}
	}
	checksum := sum + "  rout-linux-amd64\n" + sum + "  rout-linux-arm64\n"
	if e := os.WriteFile(filepath.Join(fixtures, "checksums.txt"), []byte(checksum), 0600); e != nil {
		t.Fatal(e)
	}
	curl := "#!/bin/sh\nset -eu\nout=\nurl=\nwhile [ $# -gt 0 ]; do\n case \"$1\" in -o) out=$2; shift 2 ;; https://*) url=$1; shift ;; *) shift ;; esac\ndone\ncp \"$ROUT_TEST_FIXTURES/${url##*/}\" \"$out\"\n"
	if e := os.WriteFile(filepath.Join(bin, "curl"), []byte(curl), 0755); e != nil {
		t.Fatal(e)
	}
	// Installation is restricted to a private test directory; no root privileges are needed.
	if e := os.WriteFile(filepath.Join(bin, "id"), []byte("#!/bin/sh\nprintf '0\\n'\n"), 0755); e != nil {
		t.Fatal(e)
	}
	// The shell installer targets Linux; emulate its platform check on other
	// development hosts while retaining the real host architecture.
	if e := os.WriteFile(filepath.Join(bin, "uname"), []byte("#!/bin/sh\nif [ \"$1\" = -s ]; then echo Linux; else /usr/bin/uname \"$@\"; fi\n"), 0755); e != nil {
		t.Fatal(e)
	}
	run := func() ([]byte, error) {
		c := exec.Command("sh", "../../install.sh")
		c.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "ROUT_INSTALL_DIR="+dest, "ROUT_TEST_FIXTURES="+fixtures, "ROUT_VERSION=v0.1.0")
		return c.CombinedOutput()
	}
	if out, e := run(); e != nil {
		t.Fatalf("installer: %v %s", e, out)
	}
	actual, e := os.ReadFile(filepath.Join(dest, "rout"))
	if e != nil || string(actual) != string(payload) {
		t.Fatal("install mismatch")
	}
	wrong := []byte("#!/bin/sh\nprintf 'rout 9.9.9\\n'\n")
	wrongSum := fmt.Sprintf("%x", sha256.Sum256(wrong))
	for _, arch := range []string{"amd64", "arm64"} {
		if e := os.WriteFile(filepath.Join(fixtures, "rout-linux-"+arch), wrong, 0600); e != nil {
			t.Fatal(e)
		}
	}
	if e := os.WriteFile(filepath.Join(fixtures, "checksums.txt"), []byte(wrongSum+"  rout-linux-amd64\n"+wrongSum+"  rout-linux-arm64\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if out, e := run(); e == nil {
		t.Fatalf("accepted checksummed binary with wrong version: %s", out)
	}
	actual, e = os.ReadFile(filepath.Join(dest, "rout"))
	if e != nil || string(actual) != string(payload) {
		t.Fatal("version mismatch replaced executable")
	}
	if e = os.WriteFile(filepath.Join(fixtures, "checksums.txt"), []byte(strings.Repeat("0", 64)+"  rout-linux-amd64\n"+strings.Repeat("0", 64)+"  rout-linux-arm64\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if out, e := run(); e == nil {
		t.Fatalf("accepted wrong checksum: %s", out)
	}
	actual, e = os.ReadFile(filepath.Join(dest, "rout"))
	if e != nil || string(actual) != string(payload) {
		t.Fatal("failed update replaced executable")
	}
}
