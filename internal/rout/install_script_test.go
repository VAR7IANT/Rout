package rout

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// Runs scripts/test-install.sh, the regression test of the unmodified install.sh (asset names,
// SHA256, version check, atomic replacement, a missing release fails closed, no download source
// other than the official release URLs). It builds the binary of this checkout, so what is
// tested is the installer together with the version it would install. The release workflow
// repeats it on the real cross-built artifacts of both architectures.
func TestInstallScriptRegression(t *testing.T) {
	if runtime.GOOS != "linux" || testing.Short() {
		t.Skip("Linux installer regression; skipped in -short mode")
	}
	goBin, e := exec.LookPath("go")
	if e != nil {
		t.Skip("go toolchain not available")
	}
	if _, e = exec.LookPath("sh"); e != nil {
		t.Skip("sh not available")
	}
	host := runtime.GOARCH
	other := map[string]string{"amd64": "arm64", "arm64": "amd64"}[host]
	if other == "" {
		t.Skipf("the installer supports amd64 and arm64, not %s", host)
	}
	dist := t.TempDir()
	build := exec.Command(goBin, "build", "-trimpath", "-o", filepath.Join(dist, "rout-linux-"+host), "./cmd/rout")
	build.Dir = "../.."
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+host)
	if out, e := build.CombinedOutput(); e != nil {
		t.Fatalf("build: %v\n%s", e, out)
	}
	binary, e := os.ReadFile(filepath.Join(dist, "rout-linux-"+host))
	if e != nil {
		t.Fatal(e)
	}
	// The other architecture's artifact is a copy: here only its NAME and checksum handling
	// are under test (it cannot run on this host); the workflow tests the real cross build.
	if e = os.WriteFile(filepath.Join(dist, "rout-linux-"+other), binary, 0755); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(dist, "version.txt"), []byte("v"+Version+"\n"), 0644); e != nil {
		t.Fatal(e)
	}
	sum := fmt.Sprintf("%x", sha256.Sum256(binary))
	ver := fmt.Sprintf("%x", sha256.Sum256([]byte("v"+Version+"\n")))
	manifest := fmt.Sprintf("%s  rout-linux-amd64\n%s  rout-linux-arm64\n%s  version.txt\n", sum, sum, ver)
	if e = os.WriteFile(filepath.Join(dist, "checksums.txt"), []byte(manifest), 0644); e != nil {
		t.Fatal(e)
	}
	out, e := exec.Command("sh", "../../scripts/test-install.sh", dist).CombinedOutput()
	t.Logf("%s", out)
	if e != nil {
		t.Fatalf("install.sh regression failed: %v", e)
	}
}
