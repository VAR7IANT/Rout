package rout

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// Engine installation tests. A local TLS server stands in for GitHub; the installer talks to
// it through newHTTPClient. The fake "engine" is a shell script so the staged-binary
// execution check is real.

const fakeEngineScript = "#!/bin/sh\nexit 0\n"

func tarGz(t testing.TB, entries map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range entries {
		if e := tw.WriteHeader(&tar.Header{Name: name, Mode: 0755, Size: int64(len(body)), Typeflag: tar.TypeReg}); e != nil {
			t.Fatal(e)
		}
		if _, e := tw.Write(body); e != nil {
			t.Fatal(e)
		}
	}
	if e := tw.Close(); e != nil {
		t.Fatal(e)
	}
	if e := gz.Close(); e != nil {
		t.Fatal(e)
	}
	return buf.Bytes()
}
func sumHex(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func installApp(t *testing.T) *App {
	t.Helper()
	return &App{Home: t.TempDir(), BinDir: t.TempDir(), ServiceMode: "none", Language: "en"}
}

// serve starts a TLS server and routes the installer's HTTP client to it.
func serve(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	prev := newHTTPClient
	newHTTPClient = func() *http.Client { return srv.Client() }
	t.Cleanup(func() { newHTTPClient = prev; srv.Close() })
	return srv
}
func bodyHandler(body []byte, hits *atomic.Int32) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			hits.Add(1)
		}
		w.Write(body)
	})
}

// leftovers lists anything the installer left in the bin directory besides engines and its lock.
func leftovers(t *testing.T, dir string) []string {
	t.Helper()
	entries, e := os.ReadDir(dir)
	if e != nil {
		t.Fatal(e)
	}
	var out []string
	for _, ent := range entries {
		if strings.HasPrefix(ent.Name(), ".download-") || strings.HasPrefix(ent.Name(), ".rout-") {
			out = append(out, ent.Name())
		}
	}
	return out
}
func readFile(t *testing.T, path string) string {
	t.Helper()
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	return string(b)
}

func TestEngineInstallStreamsVerifiesAndCleans(t *testing.T) {
	a := installApp(t)
	archive := tarGz(t, map[string][]byte{"sing-box-1.0/LICENSE": []byte("license"), "sing-box-1.0/sing-box": []byte(fakeEngineScript)})
	var hits atomic.Int32
	srv := serve(t, bodyHandler(archive, &hits))
	path := a.enginePath("sing-box")
	if e := a.installEngine("sing-box", path, Asset{URL: srv.URL + "/e.tar.gz", SHA256: sumHex(archive)}); e != nil {
		t.Fatal(e)
	}
	st, e := os.Stat(path)
	if e != nil || st.Mode().Perm() != 0755 || readFile(t, path) != fakeEngineScript {
		t.Fatalf("installed engine wrong: %v %v", e, st)
	}
	if l := leftovers(t, a.BinDir); len(l) != 0 {
		t.Fatalf("temporary files left behind: %v", l)
	}
	// A working engine is never downloaded again.
	if e := a.installEngine("sing-box", path, Asset{URL: srv.URL + "/e.tar.gz", SHA256: sumHex(archive)}); e != nil || hits.Load() != 1 {
		t.Fatalf("working engine re-downloaded: %v hits=%d", e, hits.Load())
	}
}

func TestEngineInstallFailuresKeepExistingEngineAndClean(t *testing.T) {
	good := tarGz(t, map[string][]byte{"sing-box": []byte(fakeEngineScript)})
	notRunnable := tarGz(t, map[string][]byte{"sing-box": []byte("\x7fELF-not-runnable")})
	garbage := []byte("this is not gzip at all")
	truncatedTar := func() []byte {
		// A valid gzip stream whose tar header promises more bytes than the archive holds.
		var raw bytes.Buffer
		tw := tar.NewWriter(&raw)
		tw.WriteHeader(&tar.Header{Name: "sing-box", Mode: 0755, Size: 4096, Typeflag: tar.TypeReg})
		tw.Write(bytes.Repeat([]byte("x"), 100))
		var out bytes.Buffer
		gz := gzip.NewWriter(&out)
		gz.Write(raw.Bytes()[:512+100]) // header block + part of the data, no padding or trailer
		gz.Close()
		return out.Bytes()
	}()
	oversize := func() []byte {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gz)
		tw.WriteHeader(&tar.Header{Name: "sing-box", Mode: 0755, Size: maxEngineBytes + 1, Typeflag: tar.TypeReg})
		gz.Close()
		return buf.Bytes()
	}()
	cases := []struct {
		name    string
		body    []byte
		digest  string // empty: correct digest of body
		handler http.Handler
		want    string
	}{
		{"checksum mismatch", good, sumHex([]byte("something else")), nil, "SHA256"},
		{"not gzip", garbage, "", nil, "损坏"},
		{"truncated entry", truncatedTar, "", nil, "损坏"},
		{"entry missing", tarGz(t, map[string][]byte{"other": []byte("x")}), "", nil, "没有找到内核"},
		{"entry too large", oversize, "", nil, ""},
		{"engine cannot run", notRunnable, "", nil, "无法在本机运行"},
		{"HTTP error", nil, "", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", 500) }), "HTTP 500"},
		{"connection cut mid-download", nil, "", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", "100000")
			w.Write(bytes.Repeat([]byte("x"), 1000))
			c, _, _ := w.(http.Hijacker).Hijack()
			c.Close()
		}), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := installApp(t)
			path := a.enginePath("sing-box")
			// An existing but unusable engine (e.g. a glibc build on Alpine) is the only
			// thing an install may replace, and only with a verified, runnable one.
			const old = "\x7fELF-old-unusable-engine"
			if e := os.WriteFile(path, []byte(old), 0755); e != nil {
				t.Fatal(e)
			}
			h := tc.handler
			digest := tc.digest
			if h == nil {
				h = bodyHandler(tc.body, nil)
				if digest == "" {
					digest = sumHex(tc.body)
				}
			}
			srv := serve(t, h)
			e := a.installEngine("sing-box", path, Asset{URL: srv.URL + "/e", SHA256: digest})
			if e == nil {
				t.Fatal("failure was not reported")
			}
			if tc.want != "" && !strings.Contains(e.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", e, tc.want)
			}
			if got := readFile(t, path); got != old {
				t.Fatalf("existing engine was modified by a failed install: %q", got)
			}
			if l := leftovers(t, a.BinDir); len(l) != 0 {
				t.Fatalf("temporary files left behind: %v", l)
			}
		})
	}
	t.Run("plain HTTP is refused", func(t *testing.T) {
		a := installApp(t)
		if e := a.installEngine("sing-box", a.enginePath("sing-box"), Asset{URL: "http://127.0.0.1:1/e", SHA256: strings.Repeat("0", 64)}); e == nil || !strings.Contains(e.Error(), "HTTPS") {
			t.Fatal("accepted a non-HTTPS download", e)
		}
	})
	t.Run("a verified runnable engine replaces an unusable one", func(t *testing.T) {
		a := installApp(t)
		path := a.enginePath("sing-box")
		os.WriteFile(path, []byte("\x7fELF-old-unusable-engine"), 0755)
		srv := serve(t, bodyHandler(good, nil))
		if e := a.installEngine("sing-box", path, Asset{URL: srv.URL + "/e", SHA256: sumHex(good)}); e != nil {
			t.Fatal(e)
		}
		if readFile(t, path) != fakeEngineScript {
			t.Fatal("engine not replaced")
		}
	})
}

func TestEngineInstallConcurrentAttemptsDownloadOnce(t *testing.T) {
	a := installApp(t)
	archive := tarGz(t, map[string][]byte{"sing-box": []byte(fakeEngineScript)})
	var hits atomic.Int32
	srv := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		time.Sleep(200 * time.Millisecond) // widen the race window
		w.Write(archive)
	}))
	path := a.enginePath("sing-box")
	asset := Asset{URL: srv.URL + "/e", SHA256: sumHex(archive)}
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- a.installEngine("sing-box", path, asset) }()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("concurrent installers downloaded %d times", hits.Load())
	}
	if !engineRuns("sing-box", path) || len(leftovers(t, a.BinDir)) != 0 {
		t.Fatal("engine missing or temporary files left")
	}
}

func TestEngineInstallRemovesOnlyStaleStaging(t *testing.T) {
	a := installApp(t)
	stale := filepath.Join(a.BinDir, ".download-stale")
	fresh := filepath.Join(a.BinDir, ".download-fresh")
	for _, d := range []string{stale, fresh} {
		if e := os.MkdirAll(d, 0700); e != nil {
			t.Fatal(e)
		}
		os.WriteFile(filepath.Join(d, "engine.tar.gz"), []byte("partial"), 0600)
	}
	old := time.Now().Add(-time.Hour)
	os.Chtimes(stale, old, old)
	archive := tarGz(t, map[string][]byte{"sing-box": []byte(fakeEngineScript)})
	srv := serve(t, bodyHandler(archive, nil))
	if e := a.installEngine("sing-box", a.enginePath("sing-box"), Asset{URL: srv.URL + "/e", SHA256: sumHex(archive)}); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(stale); e == nil {
		t.Fatal("abandoned staging directory from a killed installer was kept")
	}
	if _, e := os.Stat(fresh); e != nil {
		t.Fatal("a recent staging directory (maybe another installer's) was removed")
	}
}

// ---- Process-level tests: killed installers and peak memory ----

// The test binary re-executes itself as the installer under test.
//
//	ROUT_ENGINE_CHILD=stream|legacy|idle|hang  ROUT_ENGINE_ARCHIVE=<tar.gz path>  ROUT_ENGINE_BIN=<dir>
func TestMain(m *testing.M) {
	if mode := os.Getenv("ROUT_ENGINE_CHILD"); mode != "" {
		os.Exit(engineChild(mode))
	}
	os.Exit(m.Run())
}

// legacyInstall is the v0.3.0 extraction (the whole engine in memory, then one write), kept
// only so the memory test can show that it measures the problem.
func legacyInstall(archive, name, path string) error {
	f, e := os.Open(archive)
	if e != nil {
		return e
	}
	defer f.Close()
	gz, e := gzip.NewReader(f)
	if e != nil {
		return e
	}
	tr := tar.NewReader(gz)
	for {
		h, e := tr.Next()
		if e != nil {
			return e
		}
		if h.Typeflag == tar.TypeReg && filepath.Base(h.Name) == name {
			b, e := io.ReadAll(io.LimitReader(tr, h.Size))
			if e != nil {
				return e
			}
			return AtomicWrite(path, b, 0755)
		}
	}
}

func engineChild(mode string) int {
	archive, bin := os.Getenv("ROUT_ENGINE_ARCHIVE"), os.Getenv("ROUT_ENGINE_BIN")
	a := &App{Home: filepath.Join(bin, "home"), BinDir: bin, ServiceMode: "none", Language: "en"}
	path := a.enginePath("sing-box")
	if mode == "legacy" {
		if e := legacyInstall(archive, "sing-box", path); e != nil {
			fmt.Fprintln(os.Stderr, e)
			return 1
		}
		return 0
	}
	hang := mode == "hang"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f, e := os.Open(archive)
		if e != nil {
			http.Error(w, e.Error(), 500)
			return
		}
		defer f.Close()
		if hang {
			st, _ := f.Stat()
			w.Header().Set("Content-Length", fmt.Sprint(st.Size()))
			io.CopyN(w, f, 1<<20)
			w.(http.Flusher).Flush()
			fmt.Println("partial") // the parent kills this process while the body is incomplete
			time.Sleep(time.Minute)
			return
		}
		http.ServeContent(w, r, "e.tar.gz", time.Time{}, f)
	}))
	defer srv.Close()
	newHTTPClient = func() *http.Client { return srv.Client() }
	sum, e := fileSum(archive)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		return 1
	}
	if mode == "idle" {
		return 0
	}
	if e := a.installEngine("sing-box", path, Asset{URL: srv.URL + "/e", SHA256: sum}); e != nil {
		fmt.Fprintln(os.Stderr, e)
		return 1
	}
	return 0
}
func fileSum(path string) (string, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	h := sha256.New()
	if _, e = io.Copy(h, f); e != nil {
		return "", e
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// bigArchive writes a tar.gz holding one incompressible engine of the given size, streaming
// so the test itself stays small.
func bigArchive(t *testing.T, size int64) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "engine.tar.gz")
	f, e := os.Create(path)
	if e != nil {
		t.Fatal(e)
	}
	gz, _ := gzip.NewWriterLevel(f, gzip.BestSpeed)
	tw := tar.NewWriter(gz)
	if e = tw.WriteHeader(&tar.Header{Name: "sing-box-x/sing-box", Mode: 0755, Size: size, Typeflag: tar.TypeReg}); e != nil {
		t.Fatal(e)
	}
	// Runnable script first; random bytes after `exit 0` are never parsed by sh.
	if _, e = tw.Write([]byte(fakeEngineScript)); e != nil {
		t.Fatal(e)
	}
	rng := rand.New(rand.NewSource(1))
	chunk := make([]byte, 1<<20)
	for left := size - int64(len(fakeEngineScript)); left > 0; {
		n := int64(len(chunk))
		if left < n {
			n = left
		}
		rng.Read(chunk[:n])
		if _, e = tw.Write(chunk[:n]); e != nil {
			t.Fatal(e)
		}
		left -= n
	}
	if e = tw.Close(); e == nil {
		e = gz.Close()
	}
	if e == nil {
		e = f.Close()
	}
	if e != nil {
		t.Fatal(e)
	}
	return path
}
func runChild(t *testing.T, mode, archive, bin string) (peakKiB int64, err error) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), "ROUT_ENGINE_CHILD="+mode, "ROUT_ENGINE_ARCHIVE="+archive, "ROUT_ENGINE_BIN="+bin)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err = cmd.Run()
	if err != nil {
		err = fmt.Errorf("%w: %s", err, stderr.String())
	}
	if cmd.ProcessState != nil {
		if ru, ok := cmd.ProcessState.SysUsage().(*syscall.Rusage); ok {
			peakKiB = int64(ru.Maxrss)
		}
	}
	return
}

// The headline memory regression: installing a ~96 MiB engine must not need memory
// proportional to its size, while the previous implementation does. Peak RSS is read from
// the kernel (ru_maxrss) of an isolated child process; the child's idle baseline (Go
// runtime, TLS test server, race detector if enabled) is subtracted.
func TestEngineInstallPeakMemoryIsBounded(t *testing.T) {
	if runtime.GOOS != "linux" || testing.Short() {
		t.Skip("peak RSS measurement needs Linux and a full run")
	}
	const size = 96 << 20
	archive := bigArchive(t, size)
	base, e := runChild(t, "idle", archive, t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	bin := t.TempDir()
	stream, e := runChild(t, "stream", archive, bin)
	if e != nil {
		t.Fatal(e)
	}
	if st, er := os.Stat(filepath.Join(bin, "sing-box-"+engines()["sing-box"].Version)); er != nil || st.Size() != size {
		t.Fatalf("engine not installed completely: %v", er)
	}
	legacy, e := runChild(t, "legacy", archive, t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	mib := func(k int64) float64 { return float64(k) / 1024 }
	t.Logf("peak RSS: idle baseline %.1f MiB, streaming install %.1f MiB (+%.1f), previous in-memory install %.1f MiB (+%.1f), engine size %d MiB",
		mib(base), mib(stream), mib(stream-base), mib(legacy), mib(legacy-base), size>>20)
	if d := (stream - base) * 1024; d > size/3 {
		t.Errorf("streaming install grew peak RSS by %.1f MiB for a %d MiB engine", float64(d)/(1<<20), size>>20)
	}
	if d := (legacy - base) * 1024; d < size {
		t.Errorf("harness failed to expose the old in-memory behaviour (+%.1f MiB)", float64(d)/(1<<20))
	}
}

// A SIGKILLed installer (what the OOM killer does) must neither wedge later installs nor
// damage an existing engine; its abandoned staging data is reclaimed once it is stale.
func TestEngineInstallAfterKilledInstaller(t *testing.T) {
	if runtime.GOOS != "linux" || testing.Short() {
		t.Skip("needs Linux and a full run")
	}
	archive := bigArchive(t, 8<<20)
	bin := t.TempDir()
	a := &App{Home: filepath.Join(bin, "home"), BinDir: bin, ServiceMode: "none", Language: "en"}
	path := a.enginePath("sing-box")
	const old = "\x7fELF-old-unusable-engine"
	if e := os.WriteFile(path, []byte(old), 0755); e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), "ROUT_ENGINE_CHILD=hang", "ROUT_ENGINE_ARCHIVE="+archive, "ROUT_ENGINE_BIN="+bin)
	stdout, _ := cmd.StdoutPipe()
	if e := cmd.Start(); e != nil {
		t.Fatal(e)
	}
	buf := make([]byte, 16)
	if _, e := stdout.Read(buf); e != nil {
		t.Fatal("installer never reached the download", e)
	}
	if got := leftovers(t, bin); len(got) != 1 {
		t.Fatalf("expected the child's staging directory, got %v", got)
	}
	cmd.Process.Kill()
	cmd.Wait()
	if readFile(t, path) != old {
		t.Fatal("killed installer damaged the existing engine")
	}
	// Its staging directory is abandoned. Age it, then a new install cleans it and succeeds.
	for _, name := range leftovers(t, bin) {
		oldTime := time.Now().Add(-time.Hour)
		os.Chtimes(filepath.Join(bin, name), oldTime, oldTime)
	}
	sum, _ := fileSum(archive)
	srv := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.ServeFile(w, r, archive) }))
	if e := a.installEngine("sing-box", path, Asset{URL: srv.URL + "/e", SHA256: sum}); e != nil {
		t.Fatalf("install after a killed installer failed (stuck lock?): %v", e)
	}
	if !engineRuns("sing-box", path) || len(leftovers(t, bin)) != 0 {
		t.Fatal("engine not recovered or abandoned staging data kept")
	}
}

func TestCopyFileAtomicStreamsAndKeepsDestinationOnFailure(t *testing.T) {
	dir := t.TempDir()
	src, dst := filepath.Join(dir, "src"), filepath.Join(dir, "dst")
	os.WriteFile(src, bytes.Repeat([]byte("ab"), 1<<20), 0600)
	os.WriteFile(dst, []byte("previous"), 0755)
	if e := copyFileAtomic(src, dst, 0755); e != nil || readFile(t, dst) != readFile(t, src) {
		t.Fatal("copy failed", e)
	}
	if e := copyFileAtomic(filepath.Join(dir, "missing"), dst, 0755); e == nil || readFile(t, dst) != readFile(t, src) {
		t.Fatal("failed copy changed the destination")
	}
	if l := leftovers(t, dir); len(l) != 0 {
		t.Fatal("temporary files left", l)
	}
}
