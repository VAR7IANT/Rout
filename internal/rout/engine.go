package rout

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

//go:embed engines.lock.json
var engineLock []byte

type Asset struct {
	Name   string `json:"name"`
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	// "musl" marks a statically linked build for hosts without glibc (Alpine).
	Libc string `json:"libc,omitempty"`
}
type Engine struct {
	Version string  `json:"version"`
	Assets  []Asset `json:"assets"`
}

func engines() map[string]Engine {
	var out map[string]Engine
	if e := json.Unmarshal(engineLock, &out); e != nil {
		panic(e)
	}
	return out
}
func (a *App) enginePath(name string) string {
	return filepath.Join(a.BinDir, name+"-"+engines()[name].Version)
}
func httpClient() *http.Client {
	return &http.Client{Timeout: 3 * time.Minute, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" {
			return errors.New("拒绝非 HTTPS 下载")
		}
		if len(via) > 10 {
			return errors.New("重定向过多")
		}
		return nil
	}}
}

// Tests substitute a client that trusts their local TLS server.
var newHTTPClient = httpClient

// Memory discipline: nothing here ever holds an archive or an engine in memory. Bytes move
// through one fixed-size buffer, and written data is flushed and dropped from the page
// cache every syncEvery bytes, because on a small VPS inside a memory-limited cgroup the
// dirty pages of an 80 MB engine count against the limit just like heap does.
const (
	maxArchiveBytes  = 200 << 20
	maxEngineBytes   = 150 << 20
	copyBufferSize   = 256 << 10
	syncEvery        = 8 << 20
	engineLockWait   = 5 * time.Minute
	staleDownloadAge = 15 * time.Minute
)

// flushWriter forwards writes and periodically makes them durable and evictable.
type flushWriter struct {
	f       *os.File
	pending int64
}

func (w *flushWriter) Write(b []byte) (int, error) {
	n, e := w.f.Write(b)
	w.pending += int64(n)
	if e == nil && w.pending >= syncEvery {
		w.pending = 0
		if e = w.f.Sync(); e == nil {
			dropFileCache(w.f)
		}
	}
	return n, e
}

// copyN copies exactly n bytes through one bounded buffer; a short source is an error.
func copyN(dst io.Writer, src io.Reader, n int64) error {
	buf := make([]byte, copyBufferSize)
	written, e := io.CopyBuffer(struct{ io.Writer }{dst}, io.LimitReader(src, n), buf)
	if e != nil {
		return e
	}
	if written != n {
		return io.ErrUnexpectedEOF
	}
	return nil
}

// download streams a HTTPS body to path, hashing as it goes. On any failure the partial
// file is removed. An empty digest skips verification (used only for the checksum list,
// whose content is then compared by the caller).
func download(url, path, digest string) (err error) {
	if !strings.HasPrefix(url, "https://") {
		return errors.New("下载地址必须为 HTTPS")
	}
	r, e := newHTTPClient().Get(url)
	if e != nil {
		return errors.New("下载连接失败，请检查网络")
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return fmt.Errorf("下载失败 HTTP %d", r.StatusCode)
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			os.Remove(path)
		}
	}()
	h := sha256.New()
	buf := make([]byte, copyBufferSize)
	n, e := io.CopyBuffer(struct{ io.Writer }{io.MultiWriter(&flushWriter{f: f}, h)}, io.LimitReader(r.Body, maxArchiveBytes), buf)
	if e != nil {
		return e
	}
	if n >= maxArchiveBytes {
		return errors.New("下载文件过大")
	}
	if digest != "" && hex.EncodeToString(h.Sum(nil)) != digest {
		return errors.New("SHA256 校验失败，未安装下载内容")
	}
	return f.Sync()
}

// copyFileAtomic copies src to dst through a same-directory temporary file (streaming).
func copyFileAtomic(src, dst string, mode os.FileMode) (err error) {
	in, e := os.Open(src)
	if e != nil {
		return e
	}
	defer in.Close()
	out, e := os.CreateTemp(filepath.Dir(dst), ".rout-*")
	if e != nil {
		return e
	}
	tmp := out.Name()
	defer func() {
		if err != nil {
			os.Remove(tmp)
		}
	}()
	buf := make([]byte, copyBufferSize)
	if _, e = io.CopyBuffer(struct{ io.Writer }{&flushWriter{f: out}}, in, buf); e == nil {
		e = out.Chmod(mode)
	}
	if e == nil {
		e = out.Sync()
	}
	if ce := out.Close(); e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	return os.Rename(tmp, dst)
}

// hostLibc is "glibc" when the dynamic loader that default engine builds need exists;
// otherwise (Alpine/musl, minimal images) only a statically linked build can run.
var glibcLoaders = map[string]string{"amd64": "/lib64/ld-linux-x86-64.so.2", "arm64": "/lib/ld-linux-aarch64.so.1"}

func hostLibc() string {
	if _, e := os.Stat(glibcLoaders[runtime.GOARCH]); e == nil {
		return "glibc"
	}
	return "musl"
}

// engineAsset picks the pinned archive for this architecture and C library. A static
// (libc-neutral) asset serves every host; a musl asset is preferred where glibc is absent.
func engineAsset(name, arch, libc string) Asset {
	var generic, musl Asset
	for _, v := range engines()[name].Assets {
		if !strings.Contains(v.Name, "linux-"+arch) && !strings.Contains(v.Name, "linux_"+arch) {
			continue
		}
		if v.Libc == "musl" {
			musl = v
		} else if v.Libc == "" {
			generic = v
		}
	}
	if libc == "musl" && musl.URL != "" {
		return musl
	}
	return generic
}

// engineRuns proves an installed engine can execute on this host (a glibc-linked
// binary on Alpine cannot), so a broken install is replaced instead of trusted.
func engineRuns(name, path string) bool {
	flag := "version"
	if name == "gost" {
		flag = "-V"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Only a failure to execute at all (missing loader, wrong format) means broken; a
	// started process that exits non-zero is left for the configuration check to report.
	e := exec.CommandContext(ctx, path, flag).Run()
	var exit *exec.ExitError
	return e == nil || errors.As(e, &exit) || ctx.Err() != nil
}
func engineUsable(name, path string) bool {
	st, e := os.Stat(path)
	return e == nil && st.Mode().IsRegular() && st.Mode()&0111 != 0 && engineRuns(name, path)
}

func (a *App) EnsureEngine(name string) error {
	path := a.enginePath(name)
	if engineUsable(name, path) {
		return nil
	}
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		return errors.New("仅支持 Linux amd64/arm64")
	}
	asset := engineAsset(name, runtime.GOARCH, hostLibc())
	if asset.URL == "" || len(asset.SHA256) != 64 {
		return errors.New("缺少经过校验的内核下载信息")
	}
	if e := os.MkdirAll(a.BinDir, 0755); e != nil {
		return e
	}
	a.printf("下载并校验 %s %s…\n", name, engines()[name].Version)
	return a.installEngine(name, path, asset)
}

// installEngine downloads, verifies, extracts and atomically installs one engine.
//
//   - One installer at a time per bin directory (flock); a waiter re-checks afterwards, so
//     concurrent attempts download once.
//   - The archive is streamed to disk and SHA256-verified before it is opened; the engine is
//     streamed out of the archive into a staging file, never held in memory.
//   - The staged binary must actually execute before it replaces anything. The final step
//     is a same-filesystem rename, so a failure at any earlier point leaves the existing
//     file (if any) untouched; the staging directory is always removed.
func (a *App) installEngine(name, path string, asset Asset) error {
	unlock, e := lockFile(filepath.Join(a.BinDir, ".install.lock"), engineLockWait)
	if e != nil {
		if errors.Is(e, errLockBusy) {
			return errors.New("另一个内核安装仍在进行，请稍后重试")
		}
		return e
	}
	defer unlock()
	if engineUsable(name, path) {
		return nil
	}
	removeStaleDownloads(a.BinDir, staleDownloadAge)
	tmp, e := os.MkdirTemp(a.BinDir, ".download-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(tmp)
	archive := filepath.Join(tmp, "engine.tar.gz")
	if e = download(asset.URL, archive, asset.SHA256); e != nil {
		return e
	}
	staged := filepath.Join(tmp, "engine.bin")
	if e = extractEngine(archive, name, staged); e != nil {
		return e
	}
	// The archive is no longer needed; free its disk space before the final steps.
	os.Remove(archive)
	if !engineRuns(name, staged) {
		return errors.New("下载的内核无法在本机运行，已保留原有文件")
	}
	if e = os.Rename(staged, path); e != nil {
		return e
	}
	if d, er := os.Open(filepath.Dir(path)); er == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

// extractEngine streams the named regular file from a .tar.gz into dst (mode 0755).
func extractEngine(archive, name, dst string) (err error) {
	f, e := os.Open(archive)
	if e != nil {
		return e
	}
	defer f.Close()
	gz, e := gzip.NewReader(f)
	if e != nil {
		return errors.New("下载归档已损坏")
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return errors.New("下载归档已损坏")
		}
		if h.Typeflag != tar.TypeReg || filepath.Base(h.Name) != name {
			continue
		}
		if h.Size <= 0 || h.Size > maxEngineBytes {
			return errors.New("内核文件大小无效")
		}
		out, e := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
		if e != nil {
			return e
		}
		defer func() {
			if err != nil {
				os.Remove(dst)
			}
		}()
		e = copyN(&flushWriter{f: out}, tr, h.Size)
		if e == nil {
			e = out.Chmod(0755)
		}
		if e == nil {
			e = out.Sync()
		}
		if ce := out.Close(); e == nil {
			e = ce
		}
		if e != nil {
			if errors.Is(e, io.ErrUnexpectedEOF) {
				return errors.New("下载归档已损坏")
			}
			return e
		}
		return nil
	}
	return errors.New("下载归档中没有找到内核")
}

// removeStaleDownloads deletes staging directories abandoned by a killed installer. The
// caller holds the install lock, so only old directories (possibly from a v0.3.0 process
// that did not lock) are considered.
func removeStaleDownloads(dir string, age time.Duration) {
	entries, _ := os.ReadDir(dir)
	for _, ent := range entries {
		if !ent.IsDir() || !strings.HasPrefix(ent.Name(), ".download-") {
			continue
		}
		if info, e := ent.Info(); e == nil && time.Since(info.ModTime()) > age {
			os.RemoveAll(filepath.Join(dir, ent.Name()))
		}
	}
}
func runOutput(timeout time.Duration, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, e := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if ctx.Err() != nil {
		return out, errors.New("命令执行超时")
	}
	return out, e
}
func (a *App) checkConfig(path string) error {
	out, e := runOutput(15*time.Second, a.enginePath("sing-box"), "check", "-c", path)
	if e != nil {
		// Config errors may contain credentials: show only the error category to users.
		_ = out
		return errors.New("sing-box 配置检查失败，请检查协议参数、证书或内核兼容性")
	}
	return nil
}

// parseVersion accepts only plain release tags such as v0.2.2.
func parseVersion(tag string) ([3]int, bool) {
	var v [3]int
	parts := strings.Split(strings.TrimPrefix(tag, "v"), ".")
	if !strings.HasPrefix(tag, "v") || len(parts) != 3 {
		return v, false
	}
	for i, part := range parts {
		n, e := strconv.Atoi(part)
		if e != nil || n < 0 || part != strconv.Itoa(n) {
			return v, false
		}
		v[i] = n
	}
	return v, true
}

// compareVersions returns -1, 0 or 1 like strings.Compare.
func compareVersions(a, b [3]int) int {
	for i := range a {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// SelfUpdate replaces the manager with a newer release only. The SHA256 file comes
// from the same release, so it proves integrity, not authenticity; releases also carry
// GitHub build-provenance attestations for independent verification.
func SelfUpdate(language ...string) error {
	a := DefaultApp()
	if len(language) > 0 {
		a.Language = language[0]
	}
	return a.selfUpdate()
}
func (a *App) selfUpdate() error {
	r, e := httpClient().Get("https://api.github.com/repos/VAR7IANT/Rout/releases/latest")
	if e != nil {
		return errors.New("无法查询更新")
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return fmt.Errorf("查询更新失败 HTTP %d", r.StatusCode)
	}
	var release struct {
		Tag    string `json:"tag_name"`
		Draft  bool   `json:"draft"`
		Pre    bool   `json:"prerelease"`
		Assets []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if e = json.NewDecoder(io.LimitReader(r.Body, 2<<20)).Decode(&release); e != nil {
		return e
	}
	latest, ok := parseVersion(release.Tag)
	current, _ := parseVersion("v" + Version)
	if !ok || release.Draft || release.Pre {
		return errors.New("最新发布版本标签无效，未更新")
	}
	switch compareVersions(latest, current) {
	case 0:
		a.say("已是当前发布版本")
		return nil
	case -1:
		return fmt.Errorf("最新发布版本 %s 低于当前版本 v%s，拒绝降级", release.Tag, Version)
	}
	name := "rout-linux-" + runtime.GOARCH
	var binaryURL, checksumURL string
	for _, v := range release.Assets {
		if v.Name == name {
			binaryURL = v.URL
		}
		if v.Name == "checksums.txt" {
			checksumURL = v.URL
		}
	}
	if binaryURL == "" || checksumURL == "" {
		return errors.New("该版本缺少适用的二进制或校验文件")
	}
	exe, e := os.Executable()
	if e != nil {
		return e
	}
	exe, e = filepath.EvalSymlinks(exe)
	if e != nil {
		return e
	}
	tmp, e := os.MkdirTemp(filepath.Dir(exe), ".rout-update-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(tmp)
	if e = download(checksumURL, filepath.Join(tmp, "checksums"), ""); e != nil {
		return e
	}
	b, e := os.ReadFile(filepath.Join(tmp, "checksums"))
	if e != nil {
		return e
	}
	var hash string
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == name {
			hash = f[0]
		}
	}
	if len(hash) != 64 {
		return errors.New("缺少校验值")
	}
	p := filepath.Join(tmp, name)
	if e = download(binaryURL, p, hash); e != nil {
		return e
	}
	if e = os.Chmod(p, 0755); e != nil {
		return e
	}
	// The staged binary must run AND report exactly the release it claims to be.
	out, e := runOutput(10*time.Second, p, "version")
	if e != nil || strings.TrimSpace(string(out)) != "rout "+strings.TrimPrefix(release.Tag, "v") {
		return errors.New("新版本无法运行或版本不符，保留旧版本")
	}
	// Ask the staged, backward-compatible manager to snapshot subscriptions before
	// replacement. No migration, token regeneration or service restart occurs here.
	if _, e = runOutput(30*time.Second, p, "--home", a.Home, "--bin-dir", a.BinDir, "--lang", languageOr(a.Language), "subscription", "prepare-upgrade"); e != nil {
		return errors.New("subscription backup failed; previous manager and services preserved")
	}
	// Keep the previous manager for a one-command rollback.
	_ = copyFileAtomic(exe, exe+".previous", 0755)
	if e = os.Rename(p, exe); e != nil {
		return e
	}
	a.printf("已更新为 %s，现有节点继续运行；回滚：mv %s.previous %s\n", release.Tag, exe, exe)
	// The monitor helper must match the manager; reinstalling it restarts only the
	// monitor (finite nodes resume after their sealed checkpoints are verified).
	if a.trafficActive() {
		if out, er := runOutput(2*time.Minute, exe, "--home", a.Home, "--bin-dir", a.BinDir, "--lang", languageOr(a.Language), "traffic", "install"); er != nil {
			a.printf("流量监控程序未更新，请运行 rout traffic install：%s\n", strings.TrimSpace(string(out)))
		} else if msg := strings.TrimSpace(string(out)); msg != "" {
			fmt.Println(msg)
		}
	}
	if _, er := runOutput(45*time.Second, exe, "--home", a.Home, "--bin-dir", a.BinDir, "--lang", languageOr(a.Language), "subscription", "refresh"); er != nil {
		return errors.New("manager updated; subscription helper refresh failed and rolled back, run rout subscription refresh; existing tokens and Caddy configuration were preserved")
	}

	return nil
}
func languageOr(lang string) string {
	if lang == "" {
		return "zh-CN"
	}
	return lang
}
