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
	"strings"
	"time"
)

//go:embed engines.lock.json
var engineLock []byte

type Asset struct {
	Name   string `json:"name"`
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
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
func download(url, path, digest string) error {
	if !strings.HasPrefix(url, "https://") {
		return errors.New("下载地址必须为 HTTPS")
	}
	r, e := httpClient().Get(url)
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
	defer f.Close()
	h := sha256.New()
	n, e := io.Copy(io.MultiWriter(f, h), io.LimitReader(r.Body, 200<<20))
	if e != nil {
		return e
	}
	if n >= 200<<20 {
		return errors.New("下载文件过大")
	}
	if digest != "" && hex.EncodeToString(h.Sum(nil)) != digest {
		return errors.New("SHA256 校验失败，未安装下载内容")
	}
	return f.Sync()
}
func (a *App) EnsureEngine(name string) error {
	path := a.enginePath(name)
	if st, e := os.Stat(path); e == nil && st.Mode().IsRegular() && st.Mode()&0111 != 0 {
		return nil
	}
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		return errors.New("仅支持 Linux amd64/arm64")
	}
	var asset Asset
	for _, v := range engines()[name].Assets {
		if strings.Contains(v.Name, "linux-"+runtime.GOARCH+".") || strings.Contains(v.Name, "linux_"+runtime.GOARCH+".") {
			asset = v
		}
	}
	if asset.URL == "" || len(asset.SHA256) != 64 {
		return errors.New("缺少经过校验的内核下载信息")
	}
	if e := os.MkdirAll(a.BinDir, 0755); e != nil {
		return e
	}
	tmp, e := os.MkdirTemp(a.BinDir, ".download-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(tmp)
	a.printf("下载并校验 %s %s…\n", name, engines()[name].Version)
	archive := filepath.Join(tmp, "engine.tar.gz")
	if e := download(asset.URL, archive, asset.SHA256); e != nil {
		return e
	}
	f, e := os.Open(archive)
	if e != nil {
		return e
	}
	defer f.Close()
	gz, e := gzip.NewReader(f)
	if e != nil {
		return e
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return e
		}
		if h.Typeflag != tar.TypeReg || filepath.Base(h.Name) != name {
			continue
		}
		if h.Size <= 0 || h.Size > 150<<20 {
			return errors.New("内核文件大小无效")
		}
		b, e := io.ReadAll(io.LimitReader(tr, h.Size))
		if e != nil {
			return e
		}
		return AtomicWrite(path, b, 0755)
	}
	return errors.New("下载归档中没有找到内核")
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

func SelfUpdate(language ...string) error {
	a := DefaultApp()
	if len(language) > 0 {
		a.Language = language[0]
	}
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
		Assets []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if e = json.NewDecoder(io.LimitReader(r.Body, 2<<20)).Decode(&release); e != nil {
		return e
	}
	if release.Tag == "v"+Version {
		a.say("已是当前发布版本")
		return nil
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
	if _, e = runOutput(10*time.Second, p, "version"); e != nil {
		return errors.New("新版本无法运行，保留旧版本")
	}
	if e = os.Rename(p, exe); e != nil {
		return e
	}
	a.printf("已更新为 %s，请重新运行 rout；现有服务继续运行\n", release.Tag)
	return nil
}
