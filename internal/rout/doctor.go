package rout

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// doctor inspects the installation. It is read-only unless fix is set, and even then
// every repair asks for explicit confirmation first.
type doctorRun struct {
	u              *UI
	fails, warns   int
	permissionFix  []string
	orphans        []string
	helperMismatch bool
}

func (d *doctorRun) ok(s string, args ...any) { d.u.good(fmt.Sprintf(d.u.a.T(s), args...)) }
func (d *doctorRun) warn(s string, args ...any) {
	d.warns++
	d.u.warnf(s, args...)
}
func (d *doctorRun) bad(s string, args ...any) {
	d.fails++
	d.u.fail(fmt.Sprintf(d.u.a.T(s), args...))
}
func osName() string {
	b, _ := os.ReadFile("/etc/os-release")
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "PRETTY_NAME="); ok {
			return strings.Trim(v, `"`)
		}
	}
	return runtime.GOOS
}
func hasDefaultRoute(path string, v6 bool) bool {
	b, e := os.ReadFile(path)
	if e != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if !v6 && len(f) > 2 && f[1] == "00000000" && f[0] != "lo" {
			return true
		}
		if v6 && len(f) > 9 && f[0] == strings.Repeat("0", 32) && f[1] == "00" && f[9] != "lo" {
			return true
		}
	}
	return false
}
func (u *UI) doctor(fix bool) error {
	a := u.a
	d := &doctorRun{u: u}
	u.heading("系统")
	if runtime.GOOS == "linux" && (runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64") {
		d.ok("%s · %s · Rout %s", osName(), runtime.GOARCH, Version)
	} else {
		d.bad("不受支持的平台：%s/%s", runtime.GOOS, runtime.GOARCH)
	}
	if os.Geteuid() != 0 {
		d.warn("未以 root 运行：服务、防火墙和私有文件检查不完整")
	}
	manager, e := a.serviceManager()
	if e != nil {
		d.bad("%s", a.Error(e))
	} else {
		d.ok("服务管理：%s", manager)
	}
	v4, v6 := hasDefaultRoute("/proc/net/route", false), hasDefaultRoute("/proc/net/ipv6_route", true)
	switch {
	case v4 && v6:
		d.ok("网络：IPv4 与 IPv6 默认路由可用")
	case v4:
		d.ok("网络：仅 IPv4 默认路由")
	case v6:
		d.ok("网络：仅 IPv6 默认路由（IPv4 不是必需的）")
	default:
		d.bad("没有 IPv4 或 IPv6 默认路由")
	}

	u.heading("配置")
	s, e := a.Load()
	if e != nil {
		d.bad("配置无法读取：%s", a.Error(e))
		return d.finish(fix)
	}
	if _, e = a.LoadSettings(); e != nil {
		d.bad("设置无法读取：%s", a.Error(e))
	}
	d.ok("配置有效：%d 个节点或线路，%d 个出口", len(s.Profiles), len(s.Exits))
	d.permissions()

	u.heading("内核")
	needed := map[string]bool{}
	for _, p := range s.Profiles {
		needed[a.engineName(p)] = true
	}
	for _, name := range []string{"sing-box", "gost"} {
		path := a.enginePath(name)
		st, e := os.Stat(path)
		if e != nil || st.Mode()&0111 == 0 {
			if needed[name] {
				d.bad("%s 未安装（运行 rout engines）", name)
			} else {
				d.ok("%s 未安装（当前不需要）", name)
			}
			continue
		}
		flag := "version"
		if name == "gost" {
			flag = "-V"
		}
		out, e := runOutput(10*time.Second, path, flag)
		if e != nil {
			d.bad("%s 无法运行：%s", name, strings.TrimSpace(string(out)))
			continue
		}
		line := firstLine(string(out))
		if !strings.Contains(line, name) {
			line = name + " " + line
		}
		d.ok("%s", line)
	}

	u.heading("节点")
	now := time.Now()
	for _, p := range s.Profiles {
		d.profile(s, p, manager, now)
	}
	if len(s.Profiles) == 0 {
		u.say("暂无节点或线路")
	}

	u.heading("流量统计")
	d.traffic(s, manager)
	return d.finish(fix)
}
func firstLine(s string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	return line
}
func (d *doctorRun) permissions() {
	a := d.u.a
	check := func(path string, want os.FileMode) {
		st, e := os.Stat(path)
		if e != nil {
			return
		}
		if st.Mode().Perm()&^want != 0 {
			d.warn("%s 权限为 %o，应为 %o", path, st.Mode().Perm(), want)
			d.permissionFix = append(d.permissionFix, fmt.Sprintf("%o:%s", want, path))
		}
	}
	check(a.Home, 0700)
	_ = filepath.Walk(a.Home, func(path string, info os.FileInfo, e error) error {
		if e != nil || path == a.Home {
			return nil
		}
		if info.IsDir() {
			check(path, 0700)
		} else {
			check(path, 0600)
		}
		return nil
	})
	if len(d.permissionFix) == 0 {
		d.ok("配置文件权限为私有")
	}
}
func (d *doctorRun) profile(s State, p Profile, manager string, now time.Time) {
	a := d.u.a
	label := fmt.Sprintf("%s [%s]", p.Name, p.ID)
	if e := p.CheckCompatibility(); e != nil {
		d.bad("%s：%s", label, a.Error(e))
	}
	if config, e := serverConfig(p, a.profileDir(p.ID)); e == nil {
		expected, _ := JSON(config)
		actual, er := os.ReadFile(filepath.Join(a.profileDir(p.ID), "config.json"))
		if er != nil || !bytes.Equal(expected, actual) {
			d.warn("%s：运行配置与状态不一致，运行 rout apply 修复", label)
		} else if p.Kind == "node" && a.checkConfig(filepath.Join(a.profileDir(p.ID), "config.json")) != nil {
			d.bad("%s：sing-box 配置检查失败", label)
		}
	}
	if days, ok := p.CertificateDays(now); ok {
		switch {
		case days < 0:
			d.bad("%s：证书已过期，运行 rout cert renew %s", label, p.ID)
		case days <= certificateWarnDays:
			d.warn("%s：证书 %d 天后过期", label, days)
		default:
			d.ok("%s：证书剩余 %d 天", label, days)
		}
	}
	if !p.Enabled {
		d.ok("%s：已手动停用", label)
		return
	}
	if manager == "" || manager == "none" {
		return
	}
	active := serviceActive(manager, serviceName(p))
	bound := listening(p)
	switch {
	case active && bound:
		d.ok("%s：运行中，监听 %d/%s", label, p.Port, strings.Join(p.Networks(), "+"))
	case active:
		d.bad("%s：服务运行但端口 %d 未监听", label, p.Port)
	case bound:
		d.bad("%s：服务未运行，端口 %d 被其他程序占用", label, p.Port)
	case p.trafficPolicy().LimitBytes > 0:
		d.warn("%s：未运行（可能因流量限额暂停，见下方流量统计）", label)
	default:
		d.bad("%s：服务未运行，运行 rout logs %s 查看原因", label, p.ID)
	}
}
func (d *doctorRun) traffic(s State, manager string) {
	a := d.u.a
	if _, e := exec.LookPath("nft"); e != nil {
		d.warn("未安装 nftables：流量统计与限额不可用（apt install nftables / apk add nftables）")
		return
	}
	if _, e := nftRun("", "list", "tables"); e != nil {
		d.bad("%s", a.Error(e))
		return
	}
	d.ok("nftables 可用")
	if !a.trafficActive() {
		d.warn("流量监控未启用，运行 rout traffic install")
		return
	}
	name := a.trafficService()
	if manager != "" && manager != "none" {
		if serviceActive(manager, name) {
			d.ok("流量监控运行中：%s", name)
		} else {
			d.bad("流量监控未运行：%s", name)
		}
	}
	if out, e := runOutput(10*time.Second, a.trafficHelper(), "version"); e != nil {
		d.bad("流量监控程序缺失或无法运行，运行 rout traffic install")
		d.helperMismatch = true
	} else if strings.TrimSpace(string(out)) != "rout "+Version {
		d.warn("流量监控程序版本（%s）与 Rout %s 不一致，运行 rout traffic install", strings.TrimSpace(string(out)), Version)
		d.helperMismatch = true
	}
	db, e := a.loadTraffic()
	if e != nil {
		d.bad("%s", a.Error(e))
		return
	}
	if age := time.Since(db.Updated); age > 30*time.Second {
		d.bad("流量检查点已 %d 秒未更新，监控可能停止", int(age.Seconds()))
	} else {
		d.ok("流量检查点 %d 秒前更新", int(age.Seconds()))
	}
	meter := nftMeter{home: a.Home}
	reads, orphans := meter.ReadAll(s.Profiles)
	for _, p := range s.Profiles {
		label := fmt.Sprintf("%s [%s]", p.Name, p.ID)
		r, ok := db.Records[p.ID]
		if !ok {
			d.warn("%s：尚无流量记录", label)
			continue
		}
		if read := reads[p.ID]; read.err != nil {
			d.bad("%s：计量规则不可用", label)
		} else if read.snap.Hash != r.Rules && !r.Pending {
			d.warn("%s：计量规则与检查点不一致，下一次同步将重建", label)
		}
		switch r.Blocked {
		case blockQuota:
			d.warn("%s：已达流量上限", label)
		case blockFault:
			d.warn("%s：计量缺口保护暂停（流量管理 → 保留已知用量并恢复）", label)
		case blockSealed:
			d.warn("%s：等待流量监控校验检查点后恢复", label)
		}
		if r.Incomplete {
			d.warn("%s：本周期存在计量缺口，已知用量为下限", label)
		}
	}
	if len(orphans) > 0 {
		d.warn("发现 %d 个残留的 Rout 计量表", len(orphans))
		d.orphans = orphans
	}
}

// finish summarizes and, only with --fix, offers each safe repair separately.
func (d *doctorRun) finish(fix bool) error {
	u := d.u
	u.heading("结果")
	if d.fails == 0 && d.warns == 0 {
		u.good("未发现问题")
	} else {
		u.printf("问题 %d 个，提示 %d 个\n", d.fails, d.warns)
	}
	if fix {
		if len(d.permissionFix) > 0 && u.yes("将私有文件权限修复为 0600/0700", false) {
			for _, entry := range d.permissionFix {
				mode, path, _ := strings.Cut(entry, ":")
				var m os.FileMode
				fmt.Sscanf(mode, "%o", &m)
				_ = os.Chmod(path, m)
			}
			u.good("权限已修复")
		}
		if len(d.orphans) > 0 && u.yes("删除残留的 Rout 计量表（不影响其他防火墙规则）", false) {
			if e := (nftMeter{home: u.a.Home}).DeleteTables(d.orphans); e != nil {
				u.fail(u.a.Error(e))
			} else {
				u.good("残留计量表已删除")
			}
		}
		if d.helperMismatch && u.yes("重新安装流量监控程序", false) {
			if e := u.a.InstallTraffic(); e != nil {
				u.fail(u.a.Error(e))
			}
		}
	} else if len(d.permissionFix) > 0 || len(d.orphans) > 0 || d.helperMismatch {
		u.say("运行 rout doctor --fix 可在逐项确认后修复")
	}
	if d.fails > 0 {
		return fmt.Errorf("诊断发现 %d 个问题", d.fails)
	}
	return u.err
}
