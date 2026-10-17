package rout

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func (a *App) serviceManager() (string, error) {
	if a.ServiceMode == "none" {
		return "none", nil
	}
	if a.ServiceMode != "auto" {
		return "", errors.New("service 只能为 auto 或 none")
	}
	if _, e := os.Stat("/run/systemd/system"); e == nil {
		return "systemd", nil
	}
	if _, e := exec.LookPath("rc-service"); e == nil {
		return "openrc", nil
	}
	return "", errors.New("未检测到 systemd／OpenRC，请在受支持的 VPS 中运行")
}
func serviceName(p Profile) string { return "rout-" + p.ID }
func command(name string, args ...string) error {
	out, e := runOutput(25*time.Second, name, args...)
	if e != nil {
		// Init-system output names units and states only; keep the tail for diagnosis.
		detail := strings.TrimSpace(string(out))
		if len(detail) > 400 {
			detail = "…" + detail[len(detail)-400:]
		}
		if detail != "" {
			return fmt.Errorf("服务操作失败：%s %s：%s", name, strings.Join(args, " "), detail)
		}
		return fmt.Errorf("服务操作失败：%s %s", name, strings.Join(args, " "))
	}
	return nil
}
func unitQuote(s string) string                         { return strconv.Quote(strings.ReplaceAll(s, "%", "%%")) }
func shellQuote(s string) string                        { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
func (a *App) setService(p Profile, enabled bool) error { return a.setServiceMode(p, enabled, true) }

// startService (re)installs the unit and starts it only if it is not already running.
func (a *App) startService(p Profile) error { return a.setServiceMode(p, true, false) }

// Engines only accept and dial sockets. They never receive the capability to edit
// the firewall/quota tables; QUIC engines keep CAP_NET_ADMIN solely so quic-go can
// size UDP socket buffers as it does today (it otherwise only logs a warning).
func unitSandbox(p Profile) string {
	caps := "CAP_NET_BIND_SERVICE"
	if p.Kind == "node" && (p.Protocol == "hy2" || p.Protocol == "tuic") {
		caps += " CAP_NET_ADMIN"
	}
	return "CapabilityBoundingSet=" + caps + "\nPrivateDevices=true\nProtectKernelTunables=true\nProtectKernelModules=true\nProtectKernelLogs=true\nProtectControlGroups=true\nProtectClock=true\nProtectHostname=true\nRestrictNamespaces=true\nRestrictRealtime=true\nRestrictSUIDSGID=true\nLockPersonality=true\nSystemCallArchitectures=native\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK\n"
}

const openrcLogLimit = 5 << 20

func (a *App) systemdUnit(p Profile) string {
	engine := a.enginePath(a.engineName(p))
	conf := filepath.Join(a.profileDir(p.ID), "config.json")
	args := []string{"run", "-c", conf}
	if p.Kind == "relay" {
		args = []string{"-C", conf}
	}
	cmdline := quoteArgs(append([]string{engine}, args...), unitQuote)
	after, pre := "After=network-online.target\n", ""
	if guard := a.trafficGuardCommand(p, unitQuote); guard != "" {
		after = "Requires=" + a.trafficService() + ".service\nAfter=" + a.trafficService() + ".service network-online.target\n"
		// "+" runs the guard outside the sandbox: it must read the kernel quota tables.
		pre = "ExecStartPre=+" + guard + "\n"
	}
	return "[Unit]\nDescription=Rout " + p.ID + "\n" + after + "Wants=network-online.target\n\n[Service]\nType=simple\n" + pre + "ExecStart=" + cmdline + "\nRestart=on-failure\nRestartSec=3\nLimitNOFILE=65536\nUMask=0077\nNoNewPrivileges=true\nPrivateTmp=true\nProtectHome=true\nProtectSystem=strict\n" + unitSandbox(p) + "\n[Install]\nWantedBy=multi-user.target\n"
}
func (a *App) openrcScript(p Profile) string {
	name := serviceName(p)
	engine := a.enginePath(a.engineName(p))
	conf := filepath.Join(a.profileDir(p.ID), "config.json")
	args := []string{"run", "-c", conf}
	if p.Kind == "relay" {
		args = []string{"-C", conf}
	}
	need, guard := "need net", ""
	if g := a.trafficGuardCommand(p, shellQuote); g != "" {
		need += " " + a.trafficService()
		guard = g + " || return 1; "
	}
	// supervise-daemon appends to one private log; it is rotated once at each start and
	// by the traffic monitor while running, so it cannot grow without bound.
	return "#!/sbin/openrc-run\nname=" + shellQuote(name) + "\nsupervisor=supervise-daemon\ncommand=" + shellQuote(engine) + "\ncommand_args=" + shellQuote(quoteArgs(args, shellQuote)) + "\nrespawn_delay=3\nrespawn_max=5\nrespawn_period=60\noutput_log=" + shellQuote("/var/log/"+name+".log") + "\nerror_log=" + shellQuote("/var/log/"+name+".log") + "\npidfile=" + shellQuote("/run/"+name+".pid") + "\n\ndepend() { " + need + "; }\nstart_pre() { " + guard + "umask 077; if [ -f \"$output_log\" ] && [ \"$(wc -c < \"$output_log\")\" -gt " + itoa(openrcLogLimit) + " ]; then mv -f \"$output_log\" \"$output_log.1\"; fi; touch \"$output_log\"; chmod 600 \"$output_log\"; }\n"
}
func (a *App) setServiceMode(p Profile, enabled, restart bool) error {
	m, e := a.serviceManager()
	if e != nil || m == "none" {
		return e
	}
	if enabled && p.trafficPolicy().LimitBytes > 0 {
		db, er := a.loadTraffic()
		if er != nil {
			return er
		}
		r, ok := db.Records[p.ID]
		if !ok || r.Blocked != "" || r.Pending {
			enabled = false
		}
	}
	name := serviceName(p)
	if m == "systemd" {
		written, e := writeIfChanged(filepath.Join("/etc/systemd/system", name+".service"), a.systemdUnit(p), 0644)
		if e != nil {
			return e
		}
		if written || needsDaemonReload(name) {
			if e = command("systemctl", "daemon-reload"); e != nil {
				return e
			}
		}
		if !enabled {
			return command("systemctl", "disable", "--now", name+".service")
		}
		if e = command("systemctl", "enable", name+".service"); e != nil {
			return e
		}
		if !restart && serviceActive(m, name) {
			return nil
		}
		// Planned config changes and rollback must not inherit an earlier start-limit failure.
		_ = command("systemctl", "reset-failed", name+".service")
		if e = command("systemctl", "restart", name+".service"); e != nil {
			return a.startFailure(p, e)
		}
		return a.waitHealthy(m, p)
	}
	if _, e = writeIfChanged(filepath.Join("/etc/init.d", name), a.openrcScript(p), 0755); e != nil {
		return e
	}
	if !enabled {
		if e := command("rc-service", name, "stop"); e != nil {
			if serviceActive(m, name) {
				return e
			}
		}
		_ = command("rc-update", "del", name, "default")
		return nil
	}
	if e = command("rc-update", "add", name, "default"); e != nil {
		return e
	}
	if !restart && serviceActive(m, name) {
		return nil
	}
	if e = command("rc-service", name, "restart"); e != nil {
		// A start already in progress (boot, a dependency coming up) is not a failure by
		// itself: the health check below is the real verdict.
		if !strings.Contains(e.Error(), "already starting") {
			return a.startFailure(p, e)
		}
	}
	return a.waitHealthy(m, p)
}

// writeIfChanged avoids rewriting identical init files (and the daemon-reload that
// follows), e.g. when the monitor resumes nodes during boot.
func writeIfChanged(path, content string, mode os.FileMode) (bool, error) {
	if old, e := os.ReadFile(path); e == nil && string(old) == content {
		if st, er := os.Stat(path); er == nil && st.Mode().Perm() == mode {
			return false, nil
		}
	}
	return true, AtomicWrite(path, []byte(content), mode)
}

func needsDaemonReload(name string) bool {
	b, _ := runOutput(5*time.Second, "systemctl", "show", "--property=NeedDaemonReload", "--value", name+".service")
	return strings.TrimSpace(string(b)) != "no"
}

var (
	healthTimeout = 6 * time.Second
	healthSettle  = 500 * time.Millisecond
)

func serviceActive(m, name string) bool {
	var e error
	if m == "systemd" {
		_, e = runOutput(5*time.Second, "systemctl", "is-active", "--quiet", name+".service")
	} else {
		_, e = runOutput(5*time.Second, "rc-service", name, "status")
	}
	return e == nil
}
func servicePID(m, name string) string {
	if m == "systemd" {
		b, _ := runOutput(5*time.Second, "systemctl", "show", "--property=MainPID", "--value", name+".service")
		return strings.TrimSpace(string(b))
	}
	b, _ := os.ReadFile("/run/" + name + ".pid")
	return strings.TrimSpace(string(b))
}
func (a *App) startFailure(p Profile, cause error) error {
	return fmt.Errorf("%s 启动失败，请运行 rout logs %s 查看原因：%w", p.Name, p.ID, cause)
}

// Briefly "active" is not healthy: the engine must keep running, own its expected
// sockets, and not be restarted by the init system during a settle window.
func (a *App) waitHealthy(m string, p Profile) error {
	name := serviceName(p)
	deadline := time.Now().Add(healthTimeout)
	for {
		active := serviceActive(m, name)
		if active && listening(p) {
			break
		}
		if time.Now().After(deadline) {
			if !active {
				return fmt.Errorf("%s 启动后未保持运行，请运行 rout logs %s 查看原因", p.Name, p.ID)
			}
			return fmt.Errorf("%s 已运行但未监听端口 %d，请运行 rout logs %s 查看原因", p.Name, p.Port, p.ID)
		}
		time.Sleep(100 * time.Millisecond)
	}
	pid := servicePID(m, name)
	time.Sleep(healthSettle)
	if !serviceActive(m, name) || servicePID(m, name) != pid || !listening(p) {
		return fmt.Errorf("%s 启动后立即退出或被重启，请运行 rout logs %s 查看原因", p.Name, p.ID)
	}
	return nil
}

// listening reports whether every network the profile needs has a socket bound to
// its port, read from /proc without opening sockets.
func listening(p Profile) bool {
	for _, n := range p.Networks() {
		if !socketBound(n, p.Port) {
			return false
		}
	}
	return true
}
func socketBound(network string, port int) bool {
	want := strings.ToUpper(fmt.Sprintf(":%04x", port))
	for _, suffix := range []string{"", "6"} {
		b, e := os.ReadFile("/proc/net/" + network + suffix)
		if e != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n")[1:] {
			f := strings.Fields(line)
			// TCP must be LISTEN (0A); an unconnected UDP socket reports 07.
			if len(f) > 3 && strings.HasSuffix(f[1], want) && (f[3] == "0A" || (network == "udp" && f[3] == "07")) {
				return true
			}
		}
	}
	return false
}
func (a *App) removeService(p Profile) error {
	m, e := a.serviceManager()
	if e != nil || m == "none" {
		return e
	}
	name := serviceName(p)
	if m == "systemd" {
		path := filepath.Join("/etc/systemd/system", name+".service")
		if _, e := os.Stat(path); os.IsNotExist(e) {
			return nil
		}
		if e = command("systemctl", "disable", "--now", name+".service"); e != nil {
			return e
		}
		if e = os.Remove(path); e != nil {
			return e
		}
		return command("systemctl", "daemon-reload")
	}
	path := filepath.Join("/etc/init.d", name)
	if _, e := os.Stat(path); os.IsNotExist(e) {
		return nil
	}
	if e = a.setService(p, false); e != nil {
		return e
	}
	return os.Remove(path)
}
func (a *App) Running(p Profile) string {
	m, e := a.serviceManager()
	if e != nil {
		return a.T("未知")
	}
	if m == "none" {
		return a.T("未托管（测试模式）")
	}
	if !serviceActive(m, serviceName(p)) {
		return a.T("未运行")
	}
	return a.T("运行中")
}

func (a *App) Restart(id string) error {
	unlock, e := a.lock()
	if e != nil {
		return e
	}
	defer unlock()
	s, e := a.Load()
	if e != nil {
		return e
	}
	p, e := Find(s, id)
	if e != nil {
		return e
	}
	if !p.Enabled {
		return errors.New("线路未启用")
	}
	if e = a.TrafficGuard(p.ID); e != nil {
		return e
	}
	if e = p.Ready(); e != nil {
		return e
	}
	if p.Kind == "node" {
		if e = a.checkConfig(filepath.Join(a.profileDir(p.ID), "config.json")); e != nil {
			return e
		}
	}
	return a.setService(p, true)
}
func (a *App) Logs(p Profile) error {
	m, e := a.serviceManager()
	if e != nil {
		return e
	}
	if m == "none" {
		return errors.New("测试模式没有服务日志")
	}
	if m == "systemd" {
		cmd := exec.Command("journalctl", "-u", serviceName(p)+".service", "-n", "60", "--no-pager")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	}
	b, e := os.ReadFile("/var/log/" + serviceName(p) + ".log")
	if e != nil {
		return e
	}
	lines := strings.Split(string(b), "\n")
	if len(lines) > 60 {
		lines = lines[len(lines)-60:]
	}
	fmt.Println(strings.Join(lines, "\n"))
	return nil
}
