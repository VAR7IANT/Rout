package rout

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func (a *App) trafficHelper() string { return filepath.Join(a.BinDir, "rout-traffic-v1") }
func (a *App) trafficService() string {
	return "rout-traffic-" + nftMeter{home: a.Home}.table(Profile{ID: "monitor"})[5:]
}
func (a *App) trafficArgs(command string) []string {
	return []string{"--home", a.Home, "--bin-dir", a.BinDir, "traffic", command}
}
func quoteArgs(args []string, quote func(string) string) string {
	var out []string
	for _, arg := range args {
		out = append(out, quote(arg))
	}
	return strings.Join(out, " ")
}
func (a *App) trafficGuardCommand(p Profile, quote func(string) string) string {
	if p.trafficPolicy().LimitBytes == 0 {
		return ""
	}
	return quoteArgs(append(append([]string{a.trafficHelper()}, a.trafficArgs("guard")...), p.ID), quote)
}

// During monitor shutdown the stop is queued (--no-block): systemd may be stopping the
// same unit as part of this transaction, and the kernel gate is already closed.
func (a *App) stopServiceOnly(p Profile, queue bool) error {
	m, e := a.serviceManager()
	if e != nil || m == "none" {
		return e
	}
	if m == "systemd" {
		if queue {
			return command("systemctl", "stop", "--no-block", serviceName(p)+".service")
		}
		return command("systemctl", "stop", serviceName(p)+".service")
	}
	if _, e = runOutput(3*time.Second, "rc-service", serviceName(p), "status"); e != nil {
		return nil
	}
	return command("rc-service", serviceName(p), "stop")
}
func (a *App) InstallTraffic() (err error) {
	if _, e := exec.LookPath("nft"); e != nil {
		return errors.New("请安装 nftables（Debian/Ubuntu：apt install nftables；Alpine：apk add nftables）")
	}
	m, e := a.serviceManager()
	if e != nil {
		return e
	}
	if m == "none" {
		return errors.New("测试模式请显式使用 traffic run，不安装系统监控服务")
	}
	// Serialize installers even while the configuration lock is released for init.
	installUnlock, e := lockFile(filepath.Join(a.Home, ".traffic-install.lock"), trafficLockWait)
	if e != nil {
		return e
	}
	defer installUnlock()
	unlock, e := a.lock()
	if e != nil {
		return e
	}
	defer func() { unlock() }()
	exe, e := os.Executable()
	if e != nil {
		return e
	}
	b, e := os.ReadFile(exe)
	if e != nil {
		return e
	}
	// Probe only a private disposable table; never touch the host firewall.
	p := Profile{ID: "probe_" + RandomHex(6), Listen: "127.0.0.1", Port: 9, Kind: "node", Protocol: "ss", Traffic: &TrafficPolicy{LimitBytes: 1_000_000, BillingDay: 1}}
	p.Port, e = freePort()
	if e != nil {
		return e
	}
	if e = CheckAvailable(p); e != nil {
		return e
	}
	backend := nftMeter{home: a.Home}
	if e = backend.probe(p); e != nil {
		return e
	}
	name := a.trafficService()
	running := serviceActive(m, name)
	unitPath := filepath.Join("/etc/init.d", name)
	if m == "systemd" {
		unitPath = filepath.Join("/etc/systemd/system", name+".service")
	}
	// Nothing persistent changes before the probe has been read and removed. Keep
	// the previous helper and service definition until service activation succeeds.
	previous, e := os.ReadFile(a.trafficHelper())
	if e != nil && !os.IsNotExist(e) {
		return e
	}
	changed := !bytes.Equal(previous, b)
	paths := []string{a.trafficHelper(), unitPath, filepath.Join(a.Home, "traffic.enabled")}
	type savedFile struct {
		path   string
		data   []byte
		mode   os.FileMode
		exists bool
	}
	var saved []savedFile
	for _, path := range paths {
		f := savedFile{path: path}
		st, er := os.Stat(path)
		if er == nil {
			f.exists, f.mode = true, st.Mode().Perm()
			f.data, er = os.ReadFile(path)
		}
		if er != nil && !os.IsNotExist(er) {
			return er
		}
		saved = append(saved, f)
	}
	activated := false
	defer func() {
		if err == nil {
			return
		}
		// A monitor shutdown checkpoints under the config lock. Release it before
		// restoring service state, as on the successful activation path.
		unlock()
		unlock = func() {}
		if activated && !running {
			if m == "systemd" {
				err = errors.Join(err, command("systemctl", "stop", name+".service"))
			} else {
				err = errors.Join(err, command("rc-service", name, "stop"))
			}
		}
		if activated && !saved[1].exists {
			if m == "systemd" {
				err = errors.Join(err, command("systemctl", "disable", name+".service"))
			} else {
				err = errors.Join(err, command("rc-update", "del", name, "default"))
			}
		}
		for _, f := range saved {
			var er error
			if f.exists {
				er = AtomicWrite(f.path, f.data, f.mode)
			} else {
				er = os.Remove(f.path)
				if os.IsNotExist(er) {
					er = nil
				}
			}
			if er != nil {
				err = errors.Join(err, fmt.Errorf("恢复流量安装文件 %s 失败: %w", f.path, er))
			}
		}
		if m == "systemd" {
			err = errors.Join(err, command("systemctl", "daemon-reload"))
		}
		if activated && running {
			if m == "systemd" {
				err = errors.Join(err, command("systemctl", "restart", name+".service"))
			} else {
				err = errors.Join(err, command("rc-service", name, "restart"))
			}
		}
	}()
	if changed {
		if e = AtomicWrite(a.trafficHelper(), b, 0755); e != nil {
			return e
		}
	}
	finish := func() error { return AtomicWrite(filepath.Join(a.Home, "traffic.enabled"), []byte("1\n"), 0600) }
	if m == "systemd" {
		unit := "[Unit]\nDescription=Rout traffic accounting and quota guard\nAfter=network-pre.target\nBefore=multi-user.target\n\n[Service]\nType=notify\nNotifyAccess=main\nExecStart=" + quoteArgs(append([]string{a.trafficHelper()}, a.trafficArgs("run")...), unitQuote) + "\nRestart=always\nRestartSec=2\nTimeoutStopSec=30\nUMask=0077\n\n[Install]\nWantedBy=multi-user.target\n"
		if e = AtomicWrite(unitPath, []byte(unit), 0644); e != nil {
			return e
		}
		if e = command("systemctl", "daemon-reload"); e != nil {
			return e
		}
		// The monitor needs the configuration lock for its own shutdown checkpoint.
		unlock()
		unlock = func() {}
		activated = true
		if e = command("systemctl", "enable", "--now", name+".service"); e != nil {
			return e
		}
		if !changed || !running {
			return finish()
		}
		a.say("流量监控已更新并重启；有限额节点会在校验完整检查点后自动恢复")
		if e = command("systemctl", "restart", name+".service"); e != nil {
			return e
		}
		return finish()
	}
	script := "#!/sbin/openrc-run\nname=" + shellQuote(name) + "\nsupervisor=supervise-daemon\ncommand=" + shellQuote(a.trafficHelper()) + "\ncommand_args=" + shellQuote(quoteArgs(a.trafficArgs("run"), shellQuote)) + "\nrespawn_delay=2\npidfile=" + shellQuote("/run/"+name+".pid") + "\noutput_log=" + shellQuote("/var/log/"+name+".log") + "\nerror_log=" + shellQuote("/var/log/"+name+".log") + "\ndepend() { need localmount; before net; }\nstart_pre() { umask 077; touch \"$output_log\"; chmod 600 \"$output_log\"; }\n"
	if e = AtomicWrite(unitPath, []byte(script), 0755); e != nil {
		return e
	}
	activated = true
	if e = command("rc-update", "add", name, "default"); e != nil {
		return e
	}
	unlock()
	unlock = func() {}
	if running && changed {
		a.say("流量监控已更新并重启；有限额节点会在校验完整检查点后自动恢复")
		if e = command("rc-service", name, "restart"); e != nil {
			return e
		}
		return finish()
	}
	if !running {
		if e = command("rc-service", name, "start"); e != nil {
			return e
		}
	}
	return finish()
}
func notifyTrafficReady() {
	path := os.Getenv("NOTIFY_SOCKET")
	if path == "" {
		return
	}
	c, e := net.Dial("unixgram", path)
	if e == nil {
		defer c.Close()
		_, _ = c.Write([]byte("READY=1"))
	}
}

// rotateLog keeps a supervise-daemon log bounded without signalling its writer: the
// file is copied aside and truncated in place (the daemon writes with O_APPEND).
func rotateLog(path string, limit int64) error {
	st, e := os.Stat(path)
	if e != nil || st.Size() <= limit {
		return nil
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	if e = AtomicWrite(path+".1", b, 0600); e != nil {
		return e
	}
	return os.Truncate(path, 0)
}
func (a *App) rotateServiceLogs() {
	if m, e := a.serviceManager(); e != nil || m != "openrc" {
		return
	}
	state, e := a.Load()
	if e != nil {
		return
	}
	for _, p := range state.Profiles {
		_ = rotateLog("/var/log/"+serviceName(p)+".log", openrcLogLimit)
	}
	_ = rotateLog("/var/log/"+a.trafficService()+".log", openrcLogLimit)
}
func (a *App) RunTraffic(ctx context.Context) error {
	// A second daemon cannot renew leases or race the first daemon's checkpoints.
	if e := os.MkdirAll(a.Home, 0700); e != nil {
		return e
	}
	f, e := os.OpenFile(filepath.Join(a.Home, ".traffic-daemon.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		return errors.New("流量监控已经运行")
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	a.monitorMode = true
	last, lastAt := "", time.Time{}
	report := func(e error) {
		if e == nil {
			last = ""
			return
		}
		// Repeated identical faults are logged once a minute, not every poll.
		if msg := a.Error(e); msg != last || time.Since(lastAt) > time.Minute {
			fmt.Fprintf(os.Stderr, a.T("流量监控异常（有限额节点受内核租约保护，无限额节点不受影响）：%s\n"), msg)
			last, lastAt = msg, time.Now()
		}
	}
	// One node's error never stops the daemon; READY is sent before any service start
	// because finite nodes are ordered after this unit.
	report(a.trafficSync(time.Now(), false, notifyTrafficReady))
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for ticks := 1; ; ticks++ {
		select {
		case <-ctx.Done():
			return a.TrafficSync(time.Now(), true)
		case <-ticker.C:
			report(a.TrafficSync(time.Now(), false))
			if ticks%120 == 0 {
				a.rotateServiceLogs()
			}
		}
	}
}
func (a *App) removeTrafficMonitor() error {
	if !a.trafficActive() {
		return nil
	}
	m, e := a.serviceManager()
	if e != nil || m == "none" {
		return e
	}
	name := a.trafficService()
	if m == "systemd" {
		if e = command("systemctl", "disable", "--now", name+".service"); e != nil {
			return e
		}
		if e = os.Remove(filepath.Join("/etc/systemd/system", name+".service")); e != nil && !os.IsNotExist(e) {
			return e
		}
		return command("systemctl", "daemon-reload")
	}
	_ = command("rc-service", name, "stop")
	_ = command("rc-update", "del", name, "default")
	if e = os.Remove(filepath.Join("/etc/init.d", name)); e != nil && !os.IsNotExist(e) {
		return e
	}
	return nil
}
