package rout

import (
	"context"
	"errors"
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
func (a *App) stopServiceOnly(p Profile) error {
	m, e := a.serviceManager()
	if e != nil || m == "none" {
		return e
	}
	if m == "systemd" {
		return command("systemctl", "stop", serviceName(p)+".service")
	}
	if _, e = runOutput(3*time.Second, "rc-service", serviceName(p), "status"); e != nil {
		return nil
	}
	return command("rc-service", serviceName(p), "stop")
}
func (a *App) InstallTraffic() error {
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
	if e = AtomicWrite(a.trafficHelper(), b, 0755); e != nil {
		return e
	}
	// Probe only a private disposable table; never touch the host firewall.
	p := Profile{ID: RandomHex(6), Listen: "127.0.0.1", Port: 9, Kind: "node", Protocol: "ss", Traffic: &TrafficPolicy{LimitBytes: 1_000_000, BillingDay: 1}}
	p.Port, e = freePort()
	if e != nil {
		return e
	}
	if e = CheckAvailable(p); e != nil {
		return e
	}
	backend := nftMeter{home: a.Home}
	if _, e = backend.Replace(p, TrafficRecord{}); e != nil {
		return e
	}
	if e = backend.Delete(p); e != nil {
		return e
	}
	if e = AtomicWrite(filepath.Join(a.Home, "traffic.enabled"), []byte("1\n"), 0600); e != nil {
		return e
	}
	name := a.trafficService()
	cmd := append([]string{a.trafficHelper()}, a.trafficArgs("run")...)
	if m == "systemd" {
		unit := "[Unit]\nDescription=Rout traffic accounting and quota guard\nAfter=network-pre.target\nBefore=multi-user.target\n\n[Service]\nType=notify\nNotifyAccess=main\nExecStart=" + quoteArgs(cmd, unitQuote) + "\nRestart=always\nRestartSec=2\nTimeoutStopSec=30\nUMask=0077\n\n[Install]\nWantedBy=multi-user.target\n"
		if e = AtomicWrite(filepath.Join("/etc/systemd/system", name+".service"), []byte(unit), 0644); e != nil {
			return e
		}
		if e = command("systemctl", "daemon-reload"); e != nil {
			return e
		}
		// Do not restart an already-running monitor (and never restart old nodes).
		unlock()
		unlock = func() {}
		return command("systemctl", "enable", "--now", name+".service")
	}
	script := "#!/sbin/openrc-run\nname=" + shellQuote(name) + "\nsupervisor=supervise-daemon\ncommand=" + shellQuote(a.trafficHelper()) + "\ncommand_args=" + shellQuote(quoteArgs(a.trafficArgs("run"), shellQuote)) + "\nrespawn_delay=2\npidfile=" + shellQuote("/run/"+name+".pid") + "\ndepend() { need localmount; before net; }\n"
	if e = AtomicWrite(filepath.Join("/etc/init.d", name), []byte(script), 0755); e != nil {
		return e
	}
	if e = command("rc-update", "add", name, "default"); e != nil {
		return e
	}
	unlock()
	unlock = func() {}
	return command("rc-service", name, "start")
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
	if e = a.TrafficSync(time.Now(), false); e != nil {
		return e
	}
	notifyTrafficReady()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return a.TrafficSync(time.Now(), true)
		case <-ticker.C:
			if e = a.TrafficSync(time.Now(), false); e != nil {
				a.say("流量监控异常：有限额节点受内核租约保护，无限额节点不会自动停用")
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
