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
	_, e := runOutput(25*time.Second, name, args...)
	if e != nil {
		return fmt.Errorf("服务操作失败：%s %s", name, strings.Join(args, " "))
	}
	return nil
}
func unitQuote(s string) string  { return strconv.Quote(strings.ReplaceAll(s, "%", "%%")) }
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
func (a *App) setService(p Profile, enabled bool) error {
	m, e := a.serviceManager()
	if e != nil || m == "none" {
		return e
	}
	name := serviceName(p)
	engine := a.enginePath(a.engineName(p))
	conf := filepath.Join(a.profileDir(p.ID), "config.json")
	args := []string{"run", "-c", conf}
	if p.Kind == "relay" {
		args = []string{"-C", conf}
	}
	if m == "systemd" {
		quoted := []string{unitQuote(engine)}
		for _, arg := range args {
			quoted = append(quoted, unitQuote(arg))
		}
		unit := "[Unit]\nDescription=Rout " + p.ID + "\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nExecStart=" + strings.Join(quoted, " ") + "\nRestart=on-failure\nRestartSec=3\nLimitNOFILE=65536\nUMask=0077\nNoNewPrivileges=true\nPrivateTmp=true\nProtectHome=true\nProtectSystem=strict\n\n[Install]\nWantedBy=multi-user.target\n"
		if e = AtomicWrite(filepath.Join("/etc/systemd/system", name+".service"), []byte(unit), 0644); e != nil {
			return e
		}
		if e = command("systemctl", "daemon-reload"); e != nil {
			return e
		}
		if !enabled {
			return command("systemctl", "disable", "--now", name+".service")
		}
		if e = command("systemctl", "enable", name+".service"); e != nil {
			return e
		}
		// Planned config changes and rollback must not inherit an earlier start-limit failure.
		_ = command("systemctl", "reset-failed", name+".service")
		if e = command("systemctl", "restart", name+".service"); e != nil {
			return e
		}
		time.Sleep(350 * time.Millisecond)
		return command("systemctl", "is-active", "--quiet", name+".service")
	}
	quoted := []string{}
	for _, arg := range args {
		quoted = append(quoted, shellQuote(arg))
	}
	argstr := strings.Join(quoted, " ")
	script := "#!/sbin/openrc-run\nname=" + shellQuote(name) + "\nsupervisor=supervise-daemon\ncommand=" + shellQuote(engine) + "\ncommand_args=" + shellQuote(argstr) + "\nrespawn_delay=3\nrespawn_max=5\noutput_log=" + shellQuote("/var/log/"+name+".log") + "\nerror_log=" + shellQuote("/var/log/"+name+".log") + "\npidfile=" + shellQuote("/run/"+name+".pid") + "\n\ndepend() { need net; }\nstart_pre() { umask 077; touch \"$output_log\"; chmod 600 \"$output_log\"; }\n"
	if e = AtomicWrite(filepath.Join("/etc/init.d", name), []byte(script), 0755); e != nil {
		return e
	}
	if !enabled {
		if e := command("rc-service", name, "stop"); e != nil {
			if _, er := runOutput(5*time.Second, "rc-service", name, "status"); er == nil {
				return e
			}
		}
		_ = command("rc-update", "del", name, "default")
		return nil
	}
	if e = command("rc-update", "add", name, "default"); e != nil {
		return e
	}
	if e = command("rc-service", name, "restart"); e != nil {
		return e
	}
	time.Sleep(350 * time.Millisecond)
	return command("rc-service", name, "status")
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
		return "未知"
	}
	if m == "none" {
		return "未托管（测试模式）"
	}
	var er error
	if m == "systemd" {
		_, er = runOutput(5*time.Second, "systemctl", "is-active", "--quiet", serviceName(p)+".service")
	} else {
		_, er = runOutput(5*time.Second, "rc-service", serviceName(p), "status")
	}
	if er != nil {
		return "未运行"
	}
	return "运行中"
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
