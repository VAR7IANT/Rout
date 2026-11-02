package rout

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// webService is the init-system name of the management panel; like the subscription server it
// is suffixed for a non-default home so tests and side-by-side installs do not collide.
func (a *App) webService() string {
	if a.Home == "/etc/rout" {
		return "rout-web"
	}
	h := sha256.Sum256([]byte(a.Home))
	return "rout-web-" + hex.EncodeToString(h[:4])
}

// webHelper is a copy of the manager that the service runs, so `rout update` never swaps the
// binary under a running panel.
func (a *App) webHelper() string { return filepath.Join(a.BinDir, "rout-web-v1") }
func (a *App) webArgs() []string {
	return []string{"--home", a.Home, "--bin-dir", a.BinDir, "web", "serve"}
}
func (a *App) webUnitPath(m string) string {
	if m == "systemd" {
		return filepath.Join("/etc/systemd/system", a.webService()+".service")
	}
	return filepath.Join("/etc/init.d", a.webService())
}

// The panel manages nodes, relays and services, so it needs the same privilege as the
// command line and cannot run in a read-only sandbox. What it does not need is dropped:
// no raw sockets beyond netlink, no namespaces, no kernel modules, no home directories.
// It only ever binds 127.0.0.1.
func (a *App) webUnit() string {
	cmd := quoteArgs(append([]string{a.webHelper()}, a.webArgs()...), unitQuote)
	return "[Unit]\nDescription=Rout management panel (loopback only)\nAfter=network.target\n\n[Service]\nType=simple\nExecStart=" + cmd +
		"\nRestart=on-failure\nRestartSec=3\nLimitNOFILE=4096\nUMask=0077\nNoNewPrivileges=true\nPrivateTmp=true\nPrivateDevices=true\nProtectHome=true\nProtectKernelModules=true\nProtectClock=true\nProtectHostname=true\nRestrictNamespaces=true\nRestrictRealtime=true\nRestrictSUIDSGID=true\nLockPersonality=true\nSystemCallArchitectures=native\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK\n\n[Install]\nWantedBy=multi-user.target\n"
}

func (a *App) webOpenRC() string {
	name := a.webService()
	return "#!/sbin/openrc-run\nname=" + shellQuote(name) + "\nsupervisor=supervise-daemon\ncommand=" + shellQuote(a.webHelper()) + "\ncommand_args=" + shellQuote(quoteArgs(a.webArgs(), shellQuote)) +
		"\nrespawn_delay=3\nrespawn_max=5\nrespawn_period=60\noutput_log=" + shellQuote("/var/log/"+name+".log") + "\nerror_log=" + shellQuote("/var/log/"+name+".log") + "\npidfile=" + shellQuote("/run/"+name+".pid") +
		"\n\ndepend() { use net; }\nstart_pre() { umask 077; if [ -f \"$output_log\" ] && [ \"$(wc -c < \"$output_log\")\" -gt " + itoa(openrcLogLimit) + " ]; then mv -f \"$output_log\" \"$output_log.1\"; fi; touch \"$output_log\"; chmod 600 \"$output_log\"; }\n"
}

// WebStatus describes the installed panel service.
type WebStatus struct {
	Installed   bool
	Running     bool
	Managed     bool
	Port        int
	PasswordSet bool
	Hosts       []string
	HTTPSDomain string
}

func (a *App) WebStatus() (WebStatus, error) {
	cfg, e := a.LoadWebConfig()
	if e != nil {
		return WebStatus{}, e
	}
	st := WebStatus{Port: cfg.port(), PasswordSet: cfg.PasswordHash != "", Hosts: cfg.AllowedHosts, HTTPSDomain: cfg.HTTPSDomain}
	m, er := a.serviceManager()
	if er != nil || m == "none" {
		return st, nil
	}
	st.Managed = true
	if _, er := os.Stat(a.webUnitPath(m)); er == nil {
		st.Installed = true
		st.Running = serviceActive(m, a.webService())
	}
	return st, nil
}

// InstallWebService writes the helper and init definition, enables the service at boot and
// (re)starts it, returning once the panel answers on loopback.
func (a *App) InstallWebService() error {
	m, e := a.serviceManager()
	if e != nil {
		return e
	}
	if m == "none" {
		return fmt.Errorf("当前环境没有受管理的服务")
	}
	cfg, e := a.LoadWebConfig()
	if e != nil {
		return e
	}
	exe, e := os.Executable()
	if e != nil {
		return e
	}
	b, e := os.ReadFile(exe)
	if e != nil {
		return e
	}
	restart := false
	if old, er := os.ReadFile(a.webHelper()); er != nil || string(old) != string(b) {
		if e = AtomicWrite(a.webHelper(), b, 0755); e != nil {
			return e
		}
		restart = true
	}
	name := a.webService()
	if m == "systemd" {
		written, e := writeIfChanged(a.webUnitPath(m), a.webUnit(), 0644)
		if e != nil {
			return e
		}
		if written || needsDaemonReload(name) {
			if e = command("systemctl", "daemon-reload"); e != nil {
				return e
			}
			restart = true
		}
		if e = command("systemctl", "enable", name+".service"); e != nil {
			return e
		}
		if restart || !serviceActive(m, name) {
			_ = command("systemctl", "reset-failed", name+".service")
			if e = command("systemctl", "restart", name+".service"); e != nil {
				return fmt.Errorf("管理面板启动失败，请运行 journalctl -u %s 查看原因", name)
			}
		}
	} else {
		written, e := writeIfChanged(a.webUnitPath(m), a.webOpenRC(), 0755)
		if e != nil {
			return e
		}
		if e = command("rc-update", "add", name, "default"); e != nil {
			return e
		}
		if written || restart || !serviceActive(m, name) {
			if e = command("rc-service", name, "restart"); e != nil && !strings.Contains(e.Error(), "already starting") {
				return fmt.Errorf("管理面板启动失败，请查看 /var/log/%s.log", name)
			}
		}
	}
	deadline := time.Now().Add(healthTimeout)
	for {
		if c, er := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(cfg.port())), 500*time.Millisecond); er == nil {
			c.Close()
			if serviceActive(m, name) {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("管理面板未能在 127.0.0.1:%d 保持运行", cfg.port())
		}
		time.Sleep(150 * time.Millisecond)
	}
}

// RemoveWebService stops and removes the service. The password and settings are kept so a
// later install picks up where it left off.
func (a *App) RemoveWebService() error {
	m, e := a.serviceManager()
	if e != nil || m == "none" {
		return e
	}
	name, path := a.webService(), a.webUnitPath(m)
	if _, er := os.Stat(path); os.IsNotExist(er) {
		return nil
	}
	if m == "systemd" {
		if e = command("systemctl", "disable", "--now", name+".service"); e != nil {
			return e
		}
	} else {
		if e = command("rc-service", name, "stop"); e != nil && serviceActive(m, name) {
			return e
		}
		_ = command("rc-update", "del", name, "default")
	}
	if e = os.Remove(path); e != nil {
		return e
	}
	_ = os.Remove(a.webHelper())
	if m == "systemd" {
		return command("systemctl", "daemon-reload")
	}
	return nil
}

// controlWeb starts, stops or restarts the installed service.
func (a *App) controlWeb(action string) error {
	m, e := a.serviceManager()
	if e != nil {
		return e
	}
	if m == "none" {
		return fmt.Errorf("当前环境没有受管理的服务")
	}
	if _, er := os.Stat(a.webUnitPath(m)); er != nil {
		return fmt.Errorf("管理面板尚未安装，请先运行 rout web install")
	}
	if m == "systemd" {
		return command("systemctl", action, a.webService()+".service")
	}
	return command("rc-service", a.webService(), action)
}
