package rout

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const subscriptionDefaultPort = 8787

// SubscriptionSettings is stored in settings.json. The server is disabled until enabled.
type SubscriptionSettings struct {
	Enabled bool `json:"enabled"`
	// Local listening port on 127.0.0.1; 0 means the default (8787).
	Port int `json:"port,omitempty"`
	// Public HTTPS base URL of the administrator's reverse proxy, e.g. https://sub.example.com
	PublicURL string `json:"public_url,omitempty"`
	// Optional client-side Mihomo health-check URL; absent keeps the default.
	MihomoTestURL string `json:"mihomo_test_url,omitempty"`
}

func (s SubscriptionSettings) listenPort() int {
	if s.Port == 0 {
		return subscriptionDefaultPort
	}
	return s.Port
}

func (s SubscriptionSettings) Validate() error {
	if s.MihomoTestURL != "" {
		if e := validateMihomoTestURL(s.MihomoTestURL); e != nil {
			return e
		}
	}
	if s.Port != 0 && (s.Port < 1024 || s.Port > 65535) {
		return errors.New("订阅服务端口应为 1024–65535")
	}
	if s.PublicURL != "" {
		if _, e := normalizePublicURL(s.PublicURL); e != nil {
			return e
		}
	}
	return nil
}

// normalizePublicURL accepts only a plain https base URL (optionally with a path prefix).
func normalizePublicURL(raw string) (string, error) {
	u, e := url.Parse(strings.TrimSpace(raw))
	if e != nil || u.Host == "" {
		return "", errors.New("公网地址无效，应类似 https://sub.example.com")
	}
	if u.Scheme != "https" {
		return "", errors.New("订阅公网地址必须使用 HTTPS")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(raw, " \t\r\n") {
		return "", errors.New("公网地址不能包含账号、参数或空白")
	}
	if !validHostStrict(u.Hostname()) {
		return "", errors.New("公网地址无效，应类似 https://sub.example.com")
	}
	return strings.TrimRight(u.Scheme+"://"+u.Host+u.EscapedPath(), "/"), nil
}

// MihomoURL reuses the same token and public base URL, without storing either URL.
func (s SubscriptionSettings) MihomoURL(token string) string {
	if base := s.SubscriptionURL(token); base != "" {
		return base + "?format=mihomo"
	}
	return ""
}

// SubscriptionURL builds the client URL, or "" when no HTTPS public URL is configured.
func (s SubscriptionSettings) SubscriptionURL(token string) string {
	if s.PublicURL == "" {
		return ""
	}
	return s.PublicURL + "/s/" + token
}

func (a *App) subscriptionSettings() (SubscriptionSettings, error) {
	st, e := a.LoadSettings()
	if e != nil || st.Subscription == nil {
		return SubscriptionSettings{}, e
	}
	return *st.Subscription, nil
}

func (a *App) saveSubscriptionSettings(cfg SubscriptionSettings) error {
	if e := cfg.Validate(); e != nil {
		return e
	}
	unlock, e := a.lock()
	if e != nil {
		return e
	}
	defer unlock()
	st, e := a.LoadSettings()
	if e != nil {
		return e
	}
	if st.Language == "" {
		st.Language = languageOr(a.Language)
	}
	st.Subscription = &cfg
	b, e := JSON(st)
	if e != nil {
		return e
	}
	old, e := snapshotSubscriptionFile(filepath.Join(a.Home, "settings.json"))
	if e != nil {
		return e
	}
	if old.Exists && bytes.Equal(old.Data, b) {
		return nil
	}
	return atomicSubscriptionFile(old, b, 0600)
}

// SetSubscriptionPublicURL stores (or, when empty, clears) the HTTPS base URL.
func (a *App) SetSubscriptionPublicURL(raw string) error {
	unlock, e := lockFile(filepath.Join(a.Home, ".subscription.lock"), trafficLockWait)
	if e != nil {
		return e
	}
	defer unlock()

	cfg, e := a.subscriptionSettings()
	if e != nil {
		return e
	}
	original := cfg
	cfg.PublicURL = ""
	if strings.TrimSpace(raw) != "" {
		if cfg.PublicURL, e = normalizePublicURL(raw); e != nil {
			return e
		}
	}
	if cfg != original {
		if _, e = a.backupSubscriptionFiles("https-url", filepath.Join(a.Home, "settings.json"), filepath.Join(a.Home, "state.json")); e != nil {
			return e
		}
	}
	return a.saveSubscriptionSettings(cfg)
}

func (a *App) subscriptionService() string {
	if a.Home == "/etc/rout" {
		return "rout-subscription"
	}
	h := sha256.Sum256([]byte(a.Home))
	return "rout-subscription-" + hex.EncodeToString(h[:4])
}
func (a *App) subscriptionHelper() string { return filepath.Join(a.BinDir, "rout-subscription-v1") }
func (a *App) subscriptionArgs() []string {
	return []string{"--home", a.Home, "--bin-dir", a.BinDir, "subscription", "serve"}
}
func (a *App) subscriptionUnitPath(m string) string {
	if m == "systemd" {
		return filepath.Join("/etc/systemd/system", a.subscriptionService()+".service")
	}
	return filepath.Join("/etc/init.d", a.subscriptionService())
}

// The server only reads state, so the unit makes the filesystem read-only, drops every
// capability and allows only IP sockets. It needs no privilege beyond reading its own state.
func (a *App) subscriptionUnit() string {
	cmd := quoteArgs(append([]string{a.subscriptionHelper()}, a.subscriptionArgs()...), unitQuote)
	return "[Unit]\nDescription=Rout subscription server (loopback only)\nAfter=network.target\n\n[Service]\nType=simple\nExecStart=" + cmd + "\nRestart=on-failure\nRestartSec=3\nLimitNOFILE=4096\nUMask=0077\nNoNewPrivileges=true\nPrivateTmp=true\nPrivateDevices=true\nProtectHome=true\nProtectSystem=strict\nProtectKernelTunables=true\nProtectKernelModules=true\nProtectKernelLogs=true\nProtectControlGroups=true\nProtectClock=true\nProtectHostname=true\nRestrictNamespaces=true\nRestrictRealtime=true\nRestrictSUIDSGID=true\nLockPersonality=true\nCapabilityBoundingSet=\nSystemCallArchitectures=native\nRestrictAddressFamilies=AF_INET AF_INET6\n\n[Install]\nWantedBy=multi-user.target\n"
}
func (a *App) subscriptionOpenRC() string {
	name := a.subscriptionService()
	return "#!/sbin/openrc-run\nname=" + shellQuote(name) + "\nsupervisor=supervise-daemon\ncommand=" + shellQuote(a.subscriptionHelper()) + "\ncommand_args=" + shellQuote(quoteArgs(a.subscriptionArgs(), shellQuote)) + "\nrespawn_delay=3\nrespawn_max=5\nrespawn_period=60\noutput_log=" + shellQuote("/var/log/"+name+".log") + "\nerror_log=" + shellQuote("/var/log/"+name+".log") + "\npidfile=" + shellQuote("/run/"+name+".pid") + "\n\ndepend() { use net; }\nstart_pre() { umask 077; if [ -f \"$output_log\" ] && [ \"$(wc -c < \"$output_log\")\" -gt " + itoa(openrcLogLimit) + " ]; then mv -f \"$output_log\" \"$output_log.1\"; fi; touch \"$output_log\"; chmod 600 \"$output_log\"; }\n"
}

// SubscriptionServerStatus describes the saved settings and whether the service runs.
type SubscriptionServerStatus struct {
	Settings SubscriptionSettings
	Managed  bool // false in test mode (no init system)
	Running  bool
}

func (a *App) SubscriptionServerStatus() (SubscriptionServerStatus, error) {
	cfg, e := a.subscriptionSettings()
	if e != nil {
		return SubscriptionServerStatus{}, e
	}
	st := SubscriptionServerStatus{Settings: cfg}
	if m, er := a.serviceManager(); er == nil && m != "none" {
		st.Managed = true
		st.Running = serviceActive(m, a.subscriptionService())
	}
	return st, nil
}

// installSubscriptionService writes the helper and init definition and (re)starts the
// service, returning once the port accepts connections.
func (a *App) installSubscriptionService(m string, port int, restart, activate bool) error {
	exe, e := os.Executable()
	if e != nil {
		return e
	}
	b, e := os.ReadFile(exe)
	if e != nil {
		return e
	}
	// A copy outside /usr/local/bin keeps a running server independent of `rout update`.
	if old, er := os.ReadFile(a.subscriptionHelper()); er != nil || string(old) != string(b) {
		if e = AtomicWrite(a.subscriptionHelper(), b, 0755); e != nil {
			return e
		}
		restart = true
	}
	name := a.subscriptionService()
	if m == "systemd" {
		written, e := writeIfChanged(a.subscriptionUnitPath(m), a.subscriptionUnit(), 0644)
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
		if activate && (restart || !serviceActive(m, name)) {
			_ = command("systemctl", "reset-failed", name+".service")
			if e = command("systemctl", "restart", name+".service"); e != nil {
				return fmt.Errorf("订阅服务启动失败，请运行 journalctl -u %s 查看原因", name)
			}
		}
	} else {
		written, e := writeIfChanged(a.subscriptionUnitPath(m), a.subscriptionOpenRC(), 0755)
		if e != nil {
			return e
		}
		if e = command("rc-update", "add", name, "default"); e != nil {
			return e
		}
		if activate && (written || restart || !serviceActive(m, name)) {
			if e = command("rc-service", name, "restart"); e != nil && !strings.Contains(e.Error(), "already starting") {
				return fmt.Errorf("订阅服务启动失败，请查看 /var/log/%s.log", name)
			}
		}
	}
	if !activate {
		return nil
	}
	deadline := time.Now().Add(healthTimeout)
	for {
		if c, e := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(port)), 500*time.Millisecond); e == nil {
			c.Close()
			if serviceActive(m, name) {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("订阅服务未能在 127.0.0.1:%d 保持运行", port)
		}
		time.Sleep(150 * time.Millisecond)
	}
}

func (a *App) removeSubscriptionService(m string) error {
	if m == "none" {
		return nil
	}
	name := a.subscriptionService()
	path := a.subscriptionUnitPath(m)
	if _, e := os.Stat(path); os.IsNotExist(e) {
		return nil
	}
	if m == "systemd" {
		if e := command("systemctl", "disable", "--now", name+".service"); e != nil {
			return e
		}
	} else {
		if e := command("rc-service", name, "stop"); e != nil && serviceActive(m, name) {
			return e
		}
		_ = command("rc-update", "del", name, "default")
	}
	if e := os.Remove(path); e != nil {
		return e
	}
	_ = os.Remove(a.subscriptionHelper())
	if m == "systemd" {
		return command("systemctl", "daemon-reload")
	}
	return nil
}

// Subscription operations never rewrite state.json. The transaction preserves the
// helper, unit, listener settings and previous running state if a restart fails.
func (a *App) subscriptionServiceChange(next SubscriptionSettings, force, preserveStartup bool) (err error) {
	prev, e := a.subscriptionSettings()
	if e != nil {
		return e
	}
	m, e := a.serviceManager()
	if e != nil {
		return e
	}
	oldHTTPS, e := a.loadHTTPSState()
	if e != nil {
		return e
	}
	changePort := prev.listenPort() != next.listenPort()
	owned := !oldHTTPS.Removed && (oldHTTPS.Ownership == "managed" || oldHTTPS.Ownership == "adopted") && httpsOwnsPublicURL(oldHTTPS, prev.PublicURL)
	if changePort && prev.Enabled && prev.PublicURL != "" && !owned {
		return errors.New("the HTTPS proxy is external; keep the current port or update that proxy explicitly before changing ports")
	}
	state, e := a.Load()
	if e != nil {
		return e
	}
	for _, p := range state.Profiles {
		if p.Enabled && sharesNetwork(p.Networks(), []string{"tcp"}) && p.Port == next.listenPort() {
			return fmt.Errorf("端口 %d 已被节点 %s 使用", next.listenPort(), p.Name)
		}
	}
	running := m != "none" && serviceActive(m, a.subscriptionService())
	activate := !preserveStartup || force || running
	startup := a.subscriptionStartupEnabled(m)
	if (!running || changePort) && activate {
		l, er := net.Listen("tcp", net.JoinHostPort("127.0.0.1", itoa(next.listenPort())))
		if er != nil {
			return fmt.Errorf("端口 %d 不可用：%w", next.listenPort(), er)
		}
		l.Close()
	}
	var files []subscriptionFileSnapshot
	if m != "none" {
		for _, path := range []string{a.subscriptionHelper(), a.subscriptionUnitPath(m)} {
			f, er := snapshotSubscriptionFile(path)
			if er != nil {
				return er
			}
			files = append(files, f)
		}
	}
	backupPath := ""
	if m != "none" {
		exe, er := os.Executable()
		if er != nil {
			return er
		}
		data, er := os.ReadFile(exe)
		if er != nil {
			return er
		}
		unit := a.subscriptionUnit()
		if m == "openrc" {
			unit = a.subscriptionOpenRC()
		}
		unchanged := files[0].Exists && bytes.Equal(files[0].Data, data) && files[1].Exists && string(files[1].Data) == unit
		if preserveStartup && !force && next == prev && unchanged {
			return nil
		}
		saved, er := a.backupSubscriptionFiles("service", filepath.Join(a.Home, "state.json"), filepath.Join(a.Home, "settings.json"), a.subscriptionHelper(), a.subscriptionUnitPath(m))
		if er != nil {
			return er
		}
		backupPath = saved[0].backup
	}
	changedSettings := next != prev
	changedService := false
	defer func() {
		if err == nil {
			return
		}
		var rollback []error
		if changedSettings {
			rollback = append(rollback, a.saveSubscriptionSettings(prev))
		}
		if changedService && m != "none" {
			if !running {
				if m == "systemd" {
					rollback = append(rollback, command("systemctl", "stop", a.subscriptionService()+".service"))
				} else {
					rollback = append(rollback, command("rc-service", a.subscriptionService(), "stop"))
				}
			}
			if len(files) > 1 && !files[1].Exists {
				if m == "systemd" {
					rollback = append(rollback, command("systemctl", "disable", a.subscriptionService()+".service"))
				} else {
					rollback = append(rollback, command("rc-update", "del", a.subscriptionService(), "default"))
				}
			}
			rollback = append(rollback, restoreSubscriptionFiles(files))
			if m == "systemd" {
				rollback = append(rollback, command("systemctl", "daemon-reload"))
			}
			if running {
				if m == "systemd" {
					rollback = append(rollback, command("systemctl", "restart", a.subscriptionService()+".service"))
				} else {
					rollback = append(rollback, command("rc-service", a.subscriptionService(), "restart"))
				}
				if c, er := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(prev.listenPort())), 3*time.Second); er != nil {
					rollback = append(rollback, errors.New("old subscription listener could not be verified after rollback"))
				} else {
					c.Close()
				}
			}
			if !startup && len(files) > 1 && files[1].Exists {
				rollback = append(rollback, a.subscriptionSetStartup(m, false))
			}
			for _, f := range files {
				if !sameFileSnapshot(f) {
					rollback = append(rollback, fmt.Errorf("subscription file rollback not verified: %s", f.Path))
				}
			}
		}
		if rb := errors.Join(rollback...); rb != nil {
			err = errors.Join(err, fmt.Errorf("subscription rollback incomplete: %w; inspect recovery snapshot %s", rb, backupPath))
		}
	}()
	if changedSettings {
		if e = a.saveSubscriptionSettings(next); e != nil {
			return e
		}
	}
	if m != "none" {
		changedService = true
		if e = a.installSubscriptionService(m, next.listenPort(), force || changePort, activate); e != nil {
			return e
		}
	}
	if preserveStartup && len(files) > 1 && files[1].Exists && !startup {
		if e = a.subscriptionSetStartup(m, false); e != nil {
			return e
		}
	}
	if changePort && owned {
		if e = a.deploySubscriptionHTTPSLocked(oldHTTPS.Domain, HTTPSDeployOptions{}); e != nil {
			return e
		}
	}
	return nil
}
func (a *App) EnableSubscriptionServer(port int) error {
	if port < 1024 || port > 65535 {
		return errors.New("订阅服务端口应为 1024–65535")
	}
	unlock, e := lockFile(filepath.Join(a.Home, ".subscription.lock"), trafficLockWait)
	if e != nil {
		return e
	}
	defer unlock()
	next, e := a.subscriptionSettings()
	if e != nil {
		return e
	}
	next.Enabled, next.Port = true, port
	return a.subscriptionServiceChange(next, false, false)
}
func (a *App) RestartSubscriptionServer() error { return a.refreshSubscriptionServer(true) }
func (a *App) RefreshSubscriptionServer() error { return a.refreshSubscriptionServer(false) }
func (a *App) refreshSubscriptionServer(force bool) error {
	unlock, e := lockFile(filepath.Join(a.Home, ".subscription.lock"), trafficLockWait)
	if e != nil {
		return e
	}
	defer unlock()
	cfg, e := a.subscriptionSettings()
	if e != nil {
		return e
	}
	if !cfg.Enabled {
		if force {
			return errors.New("订阅服务未启用")
		}
		return nil
	}
	if m, er := a.serviceManager(); er != nil {
		return er
	} else if m == "none" {
		return nil
	}
	return a.subscriptionServiceChange(cfg, force, true)
}

// Stop/disable only the subscription unit. Caddy and all subscription data remain.
func (a *App) DisableSubscriptionServer() error {
	unlock, e := lockFile(filepath.Join(a.Home, ".subscription.lock"), trafficLockWait)
	if e != nil {
		return e
	}
	defer unlock()
	cfg, e := a.subscriptionSettings()
	if e != nil {
		return e
	}
	m, e := a.serviceManager()
	if e != nil {
		return e
	}
	if e = a.removeSubscriptionService(m); e != nil {
		return e
	}
	cfg.Enabled = false
	return a.saveSubscriptionSettings(cfg)
}

// Logs are bounded and every subscription token-shaped URL is redacted before
// display, including messages from an older helper or a failing reverse proxy.
var subscriptionLogToken = regexp.MustCompile(`/s/[A-Za-z0-9_-]{43}`)

func sanitizeSubscriptionLogs(b []byte) string {
	return subscriptionLogToken.ReplaceAllString(string(b), "/s/[redacted]")
}
func (a *App) SubscriptionLogs() (string, error) {
	m, e := a.serviceManager()
	if e != nil {
		return "", e
	}
	if m == "systemd" {
		b, e := runOutput(5*time.Second, "journalctl", "-u", a.subscriptionService(), "-n", "50", "--no-pager", "-o", "cat")
		if e != nil {
			return "", errors.New("cannot read subscription service logs")
		}
		return sanitizeSubscriptionLogs(b), nil
	}
	if m == "openrc" {
		f, e := os.Open("/var/log/" + a.subscriptionService() + ".log")
		if e != nil {
			return "", e
		}
		defer f.Close()
		st, e := f.Stat()
		if e != nil {
			return "", e
		}
		if st.Size() > 32<<10 {
			_, _ = f.Seek(-(32 << 10), 2)
		}
		b, e := io.ReadAll(io.LimitReader(f, 32<<10))
		return sanitizeSubscriptionLogs(b), e
	}
	return "", errors.New("no managed subscription service logs in test mode")
}

func (a *App) StopSubscriptionServer() error {
	unlock, e := lockFile(filepath.Join(a.Home, ".subscription.lock"), trafficLockWait)
	if e != nil {
		return e
	}
	defer unlock()
	m, e := a.serviceManager()
	if e != nil || m == "none" {
		return e
	}
	if m == "systemd" {
		return command("systemctl", "stop", a.subscriptionService()+".service")
	}
	return command("rc-service", a.subscriptionService(), "stop")
}
func (a *App) subscriptionStartupEnabled(m string) bool {
	if m == "systemd" {
		_, e := runOutput(3*time.Second, "systemctl", "is-enabled", a.subscriptionService()+".service")
		return e == nil
	}
	if m == "openrc" {
		b, e := runOutput(3*time.Second, "rc-update", "show", "default")
		if e != nil {
			return false
		}
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) > 0 && f[0] == a.subscriptionService() {
				return true
			}
		}
	}
	return false
}
func (a *App) subscriptionSetStartup(m string, enabled bool) error {
	if m == "systemd" {
		action := "disable"
		if enabled {
			action = "enable"
		}
		return command("systemctl", action, a.subscriptionService()+".service")
	}
	if m == "openrc" {
		action := "del"
		if enabled {
			action = "add"
		}
		return command("rc-update", action, a.subscriptionService(), "default")
	}
	return nil
}
func (a *App) SubscriptionStartup(enabled bool) error {
	unlock, e := lockFile(filepath.Join(a.Home, ".subscription.lock"), trafficLockWait)
	if e != nil {
		return e
	}
	defer unlock()
	cfg, e := a.subscriptionSettings()
	if e != nil {
		return e
	}
	if !cfg.Enabled {
		return errors.New("订阅服务未启用")
	}
	m, e := a.serviceManager()
	if e != nil {
		return e
	}
	return a.subscriptionSetStartup(m, enabled)
}
