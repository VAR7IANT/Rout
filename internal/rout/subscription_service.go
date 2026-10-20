package rout

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
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
}

func (s SubscriptionSettings) listenPort() int {
	if s.Port == 0 {
		return subscriptionDefaultPort
	}
	return s.Port
}

func (s SubscriptionSettings) Validate() error {
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
	st, e := a.LoadSettings()
	if e != nil {
		return e
	}
	if st.Language == "" {
		st.Language = a.Language
	}
	st.Subscription = &cfg
	return a.SaveSettings(st)
}

// SetSubscriptionPublicURL stores (or, when empty, clears) the HTTPS base URL.
func (a *App) SetSubscriptionPublicURL(raw string) error {
	cfg, e := a.subscriptionSettings()
	if e != nil {
		return e
	}
	cfg.PublicURL = ""
	if strings.TrimSpace(raw) != "" {
		if cfg.PublicURL, e = normalizePublicURL(raw); e != nil {
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
func (a *App) installSubscriptionService(m string, port int, restart bool) error {
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
		if restart || !serviceActive(m, name) {
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
		if written || restart || !serviceActive(m, name) {
			if e = command("rc-service", name, "restart"); e != nil && !strings.Contains(e.Error(), "already starting") {
				return fmt.Errorf("订阅服务启动失败，请查看 /var/log/%s.log", name)
			}
		}
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

// EnableSubscriptionServer saves the settings and starts the service. On failure the
// previous settings and service state are restored.
func (a *App) EnableSubscriptionServer(port int) error {
	if port < 1024 || port > 65535 {
		return errors.New("订阅服务端口应为 1024–65535")
	}
	unlock, e := lockFile(filepath.Join(a.Home, ".subscription.lock"), trafficLockWait)
	if e != nil {
		return e
	}
	defer unlock()
	m, e := a.serviceManager()
	if e != nil {
		return e
	}
	prev, e := a.subscriptionSettings()
	if e != nil {
		return e
	}
	s, e := a.Load()
	if e != nil {
		return e
	}
	for _, p := range s.Profiles {
		if p.Enabled && sharesNetwork(p.Networks(), []string{"tcp"}) && p.Port == port {
			return fmt.Errorf("端口 %d 已被节点 %s 使用", port, p.Name)
		}
	}
	running := m != "none" && prev.Enabled && prev.listenPort() == port && serviceActive(m, a.subscriptionService())
	if !running {
		l, er := net.Listen("tcp", net.JoinHostPort("127.0.0.1", itoa(port)))
		if er != nil {
			return fmt.Errorf("端口 %d 不可用：%w", port, er)
		}
		l.Close()
	}
	next := prev
	next.Enabled, next.Port = true, port
	if e = a.saveSubscriptionSettings(next); e != nil {
		return e
	}
	if m == "none" {
		return nil
	}
	if e = a.installSubscriptionService(m, port, prev.listenPort() != port); e != nil {
		errs := []error{e}
		if !prev.Enabled {
			errs = append(errs, a.removeSubscriptionService(m))
		}
		errs = append(errs, a.saveSubscriptionSettings(prev))
		return errors.Join(errs...)
	}
	return nil
}

// RestartSubscriptionServer refreshes the helper (after `rout update`) and restarts.
func (a *App) RestartSubscriptionServer() error {
	cfg, e := a.subscriptionSettings()
	if e != nil {
		return e
	}
	if !cfg.Enabled {
		return errors.New("订阅服务未启用")
	}
	m, e := a.serviceManager()
	if e != nil || m == "none" {
		return e
	}
	unlock, e := lockFile(filepath.Join(a.Home, ".subscription.lock"), trafficLockWait)
	if e != nil {
		return e
	}
	defer unlock()
	return a.installSubscriptionService(m, cfg.listenPort(), true)
}

// DisableSubscriptionServer stops and removes the service; existing subscriptions are kept.
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
