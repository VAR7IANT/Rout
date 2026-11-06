package rout

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ---- service naming and definition (modelled on the panel's service) ---------------------------

func (a *App) telegramService() string {
	if a.Home == "/etc/rout" {
		return "rout-telegram"
	}
	h := sha256.Sum256([]byte(a.Home))
	return "rout-telegram-" + hex.EncodeToString(h[:4])
}

// telegramHelper is a copy of the manager that the service runs, so `rout update` never swaps
// the binary under a running service.
func (a *App) telegramHelper() string { return filepath.Join(a.BinDir, "rout-telegram-v1") }
func (a *App) telegramArgs() []string {
	return []string{"--home", a.Home, "--bin-dir", a.BinDir, "telegram", "serve"}
}
func (a *App) telegramUnitPath(m string) string {
	if m == "systemd" {
		return filepath.Join("/etc/systemd/system", a.telegramService()+".service")
	}
	return filepath.Join("/etc/init.d", a.telegramService())
}

// The service applies AI routing changes through the same code as the menu, so it needs the same
// privilege; what it does not need is dropped, as for the panel. It makes outbound HTTPS calls
// and, on the hub only and only when multi-server mode is enabled, listens on one TCP port.
func (a *App) telegramUnit() string {
	cmd := quoteArgs(append([]string{a.telegramHelper()}, a.telegramArgs()...), unitQuote)
	return "[Unit]\nDescription=Rout Telegram remote control\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nExecStart=" + cmd +
		"\nRestart=always\nRestartSec=5\nLimitNOFILE=4096\nUMask=0077\nNoNewPrivileges=true\nPrivateTmp=true\nPrivateDevices=true\nProtectHome=true\nProtectKernelModules=true\nProtectClock=true\nProtectHostname=true\nRestrictNamespaces=true\nRestrictRealtime=true\nRestrictSUIDSGID=true\nLockPersonality=true\nSystemCallArchitectures=native\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK\n\n[Install]\nWantedBy=multi-user.target\n"
}

func (a *App) telegramOpenRC() string {
	name := a.telegramService()
	return "#!/sbin/openrc-run\nname=" + shellQuote(name) + "\nsupervisor=supervise-daemon\ncommand=" + shellQuote(a.telegramHelper()) + "\ncommand_args=" + shellQuote(quoteArgs(a.telegramArgs(), shellQuote)) +
		"\nrespawn_delay=5\nrespawn_max=0\noutput_log=" + shellQuote("/var/log/"+name+".log") + "\nerror_log=" + shellQuote("/var/log/"+name+".log") + "\npidfile=" + shellQuote("/run/"+name+".pid") +
		"\n\ndepend() { need net; }\nstart_pre() { umask 077; if [ -f \"$output_log\" ] && [ \"$(wc -c < \"$output_log\")\" -gt " + itoa(openrcLogLimit) + " ]; then mv -f \"$output_log\" \"$output_log.1\"; fi; touch \"$output_log\"; chmod 600 \"$output_log\"; }\n"
}

// TelegramServiceState describes the installed service.
type TelegramServiceState struct{ Managed, Installed, Running bool }

func (a *App) TelegramServiceState() TelegramServiceState {
	var st TelegramServiceState
	m, e := a.serviceManager()
	if e != nil || m == "none" {
		return st
	}
	st.Managed = true
	if _, er := os.Stat(a.telegramUnitPath(m)); er == nil {
		st.Installed = true
		st.Running = serviceActive(m, a.telegramService())
	}
	return st
}

// InstallTelegramService writes the helper and init definition, enables the service at boot and
// (re)starts it.
func (a *App) InstallTelegramService() error {
	m, e := a.serviceManager()
	if e != nil {
		return e
	}
	if m == "none" {
		return fmt.Errorf("当前环境没有受管理的服务")
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
	if old, er := os.ReadFile(a.telegramHelper()); er != nil || string(old) != string(b) {
		if e = AtomicWrite(a.telegramHelper(), b, 0755); e != nil {
			return e
		}
		restart = true
	}
	name := a.telegramService()
	if m == "systemd" {
		written, e := writeIfChanged(a.telegramUnitPath(m), a.telegramUnit(), 0644)
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
				return fmt.Errorf("Telegram 服务启动失败，请运行 journalctl -u %s 查看原因", name)
			}
		}
		return nil
	}
	written, e := writeIfChanged(a.telegramUnitPath(m), a.telegramOpenRC(), 0755)
	if e != nil {
		return e
	}
	if e = command("rc-update", "add", name, "default"); e != nil {
		return e
	}
	if written || restart || !serviceActive(m, name) {
		if e = command("rc-service", name, "restart"); e != nil && !strings.Contains(e.Error(), "already starting") {
			return fmt.Errorf("Telegram 服务启动失败，请查看 /var/log/%s.log", name)
		}
	}
	return nil
}

// RemoveTelegramService stops and removes the service and its helper copy.
func (a *App) RemoveTelegramService() error {
	m, e := a.serviceManager()
	if e != nil || m == "none" {
		return e
	}
	name, path := a.telegramService(), a.telegramUnitPath(m)
	if _, er := os.Stat(path); os.IsNotExist(er) {
		_ = os.Remove(a.telegramHelper())
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
	_ = os.Remove(a.telegramHelper())
	if m == "systemd" {
		return command("systemctl", "daemon-reload")
	}
	return nil
}

// RefreshTelegramService re-installs an already installed service (after an upgrade). A host
// without the service is left alone.
func (a *App) RefreshTelegramService() error {
	if _, e := a.LoadTelegram(); e != nil {
		return nil
	}
	if !a.TelegramServiceState().Installed {
		return nil
	}
	return a.InstallTelegramService()
}

// ---- the service loop ----------------------------------------------------------------------------

// runKey is the part of the configuration that needs the running component to restart when it
// changes. Offset, approvals and message IDs change continuously and are deliberately excluded.
func (c TelegramConfig) runKey() string {
	h := sha256.New()
	fmt.Fprint(h, c.Token, "|", c.ChatID, "|", c.Role, "|", c.ServerID, "|", c.Name, "|", c.CertPEM)
	if c.Hub != nil {
		fmt.Fprint(h, "|h|", c.Hub.Port, c.Hub.MultiServer, strings.Join(c.Hub.Advertise, ","))
	}
	if c.Agent != nil {
		fmt.Fprint(h, "|a|", c.Agent.HubFP, c.Agent.State == "revoked", strings.Join(c.Agent.Endpoints, ","))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// RunTelegram is `rout telegram serve`: it runs whatever the configuration says, follows
// configuration changes made by the menu or the panel, and never takes the proxy services down:
// it only reads Rout's state and, when told by an authorised command, calls the same
// application functions the menu uses.
func (a *App) RunTelegram(ctx context.Context) error {
	for ctx.Err() == nil {
		cfg, e := a.LoadTelegram()
		if e != nil {
			a.writeTelegramRuntime(TelegramRuntime{State: tgStateStopped, Detail: "未绑定 Telegram Bot"})
			if !a.waitTelegramChange(ctx, "") {
				return ctx.Err()
			}
			continue
		}
		key := cfg.runKey()
		sub, cancel := context.WithCancel(ctx)
		done := make(chan error, 1)
		go func() { done <- a.runTelegramOnce(sub, cfg) }()
		changed := make(chan struct{})
		go func() {
			a.waitTelegramChange(sub, key)
			close(changed)
		}()
		select {
		case <-changed:
			cancel()
			<-done
		case err := <-done:
			cancel()
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// A terminal condition (revoked, hub changed) or a failure: wait for the owner to
			// change something, or retry after a pause.
			if err != nil && !errors.Is(err, context.Canceled) {
				_, _, retry := a.tgDurations()
				wait, stop := context.WithTimeout(ctx, 30*retry)
				a.waitTelegramChange(wait, key)
				stop()
			}
		}
	}
	return ctx.Err()
}

// waitTelegramChange returns true when the effective configuration differs from key (an empty key
// means "wait until something is bound"), false when ctx ends first.
func (a *App) waitTelegramChange(ctx context.Context, key string) bool {
	_, _, retry := a.tgDurations()
	tick := 2 * retry
	if tick < 20*time.Millisecond {
		tick = 20 * time.Millisecond
	}
	if tick > 3*time.Second {
		tick = 3 * time.Second
	}
	for {
		if !sleepCtx(ctx, tick) {
			return false
		}
		cfg, e := a.LoadTelegram()
		switch {
		case key == "" && e == nil:
			return true
		case key != "" && (e != nil || cfg.runKey() != key):
			return true
		}
	}
}

func (a *App) runTelegramOnce(ctx context.Context, cfg TelegramConfig) error {
	if cfg.Role == tgRoleAgent {
		return a.runTelegramAgent(ctx, cfg)
	}
	return a.runTelegramHub(ctx, cfg)
}

func (a *App) runTelegramAgent(ctx context.Context, cfg TelegramConfig) error {
	if cfg.Agent.State == "revoked" {
		a.writeTelegramRuntime(TelegramRuntime{Role: tgRoleAgent, State: tgStateRevoked, Detail: "控制中心已撤销本服务器的授权；请重新绑定", HubName: cfg.Agent.HubName})
		<-ctx.Done()
		return ctx.Err()
	}
	g, e := a.newTelegramAgent(cfg)
	if e != nil {
		a.writeTelegramRuntime(TelegramRuntime{Role: tgRoleAgent, State: tgStateError, Detail: a.tgErr(e)})
		return e
	}
	return g.run(ctx)
}

func (a *App) runTelegramHub(ctx context.Context, cfg TelegramConfig) error {
	rt := TelegramRuntime{Role: tgRoleHub, State: tgStateConnecting, BotUser: cfg.BotUser}
	a.writeTelegramRuntime(rt)
	cl := a.tgClient(cfg.Token)
	defer cl.close()
	_, _, retry := a.tgDurations()
	// Verify the token and make sure nobody else owns the update stream before touching it.
	for ctx.Err() == nil {
		me, e := cl.getMe(ctx)
		if e == nil {
			rt.BotUser = me.Username
			var wh tgWebhookInfo
			if wh, e = cl.getWebhook(ctx); e == nil && wh.URL != "" {
				rt.State, rt.Detail = tgStateConflict, "这个机器人设置了 webhook；Rout 不会覆盖它。请先在设置 webhook 的程序中移除，或换用专用机器人"
				a.writeTelegramRuntime(rt)
				if !sleepCtx(ctx, 15*retry) {
					return ctx.Err()
				}
				continue
			}
		}
		if e == nil {
			break
		}
		if tgIsAuth(e) {
			rt.State, rt.Detail = tgStateError, "Bot Token 无效或已被撤销"
		} else {
			rt.State, rt.Detail = tgStateOffline, "无法连接 Telegram"
		}
		a.writeTelegramRuntime(rt)
		if !sleepCtx(ctx, jitter(15*retry)) {
			return ctx.Err()
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	hub := newTelegramHub(a)
	defer hub.close()
	if cfg.Hub.MultiServer {
		if e := hub.listen(cfg); e != nil {
			rt.State, rt.Detail = tgStateError, a.tgErr(e)
			a.writeTelegramRuntime(rt)
			return e
		}
		rt.Listen = hub.addr()
		if a.telegram != nil && a.telegram.onHub != nil {
			a.telegram.onHub(hub)
		}
	}
	bot := newTelegramBot(a, hub, cl)
	hub.onPending = func(rec TelegramPendingRecord) {
		if cur, e := a.LoadTelegram(); e == nil {
			bot.notifyPending(ctx, cur, rec)
		}
	}
	rt.State, rt.Detail = tgStateOK, ""
	if e := bot.announce(ctx, cfg); e != nil {
		rt.Detail = tgScrub(a.Error(e), 200, cfg.Token)
		if strings.Contains(e.Error(), "另一个控制中心") {
			rt.State = tgStateConflict
			a.writeTelegramRuntime(rt)
			<-ctx.Done()
			return ctx.Err()
		}
	}
	a.writeTelegramRuntime(rt)
	// Ask again for requests that were saved but never reached the chat (a restart in between).
	for _, p := range cfg.Hub.Pending {
		bot.notifyPending(ctx, cfg, p)
	}
	go a.telegramHubTicker(ctx, hub, bot, &rt)
	return bot.run(ctx, &rt)
}

// telegramHubTicker refreshes the fleet summary and re-announces when the addresses change.
func (a *App) telegramHubTicker(ctx context.Context, hub *tgHub, bot *tgBot, rt *TelegramRuntime) {
	_, _, retry := a.tgDurations()
	every := 5 * retry
	last := time.Now()
	for sleepCtx(ctx, every) {
		cfg, e := a.LoadTelegram()
		if e != nil {
			return
		}
		rt.Servers = rt.Servers[:0]
		for _, v := range hub.servers(cfg) {
			e := TelegramRuntimeServer{ID: v.ID, Name: v.Name, Online: v.Online, LastSeen: v.LastSeen}
			if v.Status != nil {
				e.AIEnabled, e.ExitName, e.Version = v.Status.Enabled, v.Status.ExitName, v.Status.Version
			}
			rt.Servers = append(rt.Servers, e)
		}
		a.writeTelegramRuntime(*rt)
		if time.Since(last) > 10*time.Minute || (a.telegram != nil && a.telegram.retry > 0) {
			last = time.Now()
			bot.announce(ctx, cfg)
		}
	}
}

// ---- bind / unbind / change -----------------------------------------------------------------------

var (
	errTelegramBound = errors.New("已绑定 Telegram Bot；请先解绑，或使用“修改”")
	errNeedPrivate   = errors.New("Chat ID 必须是你自己与机器人的私聊（正整数用户 ID）；群组和频道暂不支持")
)

type TelegramBindRequest struct {
	Token    string
	ChatID   int64
	Name     string
	ForceHub bool
	// TrustHubFP is the hub fingerprint the user confirmed (an agent's first bind).
	TrustHubFP string
}

type TelegramBindResult struct {
	Role       string
	Name       string
	BotUser    string
	HubName    string
	HubFP      string
	NeedsTrust bool
	Warnings   []string
}

func (a *App) tgCheckBot(ctx context.Context, cl *tgClient, chat int64) (tgUser, error) {
	me, e := cl.getMe(ctx)
	if e != nil {
		return tgUser{}, errors.New(tgFriendly(e))
	}
	ch, e := cl.getChat(ctx, chat)
	if e != nil {
		return tgUser{}, errors.New(tgFriendly(e))
	}
	if ch.Type != "private" {
		return tgUser{}, errNeedPrivate
	}
	return me, nil
}

// TelegramBind validates the token and chat with Telegram itself, decides the role from what the
// chat already announces, and stores the configuration. It does not touch Rout's proxy state.
func (a *App) TelegramBind(ctx context.Context, req TelegramBindRequest) (TelegramBindResult, error) {
	var res TelegramBindResult
	if _, e := a.LoadTelegram(); e == nil {
		return res, errTelegramBound
	}
	token := strings.TrimSpace(req.Token)
	if !validTelegramToken(token) {
		return res, errors.New("Bot Token 格式不正确（形如 123456789:AA…，从 @BotFather 获取）")
	}
	if req.ChatID <= 0 {
		return res, errNeedPrivate
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = a.defaultServerName()
	}
	if e := validDisplayName(name); e != nil {
		return res, e
	}
	cl := a.tgClient(token)
	defer cl.close()
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	me, e := a.tgCheckBot(cctx, cl, req.ChatID)
	if e != nil {
		return res, e
	}
	cfg := TelegramConfig{Version: telegramConfigVersion, Token: token, ChatID: req.ChatID, BotUser: me.Username, Name: name, ServerID: randomID(8)}
	id, e := newTelegramIdentity(cfg.ServerID)
	if e != nil {
		return res, e
	}
	cfg.CertPEM, cfg.KeyPEM = id.CertPEM, id.KeyPEM
	res.Name, res.BotUser = name, me.Username

	an, annErr := a.telegramFetchAnnouncement(cctx, cl, cfg)
	switch {
	case annErr != nil || req.ForceHub:
		cfg.Role = tgRoleHub
		cfg.Hub = &TelegramHub{}
		wh, e := cl.getWebhook(cctx)
		if e != nil {
			return res, errors.New(tgFriendly(e))
		}
		if wh.URL != "" {
			return res, errors.New("这个机器人设置了 webhook；Rout 不会覆盖它。请先移除 webhook，或换用专用机器人")
		}
		if annErr == nil && req.ForceHub {
			// Replace a dead hub's announcement deliberately; agents bound to it keep refusing
			// the new certificate until they are re-trusted.
			if ch, er := cl.getChat(cctx, req.ChatID); er == nil && ch.PinnedMessage != nil {
				cl.unpin(cctx, req.ChatID, ch.PinnedMessage.MessageID)
				res.Warnings = append(res.Warnings, "已替换聊天中原有的控制中心公告；绑定到旧控制中心的服务器需要重新绑定")
			}
		}
		res.Role = tgRoleHub
	default:
		if len(an.Endpoints) == 0 {
			return res, fmt.Errorf("控制中心 %s 尚未启用多服务器模式；请先在那台服务器的 Telegram Bot 管理中启用", an.Name)
		}
		res.HubName, res.HubFP = an.Name, an.FP
		if !sameFingerprint(an.FP, req.TrustHubFP) {
			res.NeedsTrust, res.Role = true, tgRoleAgent
			return res, nil
		}
		cfg.Role = tgRoleAgent
		cfg.Agent = &TelegramAgent{HubID: an.HubID, HubName: an.Name, Endpoints: an.Endpoints, HubFP: an.FP, State: "pending"}
		res.Role = tgRoleAgent
		if w := a.telegramProbeHub(cctx, an, id); w != "" {
			res.Warnings = append(res.Warnings, w)
		}
	}
	if e := a.saveTelegram(cfg); e != nil {
		return res, e
	}
	return res, nil
}

// telegramProbeHub checks that the hub answers with the announced certificate. A failure is only a
// warning: the service keeps retrying, and NAT or a firewall is the usual cause.
func (a *App) telegramProbeHub(ctx context.Context, an tgAnnouncement, id tgIdentity) string {
	var last error
	cert, _ := id.tlsCert()
	for _, ep := range an.Endpoints {
		d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second}, Config: &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, Certificates: []tls.Certificate{cert},
			VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
				if len(raw) == 0 || certFingerprint(raw[0]) != an.FP {
					return errTgHubChanged
				}
				return nil
			}}}
		c, e := d.DialContext(ctx, "tcp", ep)
		if e == nil {
			c.Close()
			return ""
		}
		last = e
	}
	if errors.Is(last, errTgHubChanged) {
		return "控制中心的证书与公告不一致，请不要继续，先在控制中心核对"
	}
	return "暂时无法连接控制中心的地址（防火墙或 NAT？）；服务会持续重试，详见 docs/TELEGRAM.md"
}

// TelegramUnbind removes the control channel completely: the service stops first, the remote side
// is told best-effort, then every file holding a secret is deleted.
func (a *App) TelegramUnbind(ctx context.Context) ([]string, error) {
	var warns []string
	cfg, e := a.LoadTelegram()
	if e != nil {
		if errors.Is(e, errTelegramUnbound) {
			a.RemoveTelegramService()
			return nil, nil
		}
		// An unreadable file is still removed: unbinding must always be possible.
		a.RemoveTelegramService()
		return []string{"Telegram 配置无法读取，已直接清除"}, a.removeTelegramFiles()
	}
	if e = a.RemoveTelegramService(); e != nil {
		return nil, fmt.Errorf("无法停止 Telegram 服务：%w", e)
	}
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	switch cfg.Role {
	case tgRoleAgent:
		a.telegramLeave(cctx, cfg)
	case tgRoleHub:
		cl := a.tgClient(cfg.Token)
		if cfg.Hub != nil && cfg.Hub.AnnounceMsgID != 0 {
			if er := cl.unpin(cctx, cfg.ChatID, cfg.Hub.AnnounceMsgID); er != nil {
				warns = append(warns, "未能取消聊天中控制中心公告的置顶（可手动删除）")
			}
			cl.deleteMessage(cctx, cfg.ChatID, cfg.Hub.AnnounceMsgID)
		}
		cl.close()
		if cfg.Hub != nil && len(cfg.Hub.Agents) > 0 {
			warns = append(warns, fmt.Sprintf("已授权的 %d 台服务器将失去控制中心；它们的代理服务不受影响", len(cfg.Hub.Agents)))
		}
	}
	if e = a.removeTelegramFiles(); e != nil {
		return warns, e
	}
	return warns, nil
}

// TelegramSetCredentials replaces the Bot Token and/or Chat ID of a hub after Telegram confirms
// them. Approved servers receive the new values over their authenticated channel.
func (a *App) TelegramSetCredentials(ctx context.Context, token string, chat int64) ([]string, error) {
	cfg, e := a.LoadTelegram()
	if e != nil {
		return nil, e
	}
	if cfg.Role != tgRoleHub {
		return nil, errors.New("Token / Chat ID 由控制中心统一管理；请在控制中心修改，其他服务器会自动同步")
	}
	token = strings.TrimSpace(token)
	if token == "" {
		token = cfg.Token
	}
	if chat == 0 {
		chat = cfg.ChatID
	}
	if !validTelegramToken(token) {
		return nil, errors.New("Bot Token 格式不正确")
	}
	if chat <= 0 {
		return nil, errNeedPrivate
	}
	cl := a.tgClient(token)
	defer cl.close()
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	me, e := a.tgCheckBot(cctx, cl, chat)
	if e != nil {
		return nil, e
	}
	var warns []string
	if token != cfg.Token || chat != cfg.ChatID {
		// The old announcement lives in the old chat under the old token; withdraw it.
		old := a.tgClient(cfg.Token)
		if cfg.Hub != nil && cfg.Hub.AnnounceMsgID != 0 {
			old.unpin(cctx, cfg.ChatID, cfg.Hub.AnnounceMsgID)
			old.deleteMessage(cctx, cfg.ChatID, cfg.Hub.AnnounceMsgID)
		}
		old.close()
	}
	e = a.mutateTelegram(func(c *TelegramConfig) error {
		c.Token, c.ChatID, c.BotUser = token, chat, me.Username
		c.Offset = 0
		if c.Hub != nil {
			c.Hub.AnnounceMsgID = 0
		}
		return nil
	})
	if e != nil {
		return nil, e
	}
	if cfg.Hub != nil && len(cfg.Hub.Agents) > 0 {
		warns = append(warns, "已授权的服务器会在下次连接时自动同步新凭据；离线的服务器上线后同步")
	}
	return warns, nil
}

// TelegramRename changes this server's display name.
func (a *App) TelegramRename(name string) error {
	name = strings.TrimSpace(name)
	if e := validDisplayName(name); e != nil {
		return e
	}
	return a.mutateTelegram(func(c *TelegramConfig) error { c.Name = name; return nil })
}

// TelegramSetMultiServer turns the hub's agent listener on or off. Off means no listening port.
func (a *App) TelegramSetMultiServer(on bool, port int, advertise []string) error {
	return a.mutateTelegram(func(c *TelegramConfig) error {
		if c.Role != tgRoleHub || c.Hub == nil {
			return errors.New("只有控制中心可以启用多服务器模式")
		}
		if !on {
			c.Hub.MultiServer = false
			return nil
		}
		if port == 0 {
			port = c.Hub.Port
		}
		if port == 0 {
			port = randomFreeTelegramPort()
		}
		if port < 1024 || port > 65535 {
			return errors.New("端口应在 1024–65535 之间")
		}
		c.Hub.MultiServer, c.Hub.Port, c.Hub.Advertise = true, port, advertise
		return nil
	})
}

func randomFreeTelegramPort() int {
	for i := 0; i < 50; i++ {
		p := 20000 + rand.Intn(40000)
		if l, e := net.Listen("tcp", ":"+itoa(p)); e == nil {
			l.Close()
			return p
		}
	}
	return 28443
}

// TelegramRetrust lets an agent follow a changed hub: the user has compared the new fingerprint.
func (a *App) TelegramRetrust(ctx context.Context, trustFP string) (TelegramBindResult, error) {
	var res TelegramBindResult
	cfg, e := a.LoadTelegram()
	if e != nil {
		return res, e
	}
	if cfg.Role != tgRoleAgent {
		return res, errors.New("只有被控制的服务器需要重新信任控制中心")
	}
	cl := a.tgClient(cfg.Token)
	defer cl.close()
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	an, e := a.telegramFetchAnnouncement(cctx, cl, cfg)
	if e != nil {
		return res, errors.New("聊天中没有可用的控制中心公告")
	}
	res.HubName, res.HubFP, res.Role = an.Name, an.FP, tgRoleAgent
	if len(an.Endpoints) == 0 {
		return res, fmt.Errorf("控制中心 %s 尚未启用多服务器模式", an.Name)
	}
	if !sameFingerprint(an.FP, trustFP) {
		res.NeedsTrust = true
		return res, nil
	}
	// A new hub means a new approval: forget the old pin and start over with a fresh identity.
	id, e := newTelegramIdentity(cfg.ServerID)
	if e != nil {
		return res, e
	}
	e = a.mutateTelegram(func(c *TelegramConfig) error {
		c.CertPEM, c.KeyPEM = id.CertPEM, id.KeyPEM
		c.Agent = &TelegramAgent{HubID: an.HubID, HubName: an.Name, Endpoints: an.Endpoints, HubFP: an.FP, State: "pending"}
		return nil
	})
	return res, e
}
