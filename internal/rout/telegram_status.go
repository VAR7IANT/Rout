package rout

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// TelegramSummary is everything the menu, the command line and the panel show about the
// binding. It never contains the Bot Token or any private key.
type TelegramSummary struct {
	Bound       bool
	Role        string
	Name        string
	ServerID    string
	BotUser     string
	ChatMasked  string
	Fingerprint string // this server's own certificate (what the owner compares in Telegram)

	// Hub
	MultiServer bool
	Port        int
	Advertise   []string
	Endpoints   []string // what agents are told to dial, as last observed
	Agents      []TelegramAgentView
	Pending     []TelegramPendingView

	// Agent
	HubName      string
	HubFP        string
	HubEndpoints []string
	AgentState   string

	Service TelegramServiceState
	Runtime *TelegramRuntime
}

type TelegramAgentView struct {
	ID         string
	Name       string
	FP         string
	ApprovedAt time.Time
	Online     bool
}

type TelegramPendingView struct {
	ID, ServerID, Name, FP string
	RequestedAt            time.Time
}

func (a *App) TelegramSummary() (TelegramSummary, error) {
	var s TelegramSummary
	cfg, e := a.LoadTelegram()
	if e != nil {
		if errors.Is(e, errTelegramUnbound) {
			s.Service = a.TelegramServiceState()
			return s, nil
		}
		return s, e
	}
	s = TelegramSummary{Bound: true, Role: cfg.Role, Name: cfg.Name, ServerID: cfg.ServerID, BotUser: cfg.BotUser, ChatMasked: maskChatID(cfg.ChatID),
		Fingerprint: fingerprintGroups(cfg.identity().fingerprint()), Service: a.TelegramServiceState()}
	if rt, ok := a.LoadTelegramRuntime(); ok {
		s.Runtime = &rt
	}
	online := map[string]bool{}
	if s.Runtime != nil {
		for _, v := range s.Runtime.Servers {
			online[v.ID] = v.Online
		}
	}
	switch cfg.Role {
	case tgRoleHub:
		s.MultiServer, s.Port, s.Advertise = cfg.Hub.MultiServer, cfg.Hub.Port, append([]string(nil), cfg.Hub.Advertise...)
		for _, ag := range cfg.Hub.Agents {
			s.Agents = append(s.Agents, TelegramAgentView{ID: ag.ID, Name: ag.Name, FP: fingerprintGroups(ag.FP), ApprovedAt: ag.ApprovedAt, Online: online[ag.ID]})
		}
		sort.SliceStable(s.Agents, func(i, j int) bool { return strings.ToLower(s.Agents[i].Name) < strings.ToLower(s.Agents[j].Name) })
		for _, p := range cfg.Hub.Pending {
			s.Pending = append(s.Pending, TelegramPendingView{ID: p.ID, ServerID: p.ServerID, Name: p.Name, FP: fingerprintGroups(p.FP), RequestedAt: p.RequestedAt})
		}
	case tgRoleAgent:
		s.HubName, s.HubFP, s.HubEndpoints, s.AgentState = cfg.Agent.HubName, fingerprintGroups(cfg.Agent.HubFP), append([]string(nil), cfg.Agent.Endpoints...), cfg.Agent.State
	}
	return s, nil
}

// TelegramCheck is one line of the connection test.
type TelegramCheck struct {
	Level string // ok, warn, fail
	Text  string
}

// TelegramTest checks the bot, the chat and the path between servers, with real calls.
func (a *App) TelegramTest(ctx context.Context) ([]TelegramCheck, error) {
	cfg, e := a.LoadTelegram()
	if e != nil {
		return nil, e
	}
	var out []TelegramCheck
	add := func(level, text string) { out = append(out, TelegramCheck{level, a.T(text)}) }
	cl := a.tgClient(cfg.Token)
	defer cl.close()
	cctx, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	me, e := cl.getMe(cctx)
	if e != nil {
		add("fail", tgFriendly(e))
		return out, nil
	}
	add("ok", fmt.Sprintf(a.T("Bot @%s 可用，Token 有效"), me.Username))
	ch, e := cl.getChat(cctx, cfg.ChatID)
	switch {
	case e != nil:
		add("fail", tgFriendly(e))
	case ch.Type != "private":
		add("fail", errNeedPrivate.Error())
	default:
		add("ok", a.T("Chat ID 是可到达的私聊"))
	}
	svc := a.TelegramServiceState()
	switch {
	case !svc.Managed:
		add("warn", a.T("当前环境没有受管理的服务；请自行运行 rout telegram serve"))
	case !svc.Installed:
		add("warn", a.T("Telegram 服务尚未安装"))
	case !svc.Running:
		add("fail", a.T("Telegram 服务已安装但未运行"))
	default:
		add("ok", a.T("Telegram 服务正在运行"))
	}
	rt, _ := a.LoadTelegramRuntime()
	switch cfg.Role {
	case tgRoleHub:
		if wh, er := cl.getWebhook(cctx); er == nil && wh.URL != "" {
			add("fail", a.T("这个机器人设置了 webhook；Rout 不会覆盖它"))
		} else if er == nil {
			add("ok", a.T("没有 webhook，Rout 是这个机器人唯一的消息接收方"))
		}
		if ch.PinnedMessage != nil {
			if an, er := cfg.keys().openAnnouncement(ch.PinnedMessage.Text); er == nil && an.HubID == cfg.ServerID {
				add("ok", a.T("控制中心地址已置顶公布（加密）"))
			} else {
				add("warn", a.T("聊天中置顶的消息不是本控制中心的公告"))
			}
		} else {
			add("warn", a.T("尚未公布控制中心地址；服务运行后会自动公布"))
		}
		if cfg.Hub.MultiServer {
			if rt.Listen != "" {
				add("ok", fmt.Sprintf(a.T("多服务器模式已开启，监听 %s；请确认防火墙已放行该 TCP 端口"), rt.Listen))
			} else {
				add("warn", a.T("多服务器模式已开启，但服务尚未开始监听"))
			}
		} else {
			add("ok", a.T("单服务器模式：不开放任何端口"))
		}
	case tgRoleAgent:
		an, er := a.telegramFetchAnnouncement(cctx, cl, cfg)
		switch {
		case er != nil:
			add("warn", a.T("读不到聊天中的控制中心公告（已绑定的地址仍会继续使用）"))
		case an.HubID != cfg.Agent.HubID || an.FP != cfg.Agent.HubFP:
			add("fail", a.T("聊天中公布的控制中心与绑定时记录的不一致；请核对后在本机重新信任"))
		default:
			add("ok", a.T("控制中心公告与绑定记录一致"))
		}
		hub := tgAnnouncement{FP: cfg.Agent.HubFP, Endpoints: cfg.Agent.Endpoints}
		if w := a.telegramProbeHub(cctx, hub, cfg.identity()); w != "" {
			add("fail", a.T(w))
		} else {
			add("ok", a.T("可以连接控制中心，且证书与记录一致"))
		}
		switch rt.State {
		case tgStateOK:
			add("ok", a.T("已被控制中心批准并保持连接"))
		case tgStatePending:
			add("warn", a.T("等待你在 Telegram 里批准本服务器"))
		case tgStateRevoked:
			add("fail", a.T("控制中心已撤销本服务器；请重新绑定"))
		case tgStateHubChanged:
			add("fail", a.T("控制中心身份已变化；请核对后重新信任"))
		}
	}
	return out, nil
}

// TelegramProbeResult is what the panel shows before anything is stored.
type TelegramProbeResult struct {
	BotUser       string
	SuggestedName string
	WebhookActive bool
	HubFound      bool
	HubName       string
	HubFP         string
	Endpoints     []string
}

// TelegramProbe validates a token and chat with Telegram and looks for an existing hub. It
// stores nothing.
func (a *App) TelegramProbe(ctx context.Context, token string, chat int64) (TelegramProbeResult, error) {
	var res TelegramProbeResult
	if _, e := a.LoadTelegram(); e == nil {
		return res, errTelegramBound
	}
	token = strings.TrimSpace(token)
	if !validTelegramToken(token) {
		return res, errors.New("Bot Token 格式不正确（形如 123456789:AA…，从 @BotFather 获取）")
	}
	if chat <= 0 {
		return res, errNeedPrivate
	}
	cl := a.tgClient(token)
	defer cl.close()
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	me, e := a.tgCheckBot(cctx, cl, chat)
	if e != nil {
		return res, e
	}
	res.BotUser, res.SuggestedName = me.Username, a.defaultServerName()
	if wh, er := cl.getWebhook(cctx); er == nil && wh.URL != "" {
		res.WebhookActive = true
	}
	an, er := a.telegramFetchAnnouncement(cctx, cl, TelegramConfig{Token: token, ChatID: chat})
	if er == nil {
		if len(an.Endpoints) == 0 {
			return res, fmt.Errorf(a.T("控制中心 %s 尚未启用多服务器模式；请先在那台服务器的 Telegram Bot 管理中启用"), an.Name)
		}
		res.HubFound, res.HubName, res.HubFP, res.Endpoints = true, an.Name, fingerprintGroups(an.FP), an.Endpoints
	}
	return res, nil
}

// telegramAuditTail returns the newest n audit lines, oldest first, ready to display.
func (a *App) telegramAuditTail(n int) []string {
	b, e := os.ReadFile(a.telegramAuditPath())
	if e != nil {
		return []string{}
	}
	if len(b) > 256<<10 {
		b = b[len(b)-256<<10:]
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	out := []string{}
	for _, l := range lines {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, strings.ReplaceAll(l, "\t", " · "))
		}
	}
	return out
}
