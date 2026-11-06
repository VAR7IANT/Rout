package rout

import (
	"context"
	"errors"
	"fmt"
	"html"
	"os"
	"strings"
	"sync"
	"time"
)

// The bot is the hub's Telegram side. It is the single consumer of getUpdates for this token.
//
// Who may do anything: only the configured Chat ID, in a PRIVATE chat, and only when the sender's
// user ID equals that Chat ID. Everything else is refused and audited. Buttons carry a MAC bound
// to the chat; dangerous actions go through a single-use server-side confirmation; operations on
// one server are serialised so a double tap or a replay cannot run twice at once.

type tgConfirm struct {
	serverID, kind, exitID, exitName string
	enabled                          bool
	chat, msg                        int64
	exp                              time.Time
}

type tgBot struct {
	app *App
	hub *tgHub
	cl  *tgClient

	mu       sync.Mutex
	confirms map[string]*tgConfirm
	seenCB   map[string]time.Time
	unauth   map[int64]time.Time
	taps     []time.Time
	annText  string
	wg       sync.WaitGroup
	rt       *tgRTBox // runtime status shared with the service (may be nil in tests of the bot alone)
}

func newTelegramBot(a *App, h *tgHub, cl *tgClient) *tgBot {
	return &tgBot{app: a, hub: h, cl: cl, confirms: map[string]*tgConfirm{}, seenCB: map[string]time.Time{}, unauth: map[int64]time.Time{}}
}

func (b *tgBot) t(s string) string { return b.app.T(s) }
func esc(s string) string          { return html.EscapeString(s) }

// ---- audit -----------------------------------------------------------------------------------

// audit appends one line: time, who (masked), what. Never a token, key or exit address.
func (b *tgBot) audit(who, action, detail string) { b.app.tgAudit(who, action, detail) }

// tgAudit writes one audit line; it is shared by the bot and the hub.
func (a *App) tgAudit(who, action, detail string) {
	line := fmt.Sprintf("%s\t%s\t%s\t%s\n", a.tgNow().Format(time.RFC3339), who, action, tgScrub(detail, 160))
	p := a.telegramAuditPath()
	if st, e := os.Stat(p); e == nil && st.Size() > 256<<10 {
		os.Rename(p, p+".1")
	}
	f, e := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if e != nil {
		return
	}
	f.WriteString(line)
	f.Close()
}

// ---- authorisation ---------------------------------------------------------------------------

func tgAuthorised(cfg TelegramConfig, chat tgChat, from *tgUser) bool {
	return chat.Type == "private" && chat.ID == cfg.ChatID && from != nil && !from.IsBot && from.ID == cfg.ChatID
}

// tapAllowed is a sliding window on how fast an authorised chat may press buttons.
func (b *tgBot) tapAllowed() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	kept := b.taps[:0]
	for _, t := range b.taps {
		if now.Sub(t) < 10*time.Second {
			kept = append(kept, t)
		}
	}
	b.taps = kept
	if len(b.taps) >= 30 {
		return false
	}
	b.taps = append(b.taps, now)
	return true
}

// ---- main loop -------------------------------------------------------------------------------

// run consumes updates until ctx ends. It returns an error only for conditions that need a
// human (invalid token, another consumer), after recording them in the runtime status.
func (b *tgBot) run(ctx context.Context, rt *tgRTBox) error {
	poll, _, retry := b.app.tgDurations()
	backoff := retry
	for ctx.Err() == nil {
		cfg, e := b.app.LoadTelegram()
		if e != nil {
			return e
		}
		ups, e := b.cl.getUpdates(ctx, cfg.Offset, poll)
		if ctx.Err() != nil {
			break
		}
		if e != nil {
			var ae *tgAPIError
			switch {
			case tgIsAuth(e):
				rt.set(func(r *TelegramRuntime) { r.State, r.Detail = tgStateError, "Bot Token 无效或已被撤销" })
				if !sleepCtx(ctx, 30*retry) {
					return ctx.Err()
				}
			case tgIsConflict(e):
				// If the other consumer is another Rout hub (two servers bound at the same moment,
				// or a hub was forced while the old one still ran), the one whose announcement is
				// not the pinned one gives way for good instead of fighting over the update stream.
				if oh := b.otherHub(ctx, cfg); oh != nil {
					rt.set(func(r *TelegramRuntime) {
						r.State, r.Detail = tgStateConflict, tgScrub(b.app.Error(oh), 200, cfg.Token)
					})
					return oh
				}
				rt.set(func(r *TelegramRuntime) {
					r.State, r.Detail = tgStateConflict, "另一个程序正在接收这个机器人的消息（getUpdates 或 webhook）；Rout 不会覆盖它"
				})
				if !sleepCtx(ctx, 15*retry) {
					return ctx.Err()
				}
			case errors.As(e, &ae) && ae.Code == 429:
				if !sleepCtx(ctx, time.Duration(ae.RetryAfter+1)*time.Second) {
					return ctx.Err()
				}
			default:
				rt.set(func(r *TelegramRuntime) { r.State, r.Detail = tgStateOffline, "无法连接 Telegram" })
				if !sleepCtx(ctx, jitter(backoff)) {
					return ctx.Err()
				}
				if backoff *= 2; backoff > 60*time.Second {
					backoff = 60 * time.Second
				}
			}
			continue
		}
		backoff = retry
		if rt.state() != tgStateOK {
			rt.set(func(r *TelegramRuntime) { r.State, r.Detail = tgStateOK, "" })
		}
		for _, up := range ups {
			// The long poll can last half a minute: handle each update against the configuration
			// as it is now (approvals, renames and the server list change meanwhile).
			if cur, er := b.app.LoadTelegram(); er == nil {
				cfg = cur
			}
			b.handle(ctx, cfg, up)
			// Confirm each update only after it was handled.
			next := up.UpdateID + 1
			b.app.mutateTelegram(func(c *TelegramConfig) error {
				if next > c.Offset {
					c.Offset = next
				}
				return nil
			})
			cfg.Offset = next
		}
	}
	b.wg.Wait()
	return ctx.Err()
}

func (b *tgBot) handle(ctx context.Context, cfg TelegramConfig, up tgUpdate) {
	defer func() {
		if r := recover(); r != nil {
			b.audit("-", "panic", fmt.Sprint(r))
		}
	}()
	switch {
	case up.Message != nil:
		m := up.Message
		if !tgAuthorised(cfg, m.Chat, m.From) {
			b.refuseMessage(ctx, m)
			return
		}
		b.onMessage(ctx, cfg, m)
	case up.Callback != nil:
		cb := up.Callback
		if cb.Message == nil || !tgAuthorised(cfg, cb.Message.Chat, &cb.From) {
			b.audit(maskChatID(cb.From.ID), "callback_denied", "")
			b.cl.answerCallback(ctx, cb.ID, b.t("无权限"), true)
			return
		}
		b.onCallback(ctx, cfg, cb)
	}
}

// refuseMessage answers an unauthorised private chat once a minute and ignores everything else
// (groups, channels, bots), so the bot is not an oracle and cannot be used to flood anyone.
func (b *tgBot) refuseMessage(ctx context.Context, m *tgMessage) {
	who := maskChatID(m.Chat.ID)
	b.audit(who, "message_denied", m.Chat.Type)
	if m.Chat.Type != "private" || (m.From != nil && m.From.IsBot) {
		return
	}
	b.mu.Lock()
	last := b.unauth[m.Chat.ID]
	ok := time.Since(last) > time.Minute
	if ok {
		b.unauth[m.Chat.ID] = time.Now()
		if len(b.unauth) > 256 {
			b.unauth = map[int64]time.Time{m.Chat.ID: time.Now()}
		}
	}
	b.mu.Unlock()
	if ok {
		b.cl.sendMessage(ctx, m.Chat.ID, esc(b.t("无权限：这个机器人只接受它的所有者。")), nil)
	}
}

func (b *tgBot) onMessage(ctx context.Context, cfg TelegramConfig, m *tgMessage) {
	cmd := strings.ToLower(strings.TrimSpace(strings.Fields(m.Text + " x")[0]))
	if i := strings.IndexByte(cmd, '@'); i > 0 {
		cmd = cmd[:i]
	}
	switch cmd {
	case "/start", "/servers", "/menu":
		b.audit(maskChatID(cfg.ChatID), "open_list", "")
		b.showList(ctx, cfg, 0, "")
	default:
		b.cl.sendMessage(ctx, cfg.ChatID, esc(b.t("发送 /start 打开服务器列表。")), nil)
	}
}

// ---- callbacks -------------------------------------------------------------------------------

// cb builds a button with an authenticated callback_data (verb[:a[:b]]~tag, at most 64 bytes).
func (b *tgBot) cb(cfg TelegramConfig, text string, parts ...string) tgButton {
	data := strings.Join(parts, ":")
	return tgButton{Text: text, Data: data + "~" + cfg.keys().cbTag(cfg.ChatID, data)}
}

// ack answers a button press and reports whether the press is still current. A press that Telegram
// no longer accepts an answer for ("query is too old") was made long ago, for instance while this
// hub was down, and arrives only now from Telegram's backlog: running it would carry out an
// instruction the owner gave hours earlier and has probably forgotten, so it is dropped.
func (b *tgBot) ack(ctx context.Context, id string) bool {
	e := b.cl.answerCallback(ctx, id, "", false)
	var ae *tgAPIError
	if errors.As(e, &ae) && ae.Code == 400 && (strings.Contains(ae.Desc, "too old") || strings.Contains(ae.Desc, "query ID is invalid")) {
		b.audit("-", "stale_press_ignored", "")
		return false
	}
	return true
}

func (b *tgBot) onCallback(ctx context.Context, cfg TelegramConfig, cb *tgCallback) {
	b.mu.Lock()
	if _, dup := b.seenCB[cb.ID]; dup {
		b.mu.Unlock()
		b.cl.answerCallback(ctx, cb.ID, "", false)
		return
	}
	now := time.Now()
	for k, t := range b.seenCB {
		if now.Sub(t) > 10*time.Minute {
			delete(b.seenCB, k)
		}
	}
	b.seenCB[cb.ID] = now
	b.mu.Unlock()

	i := strings.LastIndexByte(cb.Data, '~')
	if i < 0 || len(cb.Data) > 64 || !cfg.keys().cbCheck(cfg.ChatID, cb.Data[:i], cb.Data[i+1:]) {
		b.cl.answerCallback(ctx, cb.ID, b.t("按钮已失效，请发送 /start 重新打开"), true)
		return
	}
	if !b.tapAllowed() {
		b.cl.answerCallback(ctx, cb.ID, b.t("操作过于频繁，请稍后再试"), true)
		return
	}
	p := strings.Split(cb.Data[:i], ":")
	msg := cb.Message.MessageID
	arg := func(n int) string {
		if n < len(p) {
			return p[n]
		}
		return ""
	}
	switch p[0] {
	case "L":
		b.cl.answerCallback(ctx, cb.ID, "", false)
		b.showList(ctx, cfg, msg, "")
	case "S", "R":
		b.cl.answerCallback(ctx, cb.ID, "", false)
		b.showServer(ctx, cfg, msg, arg(1), "", p[0] == "R")
	case "T":
		b.toggle(ctx, cfg, cb, msg, arg(1), arg(2) == "1")
	case "E":
		b.cl.answerCallback(ctx, cb.ID, "", false)
		b.showExits(ctx, cfg, msg, arg(1))
	case "X":
		b.askSwitch(ctx, cfg, cb, msg, arg(1), arg(2))
	case "C":
		b.confirm(ctx, cfg, cb, msg, arg(1))
	case "Q":
		b.test(ctx, cfg, cb, msg, arg(1))
	case "V":
		b.askRemove(ctx, cfg, cb, msg, arg(1))
	case "A", "D":
		b.decide(ctx, cfg, cb, msg, p[0] == "A", arg(1))
	default:
		b.cl.answerCallback(ctx, cb.ID, b.t("按钮已失效，请发送 /start 重新打开"), true)
	}
}

// ---- screens ---------------------------------------------------------------------------------

func (b *tgBot) send(ctx context.Context, cfg TelegramConfig, msg int64, text string, rows ...[]tgButton) {
	mk := &tgMarkup{Keyboard: rows}
	if msg != 0 {
		if e := b.cl.editMessage(ctx, cfg.ChatID, msg, text, mk); e == nil {
			return
		}
	}
	b.cl.sendMessage(ctx, cfg.ChatID, text, mk)
}

func statusDot(ok bool) string {
	if ok {
		return "🟢"
	}
	return "🔴"
}

func (b *tgBot) showList(ctx context.Context, cfg TelegramConfig, msg int64, banner string) {
	views := b.hub.servers(cfg)
	var sb strings.Builder
	if banner != "" {
		sb.WriteString(banner + "\n\n")
	}
	sb.WriteString("🤖 <b>Rout Control</b>\n")
	online := 0
	for _, v := range views {
		if v.Online {
			online++
		}
	}
	sb.WriteString(fmt.Sprintf(b.t("已连接服务器：%d"), online) + "\n")
	if len(cfg.Hub.Pending) > 0 {
		sb.WriteString(fmt.Sprintf(b.t("⏳ 待批准的服务器：%d"), len(cfg.Hub.Pending)) + "\n")
	}
	sb.WriteString("\n" + esc(b.t("请选择服务器：")))
	var rows [][]tgButton
	for _, v := range views {
		label := statusDot(v.Online) + " " + v.Name
		rows = append(rows, []tgButton{b.cb(cfg, label, "S", v.ID)})
	}
	rows = append(rows, []tgButton{b.cb(cfg, "🔄 "+b.t("刷新"), "L")})
	b.send(ctx, cfg, msg, sb.String(), rows...)
}

func (b *tgBot) serverText(v tgServerView, banner string) string {
	var sb strings.Builder
	if banner != "" {
		sb.WriteString(banner + "\n\n")
	}
	sb.WriteString("🌐 <b>" + esc(v.Name) + "</b>\n")
	if v.Online {
		sb.WriteString(b.t("服务器状态：") + " 🟢 " + esc(b.t("在线")) + "\n")
	} else {
		sb.WriteString(b.t("服务器状态：") + " 🔴 " + esc(b.t("离线")))
		if !v.LastSeen.IsZero() {
			sb.WriteString(esc(fmt.Sprintf(b.t("（最后在线 %s）"), v.LastSeen.Local().Format("01-02 15:04"))))
		}
		sb.WriteString("\n")
	}
	if st := v.Status; st != nil {
		on := "⚪ " + b.t("已关闭")
		if st.Enabled {
			on = "🟢 " + b.t("已开启")
		}
		sb.WriteString(esc(b.t("AI 分流：")) + " " + esc(on) + "\n")
		exit := b.t("未选择")
		if st.ExitName != "" {
			exit = st.ExitName
			if st.ExitKind != "" {
				exit += " (" + st.ExitKind + ")"
			}
		}
		sb.WriteString(esc(b.t("当前 AI 出口：")) + " " + esc(exit) + "\n")
		sb.WriteString(esc(b.t("已绑定入站：")) + fmt.Sprintf(" %d\n", st.Bound))
		for _, pr := range st.Problems {
			sb.WriteString("⚠️ " + esc(pr) + "\n")
		}
		if !v.Online {
			sb.WriteString("\n" + esc(b.t("（离线，显示的是最后一次上报的状态；离线时不能操作）")))
		}
	} else if !v.Online {
		sb.WriteString("\n" + esc(b.t("尚无状态，等待服务器上线。")))
	}
	return sb.String()
}

func (b *tgBot) serverButtons(cfg TelegramConfig, v tgServerView) [][]tgButton {
	var rows [][]tgButton
	if v.Online && v.Status != nil {
		toggle := b.cb(cfg, "🟢 "+b.t("开启 AI 分流"), "T", v.ID, "1")
		if v.Status.Enabled {
			toggle = b.cb(cfg, "⚪ "+b.t("关闭 AI 分流"), "T", v.ID, "0")
		}
		rows = append(rows,
			[]tgButton{toggle},
			[]tgButton{b.cb(cfg, "🔀 "+b.t("切换 AI 出站"), "E", v.ID)},
			[]tgButton{b.cb(cfg, "🧪 "+b.t("测试 AI 出口"), "Q", v.ID)},
		)
	}
	if !v.Local {
		rows = append(rows, []tgButton{b.cb(cfg, "🗑 "+b.t("移除此服务器"), "V", v.ID)})
	}
	rows = append(rows,
		[]tgButton{b.cb(cfg, "📊 "+b.t("查看状态"), "R", v.ID)},
		[]tgButton{b.cb(cfg, "⬅️ "+b.t("返回服务器列表"), "L")},
	)
	return rows
}

// showServer renders one server. With refresh it asks the server for its real state first.
func (b *tgBot) showServer(ctx context.Context, cfg TelegramConfig, msg int64, id, banner string, refresh bool) {
	v, ok := b.hub.findServer(cfg, id)
	if !ok {
		b.showList(ctx, cfg, msg, esc(b.t("该服务器已不在列表中")))
		return
	}
	if v.Online && !v.Local && !b.hub.isBusy(id) {
		if res, e := b.hub.dispatch(ctx, cfg, id, tgCommand{ID: randomID(8), Kind: tgCmdStatus}, 8*time.Second); e == nil && res.Status != nil {
			v.Status = res.Status
			v.Status.Name = v.Name
		} else if errors.Is(e, errTgOffline) {
			v.Online = false
		}
	}
	b.send(ctx, cfg, msg, b.serverText(v, banner), b.serverButtons(cfg, v)...)
}

func (b *tgBot) showExits(ctx context.Context, cfg TelegramConfig, msg int64, id string) {
	v, ok := b.hub.findServer(cfg, id)
	if !ok || !v.Online {
		b.showServer(ctx, cfg, msg, id, "", false)
		return
	}
	res, e := b.hub.dispatch(ctx, cfg, id, tgCommand{ID: randomID(8), Kind: tgCmdStatus}, 8*time.Second)
	if e != nil || res.Status == nil {
		b.showServer(ctx, cfg, msg, id, "❌ "+esc(b.errText(e)), false)
		return
	}
	st := res.Status
	var sb strings.Builder
	sb.WriteString("🔀 <b>" + esc(v.Name) + "</b>\n" + esc(b.t("选择新的 AI 出口：")) + "\n")
	var rows [][]tgButton
	for _, ex := range st.Exits {
		mark := "⚪"
		switch {
		case ex.ID == st.ExitID:
			mark = "✅"
		case !ex.Usable:
			mark = "⛔"
		}
		if len(ex.ID) > 24 {
			continue // cannot be encoded in a button; still manageable on the server itself
		}
		rows = append(rows, []tgButton{b.cb(cfg, mark+" "+ex.Name+" · "+ex.Kind, "X", id, ex.ID)})
	}
	if len(rows) == 0 {
		sb.WriteString("\n" + esc(b.t("这台服务器还没有可用的出口。请先在服务器上添加出口。")))
	}
	rows = append(rows, []tgButton{b.cb(cfg, "⬅️ "+b.t("返回"), "S", id)})
	b.send(ctx, cfg, msg, sb.String(), rows...)
}

func (b *tgBot) errText(e error) string {
	switch {
	case e == nil:
		return b.t("未知错误")
	case errors.Is(e, errTgOffline):
		return b.t("服务器离线")
	case errors.Is(e, errTgNoAnswer):
		return b.t("服务器没有响应，命令可能尚未执行；请稍后刷新状态")
	}
	return b.t(tgScrub(e.Error(), 200))
}

// ---- actions ---------------------------------------------------------------------------------

func (b *tgBot) newConfirm(c *tgConfirm) string {
	id := randomID(6)
	c.exp = time.Now().Add(5 * time.Minute)
	b.mu.Lock()
	defer b.mu.Unlock()
	for k, v := range b.confirms {
		if time.Now().After(v.exp) {
			delete(b.confirms, k)
		}
	}
	if len(b.confirms) > 64 {
		b.confirms = map[string]*tgConfirm{}
	}
	b.confirms[id] = c
	return id
}

func (b *tgBot) askSwitch(ctx context.Context, cfg TelegramConfig, cb *tgCallback, msg int64, id, exitID string) {
	v, ok := b.hub.findServer(cfg, id)
	if !ok || !v.Online {
		b.cl.answerCallback(ctx, cb.ID, b.t("服务器离线"), true)
		return
	}
	res, e := b.hub.dispatch(ctx, cfg, id, tgCommand{ID: randomID(8), Kind: tgCmdStatus}, 8*time.Second)
	if e != nil || res.Status == nil {
		b.cl.answerCallback(ctx, cb.ID, b.errText(e), true)
		return
	}
	var target *tgExitInfo
	for i := range res.Status.Exits {
		if res.Status.Exits[i].ID == exitID {
			target = &res.Status.Exits[i]
		}
	}
	switch {
	case target == nil:
		b.cl.answerCallback(ctx, cb.ID, b.t("该出口已不存在，请刷新"), true)
		b.showExits(ctx, cfg, msg, id)
		return
	case !target.Usable:
		b.cl.answerCallback(ctx, cb.ID, fmt.Sprintf(b.t("该出口不能用于 AI 分流：%s"), target.Problem), true)
		return
	case target.ID == res.Status.ExitID:
		b.cl.answerCallback(ctx, cb.ID, b.t("当前已使用该出口"), false)
		return
	}
	b.cl.answerCallback(ctx, cb.ID, "", false)
	cid := b.newConfirm(&tgConfirm{serverID: id, kind: tgCmdSetExit, exitID: exitID, exitName: target.Name, chat: cfg.ChatID, msg: msg})
	cur := res.Status.ExitName
	if cur == "" {
		cur = b.t("未选择")
	}
	text := "🔀 <b>" + esc(v.Name) + "</b>\n" + esc(b.t("确认切换 AI 出口？")) + "\n\n" +
		esc(b.t("当前：")) + " " + esc(cur) + "\n" + esc(b.t("新的：")) + " <b>" + esc(target.Name) + "</b>\n\n" +
		esc(fmt.Sprintf(b.t("只影响已绑定的 %d 个入站，其他节点不受影响。"), res.Status.Bound))
	b.send(ctx, cfg, msg, text,
		[]tgButton{b.cb(cfg, "✅ "+b.t("确认切换"), "C", cid)},
		[]tgButton{b.cb(cfg, "❌ "+b.t("取消"), "E", id)},
	)
}

// take removes and returns a confirmation: each one works once, for the chat and message it was
// issued for, within five minutes.
func (b *tgBot) take(cid string, chat, msg int64) (*tgConfirm, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	c, ok := b.confirms[cid]
	delete(b.confirms, cid)
	if !ok || time.Now().After(c.exp) || c.chat != chat || c.msg != msg {
		return nil, false
	}
	return c, true
}

// askRemove asks before revoking a server's authorization.
func (b *tgBot) askRemove(ctx context.Context, cfg TelegramConfig, cb *tgCallback, msg int64, id string) {
	v, ok := b.hub.findServer(cfg, id)
	if !ok || v.Local {
		b.cl.answerCallback(ctx, cb.ID, b.t("该服务器已不在列表中"), true)
		return
	}
	b.cl.answerCallback(ctx, cb.ID, "", false)
	cid := b.newConfirm(&tgConfirm{serverID: id, kind: "revoke", exitName: v.Name, chat: cfg.ChatID, msg: msg})
	b.send(ctx, cfg, msg, "🗑 <b>"+esc(v.Name)+"</b>\n"+esc(b.t("确认撤销这台服务器的授权？撤销后它不能再被这个机器人控制，需要在该服务器上重新绑定并再次批准。")),
		[]tgButton{b.cb(cfg, "✅ "+b.t("确认移除"), "C", cid)},
		[]tgButton{b.cb(cfg, "❌ "+b.t("取消"), "S", id)},
	)
}

func (b *tgBot) confirm(ctx context.Context, cfg TelegramConfig, cb *tgCallback, msg int64, cid string) {
	c, ok := b.take(cid, cfg.ChatID, msg)
	if !ok {
		b.cl.answerCallback(ctx, cb.ID, b.t("这个确认已失效或已使用，请重新操作"), true)
		return
	}
	if !b.ack(ctx, cb.ID) {
		return
	}
	if c.kind == "revoke" {
		b.audit(maskChatID(cfg.ChatID), "revoke_server", c.exitName)
		if e := b.hub.revoke(c.serverID); e != nil {
			b.showList(ctx, cfg, msg, "❌ "+esc(b.t(e.Error())))
			return
		}
		b.showList(ctx, cfg, msg, "✅ "+esc(fmt.Sprintf(b.t("已移除 %s"), c.exitName)))
		return
	}
	b.runOp(ctx, cfg, msg, c.serverID, tgCommand{Kind: tgCmdSetExit, ExitID: c.exitID}, 60*time.Second,
		fmt.Sprintf(b.t("正在切换 AI 出口为 %s…"), c.exitName),
		func(before, after *tgServerStatus, res tgResult, e error) string {
			if e == nil && res.OK {
				if res.Note != "" {
					return "ℹ️ " + esc(b.t(res.Note))
				}
				return "✅ " + esc(fmt.Sprintf(b.t("已切换 AI 出口为 %s"), c.exitName))
			}
			msgText := b.t(res.Error)
			if e != nil {
				msgText = b.errText(e)
			}
			keep := ""
			if after != nil && after.ExitName != "" {
				keep = " " + fmt.Sprintf(b.t("当前出口仍是 %s。"), after.ExitName)
			}
			return "❌ " + esc(fmt.Sprintf(b.t("切换失败：%s"), msgText)) + esc(keep)
		}, "switch_exit", c.exitName)
}

func (b *tgBot) toggle(ctx context.Context, cfg TelegramConfig, cb *tgCallback, msg int64, id string, on bool) {
	v, ok := b.hub.findServer(cfg, id)
	if !ok || !v.Online {
		b.cl.answerCallback(ctx, cb.ID, b.t("服务器离线"), true)
		return
	}
	if !b.ack(ctx, cb.ID) {
		return
	}
	label := b.t("正在关闭 AI 分流…")
	if on {
		label = b.t("正在开启 AI 分流…")
	}
	b.runOp(ctx, cfg, msg, id, tgCommand{Kind: tgCmdSetEnabled, Enabled: on}, 60*time.Second, label,
		func(before, after *tgServerStatus, res tgResult, e error) string {
			if e == nil && res.OK {
				if res.Note != "" {
					return "ℹ️ " + esc(b.t(res.Note))
				}
				if on {
					return "✅ " + esc(b.t("已开启 AI 分流"))
				}
				return "✅ " + esc(b.t("已关闭 AI 分流"))
			}
			msgText := b.t(res.Error)
			if e != nil {
				msgText = b.errText(e)
			}
			return "❌ " + esc(fmt.Sprintf(b.t("操作失败：%s"), msgText))
		}, map[bool]string{true: "enable_ai", false: "disable_ai"}[on], "")
}

func (b *tgBot) test(ctx context.Context, cfg TelegramConfig, cb *tgCallback, msg int64, id string) {
	v, ok := b.hub.findServer(cfg, id)
	if !ok || !v.Online {
		b.cl.answerCallback(ctx, cb.ID, b.t("服务器离线"), true)
		return
	}
	b.cl.answerCallback(ctx, cb.ID, "", false)
	b.runOp(ctx, cfg, msg, id, tgCommand{Kind: tgCmdTest}, 90*time.Second, b.t("正在测试 AI 出口…"),
		func(before, after *tgServerStatus, res tgResult, e error) string {
			if e != nil {
				return "❌ " + esc(fmt.Sprintf(b.t("测试失败：%s"), b.errText(e)))
			}
			var sb strings.Builder
			if res.OK {
				sb.WriteString("✅ <b>" + esc(b.t("AI 出口测试通过")) + "</b>")
			} else {
				sb.WriteString("❌ <b>" + esc(b.t("AI 出口测试未通过")) + "</b>")
				if res.Error != "" && len(res.Steps) == 0 {
					sb.WriteString("\n" + esc(b.t(res.Error)))
				}
			}
			for _, s := range res.Steps {
				icon := map[string]string{"ok": "✅", "warn": "⚠️", "fail": "❌"}[s.Level]
				if icon == "" {
					icon = "•"
				}
				sb.WriteString("\n" + icon + " " + esc(b.t(s.Text)))
			}
			return sb.String()
		}, "test_exit", "")
}

// runOp executes one command on one server in the background, editing the message first to
// "working" and afterwards to the real resulting state. Only one operation per server at a time.
func (b *tgBot) runOp(ctx context.Context, cfg TelegramConfig, msg int64, id string, c tgCommand, wait time.Duration, working string,
	render func(before, after *tgServerStatus, res tgResult, e error) string, action, detail string) {
	if !b.hub.tryLock(id) {
		b.send(ctx, cfg, msg, "⏳ "+esc(errTgBusy.Error()), []tgButton{b.cb(cfg, "⬅️ "+b.t("返回"), "S", id)})
		return
	}
	v, _ := b.hub.findServer(cfg, id)
	b.audit(maskChatID(cfg.ChatID), action, v.Name+" "+detail)
	b.send(ctx, cfg, msg, "⏳ "+esc(working))
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		defer b.hub.unlock(id)
		c.ID = randomID(8)
		var before *tgServerStatus
		if v.Status != nil {
			s := *v.Status
			before = &s
		}
		res, e := b.hub.dispatch(ctx, cfg, id, c, wait)
		banner := render(before, res.Status, res, e)
		result := "ok"
		if e != nil || !res.OK {
			result = "failed"
		}
		b.audit(maskChatID(cfg.ChatID), action+"_result", v.Name+" "+result)
		// Show the state as the server reports it now, not what we hoped for.
		fresh, _ := b.hub.findServer(cfg, id)
		if res.Status != nil {
			st := *res.Status
			st.Name = fresh.Name
			fresh.Status = &st
		}
		if e != nil && errors.Is(e, errTgOffline) {
			fresh.Online = false
		}
		cctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		b.send(cctx, cfg, msg, b.serverText(fresh, banner), b.serverButtons(cfg, fresh)...)
	}()
}

// ---- enrollment ------------------------------------------------------------------------------

// notifyPending asks the owner, in the private chat, whether a server may join.
func (b *tgBot) notifyPending(ctx context.Context, cfg TelegramConfig, rec TelegramPendingRecord) {
	text := "🆕 <b>" + esc(b.t("新服务器请求加入")) + "</b>\n\n" +
		esc(b.t("名称：")) + " <b>" + esc(rec.Name) + "</b>\n" +
		esc(b.t("证书指纹：")) + " <code>" + esc(fingerprintGroups(rec.FP)) + "</code>\n\n" +
		esc(b.t("请到该服务器的 Rout 菜单（Telegram Bot 管理 → 查看绑定状态）核对指纹，一致再允许。不认识的请求请拒绝。"))
	if _, e := b.cl.sendMessage(ctx, cfg.ChatID, text, &tgMarkup{Keyboard: [][]tgButton{{
		b.cb(cfg, "✅ "+b.t("允许"), "A", rec.ID),
		b.cb(cfg, "🚫 "+b.t("拒绝"), "D", rec.ID),
	}}}); e != nil {
		// The request is saved either way: it is still listed in the menu and the panel.
		b.audit(maskChatID(cfg.ChatID), "join_notice_failed", rec.Name+" "+tgScrub(tgFriendly(e), 120))
	}
	b.audit(maskChatID(cfg.ChatID), "join_request", rec.Name+" "+tgShort(rec.FP))
}

func (b *tgBot) decide(ctx context.Context, cfg TelegramConfig, cb *tgCallback, msg int64, allow bool, reqID string) {
	if !b.ack(ctx, cb.ID) {
		return
	}
	var name string
	if allow {
		rec, e := b.hub.approve(reqID)
		if e != nil {
			b.cl.editMessage(ctx, cfg.ChatID, msg, esc(b.t("该请求已处理或已过期")), nil)
			return
		}
		name = rec.Name
		b.audit(maskChatID(cfg.ChatID), "join_allowed", name+" "+tgShort(rec.FP))
		b.cl.editMessage(ctx, cfg.ChatID, msg, "✅ "+esc(fmt.Sprintf(b.t("已允许 %s 加入"), name)), nil)
		return
	}
	rec, e := b.hub.reject(reqID)
	if e != nil {
		b.cl.editMessage(ctx, cfg.ChatID, msg, esc(b.t("该请求已处理或已过期")), nil)
		return
	}
	b.audit(maskChatID(cfg.ChatID), "join_rejected", rec.Name+" "+tgShort(rec.FP))
	b.cl.editMessage(ctx, cfg.ChatID, msg, "🚫 "+esc(fmt.Sprintf(b.t("已拒绝 %s"), rec.Name)), nil)
}

// ---- announcement ----------------------------------------------------------------------------

// otherHub reports another Rout hub if the chat's pinned announcement belongs to one.
func (b *tgBot) otherHub(ctx context.Context, cfg TelegramConfig) error {
	ch, e := b.cl.getChat(ctx, cfg.ChatID)
	if e != nil || ch.PinnedMessage == nil {
		return nil
	}
	if an, er := cfg.keys().openAnnouncement(ch.PinnedMessage.Text); er == nil && an.HubID != cfg.ServerID {
		return &tgOtherHubError{name: an.Name}
	}
	return nil
}

// announce publishes (or refreshes) the pinned, encrypted hub address. It refuses to overwrite
// an announcement that belongs to another hub.
func (b *tgBot) announce(ctx context.Context, cfg TelegramConfig) error {
	keys := cfg.keys()
	want := b.hub.announcement(cfg)
	if b.rt != nil {
		b.rt.set(func(r *TelegramRuntime) { r.Endpoints = want.Endpoints })
	}
	ch, e := b.cl.getChat(ctx, cfg.ChatID)
	if e != nil {
		return e
	}
	if ch.PinnedMessage != nil {
		if cur, er := keys.openAnnouncement(ch.PinnedMessage.Text); er == nil {
			if cur.HubID != cfg.ServerID {
				return &tgOtherHubError{name: cur.Name}
			}
			if cur.FP == want.FP && sameStrings(cur.Endpoints, want.Endpoints) && cur.Name == want.Name {
				if cfg.Hub.AnnounceMsgID != ch.PinnedMessage.MessageID {
					b.app.mutateTelegram(func(c *TelegramConfig) error { c.Hub.AnnounceMsgID = ch.PinnedMessage.MessageID; return nil })
				}
				return nil
			}
			sealed, er := keys.sealAnnouncement(want)
			if er != nil {
				return er
			}
			if er = b.cl.editMessage(ctx, cfg.ChatID, ch.PinnedMessage.MessageID, esc(announcementText(sealed)), nil); er == nil {
				return nil
			}
		}
	}
	return b.publishNew(ctx, cfg, want)
}

func (b *tgBot) publishNew(ctx context.Context, cfg TelegramConfig, an tgAnnouncement) error {
	sealed, e := cfg.keys().sealAnnouncement(an)
	if e != nil {
		return e
	}
	m, e := b.cl.sendMessage(ctx, cfg.ChatID, esc(announcementText(sealed)), nil)
	if e != nil {
		return e
	}
	if e = b.cl.pin(ctx, cfg.ChatID, m.MessageID); e != nil {
		return fmt.Errorf("无法置顶控制中心地址：%s", tgFriendly(e))
	}
	if oh := b.otherHub(ctx, cfg); oh != nil {
		// Someone else announced at the same moment and their pin is the newer: withdraw ours.
		b.cl.unpin(ctx, cfg.ChatID, m.MessageID)
		b.cl.deleteMessage(ctx, cfg.ChatID, m.MessageID)
		return oh
	}
	return b.app.mutateTelegram(func(c *TelegramConfig) error { c.Hub.AnnounceMsgID = m.MessageID; return nil })
}

// tgOtherHubError means the chat already announces a different hub; Rout never overwrites it.
type tgOtherHubError struct{ name string }

func (e *tgOtherHubError) Error() string {
	return fmt.Sprintf("聊天中已有另一个控制中心（%s）", e.name)
}
