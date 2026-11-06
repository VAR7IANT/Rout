package rout

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// AI Smart Routing → Telegram Bot management. This file asks questions and prints; every change
// goes through the App methods in telegram_service.go, so the menu, `rout telegram …` and the
// panel behave the same. The Bot Token is read with hidden input and is never printed.

func (u *UI) telegramControl(action string) error {
	if u.telegramSvc != nil {
		return u.telegramSvc(action)
	}
	switch action {
	case "install":
		return u.a.InstallTelegramService()
	case "remove":
		return u.a.RemoveTelegramService()
	}
	return nil
}

func (u *UI) telegramRoleName(role string) string {
	if role == tgRoleHub {
		return u.a.T("控制中心")
	}
	return u.a.T("受控服务器")
}

func (u *UI) telegramStatusLines(s TelegramSummary) {
	w := u.writer()
	row := func(k, v string) { fmt.Fprintf(w, "  %s  %s\n", pad(u.a.T(k), 14), v) }
	if !s.Bound {
		row("绑定状态", u.a.T("未绑定"))
		return
	}
	row("绑定状态", u.paint("32", u.a.T("已绑定")))
	row("角色", u.telegramRoleName(s.Role))
	row("服务器名称", s.Name)
	if s.BotUser != "" {
		row("机器人", "@"+s.BotUser)
	}
	row("Chat ID", s.ChatMasked)
	row("Bot Token", u.a.T("已设置（不显示）"))
	row("本机证书指纹", s.Fingerprint)
	state := u.a.T("未知")
	switch {
	case !s.Service.Managed:
		state = u.a.T("当前环境没有受管理的服务")
	case !s.Service.Installed:
		state = u.paint("33", u.a.T("服务未安装"))
	case !s.Service.Running:
		state = u.paint("31", u.a.T("服务未运行"))
	default:
		state = u.paint("32", u.a.T("服务运行中"))
	}
	row("服务", state)
	if s.Runtime != nil && s.Runtime.State != "" {
		rs := u.a.T(map[string]string{tgStateOK: "正常", tgStateConnecting: "连接中", tgStatePending: "等待批准", tgStateOffline: "离线", tgStateRevoked: "已被撤销",
			tgStateHubChanged: "控制中心身份已变化", tgStateConflict: "冲突", tgStateError: "错误", tgStateStopped: "已停止"}[s.Runtime.State])
		if s.Runtime.Detail != "" {
			rs += " — " + u.a.T(s.Runtime.Detail)
		}
		row("运行状态", rs)
	}
	switch s.Role {
	case tgRoleHub:
		if s.MultiServer {
			listen := fmt.Sprintf("TCP %d", s.Port)
			if s.Runtime != nil && s.Runtime.Listen != "" {
				listen = s.Runtime.Listen
			}
			row("多服务器", u.a.T("已开启")+" · "+listen)
			if len(s.Advertise) > 0 {
				row("公告地址", strings.Join(s.Advertise, ", "))
			}
		} else {
			row("多服务器", u.a.T("未开启（不监听任何端口）"))
		}
		for _, p := range s.Pending {
			fmt.Fprintf(w, "  %s %s  %s\n", u.paint("33", "⏳"), p.Name, u.dim(p.FP))
		}
		for _, ag := range s.Agents {
			dot := u.paint("31", "●")
			if ag.Online {
				dot = u.paint("32", "●")
			}
			fmt.Fprintf(w, "  %s %s  %s\n", dot, ag.Name, u.dim(ag.FP))
		}
	case tgRoleAgent:
		row("控制中心", s.HubName)
		row("控制中心指纹", s.HubFP)
		row("控制中心地址", strings.Join(s.HubEndpoints, ", "))
	}
}

func (u *UI) telegramMenu() error {
	defer u.enter("Telegram Bot 管理")()
	for {
		sum, e := u.a.TelegramSummary()
		if e != nil {
			return e
		}
		u.heading("Telegram Bot 管理")
		u.telegramStatusLines(sum)
		items := []menuItem{item("bind", "绑定 Telegram Bot"), item("status", "查看绑定状态"), item("edit", "修改 Bot Token / Chat ID"), item("test", "测试机器人连接"), item("unbind", "解绑机器人")}
		if sum.Bound {
			items = append(items, item("rename", "重命名本服务器"))
			switch sum.Role {
			case tgRoleHub:
				items = append(items, item("multi", "多服务器模式"), item("servers", "批准或撤销服务器"))
			case tgRoleAgent:
				items = append(items, item("retrust", "重新信任控制中心"))
			}
		}
		v := u.menu("", items, "返回")
		if u.err != nil || v == "" {
			return u.err
		}
		switch v {
		case "bind":
			e = u.telegramBind(sum)
		case "status":
			u.telegramShowStatus(sum)
		case "edit":
			e = u.telegramEdit(sum)
		case "test":
			e = u.telegramTest(sum)
		case "unbind":
			e = u.telegramUnbind(sum)
		case "rename":
			e = u.telegramRename()
		case "multi":
			e = u.telegramMulti(sum)
		case "servers":
			e = u.telegramServers(sum)
		case "retrust":
			e = u.telegramRetrust()
		}
		if e != nil {
			if errors.Is(e, errQuit) || errors.Is(e, io.EOF) {
				return e
			}
			u.fail(u.a.Error(e))
		}
		if u.err != nil {
			return u.err
		}
	}
}

func (u *UI) telegramShowStatus(s TelegramSummary) {
	u.heading("绑定状态")
	u.telegramStatusLines(s)
	if s.Bound && s.Role == tgRoleHub {
		u.say("新服务器请求加入时，会在 Telegram 里显示它的证书指纹；请与那台服务器菜单中的“本机证书指纹”核对后再点“允许”")
	}
}

func parseChatID(s string) (int64, error) {
	n, e := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if e != nil || n <= 0 {
		return 0, errNeedPrivate
	}
	return n, nil
}

func (u *UI) telegramBind(s TelegramSummary) error {
	if s.Bound {
		return errTelegramBound
	}
	u.say("只需要两项信息：")
	u.say("  1. Bot Token：在 Telegram 里找 @BotFather 创建机器人后获得")
	u.say("  2. Chat ID：你自己的数字用户 ID（例如向 @userinfobot 查询）；请先打开你的机器人并发送 /start")
	token := u.secret("Bot Token")
	if u.err != nil {
		return u.err
	}
	chat, e := parseChatID(u.ask("Chat ID", ""))
	if u.err != nil {
		return u.err
	}
	if e != nil {
		return e
	}
	return u.telegramBindWith(TelegramBindRequest{Token: token, ChatID: chat})
}

// telegramBindWith runs the bind (asking the user to confirm a hub's fingerprint when the chat
// already has one) and then starts the service.
func (u *UI) telegramBindWith(req TelegramBindRequest) error {
	u.say("正在向 Telegram 验证…")
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	res, e := u.a.TelegramBind(ctx, req)
	if e != nil {
		return e
	}
	if res.NeedsTrust {
		u.warn("这个机器人已经有控制中心，本机将作为被控制的服务器加入")
		fmt.Fprintf(u.writer(), "  %s  %s\n  %s  %s\n", pad(u.a.T("控制中心"), 12), res.HubName, pad(u.a.T("证书指纹"), 12), fingerprintGroups(res.HubFP))
		u.say("请到控制中心服务器的菜单（Telegram Bot 管理 → 查看绑定状态）核对“本机证书指纹”，两者一致才能继续")
		switch u.choose(u.a.T("1) 一致，信任并加入  2) 旧控制中心已废弃，让本机成为新的控制中心  0) 取消"), []string{"1", "2", "0"}, "0") {
		case "1":
			req.TrustHubFP = fingerprintGroups(res.HubFP)
		case "2":
			if !u.yes("这会替换聊天中原有的控制中心公告；绑定到旧控制中心的服务器需要重新绑定。继续？", false) {
				return u.err
			}
			req.ForceHub = true
		default:
			return u.err
		}
		if res, e = u.a.TelegramBind(ctx, req); e != nil {
			return e
		}
	}
	for _, w := range res.Warnings {
		u.warn(w)
	}
	u.good(fmt.Sprintf(u.a.T("已绑定 @%s，本服务器名称：%s（可稍后重命名）"), res.BotUser, res.Name))
	if e = u.telegramControl("install"); e != nil {
		u.warn(fmt.Sprintf(u.a.T("配置已保存，但服务未能启动：%s"), u.a.Error(e)))
		return nil
	}
	if res.Role == tgRoleHub {
		u.say("本机现在是控制中心。在 Telegram 里发送 /start 即可管理本机。")
		u.say("要用同一个机器人管理更多服务器：选择“多服务器模式”开启（需要放行一个 TCP 端口），然后在其他服务器上用同样的 Token 和 Chat ID 绑定。")
	} else {
		u.say("已向控制中心申请加入：请到 Telegram 点“允许”（核对指纹一致）。批准后即可在机器人里管理本机。")
	}
	return nil
}

func (u *UI) telegramEdit(s TelegramSummary) error {
	if !s.Bound {
		return errTelegramUnbound
	}
	if s.Role != tgRoleHub {
		u.say("Token 与 Chat ID 由控制中心统一管理：请在控制中心修改，本机会自动同步；也可以先解绑再重新绑定")
		return nil
	}
	u.say("留空表示保持不变")
	token := u.secret("新的 Bot Token")
	chatText := u.ask("新的 Chat ID", "")
	if u.err != nil {
		return u.err
	}
	var chat int64
	if strings.TrimSpace(chatText) != "" {
		var e error
		if chat, e = parseChatID(chatText); e != nil {
			return e
		}
	}
	if strings.TrimSpace(token) == "" && chat == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	warns, e := u.a.TelegramSetCredentials(ctx, token, chat)
	if e != nil {
		return e
	}
	for _, w := range warns {
		u.warn(w)
	}
	u.good("已更新；服务会自动切换到新的凭据")
	return nil
}

func (u *UI) telegramTest(s TelegramSummary) error {
	if !s.Bound {
		return errTelegramUnbound
	}
	u.say("正在测试…")
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	checks, e := u.a.TelegramTest(ctx)
	if e != nil {
		return e
	}
	bad := 0
	for _, c := range checks {
		switch c.Level {
		case "ok":
			u.good(c.Text)
		case "warn":
			u.warn(c.Text)
		default:
			bad++
			u.fail(c.Text)
		}
	}
	if bad == 0 {
		u.good("机器人连接正常")
	}
	return nil
}

func (u *UI) telegramUnbind(s TelegramSummary) error {
	if !s.Bound {
		return errTelegramUnbound
	}
	u.say("解绑会停止 Telegram 服务，并删除本机保存的 Token 和私钥；代理节点和 AI 分流配置不受影响。")
	if !u.yes("确认解绑？", false) {
		return u.err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	warns, e := u.a.TelegramUnbind(ctx)
	for _, w := range warns {
		u.warn(w)
	}
	if e != nil {
		return e
	}
	u.good("已解绑，本机不再接受 Telegram 控制")
	return nil
}

func (u *UI) telegramRename() error {
	name := u.ask("服务器名称", "")
	if u.err != nil || strings.TrimSpace(name) == "" {
		return u.err
	}
	if e := u.a.TelegramRename(name); e != nil {
		return e
	}
	u.good("已重命名")
	return nil
}

func (u *UI) telegramMulti(s TelegramSummary) error {
	if s.MultiServer {
		u.say("多服务器模式已开启：本机监听一个 TCP 端口，其他服务器主动连入（它们不需要开放端口）。")
		if !u.yes("关闭多服务器模式？（已授权的服务器将断开，不再监听任何端口）", false) {
			return u.err
		}
		if e := u.a.TelegramSetMultiServer(false, 0, nil); e != nil {
			return e
		}
		u.good("已关闭，本机不再监听端口")
		return nil
	}
	u.say("开启后，本机会监听一个 TCP 端口，供你的其他服务器连入（双向 TLS 1.3 + 证书指纹固定，且必须由你在 Telegram 里批准）。")
	u.say("请在防火墙 / 云安全组放行该 TCP 端口。如果本机在 NAT 后，需要手动填写外部可达的“地址:端口”。")
	port := u.port("监听端口（TCP）", randomFreeTelegramPort())
	adv := strings.TrimSpace(u.ask("对外公告地址（地址:端口，多个用逗号分隔；留空=自动检测公网 IP）", ""))
	if u.err != nil {
		return u.err
	}
	var list []string
	for _, p := range strings.Split(adv, ",") {
		if p = strings.TrimSpace(p); p != "" {
			list = append(list, p)
		}
	}
	if e := u.a.TelegramSetMultiServer(true, port, list); e != nil {
		return e
	}
	u.good(fmt.Sprintf(u.a.T("已开启，监听 TCP %d。请确认防火墙已放行"), port))
	return nil
}

func (u *UI) telegramServers(s TelegramSummary) error {
	if len(s.Pending) == 0 && len(s.Agents) == 0 {
		u.say("还没有其他服务器")
		return nil
	}
	hub := newTelegramHub(u.a)
	var items []menuItem
	for _, p := range s.Pending {
		items = append(items, itemNote("p:"+p.ID, fmt.Sprintf(u.a.T("待批准：%s"), p.Name), p.FP))
	}
	for _, ag := range s.Agents {
		items = append(items, itemNote("a:"+ag.ID, fmt.Sprintf(u.a.T("已授权：%s"), ag.Name), ag.FP))
	}
	v := u.menu("选择服务器", items, "返回")
	if u.err != nil || v == "" {
		return u.err
	}
	id := v[2:]
	if v[0] == 'p' {
		switch u.choose(u.a.T("1) 允许  2) 拒绝  0) 取消"), []string{"1", "2", "0"}, "0") {
		case "1":
			rec, e := hub.approve(id)
			if e != nil {
				return e
			}
			u.good(fmt.Sprintf(u.a.T("已允许 %s 加入"), rec.Name))
		case "2":
			rec, e := hub.reject(id)
			if e != nil {
				return e
			}
			u.good(fmt.Sprintf(u.a.T("已拒绝 %s"), rec.Name))
		}
		return u.err
	}
	if !u.yes("撤销这台服务器的授权？它将不能再被这个机器人控制，需要重新绑定并再次批准。", false) {
		return u.err
	}
	if e := hub.revoke(id); e != nil {
		return e
	}
	u.good("已撤销")
	return nil
}

func (u *UI) telegramRetrust() error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res, e := u.a.TelegramRetrust(ctx, "")
	if e != nil {
		return e
	}
	u.warn("重新信任会放弃之前记录的控制中心，并向新的控制中心重新申请加入")
	fmt.Fprintf(u.writer(), "  %s  %s\n  %s  %s\n", pad(u.a.T("控制中心"), 12), res.HubName, pad(u.a.T("证书指纹"), 12), fingerprintGroups(res.HubFP))
	u.say("请到控制中心服务器的菜单核对“本机证书指纹”，一致才继续")
	if !u.yes("指纹一致，信任该控制中心？", false) {
		return u.err
	}
	if _, e = u.a.TelegramRetrust(ctx, fingerprintGroups(res.HubFP)); e != nil {
		return e
	}
	u.good("已重新申请加入，请到 Telegram 点“允许”")
	return nil
}

// ---- command line --------------------------------------------------------------------------

func (u *UI) telegramCommand(args []string) error {
	a := u.a
	if len(args) < 2 {
		if e := u.initLanguage(false); e != nil {
			return e
		}
		return u.telegramMenu()
	}
	rest := args[2:]
	flag := func(name string) (string, bool) {
		for i := 0; i < len(rest); i++ {
			if rest[i] == name && i+1 < len(rest) {
				return rest[i+1], true
			}
		}
		return "", false
	}
	has := func(name string) bool { return contains(rest, name) }
	switch args[1] {
	case "serve":
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		e := a.RunTelegram(ctx)
		if errors.Is(e, context.Canceled) {
			return nil
		}
		return e
	case "bind":
		token := os.Getenv("ROUT_TELEGRAM_TOKEN")
		if token == "" {
			token = u.secret("Bot Token")
		}
		if u.err != nil {
			return u.err
		}
		cs, ok := flag("--chat-id")
		if !ok {
			cs = u.ask("Chat ID", "")
		}
		chat, e := parseChatID(cs)
		if e != nil {
			return e
		}
		name, _ := flag("--name")
		req := TelegramBindRequest{Token: token, ChatID: chat, Name: name, ForceHub: has("--hub")}
		if fp, ok := flag("--trust-fingerprint"); ok {
			req.TrustHubFP = fp
		}
		return u.telegramBindWith(req)
	case "status":
		s, e := a.TelegramSummary()
		if e != nil {
			return e
		}
		u.telegramStatusLines(s)
		return nil
	case "test":
		s, e := a.TelegramSummary()
		if e != nil {
			return e
		}
		return u.telegramTest(s)
	case "unbind":
		s, e := a.TelegramSummary()
		if e != nil {
			return e
		}
		if !has("--yes") {
			return u.telegramUnbind(s)
		}
		warns, e := a.TelegramUnbind(context.Background())
		for _, w := range warns {
			u.warn(w)
		}
		if e == nil {
			u.good("已解绑，本机不再接受 Telegram 控制")
		}
		return e
	case "multi":
		if len(rest) == 0 || rest[0] != "on" && rest[0] != "off" {
			return errors.New("用法：rout telegram multi on|off [--port 端口] [--advertise 地址:端口]")
		}
		port := 0
		if p, ok := flag("--port"); ok {
			n, e := strconv.Atoi(p)
			if e != nil {
				return errors.New("端口应在 1024–65535 之间")
			}
			port = n
		}
		var adv []string
		if v, ok := flag("--advertise"); ok {
			for _, p := range strings.Split(v, ",") {
				if p = strings.TrimSpace(p); p != "" {
					adv = append(adv, p)
				}
			}
		}
		return a.TelegramSetMultiServer(rest[0] == "on", port, adv)
	case "approve", "reject", "revoke":
		if len(rest) != 1 {
			return fmt.Errorf("用法：rout telegram %s <ID>", args[1])
		}
		hub := newTelegramHub(a)
		switch args[1] {
		case "approve":
			_, e := hub.approve(rest[0])
			return e
		case "reject":
			_, e := hub.reject(rest[0])
			return e
		}
		return hub.revoke(rest[0])
	case "rename":
		if len(rest) != 1 {
			return errors.New("用法：rout telegram rename <名称>")
		}
		return a.TelegramRename(rest[0])
	case "refresh":
		return a.RefreshTelegramService()
	}
	return errors.New("用法：rout telegram [bind|status|test|unbind|multi|approve|reject|revoke|rename|serve|refresh]")
}
