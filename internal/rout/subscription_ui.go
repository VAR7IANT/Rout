package rout

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Subscription menus. This file only asks questions and prints; every change goes through
// the App methods in subscription.go and subscription_service.go.

// parseSelection turns "2 1,3" into zero-based indexes in the typed order. Duplicates,
// out-of-range values and non-numbers are rejected; there is no "all" shortcut.
func parseSelection(raw string, max int) ([]int, error) {
	var out []int
	seen := map[int]bool{}
	for _, f := range strings.Fields(strings.ReplaceAll(normalizeInput(raw), ",", " ")) {
		n, e := strconv.Atoi(f)
		if e != nil || n < 1 || n > max || seen[n] {
			return nil, errors.New("编号无效")
		}
		seen[n] = true
		out = append(out, n-1)
	}
	if len(out) == 0 {
		return nil, errors.New("请至少选择一个节点")
	}
	return out, nil
}

func (u *UI) nodeLine(n int, p Profile) string {
	return fmt.Sprintf("  %s  %s", u.paint(accent, fmt.Sprintf("%2d", n)), u.nodeText(p))
}

// nodeText describes a node without credentials or links.
func (u *UI) nodeText(p Profile) string {
	line := fmt.Sprintf("%s  [%s]  %s  %s", pad(p.Name, 22), p.ID, pad(ProtocolLabel(p.Protocol), 12), net.JoinHostPort(p.PublicHost, itoa(p.PublicPort)))
	if p.Kind == "relay" {
		line += "  " + u.a.T("[转发]")
	}
	if !p.Enabled {
		line += "  " + u.paint("33", u.a.T("[已停用]"))
	}
	return line
}

// pickSubscriptionNodes shows a numbered list and returns the chosen node IDs in typed
// order, or nil when cancelled. Links and credentials are never shown.
func (u *UI) pickSubscriptionNodes(list []Profile, prompt string) []string {
	if len(list) == 0 {
		u.say("没有可选择的节点")
		return nil
	}
	for i, p := range list {
		fmt.Fprintln(u.writer(), u.nodeLine(i+1, p))
	}
	u.hint("输入编号，多个用空格或逗号分隔，顺序即订阅顺序 · 直接回车取消")
	for u.err == nil {
		raw := u.ask(prompt, "")
		if u.err != nil || normalizeInput(raw) == "" || menuShortcut(raw) == "back" || raw == "0" {
			return nil
		}
		if menuShortcut(raw) == "quit" {
			u.err = errQuit
			return nil
		}
		idx, e := parseSelection(raw, len(list))
		if e != nil {
			u.say(e.Error())
			continue
		}
		ids := make([]string, len(idx))
		for i, n := range idx {
			ids[i] = list[n].ID
		}
		return ids
	}
	return nil
}

func nodesByID(s State, ids []string) []Profile {
	var out []Profile
	for _, id := range ids {
		if p, e := Find(s, id); e == nil {
			out = append(out, p)
		}
	}
	return out
}

func (u *UI) candidates(s State) []Profile {
	list, warnings := s.SubscriptionCandidates()
	for _, w := range warnings {
		u.warn(w)
	}
	return list
}

func (u *UI) subStatus(s State, sub Subscription) string {
	exp := s.exportSubscription(sub)
	state := u.paint("32", u.a.T("已启用"))
	if !sub.Enabled {
		state = u.paint("33", u.a.T("已停用"))
	}
	return fmt.Sprintf("%s · "+u.a.T("%d/%d 个节点可用"), state, len(exp.URIs), len(sub.NodeIDs))
}

// planLines describes the plan and its current usage; nothing for a subscription without one.
func (u *UI) planLines(sub Subscription) []string {
	if sub.Plan == nil {
		return nil
	}
	now := time.Now()
	v, ok := u.a.SubscriptionUsage(sub, now)
	if !ok {
		return nil
	}
	var out []string
	row := func(label, value string) { out = append(out, fmt.Sprintf("  %s  %s", pad(u.a.T(label), 10), value)) }
	if v.Plan.LimitBytes > 0 {
		row("共享流量", fmt.Sprintf(u.a.T("剩余 %s / 共 %s（已用 %s）"), FormatTraffic(v.remaining()), FormatTraffic(v.Plan.LimitBytes), FormatTraffic(v.Used)))
		row("下次重置", u.dateAndDays(v.Next))
		if v.Incomplete {
			out = append(out, "  "+u.paint("33", u.a.T("! 本周期曾有计数中断，已用量为下限")))
		}
	}
	if t, ok := v.Plan.nextExpiry(now); ok {
		row("套餐到期", t.Format(planDateLayout))
	}
	return out
}

// subscriptionList prints every subscription with its nodes and diagnostics.
func (u *UI) subscriptionList(s State) {
	if len(s.Subscriptions) == 0 {
		u.say("暂无订阅")
		return
	}
	cfg, _ := u.a.subscriptionSettings()
	tokens, tokenError := u.a.loadSubscriptionTokens()
	if tokenError != nil {
		u.warn(u.a.Error(tokenError))
	}
	for i, sub := range s.Subscriptions {
		fmt.Fprintf(u.writer(), "\n%s  %s  [%s]\n      %s\n", u.paint(accent, fmt.Sprintf("%2d", i+1)), u.bold(sub.Name), sub.ID, u.subStatus(s, sub))
		for _, line := range u.planLines(sub) {
			fmt.Fprintln(u.writer(), "    "+line)
		}
		for _, id := range sub.NodeIDs {
			if p, e := Find(s, id); e == nil {
				fmt.Fprintln(u.writer(), "      "+u.nodeText(p))
			}
		}
		if token := tokens[sub.TokenHash]; token != "" {
			u.subscriptionURLs(cfg, token, sub.Name)
		} else {
			if tokenError == nil {
				u.hint("此订阅仅保存了令牌校验值，无法还原原令牌；请使用之前保存的 URL，或在“更换访问令牌”中确认生成新链接（旧链接会失效）")
			}
			u.subscriptionURLs(cfg, "{access_token}", sub.Name)
		}
		for _, w := range s.exportSubscription(sub).Warnings {
			u.warn(w)
		}
		_, warnings := s.exportMihomo(sub)
		for _, warning := range warnings {
			u.warn(u.a.T("Mihomo：") + u.a.T(warning))
		}
	}
}

func (u *UI) pickSubscription(s State, prompt string) (Subscription, bool) {
	if len(s.Subscriptions) == 0 {
		u.say("暂无订阅")
		return Subscription{}, false
	}
	for i, sub := range s.Subscriptions {
		fmt.Fprintf(u.writer(), "  %s  %s  [%s]  %s\n", u.paint(accent, fmt.Sprintf("%2d", i+1)), pad(sub.Name, 22), sub.ID, u.subStatus(s, sub))
	}
	n := u.number(prompt, len(s.Subscriptions))
	if n <= 0 {
		return Subscription{}, false
	}
	return s.Subscriptions[n-1], true
}

// Tokens are shown only in explicit subscription creation/rotation/list views.
func (u *UI) showToken(token, heading, name string) {
	cfg, _ := u.a.subscriptionSettings()
	u.good(heading)
	u.hint("令牌已私密保存；以后可在“查看订阅”中查看完整链接，请勿公开分享")
	fmt.Fprintf(u.writer(), "  %s  %s\n", pad(u.a.T("访问令牌"), 10), token)
	u.heading("订阅链接")
	u.subscriptionURLs(cfg, token, name)
	if cfg.PublicURL == "" {
		u.warn("尚未配置 HTTPS 公网地址：订阅服务只监听本机，请先用反向代理提供 HTTPS，再在“订阅服务设置”中填写公网地址")
	}
	if !cfg.Enabled {
		u.warn("订阅服务尚未启用：请在“订阅服务设置”中启用")
	}
}

// shadowrocketImportURL is Shadowrocket's one-tap import link. Only this form carries the
// title (remark), so the subscription is listed under its Rout name instead of its host.
func shadowrocketImportURL(subscriptionURL, name string) string {
	remark := strings.ReplaceAll(url.QueryEscape(name), "+", "%20")
	return "shadowrocket://add/sub://" + base64.StdEncoding.EncodeToString([]byte(subscriptionURL)) + "?remark=" + remark
}

func (u *UI) subscriptionURLs(cfg SubscriptionSettings, token, name string) {
	base := cfg.SubscriptionURL(token)
	if base == "" {
		base = "https://YOUR-DOMAIN/s/" + token
	}
	fmt.Fprintf(u.writer(), "      Base64:\n%s\n      Mihomo:\n%s?format=mihomo\n      Clash:\n%s?format=clash\n", base, base, base)
	if token != "{access_token}" {
		fmt.Fprintf(u.writer(), "      Shadowrocket:\n%s\n", shadowrocketImportURL(base, name))
		u.hint("在 iPhone 上打开 Shadowrocket 链接即可导入，标题为订阅名称；直接粘贴 Base64 链接时需自行填写备注")
	}
}

func (u *UI) subscriptionCreate() error {
	s, e := u.a.Load()
	if e != nil {
		return e
	}
	list := u.candidates(s)
	if len(list) == 0 {
		return errors.New("没有可订阅的节点，请先创建节点")
	}
	name := strings.TrimSpace(u.ask("订阅名称", ""))
	if u.err != nil || name == "" {
		return u.err
	}
	if e = validSubscriptionName(name); e != nil {
		return e
	}
	if nameTaken(s, name, "") {
		return errors.New("订阅名称已存在")
	}
	ids := u.pickSubscriptionNodes(list, "选择节点编号")
	if len(ids) == 0 {
		return u.err
	}
	u.heading("确认订阅")
	fmt.Fprintf(u.writer(), "  %s  %s\n", pad(u.a.T("名称"), 6), name)
	for i, p := range nodesByID(s, ids) {
		fmt.Fprintln(u.writer(), u.nodeLine(i+1, p))
		if !p.Enabled {
			u.warn("该节点已停用，启用前不会出现在订阅中")
		}
	}
	if !u.yes("创建此订阅", true) {
		return u.err
	}
	sub, token, e := u.a.CreateSubscription(name, ids)
	if e != nil {
		return e
	}
	fmt.Fprintf(u.writer(), "  %s  %s [%s]\n", pad(u.a.T("订阅"), 10), sub.Name, sub.ID)
	u.showToken(token, "订阅已创建", sub.Name)
	return nil
}

func (u *UI) subscriptionEdit() error {
	u.showExistingSubscriptionURL()
	for {
		s, e := u.a.Load()
		if e != nil {
			return e
		}
		sub, ok := u.pickSubscription(s, "选择订阅编号（0 返回）")
		if !ok {
			return u.err
		}
		if e = u.subscriptionEditOne(sub.ID); e != nil || u.err != nil {
			return errors.Join(e, u.err)
		}
	}
}

func (u *UI) subscriptionEditOne(id string) error {
	for {
		s, e := u.a.Load()
		if e != nil {
			return e
		}
		i, e := findSubscription(s, id)
		if e != nil {
			return e
		}
		sub := s.Subscriptions[i]
		u.heading(sub.Name)
		fmt.Fprintf(u.writer(), "  %s\n", u.subStatus(s, sub))
		toggle := item("toggle", "停用订阅")
		if !sub.Enabled {
			toggle = item("toggle", "启用订阅")
		}
		for _, line := range u.planLines(sub) {
			fmt.Fprintln(u.writer(), line)
		}
		v := u.menu("", []menuItem{item("rename", "重命名"), item("add", "添加节点"), item("remove", "移除节点"), item("reorder", "调整顺序"), toggle, item("plan", "流量与到期设置")}, "返回")
		if v == "" || u.err != nil {
			return u.err
		}
		var err error
		saved := false
		switch v {
		case "rename":
			name := strings.TrimSpace(u.ask("新名称", sub.Name))
			if u.err == nil {
				err, saved = u.a.RenameSubscription(id, name), true
			}
		case "add":
			var rest []Profile
			for _, p := range u.candidates(s) {
				if !contains(sub.NodeIDs, p.ID) {
					rest = append(rest, p)
				}
			}
			if add := u.pickSubscriptionNodes(rest, "选择要添加的节点编号"); len(add) > 0 {
				err, saved = u.a.SetSubscriptionNodes(id, append(append([]string(nil), sub.NodeIDs...), add...)), true
			}
		case "remove":
			if len(sub.NodeIDs) <= 1 {
				u.warn("订阅至少需要保留一个节点；如需停止请停用或删除订阅")
				break
			}
			cur := nodesByID(s, sub.NodeIDs)
			if drop := u.pickSubscriptionNodes(cur, "选择要移除的节点编号"); len(drop) > 0 {
				var keep []string
				for _, v := range sub.NodeIDs {
					if !contains(drop, v) {
						keep = append(keep, v)
					}
				}
				err, saved = u.a.SetSubscriptionNodes(id, keep), true
			}
		case "reorder":
			cur := nodesByID(s, sub.NodeIDs)
			u.say("按新的顺序输入全部编号")
			if order := u.pickSubscriptionNodes(cur, "新顺序"); len(order) > 0 {
				if len(order) != len(cur) {
					u.warn("必须包含全部节点；要删除节点请使用“移除节点”")
					break
				}
				err, saved = u.a.SetSubscriptionNodes(id, order), true
			}
		case "plan":
			err = u.subscriptionPlanMenu(id)
		case "toggle":
			err, saved = u.a.SetSubscriptionEnabled(id, !sub.Enabled), true
		}
		if err != nil {
			u.fail(u.a.subscriptionText(u.a.Error(err)))
		} else if saved && u.err == nil {
			u.good("已保存；令牌保持不变")
		}
		if u.err != nil {
			return u.err
		}
	}
}

// subscriptionPlanMenu edits the shared allowance, reset day and expiry of one subscription.
func (u *UI) subscriptionPlanMenu(id string) error {
	defer u.enter("流量与到期设置")()
	for {
		s, e := u.a.Load()
		if e != nil {
			return e
		}
		i, e := findSubscription(s, id)
		if e != nil {
			return e
		}
		sub := s.Subscriptions[i]
		u.heading("流量与到期设置")
		if lines := u.planLines(sub); len(lines) > 0 {
			for _, line := range lines {
				fmt.Fprintln(u.writer(), line)
			}
		} else {
			u.say("尚未设置流量额度或到期日")
		}
		u.hint("额度由订阅内所有节点共用，约每 5 秒核对一次，用完后停止这些节点，下个周期自动恢复；到期日只用于显示，到期后顺延到下个月同一天，不会停用订阅")
		plan := SubscriptionPlan{}
		if sub.Plan != nil {
			plan = *sub.Plan
		}
		v := u.menu("", []menuItem{item("limit", "流量额度（共享）"), item("day", "每月重置日"), item("expires", "套餐到期日"), item("reset", "立即重置本周期用量"), item("clear", "清除全部设置")}, "返回")
		if v == "" || u.err != nil {
			return u.err
		}
		var err error
		saved := false
		switch v {
		case "limit":
			u.hint("数字按 GB 计，也可写 500 MB、2 TB；0 表示不限；需先启用流量监控（rout traffic install）")
			raw := u.ask("共享流量额度", limitInput(plan.LimitBytes))
			if u.err != nil {
				break
			}
			var limit uint64
			if limit, err = parseLimitInput(raw); err == nil {
				err, saved = u.a.UpdateSubscriptionPlan(id, func(p *SubscriptionPlan) { p.LimitBytes = limit }), true
			}
		case "day":
			raw := u.ask("每月重置日（1–31）", strconv.Itoa(plan.policy().BillingDay))
			if u.err != nil {
				break
			}
			day, perr := strconv.Atoi(strings.TrimSpace(normalizeInput(raw)))
			if perr != nil || day < 1 || day > 31 {
				err = errors.New("订阅流量额度或重置日无效")
				break
			}
			err, saved = u.a.UpdateSubscriptionPlan(id, func(p *SubscriptionPlan) { p.BillingDay = day }), true
		case "expires":
			raw := u.ask("套餐到期日（YYYY-MM-DD，留空清除）", plan.Expires)
			if u.err != nil {
				break
			}
			var date string
			if date, err = ParsePlanDate(raw); err == nil {
				err, saved = u.a.UpdateSubscriptionPlan(id, func(p *SubscriptionPlan) { p.Expires = date }), true
			}
		case "reset":
			if plan.LimitBytes == 0 {
				u.warn("此订阅没有设置流量额度")
				break
			}
			if u.yes("立即开始新的流量周期并清零已用量", false) {
				err, saved = u.a.ResetSubscriptionUsage(id, time.Now()), true
			}
		case "clear":
			if u.yes("清除此订阅的流量额度、重置日和到期日", false) {
				err, saved = u.a.SetSubscriptionPlan(id, SubscriptionPlan{}), true
			}
		}
		if err != nil {
			u.fail(u.a.subscriptionText(u.a.Error(err)))
		} else if saved && u.err == nil {
			u.good("已保存；下次客户端刷新订阅时生效")
		}
		if u.err != nil {
			return u.err
		}
	}
}

func (u *UI) subscriptionDelete() error {
	s, e := u.a.Load()
	if e != nil {
		return e
	}
	sub, ok := u.pickSubscription(s, "选择要删除的订阅编号（0 返回）")
	if !ok {
		return u.err
	}
	u.warn("删除后订阅链接立即失效，客户端将无法更新")
	if !u.yes(fmt.Sprintf(u.a.T("删除订阅 %s"), sub.Name), false) {
		return u.err
	}
	if e = u.a.DeleteSubscription(sub.ID); e != nil {
		return e
	}
	u.good("订阅已删除，其链接已失效")
	return nil
}

func (u *UI) subscriptionRotate() error {
	s, e := u.a.Load()
	if e != nil {
		return e
	}
	sub, ok := u.pickSubscription(s, "选择要更换令牌的订阅编号（0 返回）")
	if !ok {
		return u.err
	}
	u.warn("旧令牌将立即失效，使用该订阅的所有客户端都需要改用新链接")
	if !u.yes(fmt.Sprintf(u.a.T("更换 %s 的令牌"), sub.Name), false) {
		return u.err
	}
	token, e := u.a.RotateSubscriptionToken(sub.ID)
	if e != nil {
		return e
	}
	u.showToken(token, "令牌已更换，旧链接已失效", sub.Name)
	return nil
}

func (u *UI) subscriptionServerInfo() (SubscriptionServerStatus, error) {
	st, e := u.a.SubscriptionServerStatus()
	if e != nil {
		return st, e
	}
	state := u.a.T("未启用")
	switch {
	case st.Settings.Enabled && !st.Managed:
		state = u.a.T("已启用（测试模式，未托管）")
	case st.Settings.Enabled && st.Running:
		state = u.paint("32", u.a.T("运行中"))
	case st.Settings.Enabled:
		state = u.paint("31", u.a.T("已启用但未运行"))
	}
	pub := st.Settings.PublicURL
	if pub == "" {
		pub = u.a.T("未配置")
	}
	fmt.Fprintf(u.writer(), "  %s  %s\n", pad(u.a.T("状态"), 10), state)
	fmt.Fprintf(u.writer(), "  %s  127.0.0.1:%d\n", pad(u.a.T("本机监听"), 10), st.Settings.listenPort())
	fmt.Fprintf(u.writer(), "  %s  %s\n", pad(u.a.T("公网地址"), 10), pub)
	return st, nil
}

func (u *UI) subscriptionServer() error {
	defer u.enter("订阅服务设置")()
	for {
		u.heading("订阅服务设置")
		st, e := u.subscriptionServerInfo()
		if e != nil {
			return e
		}
		u.hint("服务只监听回环地址；可自动部署 HTTPS，或继续使用已有反向代理")
		items := []menuItem{item("enable", "启用／修改端口"), item("public", "设置 HTTPS 公网地址"), item("deploy", "自动部署／修复 HTTPS"), item("diagnostics", "HTTPS 状态与诊断"), item("restart", "重启服务"), item("disable", "停用服务"), item("remove", "移除 Rout 管理的 HTTPS 配置"), item("mihomo", "Mihomo 健康检查地址")}

		v := u.menu("", items, "返回")
		if v == "" || u.err != nil {
			return u.err
		}
		var err error
		switch v {
		case "mihomo":
			cfg, e := u.a.subscriptionSettings()
			if e != nil {
				err = e
				break
			}
			u.hint("此 HTTPS 地址仅由客户端用于测速，每 600 秒按需检查；Rout 服务端不会访问")
			raw := u.ask("Mihomo 健康检查 HTTPS 地址", cfg.mihomoTestURL())
			if u.err == nil {
				if err = u.a.SetMihomoTestURL(raw); err == nil {
					u.good("Mihomo 健康检查地址已保存，无需重启服务")
				}
			}
		case "enable":
			port := u.port("本机监听端口", st.Settings.listenPort())
			if u.err == nil {
				if err = u.a.EnableSubscriptionServer(port); err == nil {
					u.good("订阅服务已启用并设为开机自启")
				}
			}
		case "public":
			raw := u.ask("HTTPS 公网地址（如 https://sub.example.com，留空清除）", st.Settings.PublicURL)
			if u.err == nil {
				parsed, _ := url.Parse(raw)
				if parsed != nil && !u.subscriptionDomainWarning(st.Settings.PublicURL, parsed.Hostname()) {
					break
				}
				if err = u.a.SetSubscriptionPublicURL(raw); err == nil {
					u.good("公网地址已保存")
				}
			}
		case "deploy":
			err = u.subscriptionHTTPSDeploy("")
		case "diagnostics":
			err = u.subscriptionHTTPSDiagnostics()
		case "remove":
			err = u.subscriptionHTTPSRemove()
		case "restart":
			if err = u.a.RestartSubscriptionServer(); err == nil {
				u.good("订阅服务已重启")
			}
		case "disable":
			u.warn("停用后客户端暂时无法刷新；订阅和令牌保留，Caddy 与 HTTPS 配置不会停止或删除")
			if u.yes("停用订阅服务（订阅配置会保留）", true) {
				if err = u.a.DisableSubscriptionServer(); err == nil {
					u.good("订阅服务已停用")
				}
			}
		}
		if err != nil {
			u.fail(u.a.subscriptionText(u.a.Error(err)))
		}
		if u.err != nil {
			return u.err
		}
	}
}

func (u *UI) subscriptions() error {
	defer u.enter("订阅管理")()
	for {
		v := u.menu("订阅管理", []menuItem{item("list", "查看订阅"), item("create", "创建订阅"), item("edit", "编辑订阅"), item("delete", "删除订阅"), item("rotate", "更换访问令牌"), item("server", "订阅服务设置")}, "返回")
		if u.err != nil || v == "" {
			return u.err
		}
		var e error
		switch v {
		case "list":
			var s State
			if s, e = u.a.Load(); e == nil {
				u.subscriptionList(s)
			}
		case "create":
			e = u.subscriptionCreate()
		case "edit":
			e = u.subscriptionEdit()
		case "delete":
			e = u.subscriptionDelete()
		case "rotate":
			e = u.subscriptionRotate()
		case "server":
			e = u.subscriptionServer()
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

// subscriptionCommand implements `rout subscription [list|status|restart|serve]`.
func (u *UI) subscriptionCommand(args []string) (err error) {
	defer func() {
		if err != nil {
			err = subscriptionUIError{err, u.a.subscriptionText(err.Error())}
		}
	}()
	if len(args) < 2 {
		if e := u.initLanguage(false); e != nil {
			return e
		}
		if e := u.a.RefreshSubscriptionServer(); e != nil {
			return e
		}
		return u.subscriptions()
	}
	switch args[1] {
	case "serve":
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		return u.a.ServeSubscriptions(ctx)
	case "list":
		s, e := u.a.Load()
		if e != nil {
			return e
		}
		u.subscriptionList(s)
		return nil
	case "status":
		_, e := u.subscriptionServerInfo()
		return e
	case "prepare-upgrade":
		return u.a.PrepareSubscriptionUpgrade()
	case "refresh":
		return u.a.RefreshSubscriptionServer()
	case "enable", "start":
		cfg, e := u.a.subscriptionSettings()
		if e != nil {
			return e
		}
		port := cfg.listenPort()
		if len(args) > 2 {
			var parsed int
			if _, e = fmt.Sscan(args[2], &parsed); e != nil {
				return e
			}
			port = parsed
		}
		return u.a.EnableSubscriptionServer(port)
	case "stop":
		return u.a.StopSubscriptionServer()
	case "disable":
		return u.a.DisableSubscriptionServer()
	case "startup":
		if len(args) != 3 || (args[2] != "on" && args[2] != "off") {
			return errors.New("use subscription startup on|off")
		}
		return u.a.SubscriptionStartup(args[2] == "on")
	case "logs":
		logs, e := u.a.SubscriptionLogs()
		if e == nil {
			fmt.Fprintln(u.writer(), logs)
		}
		return e
	case "mihomo-test-url":
		if len(args) != 3 {
			return errors.New("用法：rout subscription mihomo-test-url HTTPS_URL（default 恢复默认）")
		}
		raw := args[2]
		if raw == "default" {
			raw = ""
		}
		return u.a.SetMihomoTestURL(raw)
	case "https":
		if len(args) < 3 || args[2] == "status" {
			return u.subscriptionHTTPSDiagnostics()
		}
		switch args[2] {
		case "deploy", "repair":
			domain := ""
			if len(args) > 3 {
				domain = args[3]
			}
			return u.subscriptionHTTPSDeploy(domain)
		case "remove":
			return u.subscriptionHTTPSRemove()
		}
	case "plan":
		return u.subscriptionPlanCommand(args[2:])
	case "restart":
		return u.a.RestartSubscriptionServer()
	}
	return errors.New("用法：rout subscription [list|status|enable|start|stop|restart|refresh|disable|startup|logs|https|plan|serve]")
}

// subscriptionPlanCommand implements `rout subscription plan [ID [show|limit V|reset-day N|expires DATE|reset|clear]]`.
func (u *UI) subscriptionPlanCommand(args []string) error {
	s, e := u.a.Load()
	if e != nil {
		return e
	}
	usage := errors.New("用法：rout subscription plan [ID [show|limit 大小|reset-day 日|expires 日期|reset|clear]]")
	if len(args) == 0 {
		for _, sub := range s.Subscriptions {
			fmt.Fprintf(u.writer(), "%s  [%s]\n", u.bold(sub.Name), sub.ID)
			lines := u.planLines(sub)
			if len(lines) == 0 {
				lines = []string{"  " + u.a.T("尚未设置流量额度或到期日")}
			}
			for _, line := range lines {
				fmt.Fprintln(u.writer(), line)
			}
		}
		return nil
	}
	i, e := findSubscription(s, args[0])
	if e != nil {
		return e
	}
	id, sub := args[0], s.Subscriptions[i]
	if len(args) == 1 || args[1] == "show" {
		fmt.Fprintf(u.writer(), "%s  [%s]\n", u.bold(sub.Name), sub.ID)
		for _, line := range u.planLines(sub) {
			fmt.Fprintln(u.writer(), line)
		}
		return nil
	}
	switch args[1] {
	case "limit", "reset-day", "expires":
		if len(args) != 3 {
			return usage
		}
		var change func(*SubscriptionPlan)
		switch args[1] {
		case "limit":
			limit, e := parseLimitInput(args[2])
			if e != nil {
				return e
			}
			change = func(p *SubscriptionPlan) { p.LimitBytes = limit }
		case "reset-day":
			day, e := strconv.Atoi(args[2])
			if e != nil || day < 1 || day > 31 {
				return errors.New("订阅流量额度或重置日无效")
			}
			change = func(p *SubscriptionPlan) { p.BillingDay = day }
		default:
			date, e := ParsePlanDate(args[2])
			if e != nil {
				return e
			}
			change = func(p *SubscriptionPlan) { p.Expires = date }
		}
		if e = u.a.UpdateSubscriptionPlan(id, change); e != nil {
			return e
		}
	case "reset":
		if len(args) != 2 {
			return usage
		}
		if e = u.a.ResetSubscriptionUsage(id, time.Now()); e != nil {
			return e
		}
	case "clear":
		if len(args) != 2 {
			return usage
		}
		if e = u.a.SetSubscriptionPlan(id, SubscriptionPlan{}); e != nil {
			return e
		}
	default:
		return usage
	}
	u.good("已保存；下次客户端刷新订阅时生效")
	return nil
}
