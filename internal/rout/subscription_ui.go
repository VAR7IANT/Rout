package rout

import (
	"context"
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

// subscriptionList prints every subscription with its nodes and diagnostics.
func (u *UI) subscriptionList(s State) {
	if len(s.Subscriptions) == 0 {
		u.say("暂无订阅")
		return
	}
	for i, sub := range s.Subscriptions {
		fmt.Fprintf(u.writer(), "\n%s  %s  [%s]\n      %s\n", u.paint(accent, fmt.Sprintf("%2d", i+1)), u.bold(sub.Name), sub.ID, u.subStatus(s, sub))
		for _, id := range sub.NodeIDs {
			if p, e := Find(s, id); e == nil {
				fmt.Fprintln(u.writer(), "      "+u.nodeText(p))
			}
		}
		for _, w := range s.exportSubscription(sub).Warnings {
			u.warn(w)
		}
	}
	u.showExistingSubscriptionURL()
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

// showToken is the only place a plaintext token is ever printed.
func (u *UI) showToken(token, heading string) {
	cfg, _ := u.a.subscriptionSettings()
	u.good(heading)
	u.warn("访问令牌只显示这一次，请立即保存；Rout 只保存它的校验值")
	fmt.Fprintf(u.writer(), "  %s  %s\n", pad(u.a.T("访问令牌"), 10), token)
	if url := cfg.SubscriptionURL(token); url != "" {
		fmt.Fprintf(u.writer(), "  %s  %s\n", pad(u.a.T("订阅链接"), 10), url)
	} else {
		fmt.Fprintf(u.writer(), "  %s  https://YOUR-DOMAIN/s/%s\n", pad(u.a.T("链接模板"), 10), token)
		u.warn("尚未配置 HTTPS 公网地址：订阅服务只监听本机，请先用反向代理提供 HTTPS，再在“订阅服务设置”中填写公网地址")
	}
	if !cfg.Enabled {
		u.warn("订阅服务尚未启用：请在“订阅服务设置”中启用")
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
	u.showToken(token, "订阅已创建")
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
		v := u.menu("", []menuItem{item("rename", "重命名"), item("add", "添加节点"), item("remove", "移除节点"), item("reorder", "调整顺序"), toggle}, "返回")
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
	u.showToken(token, "令牌已更换，旧链接已失效")
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
	for {
		u.heading("订阅服务设置")
		st, e := u.subscriptionServerInfo()
		if e != nil {
			return e
		}
		u.hint("服务只监听回环地址；可自动部署 HTTPS，或继续使用已有反向代理")
		items := []menuItem{item("enable", "启用／修改端口"), item("public", "设置 HTTPS 公网地址"), item("deploy", "自动部署／修复 HTTPS"), item("diagnostics", "HTTPS 状态与诊断"), item("restart", "重启服务"), item("disable", "停用服务"), item("remove", "移除 Rout 管理的 HTTPS 配置")}

		v := u.menu("", items, "返回")
		if v == "" || u.err != nil {
			return u.err
		}
		var err error
		switch v {
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
	case "restart":
		return u.a.RestartSubscriptionServer()
	}
	return errors.New("用法：rout subscription [list|status|enable|start|stop|restart|refresh|disable|startup|logs|https|serve]")
}
