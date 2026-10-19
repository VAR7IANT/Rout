package rout

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// AI Smart Routing menus. This file only asks questions and prints; every change goes
// through the App methods in ai_routing.go (SetAIEnabled, SetAIBindings, SetAIExit,
// ApplyAI), so a future Web interface can call the same functions.

// aiSummary is the short status shown in the main menu header.
func (u *UI) aiSummary(s State) string {
	if s.AI == nil || !s.AI.Enabled {
		return u.a.T("AI 分流：未启用")
	}
	n := 0
	for _, p := range s.Profiles {
		if p.AIRoute != nil {
			n++
		}
	}
	return fmt.Sprintf(u.a.T("AI 分流：已启用（%d 个入站）"), n)
}

func (u *UI) aiStatusLines(st AIStatus) {
	w := u.writer()
	state := u.a.T("未启用")
	if st.Config.Enabled {
		state = u.paint("32", u.a.T("已启用"))
	}
	exit := u.a.T("未选择")
	if st.ExitName != "" {
		exit = st.ExitName + " (" + strings.ToUpper(st.ExitProtocol) + ")"
	} else if st.Config.AIOutboundID != "" {
		exit = u.paint("33", u.a.T("所选出口已不存在"))
	}
	fmt.Fprintf(w, "  %s  %s\n", pad(u.a.T("状态"), 10), state)
	fmt.Fprintf(w, "  %s  %s\n", pad(u.a.T("AI 出口"), 10), exit)
	fmt.Fprintf(w, "  %s  %d\n", pad(u.a.T("已绑定入站"), 10), st.BoundCount)
	for _, p := range st.Problems {
		u.warn(u.a.T(p))
	}
	pending := 0
	for _, n := range st.Nodes {
		if !n.InSync {
			pending++
		}
	}
	if pending > 0 {
		u.warnf("有 %d 个节点的配置与已保存的设置不一致，请选择“应用更改”", pending)
	}
	if st.Config.Enabled && st.BoundCount == 0 {
		u.warn("尚未选择入站节点：目前不会影响任何节点")
	}
}

func (u *UI) aiMenu() error {
	for {
		st, e := u.a.AIStatus()
		if e != nil {
			return e
		}
		u.heading("AI 智能分流")
		u.aiStatusLines(st)
		toggle := "启用 AI 智能分流"
		if st.Config.Enabled {
			toggle = "停用 AI 智能分流"
		}
		v := u.menu("", []menuItem{item("toggle", toggle), item("inbounds", "选择入站节点"), item("exit", "选择 AI 出口"), item("rules", "查看 AI 规则"), item("test", "测试配置"), item("status", "状态与诊断"), item("apply", "应用更改")}, "返回")
		if u.err != nil || v == "" {
			return u.err
		}
		switch v {
		case "toggle":
			e = u.aiToggle(st)
		case "inbounds":
			e = u.aiSelectInbounds()
		case "exit":
			e = u.aiSelectExit()
		case "rules":
			u.aiRules(st.Config.RuleSetVersion)
		case "test":
			e = u.aiTest()
		case "status":
			e = u.aiDiagnostics()
		case "apply":
			e = u.aiApply(st)
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

func (u *UI) aiToggle(st AIStatus) error {
	if st.Config.Enabled {
		if !u.yes(fmt.Sprintf(u.a.T("停用 AI 智能分流（会重启 %d 个已绑定节点，恢复其原有路由；设置会保留）"), st.BoundCount), true) {
			return u.err
		}
		if e := u.a.SetAIEnabled(false); e != nil {
			return e
		}
		u.good("AI 智能分流已停用，已绑定节点恢复原有路由")
		return nil
	}
	if st.Config.AIOutboundID == "" {
		return errors.New("请先选择 AI 出口")
	}
	if st.BoundCount == 0 {
		u.warn("尚未选择入站节点：启用后不会影响任何节点")
	}
	if !u.yes(fmt.Sprintf(u.a.T("启用 AI 智能分流（会重启 %d 个已绑定节点）"), st.BoundCount), true) {
		return u.err
	}
	if e := u.a.SetAIEnabled(true); e != nil {
		return e
	}
	u.good("AI 智能分流已启用")
	return nil
}

// aiSelectInbounds is a checklist. Nothing is selected by default and an empty selection
// binds nothing.
func (u *UI) aiSelectInbounds() error {
	s, e := u.a.Load()
	if e != nil {
		return e
	}
	cfg := s.aiConfigured()
	var nodes []Profile
	for _, p := range s.Profiles {
		if aiEligible(p) == nil {
			nodes = append(nodes, p)
		}
	}
	if len(nodes) == 0 {
		u.say("暂无可绑定的节点，请先创建节点")
		return nil
	}
	chosen := map[string]bool{}
	current := cfg.aiBound()
	for _, p := range nodes {
		chosen[p.ID] = current[p.ID]
	}
	for _, id := range cfg.BoundInboundIDs {
		if _, er := Find(s, id); er != nil {
			u.warnf("绑定的入站 %s 已不存在，保存时将移除", id)
		}
	}
	for u.err == nil {
		u.heading("选择入站节点")
		for i, p := range nodes {
			mark := "[ ]"
			if chosen[p.ID] {
				mark = u.paint(accent, "[x]")
			}
			fmt.Fprintf(u.writer(), "  %2d  %s %s %s\n", i+1, mark, u.bold(p.Name), u.dim("["+p.ID+"] "+ProtocolLabel(p.Protocol)))
		}
		u.hint("输入编号切换选中，可多个，如 1 3 · s 保存 · 0 取消")
		raw := normalizeInput(u.ask("选择", ""))
		if u.err != nil {
			return u.err
		}
		switch {
		case raw == "0" || menuShortcut(raw) == "back":
			u.say("已取消")
			return nil
		case menuShortcut(raw) == "quit":
			u.err = errQuit
			return u.err
		case raw == "s" || raw == "save" || raw == "保存":
			return u.aiSaveInbounds(s, nodes, chosen, cfg)
		}
		toggles := []int{}
		ok := true
		for _, f := range strings.Fields(strings.ReplaceAll(raw, ",", " ")) {
			n, er := strconv.Atoi(f)
			if er != nil || n < 1 || n > len(nodes) {
				ok = false
				break
			}
			toggles = append(toggles, n)
		}
		if !ok || len(toggles) == 0 {
			u.say("编号无效")
			continue
		}
		for _, n := range toggles {
			chosen[nodes[n-1].ID] = !chosen[nodes[n-1].ID]
		}
	}
	return u.err
}

func (u *UI) aiSaveInbounds(s State, nodes []Profile, chosen map[string]bool, cfg AIRouting) error {
	var ids, added, removed []string
	was := cfg.aiBound()
	for _, p := range nodes {
		if chosen[p.ID] {
			ids = append(ids, p.ID)
			if !was[p.ID] {
				added = append(added, p.Name)
			}
		} else if was[p.ID] {
			removed = append(removed, p.Name)
		}
	}
	stale := false
	for id := range was {
		if _, er := Find(s, id); er != nil {
			stale = true
		}
	}
	if len(added) == 0 && len(removed) == 0 && !stale {
		u.say("绑定未改变")
		return nil
	}
	if len(added) > 0 {
		u.printf("绑定：%s\n", joinNames(added))
	}
	if len(removed) > 0 {
		u.printf("解除绑定：%s\n", joinNames(removed))
	}
	if len(ids) == 0 {
		u.warn("没有选择任何入站：AI 智能分流不会影响任何节点")
	}
	if !cfg.Enabled {
		u.say("AI 智能分流当前未启用，绑定将在启用后生效")
	} else {
		u.say("只会重启绑定状态发生变化的节点；未绑定的节点不受影响")
	}
	if !u.yes("保存", true) {
		return u.err
	}
	if e := u.a.SetAIBindings(ids); e != nil {
		return e
	}
	u.good("入站绑定已保存")
	return nil
}

func (u *UI) aiSelectExit() error {
	s, e := u.a.Load()
	if e != nil {
		return e
	}
	if len(s.Exits) == 0 {
		u.say("暂无出站代理。请先在“出站代理”中创建 AI 出口（例如位于加拿大的 SOCKS5 或 HTTP 代理）")
		return nil
	}
	cfg := s.aiConfigured()
	u.heading("选择 AI 出口")
	local := localIPs()
	usable := map[int]bool{}
	for i, ex := range s.Exits {
		why := aiExitUsable(ex.Proxy)
		if why == nil {
			why = aiExitLoop(s, ex.Proxy, local)
		}
		mark := ""
		if ex.ID == cfg.AIOutboundID {
			mark = " " + u.paint("32", u.a.T("（当前）"))
		}
		fmt.Fprintf(u.writer(), "  %s %s — %s — %s%s\n", u.paint(accent, fmt.Sprintf("%2d.", i+1)), u.bold(ex.Name), strings.ToUpper(ex.Proxy.Protocol), u.dim(fmt.Sprintf("%s:%d", ex.Proxy.Host, ex.Proxy.Port)), mark)
		if why != nil {
			fmt.Fprintf(u.writer(), "      %s\n", u.paint("31", "✗ "+u.a.Error(why)))
		}
		usable[i+1] = why == nil
	}
	n := u.number("选择 AI 出口编号（0 返回）", len(s.Exits))
	if n <= 0 {
		return u.err
	}
	if !usable[n] {
		return errors.New("此出站代理不能作为 AI 出口")
	}
	ex := s.Exits[n-1]
	if ex.ID == cfg.AIOutboundID {
		u.say("AI 出口未改变")
		return nil
	}
	u.say("正在测试出站代理…")
	if ip, er := u.testExit(ex.Proxy); er != nil {
		u.warn(u.a.Error(er))
		if !u.yes("出口当前不可用，仍然选择它", false) {
			return u.err
		}
	} else {
		u.printf("实际出口 IP：%s\n", ip)
	}
	if cfg.Enabled {
		u.say("只会重启已绑定的节点；其他节点和入站配置不受影响")
	}
	if !u.yes(fmt.Sprintf(u.a.T("将 AI 出口设为 %s"), ex.Name), true) {
		return u.err
	}
	if e = u.a.SetAIExit(ex.ID); e != nil {
		return e
	}
	u.good("AI 出口已更新")
	return nil
}

func (u *UI) aiRules(version int) {
	if version == 0 {
		version = AIRuleSetCurrent
	}
	u.heading("AI 规则")
	u.printf("规则集版本：%d\n", version)
	for _, svc := range AIServices(version) {
		fmt.Fprintf(u.writer(), "  %s\n", u.bold(svc.Name))
		fmt.Fprintf(u.writer(), "      %s\n", u.dim(strings.Join(svc.Suffixes, ", ")))
	}
	fmt.Fprintln(u.writer())
	for _, line := range []string{
		"规则按域名后缀匹配（含子域名），只列出 AI 服务专用的域名，不包含 google.com、github.com 等整站域名",
		"仅按域名判断：客户端只发送 IP、使用 ECH 加密握手或域名无法获取的连接，无法识别，会走原有路由",
		"GitHub Copilot 的令牌请求发往 api.github.com，为避免误伤普通 GitHub 流量不在规则内",
		"针对 AI 域名的 UDP（如 QUIC）会被拒绝，让客户端回退到 TCP；AI 出口只转发 TCP",
		"规则集不能保证覆盖全部 AI 流量；后续版本会更新规则，更新后请选择“应用更改”",
	} {
		fmt.Fprintln(u.writer(), "· "+u.a.T(line))
	}
}

func (u *UI) aiTest() error {
	u.say("正在检查配置…")
	checks, e := u.a.TestAI(u.testExit)
	if e != nil {
		return e
	}
	bad := false
	for _, c := range checks {
		switch {
		case c.OK:
			u.good(c.Text)
		case c.Warning:
			u.warn(c.Text)
		default:
			bad = true
			u.fail(u.a.T(c.Text))
		}
	}
	if bad {
		u.say("配置存在问题，请先修复；当前运行中的节点不受此测试影响")
	}
	s, e := u.a.Load()
	if e != nil {
		return e
	}
	domain := normalizeInput(u.ask("输入一个域名，查看各节点会如何路由（规则模拟，不发起真实请求；留空跳过）", "chat.openai.com"))
	if u.err != nil || domain == "" || domain == "0" {
		return u.err
	}
	u.heading("路由模拟")
	for _, p := range s.Profiles {
		if p.Kind != "node" {
			continue
		}
		route, er := AIDecision(s, p.ID, domain)
		if er != nil {
			return er
		}
		label := u.a.T("原有路由")
		switch route {
		case "ai":
			label = u.paint("32", u.a.T("AI 出口"))
		case "blocked":
			label = u.paint("31", u.a.T("已拒绝（AI 出口不可用）"))
		}
		fmt.Fprintf(u.writer(), "  %s  %s\n", pad(p.Name, 28), label)
	}
	u.say("以上是对规则的模拟；真实网络效果请参考手动验收清单")
	return nil
}

func (u *UI) aiDiagnostics() error {
	st, e := u.a.AIStatus()
	if e != nil {
		return e
	}
	u.heading("状态与诊断")
	u.aiStatusLines(st)
	fmt.Fprintln(u.writer())
	if len(st.Nodes) == 0 {
		u.say("暂无节点")
	}
	for _, n := range st.Nodes {
		bound := u.a.T("未绑定")
		if n.Bound {
			bound = u.paint(accent, u.a.T("已绑定"))
		}
		applied := u.a.T("配置一致")
		if !n.InSync {
			applied = u.paint("33", u.a.T("待应用"))
		}
		fmt.Fprintf(u.writer(), "  %s %s %s %s\n", pad(n.Name, 24), pad(bound, 8), pad(n.Running, 8), applied)
		if n.Note != "" {
			fmt.Fprintf(u.writer(), "      %s\n", u.dim(u.a.T(n.Note)))
		}
	}
	fmt.Fprintln(u.writer())
	for _, line := range []string{
		"域名识别：已绑定节点启用嗅探（TLS SNI、HTTP Host、QUIC），客户端直接发送域名或 IP 时都可识别",
		"无法识别的情况：ECH 加密握手、纯 IP 且无嗅探信息的连接；这些连接走原有路由",
		"AI 出口不可用时，AI 域名的连接会失败（不会静默改走原有出口），请选择“选择 AI 出口”更换",
	} {
		fmt.Fprintln(u.writer(), "· "+u.a.T(line))
	}
	if _, er := os.Stat(filepath.Join(u.a.Home, "state.json")); er != nil {
		u.say("尚无配置文件")
	}
	return nil
}

func (u *UI) aiApply(st AIStatus) error {
	if !u.yes(fmt.Sprintf(u.a.T("重新校验并应用 AI 智能分流，并更新到最新规则集（会重启 %d 个已绑定节点）"), st.BoundCount), true) {
		return u.err
	}
	if e := u.a.ApplyAI(); e != nil {
		return e
	}
	u.good("已应用")
	return nil
}

// aiCommand is `rout ai [status|test|apply]`; without a subcommand it opens the menu.
func (u *UI) aiCommand(args []string) error {
	if len(args) == 1 {
		if e := u.initLanguage(false); e != nil {
			return e
		}
		return u.aiMenu()
	}
	if len(args) != 2 {
		return errors.New("用法：rout ai [status|test|apply]")
	}
	switch args[1] {
	case "status":
		st, e := u.a.AIStatus()
		if e != nil {
			return e
		}
		u.aiStatusLines(st)
		for _, n := range st.Nodes {
			if n.Bound {
				fmt.Fprintf(u.writer(), "  %s %s %s\n", pad(n.Name, 24), pad(n.Running, 8), map[bool]string{true: u.a.T("配置一致"), false: u.a.T("待应用")}[n.InSync])
			}
		}
		return nil
	case "test":
		return u.aiTest()
	case "apply":
		return u.a.ApplyAI()
	}
	return errors.New("用法：rout ai [status|test|apply]")
}
