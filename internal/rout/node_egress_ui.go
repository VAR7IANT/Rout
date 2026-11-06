package rout

import (
	"errors"
	"fmt"
)

// Terminal side of the node outbound IP family: the choice list (create and manage), the manage
// submenu, and the egress report. The decisions live in node_egress.go; this only asks and shows.

// nodePolicyItems is the five-entry list with fixed numbering (1 auto … 5 IPv6 only). A family the
// host has no route for is annotated, never removed, so the numbers do not depend on the host.
func (u *UI) nodePolicyItems(routes familyRoutes) []menuItem {
	notes := map[string]string{
		outAuto:      "不限制，由系统选择；与旧版本行为一致（推荐）",
		outIPv4First: "优先使用 IPv4；不通时回退 IPv6",
		outIPv6First: "优先使用 IPv6；不通时回退 IPv4（不等于仅 IPv6）",
		outIPv4Only:  "只使用 IPv4；IPv6 地址和仅有 AAAA 记录的域名会被明确拒绝，不回退 IPv6",
		outIPv6Only:  "只使用 IPv6；IPv4 地址和仅有 A 记录的域名会被明确拒绝，不回退 IPv4",
	}
	var items []menuItem
	for _, c := range nodePolicyChoices(routes) {
		note := u.a.T(notes[c.Policy])
		if c.Missing != "" {
			note += " · " + fmt.Sprintf(u.a.T("本机没有 %s 出站路由"), c.Missing)
		}
		items = append(items, menuItem{key: c.Policy, label: outboundLabel(c.Policy), note: note})
	}
	return items
}

// chooseNodePolicy asks for a policy, with cur preselected. ok is false when the user backed out
// or declined to use a policy the host cannot satisfy.
func (u *UI) chooseNodePolicy(prompt, cur string) (policy string, ok bool) {
	routes := u.hostRoutesNow()
	if cur == "" {
		cur = outAuto
	}
	choice := u.option(prompt, u.nodePolicyItems(routes), cur)
	if u.err != nil || choice == "" {
		return "", false
	}
	for _, c := range nodePolicyChoices(routes) {
		if c.Policy == choice && !c.Available {
			u.warn(fmt.Sprintf(u.a.T("本机没有 %s 出站路由，选择该策略后节点将无法访问任何站点"), c.Missing))
			if !u.yes("仍要使用该策略", false) {
				return "", false
			}
		}
	}
	return choice, true
}

// nodeEgressLine is the one-line summary shown in the node card; empty for Auto, so nodes that
// never set a policy look as they always did.
func (u *UI) nodeEgressLine(p Profile) string {
	if p.Kind != "node" || p.outboundPolicy() == outAuto {
		return ""
	}
	return u.a.T("网络策略：") + u.a.T(outboundLabel(p.outboundPolicy()))
}

// nodeEgressMenu is the "出站网络策略" entry of the manage-node menu.
func (u *UI) nodeEgressMenu(p Profile) error {
	for {
		s, e := u.a.Load()
		if e != nil {
			return e
		}
		if p, e = Find(s, p.ID); e != nil {
			return e
		}
		u.heading("出站网络策略")
		u.printf("当前策略：%s\n", u.a.T(outboundLabel(p.outboundPolicy())))
		if note := p.egressScopeNote(); note != "" {
			u.say(note)
		}
		v := u.menu("", []menuItem{
			item("change", "修改出站网络策略"),
			item("test", "测试 IPv6 出站"),
			item("ip", "查看出站 IP"),
		}, "返回")
		if u.err != nil || v == "" {
			return u.err
		}
		switch v {
		case "change":
			e = u.changeNodePolicy(p)
		case "test":
			e = u.runEgressTest(p, false)
		case "ip":
			e = u.runEgressTest(p, true)
		}
		if e != nil {
			if errors.Is(e, errQuit) {
				return e
			}
			u.fail(u.a.Error(e))
		}
		if u.err != nil {
			return u.err
		}
	}
}

func (u *UI) changeNodePolicy(p Profile) error {
	policy, ok := u.chooseNodePolicy("出站网络策略", p.outboundPolicy())
	if !ok {
		return u.err
	}
	norm, e := normalizeNodePolicy(policy)
	if e != nil {
		return e
	}
	if norm == p.OutboundPolicy {
		u.say("策略没有变化")
		return nil
	}
	// The route check already happened in chooseNodePolicy (and was confirmed), so the change is
	// forced past SetNodeOutboundPolicy's own check rather than asking twice.
	if e = u.a.SetNodeOutboundPolicy(p.ID, policy, true); e != nil {
		return e
	}
	u.good("出站网络策略已保存；该节点已重启，其他节点未受影响，UUID、端口、证书和订阅链接保持不变")
	return nil
}

func (u *UI) runEgressTest(p Profile, quick bool) error {
	u.say("正在经由节点实际出口测试，请稍候…")
	env := u.egressEnvOrDefault()
	rep, e := u.a.nodeEgressTest(p.ID, quick, env)
	if e != nil {
		return e
	}
	u.printEgressReport(rep)
	return nil
}

// egressEnvOrDefault returns the UI's test override or the real environment.
func (u *UI) egressEnvOrDefault() egressEnv {
	if u.egress != nil {
		return *u.egress
	}
	return defaultEgressEnv()
}

// printEgressReport shows the measurements with their origin: host tests and node tests are
// printed in separate blocks and labelled, so one is never mistaken for the other.
func (u *UI) printEgressReport(rep EgressReport) {
	w := u.writer()
	u.heading("出站网络测试")
	u.printf("策略：%s\n", rep.PolicyLabel)
	if rep.Note != "" {
		fmt.Fprintln(u.writer(), "  "+u.dim(rep.Note))
	}
	yesNo := func(b bool) string {
		if b {
			return u.a.T("有")
		}
		return u.a.T("无")
	}
	fmt.Fprintf(w, "\n  %s\n", u.bold(u.a.T("主机网络测试（本服务器自身，不经过节点）")))
	for _, f := range []struct {
		label string
		h     EgressHostFamily
	}{{"IPv4", rep.Host.V4}, {"IPv6", rep.Host.V6}} {
		ip := f.h.IP
		if ip == "" {
			ip = u.a.T("不可用")
		}
		fmt.Fprintf(w, "    %s  %s %s · %s %s · %s %s\n", f.label, u.a.T("路由"), yesNo(f.h.Route), u.a.T("DNS"), yesNo(f.h.DNS), u.a.T("本机公网地址"), ip)
	}
	fmt.Fprintf(w, "\n  %s\n", u.bold(u.a.T("节点出站测试（经由节点的真实出口）")))
	if rep.Node.Error != "" {
		fmt.Fprintf(w, "    %s %s\n", u.paint(colorErr, "✗"), rep.Node.Error)
	}
	for _, c := range rep.Checks {
		mark := u.dim("·")
		switch c.Status {
		case egressPass:
			mark = u.paint(colorOK, "✓")
		case egressFail:
			mark = u.paint(colorErr, "✗")
		case egressInconclusive:
			mark = u.paint(colorWarn, "!")
		}
		fmt.Fprintf(w, "    %s %s\n", mark, c.Text)
	}
	fmt.Fprintln(w)
	switch {
	case rep.Quick && rep.Result == "":
		u.say("已列出经节点的实际出口地址；要验证策略请使用『测试 IPv6 出站』")
	case rep.Result == egressPass:
		u.good("结果：通过")
	case rep.Result == egressFail:
		u.fail(u.a.T("结果：未通过"))
	default:
		u.warn("结果：无法完全验证（见上面标有 ! 的项目）；不要据此认为策略已生效")
	}
}
