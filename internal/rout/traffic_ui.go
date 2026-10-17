package rout

import (
	"errors"
	"fmt"
	"strconv"
	"time"
)

func (u *UI) showTraffic(p Profile) error {
	u.printf("\n%s [%s] %s\n", p.Name, p.ID, ProtocolLabel(p.Protocol))
	u.printf("节点运行状态：%s\n", u.a.Running(p))
	policy := p.trafficPolicy()
	limit := u.a.T("无限制")
	if policy.LimitBytes > 0 {
		limit = FormatTraffic(policy.LimitBytes)
	}
	u.printf("流量上限：%s\n", limit)
	if !u.a.trafficActive() {
		return errors.New("请先运行 rout traffic install，未启用流量监控")
	}
	db, e := u.a.loadTraffic()
	if e != nil {
		return e
	}
	r, ok := db.Records[p.ID]
	if !ok {
		return errors.New("流量统计尚未就绪")
	}
	s, er := u.a.meter().Read(p)
	if er == nil && s.Hash == r.Rules && !r.Pending {
		er = mergeTraffic(&r, s)
	} else {
		u.say("当前计量不可用，以下为最近落盘数据，不代表完整实时用量")
	}
	if er != nil || r.Incomplete {
		u.say("存在计量缺口：已知字节为下限，不是估算的完整用量")
	}
	up, down, total, e := r.totals()
	if e != nil {
		return e
	}
	exact := func(n uint64) string { return fmt.Sprintf("%s (%d B)", FormatTraffic(n), n) }
	u.printf("本期上传：%s\n本期下载：%s\n双向合计：%s\n", exact(up), exact(down), exact(total))
	if policy.LimitBytes > 0 {
		u.printf("已使用百分比：%s\n", fmt.Sprintf("%.2f%%", float64(total)/float64(policy.LimitBytes)*100))
	} else {
		u.say("已使用百分比：不适用（无限制）")
	}
	u.printf("账单周期：%s → %s\n", r.Start.Format(time.RFC3339), r.Next.Format(time.RFC3339))
	u.printf("下次重置：%s\n", r.Next.Format(time.RFC3339))
	u.printf("开始观测：%s\n", r.Observed.Format(time.RFC3339))
	status := u.a.T("正常")
	switch {
	case r.Blocked == blockQuota || (policy.LimitBytes > 0 && r.Consumed >= policy.LimitBytes):
		status = u.a.T("已达流量上限，自动停用，下个账单周期自动恢复")
	case r.Blocked == blockSealed:
		status = u.a.T("流量监控已停止，检查点完整；监控恢复后自动继续")
	case r.Blocked != "":
		status = u.a.T("计量故障保护暂停：可保留已知用量恢复、确认清零或等待新周期")
	}
	u.printf("流量保护状态：%s\n", status)
	manual := u.a.T("启用")
	if !p.Enabled {
		manual = u.a.T("停用")
	}
	u.printf("用户手动开关：%s\n", manual)
	return nil
}
func (u *UI) trafficRecord(id string) TrafficRecord {
	if db, e := u.a.loadTraffic(); e == nil {
		return db.Records[id]
	}
	return TrafficRecord{}
}

// recoverTraffic resumes a fault-paused node with its known usage after warning that
// traffic during the gap could not be counted.
func (u *UI) recoverTraffic(p Profile) error {
	u.warn("计量缺口期间的流量无法统计：恢复后本周期用量为已知下限，限额按已知用量继续执行")
	if !u.yes("保留已知用量并恢复此节点", false) {
		return u.err
	}
	if e := u.a.RecoverTraffic(p.ID, time.Now()); e != nil {
		return e
	}
	u.good("已恢复，已知用量保持不变")
	return nil
}
func (u *UI) trafficManage(p Profile) error {
	if e := u.showTraffic(p); e != nil {
		u.warn(u.a.Error(e))
	}
	policy := p.trafficPolicy()
	r := u.trafficRecord(p.ID)
	items := []menuItem{item("view", "查看流量"), item("limit", "设置或修改限额")}
	if policy.LimitBytes > 0 {
		items = append(items, item("unlimited", "恢复无限流量"))
	}
	items = append(items, item("billing", "账单日与时区"), item("reset", "手动清零本期用量"), item("pause", "手动暂停或恢复节点"))
	if policy.LimitBytes > 0 && r.Blocked == blockFault {
		items = append(items, item("recover", "保留已知用量并恢复"))
	}
	v := u.menu("流量管理", items, "返回")
	if u.err != nil {
		return u.err
	}
	mode := trafficKeep
	switch v {
	case "":
		return nil
	case "view":
		return u.showTraffic(p)
	case "recover":
		return u.recoverTraffic(p)
	case "limit":
		for u.err == nil {
			n, e := ParseTrafficLimit(u.ask("双向流量限额，例如 100 GB（十进制）", ""))
			if e != nil {
				u.say(u.a.Error(e))
				continue
			}
			policy.LimitBytes = n
			break
		}
		if !u.yes("启用或修改此节点限额，达到上限将断流", false) {
			return u.err
		}
		if r.Incomplete && p.trafficPolicy().LimitBytes == 0 {
			u.warn("本周期存在计量缺口（升级、重启或监控中断前的流量无法补算）")
			switch u.option("如何处理本周期用量", []menuItem{item("keep", "保留已知用量继续计量（缺口期间流量不计入）"), item("reset", "清零并从现在开始计量"), item("cancel", "取消")}, "keep") {
			case "keep":
				mode = trafficAcceptGap
			case "reset":
				if u.ask("输入 RESET 再次确认清零", "") != "RESET" {
					return errors.New("清零已取消")
				}
				mode = trafficReset
			default:
				return u.err
			}
		}
	case "unlimited":
		if !u.yes("取消此节点流量限制并恢复无限流量", false) {
			return u.err
		}
		policy.LimitBytes = 0
	case "billing":
		for u.err == nil {
			n, e := strconv.Atoi(u.ask("每月账单日（1–31）", itoa(policy.BillingDay)))
			if e == nil && n >= 1 && n <= 31 {
				policy.BillingDay = n
				break
			}
			u.say("流量限额或账单日无效")
		}
		policy.Timezone = u.ask("账单时区（Local 为服务器本地时区）", policy.Timezone)
		if policy.Timezone == "Local" {
			policy.Timezone = ""
		}
		u.say("修改账单设置不会立即清零本期用量")
	case "reset":
		if !u.yes("清零本期上传和下载并解除流量保护暂停", false) {
			return u.err
		}
		if u.ask("输入 RESET 再次确认清零", "") != "RESET" {
			return errors.New("清零已取消")
		}
		mode = trafficReset
	case "pause":
		s, e := u.a.Load()
		if e != nil {
			return e
		}
		p.Enabled = !p.Enabled
		return u.a.Commit(s, replace(s, p), false)
	}
	if u.err != nil {
		return u.err
	}
	if e := u.a.configureTraffic(p.ID, &policy, mode, time.Now()); e != nil {
		return e
	}
	u.good("流量设置已保存")
	return nil
}
