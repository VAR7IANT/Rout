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
	u.printf("本期上传：%s\n本期下载：%s\n双向合计：%s\n", FormatTraffic(up), FormatTraffic(down), FormatTraffic(total))
	if policy.LimitBytes > 0 {
		u.printf("已使用百分比：%s\n", fmt.Sprintf("%.2f%%", float64(total)/float64(policy.LimitBytes)*100))
	} else {
		u.say("已使用百分比：不适用（无限制）")
	}
	u.printf("账单周期：%s → %s\n", r.Start.Format(time.RFC3339), r.Next.Format(time.RFC3339))
	u.printf("下次重置：%s\n", r.Next.Format(time.RFC3339))
	u.printf("开始观测：%s\n", r.Observed.Format(time.RFC3339))
	status := u.a.T("正常")
	if r.Blocked == "quota" || (policy.LimitBytes > 0 && r.Consumed >= policy.LimitBytes) {
		status = u.a.T("已达流量上限，自动停用")
	} else if r.Blocked != "" {
		status = u.a.T("计量故障保护暂停，需新周期或确认清零")
	}
	u.printf("流量保护状态：%s\n", status)
	manual := u.a.T("启用")
	if !p.Enabled {
		manual = u.a.T("停用")
	}
	u.printf("用户手动开关：%s\n", manual)
	return nil
}
func (u *UI) trafficManage(p Profile) error {
	if e := u.showTraffic(p); e != nil {
		u.say(u.a.Error(e))
	}
	v := u.choose("1.查看流量  2.设置限额  3.恢复无限流量  4.账单日与时区  5.手动清零  6.手动暂停或恢复  0.返回", []string{"0", "1", "2", "3", "4", "5", "6"}, "0")
	if u.err != nil {
		return u.err
	}
	policy := p.trafficPolicy()
	reset := false
	switch v {
	case "0":
		return nil
	case "1":
		return u.showTraffic(p)
	case "2":
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
	case "3":
		if !u.yes("取消此节点流量限制并恢复无限流量", false) {
			return u.err
		}
		policy.LimitBytes = 0
	case "4":
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
	case "5":
		if !u.yes("清零本期上传和下载并解除流量保护暂停", false) {
			return u.err
		}
		if u.ask("输入 RESET 再次确认清零", "") != "RESET" {
			return errors.New("清零已取消")
		}
		reset = true
	case "6":
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
	return u.a.ConfigureTraffic(p.ID, policy, reset, time.Now())
}
