package rout

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var plainNumber = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?$`)

// parseLimitInput reads a quota as typed by a user. A bare number is decimal GB
// (1 GB = 1,000,000,000 bytes); MB/GB/TB suffixes are accepted; empty, 0 and
// "unlimited" mean no limit.
func parseLimitInput(s string) (uint64, error) {
	v := strings.ReplaceAll(normalizeInput(s), " ", "")
	switch v {
	case "", "0", "unlimited", "none", "不限", "无限", "无限制":
		return 0, nil
	}
	if plainNumber.MatchString(v) {
		v += "gb"
	}
	for _, unit := range []string{"mb", "gb", "tb"} {
		if strings.HasSuffix(v, unit) {
			v = strings.TrimSuffix(v, unit) + " " + unit
			break
		}
		if short := unit[:1]; strings.HasSuffix(v, short) && plainNumber.MatchString(strings.TrimSuffix(v, short)) {
			v = strings.TrimSuffix(v, short) + " " + unit
			break
		}
	}
	return ParseTrafficLimit(v)
}

// limitInput renders a limit the way a user would type it back (100, 1.5, 500 MB).
func limitInput(n uint64) string {
	if n == 0 {
		return ""
	}
	if n%1_000_000_000 == 0 {
		return strconv.FormatUint(n/1_000_000_000, 10)
	}
	return strings.TrimSuffix(strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.3f", float64(n)/1e9), "0"), "."), ".")
}
func (u *UI) dateAndDays(t time.Time) string {
	days := int(time.Until(t).Hours()/24 + 0.999)
	if days < 0 {
		days = 0
	}
	return fmt.Sprintf(u.a.T("%s（%d 天后）"), t.Format("2006-01-02"), days)
}
func (u *UI) showTraffic(p Profile) error {
	u.heading(p.Name)
	policy := p.trafficPolicy()
	quota := u.a.T("不限")
	if policy.LimitBytes > 0 {
		quota = FormatTraffic(policy.LimitBytes)
	}
	if !u.a.trafficActive() {
		u.printf("限额：%s\n", quota)
		return errors.New("请先运行 rout traffic install，未启用流量监控")
	}
	db, e := u.a.loadTraffic()
	if e != nil {
		return e
	}
	r, ok := db.Records[p.ID]
	if !ok {
		u.printf("限额：%s\n", quota)
		return errors.New("流量统计尚未就绪")
	}
	s, er := u.a.meter().Read(p)
	live := er == nil && s.Hash == r.Rules && !r.Pending
	if live {
		er = mergeTraffic(&r, s)
	}
	up, down, total, e := r.totals()
	if e != nil {
		return e
	}
	exact := func(n uint64) string {
		return fmt.Sprintf("%-12s %s", FormatTraffic(n), u.dim(fmt.Sprintf("(%d B)", n)))
	}
	row := func(label, value string) { fmt.Fprintf(u.writer(), "  %s %s\n", pad(u.a.T(label), 10), value) }
	row("上传", exact(up))
	row("下载", exact(down))
	row("合计", exact(total)+u.dim("  "+u.a.T("上传＋下载")))
	row("限额", quota)
	if policy.LimitBytes > 0 {
		left := uint64(0)
		if total < policy.LimitBytes {
			left = policy.LimitBytes - total
		}
		row("剩余", fmt.Sprintf(u.a.T("%s（剩余 %.1f%%）"), FormatTraffic(left), float64(left)/float64(policy.LimitBytes)*100))
	}
	zone := policy.Timezone
	if zone == "" {
		zone = u.a.T("服务器时区")
	}
	row("下次重置", fmt.Sprintf("%s · %s %d · %s", u.dateAndDays(r.Next), u.a.T("每月"), policy.BillingDay, zone))
	status := u.a.T("正常")
	switch {
	case !p.Enabled:
		status = u.a.T("已手动停用")
	case r.Blocked == blockQuota || (policy.LimitBytes > 0 && r.Consumed >= policy.LimitBytes):
		status = u.a.T("已达限额，节点已停止；下次重置后自动恢复")
	case r.Blocked == blockSealed:
		status = u.a.T("流量监控已停止；监控恢复后自动继续（用量完整）")
	case r.Blocked != "":
		status = u.a.T("计量中断后已暂停：可选择『保留已知用量并恢复』")
	}
	row("状态", status)
	fmt.Fprintln(u.writer(), "  "+u.dim(u.a.T("单位为十进制：1 GB = 1,000,000,000 字节")))
	if !live {
		u.warn("当前读取的是最近保存的数据，实时计数暂不可用")
	}
	if er != nil || r.Incomplete {
		u.warn("本周期有一段时间未能计量（例如崩溃或升级前），显示的用量可能偏低")
	}
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
	u.warn("计量中断期间的流量无法统计：恢复后继续按已知用量计算限额")
	if !u.yes("保留已知用量并恢复此节点", true) {
		return u.err
	}
	if e := u.a.RecoverTraffic(p.ID, time.Now()); e != nil {
		return e
	}
	u.good("已恢复，已知用量保持不变")
	return nil
}

// askLimit asks for a quota in GB. Empty keeps the current value (unlimited when none).
func (u *UI) askLimit(current uint64) (uint64, bool) {
	for u.err == nil {
		raw := u.ask("流量限额，单位 GB（如 100；也可写 500 MB、2 TB；0 = 不限）", limitInput(current))
		if u.err != nil {
			return 0, false
		}
		n, e := parseLimitInput(raw)
		if e == nil {
			return n, true
		}
		u.say("请输入数字（GB），例如 100；或 0 表示不限")
	}
	return 0, false
}
func (u *UI) trafficManage(p Profile) error {
	if e := u.showTraffic(p); e != nil {
		u.warn(u.a.Error(e))
	}
	policy := p.trafficPolicy()
	r := u.trafficRecord(p.ID)
	items := []menuItem{item("limit", "设置流量限额"), item("billing", "账单日与时区"), item("reset", "清零本期用量"), item("pause", "暂停或恢复节点")}
	if policy.LimitBytes > 0 && r.Blocked == blockFault {
		items = append([]menuItem{item("recover", "保留已知用量并恢复")}, items...)
	}
	v := u.menu("", items, "返回")
	if u.err != nil || v == "" {
		return u.err
	}
	mode := trafficKeep
	switch v {
	case "recover":
		return u.recoverTraffic(p)
	case "limit":
		n, ok := u.askLimit(policy.LimitBytes)
		if !ok {
			return u.err
		}
		if n == policy.LimitBytes {
			u.say("限额未改变")
			return nil
		}
		policy.LimitBytes = n
		if n > 0 && p.trafficPolicy().LimitBytes == 0 && r.Incomplete {
			u.warn("本周期有一段时间未能计量（升级、重启或监控中断前），这部分流量无法补算")
			switch u.option("本周期用量如何处理？", []menuItem{itemNote("keep", "保留已知用量", "推荐：限额从已统计的用量继续计算"), itemNote("reset", "从零开始计算", "清零本期上传和下载")}, "keep") {
			case "keep":
				mode = trafficAcceptGap
			case "reset":
				if !u.yes("确认清零本期用量", false) {
					return u.err
				}
				mode = trafficReset
			default:
				return u.err
			}
		}
		if n > 0 {
			u.printf("达到 %s 后此节点会自动停止（其他节点不受影响），下次重置后自动恢复\n", FormatTraffic(n))
		}
	case "billing":
		for u.err == nil {
			n, e := strconv.Atoi(strings.TrimSpace(u.ask("每月重置日（1–31，大于当月天数时取月末）", itoa(policy.BillingDay))))
			if e == nil && n >= 1 && n <= 31 {
				policy.BillingDay = n
				break
			}
			u.say("请输入 1–31")
		}
		zone := u.ask(fmt.Sprintf(u.a.T("时区（直接回车 = 服务器时区 %s；或输入如 Asia/Shanghai、UTC）"), time.Local.String()), policy.Timezone)
		if strings.EqualFold(zone, "local") {
			zone = ""
		}
		policy.Timezone = zone
		u.say("修改重置日不会清零本期用量")
	case "reset":
		if !u.confirmWord("将清零本期上传和下载用量，此操作无法撤销", "reset") {
			u.say("已取消")
			return u.err
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
