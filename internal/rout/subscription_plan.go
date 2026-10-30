package rout

import (
	"errors"
	"fmt"
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// A subscription plan is the optional "package" shown to clients: a traffic allowance
// shared by every node of the subscription, a monthly reset day and an expiry date.
// Usage lives in subscription_pool.go; this file holds the stored settings and what
// clients see (informational nodes and the Subscription-Userinfo header).

const planDateLayout = "2006-01-02"

type SubscriptionPlan struct {
	// Shared allowance for all nodes of the subscription, decimal bytes; 0 = unlimited.
	LimitBytes uint64 `json:"limit_bytes,omitempty"`
	// Day of the month the allowance resets (1–31, clamped to short months); 0 means 1.
	BillingDay int    `json:"billing_day,omitempty"`
	Timezone   string `json:"timezone,omitempty"` // IANA name; empty is the server's local zone
	// Package expiry, YYYY-MM-DD. It is informational and renews: a date in the past is
	// shown as the same day of the next month. It never disables the subscription.
	Expires string `json:"expires,omitempty"`
}

func (p SubscriptionPlan) empty() bool { return p == SubscriptionPlan{} }

// policy reuses the per-node billing-cycle arithmetic for the shared allowance.
func (p SubscriptionPlan) policy() TrafficPolicy {
	day := p.BillingDay
	if day == 0 {
		day = 1
	}
	return TrafficPolicy{LimitBytes: p.LimitBytes, BillingDay: day, Timezone: p.Timezone}
}

func (p SubscriptionPlan) Validate() error {
	if p.LimitBytes > math.MaxInt64 || p.BillingDay < 0 || p.BillingDay > 31 {
		return errors.New("订阅流量额度或重置日无效")
	}
	if _, e := p.policy().location(); e != nil {
		return errors.New("账单时区无效，请使用 IANA 时区名称")
	}
	if p.Expires != "" {
		t, e := time.Parse(planDateLayout, p.Expires)
		if e != nil || t.Year() < 2000 || t.Year() > 2999 {
			return errors.New("到期日格式应为 YYYY-MM-DD")
		}
	}
	return nil
}

// ParsePlanDate accepts YYYY-MM-DD, or none, clear or empty to remove the date.
func ParsePlanDate(s string) (string, error) {
	v := strings.TrimSpace(normalizeInput(s))
	switch v {
	case "", "none", "clear":
		return "", nil
	}
	if _, e := time.Parse(planDateLayout, v); e != nil {
		return "", errors.New("到期日格式应为 YYYY-MM-DD")
	}
	return v, nil
}

func monthDate(base time.Time, months int, loc *time.Location) time.Time {
	first := time.Date(base.Year(), base.Month()+time.Month(months), 1, 12, 0, 0, 0, loc)
	day := base.Day()
	if last := time.Date(first.Year(), first.Month()+1, 0, 12, 0, 0, 0, loc).Day(); day > last {
		day = last
	}
	return time.Date(first.Year(), first.Month(), day, 0, 0, 0, 0, loc)
}

// nextExpiry is the date to show now. The stored date renews monthly once it has
// passed (it is still shown on the day itself), keeping the original day of month.
func (p SubscriptionPlan) nextExpiry(now time.Time) (time.Time, bool) {
	if p.Expires == "" {
		return time.Time{}, false
	}
	loc, e := p.policy().location()
	if e != nil {
		return time.Time{}, false
	}
	base, e := time.ParseInLocation(planDateLayout, p.Expires, loc)
	if e != nil {
		return time.Time{}, false
	}
	n := now.In(loc)
	today := time.Date(n.Year(), n.Month(), n.Day(), 0, 0, 0, 0, loc)
	if !base.Before(today) {
		return base, true
	}
	months := (today.Year()-base.Year())*12 + int(today.Month()-base.Month())
	if t := monthDate(base, months, loc); !t.Before(today) {
		return t, true
	}
	return monthDate(base, months+1, loc), true
}

func daysUntil(t, now time.Time) int {
	d := t.Sub(now)
	if d <= 0 {
		return 0
	}
	return int((d + 24*time.Hour - 1) / (24 * time.Hour))
}

// planView is the plan together with its usage, as of one moment.
type planView struct {
	Plan       SubscriptionPlan
	Used, Up   uint64
	Down       uint64
	Next       time.Time // next allowance reset
	Incomplete bool
}

func (v planView) remaining() uint64 {
	if v.Used >= v.Plan.LimitBytes {
		return 0
	}
	return v.Plan.LimitBytes - v.Used
}

// viewPlan combines a plan with its journal record. A record whose cycle has already
// ended (the monitor has not rolled it over yet) shows a fresh allowance.
func viewPlan(plan SubscriptionPlan, rec PoolRecord, have bool, now time.Time) planView {
	v := planView{Plan: plan}
	_, v.Next = trafficWindow(now, plan.policy())
	if have && now.Before(rec.Next) {
		v.Up, v.Down, v.Incomplete = rec.Up, rec.Down, rec.Incomplete
		v.Used = satAdd(rec.Up, rec.Down)
		v.Next = rec.Next
	}
	return v
}

// infoLines are the texts of the informational entries, in display order.
func (v planView) infoLines(lang string, now time.Time) []string {
	var out []string
	if v.Plan.LimitBytes > 0 {
		out = append(out, fmt.Sprintf(Translate(lang, "剩余流量：%s"), FormatTraffic(v.remaining())))
		out = append(out, fmt.Sprintf(Translate(lang, "距离下次重置剩余：%d 天"), daysUntil(v.Next, now)))
	}
	if t, ok := v.Plan.nextExpiry(now); ok {
		out = append(out, fmt.Sprintf(Translate(lang, "套餐到期：%s"), t.Format(planDateLayout)))
	}
	return out
}

// userinfo is the de-facto standard Subscription-Userinfo header (Clash Verge, Stash,
// Shadowrocket, Hiddify and others show it as a usage bar). Empty when nothing applies.
func (v planView) userinfo(now time.Time) string {
	var parts []string
	if v.Plan.LimitBytes > 0 {
		parts = append(parts, "upload="+strconv.FormatUint(v.Up, 10), "download="+strconv.FormatUint(v.Down, 10), "total="+strconv.FormatUint(v.Plan.LimitBytes, 10))
	}
	if t, ok := v.Plan.nextExpiry(now); ok {
		parts = append(parts, "expire="+strconv.FormatInt(t.Unix(), 10))
	}
	return strings.Join(parts, "; ")
}

// Informational entries are placeholders that point at a closed loopback port. They
// carry no credentials, never appear in automatic or fallback groups, and exist only so
// clients show the lines above in their node lists.
const (
	infoHost     = "127.0.0.1"
	infoPort     = 1
	infoPassword = "rout-info"
)

func infoURI(name string) string {
	u := url.URL{Scheme: "trojan", User: url.User(infoPassword), Host: infoHost + ":" + strconv.Itoa(infoPort), Fragment: name}
	return u.String()
}

func infoProxy(name string) M {
	return M{"name": name, "type": "trojan", "server": infoHost, "port": infoPort, "password": infoPassword, "udp": true}
}

// SubscriptionUsage reads the shared-allowance usage for display without taking any lock.
func (a *App) SubscriptionUsage(sub Subscription, now time.Time) (planView, bool) {
	if sub.Plan == nil || sub.Plan.empty() {
		return planView{}, false
	}
	pools, _ := a.loadPools()
	rec, have := pools.Records[sub.ID]
	return viewPlan(*sub.Plan, rec, have, now), true
}

// UpdateSubscriptionPlan changes the plan of one subscription under the configuration
// lock; a plan left empty is removed. A new finite allowance needs traffic monitoring,
// which supplies the usage it counts.
func (a *App) UpdateSubscriptionPlan(id string, change func(*SubscriptionPlan)) error {
	return a.editSubscription(id, func(s *State, sub *Subscription) error {
		var plan SubscriptionPlan
		if sub.Plan != nil {
			plan = *sub.Plan
		}
		before := plan
		change(&plan)
		if e := plan.Validate(); e != nil {
			return e
		}
		if plan.LimitBytes > 0 && plan.LimitBytes != before.LimitBytes && !a.trafficActive() {
			return errors.New("请先运行 rout traffic install，未启用流量监控")
		}
		if plan.empty() {
			sub.Plan = nil
			return nil
		}
		sub.Plan = &plan
		if plan.LimitBytes > 0 {
			s.Schema = 2 // like node limits: an old backup must not silently drop the allowance
		}
		return nil
	})
}

func (a *App) SetSubscriptionPlan(id string, plan SubscriptionPlan) error {
	return a.UpdateSubscriptionPlan(id, func(p *SubscriptionPlan) { *p = plan })
}
