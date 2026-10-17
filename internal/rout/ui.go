package rout

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type UI struct {
	a        *App
	in       *bufio.Reader
	out      io.Writer
	err      error
	detectIP func() string
	// Test hooks for the dual-stack setup; nil means the real host is inspected.
	detectAddrs  func() Addresses
	caps         func() listenCaps
	probeProxy   func(Proxy) (string, error)
	checkReality func(string) error
	// Presentation state: the logo appears once per session; tests can force it,
	// simulate a color terminal or fix the width.
	logoShown, forceLogo, forceColor bool
	termWidth                        int
}

func (u *UI) writer() io.Writer {
	if u.out != nil {
		return u.out
	}
	return os.Stdout
}
func (u *UI) say(s string)                 { fmt.Fprintln(u.writer(), u.a.T(s)) }
func (u *UI) printf(s string, args ...any) { fmt.Fprintf(u.writer(), u.a.T(s), args...) }
func (u *UI) ask(prompt, def string) string {
	if u.err != nil {
		return ""
	}
	if def != "" {
		fmt.Fprintf(u.writer(), "%s [%s]: ", u.a.T(prompt), def)
	} else {
		fmt.Fprint(u.writer(), u.a.T(prompt)+": ")
	}
	s, e := u.in.ReadString('\n')
	if e != nil && !(errors.Is(e, io.EOF) && s != "") {
		u.err = e
		return ""
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return def
	}
	return s
}
func (u *UI) secret(prompt string) string {
	if u.err != nil {
		return ""
	}
	st, e := os.Stdin.Stat()
	if e != nil || st.Mode()&os.ModeCharDevice == 0 || u.out != nil {
		return u.ask(prompt, "")
	}
	cmd := exec.Command("stty", "-g")
	cmd.Stdin = os.Stdin
	b, e := cmd.Output()
	if e != nil {
		return u.ask(prompt, "")
	}
	saved := strings.TrimSpace(string(b))
	set := func(arg string) { c := exec.Command("stty", arg); c.Stdin = os.Stdin; _ = c.Run() }
	set("-echo")
	defer set(saved)
	ch := make(chan os.Signal, 1)
	done := make(chan struct{})
	signal.Notify(ch, os.Interrupt)
	defer signal.Stop(ch)
	defer close(done)
	go func() {
		select {
		case <-ch:
			set(saved)
			fmt.Println()
			os.Exit(130)
		case <-done:
		}
	}()
	s := u.ask(u.a.T(prompt)+u.a.T("（输入隐藏）"), "")
	fmt.Fprintln(u.writer())
	return s
}
func (u *UI) choose(prompt string, allowed []string, def string) string {
	for u.err == nil {
		s := normalizeInput(u.ask(prompt, def))
		if u.err != nil {
			return ""
		}
		switch menuShortcut(s) {
		case "quit":
			u.err = errQuit
			return ""
		case "back":
			if contains(allowed, "0") {
				return "0"
			}
		}
		for _, v := range allowed {
			if s == v {
				return s
			}
		}
		u.say("请选择菜单中的编号")
	}
	return ""
}
func (u *UI) port(prompt string, def int) int {
	for u.err == nil {
		n, e := strconv.Atoi(u.ask(prompt, itoa(def)))
		if e == nil && validPort(n) {
			return n
		}
		u.say("端口应为 1–65535")
	}
	return 0
}
func (u *UI) initLanguage(force bool) error {
	s, e := u.a.LoadSettings()
	if e != nil {
		return e
	}
	if !force && u.a.Language != "" {
		return nil
	}
	if !force && s.Language != "" {
		u.a.Language = s.Language
		return nil
	}
	fmt.Fprintln(u.writer(), "请选择语言 / Select language\n1. 简体中文\n2. English")
	v := u.choose("Language", []string{"1", "2"}, "1")
	if u.err != nil {
		return u.err
	}
	s.Language = map[string]string{"1": "zh-CN", "2": "en"}[v]
	u.a.Language = s.Language
	return u.a.SaveSettings(s)
}

func ProtocolLabel(p string) string {
	return map[string]string{"vless": "VLESS", "anytls": "AnyTLS", "ss": "SS", "hy2": "HY2", "tuic": "TUIC", "tcp": "TCP", "udp": "UDP", "both": "TCP+UDP"}[p]
}

// outboundLabel names the outbound proxy a node uses ("Direct connection" if none).
// Relays have no outbound proxy: their destination is shown instead.
func (u *UI) outboundLabel(s State, p Profile) string {
	if p.ExitID != "" {
		if e, er := FindExit(s, p.ExitID); er == nil {
			return e.Name + " (" + strings.ToUpper(e.Proxy.Protocol) + ")"
		}
	}
	if p.Outbound != nil {
		return strings.ToUpper(p.Outbound.Protocol) + " " + net.JoinHostPort(p.Outbound.Host, itoa(p.Outbound.Port))
	}
	return u.a.T("直连")
}

// usage summarizes a node's traffic for list views; db may be nil (not monitored).
func (u *UI) usage(db *TrafficState, p Profile) string {
	policy := p.trafficPolicy()
	if db == nil {
		if policy.LimitBytes > 0 {
			return fmt.Sprintf(u.a.T("限额 %s（流量统计未启用）"), FormatTraffic(policy.LimitBytes))
		}
		return u.a.T("不限流量（流量统计未启用）")
	}
	quota := u.a.T("不限流量")
	if policy.LimitBytes > 0 {
		quota = fmt.Sprintf(u.a.T("限额 %s"), FormatTraffic(policy.LimitBytes))
	}
	r, ok := db.Records[p.ID]
	if !ok {
		return quota
	}
	_, _, total, e := r.totals()
	if e != nil {
		return quota
	}
	line := fmt.Sprintf(u.a.T("已用 %s"), FormatTraffic(total))
	if policy.LimitBytes > 0 {
		left := uint64(0)
		if total < policy.LimitBytes {
			left = policy.LimitBytes - total
		}
		line = fmt.Sprintf(u.a.T("已用 %s / %s，剩余 %s"), FormatTraffic(total), FormatTraffic(policy.LimitBytes), FormatTraffic(left))
	} else {
		line += " · " + u.a.T("不限流量")
	}
	switch r.Blocked {
	case blockQuota:
		line += " · " + u.paint("33", u.a.T("已达上限，已暂停"))
	case blockFault:
		line += " · " + u.paint("33", u.a.T("计量故障，已暂停"))
	case blockSealed:
		line += " · " + u.a.T("等待流量监控")
	}
	return line
}
func (u *UI) trafficDB() *TrafficState {
	if !u.a.trafficActive() {
		return nil
	}
	db, e := u.a.loadTraffic()
	if e != nil {
		return nil
	}
	return &db
}

// nodeStatus is one word: Running, Stopped or Disabled.
func (u *UI) nodeStatus(p Profile) string {
	if !p.Enabled {
		return u.a.T("已停用")
	}
	return u.a.Running(p)
}

// nodeCard is a credential-free summary that fits narrow/mobile terminals.
func (u *UI) nodeCard(s State, i int, p Profile, db *TrafficState) {
	if p.Kind == "relay" {
		u.relayCard(i, p)
		return
	}
	prefix := "   "
	if i > 0 {
		prefix = u.paint("36", fmt.Sprintf("%2d.", i))
	}
	fmt.Fprintf(u.writer(), "  %s %s %s\n", prefix, u.bold(p.Name), u.dim("["+p.ID+"]"))
	fmt.Fprintf(u.writer(), "      %s · %s · %s %d · %s %s\n", ProtocolLabel(p.Protocol), u.nodeStatus(p), u.a.T("监听端口"), p.Port, u.a.T("公网"), net.JoinHostPort(p.PublicHost, itoa(p.PublicPort)))
	line := u.a.T("出站：") + u.outboundLabel(s, p)
	if use := u.usage(db, p); use != "" {
		line += " · " + use
	}
	fmt.Fprintln(u.writer(), "      "+line)
	if days, ok := p.CertificateDays(time.Now()); ok {
		if days < 0 {
			fmt.Fprintln(u.writer(), "      "+u.paint("31", u.a.T("证书已过期，请在证书管理中更新")))
		} else if days <= certificateWarnDays {
			fmt.Fprintln(u.writer(), "      "+u.paint("33", fmt.Sprintf(u.a.T("证书 %d 天后过期，请在证书管理中更新"), days)))
		}
	}
}
func (u *UI) viewNodes(s State) {
	if len(s.Profiles) == 0 {
		u.say("暂无节点")
		return
	}
	db := u.trafficDB()
	for i, p := range s.Profiles {
		u.nodeCard(s, i+1, p, db)
	}
}

// list is the explicit `rout list` view: every node and relay with its complete link.
func (u *UI) list(s State) {
	if len(s.Profiles) == 0 {
		u.say("暂无节点")
		return
	}
	db := u.trafficDB()
	for i, p := range s.Profiles {
		u.nodeCard(s, i+1, p, db)
		if uri, e := p.URI(); e == nil {
			fmt.Fprintln(u.writer(), "      "+uri)
			if st, er := u.a.LoadSettings(); er == nil && st.Server != nil {
				if label, alt, ok := altLink(*st.Server, p); ok {
					fmt.Fprintln(u.writer(), "      "+label+": "+alt)
				}
			}
		} else if p.Kind == "relay" {
			fmt.Fprintln(u.writer(), "      "+u.a.T("客户端连接地址：")+relayEndpoint(p))
		}
	}
}
func nodesOnly(s State) State {
	out := s.Clone()
	out.Profiles = nil
	for _, p := range s.Profiles {
		if p.Kind == "node" {
			out.Profiles = append(out.Profiles, p)
		}
	}
	return out
}

// pick shows credential-free cards; links appear only when explicitly requested.
func (u *UI) pick(s State, nodeOnly bool) (Profile, error) {
	choices := s
	if nodeOnly {
		choices = nodesOnly(s)
	}
	if len(choices.Profiles) == 0 {
		return Profile{}, errors.New("没有可选节点，请先创建节点")
	}
	u.viewNodes(choices)
	n := u.number("选择节点编号（0 返回）", len(choices.Profiles))
	if n <= 0 {
		return Profile{}, nil
	}
	return choices.Profiles[n-1], nil
}

// pickMany selects several entries ("1 3", "1,3" or "all"); empty means cancel.
func (u *UI) pickMany(s State, prompt string) []Profile {
	if len(s.Profiles) == 0 {
		u.say("暂无节点")
		return nil
	}
	u.viewNodes(s)
	for u.err == nil {
		raw := normalizeInput(u.ask(prompt, ""))
		if u.err != nil || raw == "" || raw == "0" || menuShortcut(raw) == "back" {
			return nil
		}
		if menuShortcut(raw) == "quit" {
			u.err = errQuit
			return nil
		}
		if raw == "all" || raw == "全部" {
			return append([]Profile(nil), s.Profiles...)
		}
		var out []Profile
		seen := map[int]bool{}
		ok := true
		for _, f := range strings.Fields(strings.ReplaceAll(raw, ",", " ")) {
			n, e := strconv.Atoi(f)
			if e != nil || n < 1 || n > len(s.Profiles) || seen[n] {
				ok = false
				break
			}
			seen[n] = true
			out = append(out, s.Profiles[n-1])
		}
		if ok && len(out) > 0 {
			return out
		}
		u.say("编号无效")
	}
	return nil
}
func (u *UI) exitUsers(s State, id string) []Profile {
	var out []Profile
	for _, p := range s.Profiles {
		if p.ExitID == id {
			out = append(out, p)
		}
	}
	return out
}

// outboundLine renders "Name — PROTOCOL — host:port — usage".
func (u *UI) outboundLine(s State, i int, e Exit) {
	use := u.a.T("未分配")
	if n := len(u.exitUsers(s, e.ID)); n > 0 {
		use = fmt.Sprintf(u.a.T("%d 个节点使用"), n)
	}
	fmt.Fprintf(u.writer(), "  %s %s — %s — %s — %s\n", u.paint("36", fmt.Sprintf("%2d.", i)), u.bold(e.Name), strings.ToUpper(e.Proxy.Protocol), net.JoinHostPort(e.Proxy.Host, itoa(e.Proxy.Port)), u.dim(use))
}

// pickProxy selects an existing outbound proxy by its displayed number.
func (u *UI) pickProxy(s State) (Exit, bool) {
	if len(s.Exits) == 0 {
		u.say("暂无出站代理，请先创建")
		return Exit{}, false
	}
	for i, e := range s.Exits {
		u.outboundLine(s, i+1, e)
	}
	n := u.number("选择出站代理编号（0 返回）", len(s.Exits))
	if n <= 0 {
		return Exit{}, false
	}
	return s.Exits[n-1], true
}

// pickOutbound chooses what a node uses: one of the proxies, or Direct connection as
// the last numbered entry. ok=false means the user went back.
func (u *UI) pickOutbound(s State, current string) (string, bool) {
	for i, e := range s.Exits {
		u.outboundLine(s, i+1, e)
	}
	direct := len(s.Exits) + 1
	fmt.Fprintf(u.writer(), "  %s %s\n", u.paint("36", fmt.Sprintf("%2d.", direct)), u.bold(u.a.T("直连（不使用出站代理）")))
	def := itoa(direct)
	for i, e := range s.Exits {
		if e.ID == current {
			def = itoa(i + 1)
		}
	}
	allowed := []string{"0"}
	for i := 1; i <= direct; i++ {
		allowed = append(allowed, itoa(i))
	}
	v := u.choose("选择出站（0 返回）", allowed, def)
	n, _ := strconv.Atoi(v)
	if u.err != nil || n == 0 {
		return "", false
	}
	if n == direct {
		return "", true
	}
	return s.Exits[n-1].ID, true
}

// uniqueName keeps generated batch names distinct from every existing node.
func uniqueName(s State, name string) string {
	taken := map[string]bool{}
	for _, p := range s.Profiles {
		taken[strings.ToLower(p.Name)] = true
	}
	candidate := name
	for i := 2; taken[strings.ToLower(candidate)]; i++ {
		candidate = name + "-" + itoa(i)
	}
	return candidate
}
func (u *UI) realityCheck(sni string) error {
	if u.checkReality != nil {
		return u.checkReality(sni)
	}
	return CheckRealityTarget(sni)
}
func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
func (u *UI) readCertificate() (string, string, error) {
	cert := u.ask("PEM 证书文件路径", "")
	key := u.ask("PEM 私钥文件路径", "")
	if u.err != nil {
		return "", "", u.err
	}
	c, e := os.ReadFile(cert)
	if e != nil {
		return "", "", errors.New("无法读取证书")
	}
	k, e := os.ReadFile(key)
	if e != nil {
		return "", "", errors.New("无法读取私钥")
	}
	return string(c), string(k), nil
}

// bindProfile sets one node's outbound proxy (or direct connection).
func (u *UI) bindProfile(old State, p Profile) error {
	if p.Kind != "node" {
		return errors.New("中转节点没有出站代理：它把流量原样转发到目标")
	}
	u.printf("当前出站：%s\n", u.outboundLabel(old, p))
	id, ok := u.pickOutbound(old, p.ExitID)
	if !ok {
		return u.err
	}
	return u.assignOutbound(old, []Profile{p}, id)
}

// assignOutbound binds the chosen nodes, and only those, to one outbound in a single
// transaction. A proxy is tested once before any node changes.
func (u *UI) assignOutbound(old State, nodes []Profile, id string) error {
	var changed []Profile
	for _, p := range nodes {
		if p.Kind != "node" || p.ExitID == id {
			continue
		}
		// Rejected combinations are skipped up front instead of failing the whole batch.
		if id != "" {
			probe := p
			probe.Outbound = &Proxy{}
			if e := probe.CheckCompatibility(); e != nil {
				u.warnf("%s: %s", p.Name, u.a.Error(e))
				continue
			}
		}
		changed = append(changed, p)
	}
	if len(changed) == 0 {
		u.say("出站未改变")
		return nil
	}
	label := u.a.T("直连")
	if id != "" {
		ex, e := FindExit(old, id)
		if e != nil {
			return e
		}
		label = ex.Name
		u.say("正在测试出站代理…")
		ip, e := u.testExit(ex.Proxy)
		if e != nil {
			return e
		}
		u.printf("实际出口 IP：%s\n", ip)
	}
	next := old
	var names []string
	for _, p := range changed {
		var e error
		if next, e = BindExit(next, p.ID, id); e != nil {
			return e
		}
		names = append(names, p.Name)
	}
	u.printf("将以下节点的出站改为 %s：%s（会重启这些节点）\n", label, strings.Join(names, "、"))
	if !u.yes("确认修改", true) {
		return u.err
	}
	if e := u.a.Commit(old, next, false); e != nil {
		return e
	}
	u.good("出站已更新")
	return nil
}
func (u *UI) proxyInput() (Proxy, error) {
	protocol := u.option("代理协议", []menuItem{item("socks5", "SOCKS5"), item("http", "HTTP CONNECT")}, "socks5")
	for u.err == nil {
		raw := u.secret("输入代理 IP:端口:用户名:密码（IPv6 使用 [地址]:端口:用户名:密码）")
		if u.err != nil {
			return Proxy{}, u.err
		}
		p, e := ParseProxy(protocol, raw)
		if e == nil {
			return *p, nil
		}
		u.say(u.a.Error(e))
	}
	return Proxy{}, u.err
}
func (u *UI) testExit(p Proxy) (string, error) {
	if u.probeProxy != nil {
		return u.probeProxy(p)
	}
	return u.a.ProbeProxy(p)
}

// outbounds is Outbound Proxy Management. Proxies are chosen by displayed number;
// their stable IDs remain the persistent references in the configuration.
func (u *UI) outbounds() error {
	for {
		s, e := u.a.Load()
		if e != nil {
			return e
		}
		u.heading("出站代理")
		u.say("出站代理决定节点访问互联网时使用的出口；不设置则为直连。中转节点不使用出站代理。")
		if len(s.Exits) == 0 {
			u.say("暂无出站代理")
		}
		for i, ex := range s.Exits {
			u.outboundLine(s, i+1, ex)
		}
		direct := 0
		for _, p := range u.exitUsers(s, "") {
			if p.Kind == "node" {
				direct++
			}
		}
		use := u.a.T("未分配")
		if direct > 0 {
			use = fmt.Sprintf(u.a.T("%d 个节点使用"), direct)
		}
		fmt.Fprintf(u.writer(), "  %s %s — %s — %s\n", u.paint("36", "  ·"), u.bold(u.a.T("直连")), u.a.T("内置，不经过代理"), u.dim(use))
		v := u.menu("", []menuItem{item("add", "创建出站代理"), item("edit", "编辑出站代理"), item("test", "测试出站代理"), item("delete", "删除出站代理"), item("assign", "分配给节点")}, "返回")
		if u.err != nil || v == "" {
			return u.err
		}
		if e = u.outboundAction(s, v); e != nil {
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
func proxyName(p Proxy) string { return strings.ToUpper(p.Protocol) + "-" + p.Host }
func (u *UI) outboundAction(s State, v string) error {
	switch v {
	case "add":
		p, e := u.proxyInput()
		if e != nil {
			return e
		}
		name := u.ask("出站代理名称", proxyName(p))
		if u.err != nil {
			return u.err
		}
		next := UpsertExit(s, Exit{ID: RandomHex(6), Name: name, Proxy: p})
		if e = u.a.Commit(s, next, false); e != nil {
			return e
		}
		u.good("出站代理已保存；未改变任何节点。可在『分配给节点』中使用")
		return nil
	case "assign":
		u.say("1. 选择出站")
		id, ok := u.pickOutbound(s, "")
		if !ok {
			return u.err
		}
		u.say("2. 选择要使用它的节点")
		nodes := u.pickMany(nodesOnly(s), "节点编号，可多选，如 1 3，或 all（0 返回）")
		if len(nodes) == 0 {
			return u.err
		}
		return u.assignOutbound(s, nodes, id)
	}
	ex, ok := u.pickProxy(s)
	if !ok {
		return u.err
	}
	users := u.exitUsers(s, ex.ID)
	switch v {
	case "test":
		u.say("正在测试出站代理…")
		ip, e := u.testExit(ex.Proxy)
		if e != nil {
			return e
		}
		u.good(fmt.Sprintf(u.a.T("出站代理可用，实际出口 IP：%s"), ip))
	case "edit":
		ex.Name = u.ask("出站代理名称", ex.Name)
		previous := ex.Proxy
		if u.yes("修改代理地址或认证信息", false) {
			var e error
			if ex.Proxy, e = u.proxyInput(); e != nil {
				return e
			}
		}
		if u.err != nil {
			return u.err
		}
		if ex.Proxy != previous && len(users) > 0 {
			if _, e := u.testExit(ex.Proxy); e != nil {
				return e
			}
			if !u.yes(fmt.Sprintf(u.a.T("保存修改（将重启使用它的 %d 个节点）"), len(users)), true) {
				return u.err
			}
		}
		if e := u.a.Commit(s, UpsertExit(s, ex), false); e != nil {
			return e
		}
		u.good("出站代理已更新")
	case "delete":
		if len(users) > 0 {
			var names []string
			for _, p := range users {
				names = append(names, p.Name)
			}
			return fmt.Errorf(u.a.T("出站代理仍被以下节点使用：%s；请先在『分配给节点』中改为其他出站或直连"), strings.Join(names, "、"))
		}
		next, e := DeleteExit(s, ex.ID)
		if e != nil {
			return e
		}
		if !u.yes(fmt.Sprintf(u.a.T("删除出站代理 %s"), ex.Name), false) {
			return u.err
		}
		if e = u.a.Commit(s, next, false); e != nil {
			return e
		}
		u.good("出站代理已删除")
	}
	return nil
}
func (u *UI) copy(p Profile) error {
	uri, e := p.URI()
	if e != nil {
		return e
	}
	if e = u.printLinks(p, nil); e != nil {
		return e
	}
	if u.out == nil {
		if st, e := os.Stdout.Stat(); e == nil && st.Mode()&os.ModeCharDevice != 0 {
			fmt.Fprintf(u.writer(), "\033]52;c;%s\a", base64.StdEncoding.EncodeToString([]byte(uri)))
			u.say("已发送终端复制请求；若终端不支持，请手动复制以上完整链接")
			return nil
		}
	}
	u.say("请复制以上完整链接")
	return nil
}
func (u *UI) exportClient(p Profile) error {
	c, e := ClientConfig(p, p.PublicHost, p.PublicPort, 2080)
	if e != nil {
		return e
	}
	path := u.ask("保存路径", filepath.Join(u.a.Home, "exports", p.ID+"-client.json"))
	if u.err != nil {
		return u.err
	}
	b, e := JSON(c)
	if e != nil {
		return e
	}
	if e = AtomicWrite(path, b, 0600); e != nil {
		return e
	}
	u.printf("已保存：%s\n", path)
	return nil
}
func (u *UI) export(p Profile) error {
	if e := u.copy(p); e != nil {
		return e
	}
	if !u.yes("同时导出 sing-box 客户端配置", false) {
		return u.err
	}
	return u.exportClient(p)
}

// AllLinks renders every node's name and complete share link (credentials included).
func AllLinks(s State) string {
	var b strings.Builder
	for _, p := range s.Profiles {
		if uri, e := p.URI(); e == nil {
			fmt.Fprintf(&b, "# %s [%s]\n%s\n", p.Name, p.ID, uri)
		}
	}
	return b.String()
}

// allLinks is AllLinks plus, on a dual-stack host, each node's link for the other address family.
func (u *UI) allLinks(s State) string {
	var setup *ServerSetup
	if st, e := u.a.LoadSettings(); e == nil {
		setup = st.Server
	}
	var b strings.Builder
	for _, p := range s.Profiles {
		uri, e := p.URI()
		if e != nil {
			continue
		}
		fmt.Fprintf(&b, "# %s [%s]\n%s\n", p.Name, p.ID, uri)
		if setup != nil {
			if label, alt, ok := altLink(*setup, p); ok {
				fmt.Fprintf(&b, "# %s [%s] %s\n%s\n", p.Name, p.ID, label, alt)
			}
		}
	}
	return b.String()
}
func (u *UI) exportAll(s State) error {
	links := u.allLinks(s)
	if links == "" {
		u.say("暂无可导出的节点链接")
		return nil
	}
	u.warn("以下链接包含客户端凭据，请勿公开分享")
	fmt.Fprint(u.writer(), links)
	if !u.yes("同时保存为文件", false) {
		return u.err
	}
	path := u.ask("保存路径", filepath.Join(u.a.Home, "exports", "links.txt"))
	if u.err != nil {
		return u.err
	}
	if e := AtomicWrite(path, []byte(links), 0600); e != nil {
		return e
	}
	u.printf("已保存：%s\n", path)
	return nil
}
func (u *UI) links() error {
	v := u.menu("连接链接", []menuItem{item("one", "查看或复制单个节点链接"), item("all", "查看全部节点链接"), item("client", "导出 sing-box 客户端配置")}, "返回")
	if v == "" {
		return u.err
	}
	s, e := u.a.Load()
	if e != nil {
		return e
	}
	if v == "all" {
		return u.exportAll(s)
	}
	p, e := u.pick(s, false)
	if e != nil || p.ID == "" {
		return e
	}
	if v == "client" {
		return u.exportClient(p)
	}
	return u.copy(p)
}

// manage is Node Management (proxy nodes; relays have their own menu).
func (u *UI) manage() error {
	for {
		v := u.menu("节点管理", []menuItem{item("view", "查看节点"), item("add", "创建节点"), item("edit", "编辑节点"), item("delete", "删除节点"), item("restart", "重启节点"), item("links", "连接链接")}, "返回")
		if u.err != nil || v == "" {
			return u.err
		}
		var e error
		switch v {
		case "view":
			var s State
			if s, e = u.a.Load(); e == nil {
				u.viewNodes(nodesOnly(s))
			}
		case "add":
			e = u.create()
		case "links":
			e = u.links()
		default:
			var s State
			var p Profile
			if s, e = u.a.Load(); e == nil {
				if p, e = u.pick(s, true); e == nil && p.ID != "" {
					switch v {
					case "edit":
						e = u.nodeMenu(p.ID)
					case "delete":
						if u.yes(fmt.Sprintf(u.a.T("删除 %s 及其服务"), p.Name), false) {
							if e = u.a.Commit(s, removeProfile(s, p.ID), false); e == nil {
								u.good("节点已删除")
							}
						}
					case "restart":
						if e = u.a.Restart(p.ID); e == nil {
							u.good("节点已重启")
						}
					}
				}
			}
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

// nodeMenu shows only the operations that apply to the selected node.
func (u *UI) nodeMenu(id string) error {
	for {
		s, e := u.a.Load()
		if e != nil {
			return e
		}
		p, e := Find(s, id)
		if e != nil {
			return e
		}
		if p.Kind == "relay" {
			return u.relayEdit(p.ID)
		}
		u.heading(p.Name)
		u.nodeCard(s, 0, p, u.trafficDB())
		toggle := "停用节点"
		if !p.Enabled {
			toggle = "启用节点"
		}
		items := []menuItem{item("link", "查看或复制连接链接"), item("name", "重命名"), item("address", "修改端口或公网地址"), item("exit", "选择出站代理"), item("toggle", toggle), item("test", "测试连接"), item("logs", "查看日志"), item("traffic", "流量与限额"), item("credentials", "重置认证凭据")}
		if _, ok := p.CertificateExpiry(); ok {
			items = append(items, item("cert", "证书管理"))
		}
		v := u.menu("", items, "返回")
		if u.err != nil || v == "" {
			return u.err
		}
		if e = u.nodeAction(s, p, v); e != nil {
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

// nodeAddress edits the listening port or the public endpoint. On a regular VPS the
// public port follows the listening port; on NAT it is the provider's mapping.
func (u *UI) nodeAddress(p *Profile) error {
	v := u.option("修改哪一项？", []menuItem{
		itemNote("port", "监听端口", "本服务器上节点实际监听的端口"),
		itemNote("public", "公网地址和端口", "客户端连接使用的地址；写入分享链接（仅当需要改为监听 IPv6 时才会重启节点）"),
	}, "port")
	if u.err != nil {
		return u.err
	}
	settings, e := u.a.LoadSettings()
	if e != nil {
		return e
	}
	if v == "public" {
		for u.err == nil {
			p.PublicHost = u.ask("公网 IP 或域名", p.PublicHost)
			if validPublicHost(p.PublicHost) {
				break
			}
			u.say("地址无效：不能是空值、未指定地址或链路本地地址（如 fe80::）")
		}
		p.PublicPort = u.askPortValue("公网端口", p.PublicPort)
		if u.err == nil {
			u.fitListen(p)
		}
		return u.err
	}
	oldPort := p.Port
	p.Port = u.askPortValue("监听端口", p.Port)
	if u.err != nil {
		return u.err
	}
	if !p.NAT {
		if p.PublicPort == oldPort {
			p.PublicPort = p.Port
		}
		return nil
	}
	def := 0
	if settings.Server != nil && settings.Server.NAT && p.Port >= settings.Server.LocalStart && p.Port <= settings.Server.LocalEnd {
		def = settings.Server.PublicStart + p.Port - settings.Server.LocalStart
	} else if settings.Server != nil && settings.Server.NAT {
		u.warnf("端口 %d 不在已保存的 NAT 范围 %d-%d 内，请确认商家确实映射了此端口", p.Port, settings.Server.LocalStart, settings.Server.LocalEnd)
	}
	p.PublicPort = u.askPortValue(fmt.Sprintf(u.a.T("商家映射到内部端口 %d 的公网端口"), p.Port), def)
	return u.err
}
func (u *UI) nodeAction(s State, p Profile, v string) error {
	switch v {
	case "link":
		return u.export(p)
	case "exit":
		return u.bindProfile(s, p)
	case "test":
		return u.a.Probe(p)
	case "logs":
		return u.a.Logs(p)
	case "traffic":
		return u.trafficManage(p)
	case "cert":
		return u.certificate(s, p)
	case "name":
		p.Name = u.ask("节点名称", p.Name)
	case "address":
		if e := u.nodeAddress(&p); e != nil {
			return e
		}
	case "toggle":
		if p.Enabled && !u.yes(fmt.Sprintf(u.a.T("停用 %s（服务会停止，客户端将无法连接）"), p.Name), true) {
			return u.err
		}
		p.Enabled = !p.Enabled
	case "credentials":
		if !u.yes("重置后旧链接立即失效，需要重新导入客户端链接", false) {
			return u.err
		}
		fresh, e := NewProfile(p.Protocol)
		if e != nil {
			return e
		}
		p.Password = fresh.Password
		p.UUID = fresh.UUID
		p.PrivateKey = fresh.PrivateKey
		p.PublicKey = fresh.PublicKey
		p.ShortID = fresh.ShortID
	}
	if u.err != nil {
		return u.err
	}
	if e := u.a.Commit(s, replace(s, p), false); e != nil {
		return e
	}
	u.good("已保存")
	if v == "credentials" || v == "address" {
		return u.copy(p)
	}
	return nil
}

// certificate shows validity and replaces a HY2/TUIC certificate on explicit request.
// Rotation is never automatic: every replacement changes what clients must trust.
func (u *UI) certificate(s State, p Profile) error {
	end, _ := p.CertificateExpiry()
	days, _ := p.CertificateDays(time.Now())
	kind := u.a.T("现有 PEM 证书")
	if p.TLSGenerated {
		kind = u.a.T("自签证书（链接含指纹）")
	}
	u.printf("证书：%s · %s · 到期 %s（剩余 %d 天）\n", kind, p.SNI, end.Format("2006-01-02"), days)
	v := u.menu("", []menuItem{item("self", "重新生成自签证书"), item("pem", "改用现有 PEM 证书文件")}, "返回")
	if v == "" {
		return u.err
	}
	var e error
	if v == "self" {
		u.warn("新证书的指纹会改变：所有客户端必须重新导入链接或客户端配置")
		if !u.yes("重新生成证书", false) {
			return u.err
		}
		if p, e = RegenerateCertificate(p); e != nil {
			return e
		}
	} else {
		p.SNI = u.ask("TLS 证书域名或 IP", p.SNI)
		if p.CertPEM, p.KeyPEM, e = u.readCertificate(); e != nil {
			return e
		}
		p.TLSGenerated = false
	}
	if e = u.a.Commit(s, replace(s, p), false); e != nil {
		return e
	}
	u.good("证书已更新；请重新导入以下链接")
	return u.copy(p)
}

// trafficMenu is Traffic and Limits: an overview of every node, then one node.
func (u *UI) trafficMenu() error {
	s, e := u.a.Load()
	if e != nil {
		return e
	}
	u.heading("流量与限额")
	if !u.a.trafficActive() {
		u.warn("流量统计未启用：运行 rout traffic install（需要 nftables）")
	}
	if len(s.Profiles) == 0 {
		u.say("暂无节点")
		return nil
	}
	db := u.trafficDB()
	for i, p := range s.Profiles {
		use := u.usage(db, p)
		if use == "" {
			use = u.a.T("暂无数据")
		}
		fmt.Fprintf(u.writer(), "  %s %s  %s\n", u.paint("36", fmt.Sprintf("%2d.", i+1)), u.bold(p.Name), use)
	}
	n := u.number("选择节点编号查看或设置限额（0 返回）", len(s.Profiles))
	if n <= 0 {
		return u.err
	}
	return u.trafficManage(s.Profiles[n-1])
}

// services is Service Management for every node and relay plus the traffic monitor.
func (u *UI) services() error {
	for {
		v := u.menu("服务管理", []menuItem{item("status", "服务状态"), item("restart", "重启节点或中转"), item("toggle", "启动或停止节点或中转"), item("logs", "查看日志"), item("apply", "重新应用全部配置"), item("monitor", "安装或更新流量监控服务")}, "返回")
		if u.err != nil || v == "" {
			return u.err
		}
		s, e := u.a.Load()
		if e == nil {
			switch v {
			case "status":
				if len(s.Profiles) == 0 {
					u.say("暂无节点")
				}
				for _, p := range s.Profiles {
					kind := ProtocolLabel(p.Protocol)
					if p.Kind == "relay" {
						kind = u.a.T("中转")
					}
					fmt.Fprintf(u.writer(), "  %s  %s  %s\n", pad(p.Name, 24), pad(kind, 8), u.nodeStatus(p))
				}
				if u.a.trafficActive() {
					m, _ := u.a.serviceManager()
					state := u.a.T("未运行")
					if m == "none" || serviceActive(m, u.a.trafficService()) {
						state = u.a.T("运行中")
					}
					fmt.Fprintf(u.writer(), "  %s  %s\n", pad(u.a.T("流量监控"), 34), state)
				}
			case "apply":
				if u.yes("重新校验并应用全部配置（会依次重启所有节点和中转）", false) {
					if e = u.a.Commit(s, s, true); e == nil {
						u.good("已重新应用")
					}
				}
			case "monitor":
				if e = u.a.InstallTraffic(); e == nil {
					u.good("流量监控服务已就绪")
				}
			default:
				var p Profile
				if p, e = u.pick(s, false); e == nil && p.ID != "" {
					switch v {
					case "restart":
						if e = u.a.Restart(p.ID); e == nil {
							u.good("已重启")
						}
					case "logs":
						e = u.a.Logs(p)
					case "toggle":
						if p.Enabled && !u.yes(fmt.Sprintf(u.a.T("停用 %s（服务会停止，客户端将无法连接）"), p.Name), true) {
							break
						}
						p.Enabled = !p.Enabled
						if e = u.a.Commit(s, replace(s, p), false); e == nil {
							u.good("已保存")
						}
					}
				}
			}
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
func (u *UI) settings() error {
	for {
		v := u.menu("设置", []menuItem{item("language", "语言 / Language"), item("server", "服务器地址（IPv4 / IPv6）"), item("backups", "自动备份保留数量"), item("backup", "备份与恢复"), item("uninstall", "卸载 Rout")}, "返回")
		if u.err != nil || v == "" {
			return u.err
		}
		var e error
		switch v {
		case "language":
			e = u.initLanguage(true)
		case "server":
			e = u.serverMenu()
		case "backups":
			e = u.backupRetention()
		case "backup":
			e = u.backupMenu()
		case "uninstall":
			if u.confirmWord("卸载会删除所有节点、中转、出站代理、配置、备份和 Rout 程序；其他软件不受影响", "uninstall") {
				if e = u.a.Uninstall(); e == nil {
					u.err = errQuit
				}
			} else {
				u.say("已取消")
			}
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
func (u *UI) backupRetention() error {
	saved, e := u.a.LoadSettings()
	if e != nil {
		return e
	}
	keep := saved.BackupKeep
	if keep == 0 {
		keep = defaultBackupKeep
	}
	for u.err == nil {
		n, e := strconv.Atoi(strings.TrimSpace(u.ask("保留最近的自动备份数量（1–1000）", itoa(keep))))
		if e == nil && n >= 1 && n <= 1000 {
			saved.BackupKeep = n
			break
		}
		u.say("请输入 1–1000")
	}
	if u.err != nil {
		return u.err
	}
	if saved.Language == "" {
		saved.Language = u.a.Language
	}
	return u.a.SaveSettings(saved)
}

// defaultBackupPath lives outside the configuration directory, which uninstall removes.
func (u *UI) defaultBackupPath() string {
	dir := "/root"
	if u.a.Home != "/etc/rout" {
		dir = filepath.Dir(u.a.Home)
	}
	return filepath.Join(dir, "rout-backup-"+time.Now().Format("20060102")+".json")
}
func (u *UI) backupMenu() error {
	v := u.menu("备份与恢复", []menuItem{item("backup", "创建备份"), item("restore", "从备份恢复")}, "返回")
	if v == "" {
		return u.err
	}
	path := u.ask("备份文件路径", u.defaultBackupPath())
	if u.err != nil {
		return u.err
	}
	if v == "backup" {
		if e := u.a.Backup(path); e != nil {
			return e
		}
		u.good("备份已保存（包含认证信息和私钥，请妥善保管）")
		return nil
	}
	if !u.yes("使用备份替换当前配置（当前配置会先自动备份）", false) {
		return u.err
	}
	if e := u.a.Restore(path); e != nil {
		return e
	}
	u.good("配置已恢复")
	return nil
}
func (u *UI) updates() error {
	v := u.menu("更新", []menuItem{item("rout", "更新 Rout（拒绝降级，现有节点继续运行）"), item("engines", "检查并修复内核程序（sing-box / GOST）")}, "返回")
	switch v {
	case "rout":
		return SelfUpdate(u.a.Language)
	case "engines":
		for _, name := range []string{"sing-box", "gost"} {
			if e := u.a.EnsureEngine(name); e != nil {
				return e
			}
		}
		u.good("内核程序已就绪并通过校验")
	}
	return u.err
}

// summary is one status line above the main menu.
func (u *UI) summary(s State) string {
	nodes, relays, running, paused := 0, 0, 0, 0
	db := u.trafficDB()
	for _, p := range s.Profiles {
		if p.Kind == "relay" {
			relays++
		} else {
			nodes++
		}
		if p.Enabled && u.a.Running(p) == u.a.T("运行中") {
			running++
		}
		if db != nil && db.Records[p.ID].Blocked != "" && p.trafficPolicy().LimitBytes > 0 {
			paused++
		}
	}
	line := fmt.Sprintf(u.a.T("%d 个节点 · %d 个中转 · %d 个运行中"), nodes, relays, running)
	if paused > 0 {
		line += " · " + fmt.Sprintf(u.a.T("%d 个因流量暂停"), paused)
	}
	return line
}

// notices lists conditions that need attention, shown once when the menu opens.
func (u *UI) notices(s State) {
	now := time.Now()
	limited := false
	for _, p := range s.Profiles {
		if days, ok := p.CertificateDays(now); ok && days <= certificateWarnDays {
			if days < 0 {
				u.warnf("%s 的证书已过期，请在 节点管理 → 编辑节点 → 证书管理 中更新", p.Name)
			} else {
				u.warnf("%s 的证书 %d 天后过期", p.Name, days)
			}
		}
		limited = limited || p.trafficPolicy().LimitBytes > 0
	}
	if !u.a.trafficActive() {
		if limited {
			u.warn("流量监控未启用：有限额节点保持暂停，请运行 rout traffic install")
		}
		return
	}
	if db, e := u.a.loadTraffic(); e == nil {
		for _, p := range s.Profiles {
			switch db.Records[p.ID].Blocked {
			case blockFault:
				u.warnf("%s 因计量缺口暂停，可在 流量与限额 中选择保留已知用量并恢复", p.Name)
			case blockQuota:
				u.warnf("%s 已达流量上限，将在下个账单周期恢复", p.Name)
			}
		}
	}
}
func (u *UI) menu0() []menuItem {
	return []menuItem{item("nodes", "节点管理"), item("relays", "中转管理"), item("outbounds", "出站代理"), item("traffic", "流量与限额"), item("services", "服务管理"), item("settings", "设置"), item("doctor", "诊断"), item("updates", "更新")}
}
func (u *UI) mainMenu() error {
	u.showLogo()
	if e := u.initLanguage(false); e != nil {
		if errors.Is(e, io.EOF) {
			return nil
		}
		return e
	}
	if u.a.ServiceMode != "none" && !u.a.trafficActive() {
		if _, e := exec.LookPath("nft"); e == nil {
			if e = u.a.InstallTraffic(); e != nil {
				u.warn(u.a.Error(e))
			}
		}
	}
	if s, e := u.a.Load(); e != nil {
		u.fail(u.a.Error(e))
	} else {
		u.notices(s)
	}
	for {
		title := "Rout " + Version
		if s, e := u.a.Load(); e == nil {
			title += "  ·  " + u.summary(s)
		}
		v := u.menu(title, u.menu0(), "退出")
		if u.err != nil {
			if errors.Is(u.err, io.EOF) || errors.Is(u.err, errQuit) {
				return nil
			}
			return u.err
		}
		var e error
		switch v {
		case "":
			return nil
		case "nodes":
			e = u.manage()
		case "relays":
			e = u.relays()
		case "outbounds":
			e = u.outbounds()
		case "traffic":
			e = u.trafficMenu()
		case "services":
			e = u.services()
		case "settings":
			e = u.settings()
		case "doctor":
			e = u.doctor(false)
		case "updates":
			e = u.updates()
		}
		if e != nil {
			if errors.Is(e, io.EOF) || errors.Is(e, errQuit) {
				return nil
			}
			u.fail(u.a.Error(e))
		}
		if u.err != nil {
			if errors.Is(u.err, io.EOF) || errors.Is(u.err, errQuit) {
				return nil
			}
			return u.err
		}
	}
}
