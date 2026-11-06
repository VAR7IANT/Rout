package rout

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// The executor is the ONLY thing a Telegram command can reach on a server. It is a closed set of
// four operations, each one a call to the same application service the menu and the panel use
// (SetAIEnabled, SetAIExit, TestAIExit, AIStatus) and therefore the same validation, the same
// Commit transaction and the same rollback. There is no command that runs a shell, reads or
// writes a file, or returns a credential.

// Command kinds.
const (
	tgCmdStatus      = "status"
	tgCmdSetEnabled  = "set_enabled"
	tgCmdSetExit     = "set_exit"
	tgCmdTest        = "test"
	tgCmdCredentials = "set_credentials"
)

// tgCommand travels hub → agent over the authenticated channel.
type tgCommand struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	Enabled bool   `json:"enabled,omitempty"`
	ExitID  string `json:"exit_id,omitempty"`
	// set_credentials: the new token and chat, pushed only to approved servers.
	Token  string `json:"token,omitempty"`
	ChatID int64  `json:"chat_id,omitempty"`
	// TTL is how many seconds the command stays valid after the agent receives it. It is relative
	// on purpose: an absolute time would make every command fail on a server whose clock is off.
	TTL int `json:"ttl"`
}

func (c tgCommand) String() string { return c.Kind + "#" + tgShort(c.ID) } // never prints the token

// tgExitInfo is the safe projection of an exit: a name and whether AI can use it. No host,
// port, user name, password or link ever leaves the server.
type tgExitInfo struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	Usable  bool   `json:"usable"`
	Problem string `json:"problem,omitempty"`
}

// tgServerStatus is what a server reports about itself.
type tgServerStatus struct {
	ServerID string       `json:"server_id"`
	Name     string       `json:"name"`
	Enabled  bool         `json:"enabled"`
	ExitID   string       `json:"exit_id"`
	ExitName string       `json:"exit_name"`
	ExitKind string       `json:"exit_kind,omitempty"`
	Bound    int          `json:"bound"`
	Exits    []tgExitInfo `json:"exits"`
	Problems []string     `json:"problems,omitempty"`
	Version  string       `json:"version"`
	At       int64        `json:"at"`
	// CredTag identifies the Bot credentials this server holds without revealing them, so the
	// hub can tell when a server still has an old token and bring it up to date.
	CredTag string `json:"cred,omitempty"`
}

func (c TelegramConfig) credTag() string {
	h := sha256.Sum256([]byte("rout-cred1\x00" + c.Token + "\x00" + itoa64(c.ChatID)))
	return hex.EncodeToString(h[:8])
}

type tgStep struct {
	Level string `json:"level"` // ok, warn, fail, info
	Text  string `json:"text"`
}

// tgResult travels agent → hub.
type tgResult struct {
	ID     string          `json:"id"`
	OK     bool            `json:"ok"`
	Error  string          `json:"error,omitempty"`
	Note   string          `json:"note,omitempty"`
	Status *tgServerStatus `json:"status,omitempty"`
	Steps  []tgStep        `json:"steps,omitempty"`
}

// tgRedacted replaces anything removed from text that crosses the wire or reaches a chat.
const tgRedacted = "[redacted]"

var (
	// Anything that looks like key material or a URL is removed from text that crosses the wire
	// or reaches a chat: diagnostics are written for a local operator, not for a message history.
	tgSecretLike = regexp.MustCompile(`[A-Za-z0-9_+/=-]{32,}`)
	tgURLLike    = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://\S+`)
	tgIPv4       = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b`)
	tgIPv6Brack  = regexp.MustCompile(`\[[0-9A-Fa-f:.]{3,}\](?::\d{1,5})?`)
	// tgIPv6Bare finds candidates (hex digits, dots and at least two colons); only those that
	// really parse as an IPv6 address are removed, so times, MAC addresses and versions stay.
	tgIPv6Bare = regexp.MustCompile(`[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*`)
	tgUserInfo = regexp.MustCompile(`(?i)(password|passwd|pwd|secret|token|key|uuid|\x{5BC6}\x{7801}|\x{5BC6}\x{94A5})\s*[=:\x{FF1A}]\s*\S+`)
)

// tgRedactIPv6 removes bare IPv6 literals ("2001:db8::20", "::1") including one that ends a
// sentence ("2001:db8::20: failed") without touching things that merely contain colons.
func tgRedactIPv6(s string) string {
	return tgIPv6Bare.ReplaceAllStringFunc(s, func(m string) string {
		t := m
		for i := 0; i < 3; i++ {
			if net.ParseIP(t) != nil && strings.Contains(t, ":") {
				return tgRedacted + m[len(t):]
			}
			t = strings.TrimRight(t, ":.")
			if t == "" {
				break
			}
		}
		return m
	})
}

// tgScrub makes text safe to send: control characters out, URLs/addresses/credentials/long
// key-like runs hidden, length bounded. extra lists exact strings (such as the token) to remove
// first.
func tgScrub(s string, max int, extra ...string) string {
	for _, x := range extra {
		if len(x) >= 6 {
			s = strings.ReplaceAll(s, x, tgRedacted)
		}
	}
	s = tgURLLike.ReplaceAllString(s, tgRedacted)
	s = tgIPv6Brack.ReplaceAllString(s, tgRedacted)
	s = tgRedactIPv6(s)
	s = tgIPv4.ReplaceAllString(s, tgRedacted)
	s = tgUserInfo.ReplaceAllString(s, "$1="+tgRedacted)
	s = tgSecretLike.ReplaceAllString(s, tgRedacted)
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == utf8.RuneError {
			return ' '
		}
		return r
	}, s)
	if r := []rune(s); max > 0 && len(r) > max {
		s = string(r[:max]) + "…"
	}
	return strings.TrimSpace(s)
}

// tgSensitive lists the strings of this server's configuration that must never reach a chat:
// every exit's host, credentials and link, a chain hop's address and every relay's destination.
// Diagnostics print these in formats no generic pattern can anticipate (a host name in a DNS
// step, a bare IPv6 literal in an address step), so they are removed by value.
func tgSensitive(s State) []string {
	seen := map[string]bool{}
	var out []string
	add := func(v string, min int) {
		v = strings.TrimSpace(v)
		if len(v) < min || seen[strings.ToLower(v)] {
			return
		}
		seen[strings.ToLower(v)] = true
		out = append(out, v)
	}
	// hostOf extracts the host of "host:port", "[v6]:port", a URL or a bare host.
	hostOf := func(v string) string {
		v = strings.TrimSpace(v)
		if v == "" {
			return ""
		}
		if u, e := url.Parse(v); e == nil && u.Host != "" {
			return u.Hostname()
		}
		if h, _, e := net.SplitHostPort(v); e == nil {
			return h
		}
		return strings.Trim(v, "[]")
	}
	for _, ex := range s.Exits {
		p := ex.Proxy
		add(p.Host, 3)
		add(p.Username, 4)
		add(p.Password, 4)
		add(p.Link, 8)
		add(hostOf(p.Link), 3)
		add(ex.ViaAddress, 6)
		add(hostOf(ex.ViaAddress), 3)
	}
	for _, p := range s.Profiles {
		if p.Kind == "relay" {
			add(p.Target, 6)
			add(hostOf(p.Target), 3)
			add(p.TargetURI, 8)
			add(hostOf(p.TargetURI), 3)
		}
	}
	sort.Slice(out, func(i, j int) bool { return len(out[i]) > len(out[j]) })
	return out
}

// tgScrubber removes this server's sensitive strings (case-insensitively, longest first) and then
// applies the generic scrub.
type tgScrubber struct{ re *regexp.Regexp }

func newTGScrubber(s State) *tgScrubber {
	var parts []string
	for _, v := range tgSensitive(s) {
		parts = append(parts, regexp.QuoteMeta(v))
	}
	if len(parts) == 0 {
		return &tgScrubber{}
	}
	return &tgScrubber{re: regexp.MustCompile(`(?i)` + strings.Join(parts, "|"))}
}

func (x *tgScrubber) clean(text string, max int, extra ...string) string {
	if x != nil && x.re != nil {
		text = x.re.ReplaceAllString(text, tgRedacted)
	}
	return tgScrub(text, max, extra...)
}

// tgClean scrubs against the current configuration; used for error text.
func (a *App) tgClean(text string, max int, extra ...string) string {
	s, e := a.Load()
	if e != nil {
		return tgScrub(text, max, extra...)
	}
	return newTGScrubber(s).clean(text, max, extra...)
}

func (a *App) tgErr(e error) string {
	if e == nil {
		return ""
	}
	return a.tgClean(a.Error(e), 240)
}

// tgStatus reports this server's AI state from the same summary AIStatus builds on (never by
// reading state.json directly, and without a service query per node).
func (a *App) tgStatus(cfg TelegramConfig) (tgServerStatus, error) {
	s, e := a.Load()
	if e != nil {
		return tgServerStatus{}, e
	}
	st := a.aiSummary(s)
	x := newTGScrubber(s)
	out := tgServerStatus{ServerID: cfg.ServerID, Name: cfg.Name, Enabled: st.Config.Enabled, ExitID: st.Config.AIOutboundID,
		ExitName: tgScrub(st.ExitName, 60), Bound: st.BoundCount, Version: Version, At: a.tgNow().Unix(), Exits: []tgExitInfo{}, CredTag: cfg.credTag()}
	if ex, er := FindExit(s, st.Config.AIOutboundID); er == nil {
		out.ExitKind = ex.KindLabel()
	}
	local := localIPs()
	for _, ex := range s.Exits {
		info := tgExitInfo{ID: ex.ID, Name: tgScrub(ex.Name, 60), Kind: tgScrub(ex.KindLabel(), 30)}
		if _, er := aiExitProxy(s, ex, local); er != nil {
			info.Problem = x.clean(a.Error(er), 240)
		} else {
			info.Usable = true
		}
		out.Exits = append(out.Exits, info)
		if len(out.Exits) >= 40 { // a Telegram keyboard cannot usefully show more
			break
		}
	}
	for _, p := range st.Problems {
		out.Problems = append(out.Problems, x.clean(a.T(p), 200))
	}
	return out, nil
}

// sanitize bounds and scrubs a status received from another server. The sender is an approved
// server, not a trusted one: whatever it sends is shown to the owner, so it is limited the same
// way a local status is.
func (st *tgServerStatus) sanitize() {
	st.ExitName, st.ExitKind = tgScrub(st.ExitName, 60), tgScrub(st.ExitKind, 30)
	st.Version = tgScrub(st.Version, 24)
	if len(st.Exits) > 40 {
		st.Exits = st.Exits[:40]
	}
	for i := range st.Exits {
		e := &st.Exits[i]
		e.ID, e.Name, e.Kind, e.Problem = tgScrub(e.ID, 64), tgScrub(e.Name, 60), tgScrub(e.Kind, 30), tgScrub(e.Problem, 240)
	}
	if len(st.Problems) > 8 {
		st.Problems = st.Problems[:8]
	}
	for i := range st.Problems {
		st.Problems[i] = tgScrub(st.Problems[i], 200)
	}
	if st.Bound < 0 {
		st.Bound = 0
	}
}

// sanitize does the same for a command result.
func (r *tgResult) sanitize() {
	r.Error, r.Note = tgScrub(r.Error, 240), tgScrub(r.Note, 160)
	if len(r.Steps) > 12 {
		r.Steps = r.Steps[:12]
	}
	for i := range r.Steps {
		switch r.Steps[i].Level {
		case "ok", "warn", "fail", "info":
		default:
			r.Steps[i].Level = "info"
		}
		r.Steps[i].Text = tgScrub(r.Steps[i].Text, 160)
	}
	if r.Status != nil {
		r.Status.sanitize()
	}
}

// tgExecute runs one command. It never panics the caller and returns a fresh status with
// every result so the chat always shows the real state after the operation.
func (a *App) tgExecute(ctx context.Context, cfg TelegramConfig, c tgCommand) (res tgResult) {
	res.ID = c.ID
	defer func() {
		if r := recover(); r != nil {
			res.OK, res.Error = false, "内部错误，操作未执行"
		}
		if st, e := a.tgStatus(cfg); e == nil {
			res.Status = &st
		}
	}()
	switch c.Kind {
	case tgCmdStatus:
		res.OK = true
	case tgCmdSetEnabled:
		cs, e := a.Load()
		if e != nil {
			res.Error = a.tgErr(e)
			return
		}
		if cur := a.aiSummary(cs); cur.Config.Enabled == c.Enabled {
			res.OK, res.Note = true, "已经是该状态，未做更改"
			return
		}
		if e = a.SetAIEnabled(c.Enabled); e != nil {
			res.Error = a.tgErr(e)
			return
		}
		res.OK = true
	case tgCmdSetExit:
		if c.ExitID == "" || len(c.ExitID) > 64 {
			res.Error = "出口 ID 无效"
			return
		}
		cs, e := a.Load()
		if e != nil {
			res.Error = a.tgErr(e)
			return
		}
		if cur := a.aiSummary(cs); cur.Config.AIOutboundID == c.ExitID {
			res.OK, res.Note = true, "当前已使用该出口，未做更改"
			return
		}
		if e = a.SetAIExit(c.ExitID); e != nil {
			res.Error = a.tgErr(e)
			return
		}
		// Verify, do not assume: the committed state must name the requested exit.
		if after, er := a.Load(); er != nil || a.aiSummary(after).Config.AIOutboundID != c.ExitID {
			res.Error = "切换后校验失败，请在服务器上检查 AI 分流状态"
			return
		}
		res.OK = true
	case tgCmdTest:
		tctx, cancel := context.WithTimeout(ctx, 75*time.Second)
		defer cancel()
		// Diagnostics print host names, resolved addresses and credentials' neighbours in formats
		// no generic pattern can anticipate, so what this server is configured with is removed by
		// value before anything leaves it.
		x := &tgScrubber{}
		if cs, er := a.Load(); er == nil {
			x = newTGScrubber(cs)
		}
		v, e := a.TestAIExit(tctx)
		if e != nil {
			res.Error = a.tgErr(e)
			return
		}
		res.OK = v.OK
		for _, s := range v.Steps {
			if len(res.Steps) >= 12 {
				break
			}
			res.Steps = append(res.Steps, tgStep{Level: s.Level, Text: x.clean(s.Text, 160, cfg.Token)})
		}
		if !v.OK {
			res.Error = "AI 出口测试未通过"
		}
	default:
		res.Error = "不支持的命令"
	}
	return
}

// tgCommandValid is the single structural check applied to a command before it executes.
func tgCommandValid(c tgCommand) error {
	if len(c.ID) < 8 || len(c.ID) > 64 {
		return errors.New("命令 ID 无效")
	}
	switch c.Kind {
	case tgCmdStatus, tgCmdSetEnabled, tgCmdSetExit, tgCmdTest, tgCmdCredentials:
	default:
		return fmt.Errorf("不支持的命令")
	}
	if c.TTL < 1 || c.TTL > 3600 {
		return errors.New("命令有效期无效")
	}
	if c.Kind == tgCmdCredentials && (!validTelegramToken(c.Token) || c.ChatID <= 0) {
		return errors.New("凭据无效")
	}
	return nil
}
