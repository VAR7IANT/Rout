package rout

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
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
	// Expires is a unix time; an agent that reconnects late ignores a stale command.
	Expires int64 `json:"exp"`
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

var (
	// Anything that looks like key material or a URL is removed from text that crosses the wire
	// or reaches a chat: diagnostics are written for a local operator, not for a message history.
	tgSecretLike = regexp.MustCompile(`[A-Za-z0-9_+/=-]{32,}`)
	tgURLLike    = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://\S+`)
	tgIPv4       = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b`)
	tgIPv6       = regexp.MustCompile(`\[[0-9A-Fa-f:.]{3,}\](?::\d{1,5})?`)
	tgUserInfo   = regexp.MustCompile(`(?i)(password|passwd|pwd|secret|token|key|uuid|密码|密钥)\s*[=:：]\s*\S+`)
)

// tgScrub makes text safe to send: control characters out, URLs/credentials/long key-like runs
// hidden, length bounded. extra lists exact strings (such as the token) to remove first.
func tgScrub(s string, max int, extra ...string) string {
	for _, x := range extra {
		if len(x) >= 6 {
			s = strings.ReplaceAll(s, x, "<隐藏>")
		}
	}
	s = tgURLLike.ReplaceAllString(s, "<地址已隐藏>")
	s = tgIPv4.ReplaceAllString(s, "<地址>")
	s = tgIPv6.ReplaceAllString(s, "<地址>")
	s = tgUserInfo.ReplaceAllString(s, "$1=<隐藏>")
	s = tgSecretLike.ReplaceAllString(s, "<隐藏>")
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

func (a *App) tgErr(e error) string {
	if e == nil {
		return ""
	}
	return tgScrub(a.Error(e), 240)
}

// tgStatus reads this server's AI state through AIStatus (never state.json directly).
func (a *App) tgStatus(cfg TelegramConfig) (tgServerStatus, error) {
	st, e := a.AIStatus()
	if e != nil {
		return tgServerStatus{}, e
	}
	s, e := a.Load()
	if e != nil {
		return tgServerStatus{}, e
	}
	out := tgServerStatus{ServerID: cfg.ServerID, Name: cfg.Name, Enabled: st.Config.Enabled, ExitID: st.Config.AIOutboundID,
		ExitName: tgScrub(st.ExitName, 60), Bound: st.BoundCount, Version: Version, At: a.tgNow().Unix(), Exits: []tgExitInfo{}, CredTag: cfg.credTag()}
	if ex, er := FindExit(s, st.Config.AIOutboundID); er == nil {
		out.ExitKind = ex.KindLabel()
	}
	local := localIPs()
	for _, ex := range s.Exits {
		info := tgExitInfo{ID: ex.ID, Name: tgScrub(ex.Name, 60), Kind: tgScrub(ex.KindLabel(), 30)}
		if _, er := aiExitProxy(s, ex, local); er != nil {
			info.Problem = a.tgErr(er)
		} else {
			info.Usable = true
		}
		out.Exits = append(out.Exits, info)
		if len(out.Exits) >= 40 { // a Telegram keyboard cannot usefully show more
			break
		}
	}
	for _, p := range st.Problems {
		out.Problems = append(out.Problems, tgScrub(a.T(p), 200))
	}
	return out, nil
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
		cur, e := a.AIStatus()
		if e != nil {
			res.Error = a.tgErr(e)
			return
		}
		if cur.Config.Enabled == c.Enabled {
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
		cur, e := a.AIStatus()
		if e != nil {
			res.Error = a.tgErr(e)
			return
		}
		if cur.Config.AIOutboundID == c.ExitID {
			res.OK, res.Note = true, "当前已使用该出口，未做更改"
			return
		}
		if e = a.SetAIExit(c.ExitID); e != nil {
			res.Error = a.tgErr(e)
			return
		}
		// Verify, do not assume: the committed state must name the requested exit.
		if after, er := a.AIStatus(); er != nil || after.Config.AIOutboundID != c.ExitID {
			res.Error = "切换后校验失败，请在服务器上检查 AI 分流状态"
			return
		}
		res.OK = true
	case tgCmdTest:
		tctx, cancel := context.WithTimeout(ctx, 75*time.Second)
		defer cancel()
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
			res.Steps = append(res.Steps, tgStep{Level: s.Level, Text: tgScrub(s.Text, 160)})
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
func tgCommandValid(c tgCommand, now time.Time) error {
	if len(c.ID) < 8 || len(c.ID) > 64 {
		return errors.New("命令 ID 无效")
	}
	switch c.Kind {
	case tgCmdStatus, tgCmdSetEnabled, tgCmdSetExit, tgCmdTest, tgCmdCredentials:
	default:
		return fmt.Errorf("不支持的命令")
	}
	if c.Expires == 0 || now.Unix() > c.Expires {
		return errors.New("命令已过期")
	}
	if c.Expires-now.Unix() > 3600 {
		return errors.New("命令有效期无效")
	}
	if c.Kind == tgCmdCredentials && (!validTelegramToken(c.Token) || c.ChatID <= 0) {
		return errors.New("凭据无效")
	}
	return nil
}
