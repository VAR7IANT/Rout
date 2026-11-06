package rout

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Telegram control plane configuration. One file, telegram.json (mode 0600, inside the 0700
// configuration directory), holds everything secret: the Bot Token and this server's private
// key. It is deliberately NOT part of state.json, `rout backup` or the panel's backup bundle, so
// a backup file never carries a credential that controls the bot. Runtime observations live in
// telegram-status.json (no secrets) so the menu and the panel can show them.

const telegramConfigVersion = 1

const (
	tgRoleHub   = "hub"
	tgRoleAgent = "agent"
)

type TelegramConfig struct {
	Version  int    `json:"version"`
	Token    string `json:"token"`
	ChatID   int64  `json:"chat_id"`
	BotUser  string `json:"bot_username,omitempty"`
	ServerID string `json:"server_id"`
	Name     string `json:"name"`
	Role     string `json:"role"`
	CertPEM  string `json:"cert_pem"`
	KeyPEM   string `json:"key_pem"`
	// Hub is set when this server is the control hub, Agent when it follows one.
	Hub   *TelegramHub   `json:"hub,omitempty"`
	Agent *TelegramAgent `json:"agent,omitempty"`
	// Offset is the next getUpdates offset (hub): an update is confirmed only after it was handled.
	Offset    int64     `json:"update_offset,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

type TelegramHub struct {
	Port        int      `json:"port"`
	MultiServer bool     `json:"multi_server"`
	Advertise   []string `json:"advertise,omitempty"` // manual endpoints; empty means detect
	// Agents are the servers a human approved; only their certificate fingerprints may poll.
	Agents  []TelegramAgentRecord   `json:"agents,omitempty"`
	Pending []TelegramPendingRecord `json:"pending,omitempty"`
	// Revoked are certificate fingerprints that were rejected or removed; they are told so on
	// their next call and are never offered for approval again.
	Revoked []string `json:"revoked,omitempty"`
	// AnnounceMsgID is the pinned announcement message in the private chat.
	AnnounceMsgID int64 `json:"announce_msg_id,omitempty"`
}

type TelegramAgentRecord struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	FP         string    `json:"fp"`
	ApprovedAt time.Time `json:"approved_at"`
}

type TelegramPendingRecord struct {
	ID          string    `json:"id"` // request id, used in the Allow/Reject buttons
	ServerID    string    `json:"server_id"`
	Name        string    `json:"name"`
	FP          string    `json:"fp"`
	RequestedAt time.Time `json:"requested_at"`
}

type TelegramAgent struct {
	HubID     string   `json:"hub_id"`
	HubName   string   `json:"hub_name,omitempty"`
	Endpoints []string `json:"endpoints"`
	HubFP     string   `json:"hub_fp"` // pinned certificate fingerprint of the hub
	// State is what the hub last said about this agent: pending, approved or revoked.
	State string `json:"state,omitempty"`
}

var errTelegramUnbound = errors.New("Telegram Bot 尚未绑定")

var tgTokenPattern = regexp.MustCompile(`^[0-9]{3,}:[A-Za-z0-9_-]{20,}$`)

func (a *App) telegramPath() string       { return filepath.Join(a.Home, "telegram.json") }
func (a *App) telegramStatusPath() string { return filepath.Join(a.Home, "telegram-status.json") }
func (a *App) telegramAuditPath() string  { return filepath.Join(a.Home, "telegram-audit.log") }

func tgShort(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func validTelegramToken(t string) bool { return len(t) <= 128 && tgTokenPattern.MatchString(t) }

func (c TelegramConfig) identity() tgIdentity {
	return tgIdentity{CertPEM: c.CertPEM, KeyPEM: c.KeyPEM}
}
func (c TelegramConfig) keys() tgKeys { return deriveTelegramKeys(c.Token) }

// maskChatID shows only the last four digits.
func maskChatID(id int64) string {
	s := itoa64(id)
	if len(s) <= 4 {
		return "••••"
	}
	return "••••" + s[len(s)-4:]
}

// Validate checks structure only; it never contacts Telegram.
func (c TelegramConfig) Validate() error {
	if c.Version != telegramConfigVersion {
		return errors.New("Telegram 配置版本不受支持")
	}
	if !validTelegramToken(c.Token) {
		return errors.New("Bot Token 格式无效")
	}
	if c.ChatID <= 0 {
		return errors.New("Chat ID 必须是私聊用户的正整数 ID；群组和频道暂不支持")
	}
	if len(c.ServerID) != 16 || strings.Trim(c.ServerID, "0123456789abcdef") != "" {
		return errors.New("服务器 ID 无效")
	}
	if e := validDisplayName(c.Name); e != nil {
		return errors.New("服务器名称无效（1–60 个字符，不能含控制字符）")
	}
	if c.CertPEM == "" || c.KeyPEM == "" {
		return errors.New("缺少服务器身份证书")
	}
	switch c.Role {
	case tgRoleHub:
		if c.Hub == nil || c.Agent != nil {
			return errors.New("控制中心配置无效")
		}
		if c.Hub.Port != 0 && (c.Hub.Port < 1024 || c.Hub.Port > 65535) {
			return errors.New("控制中心端口应在 1024–65535 之间")
		}
		if len(c.Hub.Agents) > 64 || len(c.Hub.Pending) > 16 {
			return errors.New("已授权或待批准的服务器过多")
		}
		for _, ep := range c.Hub.Advertise {
			if _, _, e := net.SplitHostPort(ep); e != nil {
				return errors.New("控制中心公告地址应为 地址:端口")
			}
		}
	case tgRoleAgent:
		if c.Agent == nil || c.Hub != nil || len(c.Agent.HubFP) != 64 || len(c.Agent.Endpoints) == 0 || len(c.Agent.Endpoints) > 8 {
			return errors.New("Agent 配置无效")
		}
		for _, ep := range c.Agent.Endpoints {
			if _, _, e := net.SplitHostPort(ep); e != nil {
				return errors.New("控制中心地址应为 地址:端口")
			}
		}
	default:
		return errors.New("Telegram 角色无效")
	}
	return nil
}

// LoadTelegram returns errTelegramUnbound when nothing is bound.
func (a *App) LoadTelegram() (TelegramConfig, error) {
	b, e := os.ReadFile(a.telegramPath())
	if os.IsNotExist(e) {
		return TelegramConfig{}, errTelegramUnbound
	}
	if e != nil {
		return TelegramConfig{}, e
	}
	var c TelegramConfig
	if e = json.Unmarshal(b, &c); e != nil {
		return TelegramConfig{}, errors.New("Telegram 配置文件无效；请保留文件并检查 telegram.json")
	}
	if e = c.Validate(); e != nil {
		return TelegramConfig{}, e
	}
	return c, nil
}

func (a *App) saveTelegram(c TelegramConfig) error {
	c.Version, c.UpdatedAt = telegramConfigVersion, a.tgNow()
	if e := c.Validate(); e != nil {
		return e
	}
	b, e := JSON(c)
	if e != nil {
		return e
	}
	return AtomicWrite(a.telegramPath(), b, 0600)
}

// mutateTelegram changes the configuration under a lock, so the service, the menu and the
// panel never overwrite each other.
func (a *App) mutateTelegram(change func(*TelegramConfig) error) error {
	unlock, e := lockFile(filepath.Join(a.Home, ".telegram.lock"), 10*time.Second)
	if e != nil {
		return e
	}
	defer unlock()
	c, e := a.LoadTelegram()
	if e != nil {
		return e
	}
	if e = change(&c); e != nil {
		return e
	}
	return a.saveTelegram(c)
}

// removeTelegramFiles wipes every Telegram file: token, private key, status and audit log.
func (a *App) removeTelegramFiles() error {
	var first error
	for _, p := range []string{a.telegramPath(), a.telegramStatusPath(), a.telegramAuditPath(), a.telegramAuditPath() + ".1"} {
		if e := os.Remove(p); e != nil && !os.IsNotExist(e) && first == nil {
			first = e
		}
	}
	return first
}

// ---- test hooks --------------------------------------------------------------------------

type telegramHooks struct {
	base      string // Bot API base URL; empty means https://api.telegram.org
	hostname  func() string
	addresses func() Addresses
	now       func() time.Time
	pollWait  time.Duration // getUpdates long-poll length
	agentWait time.Duration // how long the hub holds an agent's poll
	retry     time.Duration // base reconnect delay
	listen    string        // hub listen address override (tests: 127.0.0.1:0)
	onHub     func(*tgHub)  // tests: called once the hub is listening
}

func (a *App) tgNow() time.Time {
	if a.telegram != nil && a.telegram.now != nil {
		return a.telegram.now().UTC()
	}
	return time.Now().UTC()
}

func (a *App) tgHostname() string {
	if a.telegram != nil && a.telegram.hostname != nil {
		return a.telegram.hostname()
	}
	h, _ := os.Hostname()
	if h = strings.TrimSpace(h); h == "" {
		h = "rout-server"
	}
	return h
}

func (a *App) tgAddresses() Addresses {
	if a.telegram != nil && a.telegram.addresses != nil {
		return a.telegram.addresses()
	}
	return DetectAddresses()
}

func (a *App) tgDurations() (poll, agentWait, retry time.Duration) {
	poll, agentWait, retry = 25*time.Second, 25*time.Second, 2*time.Second
	if a.telegram != nil {
		if a.telegram.pollWait > 0 {
			poll = a.telegram.pollWait
		}
		if a.telegram.agentWait > 0 {
			agentWait = a.telegram.agentWait
		}
		if a.telegram.retry > 0 {
			retry = a.telegram.retry
		}
	}
	return
}

// defaultServerName is the hostname, shortened to a valid display name.
func (a *App) defaultServerName() string {
	n := strings.TrimSpace(a.tgHostname())
	if validDisplayName(n) != nil {
		n = "rout-server"
	}
	if r := []rune(n); len(r) > 60 {
		n = string(r[:60])
	}
	return n
}

func (c TelegramConfig) String() string {
	// Never print secrets, even by accident through %v.
	return fmt.Sprintf("telegram(%s %s chat=%s)", c.Role, c.Name, maskChatID(c.ChatID))
}
