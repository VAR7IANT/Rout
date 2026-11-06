package rout

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// A minimal Telegram Bot API client: exactly the methods the control plane needs, JSON over
// HTTPS, standard library only. The token lives in the request PATH (/bot<TOKEN>/method), which
// net/http copies into its error strings, so every error is scrubbed before it can reach a log,
// the terminal, the panel or a Telegram message.

const telegramDefaultBase = "https://api.telegram.org"

type tgClient struct {
	base  string
	token string
	hc    *http.Client
}

func (a *App) tgClient(token string) *tgClient {
	base := telegramDefaultBase
	if a.telegram != nil && a.telegram.base != "" {
		base = a.telegram.base
	}
	// ProxyFromEnvironment: servers behind an HTTPS proxy keep working; the token is never
	// part of anything but the request path.
	tr := &http.Transport{Proxy: http.ProxyFromEnvironment, TLSHandshakeTimeout: 15 * time.Second, ResponseHeaderTimeout: 45 * time.Second, MaxIdleConns: 2, IdleConnTimeout: 60 * time.Second}
	return &tgClient{base: strings.TrimRight(base, "/"), token: token, hc: &http.Client{Transport: tr}}
}

func (c *tgClient) close() { c.hc.CloseIdleConnections() }

// tgAPIError is a Telegram-reported failure.
type tgAPIError struct {
	Method     string
	Code       int
	Desc       string
	RetryAfter int
}

func (e *tgAPIError) Error() string {
	return fmt.Sprintf("telegram %s: %d %s", e.Method, e.Code, e.Desc)
}

func (c *tgClient) scrub(s string) string {
	if c.token != "" {
		s = strings.ReplaceAll(s, c.token, "<token>")
		if i := strings.IndexByte(c.token, ':'); i > 0 {
			s = strings.ReplaceAll(s, c.token[i+1:], "<token>")
		}
	}
	return s
}

type tgEnvelope struct {
	OK          bool            `json:"ok"`
	Result      json.RawMessage `json:"result"`
	ErrorCode   int             `json:"error_code"`
	Description string          `json:"description"`
	Parameters  struct {
		RetryAfter int `json:"retry_after"`
	} `json:"parameters"`
}

func (c *tgClient) call(ctx context.Context, method string, params, out any) error {
	var body io.Reader
	if params != nil {
		b, e := json.Marshal(params)
		if e != nil {
			return e
		}
		body = bytes.NewReader(b)
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/bot"+c.token+"/"+method, body)
	if e != nil {
		return errors.New("telegram " + method + ": invalid request")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, e := c.hc.Do(req)
	if e != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New(c.scrub("telegram " + method + ": " + e.Error()))
	}
	defer resp.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if e != nil {
		return errors.New(c.scrub("telegram " + method + ": " + e.Error()))
	}
	var env tgEnvelope
	if e = json.Unmarshal(raw, &env); e != nil {
		return fmt.Errorf("telegram %s: unexpected response (HTTP %d)", method, resp.StatusCode)
	}
	if !env.OK {
		return &tgAPIError{Method: method, Code: env.ErrorCode, Desc: c.scrub(env.Description), RetryAfter: env.Parameters.RetryAfter}
	}
	if out != nil && len(env.Result) > 0 {
		if e = json.Unmarshal(env.Result, out); e != nil {
			return fmt.Errorf("telegram %s: unexpected result", method)
		}
	}
	return nil
}

// ---- types -------------------------------------------------------------------------------

type tgUser struct {
	ID       int64  `json:"id"`
	IsBot    bool   `json:"is_bot"`
	Username string `json:"username"`
}
type tgChat struct {
	ID   int64  `json:"id"`
	Type string `json:"type"`
}
type tgMessage struct {
	MessageID int64   `json:"message_id"`
	From      *tgUser `json:"from"`
	Chat      tgChat  `json:"chat"`
	Text      string  `json:"text"`
	Date      int64   `json:"date"`
}
type tgCallback struct {
	ID      string     `json:"id"`
	From    tgUser     `json:"from"`
	Message *tgMessage `json:"message"`
	Data    string     `json:"data"`
}
type tgUpdate struct {
	UpdateID int64       `json:"update_id"`
	Message  *tgMessage  `json:"message"`
	Callback *tgCallback `json:"callback_query"`
}
type tgChatFull struct {
	ID            int64      `json:"id"`
	Type          string     `json:"type"`
	PinnedMessage *tgMessage `json:"pinned_message"`
}
type tgWebhookInfo struct {
	URL string `json:"url"`
}
type tgButton struct {
	Text string `json:"text"`
	Data string `json:"callback_data"`
}
type tgMarkup struct {
	Keyboard [][]tgButton `json:"inline_keyboard"`
}

// ---- methods -----------------------------------------------------------------------------

func (c *tgClient) getMe(ctx context.Context) (tgUser, error) {
	var u tgUser
	return u, c.call(ctx, "getMe", nil, &u)
}

func (c *tgClient) getChat(ctx context.Context, chat int64) (tgChatFull, error) {
	var ch tgChatFull
	return ch, c.call(ctx, "getChat", map[string]any{"chat_id": chat}, &ch)
}

func (c *tgClient) getWebhook(ctx context.Context) (tgWebhookInfo, error) {
	var w tgWebhookInfo
	return w, c.call(ctx, "getWebhookInfo", nil, &w)
}

func (c *tgClient) deleteWebhook(ctx context.Context) error {
	return c.call(ctx, "deleteWebhook", map[string]any{"drop_pending_updates": false}, nil)
}

func (c *tgClient) sendMessage(ctx context.Context, chat int64, text string, mk *tgMarkup) (tgMessage, error) {
	p := map[string]any{"chat_id": chat, "text": text, "parse_mode": "HTML", "disable_web_page_preview": true}
	if mk != nil {
		p["reply_markup"] = mk
	}
	var m tgMessage
	return m, c.call(ctx, "sendMessage", p, &m)
}

// editMessage treats "message is not modified" as success: re-rendering an unchanged screen
// (a refresh, a repeated callback) is not an error.
func (c *tgClient) editMessage(ctx context.Context, chat, msg int64, text string, mk *tgMarkup) error {
	p := map[string]any{"chat_id": chat, "message_id": msg, "text": text, "parse_mode": "HTML", "disable_web_page_preview": true}
	if mk != nil {
		p["reply_markup"] = mk
	} else {
		p["reply_markup"] = &tgMarkup{Keyboard: [][]tgButton{}}
	}
	e := c.call(ctx, "editMessageText", p, nil)
	var ae *tgAPIError
	if errors.As(e, &ae) && strings.Contains(ae.Desc, "message is not modified") {
		return nil
	}
	return e
}

func (c *tgClient) answerCallback(ctx context.Context, id, text string, alert bool) error {
	p := map[string]any{"callback_query_id": id}
	if text != "" {
		p["text"], p["show_alert"] = text, alert
	}
	return c.call(ctx, "answerCallbackQuery", p, nil)
}

func (c *tgClient) getUpdates(ctx context.Context, offset int64, wait time.Duration) ([]tgUpdate, error) {
	var ups []tgUpdate
	e := c.call(ctx, "getUpdates", map[string]any{"offset": offset, "timeout": int(wait / time.Second), "allowed_updates": []string{"message", "callback_query"}}, &ups)
	return ups, e
}

func (c *tgClient) pin(ctx context.Context, chat, msg int64) error {
	return c.call(ctx, "pinChatMessage", map[string]any{"chat_id": chat, "message_id": msg, "disable_notification": true}, nil)
}

func (c *tgClient) unpin(ctx context.Context, chat, msg int64) error {
	return c.call(ctx, "unpinChatMessage", map[string]any{"chat_id": chat, "message_id": msg}, nil)
}

func (c *tgClient) deleteMessage(ctx context.Context, chat, msg int64) error {
	return c.call(ctx, "deleteMessage", map[string]any{"chat_id": chat, "message_id": msg}, nil)
}

// isUnauthorized / isConflict classify the failures the service reacts to.
func tgIsAuth(e error) bool {
	var ae *tgAPIError
	return errors.As(e, &ae) && (ae.Code == 401 || ae.Code == 404 && ae.Method != "editMessageText")
}
func tgIsConflict(e error) bool {
	var ae *tgAPIError
	return errors.As(e, &ae) && ae.Code == 409
}

// tgFriendly explains the failures a user can fix, in the Rout message catalog's source language.
func tgFriendly(e error) string {
	var ae *tgAPIError
	if !errors.As(e, &ae) {
		return fmt.Sprintf("无法连接 Telegram：%s", redactError(e))
	}
	switch {
	case ae.Code == 401:
		return "Bot Token 无效或已被撤销（请在 @BotFather 检查）"
	case ae.Code == 403:
		return "机器人无法向该 Chat ID 发消息：请先在 Telegram 打开你的机器人并发送 /start，且不要屏蔽它"
	case ae.Code == 400 && strings.Contains(ae.Desc, "chat not found"):
		return "找不到该 Chat ID：请确认它是你自己的数字用户 ID，并且已对机器人发送过 /start"
	case ae.Code == 409:
		return "有另一个程序正在同时接收这个机器人的消息（另一个 getUpdates 或已设置的 webhook）"
	case ae.Code == 429:
		return "Telegram 请求过于频繁，请稍后再试"
	}
	return fmt.Sprintf("Telegram 返回错误：%s", redactError(errors.New(ae.Desc)))
}
