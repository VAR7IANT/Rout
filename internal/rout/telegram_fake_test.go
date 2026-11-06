package rout

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeTelegram is an in-process Telegram Bot API: enough of getMe/getChat/getUpdates/
// sendMessage/editMessageText/answerCallbackQuery/pin/unpin/delete/webhook to drive the real hub,
// bot and agents. It keeps Telegram's behaviour that matters for correctness: updates are
// redelivered until the offset moves past them, two concurrent getUpdates get a 409, and a wrong
// token is a 401. There is no real Telegram here; see docs/TELEGRAM.md for what remains unverified.
type fakeTelegram struct {
	t      *testing.T
	srv    *httptest.Server
	token  string
	chatID int64

	mu       sync.Mutex
	updates  []tgUpdate
	nextUpd  int64
	nextMsg  int64
	msgs     map[int64]*fakeMsg
	pinned   int64
	webhook  string
	pollGen  int  // id of the newest getUpdates request; an older one is terminated with a 409
	rogue    bool // another program is consuming getUpdates
	stale    int  // the next N answerCallbackQuery calls fail as Telegram does for an old press
	conflict int  // 409s handed out
	tokens   map[string]bool
	answered []fakeAnswer
	calls    map[string]int
	failNext map[string]*tgAPIError
}

type fakeMsg struct {
	ID      int64
	Chat    int64
	Text    string
	Markup  *tgMarkup
	Deleted bool
	Edits   int
}

type fakeAnswer struct {
	ID, Text string
	Alert    bool
}

func newFakeTelegram(t *testing.T, token string, chat int64) *fakeTelegram {
	f := &fakeTelegram{t: t, token: token, chatID: chat, msgs: map[int64]*fakeMsg{}, calls: map[string]int{}, failNext: map[string]*tgAPIError{}, tokens: map[string]bool{token: true}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeTelegram) URL() string { return f.srv.URL }

func (f *fakeTelegram) addToken(tok string)        { f.mu.Lock(); f.tokens[tok] = true; f.mu.Unlock() }
func (f *fakeTelegram) setRogue(on bool)           { f.mu.Lock(); f.rogue = on; f.mu.Unlock() }
func (f *fakeTelegram) makeNextPressesStale(n int) { f.mu.Lock(); f.stale = n; f.mu.Unlock() }
func (f *fakeTelegram) setWebhook(u string)        { f.mu.Lock(); f.webhook = u; f.mu.Unlock() }
func (f *fakeTelegram) stats() (calls map[string]int, conflicts int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	calls = map[string]int{}
	for k, v := range f.calls {
		calls[k] = v
	}
	return calls, f.conflict
}

func (f *fakeTelegram) reply(w http.ResponseWriter, result any) {
	w.Header().Set("Content-Type", "application/json")
	b, _ := json.Marshal(result)
	fmt.Fprintf(w, `{"ok":true,"result":%s}`, b)
}

func (f *fakeTelegram) fail(w http.ResponseWriter, code int, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	b, _ := json.Marshal(desc)
	fmt.Fprintf(w, `{"ok":false,"error_code":%d,"description":%s}`, code, b)
}

func (f *fakeTelegram) serve(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/bot")
	i := strings.IndexByte(path, '/')
	f.mu.Lock()
	known := i >= 0 && f.tokens[path[:i]]
	f.mu.Unlock()
	if !known {
		f.fail(w, 401, "Unauthorized")
		return
	}
	method := path[i+1:]
	raw, _ := io.ReadAll(r.Body)
	var p map[string]json.RawMessage
	json.Unmarshal(raw, &p)
	num := func(k string) int64 {
		var n int64
		json.Unmarshal(p[k], &n)
		return n
	}
	f.mu.Lock()
	f.calls[method]++
	if fe := f.failNext[method]; fe != nil {
		delete(f.failNext, method)
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(fe.Code)
		b, _ := json.Marshal(fe.Desc)
		fmt.Fprintf(w, `{"ok":false,"error_code":%d,"description":%s,"parameters":{"retry_after":%d}}`, fe.Code, b, fe.RetryAfter)
		return
	}
	f.mu.Unlock()
	switch method {
	case "getMe":
		f.reply(w, tgUser{ID: 4242, IsBot: true, Username: "rout_test_bot"})
	case "getWebhookInfo":
		f.mu.Lock()
		u := f.webhook
		f.mu.Unlock()
		f.reply(w, tgWebhookInfo{URL: u})
	case "deleteWebhook":
		f.mu.Lock()
		f.webhook = ""
		f.mu.Unlock()
		f.reply(w, true)
	case "getChat":
		if num("chat_id") != f.chatID {
			f.fail(w, 400, "Bad Request: chat not found")
			return
		}
		f.mu.Lock()
		ch := tgChatFull{ID: f.chatID, Type: "private"}
		if m := f.msgs[f.pinned]; m != nil && !m.Deleted && f.pinned != 0 {
			ch.PinnedMessage = &tgMessage{MessageID: m.ID, Chat: tgChat{ID: m.Chat, Type: "private"}, Text: m.Text}
		}
		f.mu.Unlock()
		f.reply(w, ch)
	case "sendMessage":
		var text string
		json.Unmarshal(p["text"], &text)
		var mk *tgMarkup
		if p["reply_markup"] != nil {
			mk = &tgMarkup{}
			json.Unmarshal(p["reply_markup"], mk)
		}
		f.mu.Lock()
		f.nextMsg++
		m := &fakeMsg{ID: f.nextMsg, Chat: num("chat_id"), Text: text, Markup: mk}
		f.msgs[m.ID] = m
		f.mu.Unlock()
		f.reply(w, tgMessage{MessageID: m.ID, Chat: tgChat{ID: m.Chat, Type: "private"}, Text: text})
	case "editMessageText":
		var text string
		json.Unmarshal(p["text"], &text)
		f.mu.Lock()
		m := f.msgs[num("message_id")]
		if m == nil || m.Deleted {
			f.mu.Unlock()
			f.fail(w, 400, "Bad Request: message to edit not found")
			return
		}
		var mk *tgMarkup
		if p["reply_markup"] != nil {
			mk = &tgMarkup{}
			json.Unmarshal(p["reply_markup"], mk)
		}
		same := m.Text == text && fmt.Sprint(m.Markup) == fmt.Sprint(mk)
		if !same {
			m.Text, m.Markup = text, mk
			m.Edits++
		}
		f.mu.Unlock()
		if same {
			f.fail(w, 400, "Bad Request: message is not modified")
			return
		}
		f.reply(w, true)
	case "answerCallbackQuery":
		f.mu.Lock()
		if f.stale > 0 {
			f.stale--
			f.mu.Unlock()
			f.fail(w, 400, "Bad Request: query is too old and response timeout expired or query ID is invalid")
			return
		}
		f.mu.Unlock()
		var id, text string
		var alert bool
		json.Unmarshal(p["callback_query_id"], &id)
		json.Unmarshal(p["text"], &text)
		json.Unmarshal(p["show_alert"], &alert)
		f.mu.Lock()
		f.answered = append(f.answered, fakeAnswer{id, text, alert})
		f.mu.Unlock()
		f.reply(w, true)
	case "pinChatMessage":
		f.mu.Lock()
		f.pinned = num("message_id")
		f.mu.Unlock()
		f.reply(w, true)
	case "unpinChatMessage":
		f.mu.Lock()
		if f.pinned == num("message_id") {
			f.pinned = 0
		}
		f.mu.Unlock()
		f.reply(w, true)
	case "deleteMessage":
		f.mu.Lock()
		if m := f.msgs[num("message_id")]; m != nil {
			m.Deleted = true
		}
		f.mu.Unlock()
		f.reply(w, true)
	case "getUpdates":
		f.getUpdates(w, r, num("offset"), int(num("timeout")))
	default:
		f.fail(w, 404, "Not Found")
	}
}

func (f *fakeTelegram) getUpdates(w http.ResponseWriter, r *http.Request, offset int64, timeout int) {
	f.mu.Lock()
	if f.rogue {
		f.conflict++
		f.mu.Unlock()
		f.fail(w, 409, "Conflict: terminated by other getUpdates request; make sure that only one bot instance is running")
		return
	}
	f.pollGen++
	mine := f.pollGen
	f.mu.Unlock()
	wait := 80 * time.Millisecond
	if timeout > 0 {
		wait = time.Duration(timeout) * time.Second
	}
	deadline := time.Now().Add(wait)
	for {
		f.mu.Lock()
		if f.pollGen != mine { // Telegram terminates the older of two concurrent getUpdates
			f.conflict++
			f.mu.Unlock()
			f.fail(w, 409, "Conflict: terminated by other getUpdates request; make sure that only one bot instance is running")
			return
		}
		if offset > 0 {
			kept := f.updates[:0]
			for _, u := range f.updates {
				if u.UpdateID >= offset {
					kept = append(kept, u)
				}
			}
			f.updates = kept
		}
		out := append([]tgUpdate(nil), f.updates...)
		f.mu.Unlock()
		if len(out) > 0 || time.Now().After(deadline) || r.Context().Err() != nil {
			f.reply(w, out)
			return
		}
		time.Sleep(15 * time.Millisecond)
	}
}

// ---- test controls ---------------------------------------------------------------------------

func (f *fakeTelegram) push(u tgUpdate) {
	f.mu.Lock()
	f.nextUpd++
	u.UpdateID = f.nextUpd
	f.updates = append(f.updates, u)
	f.mu.Unlock()
}

// say sends a text message as `from` in a chat of the given type.
func (f *fakeTelegram) say(chat, from int64, kind, text string) {
	f.push(tgUpdate{Message: &tgMessage{MessageID: 1, From: &tgUser{ID: from}, Chat: tgChat{ID: chat, Type: kind}, Text: text}})
}

var fakeCB int

// tapAs presses a button as `from`. The message is attributed to chat.
func (f *fakeTelegram) tapAs(chat, from int64, msg int64, data string) string {
	f.mu.Lock()
	fakeCB++
	id := fmt.Sprintf("cb%d", fakeCB)
	f.mu.Unlock()
	f.push(tgUpdate{Callback: &tgCallback{ID: id, From: tgUser{ID: from}, Message: &tgMessage{MessageID: msg, Chat: tgChat{ID: chat, Type: "private"}}, Data: data}})
	return id
}

func (f *fakeTelegram) tap(msg int64, data string) string {
	return f.tapAs(f.chatID, f.chatID, msg, data)
}

// tapReplay re-delivers a callback with the SAME id (Telegram can redeliver an update).
func (f *fakeTelegram) tapReplay(id string, msg int64, data string) {
	f.push(tgUpdate{Callback: &tgCallback{ID: id, From: tgUser{ID: f.chatID}, Message: &tgMessage{MessageID: msg, Chat: tgChat{ID: f.chatID, Type: "private"}}, Data: data}})
}

func (f *fakeTelegram) msg(id int64) fakeMsg {
	f.mu.Lock()
	defer f.mu.Unlock()
	if m := f.msgs[id]; m != nil {
		return *m
	}
	return fakeMsg{}
}

// button returns the callback data of the first button whose text contains label.
func (f *fakeTelegram) button(msg int64, label string) (string, bool) {
	m := f.msg(msg)
	if m.Markup == nil {
		return "", false
	}
	for _, row := range m.Markup.Keyboard {
		for _, b := range row {
			if strings.Contains(b.Text, label) {
				return b.Data, true
			}
		}
	}
	return "", false
}

// find returns the newest live message whose text contains substr.
func (f *fakeTelegram) find(substr string) (fakeMsg, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var best *fakeMsg
	for _, m := range f.msgs {
		if !m.Deleted && strings.Contains(m.Text, substr) && (best == nil || m.ID > best.ID) {
			best = m
		}
	}
	if best == nil {
		return fakeMsg{}, false
	}
	return *best, true
}

func (f *fakeTelegram) count(substr string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, m := range f.msgs {
		if !m.Deleted && strings.Contains(m.Text, substr) {
			n++
		}
	}
	return n
}

func (f *fakeTelegram) pinnedText() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if m := f.msgs[f.pinned]; m != nil && !m.Deleted {
		return m.Text
	}
	return ""
}

func (f *fakeTelegram) answers() []fakeAnswer {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]fakeAnswer(nil), f.answered...)
}

func (f *fakeTelegram) allText() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var sb strings.Builder
	for _, m := range f.msgs {
		sb.WriteString(m.Text + "\n")
		if m.Markup != nil {
			for _, r := range m.Markup.Keyboard {
				for _, b := range r {
					sb.WriteString(b.Text + "\n")
				}
			}
		}
	}
	for _, a := range f.answered {
		sb.WriteString(a.Text + "\n")
	}
	return sb.String()
}

// waitFor polls until cond is true, failing the test after the deadline.
func waitFor(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// ---- node fixture -----------------------------------------------------------------------------

const testBotToken = "7000000001:AAHtestTokenForRoutTelegramAAAAAAAAAAAA"

// tgNode is one Rout server: its own home, state, AI exits and (when started) service loop.
type tgNode struct {
	t       *testing.T
	a       *App
	name    string
	node    Profile
	exitA   Exit // usable
	exitB   Exit // usable
	exitBad Exit // points back at this server: not usable for AI
	cancel  context.CancelFunc
	done    chan error
	hub     *tgHub
	hubMu   sync.Mutex
	clock   *tgClock
}

// tgClock is a controllable clock so "offline" can be tested without waiting.
type tgClock struct {
	mu sync.Mutex
	d  time.Duration
}

func (c *tgClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().Add(c.d)
}
func (c *tgClock) advance(d time.Duration) { c.mu.Lock(); c.d += d; c.mu.Unlock() }

func newTGNode(t *testing.T, tg *fakeTelegram, name string) *tgNode {
	t.Helper()
	a := testApp(t)
	a.Language = "zh-CN" // keep the source (Chinese) button labels the tests look for
	n := &tgNode{t: t, a: a, name: name, clock: &tgClock{}}
	n.node = aiTestNode(t, a, "vless", name+"-Reality")
	n.exitA = n.secretExit(name+"-ExitA", "198.51.100.10")
	n.exitB = n.secretExit(name+"-ExitB", "198.51.100.11")
	n.exitBad = aiTestExit(t, a, name+"-Loop", "127.0.0.1", n.node.Port)
	if e := a.SetAIExit(n.exitA.ID); e != nil {
		t.Fatal(e)
	}
	if e := a.SetAIBindings([]string{n.node.ID}); e != nil {
		t.Fatal(e)
	}
	a.telegram = &telegramHooks{base: tg.URL(), hostname: func() string { return name },
		addresses: func() Addresses { return Addresses{IPv4: "127.0.0.1"} },
		now:       n.clock.now,
		pollWait:  40 * time.Millisecond, agentWait: 250 * time.Millisecond, retry: 30 * time.Millisecond,
		listen: "127.0.0.1:0",
		onHub: func(h *tgHub) {
			n.hubMu.Lock()
			n.hub = h
			n.hubMu.Unlock()
			// a restarted hub keeps its port, as it does in production where the port is configured
			n.a.telegram.listen = h.addr()
		}}
	return n
}

// secretExit adds an exit whose address and credentials must never reach Telegram.
func (n *tgNode) secretExit(name, host string) Exit {
	n.t.Helper()
	s, e := n.a.Load()
	if e != nil {
		n.t.Fatal(e)
	}
	ex := Exit{ID: RandomHex(6), Name: name, Proxy: Proxy{Protocol: "socks5", Host: host, Port: 1080, Username: tgSecretUser, Password: tgSecretPass}}
	if e = n.a.Commit(s, UpsertExit(s, ex), false); e != nil {
		n.t.Fatal(e)
	}
	return ex
}

const (
	tgSecretUser = "exit-user-xyz"
	tgSecretPass = "ExitPassw0rd-SECRET-123"
)

func (n *tgNode) theHub() *tgHub {
	n.hubMu.Lock()
	defer n.hubMu.Unlock()
	return n.hub
}

// start runs the service loop; stop ends it. Both are safe to call repeatedly.
func (n *tgNode) start() {
	if n.cancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	n.cancel, n.done = cancel, make(chan error, 1)
	go func() { n.done <- n.a.RunTelegram(ctx) }()
	n.t.Cleanup(n.stop)
}

func (n *tgNode) stop() {
	if n.cancel == nil {
		return
	}
	n.cancel()
	select {
	case <-n.done:
	case <-time.After(5 * time.Second):
		n.t.Error("service loop did not stop")
	}
	n.cancel = nil
	n.hubMu.Lock()
	n.hub = nil
	n.hubMu.Unlock()
}

func (n *tgNode) status() AIStatus {
	n.t.Helper()
	st, e := n.a.AIStatus()
	if e != nil {
		n.t.Fatal(e)
	}
	return st
}

func (n *tgNode) runtime() TelegramRuntime {
	rt, _ := n.a.LoadTelegramRuntime()
	return rt
}

// bindHub binds this node as the hub with multi-server mode on and starts it.
func (n *tgNode) bindHub(tg *fakeTelegram) {
	n.t.Helper()
	res, e := n.a.TelegramBind(context.Background(), TelegramBindRequest{Token: testBotToken, ChatID: tg.chatID})
	if e != nil || res.Role != tgRoleHub {
		n.t.Fatalf("hub bind: %+v %v", res, e)
	}
	if e = n.a.TelegramSetMultiServer(true, 0, nil); e != nil {
		n.t.Fatal(e)
	}
	n.start()
	waitFor(n.t, "hub announcement", 5*time.Second, func() bool { return strings.Contains(tg.pinnedText(), announcePrefix) })
	waitFor(n.t, "hub listener", 5*time.Second, func() bool { return n.theHub() != nil })
}

// bindAgent binds this node to the announced hub, confirming the fingerprint like a person would.
func (n *tgNode) bindAgent(tg *fakeTelegram) TelegramBindResult {
	n.t.Helper()
	first, e := n.a.TelegramBind(context.Background(), TelegramBindRequest{Token: testBotToken, ChatID: tg.chatID})
	if e != nil || !first.NeedsTrust || first.Role != tgRoleAgent {
		n.t.Fatalf("agent bind step 1: %+v %v", first, e)
	}
	res, e := n.a.TelegramBind(context.Background(), TelegramBindRequest{Token: testBotToken, ChatID: tg.chatID, TrustHubFP: fingerprintGroups(first.HubFP)})
	if e != nil || res.Role != tgRoleAgent {
		n.t.Fatalf("agent bind step 2: %+v %v", res, e)
	}
	n.start()
	return res
}

// approvePending presses "Allow" on the join request of the named server, as the owner would.
func approvePending(t *testing.T, tg *fakeTelegram, name string) {
	t.Helper()
	var m fakeMsg
	var data string
	waitFor(t, "join request for "+name, 5*time.Second, func() bool {
		var ok bool
		m, ok = tg.find("<b>" + name + "</b>")
		if !ok {
			return false
		}
		data, ok = tg.button(m.ID, "允许")
		return ok
	})
	tg.tap(m.ID, data)
}
