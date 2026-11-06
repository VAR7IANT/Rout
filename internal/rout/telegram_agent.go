package rout

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

// An agent never listens: it dials the hub (outbound), proves its identity with its own
// certificate, verifies the hub by the certificate fingerprint it pinned at bind time, and
// long-polls for commands. If the hub's certificate ever differs from the pin the agent refuses
// to talk and waits for a local, deliberate re-trust: an announcement in a chat (which anyone
// holding the bot token could forge) is never enough to redirect an already bound server.

var (
	errTgHubChanged = errors.New("控制中心身份已变化")
	errTgRevoked    = errors.New("本服务器已被控制中心撤销授权")
)

// ---- runtime status (written by the service, read by the menu and the panel) -------------------

const (
	tgStateOK         = "ok"
	tgStateConnecting = "connecting"
	tgStatePending    = "pending"
	tgStateOffline    = "offline"
	tgStateRevoked    = "revoked"
	tgStateHubChanged = "hub_changed"
	tgStateConflict   = "conflict"
	tgStateError      = "error"
	tgStateStopped    = "stopped"
)

type TelegramRuntime struct {
	Role      string    `json:"role"`
	State     string    `json:"state"`
	Detail    string    `json:"detail,omitempty"`
	Since     time.Time `json:"since"`
	UpdatedAt time.Time `json:"updated_at"`
	BotUser   string    `json:"bot_username,omitempty"`
	Listen    string    `json:"listen,omitempty"`
	// Endpoints are the hub addresses agents are told to dial (as last announced). The panel
	// shows them from here: working them out again would mean looking up this server's public
	// address on every page refresh.
	Endpoints []string                `json:"endpoints,omitempty"`
	HubName   string                  `json:"hub_name,omitempty"`
	Servers   []TelegramRuntimeServer `json:"servers,omitempty"`
}

// TelegramRuntimeServer is the hub's last observation of one server (no credentials).
type TelegramRuntimeServer struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Online    bool      `json:"online"`
	LastSeen  time.Time `json:"last_seen,omitempty"`
	AIEnabled bool      `json:"ai_enabled,omitempty"`
	ExitName  string    `json:"exit_name,omitempty"`
	Version   string    `json:"version,omitempty"`
}

func (a *App) writeTelegramRuntime(rt TelegramRuntime) {
	rt.UpdatedAt = a.tgNow()
	if rt.Since.IsZero() {
		rt.Since = rt.UpdatedAt
	}
	if b, e := JSON(rt); e == nil {
		AtomicWrite(a.telegramStatusPath(), b, 0600)
	}
}

// tgRTBox serialises the hub's runtime status: the bot loop and the fleet ticker both update it.
type tgRTBox struct {
	app *App
	mu  sync.Mutex
	rt  TelegramRuntime
}

// set changes the runtime status and writes it out.
func (b *tgRTBox) set(change func(*TelegramRuntime)) {
	b.mu.Lock()
	defer b.mu.Unlock()
	change(&b.rt)
	b.app.writeTelegramRuntime(b.rt)
}

func (b *tgRTBox) state() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.rt.State
}

// LoadTelegramRuntime returns the last status the service wrote.
func (a *App) LoadTelegramRuntime() (TelegramRuntime, bool) {
	var rt TelegramRuntime
	b, e := os.ReadFile(a.telegramStatusPath())
	if e != nil || len(b) > 1<<20 || json.Unmarshal(b, &rt) != nil {
		return rt, false
	}
	return rt, true
}

// ---- agent ----------------------------------------------------------------------------------

type tgAgent struct {
	app    *App
	cfg    TelegramConfig
	hc     *http.Client
	cache  *tgCmdCache
	rt     TelegramRuntime
	mu     sync.Mutex // guards active (the heartbeat posts while a command runs)
	active int        // index of the endpoint that last worked
}

// tgCmdCache remembers the results of the last commands by ID, so a command the hub delivers
// again (its response was lost, or this component restarted meanwhile) is answered, not run twice.
// It lives for the whole process: restarting the agent loop after a configuration change must not
// forget what was already done.
type tgCmdCache struct {
	mu    sync.Mutex
	res   map[string]tgResult
	order []string
}

var tgCmdCaches sync.Map // home directory -> *tgCmdCache

func (a *App) tgCache() *tgCmdCache {
	c, _ := tgCmdCaches.LoadOrStore(a.Home, &tgCmdCache{res: map[string]tgResult{}})
	return c.(*tgCmdCache)
}

func (c *tgCmdCache) get(id string) (tgResult, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	r, ok := c.res[id]
	return r, ok
}

func (c *tgCmdCache) put(id string, r tgResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.res[id] = r
	c.order = append(c.order, id)
	if len(c.order) > 64 {
		delete(c.res, c.order[0])
		c.order = c.order[1:]
	}
}

func (a *App) newTelegramAgent(cfg TelegramConfig) (*tgAgent, error) {
	cert, e := cfg.identity().tlsCert()
	if e != nil {
		return nil, e
	}
	pin := cfg.Agent.HubFP
	tc := &tls.Config{
		Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13,
		// The hub's certificate is self-signed on purpose: trust is the pinned fingerprint, not
		// a CA. Chain validation is replaced by an exact comparison of the leaf.
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 || certFingerprint(raw[0]) != pin {
				return errTgHubChanged
			}
			return nil
		},
	}
	wait := a.tgConnectWait()
	tr := &http.Transport{TLSClientConfig: tc, DisableKeepAlives: false, DialContext: (&net.Dialer{Timeout: wait}).DialContext, TLSHandshakeTimeout: wait, IdleConnTimeout: 60 * time.Second, MaxIdleConns: 2}
	return &tgAgent{app: a, cfg: cfg, hc: &http.Client{Transport: tr}, cache: a.tgCache()}, nil
}

func (g *tgAgent) status(state, detail string) {
	if g.rt.State != state {
		g.rt.Since = g.app.tgNow()
	}
	g.rt.Role, g.rt.State, g.rt.Detail, g.rt.HubName = tgRoleAgent, state, detail, g.cfg.Agent.HubName
	g.app.writeTelegramRuntime(g.rt)
}

// post sends one JSON request to the active (else any) endpoint.
func (g *tgAgent) post(ctx context.Context, path string, in, out any, timeout time.Duration) (int, error) {
	var last error
	eps := g.cfg.Agent.Endpoints
	g.mu.Lock()
	start := g.active
	g.mu.Unlock()
	for i := 0; i < len(eps); i++ {
		ep := eps[(start+i)%len(eps)]
		b, _ := json.Marshal(in)
		cctx, cancel := context.WithTimeout(ctx, timeout)
		req, _ := http.NewRequestWithContext(cctx, http.MethodPost, "https://"+ep+path, bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		resp, e := g.hc.Do(req)
		if e != nil {
			cancel()
			if ctx.Err() != nil {
				return 0, ctx.Err()
			}
			if errors.Is(e, errTgHubChanged) {
				return 0, errTgHubChanged
			}
			last = e
			continue
		}
		raw, e := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		cancel()
		if e != nil {
			last = e
			continue
		}
		g.mu.Lock()
		g.active = (start + i) % len(eps)
		g.mu.Unlock()
		if out != nil && len(raw) > 0 {
			json.Unmarshal(raw, out)
		}
		return resp.StatusCode, nil
	}
	if last == nil {
		last = errors.New("无可用地址")
	}
	return 0, last
}

type tgStateOut struct {
	State string `json:"state"`
	Nonce string `json:"nonce"`
}

// enroll asks the hub to admit this server. It returns the hub's answer: pending or approved.
func (g *tgAgent) enroll(ctx context.Context) (string, error) {
	fp := g.cfg.identity().fingerprint()
	var ch tgStateOut
	code, e := g.post(ctx, "/v1/enroll/challenge", enrollIn{ServerID: g.cfg.ServerID, Name: g.cfg.Name}, &ch, 20*time.Second)
	if e != nil {
		return "", e
	}
	if code != http.StatusOK || len(ch.Nonce) != 32 {
		return ch.State, fmt.Errorf("控制中心拒绝了入网请求 (%d)", code)
	}
	proof := g.cfg.keys().enrollProof(ch.Nonce, g.cfg.ServerID, fp)
	var out tgStateOut
	code, e = g.post(ctx, "/v1/enroll", enrollIn{ServerID: g.cfg.ServerID, Name: g.cfg.Name, Nonce: ch.Nonce, Proof: proof}, &out, 20*time.Second)
	if e != nil {
		return "", e
	}
	if code != http.StatusOK {
		return out.State, fmt.Errorf("控制中心拒绝了入网请求 (%d)", code)
	}
	return out.State, nil
}

// run loops until ctx ends or a terminal state is reached (revoked, hub changed).
func (g *tgAgent) run(ctx context.Context) error {
	_, agentWait, retry := g.app.tgDurations()
	backoff := retry
	fails := 0
	g.status(tgStateConnecting, "")
	for ctx.Err() == nil {
		st, _ := g.app.tgStatus(g.cfg)
		var out pollOut
		var denied tgStateOut
		code, e := g.postPoll(ctx, st, &out, &denied, agentWait+30*time.Second)
		switch {
		case ctx.Err() != nil:
			return ctx.Err()
		case errors.Is(e, errTgHubChanged):
			g.status(tgStateHubChanged, "控制中心的证书与绑定时记录的不一致；为安全起见已停止，请在本机重新信任控制中心")
			return errTgHubChanged
		case e != nil:
			fails++
			g.status(tgStateOffline, "无法连接控制中心")
			if fails%3 == 0 {
				if err := g.rediscover(ctx); errors.Is(err, errTgHubChanged) {
					g.status(tgStateHubChanged, "聊天中公布的控制中心与绑定时记录的不一致；为安全起见已停止，请在本机重新信任控制中心")
					return errTgHubChanged
				}
			}
			if !sleepCtx(ctx, jitter(backoff)) {
				return ctx.Err()
			}
			if backoff *= 2; backoff > 60*time.Second {
				backoff = 60 * time.Second
			}
			continue
		case code == http.StatusForbidden:
			switch denied.State {
			case "revoked":
				g.markState("revoked")
				g.status(tgStateRevoked, "控制中心已撤销本服务器的授权")
				return errTgRevoked
			case "pending":
				g.status(tgStatePending, "等待你在 Telegram 中批准本服务器")
				if !sleepCtx(ctx, jitter(5*retry)) {
					return ctx.Err()
				}
			default:
				state, err := g.enroll(ctx)
				if err != nil {
					if state == "revoked" {
						g.markState("revoked")
						g.status(tgStateRevoked, "控制中心已拒绝或撤销本服务器")
						return errTgRevoked
					}
					g.status(tgStateOffline, "入网请求未被接受")
					if !sleepCtx(ctx, jitter(backoff)) {
						return ctx.Err()
					}
					continue
				}
				g.status(tgStatePending, "已向控制中心申请加入，请在 Telegram 中批准")
				if !sleepCtx(ctx, jitter(2*retry)) {
					return ctx.Err()
				}
			}
			continue
		case code != http.StatusOK:
			fails++
			g.status(tgStateOffline, fmt.Sprintf("控制中心暂不可用 (%d)", code))
			if !sleepCtx(ctx, jitter(backoff)) {
				return ctx.Err()
			}
			continue
		}
		fails, backoff = 0, retry
		g.markState("approved")
		g.status(tgStateOK, "")
		received := time.Now()
		stopBeat := g.heartbeat(ctx, len(out.Commands) > 0)
		for _, c := range out.Commands {
			res := g.execute(ctx, c, received)
			if _, e := g.post(ctx, "/v1/result", resultIn{Result: res}, nil, 20*time.Second); e != nil {
				// The hub redelivers and the cache answers without executing again; pause so a
				// path that polls but cannot report does not spin.
				sleepCtx(ctx, jitter(retry))
				break
			}
		}
		stopBeat()
	}
	return ctx.Err()
}

// heartbeat tells the hub this server is alive while it executes commands, which are sequential
// and can take a minute (the AI exit test): otherwise the hub, which sees no poll in that time,
// would show the server offline in the middle of an operation the owner started.
func (g *tgAgent) heartbeat(ctx context.Context, on bool) (stop func()) {
	if !on {
		return func() {}
	}
	_, agentWait, _ := g.app.tgDurations()
	every := agentWait / 3
	if every < 20*time.Millisecond {
		every = 20 * time.Millisecond
	}
	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-t.C:
				g.post(ctx, "/v1/ping", struct{}{}, nil, 10*time.Second)
			}
		}
	}()
	return func() { close(done); <-finished }
}

func (g *tgAgent) postPoll(ctx context.Context, st tgServerStatus, out *pollOut, denied *tgStateOut, timeout time.Duration) (int, error) {
	// A 403 carries {"state":..}; a 200 carries {"commands":[..]}. Decode into both shapes.
	var both struct {
		pollOut
		tgStateOut
	}
	code, e := g.post(ctx, "/v1/poll", pollIn{Status: &st}, &both, timeout)
	*out, *denied = both.pollOut, both.tgStateOut
	return code, e
}

func (g *tgAgent) markState(state string) {
	if g.cfg.Agent.State == state {
		return
	}
	if e := g.app.mutateTelegram(func(c *TelegramConfig) error {
		if c.Agent == nil {
			return nil
		}
		c.Agent.State = state
		return nil
	}); e == nil {
		g.cfg.Agent.State = state
	}
}

// execute answers from the de-duplication cache when it can, otherwise runs the command once.
func (g *tgAgent) execute(ctx context.Context, c tgCommand, received time.Time) tgResult {
	if r, ok := g.cache.get(c.ID); ok {
		return r
	}
	var res tgResult
	if e := tgCommandValid(c); e != nil {
		res = tgResult{ID: c.ID, Error: e.Error()}
	} else if time.Since(received) > time.Duration(c.TTL)*time.Second {
		res = tgResult{ID: c.ID, Error: "命令已过期"}
	} else if c.Kind == tgCmdCredentials {
		res = g.applyCredentials(ctx, c)
	} else {
		res = g.app.tgExecute(ctx, g.cfg, c)
	}
	res.ID = c.ID
	g.cache.put(c.ID, res)
	return res
}

// applyCredentials takes a new token/chat from the approved hub, but only after Telegram itself
// confirms the token works for that chat.
func (g *tgAgent) applyCredentials(ctx context.Context, c tgCommand) tgResult {
	cl := g.app.tgClient(c.Token)
	defer cl.close()
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	me, e := cl.getMe(cctx)
	if e != nil {
		return tgResult{ID: c.ID, Error: tgScrub(tgFriendly(e), 200, c.Token)}
	}
	if _, e = cl.getChat(cctx, c.ChatID); e != nil {
		return tgResult{ID: c.ID, Error: tgScrub(tgFriendly(e), 200, c.Token)}
	}
	if e = g.app.mutateTelegram(func(cfg *TelegramConfig) error {
		cfg.Token, cfg.ChatID, cfg.BotUser = c.Token, c.ChatID, me.Username
		return nil
	}); e != nil {
		return tgResult{ID: c.ID, Error: g.app.tgErr(e)}
	}
	return tgResult{ID: c.ID, OK: true, Note: "已更新 Bot 凭据"}
}

// rediscover re-reads the pinned announcement. It may refresh the hub's addresses, but only
// when the announced hub is the one this server pinned; anything else is a hard stop.
func (g *tgAgent) rediscover(ctx context.Context) error {
	cl := g.app.tgClient(g.cfg.Token)
	defer cl.close()
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	an, e := g.app.telegramFetchAnnouncement(cctx, cl, g.cfg)
	if e != nil {
		return nil // Telegram unreachable or nothing pinned: keep trying the known addresses
	}
	if an.HubID != g.cfg.Agent.HubID || an.FP != g.cfg.Agent.HubFP {
		return errTgHubChanged
	}
	if len(an.Endpoints) > 0 && !sameStrings(an.Endpoints, g.cfg.Agent.Endpoints) {
		if e := g.app.mutateTelegram(func(c *TelegramConfig) error {
			if c.Agent != nil {
				c.Agent.Endpoints = an.Endpoints
			}
			return nil
		}); e == nil {
			g.cfg.Agent.Endpoints = an.Endpoints
			g.mu.Lock()
			g.active = 0
			g.mu.Unlock()
		}
	}
	return nil
}

// telegramFetchAnnouncement reads and authenticates the pinned announcement of the chat.
func (a *App) telegramFetchAnnouncement(ctx context.Context, cl *tgClient, cfg TelegramConfig) (tgAnnouncement, error) {
	ch, e := cl.getChat(ctx, cfg.ChatID)
	if e != nil {
		return tgAnnouncement{}, e
	}
	if ch.PinnedMessage == nil {
		return tgAnnouncement{}, errors.New("no announcement")
	}
	return cfg.keys().openAnnouncement(ch.PinnedMessage.Text)
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// jitter spreads reconnects so a restarted hub is not hit by every agent at the same instant.
func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return d
	}
	return d/2 + time.Duration(rand.Int63n(int64(d)))
}

// telegramLeave tells the hub this server is unbinding so its certificate is revoked at once
// (best effort: an unreachable hub is cleaned up from the hub's own menu or the chat).
func (a *App) telegramLeave(ctx context.Context, cfg TelegramConfig) {
	if cfg.Role != tgRoleAgent || cfg.Agent == nil {
		return
	}
	g, e := a.newTelegramAgent(cfg)
	if e != nil {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	g.post(cctx, "/v1/leave", struct{}{}, nil, 8*time.Second)
}
