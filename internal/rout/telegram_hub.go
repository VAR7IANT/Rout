package rout

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// The hub is the one process that talks to Telegram's getUpdates for a bot. Every other server
// is an agent: it dials the hub (outbound from the agent) over mutually authenticated TLS 1.3,
// long-polls for commands and posts results. Nothing here accepts a command from the network
// unless the caller's certificate fingerprint was approved by a human in Telegram.

var (
	errTgOffline  = errors.New("服务器离线")
	errTgNoAnswer = errors.New("服务器没有响应，命令可能尚未执行；请稍后刷新状态")
	errTgBusy     = errors.New("该服务器正在执行另一个操作，请稍候")
)

type tgJob struct {
	cmd  tgCommand
	done chan tgResult
}

type tgPeer struct {
	id, name, fp string
	lastSeen     time.Time
	status       *tgServerStatus
	jobs         []*tgJob
	wake         chan struct{}
	stopPoll     chan struct{} // closed when a newer poll supersedes the current one
}

type tgNonce struct {
	fp, serverID string
	exp          time.Time
}

type tgHub struct {
	app   *App
	mu    sync.Mutex
	peers map[string]*tgPeer
	nonce map[string]tgNonce
	rate  map[string][]time.Time
	busy  map[string]bool
	ln    net.Listener
	srv   *http.Server
	// onPending is called (outside the lock) when a new server asks to join.
	onPending func(TelegramPendingRecord)
}

func newTelegramHub(a *App) *tgHub {
	return &tgHub{app: a, peers: map[string]*tgPeer{}, nonce: map[string]tgNonce{}, rate: map[string][]time.Time{}, busy: map[string]bool{}}
}

// ---- listener ------------------------------------------------------------------------------

// listen starts the mTLS endpoint. It is only called when multi-server mode is enabled.
func (h *tgHub) listen(cfg TelegramConfig) error {
	cert, e := cfg.identity().tlsCert()
	if e != nil {
		return e
	}
	addr := ":" + itoa(cfg.Hub.Port)
	if h.app.telegram != nil && h.app.telegram.listen != "" {
		addr = h.app.telegram.listen
	}
	ln, e := net.Listen("tcp", addr)
	if e != nil {
		return errors.New("无法监听控制中心端口：" + e.Error())
	}
	tc := &tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAnyClientCert, MinVersion: tls.VersionTLS13}
	_, agentWait, _ := h.app.tgDurations()
	h.ln = tls.NewListener(ln, tc)
	h.srv = &http.Server{Handler: h.handler(), ErrorLog: log.New(io.Discard, "", 0), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: agentWait + 40*time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 16 << 10}
	go h.srv.Serve(h.ln)
	return nil
}

func (h *tgHub) addr() string {
	if h.ln == nil {
		return ""
	}
	return h.ln.Addr().String()
}

func (h *tgHub) close() {
	if h.srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		h.srv.Shutdown(ctx)
		cancel()
		h.srv.Close()
	}
	h.mu.Lock()
	for _, p := range h.peers {
		h.failJobsLocked(p, errTgOffline)
	}
	h.mu.Unlock()
}

// ---- HTTP ----------------------------------------------------------------------------------

func (h *tgHub) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/enroll/challenge", h.wrap(h.hChallenge, false))
	mux.HandleFunc("/v1/enroll", h.wrap(h.hEnroll, false))
	mux.HandleFunc("/v1/poll", h.wrap(h.hPoll, true))
	mux.HandleFunc("/v1/result", h.wrap(h.hResult, true))
	mux.HandleFunc("/v1/bye", h.wrap(h.hBye, true))
	mux.HandleFunc("/v1/leave", h.wrap(h.hLeave, true))
	return mux
}

type tgReq struct {
	cfg TelegramConfig
	fp  string
	ip  string
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func tgPeerFingerprint(r *http.Request) (string, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "", errors.New("no client certificate")
	}
	c := r.TLS.PeerCertificates[0]
	pub, ok := c.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return "", errors.New("unsupported key")
	}
	now := time.Now()
	if now.Before(c.NotBefore) || now.After(c.NotAfter) {
		return "", errors.New("certificate not valid now")
	}
	return certFingerprint(c.Raw), nil
}

// wrap: POST only, bounded body, current configuration, caller fingerprint. When authed is set
// the fingerprint must belong to an approved server, otherwise the caller is told its state.
func (h *tgHub) wrap(fn func(http.ResponseWriter, *http.Request, tgReq), authed bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method"})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		cfg, e := h.app.LoadTelegram()
		if e != nil || cfg.Role != tgRoleHub || cfg.Hub == nil || !cfg.Hub.MultiServer {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "hub unavailable"})
			return
		}
		fp, e := tgPeerFingerprint(r)
		if e != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "identity"})
			return
		}
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		q := tgReq{cfg: cfg, fp: fp, ip: host}
		if authed {
			if _, ok := tgFindAgent(cfg, fp); !ok {
				writeJSON(w, http.StatusForbidden, map[string]string{"state": tgPeerState(cfg, fp)})
				return
			}
		}
		fn(w, r, q)
	}
}

func tgFindAgent(cfg TelegramConfig, fp string) (TelegramAgentRecord, bool) {
	for _, a := range cfg.Hub.Agents {
		if sameFingerprint(a.FP, fp) && len(fp) == 64 {
			return a, true
		}
	}
	return TelegramAgentRecord{}, false
}

// tgPeerState tells an unapproved caller where it stands: pending, revoked or unknown.
func tgPeerState(cfg TelegramConfig, fp string) string {
	for _, v := range cfg.Hub.Revoked {
		if v == fp {
			return "revoked"
		}
	}
	for _, p := range cfg.Hub.Pending {
		if p.FP == fp {
			return "pending"
		}
	}
	return "unknown"
}

// allow is a small per-address sliding window for the unauthenticated endpoints.
func (h *tgHub) allow(ip string, limit int, window time.Duration) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	kept := h.rate[ip][:0]
	for _, t := range h.rate[ip] {
		if now.Sub(t) < window {
			kept = append(kept, t)
		}
	}
	if len(kept) >= limit {
		h.rate[ip] = kept
		return false
	}
	h.rate[ip] = append(kept, now)
	if len(h.rate) > 512 { // forget idle addresses
		for k, v := range h.rate {
			if len(v) == 0 || now.Sub(v[len(v)-1]) > window {
				delete(h.rate, k)
			}
		}
	}
	return true
}

type enrollIn struct {
	ServerID string `json:"server_id"`
	Name     string `json:"name"`
	Nonce    string `json:"nonce"`
	Proof    string `json:"proof"`
}

func validServerID(id string) bool {
	return len(id) == 16 && strings.Trim(id, "0123456789abcdef") == ""
}

func (h *tgHub) hChallenge(w http.ResponseWriter, r *http.Request, q tgReq) {
	var in enrollIn
	if json.NewDecoder(r.Body).Decode(&in) != nil || !validServerID(in.ServerID) || validDisplayName(in.Name) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "request"})
		return
	}
	if state := tgPeerState(q.cfg, q.fp); state == "revoked" {
		writeJSON(w, http.StatusForbidden, map[string]string{"state": "revoked"})
		return
	}
	if !h.allow(q.ip, 12, time.Minute) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate"})
		return
	}
	n := randomID(16)
	h.mu.Lock()
	now := time.Now()
	for k, v := range h.nonce {
		if now.After(v.exp) {
			delete(h.nonce, k)
		}
	}
	if len(h.nonce) >= 128 {
		h.mu.Unlock()
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "busy"})
		return
	}
	h.nonce[n] = tgNonce{fp: q.fp, serverID: in.ServerID, exp: now.Add(2 * time.Minute)}
	h.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"nonce": n})
}

func (h *tgHub) hEnroll(w http.ResponseWriter, r *http.Request, q tgReq) {
	var in enrollIn
	if json.NewDecoder(r.Body).Decode(&in) != nil || !validServerID(in.ServerID) || validDisplayName(in.Name) != nil || len(in.Nonce) != 32 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "request"})
		return
	}
	if !h.allow(q.ip, 12, time.Minute) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate"})
		return
	}
	// The nonce is single-use and bound to this exact certificate and server ID.
	h.mu.Lock()
	nn, ok := h.nonce[in.Nonce]
	delete(h.nonce, in.Nonce)
	h.mu.Unlock()
	if !ok || time.Now().After(nn.exp) || nn.fp != q.fp || nn.serverID != in.ServerID {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "challenge"})
		return
	}
	if !q.cfg.keys().checkEnrollProof(in.Nonce, in.ServerID, q.fp, in.Proof) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "proof"})
		return
	}
	name := strings.TrimSpace(in.Name)
	if in.ServerID == q.cfg.ServerID {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "identity"})
		return
	}
	for _, rv := range q.cfg.Hub.Revoked {
		if rv == q.fp {
			writeJSON(w, http.StatusForbidden, map[string]string{"state": "revoked"})
			return
		}
	}
	for _, ag := range q.cfg.Hub.Agents {
		if ag.ID == in.ServerID {
			if ag.FP == q.fp {
				writeJSON(w, http.StatusOK, map[string]string{"state": "approved"})
				return
			}
			// A different certificate claiming an approved server's ID is refused outright;
			// the owner must revoke the old record deliberately first.
			writeJSON(w, http.StatusConflict, map[string]string{"error": "identity"})
			return
		}
	}
	rec := TelegramPendingRecord{ID: randomID(6), ServerID: in.ServerID, Name: name, FP: q.fp, RequestedAt: h.app.tgNow()}
	e := h.app.mutateTelegram(func(c *TelegramConfig) error {
		if c.Hub == nil {
			return errors.New("not a hub")
		}
		kept := c.Hub.Pending[:0]
		for _, p := range c.Hub.Pending {
			if p.ServerID != in.ServerID && p.FP != q.fp {
				kept = append(kept, p)
			}
		}
		c.Hub.Pending = kept
		if len(c.Hub.Pending) >= 16 {
			return errors.New("too many pending")
		}
		c.Hub.Pending = append(c.Hub.Pending, rec)
		return nil
	})
	if e != nil {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "busy"})
		return
	}
	if h.onPending != nil {
		h.onPending(rec)
	}
	writeJSON(w, http.StatusOK, map[string]string{"state": "pending"})
}

type pollIn struct {
	Status *tgServerStatus `json:"status"`
}
type pollOut struct {
	Commands []tgCommand `json:"commands"`
}

func (h *tgHub) peerLocked(id, name, fp string) *tgPeer {
	p := h.peers[id]
	if p == nil || p.fp != fp {
		if p != nil {
			h.failJobsLocked(p, errTgOffline)
		}
		p = &tgPeer{id: id, fp: fp, wake: make(chan struct{}, 1)}
		h.peers[id] = p
	}
	p.name = name
	return p
}

func (h *tgHub) failJobsLocked(p *tgPeer, e error) {
	for _, j := range p.jobs {
		select {
		case j.done <- tgResult{ID: j.cmd.ID, Error: e.Error()}:
		default:
		}
	}
	p.jobs = nil
}

func (h *tgHub) hPoll(w http.ResponseWriter, r *http.Request, q tgReq) {
	ag, _ := tgFindAgent(q.cfg, q.fp)
	var in pollIn
	json.NewDecoder(r.Body).Decode(&in)
	_, agentWait, _ := h.app.tgDurations()
	stop := make(chan struct{})
	h.mu.Lock()
	p := h.peerLocked(ag.ID, ag.Name, q.fp)
	p.lastSeen = h.app.tgNow()
	if in.Status != nil && in.Status.ServerID == ag.ID {
		st := *in.Status
		st.Name = ag.Name
		p.status = &st
	}
	if p.stopPoll != nil {
		close(p.stopPoll) // a newer poll replaces a stale connection
	}
	p.stopPoll = stop
	h.syncCredentialsLocked(q.cfg, p)
	h.mu.Unlock()
	timer := time.NewTimer(agentWait)
	defer timer.Stop()
	for {
		h.mu.Lock()
		// Every unanswered job is (re)delivered: if an earlier response was lost the agent
		// answers from its de-duplication cache instead of executing twice.
		var out []tgCommand
		for _, j := range p.jobs {
			out = append(out, j.cmd)
		}
		h.mu.Unlock()
		if len(out) > 0 {
			writeJSON(w, http.StatusOK, pollOut{Commands: out})
			return
		}
		select {
		case <-p.wake:
		case <-stop:
			writeJSON(w, http.StatusOK, pollOut{})
			return
		case <-timer.C:
			writeJSON(w, http.StatusOK, pollOut{})
			return
		case <-r.Context().Done():
			return
		}
	}
}

type resultIn struct {
	Result tgResult `json:"result"`
}

func (h *tgHub) hResult(w http.ResponseWriter, r *http.Request, q tgReq) {
	ag, _ := tgFindAgent(q.cfg, q.fp)
	var in resultIn
	if json.NewDecoder(r.Body).Decode(&in) != nil || in.Result.ID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "request"})
		return
	}
	h.mu.Lock()
	if p := h.peers[ag.ID]; p != nil && p.fp == q.fp {
		p.lastSeen = h.app.tgNow()
		for i, j := range p.jobs {
			if j.cmd.ID == in.Result.ID {
				p.jobs = append(p.jobs[:i], p.jobs[i+1:]...)
				if in.Result.Status != nil && in.Result.Status.ServerID == ag.ID {
					st := *in.Result.Status
					st.Name = ag.Name
					p.status = &st
				}
				select {
				case j.done <- in.Result:
				default:
				}
				break
			}
		}
	}
	h.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"ok": "1"})
}

// syncCredentialsLocked brings an approved server up to date after the Bot Token or Chat ID
// was replaced on the hub: the new credentials travel only over the pinned, mutually
// authenticated channel, and only to servers a human already approved.
func (h *tgHub) syncCredentialsLocked(cfg TelegramConfig, p *tgPeer) {
	if p.status == nil || p.status.CredTag == "" || p.status.CredTag == cfg.credTag() {
		return
	}
	for _, j := range p.jobs {
		if j.cmd.Kind == tgCmdCredentials {
			return
		}
	}
	c := tgCommand{ID: randomID(8), Kind: tgCmdCredentials, Token: cfg.Token, ChatID: cfg.ChatID, Expires: h.app.tgNow().Add(10 * time.Minute).Unix()}
	p.jobs = append(p.jobs, &tgJob{cmd: c, done: make(chan tgResult, 1)})
}

// hLeave is a server unbinding itself: the hub forgets it and will refuse its certificate.
func (h *tgHub) hLeave(w http.ResponseWriter, r *http.Request, q tgReq) {
	ag, _ := tgFindAgent(q.cfg, q.fp)
	h.revoke(ag.ID)
	writeJSON(w, http.StatusOK, map[string]string{"ok": "1"})
}

func (h *tgHub) hBye(w http.ResponseWriter, r *http.Request, q tgReq) {
	ag, _ := tgFindAgent(q.cfg, q.fp)
	h.mu.Lock()
	if p := h.peers[ag.ID]; p != nil && p.fp == q.fp {
		p.lastSeen = time.Time{}
		h.failJobsLocked(p, errTgOffline)
	}
	h.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"ok": "1"})
}

// ---- the hub's view of the fleet -------------------------------------------------------------

type tgServerView struct {
	ID, Name string
	Local    bool
	Online   bool
	LastSeen time.Time
	Status   *tgServerStatus
}

func (h *tgHub) onlineWindow() time.Duration {
	_, agentWait, _ := h.app.tgDurations()
	return agentWait + 10*time.Second
}

// servers lists this server first, then every approved server by name.
func (h *tgHub) servers(cfg TelegramConfig) []tgServerView {
	var out []tgServerView
	local := tgServerView{ID: cfg.ServerID, Name: cfg.Name, Local: true, Online: true, LastSeen: h.app.tgNow()}
	if st, e := h.app.tgStatus(cfg); e == nil {
		local.Status = &st
	}
	out = append(out, local)
	h.mu.Lock()
	defer h.mu.Unlock()
	var rest []tgServerView
	for _, ag := range cfg.Hub.Agents {
		v := tgServerView{ID: ag.ID, Name: ag.Name}
		if p := h.peers[ag.ID]; p != nil && p.fp == ag.FP {
			v.LastSeen = p.lastSeen
			v.Online = !p.lastSeen.IsZero() && h.app.tgNow().Sub(p.lastSeen) < h.onlineWindow()
			if p.status != nil {
				st := *p.status
				v.Status = &st
			}
		}
		rest = append(rest, v)
	}
	sort.SliceStable(rest, func(i, j int) bool { return strings.ToLower(rest[i].Name) < strings.ToLower(rest[j].Name) })
	return append(out, rest...)
}

func (h *tgHub) findServer(cfg TelegramConfig, id string) (tgServerView, bool) {
	for _, v := range h.servers(cfg) {
		if v.ID == id {
			return v, true
		}
	}
	return tgServerView{}, false
}

// tryLock/unlock serialise operations per server: a second tap while one runs is refused,
// which also makes double-taps harmless.
func (h *tgHub) tryLock(id string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.busy[id] {
		return false
	}
	h.busy[id] = true
	return true
}
func (h *tgHub) unlock(id string) {
	h.mu.Lock()
	delete(h.busy, id)
	h.mu.Unlock()
}

// dispatch runs one command on a server, here or through its agent, and waits for the result.
func (h *tgHub) dispatch(ctx context.Context, cfg TelegramConfig, serverID string, c tgCommand, wait time.Duration) (tgResult, error) {
	c.Expires = h.app.tgNow().Add(wait + 15*time.Second).Unix()
	if serverID == cfg.ServerID {
		return h.app.tgExecute(ctx, cfg, c), nil
	}
	if err := tgCommandValid(c, h.app.tgNow()); err != nil {
		return tgResult{}, err
	}
	h.mu.Lock()
	var ag *TelegramAgentRecord
	for i := range cfg.Hub.Agents {
		if cfg.Hub.Agents[i].ID == serverID {
			ag = &cfg.Hub.Agents[i]
		}
	}
	p := h.peers[serverID]
	if ag == nil || p == nil || p.fp != ag.FP || p.lastSeen.IsZero() || h.app.tgNow().Sub(p.lastSeen) >= h.onlineWindow() {
		h.mu.Unlock()
		return tgResult{}, errTgOffline
	}
	job := &tgJob{cmd: c, done: make(chan tgResult, 1)}
	p.jobs = append(p.jobs, job)
	select {
	case p.wake <- struct{}{}:
	default:
	}
	h.mu.Unlock()
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case res := <-job.done:
		if res.Error == errTgOffline.Error() && !res.OK {
			return res, errTgOffline
		}
		return res, nil
	case <-timer.C:
	case <-ctx.Done():
	}
	h.mu.Lock()
	for i, j := range p.jobs {
		if j == job {
			p.jobs = append(p.jobs[:i], p.jobs[i+1:]...)
			break
		}
	}
	h.mu.Unlock()
	return tgResult{}, errTgNoAnswer
}

// ---- approvals (used by the bot, the menu and the panel) ---------------------------------------

func (h *tgHub) approve(reqID string) (TelegramAgentRecord, error) {
	var rec TelegramAgentRecord
	e := h.app.mutateTelegram(func(c *TelegramConfig) error {
		if c.Hub == nil {
			return errors.New("not a hub")
		}
		for i, p := range c.Hub.Pending {
			if p.ID == reqID {
				if len(c.Hub.Agents) >= 64 {
					return errors.New("已授权的服务器过多")
				}
				rec = TelegramAgentRecord{ID: p.ServerID, Name: p.Name, FP: p.FP, ApprovedAt: h.app.tgNow()}
				c.Hub.Agents = append(c.Hub.Agents, rec)
				c.Hub.Pending = append(c.Hub.Pending[:i], c.Hub.Pending[i+1:]...)
				return nil
			}
		}
		return errors.New("该请求已处理或已过期")
	})
	return rec, e
}

func (h *tgHub) reject(reqID string) (TelegramPendingRecord, error) {
	var rec TelegramPendingRecord
	e := h.app.mutateTelegram(func(c *TelegramConfig) error {
		if c.Hub == nil {
			return errors.New("not a hub")
		}
		for i, p := range c.Hub.Pending {
			if p.ID == reqID {
				rec = p
				c.Hub.Pending = append(c.Hub.Pending[:i], c.Hub.Pending[i+1:]...)
				c.Hub.Revoked = tgAddRevoked(c.Hub.Revoked, p.FP)
				return nil
			}
		}
		return errors.New("该请求已处理或已过期")
	})
	return rec, e
}

// revoke removes an approved server: its certificate can never poll again.
func (h *tgHub) revoke(serverID string) error {
	var fp string
	e := h.app.mutateTelegram(func(c *TelegramConfig) error {
		if c.Hub == nil {
			return errors.New("not a hub")
		}
		for i, ag := range c.Hub.Agents {
			if ag.ID == serverID {
				fp = ag.FP
				c.Hub.Agents = append(c.Hub.Agents[:i], c.Hub.Agents[i+1:]...)
				c.Hub.Revoked = tgAddRevoked(c.Hub.Revoked, ag.FP)
				return nil
			}
		}
		return errors.New("未找到该服务器")
	})
	if e == nil {
		h.mu.Lock()
		if p := h.peers[serverID]; p != nil && p.fp == fp {
			p.lastSeen = time.Time{}
			h.failJobsLocked(p, errTgOffline)
			delete(h.peers, serverID)
		}
		h.mu.Unlock()
	}
	return e
}

func tgAddRevoked(list []string, fp string) []string {
	for _, v := range list {
		if v == fp {
			return list
		}
	}
	list = append(list, fp)
	if len(list) > 128 {
		list = list[len(list)-128:]
	}
	return list
}

// ---- announcement --------------------------------------------------------------------------

// endpoints are the addresses agents should dial: the manual list, else the detected public
// addresses with the hub port. A NAT-ed hub must set the list by hand (documented).
func (h *tgHub) endpoints(cfg TelegramConfig) []string {
	if !cfg.Hub.MultiServer {
		return nil
	}
	if len(cfg.Hub.Advertise) > 0 {
		return cfg.Hub.Advertise
	}
	port := itoa(cfg.Hub.Port)
	if h.ln != nil {
		if _, p, e := net.SplitHostPort(h.ln.Addr().String()); e == nil {
			port = p
		}
	}
	var out []string
	ad := h.app.tgAddresses()
	for _, ip := range []string{ad.IPv4, ad.IPv6} {
		if ip != "" {
			out = append(out, net.JoinHostPort(ip, port))
		}
	}
	return out
}

func (h *tgHub) announcement(cfg TelegramConfig) tgAnnouncement {
	return tgAnnouncement{HubID: cfg.ServerID, Name: cfg.Name, Endpoints: h.endpoints(cfg), FP: cfg.identity().fingerprint(), TS: h.app.tgNow().Unix()}
}
