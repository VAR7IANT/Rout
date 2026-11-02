package rout

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Native relay: Rout's own TCP/UDP forwarder.
//
// It exists because the legacy GOST relay cannot honor the address-family model: GOST
// always binds "::" as a dual-stack socket (never IPv6-only), cannot restrict the families
// it dials, and leaves DNS handling to the system. This forwarder
//
//   - binds one explicit socket per family (tcp4 / tcp6 with IPV6_V6ONLY), so IPv4-only,
//     IPv6-only and dual stack behave the same on every kernel configuration;
//   - dials the destination under an outbound policy, independent of the inbound family
//     (IPv6 in → IPv4 out is two ordinary TCP connections; no NAT64 is involved);
//   - resolves a domain destination again as its TTL expires and after a failed dial, so a
//     destination with a dynamic address keeps working;
//   - forwards bytes only. It speaks no proxy protocol, accepts no commands, holds no
//     credentials and never opens a proxy of its own.
//
// Relays created by earlier versions keep running on GOST until the user changes their
// network settings.

const nativeRelayConfigVersion = 1

type nativeListen struct {
	Network string `json:"network"` // tcp4, tcp6, udp4, udp6
	Addr    string `json:"addr"`
}

// nativeRelayConfig is the file the service reads (profiles/ID/config.json, mode 0600).
type nativeRelayConfig struct {
	Version     int            `json:"version"`
	Engine      string         `json:"engine"`
	ID          string         `json:"id"`
	Listen      []nativeListen `json:"listen"`
	Target      string         `json:"target"`
	Outbound    string         `json:"outbound"`
	MaxConns    int            `json:"max_conns,omitempty"`
	MaxSessions int            `json:"max_udp_sessions,omitempty"`
	UDPIdleSec  int            `json:"udp_idle_seconds,omitempty"`
}

const (
	defaultMaxConns    = 4096
	defaultMaxSessions = 4096
	defaultUDPIdle     = 60 * time.Second
	udpPacketMax       = 64 * 1024
)

func nativeRelayConfigOf(p Profile) (nativeRelayConfig, error) {
	if !p.nativeRelay() {
		return nativeRelayConfig{}, errors.New("not a native relay")
	}
	c := nativeRelayConfig{Version: nativeRelayConfigVersion, Engine: "rout-relay", ID: p.ID, Target: p.Target, Outbound: p.outboundPolicy()}
	for _, s := range p.bindSpecs() {
		c.Listen = append(c.Listen, nativeListen{Network: s.Network, Addr: s.Addr()})
	}
	return c, nil
}

func (c nativeRelayConfig) validate() error {
	if c.Version != nativeRelayConfigVersion || c.Engine != "rout-relay" {
		return errors.New("unsupported relay configuration version")
	}
	if len(c.Listen) == 0 {
		return errors.New("relay has no listening address")
	}
	for _, l := range c.Listen {
		switch l.Network {
		case "tcp4", "tcp6", "udp4", "udp6":
		default:
			return fmt.Errorf("invalid listen network %q", l.Network)
		}
		if _, _, e := net.SplitHostPort(l.Addr); e != nil {
			return errors.New("invalid listen address")
		}
	}
	if _, _, e := splitTarget(c.Target); e != nil {
		return e
	}
	if !validOutboundPolicy(c.Outbound) {
		return errors.New("invalid outbound policy")
	}
	return nil
}

// relayLogger writes plain lines to stderr (the journal) and rate-limits repeated errors,
// so a dead destination cannot flood the log.
type relayLogger struct {
	mu   sync.Mutex
	w    io.Writer
	last map[string]time.Time
	hits map[string]int
}

func newRelayLogger(w io.Writer) *relayLogger {
	return &relayLogger{w: w, last: map[string]time.Time{}, hits: map[string]int{}}
}
func (l *relayLogger) printf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.w, "rout-relay: "+format+"\n", args...)
}

// limited logs a message at most once per 10 s per key and says how many were suppressed.
func (l *relayLogger) limited(key, format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.hits[key]++
	if t, ok := l.last[key]; ok && time.Since(t) < 10*time.Second {
		return
	}
	extra := ""
	if n := l.hits[key] - 1; n > 0 {
		extra = fmt.Sprintf(" (+%d similar)", n)
	}
	l.hits[key] = 0
	l.last[key] = time.Now()
	fmt.Fprintf(l.w, "rout-relay: "+format+extra+"\n", args...)
}

// relayRuntime wires a configuration to sockets and a dialer; tests replace the hooks.
type relayRuntime struct {
	cfg    nativeRelayConfig
	dialer *PolicyDialer
	log    *relayLogger
	// listenTCP / listenUDP open sockets; defaults bind real ones.
	listenTCP func(network, addr string) (net.Listener, error)
	listenUDP func(network, addr string) (net.PacketConn, error)

	mu    sync.Mutex
	live  map[net.Conn]struct{} // connections being forwarded, closed on shutdown
	bound []string
	stats relayStats
}

// track registers a live connection; it reports false (and the caller must close it) once
// the relay is shutting down.
func (r *relayRuntime) track(c net.Conn) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.live == nil {
		return false
	}
	r.live[c] = struct{}{}
	return true
}
func (r *relayRuntime) untrack(c net.Conn) {
	r.mu.Lock()
	delete(r.live, c)
	r.mu.Unlock()
}

// closeLive ends every forwarded connection: a stopping relay must not wait for
// long-lived tunnels, or the init system would have to kill it.
func (r *relayRuntime) closeLive() {
	r.mu.Lock()
	live := r.live
	r.live = nil
	r.mu.Unlock()
	for c := range live {
		c.Close()
	}
}

type relayStats struct {
	accepted, dialFail, refusedBusy atomic.Int64
	udpSessions, udpDropped         atomic.Int64
}

func newRelayRuntime(cfg nativeRelayConfig, log io.Writer) *relayRuntime {
	r := &relayRuntime{cfg: cfg, dialer: NewPolicyDialer(cfg.Outbound), log: newRelayLogger(log)}
	r.listenTCP = func(network, addr string) (net.Listener, error) {
		lc := net.ListenConfig{KeepAlive: 30 * time.Second}
		return lc.Listen(context.Background(), network, addr)
	}
	r.listenUDP = func(network, addr string) (net.PacketConn, error) {
		var lc net.ListenConfig
		return lc.ListenPacket(context.Background(), network, addr)
	}
	return r
}

// bind opens every socket first. If any fails, the ones already open are closed and the
// error names the failing family, so a half-bound relay never runs.
func (r *relayRuntime) bind() (tcp []net.Listener, udp []net.PacketConn, err error) {
	defer func() {
		if err != nil {
			for _, l := range tcp {
				l.Close()
			}
			for _, c := range udp {
				c.Close()
			}
			tcp, udp = nil, nil
		}
	}()
	for _, l := range r.cfg.Listen {
		switch l.Network {
		case "tcp4", "tcp6":
			ln, e := r.listenTCP(l.Network, l.Addr)
			if e != nil {
				return tcp, udp, fmt.Errorf("cannot listen on %s %s: %w", l.Network, l.Addr, e)
			}
			tcp = append(tcp, ln)
			r.bound = append(r.bound, l.Network+" "+ln.Addr().String())
		default:
			pc, e := r.listenUDP(l.Network, l.Addr)
			if e != nil {
				return tcp, udp, fmt.Errorf("cannot listen on %s %s: %w", l.Network, l.Addr, e)
			}
			udp = append(udp, pc)
			r.bound = append(r.bound, l.Network+" "+pc.LocalAddr().String())
		}
	}
	return tcp, udp, nil
}

// Serve binds and forwards until ctx ends. ready (optional) is closed once all sockets
// are open.
func (r *relayRuntime) Serve(ctx context.Context, ready chan<- struct{}) error {
	if e := r.cfg.validate(); e != nil {
		return e
	}
	tcp, udp, e := r.bind()
	if e != nil {
		return e
	}
	r.mu.Lock()
	r.live = map[net.Conn]struct{}{}
	r.mu.Unlock()
	r.dialer.Self = r.selfGuard(tcp, udp)
	for _, b := range r.bound {
		r.log.printf("listening %s -> %s (outbound %s)", b, r.cfg.Target, r.cfg.Outbound)
	}
	if ready != nil {
		close(ready)
	}
	var wg sync.WaitGroup
	maxConns := r.cfg.MaxConns
	if maxConns <= 0 {
		maxConns = defaultMaxConns
	}
	sem := make(chan struct{}, maxConns)
	for _, ln := range tcp {
		wg.Add(1)
		go func(ln net.Listener) { defer wg.Done(); r.serveTCP(ctx, ln, sem) }(ln)
	}
	idle := defaultUDPIdle
	if r.cfg.UDPIdleSec > 0 {
		idle = time.Duration(r.cfg.UDPIdleSec) * time.Second
	}
	maxSessions := r.cfg.MaxSessions
	if maxSessions <= 0 {
		maxSessions = defaultMaxSessions
	}
	for _, pc := range udp {
		wg.Add(1)
		go func(pc net.PacketConn) { defer wg.Done(); r.serveUDP(ctx, pc, idle, maxSessions) }(pc)
	}
	<-ctx.Done()
	for _, ln := range tcp {
		ln.Close()
	}
	for _, pc := range udp {
		pc.Close()
	}
	r.closeLive()
	wg.Wait()
	return nil
}

// selfGuard refuses to dial this relay's own listeners: a destination that points back at
// the relay would otherwise connect to itself in an endless loop.
func (r *relayRuntime) selfGuard(tcp []net.Listener, udp []net.PacketConn) func(netip.AddrPort) bool {
	ports := map[uint16]bool{}
	for _, l := range tcp {
		if ap, e := netip.ParseAddrPort(l.Addr().String()); e == nil {
			ports[ap.Port()] = true
		}
	}
	for _, c := range udp {
		if ap, e := netip.ParseAddrPort(c.LocalAddr().String()); e == nil {
			ports[ap.Port()] = true
		}
	}
	var mu sync.Mutex
	var cached map[string]bool
	var at time.Time
	local := func() map[string]bool {
		mu.Lock()
		defer mu.Unlock()
		if cached == nil || time.Since(at) > 30*time.Second {
			cached, at = localIPs(), time.Now()
		}
		return cached
	}
	return func(ap netip.AddrPort) bool {
		if !ports[ap.Port()] {
			return false
		}
		a := ap.Addr()
		return a.IsLoopback() || a.IsUnspecified() || local()[a.String()]
	}
}

func (r *relayRuntime) serveTCP(ctx context.Context, ln net.Listener, sem chan struct{}) {
	var wg sync.WaitGroup
	defer wg.Wait()
	var backoff time.Duration
	for {
		c, e := ln.Accept()
		if e != nil {
			if ctx.Err() != nil || errors.Is(e, net.ErrClosed) {
				return
			}
			if ne, ok := e.(net.Error); ok && ne.Timeout() {
				if backoff = backoff*2 + 5*time.Millisecond; backoff > time.Second {
					backoff = time.Second
				}
				time.Sleep(backoff)
				continue
			}
			r.log.limited("accept", "accept failed: %v", e)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		backoff = 0
		select {
		case sem <- struct{}{}:
		default:
			r.stats.refusedBusy.Add(1)
			r.log.limited("busy", "connection limit reached; refusing new connections")
			c.Close()
			continue
		}
		r.stats.accepted.Add(1)
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			r.handleTCP(ctx, c)
		}()
	}
}

func (r *relayRuntime) handleTCP(ctx context.Context, in net.Conn) {
	defer in.Close()
	if !r.track(in) {
		return
	}
	defer r.untrack(in)
	dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	out, _, e := r.dialer.DialContext(dctx, r.cfg.Target)
	cancel()
	if e != nil {
		r.stats.dialFail.Add(1)
		r.log.limited("dial:"+kindOf(e), "cannot reach %s from %s: %v", r.cfg.Target, in.RemoteAddr(), e)
		return
	}
	defer out.Close()
	if !r.track(out) {
		return
	}
	defer r.untrack(out)
	for _, c := range []net.Conn{in, out} {
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.SetKeepAlive(true)
			_ = tc.SetKeepAlivePeriod(30 * time.Second)
		}
	}
	pipe(in, out)
}

func kindOf(err error) string {
	var de *DialError
	if errors.As(err, &de) {
		return de.Stage + "/" + de.Kind
	}
	return "other"
}

// pipe copies both directions until both finish. A direction that reaches EOF half-closes
// the other side's write end, so request/response protocols that close first still work.
func pipe(a, b net.Conn) {
	var wg sync.WaitGroup
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}
	wg.Add(2)
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
}

// ---- UDP -------------------------------------------------------------------

type udpSession struct {
	up     net.Conn
	client net.Addr
	last   atomic.Int64 // unix nanoseconds of last traffic either way
}

func (r *relayRuntime) serveUDP(ctx context.Context, pc net.PacketConn, idle time.Duration, max int) {
	var mu sync.Mutex
	sessions := map[string]*udpSession{}
	var wg sync.WaitGroup
	closeSession := func(key string, s *udpSession) {
		mu.Lock()
		if sessions[key] == s {
			delete(sessions, key)
		}
		mu.Unlock()
		s.up.Close()
	}
	// Idle sessions are removed so a client that vanished frees its socket.
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(idle / 4)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				now := time.Now().UnixNano()
				mu.Lock()
				var stale []string
				for k, s := range sessions {
					if time.Duration(now-s.last.Load()) > idle {
						stale = append(stale, k)
					}
				}
				var victims []*udpSession
				for _, k := range stale {
					victims = append(victims, sessions[k])
					delete(sessions, k)
				}
				mu.Unlock()
				for _, s := range victims {
					s.up.Close()
				}
			}
		}
	}()
	buf := make([]byte, udpPacketMax)
	for {
		n, from, e := pc.ReadFrom(buf)
		if e != nil {
			if ctx.Err() != nil || errors.Is(e, net.ErrClosed) {
				break
			}
			r.log.limited("udpread", "udp read failed: %v", e)
			time.Sleep(20 * time.Millisecond)
			continue
		}
		key := from.String()
		mu.Lock()
		s := sessions[key]
		count := len(sessions)
		mu.Unlock()
		if s == nil {
			if count >= max {
				r.stats.udpDropped.Add(1)
				r.log.limited("udpfull", "udp session limit reached; dropping packets from new clients")
				continue
			}
			dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			up, _, de := r.dialer.DialUDP(dctx, r.cfg.Target)
			cancel()
			if de != nil {
				r.stats.dialFail.Add(1)
				r.log.limited("udpdial:"+kindOf(de), "cannot reach %s for %s: %v", r.cfg.Target, key, de)
				continue
			}
			s = &udpSession{up: up, client: from}
			s.last.Store(time.Now().UnixNano())
			mu.Lock()
			sessions[key] = s
			mu.Unlock()
			r.stats.udpSessions.Add(1)
			wg.Add(1)
			go func(key string, s *udpSession) {
				defer wg.Done()
				defer closeSession(key, s)
				rb := make([]byte, udpPacketMax)
				for {
					m, e := s.up.Read(rb)
					if e != nil {
						return
					}
					s.last.Store(time.Now().UnixNano())
					if _, e = pc.WriteTo(rb[:m], s.client); e != nil {
						return
					}
				}
			}(key, s)
		}
		s.last.Store(time.Now().UnixNano())
		if _, e := s.up.Write(buf[:n]); e != nil {
			closeSession(key, s)
		}
	}
	mu.Lock()
	for k, s := range sessions {
		s.up.Close()
		delete(sessions, k)
	}
	mu.Unlock()
	wg.Wait()
}

// ---- entry point -------------------------------------------------------------

// RunNativeRelay is the body of the hidden `rout relay-serve CONFIG` command that the
// relay's service runs.
func RunNativeRelay(configPath string) error {
	b, e := os.ReadFile(configPath)
	if e != nil {
		return e
	}
	var cfg nativeRelayConfig
	if e = json.Unmarshal(b, &cfg); e != nil {
		return errors.New("invalid relay configuration")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return newRelayRuntime(cfg, os.Stderr).Serve(ctx, nil)
}

// bindProbe really binds (and releases) every socket a native entry needs, reporting the
// first family that cannot be bound. It is what "is this port free for this mode" means.
func bindProbe(p Profile) error {
	for _, s := range p.bindSpecs() {
		if !validPort(s.Port) {
			return errors.New("端口应为 1–65535")
		}
		if s.Network[:3] == "tcp" {
			l, e := net.Listen(s.Network, s.Addr())
			if e != nil {
				return fmt.Errorf("%s 端口 %d 不可用（%s）：%w", s.Network[:3], s.Port, familyName(s.Network), e)
			}
			l.Close()
			continue
		}
		c, e := net.ListenPacket(s.Network, s.Addr())
		if e != nil {
			return fmt.Errorf("%s 端口 %d 不可用（%s）：%w", s.Network[:3], s.Port, familyName(s.Network), e)
		}
		c.Close()
	}
	return nil
}
