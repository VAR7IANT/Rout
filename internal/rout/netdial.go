package rout

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Dial errors carry the stage that failed and a machine-readable kind, so diagnostics can
// say "DNS", "refused", "timeout" or "no route" instead of one generic failure.
const (
	stageResolve = "resolve"
	stagePolicy  = "policy"
	stageConnect = "connect"

	kindDNS         = "dns"         // the name did not resolve
	kindNoAddress   = "no_address"  // resolved, but no address of an allowed family
	kindFamily      = "family"      // a literal address of a forbidden family
	kindRefused     = "refused"     // connection actively refused
	kindTimeout     = "timeout"     // no answer in time
	kindUnreachable = "unreachable" // no route / network down
	kindLoop        = "loop"        // the destination is this relay itself
	kindCanceled    = "canceled"
	kindOther       = "other"
)

type DialError struct {
	Stage  string
	Kind   string
	Target string
	Addr   string // the address that failed, when one was tried
	Err    error
}

func (e *DialError) Error() string {
	msg := map[string]string{
		kindDNS:         "cannot resolve host",
		kindNoAddress:   "no address allowed by the outbound policy",
		kindFamily:      "address family forbidden by the outbound policy",
		kindRefused:     "connection refused",
		kindTimeout:     "connection timed out",
		kindUnreachable: "no route to destination",
		kindLoop:        "destination is this relay itself",
		kindCanceled:    "canceled",
	}[e.Kind]
	if msg == "" {
		msg = "connection failed"
	}
	out := msg + ": " + e.Target
	if e.Addr != "" && e.Addr != e.Target {
		out += " (" + e.Addr + ")"
	}
	if e.Err != nil && e.Kind != kindCanceled {
		out += ": " + e.Err.Error()
	}
	return out
}
func (e *DialError) Unwrap() error { return e.Err }

// classifyConnectError maps a net error from a connect attempt to a kind.
func classifyConnectError(err error) string {
	var dnsErr *net.DNSError
	switch {
	case err == nil:
		return ""
	case errors.Is(err, context.Canceled):
		return kindCanceled
	case errors.Is(err, syscall.ECONNREFUSED):
		return kindRefused
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.EADDRNOTAVAIL), errors.Is(err, syscall.EAFNOSUPPORT), errors.Is(err, syscall.ENETDOWN), errors.Is(err, syscall.EHOSTDOWN):
		return kindUnreachable
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded), errors.Is(err, syscall.ETIMEDOUT):
		return kindTimeout
	case errors.As(err, &dnsErr):
		return kindDNS
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return kindTimeout
	}
	return kindOther
}

// ---------------------------------------------------------------------------
// Resolver

// Resolver is a small TTL cache in front of the system resolver. The Go resolver does not
// expose DNS record TTLs, so entries live for a fixed, short time (TTL): a domain whose
// address changes is picked up within TTL, and sooner if every cached address fails
// (Invalidate). A failed refresh falls back to the previous answer for up to StaleFor, so a
// brief DNS outage does not interrupt a working relay; the age is reported, never hidden.
type Resolver struct {
	Lookup   func(ctx context.Context, network, host string) ([]netip.Addr, error)
	TTL      time.Duration // positive answers
	NegTTL   time.Duration // failed lookups
	StaleFor time.Duration // reuse an expired answer when the refresh fails
	Now      func() time.Time

	mu     sync.Mutex
	cache  map[string]*resolveEntry
	flight map[string]*resolveCall
}

type resolveEntry struct {
	addrs   []netip.Addr
	err     error
	fetched time.Time
	// stale marks an old answer kept because the refresh failed; since is when it was
	// really fetched.
	stale bool
	since time.Time
}

// origin is when the answer was really fetched, whatever the cache did to it since.
func (e *resolveEntry) origin() time.Time {
	if e.stale {
		return e.since
	}
	return e.fetched
}

type resolveCall struct {
	done  chan struct{}
	addrs []netip.Addr
	err   error
	stale bool
	age   time.Duration
}

// Resolution is what a lookup returned, with provenance for diagnostics.
type Resolution struct {
	Addrs  []netip.Addr
	Cached bool          // served from the cache
	Stale  bool          // the refresh failed; this is an older answer
	Age    time.Duration // age of a cached or stale answer
}

const (
	defaultResolveTTL    = 30 * time.Second
	defaultResolveNegTTL = 3 * time.Second
	defaultResolveStale  = 10 * time.Minute
)

func NewResolver() *Resolver {
	return &Resolver{
		TTL: defaultResolveTTL, NegTTL: defaultResolveNegTTL, StaleFor: defaultResolveStale,
		Lookup: func(ctx context.Context, network, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, network, host)
		},
	}
}
func (r *Resolver) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func lookupNetwork(v4, v6 bool) string {
	switch {
	case v4 && !v6:
		return "ip4"
	case v6 && !v4:
		return "ip6"
	}
	return "ip"
}

// Resolve returns the addresses of host for the allowed families. An IP literal needs no
// lookup. Only the record types the policy can use are queried.
func (r *Resolver) Resolve(ctx context.Context, host string, v4, v6 bool) (Resolution, error) {
	if ip, e := netip.ParseAddr(strings.Trim(host, "[]")); e == nil {
		return Resolution{Addrs: []netip.Addr{ip.Unmap()}}, nil
	}
	network := lookupNetwork(v4, v6)
	key := network + "|" + strings.ToLower(strings.TrimSuffix(host, "."))
	now := r.now()
	r.mu.Lock()
	if r.cache == nil {
		r.cache, r.flight = map[string]*resolveEntry{}, map[string]*resolveCall{}
	}
	if ent := r.cache[key]; ent != nil {
		age := now.Sub(ent.fetched)
		ttl := r.TTL
		if ent.err != nil {
			ttl = r.NegTTL
		}
		if age >= 0 && age < ttl {
			r.mu.Unlock()
			if ent.err != nil {
				return Resolution{}, ent.err
			}
			if ent.stale {
				return Resolution{Addrs: append([]netip.Addr(nil), ent.addrs...), Cached: true, Stale: true, Age: now.Sub(ent.since)}, nil
			}
			return Resolution{Addrs: append([]netip.Addr(nil), ent.addrs...), Cached: true, Age: age}, nil
		}
	}
	if call := r.flight[key]; call != nil { // join the lookup already running
		r.mu.Unlock()
		select {
		case <-call.done:
		case <-ctx.Done():
			return Resolution{}, &DialError{Stage: stageResolve, Kind: classifyResolveCtx(ctx), Target: host, Err: ctx.Err()}
		}
		if call.err != nil {
			return Resolution{}, call.err
		}
		return Resolution{Addrs: append([]netip.Addr(nil), call.addrs...), Stale: call.stale, Age: call.age}, nil
	}
	call := &resolveCall{done: make(chan struct{})}
	r.flight[key] = call
	prev := r.cache[key]
	r.mu.Unlock()
	// The lookup is shared by every caller of this name, so it must not die with the first
	// caller's context: it runs detached with its own timeout, and each caller waits for it
	// (or for its own context).
	go r.fill(key, network, host, prev, now, call)
	select {
	case <-call.done:
	case <-ctx.Done():
		return Resolution{}, &DialError{Stage: stageResolve, Kind: classifyResolveCtx(ctx), Target: host, Err: ctx.Err()}
	}
	if call.err != nil {
		return Resolution{}, call.err
	}
	return Resolution{Addrs: append([]netip.Addr(nil), call.addrs...), Stale: call.stale, Age: call.age}, nil
}

const resolveTimeout = 6 * time.Second

// fill performs one lookup and publishes it to the cache and to everyone waiting on call.
func (r *Resolver) fill(key, network, host string, prev *resolveEntry, now time.Time, call *resolveCall) {
	ctx, cancel := context.WithTimeout(context.Background(), resolveTimeout)
	defer cancel()
	addrs, err := r.Lookup(ctx, network, host)
	clean := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		clean = append(clean, a.Unmap().WithZone(""))
	}
	stale := false
	var staleAge time.Duration
	switch {
	case err == nil && len(clean) == 0:
		err = &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	case err != nil && prev != nil && prev.err == nil && len(prev.addrs) > 0 && now.Sub(prev.origin()) < r.StaleFor:
		// The limit counts from when the answer was really fetched: a stale entry's own
		// timestamp is rewritten on every refresh and must not restart the clock.
		clean, err, stale, staleAge = prev.addrs, nil, true, now.Sub(prev.origin())
	}
	r.mu.Lock()
	switch {
	case stale:
		// Keep the old answer, flagged; the next call retries the lookup after NegTTL.
		r.cache[key] = &resolveEntry{addrs: clean, fetched: now.Add(-r.TTL + r.NegTTL), stale: true, since: now.Add(-staleAge)}
	case err != nil:
		r.cache[key] = &resolveEntry{err: wrapResolve(host, err), fetched: now}
	default:
		r.cache[key] = &resolveEntry{addrs: clean, fetched: now}
	}
	delete(r.flight, key)
	r.mu.Unlock()
	call.addrs, call.stale, call.age = clean, stale, staleAge
	if err != nil {
		call.err = wrapResolve(host, err)
	}
	close(call.done)
}

func classifyResolveCtx(ctx context.Context) string {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return kindTimeout
	}
	return kindCanceled
}
func wrapResolve(host string, err error) error {
	var de *DialError
	if errors.As(err, &de) {
		return err
	}
	kind := kindDNS
	if errors.Is(err, context.Canceled) {
		kind = kindCanceled
	}
	return &DialError{Stage: stageResolve, Kind: kind, Target: host, Err: err}
}

// Invalidate forgets a host so the next dial resolves it again (used when every cached
// address failed: the destination may have moved).
func (r *Resolver) Invalidate(host string) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, n := range []string{"ip", "ip4", "ip6"} {
		delete(r.cache, n+"|"+host)
	}
}

// ---------------------------------------------------------------------------
// Policy ordering

// familyRoutes says which families this host can currently send traffic over.
type familyRoutes struct{ V4, V6 bool }

// routeTo asks the kernel whether a route to one destination exists, by "connecting" a UDP
// socket (nothing is sent). It reads the routing table, not the interface list.
var routeTo = func(a netip.Addr) bool {
	c, e := net.Dial(netFor("udp", a), netip.AddrPortFrom(a, 9).String())
	if e != nil {
		return false
	}
	c.Close()
	return true
}

// hostRoutes asks the kernel whether a route exists per family by "connecting" a UDP
// socket (no packet is sent). It reads the routing table, not the interface list, so an
// interface with only a link-local IPv6 address does not count as IPv6 connectivity.
var hostRoutes = func() familyRoutes {
	check := func(network, addr string) bool {
		c, e := net.Dial(network, addr)
		if e != nil {
			return false
		}
		c.Close()
		return true
	}
	return familyRoutes{
		V4: check("udp4", "192.0.2.1:9"),
		V6: check("udp6", "[2001:db8::1]:9"),
	}
}

// orderAddrs filters and orders candidate addresses by policy. The error is non-nil only
// when nothing remains, and then names why.
//
//	ipv4_only / ipv6_only   exactly one family; the other is never tried
//	ipv4_first / ipv6_first the preferred family first, the other family as fallback
//	auto                    families this host has no route for are dropped; the rest are
//	                        interleaved, IPv6 first (RFC 6724), the family that worked last
//	                        for this destination ("prefer") first
func orderAddrs(addrs []netip.Addr, policy string, routes familyRoutes, prefer string) ([]netip.Addr, error) {
	var v4, v6 []netip.Addr
	for _, a := range addrs {
		if a.Is4() {
			v4 = append(v4, a)
		} else if a.Is6() {
			v6 = append(v6, a)
		}
	}
	var first, second []netip.Addr
	switch policy {
	case outIPv4Only:
		first = v4
		if len(first) == 0 {
			return nil, errNoFamily("IPv4", len(v6) > 0)
		}
	case outIPv6Only:
		first = v6
		if len(first) == 0 {
			return nil, errNoFamily("IPv6", len(v4) > 0)
		}
	case outIPv6First:
		first, second = v6, v4
	case outAuto:
		if !routes.V4 {
			v4 = nil
		}
		if !routes.V6 {
			v6 = nil
		}
		first, second = v6, v4
		if prefer == "ipv4" {
			first, second = v4, v6
		}
		return interleave(first, second), orNoAddr(len(v4)+len(v6), addrs, routes)
	default: // ipv4_first
		first, second = v4, v6
	}
	out := append(append([]netip.Addr(nil), first...), second...)
	if len(out) == 0 {
		return nil, errNoFamily("", false)
	}
	return out, nil
}
func orNoAddr(n int, all []netip.Addr, routes familyRoutes) error {
	if n > 0 {
		return nil
	}
	if len(all) > 0 {
		return &DialError{Kind: kindUnreachable, Stage: stagePolicy, Err: errors.New("this host has no route for that address family")}
	}
	return errNoFamily("", false)
}
func errNoFamily(family string, otherExists bool) error {
	msg := "the name has no usable address record"
	if family != "" {
		msg = fmt.Sprintf("the name has no %s address record", family)
		if otherExists {
			msg += " (only the other family exists)"
		}
	}
	return &DialError{Stage: stagePolicy, Kind: kindNoAddress, Err: errors.New(msg)}
}
func interleave(a, b []netip.Addr) []netip.Addr {
	out := make([]netip.Addr, 0, len(a)+len(b))
	for i := 0; i < len(a) || i < len(b); i++ {
		if i < len(a) {
			out = append(out, a[i])
		}
		if i < len(b) {
			out = append(out, b[i])
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Dialer

// Attempt records one connection attempt for diagnostics.
type Attempt struct {
	Addr     netip.AddrPort
	Err      error
	Kind     string
	Duration time.Duration
}

// DialReport describes a dial: what the name resolved to, what was tried, what worked.
type DialReport struct {
	Resolution Resolution
	Ordered    []netip.Addr
	Attempts   []Attempt
	Used       netip.AddrPort
}

// Family names the family of the address that was used ("ipv4"/"ipv6", "" if none).
func (r DialReport) Family() string {
	switch {
	case !r.Used.IsValid():
		return ""
	case r.Used.Addr().Is4():
		return "ipv4"
	}
	return "ipv6"
}

// PolicyDialer connects to host:port under an outbound policy.
type PolicyDialer struct {
	Policy   string
	Resolver *Resolver
	Timeout  time.Duration // per attempt (default 5s)
	// HappyEyeballsDelay staggers the second family in auto mode (default 250ms).
	HappyEyeballsDelay time.Duration
	// RouteTo reports whether this host has a route to an address (auto mode only).
	RouteTo func(netip.Addr) bool
	// Dial opens one connection to an explicit IP:port (network is tcp4/tcp6/udp4/udp6).
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// Self reports whether an address:port is this relay's own listener (loop guard).
	Self func(netip.AddrPort) bool

	mu     sync.Mutex
	prefer map[string]string // host -> family that last worked, for auto mode
}

func NewPolicyDialer(policy string) *PolicyDialer {
	if !validOutboundPolicy(policy) {
		policy = outAuto
	}
	return &PolicyDialer{Policy: policy, Resolver: NewResolver(), RouteTo: routeTo}
}

func (d *PolicyDialer) timeout() time.Duration {
	if d.Timeout > 0 {
		return d.Timeout
	}
	return 5 * time.Second
}
func (d *PolicyDialer) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if d.Dial != nil {
		return d.Dial(ctx, network, addr)
	}
	var nd net.Dialer
	return nd.DialContext(ctx, network, addr)
}

func splitTarget(target string) (string, int, error) {
	h, ps, e := net.SplitHostPort(target)
	if e != nil {
		return "", 0, &DialError{Stage: stagePolicy, Kind: kindOther, Target: target, Err: e}
	}
	n, e := strconv.Atoi(ps)
	if e != nil || n < 1 || n > 65535 {
		return "", 0, &DialError{Stage: stagePolicy, Kind: kindOther, Target: target, Err: errors.New("invalid port")}
	}
	return h, n, nil
}

// plan resolves the target and returns the ordered candidates.
func (d *PolicyDialer) plan(ctx context.Context, target string) (string, int, DialReport, error) {
	var rep DialReport
	host, port, e := splitTarget(target)
	if e != nil {
		return "", 0, rep, e
	}
	v4, v6 := outboundAllows(d.Policy)
	if ip, er := netip.ParseAddr(strings.Trim(host, "[]")); er == nil {
		ip = ip.Unmap()
		if (ip.Is4() && !v4) || (ip.Is6() && !v6) {
			return host, port, rep, &DialError{Stage: stagePolicy, Kind: kindFamily, Target: target, Err: fmt.Errorf("policy %s forbids %s addresses", d.Policy, ipFamilyLabel(ip))}
		}
	}
	res, e := d.Resolver.Resolve(ctx, host, v4, v6)
	rep.Resolution = res
	if e != nil {
		var de *DialError
		if errors.As(e, &de) {
			cp := *de
			cp.Target = target
			return host, port, rep, &cp
		}
		return host, port, rep, e
	}
	d.mu.Lock()
	prefer := d.prefer[strings.ToLower(host)]
	d.mu.Unlock()
	addrs := res.Addrs
	if d.Policy == outAuto && d.RouteTo != nil {
		// Auto mode only tries addresses this host can actually route to; loopback needs
		// no route. The check is per destination, so an on-link private network works
		// on a host without a default route.
		kept := make([]netip.Addr, 0, len(addrs))
		for _, a := range addrs {
			if a.IsLoopback() || d.RouteTo(a) {
				kept = append(kept, a)
			}
		}
		if len(kept) == 0 && len(addrs) > 0 {
			return host, port, rep, &DialError{Stage: stagePolicy, Kind: kindUnreachable, Target: target, Err: errors.New("this host has no route to the address")}
		}
		addrs = kept
	}
	ordered, e := orderAddrs(addrs, d.Policy, familyRoutes{V4: true, V6: true}, prefer)
	rep.Ordered = ordered
	if e != nil {
		var de *DialError
		if errors.As(e, &de) {
			cp := *de
			cp.Target = target
			return host, port, rep, &cp
		}
		return host, port, rep, e
	}
	return host, port, rep, nil
}

func netFor(proto string, a netip.Addr) string {
	if a.Is4() {
		return proto + "4"
	}
	return proto + "6"
}

// DialContext opens a TCP connection. If every address of a cached answer fails, the host
// is resolved once more before giving up: the destination's address may have changed.
func (d *PolicyDialer) DialContext(ctx context.Context, target string) (net.Conn, DialReport, error) {
	conn, rep, err := d.dialOnce(ctx, target)
	if err == nil {
		return conn, rep, nil
	}
	var de *DialError
	if errors.As(err, &de) && de.Stage == stageConnect && rep.Resolution.Cached && ctx.Err() == nil {
		host, _, _ := splitTarget(target)
		d.Resolver.Invalidate(host)
		if c2, r2, e2 := d.dialOnce(ctx, target); e2 == nil {
			return c2, r2, nil
		} else if !sameAddrs(r2.Ordered, rep.Ordered) {
			return nil, r2, e2
		}
	}
	return nil, rep, err
}
func sameAddrs(a, b []netip.Addr) bool {
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

func (d *PolicyDialer) dialOnce(ctx context.Context, target string) (net.Conn, DialReport, error) {
	host, port, rep, e := d.plan(ctx, target)
	if e != nil {
		return nil, rep, e
	}
	// Auto mode races the second family after a short delay; the other policies are
	// strictly sequential, so "IPv4 first" never opens an IPv6 connection if IPv4 works.
	var staggered bool
	if d.Policy == outAuto {
		staggered = hasBothFamilies(rep.Ordered)
	}
	type result struct {
		conn net.Conn
		att  Attempt
	}
	tryOne := func(ctx context.Context, a netip.Addr) result {
		ap := netip.AddrPortFrom(a, uint16(port))
		if d.Self != nil && d.Self(ap) {
			return result{att: Attempt{Addr: ap, Kind: kindLoop, Err: errors.New("the destination is this relay's own listener")}}
		}
		start := time.Now()
		actx, cancel := context.WithTimeout(ctx, d.timeout())
		defer cancel()
		c, err := d.dial(actx, netFor("tcp", a), ap.String())
		att := Attempt{Addr: ap, Err: err, Duration: time.Since(start), Kind: classifyConnectError(err)}
		return result{conn: c, att: att}
	}
	finish := func(att []Attempt, c net.Conn, used netip.AddrPort) (net.Conn, DialReport, error) {
		rep.Attempts = att
		if c != nil {
			rep.Used = used
			d.remember(host, used.Addr())
			return c, rep, nil
		}
		return nil, rep, connectError(target, att)
	}
	if !staggered {
		var atts []Attempt
		for _, a := range rep.Ordered {
			if ctx.Err() != nil {
				break
			}
			r := tryOne(ctx, a)
			atts = append(atts, r.att)
			if r.conn != nil {
				return finish(atts, r.conn, r.att.Addr)
			}
		}
		return finish(atts, nil, netip.AddrPort{})
	}
	// Happy Eyeballs: two sequential lanes (one per family), the second started after the
	// delay or as soon as the first lane has failed entirely.
	var lanes [2][]netip.Addr
	first := rep.Ordered[0]
	for _, a := range rep.Ordered {
		if a.Is4() == first.Is4() {
			lanes[0] = append(lanes[0], a)
		} else {
			lanes[1] = append(lanes[1], a)
		}
	}
	delay := d.HappyEyeballsDelay
	if delay <= 0 {
		delay = 250 * time.Millisecond
	}
	lctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type laneDone struct {
		lane int
		conn net.Conn
		atts []Attempt
		used netip.AddrPort
	}
	out := make(chan laneDone, 2)
	runLane := func(i int, startAfter <-chan struct{}) {
		if startAfter != nil {
			select {
			case <-startAfter:
			case <-lctx.Done():
				out <- laneDone{lane: i}
				return
			}
		}
		var atts []Attempt
		for _, a := range lanes[i] {
			if lctx.Err() != nil {
				break
			}
			r := tryOne(lctx, a)
			atts = append(atts, r.att)
			if r.conn != nil {
				out <- laneDone{lane: i, conn: r.conn, atts: atts, used: r.att.Addr}
				return
			}
		}
		out <- laneDone{lane: i, atts: atts}
	}
	go runLane(0, nil)
	start2 := make(chan struct{})
	go runLane(1, start2)
	timer := time.NewTimer(delay)
	defer timer.Stop()
	var all []Attempt
	pending := 2
	for pending > 0 {
		select {
		case <-timer.C:
			close(start2)
			start2 = nil
			timer.Reset(time.Hour)
		case r := <-out:
			pending--
			all = append(all, r.atts...)
			if r.conn != nil {
				cancel()
				// Drain the other lane and close a connection it may also have made.
				for ; pending > 0; pending-- {
					if o := <-out; o.conn != nil {
						o.conn.Close()
					}
				}
				return finish(all, r.conn, r.used)
			}
			if r.lane == 0 && start2 != nil { // the preferred lane failed: start the other now
				close(start2)
				start2 = nil
			}
		}
	}
	return finish(all, nil, netip.AddrPort{})
}
func hasBothFamilies(a []netip.Addr) bool {
	var v4, v6 bool
	for _, x := range a {
		v4 = v4 || x.Is4()
		v6 = v6 || x.Is6()
	}
	return v4 && v6
}
func (d *PolicyDialer) remember(host string, a netip.Addr) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.prefer == nil {
		d.prefer = map[string]string{}
	}
	if a.Is4() {
		d.prefer[strings.ToLower(host)] = "ipv4"
	} else {
		d.prefer[strings.ToLower(host)] = "ipv6"
	}
}

// connectError summarizes failed attempts: the kind of the most informative failure wins
// (refused > timeout > unreachable), and every attempted address is listed.
func connectError(target string, atts []Attempt) error {
	if len(atts) == 0 {
		return &DialError{Stage: stageConnect, Kind: kindCanceled, Target: target, Err: context.Canceled}
	}
	rank := map[string]int{kindLoop: 5, kindRefused: 4, kindTimeout: 3, kindUnreachable: 2, kindCanceled: 0, kindOther: 1}
	best := atts[0]
	var list []string
	for _, a := range atts {
		if rank[a.Kind] > rank[best.Kind] {
			best = a
		}
		list = append(list, a.Addr.String())
	}
	return &DialError{Stage: stageConnect, Kind: best.Kind, Target: target, Addr: strings.Join(list, ", "), Err: best.Err}
}

// DialUDP opens a connected UDP socket to the target, choosing the first address allowed
// by the policy. UDP has no handshake, so reachability is not tested here.
func (d *PolicyDialer) DialUDP(ctx context.Context, target string) (net.Conn, DialReport, error) {
	host, port, rep, e := d.plan(ctx, target)
	if e != nil {
		return nil, rep, e
	}
	var atts []Attempt
	for _, a := range rep.Ordered {
		ap := netip.AddrPortFrom(a, uint16(port))
		if d.Self != nil && d.Self(ap) {
			atts = append(atts, Attempt{Addr: ap, Kind: kindLoop, Err: errors.New("the destination is this relay's own listener")})
			continue
		}
		c, err := d.dial(ctx, netFor("udp", a), ap.String())
		atts = append(atts, Attempt{Addr: ap, Err: err, Kind: classifyConnectError(err)})
		if err == nil {
			rep.Attempts, rep.Used = atts, ap
			d.remember(host, a)
			return c, rep, nil
		}
	}
	rep.Attempts = atts
	return nil, rep, connectError(target, atts)
}

func ipFamilyLabel(a netip.Addr) string {
	if a.Is4() {
		return "IPv4"
	}
	return "IPv6"
}
