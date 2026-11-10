package rout

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// udpRelayAddr returns the address of the relay's first UDP socket.
func udpRelayAddr(t *testing.T, r *relayRuntime) string {
	t.Helper()
	for _, b := range r.bound {
		if strings.HasPrefix(b, "udp") {
			return strings.SplitN(b, " ", 2)[1]
		}
	}
	t.Fatal("no udp socket bound")
	return ""
}

// gatedDial holds the first destination dial until release is closed (or the dial's
// context ends); every later dial goes through at once.
type gatedDial struct {
	release chan struct{}
	calls   atomic.Int32
	held    chan struct{} // closed once the first dial is waiting
}

func newGatedDial() *gatedDial {
	return &gatedDial{release: make(chan struct{}), held: make(chan struct{})}
}

func (g *gatedDial) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if g.calls.Add(1) == 1 {
		close(g.held)
		select {
		case <-g.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

func udpClient(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, e := net.Dial("udp4", addr)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func readUDP(c net.Conn, wait time.Duration) (string, error) {
	c.SetReadDeadline(time.Now().Add(wait))
	b := make([]byte, 64)
	n, e := c.Read(b)
	return string(b[:n]), e
}

// A client whose destination dial is slow must not hold up the other clients of the same
// port: before this, the dial ran inside the only read loop and stalled every datagram for
// up to five seconds.
func TestNativeRelayUDPSlowDialDoesNotBlockOtherClients(t *testing.T) {
	_, port := echoUDP(t, "udp4", "127.0.0.1:0")
	gate := newGatedDial()
	cfg := nativeRelayConfig{Version: 1, Engine: "rout-relay", ID: "x", Listen: []nativeListen{{"udp4", "127.0.0.1:0"}}, Target: "127.0.0.1:" + itoa(port), Outbound: outIPv4Only}
	r := startRelay(t, cfg, func(rt *relayRuntime) { rt.dialer.Dial = gate.dial })
	addr := udpRelayAddr(t, r)

	slow := udpClient(t, addr)
	for _, m := range []string{"a1", "a2", "a3"} {
		slow.Write([]byte(m))
	}
	select {
	case <-gate.held:
	case <-time.After(2 * time.Second):
		t.Fatal("the first dial never started")
	}

	fast := udpClient(t, addr)
	start := time.Now()
	fast.Write([]byte("b1"))
	got, e := readUDP(fast, 2*time.Second)
	if e != nil || got != "b1" {
		t.Fatalf("second client blocked behind the slow dial: %q %v", got, e)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("second client answered only after %v", d)
	}

	// The datagrams sent while dialing are delivered, in order, once the dial finishes.
	close(gate.release)
	for _, want := range []string{"a1", "a2", "a3"} {
		got, e := readUDP(slow, 2*time.Second)
		if e != nil || got != want {
			t.Fatalf("queued datagram: want %q, got %q (%v)", want, got, e)
		}
	}
	slow.Write([]byte("a4"))
	if got, e := readUDP(slow, 2*time.Second); e != nil || got != "a4" {
		t.Fatalf("after dialing: %q %v", got, e)
	}
	if n := r.stats.udpSessions.Load(); n != 2 {
		t.Fatalf("sessions: %d", n)
	}
}

// Only a bounded number of datagrams waits for a dial; the rest are dropped and counted.
func TestNativeRelayUDPQueueWhileDialingIsBounded(t *testing.T) {
	_, port := echoUDP(t, "udp4", "127.0.0.1:0")
	gate := newGatedDial()
	cfg := nativeRelayConfig{Version: 1, Engine: "rout-relay", ID: "x", Listen: []nativeListen{{"udp4", "127.0.0.1:0"}}, Target: "127.0.0.1:" + itoa(port), Outbound: outIPv4Only}
	r := startRelay(t, cfg, func(rt *relayRuntime) { rt.dialer.Dial = gate.dial })
	c := udpClient(t, udpRelayAddr(t, r))
	extra := 5
	for i := 0; i < udpPendingMax+extra; i++ {
		c.Write([]byte("p" + itoa(i)))
	}
	<-gate.held
	deadline := time.Now().Add(2 * time.Second)
	for r.stats.udpDropped.Load() < int64(extra) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := r.stats.udpDropped.Load(); n != int64(extra) {
		t.Fatalf("dropped %d, want %d", n, extra)
	}
	close(gate.release)
	for i := 0; i < udpPendingMax; i++ {
		got, e := readUDP(c, 2*time.Second)
		if e != nil || got != "p"+itoa(i) {
			t.Fatalf("datagram %d: %q %v", i, got, e)
		}
	}
}

// A failed dial frees the session, so the client's next datagram tries again.
func TestNativeRelayUDPFailedDialRetriesOnNextDatagram(t *testing.T) {
	_, port := echoUDP(t, "udp4", "127.0.0.1:0")
	var calls atomic.Int32
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if calls.Add(1) == 1 {
			return nil, errors.New("connection refused")
		}
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	cfg := nativeRelayConfig{Version: 1, Engine: "rout-relay", ID: "x", Listen: []nativeListen{{"udp4", "127.0.0.1:0"}}, Target: "127.0.0.1:" + itoa(port), Outbound: outIPv4Only}
	r := startRelay(t, cfg, func(rt *relayRuntime) { rt.dialer.Dial = dial })
	c := udpClient(t, udpRelayAddr(t, r))
	c.Write([]byte("lost"))
	deadline := time.Now().Add(2 * time.Second)
	for r.stats.dialFail.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if r.stats.dialFail.Load() != 1 {
		t.Fatal("failed dial not counted")
	}
	c.Write([]byte("again"))
	if got, e := readUDP(c, 2*time.Second); e != nil || got != "again" {
		t.Fatalf("retry: %q %v", got, e)
	}
}

// plainPacketConn hides the *net.UDPConn, so the relay takes its generic net.Addr path.
type plainPacketConn struct{ net.PacketConn }

func TestNativeRelayUDPGenericPacketConn(t *testing.T) {
	_, port := echoUDP(t, "udp4", "127.0.0.1:0")
	cfg := nativeRelayConfig{Version: 1, Engine: "rout-relay", ID: "x", Listen: []nativeListen{{"udp4", "127.0.0.1:0"}}, Target: "127.0.0.1:" + itoa(port), Outbound: outIPv4Only}
	r := startRelay(t, cfg, func(rt *relayRuntime) {
		rt.listenUDP = func(network, addr string) (net.PacketConn, error) {
			pc, e := net.ListenPacket(network, addr)
			if e != nil {
				return nil, e
			}
			return plainPacketConn{pc}, nil
		}
	})
	c := udpClient(t, udpRelayAddr(t, r))
	c.Write([]byte("hi"))
	if got, e := readUDP(c, 2*time.Second); e != nil || got != "hi" {
		t.Fatalf("%q %v", got, e)
	}
}
