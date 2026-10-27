package rout

import (
	"io"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
)

func loopTestRelay(id, protocol string, port, destination int) Profile {
	return Profile{
		ID: id, Name: id, Kind: "relay", Enabled: true, Protocol: protocol,
		Listen: "127.0.0.1", Port: port, PublicHost: "203.0.113.10",
		PublicPort: port, Target: "127.0.0.1:" + itoa(destination),
	}
}

func TestRelayLoopTracksEachTransport(t *testing.T) {
	for _, tc := range []struct {
		name, first, second string
	}{
		{"tcp loop behind udp", "udp", "tcp"},
		{"udp loop behind tcp", "tcp", "udp"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entry := loopTestRelay("000000000001", "both", 21001, 21002)
			safe := loopTestRelay("000000000002", tc.first, 21002, 21003)
			loop := loopTestRelay("000000000003", tc.second, 21002, 21001)
			for _, profiles := range [][]Profile{{entry, safe, loop}, {loop, safe, entry}} {
				state := State{Schema: 1, Profiles: profiles}
				if e := state.Validate(); e != nil {
					t.Fatal(e)
				}
				if e := relayLoop(state, entry, nil); e == nil {
					t.Fatalf("accepted %s when TCP and UDP share the destination port", tc.name)
				}
			}
		})
	}
	for _, tc := range []struct {
		name, entry, unrelated string
	}{
		{"tcp cannot become udp", "tcp", "udp"},
		{"udp cannot become tcp", "udp", "tcp"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entry := loopTestRelay("000000000001", tc.entry, 22001, 22002)
			middle := loopTestRelay("000000000002", "both", 22002, 22003)
			other := loopTestRelay("000000000003", tc.unrelated, 22003, 22001)
			state := State{Schema: 1, Profiles: []Profile{entry, middle, other}}
			if e := state.Validate(); e != nil {
				t.Fatal(e)
			}
			if e := relayLoop(state, entry, nil); e != nil {
				t.Fatalf("rejected a chain that cannot carry the entry transport: %v", e)
			}
		})
	}
}

func TestRelayLoopRejectsReachableExistingCycle(t *testing.T) {
	entry := loopTestRelay("000000000001", "tcp", 23001, 23002)
	a := loopTestRelay("000000000002", "tcp", 23002, 23003)
	b := loopTestRelay("000000000003", "tcp", 23003, 23002)
	state := State{Schema: 1, Profiles: []Profile{entry, a, b}}
	if e := state.Validate(); e != nil {
		t.Fatal(e)
	}
	if e := relayLoop(state, entry, nil); e == nil {
		t.Fatal("accepted a relay whose traffic enters an existing cycle")
	} else if translated := Translate("en", e.Error()); strings.Contains(translated, "目标") {
		t.Fatalf("cycle error is not translated: %s", translated)
	}
}

func TestRelayLoopThroughPublicEntry(t *testing.T) {
	entry := loopTestRelay("000000000001", "tcp", 24001, 24002)
	middle := loopTestRelay("000000000002", "tcp", 24002, 24003)
	middle.Target = "203.0.113.10:24001"
	state := State{Schema: 1, Profiles: []Profile{entry, middle}}
	if e := state.Validate(); e != nil {
		t.Fatal(e)
	}
	if e := relayLoop(state, entry, nil); e == nil {
		t.Fatal("accepted a chain leading back to the entry's public endpoint")
	}
	middle.Target = "198.51.100.10:24001"
	state.Profiles[1] = middle
	if e := relayLoop(state, entry, nil); e != nil {
		t.Fatalf("rejected an unrelated remote destination: %v", e)
	}
}

func TestRelayLoopEditingIgnoresPreviousListener(t *testing.T) {
	previous := loopTestRelay("000000000001", "tcp", 25001, 25003)
	edited := loopTestRelay(previous.ID, "tcp", 25002, 25001)
	state := State{Schema: 1, Profiles: []Profile{previous}}
	if e := relayLoop(state, edited, nil); e != nil {
		t.Fatalf("rejected a destination pointing to the relay's old port: %v", e)
	}
}

func TestCommitRejectsHiddenTransportLoop(t *testing.T) {
	a := relayTestApp(t, ServerSetup{PublicHost: "203.0.113.10", Listen: "127.0.0.1", Network: "both"})
	entryPort, e := freePort()
	if e != nil {
		t.Fatal(e)
	}
	destinationPort, e := freePort()
	for e == nil && destinationPort == entryPort {
		destinationPort, e = freePort()
	}
	if e != nil {
		t.Fatal(e)
	}
	udp := loopTestRelay("000000000002", "udp", destinationPort, 23003)
	tcp := loopTestRelay("000000000003", "tcp", destinationPort, entryPort)
	old, e := a.Load()
	if e != nil {
		t.Fatal(e)
	}
	if e = a.Commit(old, State{Schema: 1, Profiles: []Profile{udp, tcp}}, false); e != nil {
		t.Fatal(e)
	}
	old, e = a.Load()
	if e != nil {
		t.Fatal(e)
	}
	entry := loopTestRelay("000000000001", "both", entryPort, destinationPort)
	if e = a.Commit(old, replace(old.Clone(), entry), false); e == nil {
		t.Fatal("committed a relay that loops through the TCP listener")
	}
	after, e := a.Load()
	if e != nil || !reflect.DeepEqual(old, after) {
		t.Fatalf("rejected commit changed state: %v", e)
	}
}

// Exercise the topology that requires distinct TCP and UDP traversals with real GOST
// processes and loopback echo servers. The ordinary test suite skips this when the
// repository's pinned engines are not installed.
func TestIntegrationRelaySharedPortChain(t *testing.T) {
	a := integrationApp(t)
	tcpEcho, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { tcpEcho.Close() })
	go func() {
		for {
			c, e := tcpEcho.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				b := make([]byte, 4)
				if _, e := io.ReadFull(c, b); e == nil {
					_, _ = c.Write(append([]byte("TCP:"), b...))
				}
			}()
		}
	}()
	udpEcho, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { udpEcho.Close() })
	go func() {
		b := make([]byte, 32)
		for {
			n, addr, e := udpEcho.ReadFrom(b)
			if e != nil {
				return
			}
			_, _ = udpEcho.WriteTo(append([]byte("UDP:"), b[:n]...), addr)
		}
	}()
	freeBoth := func() int {
		t.Helper()
		for i := 0; i < 50; i++ {
			tcp, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			port := tcp.Addr().(*net.TCPAddr).Port
			udp, e := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", itoa(port)))
			tcp.Close()
			if e == nil {
				udp.Close()
				return port
			}
		}
		t.Fatal("could not find a free TCP/UDP port")
		return 0
	}
	sharedPort, entryPort := freeBoth(), freeBoth()
	for entryPort == sharedPort {
		entryPort = freeBoth()
	}
	entry := loopTestRelay("000000000001", "both", entryPort, sharedPort)
	tcp := loopTestRelay("000000000002", "tcp", sharedPort, tcpEcho.Addr().(*net.TCPAddr).Port)
	udp := loopTestRelay("000000000003", "udp", sharedPort, udpEcho.LocalAddr().(*net.UDPAddr).Port)
	state := State{Schema: 1, Profiles: []Profile{entry, tcp, udp}}
	if e := state.Validate(); e != nil {
		t.Fatal(e)
	}
	if e := relayLoop(state, entry, nil); e != nil {
		t.Fatalf("valid chain rejected: %v", e)
	}
	for _, p := range []Profile{tcp, udp, entry} {
		config, e := serverConfig(p, t.TempDir())
		if e != nil {
			t.Fatal(e)
		}
		startEngine(t, profileSockets(p), a.enginePath("gost"), "-C", configFile(t, config))
	}
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			c, e := net.DialTimeout(network, net.JoinHostPort("127.0.0.1", itoa(entryPort)), time.Second)
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			if e := c.SetDeadline(time.Now().Add(3 * time.Second)); e != nil {
				t.Fatal(e)
			}
			if _, e := c.Write([]byte("ping")); e != nil {
				t.Fatal(e)
			}
			b := make([]byte, len("TCP:ping"))
			if _, e := io.ReadFull(c, b); e != nil || string(b) != strings.ToUpper(network)+":ping" {
				t.Fatalf("wrong response %q: %v", b, e)
			}
		})
	}
}
