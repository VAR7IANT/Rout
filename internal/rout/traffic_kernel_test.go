package rout

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These tests MUST run in a disposable network namespace with real CAP_NET_ADMIN.
// No fake meter is used anywhere in this file.
func kernelApp(t *testing.T) *App {
	t.Helper()
	if os.Getenv("ROUT_TEST_NFT") != "1" {
		t.Skip("set ROUT_TEST_NFT=1 inside a disposable root network namespace")
	}
	if os.Geteuid() != 0 {
		t.Fatal("kernel quota tests require root")
	}
	a := testApp(t)
	a.trafficMeter = nil
	if e := AtomicWrite(filepath.Join(a.Home, "traffic.enabled"), []byte("1"), 0600); e != nil {
		t.Fatal(e)
	}
	return a
}
func httpTestOrigin(t *testing.T) string {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "198.51.100.19") }))
	t.Cleanup(s.Close)
	return strings.TrimPrefix(s.URL, "http://")
}
func kernelProfile(t *testing.T, a *App, host, network string) Profile {
	t.Helper()
	p := fixture(t, "ss")
	p.Listen = host
	p.Network = network
	p.Port, _ = freePort()
	p.PublicPort = p.Port
	s, e := a.Load()
	if e != nil {
		t.Fatal(e)
	}
	for _, old := range s.Profiles {
		if old.Port == p.Port {
			t.Fatal("test port collision")
		}
	}
	s = replace(s, p)
	b, _ := JSON(s)
	if e = AtomicWrite(filepath.Join(a.Home, "state.json"), b, 0600); e != nil {
		t.Fatal(e)
	}
	if e = a.TrafficSync(time.Now(), false); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = a.meter().Delete(p) })
	return p
}
func udpEcho(t *testing.T, p Profile, echo bool) (net.Conn, <-chan int) {
	t.Helper()
	l, e := net.ListenPacket("udp", net.JoinHostPort(p.Listen, itoa(p.Port)))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { l.Close() })
	got := make(chan int, 512)
	go func() {
		b := make([]byte, 65536)
		for {
			n, addr, e := l.ReadFrom(b)
			if e != nil {
				return
			}
			got <- n
			if echo {
				_, _ = l.WriteTo(b[:n], addr)
			}
		}
	}()
	c, e := net.Dial("udp", l.LocalAddr().String())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { c.Close() })
	return c, got
}
func sendUDP(t *testing.T, c net.Conn, got <-chan int, n int, accepted bool) {
	t.Helper()
	if _, e := c.Write(make([]byte, n)); e != nil {
		t.Fatal(e)
	}
	select {
	case actual := <-got:
		if !accepted || actual != n {
			t.Fatalf("unexpected UDP admission %d", actual)
		}
	case <-time.After(250 * time.Millisecond):
		if accepted {
			t.Fatal("UDP admission failed")
		}
	}
}
func TestKernelExactIPv4IPv6BidirectionalCounters(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1"} {
		t.Run(host, func(t *testing.T) {
			a := kernelApp(t)
			p := kernelProfile(t, a, host, "udp")
			other := kernelProfile(t, a, host, "udp")
			c, got := udpEcho(t, p, true)
			for i := 0; i < 5; i++ {
				sendUDP(t, c, got, 100, true)
				_ = c.SetReadDeadline(time.Now().Add(time.Second))
				b := make([]byte, 100)
				if _, e := io.ReadFull(c, b); e != nil {
					t.Fatal(e)
				}
			}
			s, e := a.meter().Read(p)
			if e != nil {
				t.Fatal(e)
			}
			size := uint64(128)
			if host == "::1" {
				size = 148
			}
			if s.Up != 5*size || s.Down != 5*size {
				t.Fatalf("L3 counters not exact: %+v wanted %d each", s, 5*size)
			}
			idle, e := a.meter().Read(other)
			if e != nil || idle.Up != 0 || idle.Down != 0 {
				t.Fatal("traffic attributed to another listener", idle, e)
			}
			if e = a.TrafficSync(time.Now(), false); e != nil {
				t.Fatal(e)
			}
			if e = a.TrafficSync(time.Now(), false); e != nil {
				t.Fatal(e)
			}
			db, _ := a.loadTraffic()
			_, _, total, e := db.Records[p.ID].totals()
			if e != nil || total != 10*size {
				t.Fatal("duplicate billing", total, e)
			}
		})
	}
}
func TestKernelQuota99And100Percent(t *testing.T) {
	a := kernelApp(t)
	p := kernelProfile(t, a, "127.0.0.1", "udp")
	c, got := udpEcho(t, p, false)
	if e := a.ConfigureTraffic(p.ID, TrafficPolicy{LimitBytes: 10_000, BillingDay: 1}, false, time.Now()); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 99; i++ {
		sendUDP(t, c, got, 72, true)
	}
	s, e := a.meter().Read(p)
	if e != nil || s.Up != 9900 || s.Down != 0 || s.Consumed != 9900 {
		t.Fatalf("99%%: %+v %v", s, e)
	}
	sendUDP(t, c, got, 72, true)
	s, e = a.meter().Read(p)
	if e != nil || s.Up != 10000 || s.Consumed != 10000 {
		t.Fatalf("100%%: %+v %v", s, e)
	}
	// Existing UDP flow is dropped immediately, without a monitor tick or service stop.
	sendUDP(t, c, got, 72, false)
	s, e = a.meter().Read(p)
	if e != nil || s.Up != 10000 {
		t.Fatal("over-quota packet admitted", s, e)
	}
	if e = a.TrafficSync(time.Now(), false); e != nil {
		t.Fatal(e)
	}
	if e = a.TrafficGuard(p.ID); e == nil {
		t.Fatal("restart bypass")
	}
	// Warm recovery keeps exact kernel bytes. A lost kernel generation protects the cap.
	if e = a.TrafficSync(time.Now(), false); e != nil {
		t.Fatal(e)
	}
	if e = a.meter().Delete(p); e != nil {
		t.Fatal(e)
	}
	if e = a.TrafficSync(time.Now(), false); e != nil {
		t.Fatal(e)
	}
	sendUDP(t, c, got, 72, false)
	db, _ := a.loadTraffic()
	if !db.Records[p.ID].Incomplete || db.Records[p.ID].Blocked == "" {
		t.Fatal("lost meter silently reopened")
	}
}
func tcpEcho(t *testing.T, p Profile) net.Conn {
	t.Helper()
	l, e := net.Listen("tcp", net.JoinHostPort(p.Listen, itoa(p.Port)))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	c, e := net.Dial("tcp", l.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { c.Close() })
	return c
}
func pingTCP(c net.Conn) error {
	_ = c.SetDeadline(time.Now().Add(300 * time.Millisecond))
	if _, e := c.Write([]byte("ping")); e != nil {
		return e
	}
	b := make([]byte, 4)
	_, e := io.ReadFull(c, b)
	return e
}
func TestKernelExistingTCPConnectionAndSharedProcessIsolation(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1"} {
		t.Run(host, func(t *testing.T) {
			a := kernelApp(t)
			p := kernelProfile(t, a, host, "tcp")
			q := kernelProfile(t, a, host, "tcp")
			c := tcpEcho(t, p)
			other := tcpEcho(t, q)
			if e := pingTCP(c); e != nil {
				t.Fatal(e)
			}
			if e := pingTCP(other); e != nil {
				t.Fatal(e)
			}
			if e := a.ConfigureTraffic(p.ID, TrafficPolicy{LimitBytes: 1, BillingDay: 1}, false, time.Now()); e != nil {
				t.Fatal(e)
			}
			if e := pingTCP(c); e == nil {
				t.Fatal("existing TCP stream survived quota gate")
			}
			if newConn, e := net.DialTimeout("tcp", net.JoinHostPort(p.Listen, itoa(p.Port)), 250*time.Millisecond); e == nil {
				newConn.Close()
				t.Fatal("new TCP connection passed quota gate")
			}
			if e := pingTCP(other); e != nil {
				t.Fatal("quota affected another listener in same process", e)
			}
		})
	}
}
func TestKernelLocalNATMapping(t *testing.T) {
	a := kernelApp(t)
	p := kernelProfile(t, a, "127.0.0.1", "udp")
	local, got := udpEcho(t, p, true)
	_ = local
	publicPort, _ := freePort()
	table := "rout_nat_test_" + p.ID
	script := fmt.Sprintf("table ip %s {\n chain out {\n type nat hook output priority -100; policy accept;\n ip daddr 127.0.0.2 udp dport %d dnat to 127.0.0.1:%d;\n }\n}\n", table, publicPort, p.Port)
	if e := nftApply(script); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = nftApply("delete table ip " + table + "\n") })
	c, e := net.Dial("udp", net.JoinHostPort("127.0.0.2", itoa(publicPort)))
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	sendUDP(t, c, got, 72, true)
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, 72)
	if _, e = io.ReadFull(c, b); e != nil {
		t.Fatal(e)
	}
	s, e := a.meter().Read(p)
	if e != nil || s.Up != 100 || s.Down != 100 {
		t.Fatal("NAT counted public and local legs twice or missed local listener", s, e)
	}
}
func TestKernelTwoNodesShareOneExit(t *testing.T) {
	if os.Getenv("ROUT_TEST_NFT") != "1" {
		t.Skip("kernel tests disabled")
	}
	a := integrationApp(t)
	if e := AtomicWrite(filepath.Join(a.Home, "traffic.enabled"), []byte("1"), 0600); e != nil {
		t.Fatal(e)
	}
	proxy, count := socksFixture(t)
	origin := httpTestOrigin(t)
	_, originPort, _ := ParseEndpoint(origin)
	var nodes []Profile
	for i := 0; i < 2; i++ {
		p := fixture(t, "ss")
		p.Port, _ = freePort()
		p.PublicPort = p.Port
		p.Outbound = proxy
		nodes = append(nodes, p)
		t.Cleanup(func() { _ = a.meter().Delete(p) })
	}
	b, _ := JSON(State{Schema: 1, Profiles: nodes})
	if e := AtomicWrite(filepath.Join(a.Home, "state.json"), b, 0600); e != nil {
		t.Fatal(e)
	}
	if e := a.TrafficSync(time.Now(), false); e != nil {
		t.Fatal(e)
	}
	for _, p := range nodes {
		if e := a.writeProfile(p); e != nil {
			t.Fatal(e)
		}
		startEngine(t, a.enginePath("sing-box"), "run", "-c", filepath.Join(a.profileDir(p.ID), "config.json"))
	}
	request := func(p Profile) error {
		port, _ := freePort()
		c, e := ClientConfig(p, "127.0.0.1", p.Port, port)
		if e != nil {
			return e
		}
		return a.withClient(c, port, func(proxy string) error {
			_, e := fetchIP(proxy, "http://origin.rout.invalid:"+itoa(originPort))
			return e
		})
	}
	if e := request(nodes[0]); e != nil {
		t.Fatal(e)
	}
	time.Sleep(100 * time.Millisecond)
	first, e := a.meter().Read(nodes[0])
	if e != nil {
		t.Fatal(e)
	}
	if e := request(nodes[1]); e != nil {
		t.Fatal(e)
	}
	time.Sleep(100 * time.Millisecond)
	after, e := a.meter().Read(nodes[0])
	if e != nil || first.Up != after.Up || first.Down != after.Down {
		t.Fatal("shared exit traffic was double-attributed", first, after, e)
	}
	if count.Load() < 2 {
		t.Fatal("shared proxy was bypassed")
	}
	if e := a.ConfigureTraffic(nodes[0].ID, TrafficPolicy{LimitBytes: 1, BillingDay: 1}, false, time.Now()); e != nil {
		t.Fatal(e)
	}
	if e := request(nodes[1]); e != nil {
		t.Fatal("quota stopped another node on the shared exit", e)
	}
}
func TestKernelMonitorCrashLeaseAndWarmRecovery(t *testing.T) {
	a := kernelApp(t)
	manager := os.Getenv("ROUT_TEST_MANAGER")
	if manager == "" {
		t.Fatal("ROUT_TEST_MANAGER must point to the compiled Rout CLI")
	}
	p := kernelProfile(t, a, "127.0.0.1", "udp")
	q := kernelProfile(t, a, "127.0.0.1", "udp")
	c, got := udpEcho(t, p, false)
	other, otherGot := udpEcho(t, q, false)
	if e := a.ConfigureTraffic(p.ID, TrafficPolicy{LimitBytes: 1_000_000, BillingDay: 1}, false, time.Now()); e != nil {
		t.Fatal(e)
	}
	start := func() *exec.Cmd {
		cmd := exec.Command(manager, "--home", a.Home, "--bin-dir", a.BinDir, "--service", "none", "traffic", "run")
		if e := cmd.Start(); e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() {
			if cmd.ProcessState == nil {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
			}
		})
		return cmd
	}
	cmd := start()
	time.Sleep(500 * time.Millisecond)
	sendUDP(t, c, got, 100, true)
	// An unrelated long-running config operation must not expire finite leases.
	unlock, e := a.lock()
	if e != nil {
		t.Fatal(e)
	}
	time.Sleep(16 * time.Second)
	sendUDP(t, c, got, 100, true)
	unlock()
	if e := cmd.Process.Kill(); e != nil {
		t.Fatal(e)
	}
	_ = cmd.Wait()
	// Nothing refreshes the 15-second kernel lease after SIGKILL.
	time.Sleep(16 * time.Second)
	sendUDP(t, c, got, 100, false)
	sendUDP(t, other, otherGot, 100, true)
	cmd = start()
	time.Sleep(500 * time.Millisecond)
	sendUDP(t, c, got, 100, true)
	_ = cmd.Process.Signal(os.Interrupt)
	if e := cmd.Wait(); e != nil {
		t.Fatal(e)
	}
	db, _ := a.loadTraffic()
	if db.Records[p.ID].Blocked != "fault" {
		t.Fatal("graceful exit did not checkpoint/freeze finite node")
	}
}

func attachProtocolMeter(t *testing.T, a *App, p Profile) {
	t.Helper()
	if os.Getenv("ROUT_TEST_NFT") != "1" {
		return
	}
	if e := AtomicWrite(filepath.Join(a.Home, "traffic.enabled"), []byte("1"), 0600); e != nil {
		t.Fatal(e)
	}
	s := State{Schema: 1, Profiles: []Profile{p}}
	b, _ := JSON(s)
	if e := AtomicWrite(filepath.Join(a.Home, "state.json"), b, 0600); e != nil {
		t.Fatal(e)
	}
	if e := a.TrafficSync(time.Now(), false); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = a.meter().Delete(p) })
}
func assertProtocolQuota(t *testing.T, a *App, p Profile, proxy, endpoint string) error {
	t.Helper()
	if os.Getenv("ROUT_TEST_NFT") != "1" {
		return nil
	}
	if e := a.TrafficSync(time.Now(), false); e != nil {
		return e
	}
	db, e := a.loadTraffic()
	if e != nil {
		return e
	}
	up, down, total, e := db.Records[p.ID].totals()
	if e != nil {
		return e
	}
	if up == 0 || down == 0 {
		return errors.New("real protocol traffic was not metered bidirectionally")
	}
	if e = a.ConfigureTraffic(p.ID, TrafficPolicy{LimitBytes: total, BillingDay: 1}, false, time.Now()); e != nil {
		return e
	}
	u, _ := url.Parse(proxy)
	tr := &http.Transport{Proxy: http.ProxyURL(u)}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 400 * time.Millisecond}
	r, e := client.Get(endpoint)
	if e == nil {
		r.Body.Close()
		return fmt.Errorf("%s quota did not cut off protocol traffic", p.Protocol)
	}
	if e = a.TrafficGuard(p.ID); e == nil {
		return errors.New("protocol quota restart guard failed")
	}
	return nil
}
