package rout

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIntegrationMTPFakeTLS(t *testing.T) {
	bin := os.Getenv("ROUT_TEST_ENGINES")
	if bin == "" {
		t.Skip("set ROUT_TEST_ENGINES to download and run the pinned mtg engine")
	}
	a := &App{Home: t.TempDir(), BinDir: bin, ServiceMode: "none"}
	if e := a.EnsureEngine(mtpEngine); e != nil {
		t.Fatal(e)
	}
	v4 := []string{"127.0.0.1"}
	v6 := []string{"::1"}
	type variant struct {
		name, listen, inbound string
		accept, reject        []string
	}
	cases := []variant{{"IPv4", "0.0.0.0", inIPv4, v4, v6}}
	if ipv6LoopbackWorks() {
		cases = append(cases,
			variant{"IPv6", "::", inIPv6, v6, v4},
			variant{"dual", "::", inDual, []string{"127.0.0.1", "::1"}, nil})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := fixture(t, protoMTP)
			p.Listen, p.InboundMode, p.PublicHost = tc.listen, tc.inbound, tc.accept[0]
			var e error
			p.Port, e = freeNodePort(p)
			if e != nil {
				t.Fatal(e)
			}
			p.PublicPort = p.Port
			if e = a.writeProfile(p); e != nil {
				t.Fatal(e)
			}
			engine, args := a.serviceCommand(p)
			ctx, stop := context.WithCancel(context.Background())
			cmd := exec.CommandContext(ctx, engine, args...)
			var logs bytes.Buffer
			cmd.Stdout, cmd.Stderr = &logs, &logs
			if e := cmd.Start(); e != nil {
				stop()
				t.Fatal(e)
			}
			t.Cleanup(func() {
				stop()
				_ = cmd.Wait()
				raw, _ := hex.DecodeString(p.Password)
				if strings.Contains(logs.String(), p.Password) || strings.Contains(logs.String(), base64.RawURLEncoding.EncodeToString(raw)) {
					t.Error("mtg logged the configured secret")
				}
				if t.Failed() {
					t.Log(redactProxySecrets(logs.String(), State{Profiles: []Profile{p}}))
				}
			})
			for _, host := range tc.accept {
				deadline := time.Now().Add(12 * time.Second)
				for {
					e = probeMTPFakeTLS(p, host)
					if e == nil {
						break
					}
					if time.Now().After(deadline) {
						t.Fatalf("mtg did not authenticate a FakeTLS handshake on %s: %v", host, e)
					}
					time.Sleep(100 * time.Millisecond)
				}
			}
			for _, host := range tc.reject {
				if e = probeMTPFakeTLS(p, host); e == nil {
					t.Fatalf("mtg accepted FakeTLS on a disabled IP family (%s)", host)
				}
			}
		})
	}
}

// The FakeTLS record authenticates both peers before MTProto transport starts.
// A plain TLS handshake with the cover host cannot produce this server HMAC.
func probeMTPFakeTLS(p Profile, host string) error {
	const randomOffset = 11 // record header, handshake header, legacy TLS version
	secret, _ := hex.DecodeString(p.Password)
	key := secret[1 : 1+mtpKeyBytes]
	client, server := net.Pipe()
	defer server.Close()
	defer client.Close()
	_ = server.SetDeadline(time.Now().Add(time.Second))
	go func() {
		defer client.Close()
		_ = tls.Client(client, &tls.Config{ServerName: string(secret[1+mtpKeyBytes:]), MinVersion: tls.VersionTLS13}).Handshake()
	}()
	hello, e := readMTPTestRecord(server)
	if e != nil || len(hello) < randomOffset+sha256.Size {
		return errors.New("could not construct TLS ClientHello")
	}
	clientRandom := hello[randomOffset : randomOffset+sha256.Size]
	clear(clientRandom)
	mac := hmac.New(sha256.New, key)
	mac.Write(hello)
	copy(clientRandom, mac.Sum(nil))
	timestamp := binary.LittleEndian.Uint32(clientRandom[28:]) ^ uint32(time.Now().Unix())
	binary.LittleEndian.PutUint32(clientRandom[28:], timestamp)

	conn, e := net.DialTimeout("tcp", net.JoinHostPort(host, itoa(p.Port)), 500*time.Millisecond)
	if e != nil {
		return e
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, e = conn.Write(hello); e != nil {
		return e
	}
	reply, e := readMTPTestRecord(conn)
	if e != nil {
		return e
	}
	if reply[0] != 0x16 || len(reply) < randomOffset+sha256.Size {
		return errors.New("missing FakeTLS ServerHello")
	}
	serverRandom := append([]byte(nil), reply[randomOffset:randomOffset+sha256.Size]...)
	clear(reply[randomOffset : randomOffset+sha256.Size])
	mac.Reset()
	mac.Write(clientRandom)
	mac.Write(reply)
	for _, recordType := range []byte{0x14, 0x17} {
		record, e := readMTPTestRecord(conn)
		if e != nil {
			return e
		}
		if record[0] != recordType {
			return errors.New("unexpected FakeTLS record")
		}
		mac.Write(record)
	}
	if !hmac.Equal(serverRandom, mac.Sum(nil)) {
		return errors.New("FakeTLS server did not authenticate with the advertised secret")
	}
	return nil
}

func readMTPTestRecord(r io.Reader) ([]byte, error) {
	header := make([]byte, 5)
	if _, e := io.ReadFull(r, header); e != nil {
		return nil, e
	}
	record := append(header, make([]byte, int(binary.BigEndian.Uint16(header[3:])))...)
	_, e := io.ReadFull(r, record[len(header):])
	return record, e
}

func TestIntegrationMTPSystemdLifecycle(t *testing.T) {
	if os.Getenv("ROUT_TEST_SYSTEMD") != "1" {
		t.Skip("set ROUT_TEST_SYSTEMD=1 on a disposable root/systemd test host")
	}
	bin := os.Getenv("ROUT_TEST_ENGINES")
	if bin == "" {
		t.Fatal("ROUT_TEST_ENGINES is required")
	}
	root, e := os.MkdirTemp("/var/lib", "rout-mtp-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	a := &App{Home: filepath.Join(root, "config"), BinDir: filepath.Join(root, "bin"), ServiceMode: "auto"}
	if m, e := a.serviceManager(); e != nil || m != "systemd" {
		t.Fatal("requires a real systemd host")
	}
	cache := &App{BinDir: bin}
	if e = cache.EnsureEngine(mtpEngine); e != nil {
		t.Fatal(e)
	}
	if e = os.MkdirAll(a.BinDir, 0755); e != nil {
		t.Fatal(e)
	}
	if e = copyFileAtomic(cache.enginePath(mtpEngine), a.enginePath(mtpEngine), 0755); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if st, e := a.Load(); e == nil {
			for _, p := range st.Profiles {
				_ = a.removeService(p)
			}
		}
	})
	u, out := testUI(a, "Systemd\n9\n1\n")
	if e = u.create(); e != nil {
		t.Fatal(e)
	}
	st, e := a.Load()
	if e != nil || len(st.Profiles) != 1 {
		t.Fatalf("load created node: %v", e)
	}
	p := st.Profiles[0]
	link, _ := p.Share()
	if !strings.Contains(out.String(), link) {
		t.Fatal("the node wizard did not print the import link")
	}
	unit := serviceName(p) + ".service"
	assertRunning := func() {
		t.Helper()
		if e := command("systemctl", "is-enabled", unit); e != nil {
			t.Fatal(e)
		}
		if e := probeMTPFakeTLS(p, loopbackFor(p)); e != nil {
			t.Fatal(e)
		}
	}
	assertRunning()
	if e = a.Restart(p.ID); e != nil {
		t.Fatal(e)
	}
	assertRunning()
	pid := servicePID("systemd", serviceName(p))
	if e = command("systemctl", "kill", "--signal=KILL", unit); e != nil {
		t.Fatal(e)
	}
	deadline := time.Now().Add(20 * time.Second)
	for !mtpServiceListening("systemd", serviceName(p), p.Port) || servicePID("systemd", serviceName(p)) == pid {
		if time.Now().After(deadline) {
			t.Fatal("systemd did not recover the proxy after abnormal exit")
		}
		time.Sleep(100 * time.Millisecond)
	}
	assertRunning()
	for _, enabled := range []bool{false, true} {
		old, e := a.Load()
		if e != nil {
			t.Fatal(e)
		}
		p.Enabled = enabled
		if e = a.Commit(old, replace(old, p), false); e != nil {
			t.Fatal(e)
		}
		if enabled {
			assertRunning()
		} else if serviceActive("systemd", serviceName(p)) || socketBound("tcp", p.Port) {
			t.Fatal("disabled proxy still running")
		}
	}
	loaded, e := a.Load()
	if e != nil {
		t.Fatal(e)
	}
	got, e := loaded.Profiles[0].Share()
	if e != nil || got != link {
		t.Fatal("restart or toggling changed the persisted link")
	}
	if e = a.DeleteProfiles([]string{p.ID}); e != nil {
		t.Fatal(e)
	}
	for _, path := range []string{a.profileDir(p.ID), filepath.Join("/etc/systemd/system", unit)} {
		if _, e = os.Stat(path); !os.IsNotExist(e) {
			t.Fatalf("MTP file remains after deletion: %s", path)
		}
	}
	if serviceActive("systemd", serviceName(p)) || socketBound("tcp", p.Port) {
		t.Fatal("deleted proxy still running")
	}
}

// The NAT redirect stands in for a provider's TCP mapping. The engine and meter
// see the internal port, while the simulated Telegram client uses the share port.
func TestKernelMTPMappedPortAndAccounting(t *testing.T) {
	a := kernelApp(t)
	a.BinDir = os.Getenv("ROUT_TEST_ENGINES")
	if a.BinDir == "" {
		t.Skip("set ROUT_TEST_ENGINES to the verified mtg engine directory")
	}
	p := fixture(t, protoMTP)
	p.PublicHost, p.NAT = p.Listen, true
	listener, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	p.PublicPort = listener.Addr().(*net.TCPAddr).Port
	p.Port, e = freeNodePort(p)
	listener.Close()
	if e != nil {
		t.Fatal(e)
	}
	old, e := a.Load()
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = a.meter().Delete(p) })
	if e = a.Commit(old, replace(old, p), false); e != nil {
		t.Fatal(e)
	}
	table := "rout_test_mtp_" + p.ID
	rules := fmt.Sprintf(`table ip %s {
		chain output {
			type nat hook output priority -100; policy accept;
			ip daddr 127.0.0.1 tcp dport %d redirect to :%d
		}
	}`, table, p.PublicPort, p.Port)
	if e = nftApply(rules); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = nftApply("delete table ip " + table + "\n") })
	engine, args := a.serviceCommand(p)
	startEngine(t, profileSockets(p), engine, args...)
	before, e := a.meter().Read(p)
	if e != nil {
		t.Fatal(e)
	}
	client := p
	client.Port = p.PublicPort
	if e = probeMTPFakeTLS(client, p.PublicHost); e != nil {
		t.Fatal(e)
	}
	after, e := a.meter().Read(p)
	if e != nil {
		t.Fatal(e)
	}
	if after.Up <= before.Up || after.Down <= before.Down {
		t.Fatal("mapped MTP connection was not metered in both directions")
	}
}
