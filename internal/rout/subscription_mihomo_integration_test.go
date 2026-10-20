package rout

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func mihomoBinary(t *testing.T) string {
	t.Helper()
	binary := os.Getenv("ROUT_TEST_MIHOMO")
	if binary == "" {
		t.Skip("set ROUT_TEST_MIHOMO to the checksum-verified test core; real Mihomo has NOT run")
	}
	if _, e := os.Stat(binary); e != nil {
		t.Fatal(e)
	}
	return binary
}
func validateRealMihomo(t *testing.T, binary, body string) string {
	t.Helper()
	dir := t.TempDir()
	file := filepath.Join(dir, "subscription.yaml")
	if e := os.WriteFile(file, []byte(body), 0600); e != nil {
		t.Fatal(e)
	}
	if out, e := runOutput(20*time.Second, binary, "-t", "-d", dir, "-f", file); e != nil {
		t.Fatalf("real Mihomo rejected generated YAML: %v %s", e, sanitizeSubscriptionLogs(out))
	}
	return file
}

func TestIntegrationSubscriptionMihomoValidation(t *testing.T) {
	binary := mihomoBinary(t)
	if out, e := runOutput(5*time.Second, binary, "-v"); e != nil {
		t.Fatal(e)
	} else {
		t.Log(strings.TrimSpace(string(out)))
	}
	var profiles []Profile
	var ids []string
	for i, protocol := range []string{"vless", "ss", "hy2", "tuic", "anytls"} {
		p := linkFixture(t, protocol, "2001:db8::7")
		p.Port = 25000 + i
		p.Name = "🇯🇵 Tokyo: [A] # one \"quoted\""
		profiles = append(profiles, p)
		ids = append(ids, p.ID)
	}
	for _, link := range []string{
		"vless://" + profiles[0].UUID + "@origin.example:443?security=tls&sni=tls.example&type=ws&host=ws.example&path=%2Fsocket&fp=firefox&alpn=h2",
		"vless://" + profiles[0].UUID + "@origin.example:80?security=none&type=tcp",
		"trojan://test-password@origin.example:443?sni=tls.example&type=grpc&serviceName=service&authority=tls.example",
		"hysteria2://test-password@origin.example:443?sni=tls.example&insecure=1&pinSHA256=" + strings.Repeat("a", 64),
	} {
		target, network, e := ParseTarget(link)
		if e != nil {
			t.Fatal(e)
		}
		p := Profile{ID: RandomHex(6), Name: "DIRECT", Kind: "relay", Protocol: network, Enabled: true, Listen: "127.0.0.1", Port: 26000 + len(profiles), PublicHost: "relay.example", PublicPort: 36000 + len(profiles), Target: target, TargetURI: link, RelayMode: relayRemote}
		profiles = append(profiles, p)
		ids = append(ids, p.ID)
	}
	for _, method := range []string{"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"} {
		password := "test-password"
		if strings.HasPrefix(method, "2022-") {
			size := 32
			if method == "2022-blake3-aes-128-gcm" {
				size = 16
			}
			password = RandomPassword(size)
		}
		link := (&url.URL{Scheme: "ss", User: url.UserPassword(method, password), Host: "origin.example:443"}).String()
		target, _, _ := ParseTarget(link)
		p := Profile{ID: RandomHex(6), Name: "Cipher " + method, Kind: "relay", Protocol: "both", Enabled: true, Listen: "127.0.0.1", Port: 28000 + len(profiles), PublicHost: "relay.example", PublicPort: 38000 + len(profiles), Target: target, TargetURI: link, RelayMode: relayRemote}
		profiles = append(profiles, p)
		ids = append(ids, p.ID)
	}
	state := State{Schema: 1, Profiles: profiles}
	if e := state.Validate(); e != nil {
		t.Fatal(e)
	}
	proxies, warnings := state.exportMihomo(Subscription{NodeIDs: ids})
	if len(proxies) != len(ids)-1 || len(warnings) != 1 {
		t.Fatal("unexpected conversion coverage")
	}
	validateRealMihomo(t, binary, renderMihomo(proxies, warnings, mihomoDefaultTestURL))
}

// Real requests through the generated Mihomo select group reach real sing-box
// nodes. TLS trust, Reality Vision, auth and protocol mappings are exercised,
// rather than inferring interoperability from successful YAML parsing.
func TestIntegrationSubscriptionMihomoTraffic(t *testing.T) {
	binary := mihomoBinary(t)
	a := integrationApp(t)
	cert, key, camouflage := tlsFixture(t)
	camHost, camPort, _ := ParseEndpoint(strings.TrimPrefix(camouflage.URL, "https://"))
	hits := &atomic.Int32{}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); fmt.Fprint(w, "198.51.100.19") }))
	defer origin.Close()
	for _, protocol := range []string{"vless", "ss", "hy2", "tuic"} {
		t.Run(protocol, func(t *testing.T) {
			isolated := *a
			isolated.Home = t.TempDir()
			a := &isolated
			p := fixture(t, protocol)
			p.Port, _ = freePort()
			p.PublicPort = p.Port
			p.PublicHost = "127.0.0.1"
			p.SNI = "example.test"
			p.CertPEM, p.KeyPEM = cert, key
			if e := p.Validate(); e != nil {
				t.Fatal(e)
			}
			if e := a.writeProfile(p); e != nil {
				t.Fatal(e)
			}
			conf, e := serverConfig(p, a.profileDir(p.ID))
			if e != nil {
				t.Fatal(e)
			}
			if protocol == "vless" {
				conf["inbounds"].([]any)[0].(M)["tls"].(M)["reality"].(M)["handshake"] = M{"server": camHost, "server_port": camPort}
			}
			startEngine(t, profileSockets(p), a.enginePath("sing-box"), "run", "-c", configFile(t, conf))
			proxy, e := mihomoNode(p)
			if e != nil {
				t.Fatal(e)
			}
			proxy["name"] = "Original selected node"
			body := renderMihomo([]M{proxy}, nil, "https://127.0.0.1/unused")
			port, _ := freePort()
			body += "mixed-port: " + itoa(port) + "\nbind-address: 127.0.0.1\nallow-lan: false\nlog-level: warning\n"
			file := validateRealMihomo(t, binary, body)
			startEngine(t, []engineSocket{{"tcp", port}}, binary, "-d", filepath.Dir(file), "-f", file)
			// Mihomo binds listeners just before marking its tunnel ready. A TCP
			// socket alone is not a readiness assertion; require a real response.
			deadline := time.Now().Add(4 * time.Second)
			for {
				got, er := fetchIP("socks5://127.0.0.1:"+itoa(port), origin.URL)
				if er == nil && got == "198.51.100.19" {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("real Mihomo %s request failed: %v", protocol, er)
				}
				time.Sleep(100 * time.Millisecond)
			}
			testMihomoUDP(t, a, port)
			if protocol == "hy2" || protocol == "tuic" {
				before := hits.Load()
				proxy["fingerprint"] = strings.Repeat("0", 64)
				badPort, _ := freePort()
				bad := renderMihomo([]M{proxy}, nil, "https://127.0.0.1/unused") + "mixed-port: " + itoa(badPort) + "\nbind-address: 127.0.0.1\nallow-lan: false\nlog-level: error\n"
				badFile := validateRealMihomo(t, binary, bad)
				startEngine(t, []engineSocket{{"tcp", badPort}}, binary, "-d", filepath.Dir(badFile), "-f", badFile)
				proxyURL, _ := url.Parse("socks5://127.0.0.1:" + itoa(badPort))
				transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
				defer transport.CloseIdleConnections()
				client := &http.Client{Transport: transport, Timeout: 1500 * time.Millisecond}
				response, e := client.Get(origin.URL)
				if response != nil {
					response.Body.Close()
				}
				if e == nil || hits.Load() != before {
					t.Fatal("wrong certificate pin accepted or connection bypassed the proxy")
				}
			}

		})
	}
}

func testMihomoUDP(t *testing.T, a *App, mixedPort int) {
	t.Helper()
	sink, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer sink.Close()
	go func() {
		b := make([]byte, 512)
		for {
			n, peer, e := sink.ReadFrom(b)
			if e != nil {
				return
			}
			sink.WriteTo(b[:n], peer)
		}
	}()
	_, sinkPort, _ := ParseEndpoint(sink.LocalAddr().String())
	udpPort, _ := freePort()
	client := M{"log": M{"level": "error"}, "inbounds": []any{M{"type": "direct", "listen": "127.0.0.1", "listen_port": udpPort, "network": "udp", "override_address": "127.0.0.1", "override_port": sinkPort}}, "outbounds": []any{M{"type": "socks", "server": "127.0.0.1", "server_port": mixedPort, "version": "5"}}}
	startEngine(t, []engineSocket{{"udp", udpPort}}, a.enginePath("sing-box"), "run", "-c", configFile(t, client))
	conn, e := net.Dial("udp", "127.0.0.1:"+itoa(udpPort))
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	conn.Write([]byte("Mihomo UDP"))
	b := make([]byte, 10)
	if _, e = io.ReadFull(conn, b); e != nil || string(b) != "Mihomo UDP" {
		t.Fatal("real Mihomo UDP failed", e)
	}
}
