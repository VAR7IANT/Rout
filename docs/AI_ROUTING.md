# AI routing security and acceptance

This document is a test procedure, not evidence that the US/Canada VPS path has
been tested. No production deployment is part of this change.

## AI exits through a relay (v0.5.1)

A port forward alone is never an exit: it moves the connection, and the destination
still sees whoever dialed last. v0.5.1 therefore models a **relay chain**: an exit of
kind `chain` that names the real proxy at the END of the forward and the hop that
carries the connection there.

```text
Client → US VPS (bound Rout inbound) ─┬─ ordinary traffic → node's original exit (US IP)
                                      └─ AI domains → hop → SOCKS5 / HTTP(S) CONNECT / remote node → Internet (exit IP)
hop = a Rout relay on this server (via_relay: stable relay ID)
    | a forwarder port on another server, e.g. a NAT or IPv6-only box (via_address: host:port)
```

`state.json` stores, for example:

```json
{"id": "a1b2c3d4e5f6", "name": "CA via hop", "kind": "chain", "via_relay": "0123456789ab",
 "proxy": {"protocol": "socks5", "host": "ca.example.net", "port": 1080, "username": "…", "password": "…"}}
```

- **References, not positions.** The relay is referenced by its stable ID. The address
  the bound nodes dial (`127.0.0.1`/`::1` and the relay's port, from the relay's own
  listen address) is derived each time the configuration is rendered, so changing the
  relay's port updates the AI exit in the same transaction. The relay's target must be
  exactly the proxy's endpoint.
- **Protection.** Deleting, disabling, or retargeting a relay that a chain uses is
  refused, naming the relay and the exit. A chain whose relay disappears anyway (state
  edited by hand, partial restore) is not a fallback: AI domains of bound nodes are
  rejected, exactly like a missing exit.
- **Loops.** A relay (or a remote forwarder address) that points at a Rout node or relay
  of this server is refused: the traffic would come back and leave from this server. A
  different local service — such as the SSH-forwarded SOCKS5 below on `127.0.0.1:11080`
  — is a legitimate end of a chain. The internal loopback hop to a Rout relay is an
  explicit reference checked by ID; no loop or SSRF check is relaxed for anything else.
- **TLS identity.** For HTTPS CONNECT the certificate is still verified against the real
  proxy host (`server_name`), and for node links the link is rewritten to the hop while
  keeping its SNI/host parameters, so moving the socket never weakens TLS.
- **Transport.** The chain carries TCP. A relay must forward the transport the end needs
  (TCP for SOCKS5/HTTP/VLESS/Trojan/AnyTLS, UDP for Hysteria2/TUIC; a TCP-only NAT target
  cannot reach a UDP node). AI UDP/QUIC is still rejected so clients fall back to TCP.
- **Address families.** The hop's outbound policy (IPv4/IPv6 only/first, auto) decides
  how it reaches the proxy, independently of how clients reach the node: an IPv6 entry
  does not imply an IPv6 exit and vice versa.
- **Encryption.** SOCKS5 and HTTP CONNECT authenticate and connect in plaintext; a
  forward does not add encryption. Across the Internet prefer HTTPS CONNECT, a remote
  node link (VLESS Reality, AnyTLS, Trojan …) or an SSH tunnel.
- **Scope.** Chain exits are used by AI Smart Routing only; binding one as a node's
  ordinary outbound is refused.

*Select AI exit* offers: existing outbound proxies; **through an existing port forward**
(pick a relay, then the service at its end: SOCKS5 / HTTP CONNECT / HTTPS CONNECT with
credentials, or a node link — the relay's own target link is offered when it has one);
**remote node share link**; **create a new exit chain** (a new relay on this server that
listens on `127.0.0.1` only, with its outbound family policy, or a forwarder address on
another server, plus the proxy). Whatever is created is tested before it is selected and
removed again if you decline to keep a failing one. The panel's *AI Routing* page offers
the same four ways (`POST /api/exits/chain`).

### End-to-end AI exit test

*Test configuration* (`rout ai test`, panel *Test AI exit*, `POST /api/ai/test`) runs every
layer and stops at the first failure, naming it:

```text
AI exit test
1. Local listening   ✓ Inbound US-A is working
4. Relay             ✓ Relay CA-hop is enabled: 127.0.0.1:20001 → ca.example.net:1080
3. Target            ✓ Relay target ca.example.net:1080 is reachable: IPv4 203.0.113.7:1080 (31 ms)
3. Target            ✓ TCP connection established: IPv4 127.0.0.1:20001 (0 ms)
5. Proxy protocol    ✓ The proxy accepted the credentials (SOCKS5 handshake succeeded)
6. Real exit         ✓ Exit IPv4: <observed address>
6. Real exit         ✓ AI exit chain is working
```

The exit address is what an IP-echo service observed for a request sent through the
generated outbound (relay included); it is never taken from the configuration. A
result equal to one of this server's own addresses is flagged. The test does not prove
that every AI application uses recognizable domains, nor the exit's geography.

Automated evidence (no VPS): `TestChainDiagnosisRealTrafficThroughRelayAndSOCKS5` sends
real traffic through Rout's native relay to an authenticating SOCKS5 server that egresses
from `127.0.0.2`, checks wrong credentials (layer 5) and a stopped proxy, and that no
request reaches the origin without the proxy. `TestIntegrationAIRelayChain`
(`ROUT_TEST_ENGINES`) runs real sing-box nodes: the bound node's AI requests leave from
`127.0.0.2`, its ordinary requests and every request of the unbound node from
`127.0.0.1`, and with the relay stopped the AI request fails without reaching the
origin.

### Chain acceptance on real VPSs (operator-run)

In addition to the steps below: on the US host create a relay to the Canada SOCKS5
(or use *Create a new exit chain*), select it as the AI exit, run `rout ai test` and
record the observed exit IP (it must be the Canada address). Repeat step 4/6 with the
relay stopped (`rout off RELAY_ID`): AI requests must fail and the observer must see no
US request. Try deleting the relay: it must be refused naming the AI exit chain. For a
relay on a NAT or IPv6-only VPS, use *a forwarder port on another server* and repeat.

## US → Canada transport

`http` means **plaintext HTTP CONNECT**. Its Basic authentication is reversible;
`socks5` also sends username/password without encryption. HTTPS at the final AI
service encrypts application data, but does not protect these proxy credentials,
CONNECT destinations or the US-to-Canada proxy handshake.

`https` is an explicit new choice in Outbound proxies. It renders sing-box's HTTP
outbound with `tls.enabled=true`, the configured host as `server_name`, and a TLS
1.2 minimum. The system CA store must trust the proxy certificate; the certificate
must match that hostname (or have an IP SAN when using a literal IP). Prefer a
CA-issued hostname. Debian/Ubuntu and Alpine need an up-to-date `ca-certificates`
package. There is no `insecure` switch or plaintext/direct retry. A TLS or auth
failure fails the connection. Existing SOCKS5/HTTP entries are never converted:
a plain proxy cannot automatically become a TLS endpoint. Rout warns in the
proxy menu, doctor and AI diagnostics/test. Create and test a separate HTTPS
exit first, then explicitly select it; retain the old exit for rollback.

The implementation was checked against the [pinned sing-box 1.14.3 HTTP outbound source](https://github.com/SagerNet/sing-box/blob/v1.14.3/protocol/http/outbound.go) and [upstream HTTP/TLS documentation](https://sing-box.sagernet.org/configuration/outbound/http/). Newer documentation fields are not assumed to exist in the pinned engine.

The configuration, generated files and backups contain credentials and use mode
0600 inside private directories. The interactive proxy input hides credentials;
lists, errors and diagnostics must not print them. `rout logs` redacts known proxy
credentials and Basic/URL encodings. Init command failures omit raw output, which
can contain engine journal lines. Raw `journalctl`, OpenRC logs, exported client
links and backups remain sensitive; redaction cannot protect arbitrary externally
transformed strings or secrets from an exit removed from state. Do not share them.

### SOCKS5 through SSH (Debian, Ubuntu, Alpine; IPv4 or IPv6)

Keep the authenticated SOCKS5 server on **Canada loopback** (for example
`127.0.0.1:1080`). On the US server, use an existing SSH account restricted to TCP
forwarding to that address, a dedicated key and a host key verified out of band.
Install the verified host key in `/etc/rout-ai-ssh/known_hosts` and keep the private
key `/etc/rout-ai-ssh/id_ed25519` root-owned, mode 0600. Do not blindly trust
`ssh-keyscan` output. The Canada public SOCKS5 port need not be open.

Run on the US host, replacing the SSH destination (OpenSSH also accepts an IPv6
literal after `@`):

```sh
ssh -NT -o BatchMode=yes -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile=/etc/rout-ai-ssh/known_hosts \
  -o ExitOnForwardFailure=yes -o ServerAliveInterval=15 -o ServerAliveCountMax=3 \
  -i /etc/rout-ai-ssh/id_ed25519 \
  -L 127.0.0.1:11080:127.0.0.1:1080 tunnel@ca.example.net
```

Create a **new** Rout SOCKS5 entry for `127.0.0.1:11080`, entering the original
SOCKS5 username/password through the hidden prompt, test it, then select it as the
AI exit. `-L` preserves authenticated SOCKS5. A bare `ssh -D` proxy has no SOCKS
authentication and does not fit Rout's authenticated proxy input. Do not disable
host-key verification. Do not reuse an occupied forwarding port.

For persistence, supervise that same command separately from Rout. A systemd
unit can use `Type=simple`, the command above as `ExecStart` (one line),
`Restart=on-failure`, `RestartSec=3`, and `After/Wants=network-online.target`.
On Alpine, an `/sbin/openrc-run` service can use `supervisor=supervise-daemon`,
`command=/usr/bin/ssh`, the arguments above as `command_args`, `respawn_delay=3`,
`respawn_max=5`, `respawn_period=60`, and `depend() { use net; }`.
Verify the SSH executable path and init syntax on the host. Enable only after
running the foreground command successfully. No tunnel, SSH account, firewall or
remote service is automatically created or migrated by Rout. The warning remains
because Rout cannot prove that a loopback SOCKS5 listener is backed by SSH.

If SSH dies, new identified AI connections fail until the tunnel recovers; Rout
never substitutes the original exit. Keepalive failure detection takes time and
existing sessions can break. Test this failure on a disposable host first.

## Identification boundaries

- Only explicitly bound stable node IDs receive rules. Multiple bindings are
  supported. Empty means none. Unbound nodes/relays keep their files and services.
- Case-insensitive matching accepts a trailing DNS root dot. Explicit destination domain matching precedes sniffing, then matching is
  repeated for TLS SNI, HTTP Host and supported QUIC discovered at an IP target.
  Sniffing has a one-second timeout and never rewrites the destination address.
  Slow, fragmented or unsupported handshakes may remain unclassified.
- Identified AI TCP uses only the selected exit. Identified AI UDP is rejected;
  HTTPS CONNECT and authenticated third-party SOCKS5 are TCP-only here. QUIC/HTTP3
  can fall back to TCP only if the client supports it. Unrecognized QUIC can still
  use the original route. A missing/invalid exit produces reject rules when applied.
- There is **no DNS hijacking, DNS firewall, reverse-DNS cache or FakeIP service**.
  DNS packets are not among the selected sniffers. Client DNS, DoH/DoT to generic
  resolvers, bootstrap resolution of proxy hostnames, and ordinary direct-route
  lookups retain their original behavior. Sending a domain over the node lets the
  selected SOCKS/HTTP proxy resolve the destination; resolving it on the client
  first can lose that signal. AI DNS queries are not guaranteed to use Canada.
- ECH hides the inner TLS/QUIC name. If the proxy request still carries an explicit
  AI domain it is matched first; otherwise a non-AI outer name, an unlisted shared
  CDN, IP-only traffic without a visible AI Host/SNI, tunneling and applications
  that conceal their destination can take the original US route. IPv4/IPv6
  addresses alone do not identify a service. This is **not a zero-leak guarantee**.
- The domain list is not exhaustive. Copilot authentication at `api.github.com`
  and ordinary company domains intentionally retain their normal route. The
  configured exit is not automatically verified to be geographically Canadian.
- Disabling keeps bindings and restores the original route. Outbound replacement
  restarts only nodes that use that exit, including ordinary users of a shared
  exit. Use a dedicated AI exit when ordinary nodes must not restart with it.
  Quotas remain measured at the inbound, without resetting usage/billing cycles.

## Automated tests (local, never production)

On Linux, in the checkout:

```sh
go test ./...
go test -race ./...
go vet ./...
go build -o /tmp/rout-candidate ./cmd/rout
/tmp/rout-candidate --home /tmp/rout-test-state --bin-dir /tmp/rout-test-engines --service none engines
ROUT_TEST_ENGINES=/tmp/rout-test-engines go test -race -count=1 -v ./internal/rout \
  -run '^(TestIntegrationAI|TestIntegrationHTTPSConnect|TestAIGenerated|TestAI|TestProxy)'
sh scripts/release.sh
(cd dist && sha256sum -c checksums.txt)
```

These tests use controlled HTTP CONNECT proxies, echo servers and real sing-box
processes. They cover bound A/C versus unbound B, explicit domain, HTTP Host,
TLS SNI, IPv4/IPv6 proxy endpoints, pure-IP limitations, AI UDP rejection, ordinary
UDP preservation, failed exits and disabling. HTTPS tests include a private test
trust root, unknown CA, expired certificate, wrong hostname, failed authentication and a plain peer.
They do not assert real QUIC/ECH classification or public internet geography.

On a **disposable root Linux host**, after installing the verified engines:

```sh
go test -c -o /tmp/rout-ai.test ./internal/rout
sudo env ROUT_TEST_ENGINES=/tmp/rout-test-engines ROUT_TEST_SYSTEMD=1 \
  /tmp/rout-ai.test -test.run '^TestIntegrationAIServiceIsolation$' -test.v
# Alpine/OpenRC: replace ROUT_TEST_SYSTEMD=1 with ROUT_TEST_OPENRC=1.
```

The service test checks real PIDs, outbound replacement, engine startup failure,
rollback of state/configuration and working traffic after recovery. File-write and
syntax failure rollback tests run in the ordinary AI suite. CI runs the network
suite on Ubuntu and Alpine and the service test on both systemd and OpenRC.
Linux-only kernel accounting tests remain in the full CI. Skipped tests are not
passes. macOS cannot validate systemd/OpenRC, nftables or Linux `/proc` behavior.

## US/Canada VPS acceptance (operator-run)

1. Record the exact candidate SHA, OS, kernel version, sing-box version and US/CA
   public IPv4/IPv6. Save `rout backup /root/rout-before-ai.json` on the US host.
   Use a maintenance window/disposable nodes; retain administrative SSH access.
2. Create/test the verified HTTPS or SSH SOCKS5 exit as above. From the main
   menu select AI Smart Routing, bind test node **A** (and optionally **C**), leave
   **B** unbound, select Canada, enable. Save `rout ai status`, `rout doctor`, and
   `rout traffic` output privately. `rout ai test` is a config/proxy test plus
   a simulation, not proof of the complete routing path.
3. On US, substitute the actual 12-character IDs below. Record config hashes and
   service PIDs before and after each operation:

   ```sh
   A=REPLACE_A_ID B=REPLACE_B_ID
   sha256sum /etc/rout/profiles/"$A"/config.json /etc/rout/profiles/"$B"/config.json
   systemctl show -p MainPID -p NRestarts "rout-$A.service" "rout-$B.service"
   # OpenRC: rc-service rout-ID status; cat /run/rout-ID.pid
   /opt/rout/bin/sing-box-v1.14.3 check -c /etc/rout/profiles/"$A"/config.json
   /opt/rout/bin/sing-box-v1.14.3 check -c /etc/rout/profiles/"$B"/config.json
   rout export "$A" /root/client-A.json
   rout export "$B" /root/client-B.json
   ```

   Transfer the exports securely to an external test client. Run one with its
   local port 2080, and set the other export's `inbounds[0].listen_port` to 2081
   before running it. Run `sing-box check -c client-A.json` / `client-B.json`,
   then `sing-box run -c ...` in separate terminals. These files contain secrets.
4. On a controlled observer host reachable from both VPSs, run a temporary echo
   service (limit its test port to the participating addresses in the firewall):

   ```sh
   python3 - <<'PY'
   from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
   class Echo(BaseHTTPRequestHandler):
       def do_GET(self):
           self.send_response(200); self.end_headers()
           self.wfile.write((self.client_address[0] + '\n').encode())
       def log_message(self, *_): pass
   ThreadingHTTPServer(('0.0.0.0', 18080), Echo).serve_forever()
   PY
   ```

   On the external client, replace `OBSERVER_IPV4` with that host's literal IP:

   ```sh
   OBSERVER=http://OBSERVER_IPV4:18080
   curl --fail --max-time 10 --socks5-hostname 127.0.0.1:2080 -H 'Host: api.openai.com' "$OBSERVER"
   curl --fail --max-time 10 --socks5-hostname 127.0.0.1:2080 -H 'Host: ordinary.example' "$OBSERVER"
   curl --fail --max-time 10 --socks5-hostname 127.0.0.1:2081 -H 'Host: api.openai.com' "$OBSERVER"
   curl --fail --max-time 10 --socks5-hostname 127.0.0.1:2081 -H 'Host: ordinary.example' "$OBSERVER"
   ```

   Expect CA, original US, original US, original US respectively (or each node's
   pre-existing configured exit). This tests real HTTP Host routing through the
   nodes, not a mock rule decision. It does not prove every AI application uses
   the same recognizable domains. Repeat using a dual-stack observer listener
   and `http://[OBSERVER_IPV6]:18080` when both exit paths support IPv6.
5. Test an explicit AI domain and HTTPS from the external client:

   ```sh
   curl --max-time 15 --socks5-hostname 127.0.0.1:2080 -o /dev/null -w '%{http_code}\n' https://api.openai.com/v1/models
   curl --fail --max-time 15 --socks5-hostname 127.0.0.1:2080 https://example.com/ -o /dev/null
   ```

   A 401 from the AI API without an API key proves an HTTP response, not account
   eligibility. Use private tcpdump/connection observation on both VPSs to
   corroborate US→Canada proxy traffic and Canada→AI connections. Do not capture
   payloads or publish authenticated plaintext proxy traffic. Test real app
   login/generation separately; record service denial/geofencing as a failure.
6. Stop **only the test Canada proxy or test SSH tunnel**, keeping SSH admin access.
   Repeat step 4: A AI must fail within the curl timeout and the observer must see
   no replacement US request. A ordinary and both B requests must still succeed.
   Restore the exit. With HTTPS, also test an untrusted/expired/wrong-host
   certificate on a disposable endpoint; it must fail, never retry plaintext.
7. Change the selected AI exit, then edit that exit's connection parameters.
   Compare PIDs/hashes: only its bound nodes (and any ordinary users of the same
   exit) may restart. B stays unchanged. Test multiple bindings, delete one bound
   disposable node, and restart the remaining A service; the binding must retain
   its stable ID. Disable AI routing: A AI now uses the original exit, B is still
   unchanged and bindings remain saved. Re-enable and verify Canada again.
8. Compare quota settings, billing window and increasing usage before/after each
   step. No reset or double counting is allowed. Run write/start-failure injection
   only with the disposable automated suite above, never against production.
   Record DNS resolver traffic, IP-only/ECH and UDP/QUIC behavior; unclassified
   connections taking the original route are documented limitations, not passes
   for a claim of complete protection.

Stop the observer and client processes and remove temporary firewall allowances
when finished. Do not include proxy secrets or share links in acceptance reports.

## Release gate and commands (do not run before acceptance)

The candidate is **v0.3.2**. A `main` push only builds/tests/uploads artifacts; only
an explicit matching `v*` tag enters the publishing job. Installer defaults point
to v0.3.2 in preparation; until that release exists, installation from main fails
without replacing the installed executable. Use a local candidate build for tests
or `ROUT_VERSION=v0.3.1` for the currently published stable version.

Require green CI for the exact final SHA (Ubuntu race/config/network/systemd/kernel,
Alpine/OpenRC, amd64/arm64 checksums), then the operator's real US/Canada evidence.
QUIC/ECH identification limits and client DNS behavior remain release notes.
Only after that gate, an authorized release operator can run:

```sh
git switch main
git pull --ff-only origin main
gh run list --repo VAR7IANT/Rout --branch main --limit 5
# Inspect the successful run for the exact HEAD, then confirm VPS acceptance.
git tag -a v0.3.2 -m 'Rout v0.3.2'
git push origin v0.3.2
# CI publishes binaries, version.txt, SHA256 checksums and provenance after verification.
```

These commands are provided for a future release; the hardening task must not
execute them. No production VPS deployment is needed to prepare these artifacts.
