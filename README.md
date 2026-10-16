# Rout

Create proxy nodes, relay an existing server, or attach a purchased proxy exit to a VPS or NAT VPS. Install once and run `rout` for the Chinese interactive menu.

## Install

Linux amd64 / arm64, with systemd or OpenRC. Debian, Ubuntu and Alpine are the initial targets. Root access is required to manage services. Provider-side firewall rules and NAT mappings must already allow the selected ports.

```sh
curl -fsSL https://raw.githubusercontent.com/VAR7IANT/Rout/main/install.sh -o /tmp/rout-install.sh
sudo sh /tmp/rout-install.sh
sudo rout
```

On Alpine or when already logged in as root, omit `sudo`. The installer downloads a release binary and checks SHA256 before replacing the executable. It does not create a node or change routing until you open the menu. A published `v0.1.0` release is required; see [release instructions](#development-and-releases).

## Three workflows

| Workflow | Input | Result |
| --- | --- | --- |
| Create nodes | Protocol(s), ports, public address, SNI or certificates | New node links and independent services |
| Relay a node | Existing node URI or target `host:port`, local/public ports | TCP/UDP stream forwarding with original node credentials |
| Attach a proxy exit | A Rout-managed node, protocol, `IP:port:username:password` | That node exits through the purchased proxy |

Node creation supports VLESS Reality, AnyTLS Reality, Shadowsocks 2022, Hysteria2 and TUIC. HY2/TUIC require a PEM certificate/key pair and UDP connectivity. Their exported sing-box client configuration includes the certificate as a trust anchor. Generic share links need a certificate trusted by the client. AnyTLS Reality requires a client that supports that combination; the exported sing-box configuration is the reference format.

Relay URI import supports `vless://`, `anytls://`, `trojan://`, SIP002 `ss://`, `hysteria2://` / `hy2://` and `tuic://`. Other services can be forwarded by entering an address and choosing TCP, UDP or both. SS plugin URIs and legacy fully Base64-encoded SS URIs are not imported in this version. A relay preserves the original SNI, keys and transport settings when generating its replacement URI. It does not deploy or modify the target server.

Proxy exit setup asks for the protocol **first**, then accepts:

```text
192.0.2.10:6719:username:password
[2001:db8::10]:6719:username:password
```

Supported exit protocols: SOCKS5 and HTTP CONNECT. Passwords can contain colons; usernames cannot. The input is hidden in interactive terminals. Authentication and an actual IPv4 request through a temporary local proxy are tested before binding the exit. The IP shown is the observed exit IP, which may differ from the proxy endpoint address.

Proxy exits are TCP-only in this release. UDP is explicitly rejected, including with third-party SOCKS5 exits whose UDP capability has not been verified. If an exit fails, the node fails rather than falling back to the VPS IP. Existing node links remain usable after changing that node's exit.

## NAT and networking

Rout stores local listen ports and public mapped ports separately. It cannot create a provider's NAT mapping or infer the assigned public ports. UDP node protocols require an allowed UDP mapping. NAT servers with no reachable inbound port require a reverse tunnel, which is outside this release.

Only traffic using the managed node is routed through its configured exit. SSH, package updates, ordinary server-side `curl` and other existing services keep their normal network path. Rout does not enable TUN, change the default route, flush firewall rules, or overwrite `/etc/sing-box`.

The selected listen port must also be allowed by the VPS/provider firewall. Rout checks local port conflicts; it does not open external firewalls automatically. A successful local node test does not prove that a public/NAT port is reachable: verify the exported link from an external client.

## Management

```sh
rout                         # Chinese menu
rout list
rout status
rout test ID                 # Local entry → protocol → configured exit; IPv4 and IPv6 results
rout export ID               # Share URI (contains client credentials)
rout export ID client.json   # Full sing-box client config, local proxy on 127.0.0.1:2080
rout on ID
rout off ID
rout logs ID
rout delete ID
rout backup /root/rout.json
rout restore /root/rout.json
rout apply                   # Validate and reapply all managed entries
rout update                  # Update manager from the latest release
rout uninstall               # Interactive confirmation
```

Configuration and backups: `/etc/rout`. Pinned engine binaries: `/opt/rout/bin`. Services: `rout-<ID>`. Each node/relay has its own service, so editing a line does not require restarting unrelated lines. Each service consumes a separate engine process; size the VPS for the number of nodes you run.

Changes are locked against concurrent writers. Configuration validation happens before service changes. Failed changes restore prior state/configuration and attempt to restore the affected services; recovery errors are surfaced rather than hidden. Automatic pre-change backups and explicit backups include credentials and private keys and are written with mode `0600`.

Engine versions are locked in `internal/rout/engines.lock.json`: sing-box v1.14.3 and GOST v3.3.0, with per-architecture SHA256 values. Engines are downloaded on demand. Manager updates do not restart active services; after updating, use `rout apply` when ready to validate and switch existing services to the manager's pinned engines. Keep a backup for version rollback.

## Development and releases

Go 1.23+, standard library only. Rout is original code, with workflow inspiration from [singbox-deploy](https://github.com/caigouzi121380/singbox-deploy). Forwarding and proxy implementations are provided by separately downloaded [GOST](https://github.com/go-gost/gost) and [sing-box](https://github.com/SagerNet/sing-box), under their respective licenses.

```sh
go test -race ./...
go vet ./...
go build -o rout ./cmd/rout

# Isolated config/engine install: does not install or start system services
./rout --home /tmp/rout-state --bin-dir /tmp/rout-engines --service none engines
ROUT_TEST_ENGINES=/tmp/rout-engines go test -race -count=1 -v ./internal/rout

sh scripts/release.sh
```

The integration suite uses local origins, test HTTP/SOCKS proxies and disposable credentials. It checks actual encrypted traffic for all five node protocols, both authenticated proxy exits, and TCP/UDP forwarding. A host that permits sing-box's Linux network interface discovery is required. `ROUT_SKIP_SINGBOX_RUNTIME=1` skips those runtime cases when the environment blocks netlink; configuration checks and GOST forwarding still run. Do not equate a skipped test with a successful protocol test.

CI runs unit/race/static checks, verified-engine integration tests, actual systemd lifecycle/rollback tests and cross-compilation on every push. A successful push to `main` publishes the compiled version as a release **only after** all checks pass. An existing release is preserved. Bump `Version` and the installer's default version for a new release. Explicit version tags are also supported and must match the compiled version:

```sh
git tag v0.1.0
git push origin v0.1.0
```

The `--service none` flag is for development: it saves generated configuration but intentionally does not start services. It must not be used as a production deployment mode.
