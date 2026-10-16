# Rout

Create proxy nodes, relay an existing server, and manage reusable proxy exits on a VPS or NAT VPS. Install once and run `rout`; the first interactive run asks for **简体中文** or **English**. Menus, prompts and application errors use the saved language. Change it from Settings at any time, or pass `--lang en` / `--lang zh-CN` for a one-run override. Non-interactive commands such as `version` never wait for language input. Native engine/service logs remain verbatim diagnostic data.

## Install

Linux amd64 / arm64, with systemd or OpenRC. Debian, Ubuntu and Alpine are the initial targets. Root access is required to manage services. Provider-side firewall rules and NAT mappings must already allow the selected ports.

```sh
curl -fsSL https://raw.githubusercontent.com/VAR7IANT/Rout/main/install.sh -o /tmp/rout-install.sh
sudo sh /tmp/rout-install.sh
sudo rout
```

On Alpine or when already logged in as root, omit `sudo`. The installer downloads a release binary and checks SHA256 before replacing the executable. It does not create a node or change routing until you open the menu. The current installer targets `v0.2.0`; see [release instructions](#development-and-releases). Existing installations can run `sudo rout update`; updating the manager alone does not restart existing nodes.

## Three workflows

| Workflow | Input | Result |
| --- | --- | --- |
| Create nodes | One VPS/NAT selection, one base name, protocol(s), common address/TLS settings | Names such as `DMIT-LAX-VLESS`, `DMIT-LAX-AnyTLS`, `DMIT-LAX-HY2` and independent services |
| Relay a node | Existing node URI or target `host:port`, local/public ports | TCP/UDP stream forwarding with original node credentials |
| Manage exits | Add an exit directly, select protocol, enter `IP:port:username:password` | A reusable exit that can be tested, edited, deleted or assigned to multiple nodes |

Node creation supports VLESS Reality, AnyTLS Reality, Shadowsocks 2022, Hysteria2 and TUIC. Common server details and the base name are entered once per batch. Ports and authentication are generated automatically; optional manual ports and custom credentials remain available. Reality protocols share one SNI prompt. HY2/TUIC require UDP and can now generate a valid certificate/key pair automatically, or load existing PEM files.

### HY2 automatic TLS and client import

The automatic option creates a unique ECDSA certificate, including a DNS/IP SAN matching the chosen SNI, and a cryptographically random password. The `hysteria2://` link includes `insecure=1` **and** `pinSHA256` (the SHA256 of the DER certificate), following the [Hysteria URI scheme](https://v2.hysteria.network/docs/developers/URI-Scheme/). A native Hysteria client can import that URI without separate certificate files.

**Security:** self-signed share links are secure only when the importing client actually enforces `pinSHA256`. Clients that ignore it may accept arbitrary certificates because of `insecure=1`. For such clients, export the sing-box JSON configuration: it embeds the certificate as a trust anchor and does **not** disable verification. A trusted public CA certificate is the other option. Rout's own URI-to-sing-box converter refuses a pinned URI rather than silently dropping its pin; testing a pinned raw relay may require the original client. Self-signed TUIC share URIs need the certificate trusted separately; use the exported client configuration. AnyTLS Reality also requires a compatible client; exported sing-box JSON is the reference format.

Relay URI import supports `vless://`, `anytls://`, `trojan://`, SIP002 `ss://`, `hysteria2://` / `hy2://` and `tuic://`. Other services can be forwarded by entering an address and choosing TCP, UDP or both. SS plugin URIs and legacy fully Base64-encoded SS URIs are not imported in this version. A relay preserves the original SNI, keys and transport settings when generating its replacement URI. It does not deploy or modify the target server.

Proxy exit setup asks for the protocol **first**, then accepts:

```text
192.0.2.10:6719:username:password
[2001:db8::10]:6719:username:password
```

Supported exit protocols: SOCKS5 and HTTP CONNECT. Passwords can contain colons; usernames cannot. Input is hidden in interactive terminals. Exit creation requires no node and does not change any active connection. Test an exit from Exit Management, then bind it to existing or new nodes. Binding an existing node tests authentication and an actual IPv4 request through a temporary local proxy first. The IP shown is the observed exit IP, which may differ from the proxy endpoint address. Updating a used exit updates its bound nodes transactionally; renaming an exit alone does not restart nodes. An exit cannot be deleted while referenced by any node, preventing an accidental direct-IP fallback.

Proxy exits are TCP-only in this release. UDP is explicitly rejected, including with third-party SOCKS5 exits whose UDP capability has not been verified. If an exit fails, the node fails rather than falling back to the VPS IP. Existing node links remain usable after changing that node's exit.

## NAT and networking

Rout asks for VPS/NAT once at the beginning of node creation, then reuses that choice throughout the batch. NAT mode asks for the provider-assigned local port range, corresponding first public port, and allowed transport (TCP, UDP or both). It assigns available ports **only inside that range**, preserves the public/local offset, avoids reserved or occupied ports, and rejects HY2/TUIC on TCP-only mappings. SS automatically uses TCP-only or UDP-only when required by the mapping. Saved server defaults are reused as defaults for later batches and can be edited in Settings. No setting change modifies existing nodes automatically.

Rout cannot create a provider's mapping, discover assigned ports reliably, or open provider firewalls. A contiguous mapping range or a single mapped port is supported per setup; for differently mapped blocks, configure each block in a separate creation batch. NAT servers with no reachable inbound port require a reverse tunnel, outside this release.

Only traffic using the managed node is routed through its configured exit. SSH, package updates, ordinary server-side `curl` and other existing services keep their normal network path. Rout does not enable TUN, change the default route, flush firewall rules, or overwrite `/etc/sing-box`.

The selected listen port must also be allowed by the VPS/provider firewall. Rout checks local port conflicts; it does not open external firewalls automatically. A successful local node test does not prove that a public/NAT port is reachable: verify the exported link from an external client.

## Management

```sh
rout                         # Bilingual menu; saved language
rout --lang en               # English for this run
rout settings                # Language and server defaults
rout exits                   # Add/test/edit/delete/bind independent exits
rout list                    # All nodes: status, ports, exit and complete URI
rout status
rout test ID                 # Local entry → protocol → configured exit; IPv4 and IPv6 results
rout export ID               # Share URI (contains client credentials)
rout export ID client.json   # Full sing-box client config, local proxy on 127.0.0.1:2080
rout copy ID                 # Complete URI + OSC52 clipboard request on supported terminals
rout restart ID              # Restart only this node
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

Configuration and backups: `/etc/rout`. Language and server defaults: `/etc/rout/settings.json`. Pinned engine binaries: `/opt/rout/bin`. Services: `rout-<ID>`. Node Management displays every node and full share URI, with protocol, enabled/running state, local/public ports and exit information. Copy sends an OSC52 clipboard request only when explicitly selected; unsupported terminals can copy the printed link manually. Share URIs contain client credentials, so avoid sharing management screenshots publicly.

Each node/relay has its own service. Metadata-only changes (name, advertised address/port, exit label) do not restart or rewrite live node configurations. Runtime changes affect only the changed node(s); a reused exit credential change necessarily restarts its users. Each service consumes a separate engine process; size the VPS for the number of nodes you run.

Changes are locked against concurrent writers. Configuration and certificate validation happen in private staging directories before any live files or services change. Failed application restores prior state/configuration and attempts to restore only affected services; recovery errors are surfaced rather than hidden. Automatic pre-change backups and explicit backups include credentials and private keys and use mode `0600`.

### Compatibility and migration

Schema 1 and all node IDs, ports, keys, credentials, certificate contents and service names are retained. Legacy per-node `outbound` proxies are deduplicated into reusable exits **in memory on read**, using stable IDs. Merely upgrading, opening menus or changing language does not rewrite/restart existing nodes. The next successful state-changing operation saves the registry; the original outbound values are mirrored on each node so older Rout versions can still understand its runtime exit. Existing backups remain loadable. Backups include the exit registry but not machine-local language/default settings.

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

The integration suite uses local origins, test HTTP/SOCKS proxies and disposable credentials. It checks actual encrypted traffic for all five node protocols, both authenticated proxy exits, TCP/UDP forwarding, UI-driven HY2 generation, native Hysteria URI import, and rejection of a wrong certificate pin. Native-client tests use a separately checksum-pinned test binary, never installed by Rout:

```sh
sh scripts/test-native-hy2.sh /tmp/hysteria
ROUT_TEST_ENGINES=/tmp/rout-engines ROUT_TEST_HYSTERIA=/tmp/hysteria go test -race -count=1 -v ./internal/rout
```

A host permitting sing-box's Linux network discovery is required. `ROUT_SKIP_SINGBOX_RUNTIME=1` skips runtime cases if netlink is blocked; configuration checks and GOST forwarding still run. A skipped test is not a successful protocol test. Unit tests cover scripted English/Chinese UI flows, translation-catalog completeness, NAT ranges, one-time prompts/naming, standalone/shared exits, legacy backup compatibility and preflight isolation. Disposable systemd tests also compare PIDs to verify that adding a node/exit, editing metadata or restarting another node preserves unrelated running services. Alpine/OpenRC and provider-side NAT reachability still need real-host acceptance testing.

CI runs unit/race/static checks, verified-engine integration tests, actual systemd lifecycle/rollback tests and cross-compilation on every push. A successful push to `main` publishes the compiled version as a release **only after** all checks pass. An existing release is preserved. Bump `Version` and the installer's default version for a new release. Explicit version tags are also supported and must match the compiled version:

```sh
git tag v0.2.0
git push origin v0.2.0
```

The `--service none` flag is for development: it saves generated configuration but intentionally does not start services. It must not be used as a production deployment mode.
