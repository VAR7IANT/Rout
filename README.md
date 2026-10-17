# Rout

Create proxy nodes, relay existing servers and manage reusable proxy exits on a regular VPS or a NAT VPS — from one small, dependency-free binary with a bilingual terminal menu (**简体中文** / **English**).

- Five node protocols: **VLESS Reality, AnyTLS Reality, Shadowsocks 2022, Hysteria2, TUIC v5**
- TCP/UDP relays that keep the original node's credentials
- Reusable **SOCKS5 / HTTP CONNECT exits** shared by many nodes, with no direct-IP fallback
- Exact per-node **traffic accounting and hard monthly quotas** in the kernel (nftables)
- **systemd and OpenRC**, IPv4-only, IPv6-only and dual-stack hosts, NAT port ranges

## Install

Linux amd64 / arm64 with systemd (Debian, Ubuntu) or OpenRC (Alpine). Root is required to manage services. Provider firewalls and NAT mappings must already allow the ports you use.

```sh
f=$(mktemp) && curl -fsSL https://raw.githubusercontent.com/VAR7IANT/Rout/main/install.sh -o "$f" && sudo sh "$f"; rm -f "$f"
sudo rout
```

On Alpine, or when already root, omit `sudo`. The installer downloads release `v0.2.2`, checks its SHA256 before replacing the executable, installs `nftables` and enables traffic accounting for the default directories. It does not create nodes, set any limit or change the default route. `ROUT_SETUP_TRAFFIC=0` skips the accounting setup. The first interactive run asks for the language; change it later in Settings, or use `--lang en` / `--lang zh-CN` for one run.

Release binaries carry GitHub build-provenance attestations. The checksum file comes from the same release, so it proves integrity, not authenticity; to verify origin independently:

```sh
gh attestation verify rout-linux-amd64 --repo VAR7IANT/Rout
```

## Quick start

```text
sudo rout
  1  Create nodes          → server type once, a base name once, pick protocols
  2  Manage nodes          → view / add / edit / delete / restart / export links
  3  Manage exits          → add, test, edit, delete, bind exits by number
  4  Relay a node
  5  Traffic management
  6  Diagnostics
  ...
```

Creating `Tokyo` with VLESS, SS and HY2 produces `Tokyo-VLESS`, `Tokyo-SS` and `Tokyo-HY2`, each with its own service, generated credentials and a complete share link. A repeated name becomes `Tokyo-VLESS-2`. Every menu lists numbered choices; `0` always goes back (or exits).

## Supported protocols

| Protocol | Transport | TLS | Client notes |
| --- | --- | --- | --- |
| VLESS Reality (Vision) | TCP | Reality, borrowed from the SNI target | Standard `vless://` link |
| AnyTLS Reality | TCP | Reality | Needs a client with AnyTLS + Reality; the exported sing-box JSON is the reference |
| Shadowsocks 2022 (`2022-blake3-aes-128-gcm`) | TCP+UDP (or one of them on NAT) | — | SIP002 link with percent-encoded `method:key`, as SIP002 requires for AEAD-2022 |
| Hysteria2 | UDP | Self-signed (pinned) or your PEM | Link carries `insecure=1` **and** `pinSHA256`; secure only with clients that enforce the pin — otherwise use the exported JSON |
| TUIC v5 | UDP | Self-signed or your PEM | Self-signed links need the certificate trusted separately; use the exported JSON |

When a Reality protocol is selected, Rout checks from the server that the SNI target answers TLS 1.3 with a valid certificate (and HTTP/2). If the check fails, it warns you and asks before continuing. Pick a reachable, popular TLS 1.3 site that you do not control.

## NAT and VPS setup

The first creation asks once whether the machine is a regular VPS or a NAT VPS, then saves the answer. Later batches show the saved settings in one line and ask only `Use the saved server settings? y/n [y]`. Edit them under Settings → Server defaults. Changing settings never modifies existing nodes.

- **Regular VPS:** free ports are chosen automatically; manual ports are optional.
- **NAT VPS:** enter the provider-assigned local port range, the matching first public port and the allowed transport (TCP, UDP or both). Rout assigns ports **only inside the range**, keeps the public/local offset, skips occupied ports, rejects HY2/TUIC on TCP-only mappings and switches SS to the available transport. A UDP-only Shadowsocks node only carries UDP application traffic and cannot use a proxy exit.
- Public address detection queries IPv4 and IPv6 independently; IPv6-only hosts work without IPv4 and listen on `::`.

Rout cannot create provider mappings or open external firewalls. A local test does not prove the public port is reachable: verify the link from an external client.

Only traffic through a managed node uses its exit. SSH, package updates and other services keep their normal path. Rout never enables TUN, changes the default route, flushes firewall rules or touches `/etc/sing-box`.

## Exits (outbound proxies)

Manage exits → **Add**: choose SOCKS5 or HTTP CONNECT, then enter `IP:port:username:password` (IPv6: `[addr]:port:user:pass`; passwords may contain colons). Exits are listed and selected **by number**, with name, protocol, address and how many nodes use them; their stable internal IDs never need to be typed.

- **Test** shows the observed exit IP (IPv4, falling back to IPv6).
- **Bind or unbind** a node (or pick the exit while creating nodes). Binding tests the exit through a temporary local proxy first.
- **Edit** updates every bound node transactionally; renaming alone restarts nothing.
- **Delete** asks for confirmation and is refused while any node uses the exit, so nothing silently falls back to the VPS IP.

Exits are TCP-only: UDP through an exit is rejected rather than leaked.

## Node links

Manage nodes → Export links: one node's link (with an OSC52 copy request), **all links**, or a sing-box client configuration (local proxy `127.0.0.1:2080`). Selection menus show names, ports and status but never credentials. Share links contain client credentials; do not post screenshots of them.

```sh
rout export ID             # one link
rout export ID client.json # sing-box client configuration
rout export all [FILE]     # every link (file mode 0600)
rout list                  # every node with its complete link
```

## Traffic accounting, limits and monthly reset

All nodes are **unlimited by default**. With accounting installed, every listener is metered in the kernel: upload + download at the node's entry, bytes in decimal MB/GB/TB, including NAT, and counted once even when nodes share an exit. Limits are optional and per node. A finite limit is enforced by a kernel quota that drops the packet that would exceed it, including on existing connections; the monitor then stops only that node. Each node has a billing day (1–31, clamped to short months) and an IANA timezone; a new cycle restores quota-paused nodes but never manually paused ones. Unlimited nodes are never blocked by accounting faults.

**Recovery behavior (v0.2.2):**

- **Normal monitor restart or reboot:** at graceful shutdown the monitor closes the node's kernel gate *before* writing its final checkpoint ("sealed"). On start it verifies the seal and resumes automatically with exact usage and the exact remaining budget. Nothing is reset and no quota is granted.
- **Quota-exhausted nodes** stay paused across restarts until the next cycle.
- **Unexpected crash or power loss:** the last uncheckpointed seconds are unknown, so the node stays paused (fail-closed). Traffic management → **Resume with known usage** (or `rout traffic recover ID`) resumes it while keeping all known usage; the cycle stays marked as having a gap and its total is a lower bound. Alternatively confirm a reset (`y`, then `RESET`) or wait for the next cycle.

See [docs/TRAFFIC.md](docs/TRAFFIC.md) for the exact measurement points, precision and fault model. Accounting requires nftables and `CAP_NET_ADMIN`; OpenVZ and some LXC containers do not grant it. In that case Rout reports accounting as unavailable instead of showing zero, and unlimited nodes keep working.

## Certificates (HY2 / TUIC)

Automatic setup creates a self-signed ECDSA certificate valid for 10 years. Trust comes from the pinned or embedded certificate, not from its validity period. A certificate you supply as PEM files is used as-is. Validity is shown in `rout list`, `rout status`, `rout cert` and `rout doctor`, with warnings 30 days before expiry. Nothing rotates automatically, because every replacement changes what clients must trust.

```sh
rout cert                 # validity of every HY2/TUIC certificate
rout cert renew ID        # new self-signed certificate (asks first; clients must re-import)
```

The same actions are under Manage nodes → Edit node → Certificate. An expired certificate on one unchanged node no longer blocks `rout apply` for the other nodes.

## Diagnostics

`rout doctor` is read-only. It checks the OS, init system, IPv4/IPv6 routes, configuration validity, file permissions, engine binaries, generated configurations, service and port state, port conflicts, certificates, nftables, the traffic monitor and helper version, checkpoint freshness and per-node accounting state. It exits non-zero when problems are found. `rout doctor --fix` offers safe repairs (private file modes, leftover Rout metering tables, reinstalling the monitor helper), each confirmed separately.

## Commands

```sh
rout                          # interactive menu
rout list | status            # nodes with links | service state
rout doctor [--fix]           # diagnostics
rout test ID                  # local entry → protocol → exit, IPv4 and IPv6
rout export ID [FILE] | export all [FILE] | copy ID
rout restart|on|off|delete|logs ID
rout exits | settings
rout traffic                  # usage of all nodes
rout traffic show|manage|recover ID
rout traffic install          # install/update accounting (no node restarts)
rout cert [ID] | cert renew ID
rout apply                    # validate and re-apply all nodes
rout backup FILE | restore FILE
rout engines | update | uninstall | version | help
```

Global options work before or after the command: `--lang en|zh-CN`, `--home DIR`, `--bin-dir DIR`. `--service none` is for development only.

## Files, services and security

- Configuration `/etc/rout` (0700; files 0600): `state.json`, `traffic.json`, `settings.json` (language, server defaults, `backup_keep`).
- Automatic pre-change backups in `/etc/rout/backups`, keeping the newest **20** by default (configurable 1–1000 in Settings). The newest backup is never removed, and explicit `rout backup` files are never pruned. Backups contain credentials and private keys.
- Pinned engines in `/opt/rout/bin`: sing-box v1.14.3 and GOST v3.3.0, each verified by SHA256 (`internal/rout/engines.lock.json`). Hosts without glibc (Alpine) get sing-box's static musl build; an installed engine that cannot execute is replaced automatically.
- One service per node, `rout-<ID>`. Metadata edits (name, advertised address/port, exit label) do not restart nodes; runtime edits restart only the changed node. A start counts as successful only if the process stays up and its ports are listening.
- systemd units restrict engines with a capability bounding set (`CAP_NET_BIND_SERVICE`; HY2/TUIC also keep `CAP_NET_ADMIN` for QUIC socket buffers), `ProtectSystem=strict`, kernel/cgroup/clock protections, `RestrictNamespaces` and `RestrictAddressFamilies`. Engines therefore cannot change Rout's quota tables. New units apply on the next change or `rout apply`.
- OpenRC services use `supervise-daemon` with bounded respawns and private logs in `/var/log/rout-<ID>.log`, rotated at 5 MB.
- Changes are serialized by file locks with bounded waits, validated in private staging directories and rolled back on failure.

## Upgrading and rollback

```sh
sudo rout update      # refuses downgrades; keeps /usr/local/bin/rout.previous
```

`update` verifies the release binary and checks that it reports the expected version. It then refreshes the traffic monitor helper. The monitor restarts once: limited nodes are sealed and resume automatically, and unlimited nodes are not restarted. Existing nodes keep their IDs, ports, keys, credentials, certificates and usage. Run `rout apply` when you want existing services to pick up new unit hardening. **Coming from v0.2.1:** the old updater does not refresh the helper, so run `sudo rout traffic install` right after `rout update` (the installer script does it automatically). Roll back with `sudo mv /usr/local/bin/rout.previous /usr/local/bin/rout`. Read [docs/UPGRADING.md](docs/UPGRADING.md) for compatibility details.

## Compatibility

| Environment | Status |
| --- | --- |
| Debian / Ubuntu, systemd | Supported; CI runs real systemd lifecycle, sandbox and quota-guard tests |
| Alpine, OpenRC | Supported; CI runs an OpenRC lifecycle test in an Alpine container |
| IPv4-only / IPv6-only / dual stack | Supported; detection and tests do not require IPv4 |
| NAT VPS with port ranges | Supported; provider mappings are entered, not discovered |
| OpenVZ / restricted LXC | Proxies work; accounting needs nftables + `CAP_NET_ADMIN` |

Real-host acceptance items outside CI: provider NAT reachability, physical reboots and power loss, NIC offload and sustained high rates. Each node table adds a small per-packet cost; Rout is tuned for tens of nodes per host.

## Development and releases

Go 1.23+ (CI builds with the current stable Go), standard library only. Rout is original code, with workflow inspiration from [singbox-deploy](https://github.com/caigouzi121380/singbox-deploy). Forwarding and proxy engines are separately downloaded [GOST](https://github.com/go-gost/gost) and [sing-box](https://github.com/SagerNet/sing-box), under their own licenses.

```sh
go test -race ./... && go vet ./...
go build -o rout ./cmd/rout
./rout --home /tmp/rout-state --bin-dir /tmp/rout-engines --service none engines
ROUT_TEST_ENGINES=/tmp/rout-engines go test -race -count=1 -v ./internal/rout
```

Test layers: unit and simulated tests (fake meter, scripted English/Chinese UI) always run. Engine integration tests send real encrypted traffic for all five protocols, both exit types and TCP/UDP relays (`ROUT_TEST_ENGINES`). Kernel tests run real nftables in a disposable network namespace (`ROUT_TEST_NFT=1`), covering seal/reboot/crash recovery, batching, orphan cleanup, multiple limited nodes, and upgrade/rollback against the published v0.2.1 binary. Init tests need a disposable root host: systemd (`ROUT_TEST_SYSTEMD=1`, `ROUT_TEST_TRAFFIC_SYSTEMD=1`) or OpenRC (`ROUT_TEST_OPENRC=1`). Native Hysteria URI tests use `scripts/test-native-hy2.sh`.

CI runs everything above plus `govulncheck` and cross-compilation on every push. **Releases are published only from an explicit version tag** that matches the compiled version and `install.sh`; pushes to `main` never publish.

```sh
git tag v0.2.2 && git push origin v0.2.2
```
