# Snell

Rout creates and manages **Snell** nodes natively, next to VLESS Reality, AnyTLS, Shadowsocks 2022, Hysteria2 and TUIC. Snell is [Surge](https://nssurge.com)'s own proxy protocol, so the client is **Surge** (iOS, Mac, tvOS). Nothing else is needed: no separate Snell tool, script or database. Rout downloads the official `snell-server`, writes its configuration, runs it as one systemd (or OpenRC) service per node, meters its traffic and prints the Surge configuration.

Contents: [Versions](#versions-and-engines) · [Create](#create-a-node) · [Surge configuration](#the-surge-configuration) · [Manage](#manage-a-node) · [Subscriptions](#subscriptions) · [Traffic and quotas](#traffic-and-quotas) · [IPv4, IPv6 and NAT](#ipv4-ipv6-and-nat) · [Engines](#engines-install-upgrade-rollback-uninstall) · [Limits](#what-snell-nodes-do-not-do) · [Troubleshooting](#troubleshooting) · [Verification status](#verification-status) · [Surge iOS acceptance](#surge-ios-acceptance-checklist)

## Versions and engines

Rout offers exactly the versions Surge publishes, each on its own pinned engine, so a v5 node and a v6 node can run side by side.

| | Snell v5 | Snell v6 |
| --- | --- | --- |
| Create menu | **Snell v5** | **Snell v6 (beta)** |
| Node name suffix | `Tokyo-Snell` | `Tokyo-Snell6` |
| Pinned engine | `snell-v5` = Snell server **v5.0.1** | `snell-v6` = Snell server **v6.0.0** |
| Status (vendor) | Stable. v5.0.1 fixes a rare crash. | **Beta.** The vendor may make incompatible protocol changes during the beta: keep server and Surge on the latest beta. |
| Build | Static; also runs on Alpine/musl | **glibc only** (no musl build exists) |
| Architectures | amd64, arm64 (Surge calls it `aarch64`) | amd64, arm64 |
| Surge client line | `version=5` | `version=6` (the Surge manual lists iOS 5.20.0+ / Mac 6.7.0+) |
| Extra | Dynamic record sizing; *QUIC Proxy Mode* over UDP on the node's port | PSK-derived traffic profile per deployment; `dns-ip-preference`; no QUIC Proxy Mode; no obfuscation |

Sources: the vendor's [Snell release notes](https://kb.nssurge.com/surge-knowledge-base/release-notes/snell), the [Snell v6 announcement](https://nssurge.com/blog/snell-v6/) and the [Surge Snell policy manual](https://manual.nssurge.com/policies/snell.html). Downloads come only from `https://dl.nssurge.com/snell/` and are pinned by SHA-256 in `internal/rout/engines.lock.json`:

| Engine | Asset | SHA-256 |
| --- | --- | --- |
| snell-v5 | `snell-server-v5.0.1-linux-amd64.zip` | `9bea1c2b9e35b73b31634856c04d18c393072b9e5dcde6a32781d8b8f908c539` |
| snell-v5 | `snell-server-v5.0.1-linux-aarch64.zip` | `2f178bf5ac468ce1a130454efa40a0603fbbe4e47ecc4880a989f4abc7f824cf` |
| snell-v6 | `snell-server-v6.0.0-linux-amd64.zip` | `8a9c4463ca87cfa5eaa37c6af0d37ab93ea275aa12391985bb2a375ca3abd7f2` |
| snell-v6 | `snell-server-v6.0.0-linux-aarch64.zip` | `a0b2915cbc77dc3baf8fa069e741c20808d8a10c3a8a93e709a0a580645c3bd7` |

The vendor publishes no checksums of its own; these digests were taken from the official URLs and are what Rout enforces. v4 and older are not offered: Surge's v5 server is backward compatible with v4 *clients*, and a v1-v4 server adds nothing Rout needs. Platforms without an official build (other CPU architectures, v6 on musl) are refused with a clear message; no other file is ever substituted.

## Create a node

*Quick create node* (menu 1) → type the base name once → pick **Snell v5** (6) and/or **Snell v6 (beta)** (7), alone or together with other protocols → choose the listening address (IPv4 / dual stack, see below) → confirm. Rout then

1. generates a random 32-character PSK (the length the vendor's own wizard recommends) and picks a free port, or uses the port you chose under *Change ports* (TCP, and for v5 also UDP, are checked);
2. downloads and verifies the engine on first use;
3. writes `/etc/rout/profiles/<id>/snell-server.conf` (mode 0600), installs the unit `rout-<id>.service`, enables and starts it, and waits until the engine really listens and stays up;
4. prints the **Surge configuration** (and, on a dual-stack host, the same node for the other address family).

*Advanced options → Custom credentials* lets you type your own PSK (12-255 characters: letters, digits and `. _ ~ + -`; anything that would change the meaning of an INI or Surge line is refused). If a batch is created with an outbound proxy, the Snell nodes in it connect directly and Rout says so (see [limits](#what-snell-nodes-do-not-do)). The same flow exists in the web panel (*Nodes → New nodes*) and as `POST /api/nodes` with the protocol ids `snell` and `snell6`.

## The Surge configuration

Snell has no share link. Rout prints the line you paste into the `[Proxy]` section of a Surge profile, written exactly as the Surge manual documents it (`Name = snell, <host>, <port>, psk=<psk>, version=<n>`):

```text
Tokyo-Snell = snell, 203.0.113.10, 34567, psk=Xy3...32chars...kP9, version=5
Tokyo-Snell6 = snell, 203.0.113.10, 34568, psk=Qw8...32chars...mL2, version=6
Tokyo-Snell = snell, 2001:db8::7, 34567, psk=Xy3...32chars...kP9, version=5      # same node, IPv6
```

* `version` is always written; Surge assumes the legacy v1 protocol when it is missing, and it must equal the server version. v5's server also accepts `version=4` clients.
* The host is the node's **public** address and the port is the **public** port. On a NAT host that is the provider's mapped port, never the internal listening port. An IPv6 literal is written without brackets (the field is comma separated).
* Rout does not add optional Surge parameters. You may append the vendor-documented ones yourself: `reuse=true` (connection reuse, v4+), `tfo=true`, `udp-port=<n>` (when the server's UDP port differs). `obfs` does not exist in v6; `mode` is `default` and Rout never changes it (clients must match the server's mode).
* Names are made safe for Surge (`=` and `,` replaced, leading `#`, `;`, `[` removed).
* Copy it again at any time: *Manage nodes → node* shows it, *Copy link or export* prints it, `rout copy ID` and `rout export ID` print it, `rout export all [FILE]` lists every node (Snell lines included), the web panel's *Share link* dialog shows it.

Rout cannot test the Snell handshake itself (there is no Snell client outside Surge). `rout test ID` checks the layers it can (the service, the listening sockets) and says explicitly that the handshake must be tried in Surge.

## Manage a node

*Manage nodes → choose a node → Edit* offers the usual entries (the *Choose outbound proxy* entry is hidden for Snell, which has none) and appends two Snell-only entries:

| Action | What it does |
| --- | --- |
| Rename | Display name only; the service and the traffic table use the stable ID, so nothing restarts for a rename |
| Change port or public address | Listening port (conflicts checked on TCP, and UDP for v5) or the public address/port clients use (NAT) |
| Test connection | Layered local diagnosis; the handshake needs Surge (see above) |
| View logs | `journalctl -u rout-<id>` |
| Traffic and limits | Usage, monthly quota, reset; see below |
| Reset credentials | New random PSK, same version; old Surge lines stop working |
| Outbound IP family | Maps to the engine's only setting, see below |
| **Change listen address** | IPv4 (`0.0.0.0`), dual stack (`::`), or one address of this host |
| **Set PSK** | Type your own PSK |

Start, stop (*Disable*), restart and delete work as for every node. Deleting removes the unit, the profile directory, the traffic table and the node's subscription membership; other nodes, including other Snell nodes, are never touched. Every change is validated, written to a staging directory first, applied, health-checked and **rolled back to the previous files and service state** if the engine does not start.

**Outbound IP family.** Snell has one setting for this, written for you:

| Rout policy | Snell v5 (`ipv6 = …`) | Snell v6 (`dns-ip-preference = …`) |
| --- | --- | --- |
| Auto (default) | `true` | `default` |
| IPv4 first | not available | `prefer-ipv4` |
| IPv6 first | not available | `prefer-ipv6` |
| IPv4 only | `false` | `ipv4-only` |
| IPv6 only | not available | `ipv6-only` |

Unlike a sing-box node, this is a preference over DNS answers. The vendor documents no rule for destinations that are already IP addresses, so Rout does not report the policy as *enforced* for Snell and says so in the menu, panel and diagnostics.

## Subscriptions

Snell nodes can be members of any subscription. Because Snell has no link, only one format can carry them:

```text
https://sub.example.com/s/TOKEN?format=surge
```

It returns the Surge lines of the subscription's Snell nodes (saved order, one per line, `text/plain`), ready for a Surge external policy group (`policy-path`) or to paste. It always reflects the current node: a new PSK, port, public address or name appears on the next fetch, a disabled node is skipped, a deleted node leaves the subscription. Other nodes in the same subscription are left out of the Surge list with a skipped-node count (`X-Rout-Skipped-Nodes`); a subscription with no Snell node answers `503`.

The default (Base64) and `?format=mihomo|clash` outputs are unchanged and simply skip Snell nodes with a diagnostic; Rout never turns a Snell node into a VLESS, Shadowsocks or other node. (Mihomo documents Snell v1-v5 but not v6; Rout does not export Snell to Mihomo.) Details: [SUBSCRIPTIONS.md](SUBSCRIPTIONS.md).

## Traffic and quotas

Snell nodes use the same kernel accounting as every other node (one nftables table per node, hard quota objects, kernel-enforced cut-off, recovery after reboot; see [TRAFFIC.md](TRAFFIC.md)). Upload and download are counted separately per node; two Snell nodes never share a counter. Metering covers the node's TCP port and, for **v5, also UDP on the same port** because v5's QUIC Proxy Mode relays QUIC over UDP there; counting it keeps a quota hard. A node over its quota is stopped by Rout's monitor and its traffic is dropped by the kernel rule; limits and resets are set under *Traffic and limits*. This is the same mechanism and the same limits as for other protocols: Rout does not describe polling as a hard quota.

## IPv4, IPv6 and NAT

| Situation | Behaviour |
| --- | --- |
| IPv4-only VPS | `0.0.0.0`, v5 `listen = 0.0.0.0:PORT` |
| Dual stack | **IPv4** or **dual stack** (`::`) is offered, with a probe that proves `::` also accepts IPv4. v5 writes `::0:PORT`, v6 `[::]:PORT` |
| IPv6-only VPS | `::`; with no IPv4 on the host a wildcard IPv6 socket is IPv6-only by necessity |
| "IPv6 only" on a dual-stack host | **Not offered for Snell**: `snell-server` has no IPV6_V6ONLY switch and Rout will not fake exclusivity with a firewall rule (sing-box nodes can) |
| A specific address | *Change listen address → Specific address of this host*; the address must belong to a local interface |
| NAT VPS | The listening port is the internal one; the Surge line carries the provider's mapped public port. NAT mappings of older versions keep working; a TCP-only mapping is accepted because Snell needs only TCP |

Listening address and the address given to clients are separate settings: the public address is never rewritten when you change the listener, and a combination that makes it unreachable is refused. **v5 on a TCP-only NAT:** QUIC Proxy Mode needs UDP; Rout prints a note to set `version=4` in Surge, which the vendor documents as the way to avoid QUIC Proxy Mode (a v5 server accepts v4 clients).

## Engines: install, upgrade, rollback, uninstall

* **Install.** On first use of a version Rout takes the host architecture (`amd64`/`arm64`) and C library, streams the vendor zip to disk (never into memory), verifies the pinned SHA-256 **before** opening it, extracts only the member `snell-server` by base name (sizes and CRC checked), proves the staged file executes (`--version`) and renames it into place atomically. One installer runs at a time (file lock). Engines of other protocols are never touched; each Snell version has its own file (`/opt/rout/bin/snell-v5-v5.0.1`, `snell-v6-v6.0.0`).
* **Upgrade.** A new Rout release pins newer engines. The new file is installed next to the old one; units are re-rendered by `rout apply` (or the next change of a node) and each node is restarted and health-checked.
* **Rollback.** A failed download, digest mismatch, corrupt archive or engine that cannot run leaves everything as it was; a node whose new engine does not start is restored to its previous files and service state by the same transaction as any other change.
* **Uninstall.** `rout uninstall` removes services, kernel tables, `/etc/rout` and `/opt/rout`, which includes the Snell engines. Deleting one node never deletes an engine another node uses.
* **Idempotence.** Installing, applying and deleting can be repeated safely.
* **Unsupported platforms** (32-bit or other CPUs; Snell v6 on Alpine) fail with an explicit message.

## What Snell nodes do not do

Rout does not invent features the engine lacks:

* **No outbound proxy / exit.** `snell-server` has no upstream-proxy feature, so a Snell node always connects directly. Binding one to an exit is refused (and skipped with a warning in batch flows).
* **No AI Smart Routing.** That is a sing-box routing feature; Snell nodes are listed as not eligible. AI routing and exits for other nodes are unchanged.
* **No sing-box client config** and no standard share link. Relays can forward to a Snell node's port as plain TCP, but the Surge line must then be edited by hand to the relay's address.
* **No TLS/Reality/certificates.** Snell has its own encryption; the vendor notes it deliberately omits forward secrecy and replay protection for performance and recommends a TLS-based protocol if maximum security is the goal. Use a random PSK (Rout's default).
* **Logging.** Rout runs `snell-server` at its default log level; the vendor's server can log per-connection lines. Check `journalctl -u rout-ID` on your host and rotate or restrict journal retention if that matters to you.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| *Node created but Surge cannot connect* | The Surge `version` must match the server (5 or 6). PSK copied exactly. Provider firewall / NAT mapping for the **public** port (TCP). Server and Surge on compatible v6 betas. |
| `... 启动失败 / failed to start` | `rout logs ID` (`journalctl -u rout-ID`). Rout rolled the change back; the log shows the engine's own error. Run `rout doctor`. |
| *Port already in use* | Rout checks TCP (and UDP for v5) before saving; pick another port under *Change ports*. |
| *Snell v6 … glibc … Alpine* | The vendor ships v6 for glibc only. Use Snell v5 (static) or a glibc distribution. |
| *Download or SHA-256 failed* | Nothing was installed. Check the network to `dl.nssurge.com` and retry; a persistent mismatch means the vendor file changed and a Rout update is needed: do not bypass it. |
| `rout doctor` says the configuration differs from state | Run `rout apply` (re-renders `snell-server.conf` from the state file). |
| *v5 QUIC traffic fails on NAT* | The NAT only maps TCP; set `version=4` in Surge. |
| *IPv6 line does not connect* | The node must listen on `::` (dual stack) or an IPv6 address; the public IPv6 address must reach the host; try the IPv4 line to separate the causes. |
| *Quota reached* | *Traffic and limits → reset*, or wait for the billing day; the node resumes automatically. |
| `rout test` says the handshake cannot be verified | Expected: test the node in Surge (acceptance steps below). |

## Verification status

**Automated (always run, `go test ./...`):** configuration rendering for both versions and every listening / outbound-family variant, with a check that only documented keys are written and that tampered files are detected; PSK generation and validation; version/engine selection and the v5 vs v6 UDP rules; Surge line syntax (IPv4, IPv6, domain, name sanitising); a multi-instance lifecycle (create, change port / PSK / listen, stop/start, delete) proving isolation of files, services and ports, with a Shadowsocks node unchanged beside them; port conflicts against TCP and UDP nodes and against sockets that are really bound; NAT mapping; systemd and OpenRC definitions; per-node nftables rules; refusal of outbound proxies, AI routing and Mihomo export; Surge subscription output and its behaviour across node edits, renames, disable and delete; the create and edit menus (interactive scripts); the web API; state round trip and backup/restore; the pinned engine table, zip install with local TLS server, digest mismatch, corrupt, lying, symlink and missing-member archives, previous-engine preservation, musl/arch refusal; English and Traditional Chinese catalog coverage. The existing suite for every other protocol passes unchanged.

**CI with the real engines (Linux, `ROUT_TEST_ENGINES`):** `TestIntegrationSnellRealEngineAcceptsRoutConfiguration` downloads the pinned official engines through Rout's own installer, runs `--version`, starts `snell-server -c` on the configuration Rout writes (IPv4 wildcard and loopback, dual stack and IPv6 loopback where available, IPv4-only egress, all five v6 preferences) and checks it listens and keeps running.

**Not verified (no hardware or client available here; do these before relying on it):**

* a real VPS, a NAT VPS and an arm64 host running the engines under the real systemd unit (sandbox options such as `ProtectSystem=strict` were not exercised against `snell-server`);
* Surge iOS (or any Surge) actually connecting, including IPv6 profile lines, `version=5` and `version=6` against the pinned servers, and UDP/QUIC behaviour; the Snell handshake and traffic are never exercised by Rout's tests because no Snell client exists outside Surge;
* the v5 listen syntax for a **specific IPv6 address** (`ADDR:PORT` without brackets, as for the documented `::0:PORT`); v5's `--help` could not be read (the binary is packed), the v5 keys `listen`, `psk`, `ipv6` follow the vendor wizard's output and are checked only by the CI engine test;
* whether the v5 server opens UDP on its port by default (the vendor says QUIC Proxy Mode needs a UDP port); Rout reserves and meters it either way.

## Surge iOS acceptance checklist

Do this once on a fresh server before trusting a release:

1. Install Rout, run `sudo rout`, choose *Quick create node*, name it `Test`, select **Snell v5** (and **Snell v6 (beta)** if your Surge supports it), confirm. The Surge line(s) are printed.
2. In Surge iOS: *Profile → Edit → [Proxy]* (text mode), paste the line, save, add the node to a policy group (or use *Surge → Proxy Policy*). Check that `version=` is 5 (or 6).
3. Select the policy, open the policy's *Test* (latency) and visit an IP echo site (`https://ifconfig.me`): the address must be the **server's**, not your phone's.
4. Dual stack: paste the IPv6 line and repeat. NAT: confirm the line carries the **public** port.
5. On the server: `rout` → *Manage nodes* → the node: *Traffic and limits* shows upload/download growing. Set a small limit, exceed it, confirm the node stops and Surge fails; reset and confirm it resumes.
6. *Edit → Set PSK*: the old Surge line must fail, the new line must work. *Edit → Change port*: same.
7. Subscription: *Subscriptions* → create one with the node, copy `…/s/TOKEN?format=surge`, create a Surge external policy group with `policy-path=` that URL, refresh, confirm the node appears and connects; change the PSK on the server and confirm the next refresh carries the new one.
8. `rout restart ID`, `systemctl restart rout-ID`, then reboot the server: the node comes back by itself.
9. Delete the node; `systemctl list-units 'rout-*'`, `/etc/rout/profiles` and `nft list tables` must show nothing left for it.
