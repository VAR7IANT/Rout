# Rout

Create proxy nodes, relay traffic to this or another server and manage reusable outbound proxies on IPv4-only, IPv6-only and dual-stack VPS hosts — from one small, dependency-free binary with a bilingual terminal menu (**简体中文** / **English**).

- Five node protocols: **VLESS Reality, AnyTLS Reality, Shadowsocks 2022, Hysteria2, TUIC v5**
- Guided TCP/UDP relays to a service on this server or to a remote server, with a full path preview, loop checks and the original node's credentials kept
- Reusable **SOCKS5 / HTTP / certificate-verified HTTPS CONNECT outbound proxies** shared by many nodes, with no silent direct-IP fallback
- Exact per-node **traffic accounting and hard monthly quotas** in the kernel (nftables)
- **systemd and OpenRC**, IPv4-only, IPv6-only and dual-stack hosts; existing NAT-VPS mappings from older versions keep working
- Low-memory friendly: engines are streamed to disk and verified incrementally, never held in memory (see [Low-memory installation](#low-memory-installation))

## Install

Linux amd64 / arm64 with systemd (Debian, Ubuntu) or OpenRC (Alpine). Root is required to manage services. Provider firewalls and NAT mappings must already allow the ports you use.

```sh
f=$(mktemp) && curl -fsSL https://raw.githubusercontent.com/VAR7IANT/Rout/main/install.sh -o "$f" && sudo sh "$f"; rm -f "$f"
sudo rout
```

On Alpine, or when already root, omit `sudo`. The installer downloads release `v0.3.6` (candidate; installation from main will fail safely until publication), checks its SHA256 before replacing the executable, installs `nftables` and enables traffic accounting for the default directories. It does not create nodes, set any limit or change the default route. `ROUT_SETUP_TRAFFIC=0` skips the accounting setup. The first interactive run asks for the language; change it later in Settings, or use `--lang en` / `--lang zh-CN` for one run.

Release binaries carry GitHub build-provenance attestations. The checksum file comes from the same release, so it proves integrity, not authenticity; to verify origin independently:

```sh
gh attestation verify rout-linux-amd64 --repo VAR7IANT/Rout
```

## Quick start

```text
sudo rout
Rout 0.3.6
  Nodes: 4 · Relays: 1 · Running: 5 · AI routing: enabled (2 inbounds)
  1  Quick create node     → the guided node creation, straight from the main menu
  2  Manage nodes          → pick a node: its connection link is shown at once; edit / delete / copy / enable / restart
                             n new node · l all links · t traffic and limits
  3  AI Smart Routing      → send AI services to a chosen exit, for selected inbound nodes only
  4  Port forwarding       → relays: view / create / edit / test / delete
  5  Outbound proxies      → numbered list incl. Direct connection; create / edit / test / delete / assign to nodes
  6  Service & system      → services · diagnostics · updates · settings (language, server address, backups, uninstall)
  7  Subscriptions           → selected-node subscriptions · HTTPS deployment · diagnostics
  0  Quit
```

Earlier releases had eight top-level entries. *Traffic and limits* moved into Manage nodes (`t`); *Services*, *Diagnostics*, *Updates* and *Settings* moved under **Service & system**; the separate *view*, *edit*, *delete*, *restart* and *connection links* pickers of Manage nodes became one list where you choose a node first. Nothing was removed, and every `rout` command works as before.

The interactive menu opens with a ROUT banner once per session: the logo in a blue gradient on 256-colour terminals, with "Support by VAR7IANT" and the running version centered beneath it, or a one-line title on terminals narrower than 39 columns. It is never printed for commands, pipes or scripts, and `NO_COLOR` or `TERM=dumb` disables all colour.

**Quick create node** (1) and **New node** inside Manage nodes (`n`) run the same code, so defaults, validation and port checks are identical; `0` at the name or protocol prompt, or *Cancel* at the confirmation, creates nothing. The connection links are printed as soon as the node exists.

Creating a node takes one pass: Rout detects the server address, you type the base name once and pick one or more protocols, ports and credentials are generated automatically, and a single confirmation lists every node with its port and address before anything is written. The confirmation also offers *Change ports* (checked for TCP and UDP conflicts) and *Advanced options* (custom credentials, Reality SNI, an existing PEM certificate). Pressing Enter at every prompt creates one VLESS node named `Rout-VLESS`.

Creating `Tokyo` with VLESS, SS and HY2 produces `Tokyo-VLESS`, `Tokyo-SS` and `Tokyo-HY2`, each with its own service, generated credentials and a complete share link. A repeated name becomes `Tokyo-VLESS-2`. Every menu lists numbered choices: `0` or `b` goes back and `q` quits Rout from any menu. Answers are case-insensitive (`y`, `Y`, `yes`, `YES`; full-width input works too). Enter takes the default shown in capitals: `[Y/n]` for ordinary confirmations, `[y/N]` for deletions. Irreversible actions (manual traffic reset, uninstall) require typing the word shown, such as `reset`.

## Supported protocols

| Protocol | Transport | TLS | Client notes |
| --- | --- | --- | --- |
| VLESS Reality (Vision) | TCP | Reality, borrowed from the SNI target | Standard `vless://` link |
| AnyTLS Reality | TCP | Reality | Needs a client with AnyTLS + Reality; the exported sing-box JSON is the reference |
| Shadowsocks 2022 (`2022-blake3-aes-128-gcm`) | TCP+UDP (or one of them on a legacy NAT mapping) | — | SIP002 link with percent-encoded `method:key`, as SIP002 requires for AEAD-2022 |
| Hysteria2 | UDP | Self-signed (pinned) or your PEM | Link carries `insecure=1` **and** `pinSHA256`; secure only with clients that enforce the pin — otherwise use the exported JSON |
| TUIC v5 | UDP | Self-signed or your PEM | Self-signed links need the certificate trusted separately; use the exported JSON |

When a Reality protocol is selected, Rout checks from the server that the SNI target answers TLS 1.3 with a valid certificate (and HTTP/2). If the check fails, it warns you and asks before continuing. Pick a reachable, popular TLS 1.3 site that you do not control.

## Server address, IPv4 and IPv6

There is no server-type question. Every new node and relay behaves like a regular VPS: the **public port equals the listening port**, a free port is chosen automatically (TCP and UDP are both checked) and you may type your own, which is checked before anything is saved.

On first use Rout detects the server's public addresses and saves the result (Settings → Server address repeats the detection or lets you type an IP or domain). Detection asks an echo service only for address families the host plausibly has, falls back to the interface addresses when the service is unreachable, and never accepts a link-local (`fe80::`), unique-local (`fc00::/7`), private, CGNAT or loopback address as a public address.

| Host | What Rout does |
| --- | --- |
| IPv4-only | Uses the IPv4 address; listens on `0.0.0.0`. No question is asked. |
| IPv6-only | Uses the IPv6 address (no IPv4 needed); listens on `::`. No question is asked. |
| Dual-stack | Asks once which address clients should connect to — **IPv4 (default)** or IPv6 — and remembers the answer. |
| Nothing detectable | Asks for an IP or domain; unspecified, multicast and link-local addresses are refused. |

**One listener, two families.** On a dual-stack host Rout listens on `::` only after proving, with a real connection, that a `[::]` socket also accepts IPv4 (the engines are Go programs, which clear `IPV6_V6ONLY` themselves, so `net.ipv6.bindv6only` does not matter; `disable_ipv6=1` or a kernel that refuses IPv4-mapped sockets does, and then Rout keeps `0.0.0.0`). The same node, port and credentials then serve both families, so nothing is duplicated, and Rout prints a second link for the other address:

```text
vless://…@203.0.113.10:34567?…#Tokyo-VLESS
Same node, other address: IPv6
vless://…@[2001:db8::7]:34567?…#Tokyo-VLESS
```

The second link is also shown by *Copy link*, *Export all links* and `rout list`. IPv6 literals are always bracketed in links and `host:port` fields, relay destinations accept `2001:db8::1`, `[2001:db8::1]:443` or a pasted IPv6 share link, and the same IPv6 address written differently (`2001:DB8:0::1`) is recognised in loop checks. Choosing an IPv6 public address for a node that listens on IPv4 only offers to switch it to `::` (this restarts only that node).

### Legacy NAT-VPS mappings

Hosts set up with v0.3.0 or earlier in NAT mode keep working. Nothing is migrated or rewritten: the saved internal range, public offset and allowed networks stay in `settings.json`, existing NAT nodes and relays keep their ports, and new entries on such a host keep following the saved mapping (a notice says so) because a regular-VPS port would be unreachable there. Editing an existing NAT node or relay still asks for the provider-mapped public port. To start using regular-VPS behavior for new entries, choose Settings → Server address → *Switch to a regular VPS*; this asks for confirmation, changes only the saved default and leaves existing NAT entries as they are. There is no menu to create a new NAT mapping.

Rout cannot create provider mappings or open external firewalls. A local test does not prove the public port is reachable: verify the link from an external client.

Only traffic through a managed node uses its outbound proxy. SSH, package updates and other services keep their normal path. Rout never enables TUN, changes the default route, flushes firewall rules or touches `/etc/sing-box`.

## Relays

Relays → **Create relay** walks through four steps and shows the whole path before anything changes:

1. **Where the traffic goes:** *Local machine* (a service on this server) or *Remote relay server* (another server). The last choice is remembered.
2. **Entry on the current server:** Rout uses the saved server address and shows the planned listening address, a free listening port and the public entry once; press Enter to use them, or answer `n` to choose the port yourself (TCP and UDP availability is checked). The listening address is derived from the host (`0.0.0.0`, or `::` for IPv6 and dual-stack) and is never the public address. The public port equals the listening port. (A legacy NAT host still asks for the provider-mapped public port.)
3. **Destination:** local relays default to `127.0.0.1` and list this server's nodes by listening port. Remote relays require an explicit host (IPv4, IPv6 without brackets, or a domain) and port, or a pasted share link; the current server's public IP is never filled in.
4. **Transport:** TCP, UDP or TCP+UDP, explained in the menu (limited to what the saved mapping allows on a legacy NAT host).

```text
Client → 203.0.113.10:40005 (public entry) → 0.0.0.0:20005 (listening) → 198.51.100.7:8443 (destination) · UDP
```

Checks before saving: address and port validity, port conflicts (TCP and UDP separately), and forwarding loops (the relay's own listening port or public entry, or a chain of local relays leading back to it). Forwarding to another port on the same server is allowed, and a destination that merely shares the server's public IP is not treated as a loop: on NAT VPS hosts that IP is shared. When the destination is the public entry of a node on this server, Rout offers to switch to `127.0.0.1:<listening port>` instead, because many networks cannot hairpin (connect to their own public address). Reachability: a local destination is checked for a listening socket; a remote TCP destination gets a real connection attempt, which proves the port is reachable, not that the proxy protocol works. UDP has no handshake and is never reported as verified.

After saving, Rout prints the client endpoint and, when the destination is a known node or a pasted link, a share link rewritten to the relay entry. **Test relay** repeats the checks and can run a full protocol test through the relay. **Edit relay** changes destination, entry, transport, name or state; **Delete relay** defaults to No. Relays created by older versions keep working; their destination type is inferred.

## Outbound proxies

Outbound proxies decide how a node reaches the internet. **Direct connection** (no proxy) is built in. Relays have no outbound proxy: they forward traffic unchanged to their destination.

Outbound proxies → **Create**: choose SOCKS5, HTTP CONNECT or HTTPS CONNECT (certificate verification), then enter `IP:port:username:password` (IPv6: `[addr]:port:user:pass`; passwords may contain colons). Proxies are listed and selected **by number** (`Name — PROTOCOL — host:port — usage`), with Direct connection offered as the last choice. Their stable internal IDs never change and never need to be typed.

- **Test** shows the observed outgoing IP (IPv4, falling back to IPv6).
- **Assign to nodes** changes only the nodes you pick, in one transaction, after testing the proxy once. Nodes that cannot use a proxy (UDP-only Shadowsocks) are skipped with the reason. You can also pick the outbound while creating nodes.
- **Edit** updates every node using the proxy transactionally; renaming alone restarts nothing.
- **Delete** is refused while any node uses the proxy, and names those nodes, so nothing silently falls back to the VPS IP.

Outbound proxies carry TCP only: UDP through a proxy is rejected rather than leaked. **SOCKS5 and HTTP CONNECT are unencrypted between the VPS and proxy, including proxy credentials.** HTTPS CONNECT verifies the proxy certificate using the system CA store and hostname, with no plaintext retry. Old entries retain their transport; migration is explicit. See [transport security, SSH tunnel setup and VPS acceptance](docs/AI_ROUTING.md).

## Node links

Manage nodes → choose a node: the detail view shows protocol, address, port, status and outbound, and prints the complete link (plus the other address family on a dual-stack host) before any further choice. *Copy link or export client configuration* repeats it with an OSC52 copy request and can save a sing-box client configuration (local proxy `127.0.0.1:2080`); `l` in the node list prints **all links**. Lists show names, ports and status but never credentials. Share links contain client credentials; do not post screenshots of them.

```sh
rout export ID             # one link
rout export ID client.json # sing-box client configuration
rout export all [FILE]     # every link (file mode 0600)
rout list                  # every node with its complete link
```

## AI Smart Routing

Server-side routing of AI services, with no client configuration. For the inbound nodes you select, connections to AI domains leave through a chosen **AI exit** (for example a verified HTTPS CONNECT proxy or SSH-tunneled SOCKS5 proxy in Canada); everything else keeps the route the node already had.

```text
Client → US VPS · Rout inbound ──┬─ AI domains ──→ AI exit (outbound proxy)
                                 └─ everything else → the node's original exit
```

Main menu → **AI Smart Routing**: *Enable / Disable*, *Select inbound nodes*, *Select AI exit*, *View AI rules*, *Test configuration*, *Status and diagnostics*, *Apply changes*. Also `rout ai [status|test|apply]`.

- **The AI exit is an existing outbound proxy** (Outbound proxies menu; SOCKS5, HTTP or HTTPS). No address is hard-coded. An exit that points back at a node on this server is refused as a routing loop, and an exit used for AI cannot be deleted.
- **Inbound binding is explicit and isolated.** Nothing is selected by default and an empty selection binds nothing (never "all"). Rout runs one sing-box process per node, so only the configuration files of bound nodes receive AI rules; an unbound node's file is not rewritten and its service is not restarted. Bindings use the node's stable ID and every rule also matches the node's own inbound. Deleting a node removes it from the binding; a stale ID found in `state.json` is reported and ignored, never widened.
- **Disabling** restores each bound node's original configuration byte-for-byte and keeps the exit and bindings. Enabling needs a selected exit.
- **Rules** (`internal/rout/ai_rules.go`, versioned; `rule_set_version` is saved) cover OpenAI/ChatGPT, Claude/Anthropic, Gemini, Google AI Studio, Hugging Face, GitHub Copilot and Cursor, as domain suffixes dedicated to those products. Whole-company domains (google.com, github.com, googleapis.com…) are deliberately absent. **View AI rules** lists them.
- **Order of rules on a bound node:** explicit AI domain match → sniff TLS/HTTP/supported QUIC → AI domain match again → the node's existing rules. Identified AI UDP is rejected. A node with its own outbound proxy keeps it for non-AI traffic.
- **If the AI exit fails, AI connections fail.** There is no silent fallback to the original exit. If the exit disappears from the configuration, AI domains of bound nodes are rejected until a new exit is chosen.
- **Safe changes:** every change goes through the same transaction as node edits: validation of references, `sing-box check` of each changed configuration in a staging directory, an automatic backup of `state.json`, atomic writes, a health check of every restarted service, and automatic rollback of files, state and services on failure. Only the bound nodes whose effective routing changes are restarted.

Limits (also shown in the menu): matching is by domain. DNS is not hijacked or forced through Canada; client DNS/DoH/DoT keeps its behavior. Sniffing is limited to one second and supported protocols. Connections that expose no domain (IP-only without sniffable TLS/HTTP/QUIC data, ECH-encrypted handshakes) take the original route. The AI exit is TCP-only, so identified AI QUIC is rejected; TCP fallback depends on the client. Unrecognized QUIC may take the original route. This does not guarantee zero leakage. The Copilot token endpoint `api.github.com` is not routed, to avoid sending ordinary GitHub traffic to the AI exit. A domain list cannot guarantee complete coverage; new AI products need a rule-set update followed by *Apply changes*. *Test configuration* validates the configuration and probes the exit; its routing simulation evaluates rules and makes no real request.

## Subscriptions

A subscription is a private URL with two native formats: the unchanged Base64 node list (`GET /s/TOKEN`) and a complete Mihomo YAML configuration (`GET /s/TOKEN?format=mihomo`; `format=clash` is an alias for Mihomo, not legacy Clash). Both use the same token, selection and ordered node settings, without a converter service or a second subscription. It is a link-management feature, not a proxy client, and covers only nodes you select by hand. Menu: **Subscriptions** (the seventh entry).

1. **Create** — *Create subscription*: name it, pick nodes from the numbered list (several at once, e.g. `3 1 2`; the order you type is the subscription order), review, confirm. The access token is shown **once**; Rout stores only its SHA-256. Nodes are never added automatically, and "all nodes" is not offered. A node may be in several subscriptions. Relays are listed only if they have a share link.
2. **Edit** — rename, add, remove, reorder, enable/disable. Edits keep the token. Links are generated per request from the current nodes, so renamed, moved or re-keyed nodes show up on the client's next update; disabled nodes are left out until re-enabled; deleted nodes are removed from every subscription.
3. **Serve** — *Subscription server settings → Enable*. The server is **off by default**, listens on `127.0.0.1:8787` (port configurable, loopback only), runs as the `rout-subscription` systemd/OpenRC service and starts at boot. It never opens a firewall port.
4. **Publish over HTTPS** — choose *Subscription server settings → Deploy / repair HTTPS automatically*. Enter your domain; Rout checks A/AAAA records and TCP 80/443, asks before installing Caddy from Debian/Ubuntu's signed apt repository, validates an isolated fragment and the shared layout, then verifies TLS and an authenticated subscription response. Caddy handles automatic certificate issuance/renewal. A working existing proxy is detected first: **Use existing HTTPS configuration** preserves it without taking ownership or restarting it. Optional adoption is limited to an explicitly confirmed, standalone simple imported fragment; shared/manual configurations remain external and cannot be deleted by Rout. Other platforms/layouts can keep their existing HTTPS proxy and set its public URL in the CLI.
5. **Import** — keep `https://sub.example.com/s/TOKEN` in Shadowrocket/Base64 clients. For Clash Verge Rev, FlClash or Mihomo Party, add `https://sub.example.com/s/TOKEN?format=mihomo` as a remote configuration. Use your configured domain/prefix, and append the query to the original saved URL. New subscriptions show both complete URLs once; existing subscriptions show both safe templates. No token rotation, node reselection, client reimport or Caddy change is needed for existing Base64 clients. Mihomo responses use `application/yaml; charset=utf-8`; both formats use `Cache-Control: no-store`.
6. **Rotate** — *Rotate access token* invalidates the old URL immediately and shows the new one once. *Delete* also revokes the URL at once.

**Upgrading from v0.3.4 preserves existing subscriptions and URLs.** IDs, names, token hashes, enabled state, selected nodes/order, local port and public domain are retained; no schema migration, token rotation, recreation or client reimport is needed. Hashes cannot recover the original plaintext token: use the complete URL already saved in Shadowrocket. Existing-entry views show a safe URL template. The newer installer/updater snapshots private persistence and refreshes only the subscription helper; the older v0.3.4 updater keeps its old helper serving, and opening the new subscription menu or running `sudo rout subscription refresh` updates it safely.

**DNS and ports:** all A/AAAA records must point to appropriate origin addresses. Cloudflare proxy records are identified as inconclusive origin evidence; DNS-only is preferable for initial issuance. Rout never stops nginx/Apache/other listeners or changes a node's port/firewall. Automatic management supports Debian/Ubuntu with systemd. Diagnostics separate loopback, reverse proxy, origin-local TLS, a request through public DNS from this server, and independent external verification. A root 404 is expected. Always check the original client subscription from an external network; local success does not prove public availability.

**Failure/removal:** deployment is transactional, with private backups, digest-verified ownership, atomic files and verified rollback where possible. Failures report incomplete rollback explicitly. Disabling/restarting the subscription service preserves Caddy; dedicated confirmed HTTPS removal preserves subscriptions, tokens, unrelated sites and certificates and never uninstalls shared Caddy. See [deployment, adoption, rollback and troubleshooting](docs/SUBSCRIPTIONS.md).

Responses are deliberately uniform: unknown, malformed, disabled, revoked or deleted tokens all get `404`; only `GET`/`HEAD` are accepted; if a valid subscription currently has no usable node it returns `503` (never an empty success that could wipe a client's list) and the reason is logged by node name. Details, troubleshooting and security limits: [docs/SUBSCRIPTIONS.md](docs/SUBSCRIPTIONS.md). Mihomo output includes ordered proxies, manual/auto/fallback groups and one `MATCH` rule; it does not configure DNS, TUN, listener ports or a management API. Importing a complete remote configuration replaces its rules: use client overrides or proxy-provider integration to retain your own routing preferences. Supported native conversions are VLESS Reality/Vision, Shadowsocks 2022, Hysteria2 and TUIC; supported relay links additionally cover plain/TLS VLESS, Trojan and their TCP/WS/gRPC transports. AnyTLS Reality, UDP-only SS, unsupported relay options and protocols absent from Rout (including VMess) are not guessed. Mixed selections omit incompatible nodes with comments, logs and a skipped-node count; no compatible node returns 503. Hysteria2/TUIC use the actual server certificate SHA256 pin, never unchecked TLS. Health checks are lazy at 600 seconds, with a configurable HTTPS test URL under Subscription server settings. No runtime dependency was added. Other output formats, a web UI, arbitrary external node import and per-device tokens remain outside scope. Automated tests verify unchanged Base64 bytes/order, original tokens, real Mihomo configuration validation and live TCP/UDP traffic. Production VPS, Shadowrocket and desktop GUI behavior still require manual acceptance.

## Traffic accounting, limits and monthly reset

All nodes are **unlimited by default**. With accounting installed, every listener is metered in the kernel: upload + download at the node's entry, bytes in decimal MB/GB/TB, including NAT, and counted once even when nodes share an outbound proxy. Limits are optional and per node. A finite limit is enforced by a kernel quota that drops the packet that would exceed it, including on existing connections; the monitor then stops only that node. Each node has a billing day (1–31, clamped to short months) and an IANA timezone; a new cycle restores quota-paused nodes but never manually paused ones. Unlimited nodes are never blocked by accounting faults.

**Recovery behavior (v0.2.2):**

- **Normal monitor restart or reboot:** at graceful shutdown the monitor closes the node's kernel gate *before* writing its final checkpoint ("sealed"). On start it verifies the seal and resumes automatically with exact usage and the exact remaining budget. Nothing is reset and no quota is granted.
- **Quota-exhausted nodes** stay paused across restarts until the next cycle.
- **Unexpected crash or power loss:** the last uncheckpointed seconds are unknown, so the node stays paused (fail-closed). Traffic management → **Resume with known usage** (or `rout traffic recover ID`) resumes it while keeping all known usage; the cycle stays marked as having a gap and its total is a lower bound. Alternatively reset this cycle (type `reset` to confirm) or wait for the next cycle.

Traffic and limits shows upload, download, total (upload + download), limit, remaining and the next reset date for each node. **Set limit** takes GB: a plain number means GB (`100` = 100 GB, `1.5` = 1.5 GB), `500 MB` and `2 TB` also work, and `0` or an empty answer on a node without a limit means unlimited. Units are decimal (1 GB = 1,000,000,000 bytes). Setting or changing a limit never resets usage and needs no extra confirmation; only **Reset this cycle** does, by typing `reset`.

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
rout test ID                  # local entry → protocol → outbound proxy, IPv4 and IPv6
rout export ID [FILE] | export all [FILE] | copy ID
rout restart|on|off|delete|logs ID
rout relays | outbounds | settings   # `exits` still works as an alias
rout ai [status|test|apply]   # AI Smart Routing menu | status | check configuration | re-apply
rout subscription [list|status|restart|https|logs|serve]   # subscriptions menu | list | server status | HTTPS deployment/diagnostics/removal, sanitized logs and restart | server process
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

- Configuration `/etc/rout` (0700; files 0600): `state.json` (nodes, relays, outbound proxies and the optional `ai_routing` block), `traffic.json`, `settings.json` (language, server address and family, `backup_keep`, subscription server port and public URL). Subscriptions live in the optional `subscriptions` array of `state.json` (token hashes only).
- Automatic pre-change backups in `/etc/rout/backups`, keeping the newest **20** by default (configurable 1–1000 in Settings). The newest backup is never removed, and explicit `rout backup` files are never pruned. Backups contain credentials and private keys.
- Pinned engines in `/opt/rout/bin`: sing-box v1.14.3 and GOST v3.3.0, each verified by SHA256, streamed and installed atomically (see below) (`internal/rout/engines.lock.json`). Hosts without glibc (Alpine) get sing-box's static musl build; an installed engine that cannot execute is replaced automatically.
- One service per node, `rout-<ID>`. Metadata edits (name, advertised address/port, outbound label) do not restart nodes; runtime edits restart only the changed node. A start counts as successful only if the process stays up and its ports are listening.
- systemd units restrict engines with a capability bounding set (`CAP_NET_BIND_SERVICE`; HY2/TUIC also keep `CAP_NET_ADMIN` for QUIC socket buffers), `ProtectSystem=strict`, kernel/cgroup/clock protections, `RestrictNamespaces` and `RestrictAddressFamilies`. Engines therefore cannot change Rout's quota tables. New units apply on the next change or `rout apply`.
- OpenRC services use `supervise-daemon` with bounded respawns and private logs in `/var/log/rout-<ID>.log`, rotated at 5 MB.
- The optional `rout-subscription` service (systemd or OpenRC) is independent of node services: loopback-only, read-only filesystem and no capabilities under systemd, never writes the configuration. It runs a copy of the binary at `/opt/rout/bin/rout-subscription-v1`; the installer/newer updater refreshes it automatically when needed. The v0.3.4 updater predates that hook: open the new subscription menu or run `sudo rout subscription refresh`; existing URLs keep working meanwhile.
- Changes are serialized by file locks with bounded waits, validated in private staging directories and rolled back on failure.

## Low-memory installation

v0.3.0 read the whole engine out of its archive into memory before writing it. For the 81 MB sing-box binary that meant a peak of 220–310 MiB, and on a small VPS the kernel's OOM killer ended the install (`Killed`). Since v0.3.1 the engine path is bounded:

- the archive is streamed to a staging directory inside `/opt/rout/bin` through a 256 KiB buffer while its SHA256 is computed; nothing is unpacked unless the digest matches the pinned value;
- the engine is streamed out of the verified archive into a staging file (never into memory), flushed every 8 MiB and dropped from the page cache, because dirty pages count against a container's memory limit too;
- the staged binary must actually run before it is renamed over the target, so a failed or interrupted install never touches an existing engine; the staging directory is removed on every exit path, and one left by a killed installer is removed by the next install once it is 15 minutes old;
- a lock in the engine directory makes concurrent installers wait instead of downloading twice; `rout update` also copies `rout.previous` by streaming.

Measured on this build (cgroup memory limit, no swap, real engines): the v0.3.0 installer is OOM-killed at 160 MiB and below and peaks at about 310 MiB; the v0.3.1 installer completes sing-box and GOST with no OOM kill at limits as low as 32 MiB (peak RSS 44 MiB). `scripts/measure-engine-memory.sh` repeats the measurement on any host. This is evidence about the installer, not a guarantee for every VPS: other processes still compete for memory, and the reported production failure has not been reproduced on that exact machine.

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
| IPv4-only / IPv6-only / dual stack | Supported; detection and tests do not require IPv4; one `::` listener serves both families where the host allows it |
| Existing NAT-VPS mappings | Keep working; not offered for new setups (see Legacy NAT-VPS mappings) |
| OpenVZ / restricted LXC | Proxies work; accounting needs nftables + `CAP_NET_ADMIN` |

Real-host acceptance items outside CI: IPv6 reachability from real client networks, provider NAT reachability, behavior on the 1 GB VPS that reported the OOM kill, physical reboots and power loss, NIC offload and sustained high rates. Each node table adds a small per-packet cost; Rout is tuned for tens of nodes per host.

See [docs/AI_ROUTING.md](docs/AI_ROUTING.md) for reproducible real-network tests, US/Canada VPS acceptance commands and the release gate. No real VPS acceptance is claimed by automated local tests.

## Development and releases

Go 1.23+ (CI builds with the current stable Go), standard library only. Rout is original code, with workflow inspiration from [singbox-deploy](https://github.com/caigouzi121380/singbox-deploy). Forwarding and proxy engines are separately downloaded [GOST](https://github.com/go-gost/gost) and [sing-box](https://github.com/SagerNet/sing-box), under their own licenses.

```sh
go test -race ./... && go vet ./...
go build -o rout ./cmd/rout
./rout --home /tmp/rout-state --bin-dir /tmp/rout-engines --service none engines
ROUT_TEST_ENGINES=/tmp/rout-engines go test -race -count=1 -v ./internal/rout
```

Test layers: unit and simulated tests (fake meter, scripted English/Chinese UI) always run. Engine integration tests send real encrypted traffic for all five protocols, SOCKS5, HTTP and HTTPS CONNECT outbound proxies and TCP/UDP relays, including relays built through the interactive flow (`ROUT_TEST_ENGINES`). Kernel tests run real nftables in a disposable network namespace (`ROUT_TEST_NFT=1`), covering seal/reboot/crash recovery, batching, preservation of unknown historical tables, probe cleanup, multiple limited nodes, and upgrade/rollback against the published v0.2.1 binary. A Debian 12 container additionally checks real nftables 1.0.6 JSON/text compatibility and failure cleanup (see [traffic testing](docs/TRAFFIC.md#real-compatibility-regression-tests)). Init tests need a disposable root host: systemd (`ROUT_TEST_SYSTEMD=1`, `ROUT_TEST_TRAFFIC_SYSTEMD=1`) or OpenRC (`ROUT_TEST_OPENRC=1`). Native Hysteria URI tests use `scripts/test-native-hy2.sh`. Native Mihomo tests use the checksum-pinned core from `scripts/test-mihomo.sh` with `ROUT_TEST_MIHOMO`; they validate YAML and send real TCP/UDP traffic, including rejection of incorrect certificate pins. Real-systemd subscription upgrade tests exercise the published v0.3.4 binary and a helper built from the pinned v0.3.5 commit (that release has no binary assets). Engine-installation tests (download failure, corrupt archive, checksum mismatch, killed installer, concurrent installers, peak RSS of a 96 MiB engine against the old in-memory approach) run in every `go test`; IPv6 and dual-stack tests skip themselves on hosts without an IPv6 stack.

CI runs everything above plus `govulncheck` and cross-compilation on every push. **Releases are published only from an explicit version tag** that matches the compiled version and `install.sh`; pushes to `main` never publish.

```sh
# Only after exact-commit CI and real VPS acceptance (do not execute for preparation):
git tag -a v0.3.6 -m 'Rout v0.3.6'
git push origin v0.3.6
```
