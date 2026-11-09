# Rout

Create proxy nodes, relay traffic to this or another server and manage reusable outbound proxies on IPv4-only, IPv6-only and dual-stack VPS hosts — from one small, dependency-free binary with a bilingual terminal menu (**简体中文** / **English**).

- Six node protocols: **VLESS Reality, AnyTLS Reality, Shadowsocks 2022, Hysteria2, TUIC v5** and **Snell v5 / v6 (beta)** for Surge, run on the vendor's official `snell-server` (see [docs/SNELL.md](docs/SNELL.md))
- Guided TCP/UDP relays to a service on this server or to a remote server, with a full path preview, loop checks and the original node's credentials kept
- Reusable **SOCKS5 / HTTP / certificate-verified HTTPS CONNECT outbound proxies** shared by many nodes, with no silent direct-IP fallback
- Per-node **outbound IP family**: Auto, IPv4 first, IPv6 first, **IPv4 only**, **IPv6 only** — "only" really excludes the other family, for names and for bare addresses (see [Outbound IP family per node](#outbound-ip-family-per-node))
- Exact per-node **traffic accounting and hard monthly quotas** in the kernel (nftables)
- **systemd and OpenRC**, IPv4-only, IPv6-only and dual-stack hosts; existing NAT-VPS mappings from older versions keep working
- Low-memory friendly: engines are streamed to disk and verified incrementally, never held in memory (see [Low-memory installation](#low-memory-installation))

## Install

Linux amd64 / arm64 with systemd (Debian, Ubuntu) or OpenRC (Alpine). Root is required to manage services. Provider firewalls and NAT mappings must already allow the ports you use.

```sh
f=$(mktemp) && curl -fsSL https://raw.githubusercontent.com/VAR7IANT/Rout/main/install.sh -o "$f" && sudo sh "$f"; rm -f "$f"
sudo rout
```

On Alpine, or when already root, omit `sudo`. The installer downloads release `v0.5.2`, checks its SHA256 before replacing the executable, installs `nftables` and enables traffic accounting for the default directories. It does not create nodes, set any limit or change the default route. `ROUT_SETUP_TRAFFIC=0` skips the accounting setup. The first interactive run asks for the language; change it later in Settings (简体中文, 繁體中文 or English), or use `--lang en` / `--lang zh-CN` / `--lang zh-TW` for one run.

Release binaries carry GitHub build-provenance attestations. The checksum file comes from the same release, so it proves integrity, not authenticity; to verify origin independently:

```sh
gh attestation verify rout-linux-amd64 --repo VAR7IANT/Rout
```

## Quick start

```text
sudo rout
Rout 0.5.2
  ● Nodes: 4 · Relays: 1 · Running: 5 · AI routing: enabled (2 inbounds)
  ! Tokyo-HY2 certificate expires in 12 days

  Nodes
   1  Quick create node     → the guided node creation, straight from the main menu
   2  Manage nodes      4   → full links below every node; pick one to edit / delete / copy / enable / restart
                             n new node · l all links · t traffic and limits
  Network
   3  AI Smart Routing  Enabled → send AI services to a chosen exit, for selected inbound nodes only
   4  Port forwarding    1   → relays: view / create / edit / test / delete
   5  Outbound proxies   2   → numbered list incl. Direct connection; create / edit / test / delete / assign to nodes
  Services
   6  Service & system       → services · diagnostics · updates · settings (language, server address, backups, uninstall)
   7  Subscriptions      2   → selected-node subscriptions · HTTPS deployment · diagnostics
   8  Web management panel panel.example.com → one-click install · HTTPS deployment/repair · password · diagnostics
   0  Quit
```

The entries are grouped under small section titles, and the dim badge to the right of an entry shows its live count or state (nothing is shown for an empty category). The **numbers never change**. Conditions that need attention (certificates about to expire, nodes paused by a quota, traffic monitoring off) are shown under the status line every time the main menu is drawn, at most three at once. Pressing Enter at the main menu does **not** quit; type `0` or `q`. In sub-menus Enter still goes back.

Menu headings show where you are (`Rout › Manage nodes › Tokyo-VLESS`), shortened from the left on narrow terminals. The full key hint is printed once per session and then shortened to `0 Back · q Quit`. On a colour terminal node status gets a coloured dot (● running, ○ disabled, red when stopped) and limited nodes a usage bar such as `▓▓▓▓▓░░░ 62%`; both are glyph-only additions to the existing text, so plain output, pipes and `NO_COLOR` are unchanged.

Entry **8, Web management panel** (v0.5.1) installs and manages the browser panel without editing any file: *One-click install / initialize*, *Start / stop / restart*, *Status and address*, *Set / change admin domain*, *Set / reset admin password*, *HTTPS deployment and repair*, *Logs / diagnostics* and *Uninstall*. Every action returns to that page. See [Web management panel](#web-management-panel).

Releases before v0.3.8 had eight different top-level entries. *Traffic and limits* moved into Manage nodes (`t`); *Services*, *Diagnostics*, *Updates* and *Settings* moved under **Service & system**; the separate *view*, *edit*, *delete*, *restart* and *connection links* pickers of Manage nodes became one list where you choose a node first. Nothing was removed, and every `rout` command works as before.

The interactive menu opens with a ROUT banner once per session: the logo in a blue gradient on 256-colour terminals, with "Support by VAR7IANT" and the running version centered beneath it, or a two-line title on terminals narrower than 39 columns or shorter than 30 rows. It is never printed for commands, pipes or scripts, and `NO_COLOR` or `TERM=dumb` disables all colour.

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
| Snell v5 / v6 (beta) | TCP (v5 may also use UDP on the same port for QUIC Proxy Mode) | — (Snell's own encryption) | **Surge only.** Snell has no share link: Rout prints the Surge `[Proxy]` line (`Name = snell, host, port, psk=…, version=5`) and serves it as `?format=surge`. Official `snell-server`, one pinned engine per version; v6 is a vendor beta and glibc-only. See [docs/SNELL.md](docs/SNELL.md) |

**Snell** (Surge's own protocol) is created like any other protocol (*Snell v5* or *Snell v6 (beta)* in the same menu, random 32-character PSK, free or chosen port, IPv4 or dual stack, NAT-aware) and then listed, edited (port, public address, listen address, PSK, outbound IP family), restarted, limited and deleted like every other node, with one service, one configuration file and one traffic table per node so several Snell nodes can coexist. What a Snell node cannot do (outbound proxies, AI routing, a share link, a sing-box client file) is refused explicitly, never faked. Creation ends with the Surge line to paste. Install, upgrade and rollback of the engine, the IPv4/IPv6/NAT behaviour, troubleshooting, what is and is not verified, and a Surge iOS acceptance checklist are in [docs/SNELL.md](docs/SNELL.md).

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

### Inbound family per entry (IPv4, IPv6 or dual stack)

The saved server address says which address clients are *told* to use; it no longer decides how a new relay *listens*. A new relay asks once, and only offers what the host can really bind (each family is tried with an explicit `tcp4`/`tcp6`/`udp4`/`udp6` socket, never inferred from a wildcard):

```text
Inbound network (which IP family clients use to reach this relay)
   1  IPv4          Listen on IPv4 only (0.0.0.0); no IPv6 socket is created
   2  IPv6          Listen on IPv6 only (::, IPV6_V6ONLY); IPv4 connections are not accepted
   3  Dual stack    One separate listening socket for IPv4 and one for IPv6, on the same port
Choose [1]:
```

IPv4 is the default and the last choice is remembered. A single-family host is told what it has and is not asked. Dual stack is two sockets on one port, verified at creation to be able to coexist; it does not rely on a dual-stack wildcard, so it behaves the same whatever `net.ipv6.bindv6only` or the kernel's IPv4-mapped support say. The mode is stored on the relay (`inbound_mode`) and is never silently turned into dual stack; the public address is kept consistent with it (an IPv6 literal is never advertised by an IPv4 entry). Only a dual-stack relay prints a second link for the other address.

Nodes use the same three choices when they are created. sing-box cannot set `IPV6_V6ONLY`, so an explicit **IPv6** node listens on `::` and refuses IPv4 clients by source address in its routing rules (the first rule rejects `0.0.0.0/0`); it is not offered as dual stack, its metering counts IPv6 only, and it prints no IPv4 link. Nodes created by older versions keep their saved listening address and behavior.

### Outbound IP family per node

Independent of the inbound mode above, every node can choose which IP family it uses to reach the Internet. In the terminal: *Create node → Advanced options → Outbound IP family*, or *Manage nodes → choose a node → Outbound IP family*; in the panel: *Nodes → New nodes* and the node drawer.

```text
Outbound IP family (what the node uses to reach the Internet)
   1  Auto          No restriction; the system chooses. Same as earlier versions (recommended)
   2  IPv4 first    Prefers IPv4 and falls back to IPv6 when it fails
   3  IPv6 first    Prefers IPv6 and falls back to IPv4 when it fails (this is not IPv6 only)
   4  IPv4 only     IPv6 addresses and AAAA-only names are refused explicitly, with no IPv6 fallback
   5  IPv6 only     IPv4 addresses and A-only names are refused explicitly, with no IPv4 fallback
Choose [1]:
```

Auto is the default, adds nothing to the node's configuration and is what every existing node keeps. **IPv6 first is not IPv6 only**: only the "only" policies exclude the other family. Excluding it takes more than a DNS preference — with sing-box 1.14.3, `domain_resolver.strategy = ipv6_only` does not stop a client that asks for an IPv4 *address*, so Rout also writes a routing rule that rejects the other family's literals (verified against the real engine; see [docs/NODE_EGRESS.md](docs/NODE_EGRESS.md)). Changing the policy restarts only that node, keeps its UUID, port, certificate and links, rolls back on failure, and survives `rout apply`, restarts and backup/restore. On a VPS without a route for a family, an "only" policy for that family asks for explicit confirmation.

With an **outbound proxy** (SOCKS5, HTTP CONNECT, HTTPS CONNECT, a remote node) the policy governs only how this server reaches the proxy server; which family the proxy uses towards the website is the proxy's decision, and Rout says so instead of claiming to enforce it. *Test IPv6 egress* sends real requests through the node's own exit, compares them with the host's own network (labelled as a host test) and reports pass, fail or **could not be verified**.

### Legacy NAT-VPS mappings

Hosts set up with v0.3.0 or earlier in NAT mode keep working. Nothing is migrated or rewritten: the saved internal range, public offset and allowed networks stay in `settings.json`, existing NAT nodes and relays keep their ports, and new entries on such a host keep following the saved mapping (a notice says so) because a regular-VPS port would be unreachable there. Editing an existing NAT node or relay still asks for the provider-mapped public port. To start using regular-VPS behavior for new entries, choose Settings → Server address → *Switch to a regular VPS*; this asks for confirmation, changes only the saved default and leaves existing NAT entries as they are. There is no menu to create a new NAT mapping.

Rout cannot create provider mappings or open external firewalls. A local test does not prove the public port is reachable: verify the link from an external client.

Only traffic through a managed node uses its outbound proxy. SSH, package updates and other services keep their normal path. Rout never enables TUN, changes the default route, flushes firewall rules or touches `/etc/sing-box`.

## Relays

Relays → **Create relay** walks through a few steps and shows the whole path before anything changes:

1. **Where the traffic goes:** *Local machine* (a service on this server) or *Remote relay server* (another server). The last choice is remembered.
2. **Entry on the current server:** the **inbound network** (IPv4, IPv6 or dual stack, see above), then the planned listening address, a free listening port (checked on every family the entry binds, TCP and UDP) and the public entry; press Enter to use them, or answer `n` to choose the port yourself. The public port equals the listening port. (A legacy NAT host still asks for the provider-mapped public port.)
3. **Destination:** local relays default to `127.0.0.1` and list this server's nodes by listening port. Remote relays require an explicit host (IPv4, IPv6 without brackets, or a domain) and port, or a pasted share link; the current server's public IP is never filled in. A pasted link is recognized (`Recognized: TCP / VLESS Reality (destination host:port)`) and answers the transport question itself.
4. **Transport:** TCP, UDP or TCP+UDP, explained in the menu (limited to what the saved mapping allows on a legacy NAT host). Skipped when a VLESS/AnyTLS/Trojan or Hysteria2/TUIC link settles it.
5. **Outbound policy** (remote destinations, only on a host that can route both families): how the relay reaches the destination, independent of the inbound family.

```text
Client → 203.0.113.10:40005 (public entry) → 0.0.0.0:20005 (listening) → 198.51.100.7:8443 (destination) · UDP
```

**Outbound policy** (`outbound_policy`), per relay and independent of the inbound mode:

| Policy | Behavior |
| --- | --- |
| IPv4 first (default) | A records first; IPv6 only as a fallback |
| IPv6 first | AAAA records first; IPv4 only as a fallback |
| IPv4 only / IPv6 only | The other family is never resolved, tried or connected, and a literal address of the wrong family is refused when the relay is saved |
| Auto | Only addresses this host has a route to are tried (checked per destination in the kernel's routing table); both families are raced with a short head start for IPv6 (RFC 6724 / Happy Eyeballs) and the family that worked last is tried first |

Because the two settings are independent, **IPv6 in → IPv4 out** (and every other combination: IPv4 → IPv6, dual stack → IPv4/IPv6, …) is simply two ordinary TCP connections joined by the relay; no NAT64 is involved. Example:

```text
Client ──IPv6──▶ AS3 relay [2001:db8::7]:29519 ──TCP over IPv4──▶ ft-us.example.net:44275 (VLESS Reality)
```

**Native forwarder and legacy relays.** New relays run on Rout's own forwarder (`rout relay-serve`, started from a copy of the manager next to the engines, under the same systemd/OpenRC sandbox as before, with no extra capabilities). It binds one explicit socket per family, applies the outbound policy, and resolves a domain destination again when its short cache entry (30 s; Go does not expose DNS TTLs) expires or when every cached address fails, so a NAT whose address changes keeps working; a brief DNS outage reuses the last answer for up to ten minutes and the test says so. It forwards bytes only: it holds no credentials, speaks no proxy protocol and refuses to dial its own listener. Relays created by earlier versions keep running on GOST with exactly their old configuration until you pick **Edit relay → Change network**; that moves one relay to the native forwarder (same port, destination and share link) after a preview. Renaming or disabling a legacy relay does not migrate it. GOST cannot bind IPv6-only or restrict dialing, which is why the choice is explicit. Details and the reasoning: [docs/NETWORK.md](docs/NETWORK.md).

**TCP and UDP capability.** A plain TCP port mapping carries TCP only. Hysteria2 and TUIC are QUIC (UDP), so Rout refuses to create such a relay for a destination that only accepts TCP, instead of writing UDP into a TCP socket:

```text
The destination currently supports TCP only. Hysteria2 needs UDP transport and cannot be used through a
plain TCP port relay. Choose a UDP relay, or use a compatible tunnel that can encapsulate UDP
```

Links settle the transport (VLESS, AnyTLS, Trojan: TCP; Hysteria2, TUIC: UDP; Shadowsocks: either) and a mismatch is explained. When a relay carries UDP to a remote server and the destination is not a TCP-only link, Rout asks whether the destination's port mapping accepts UDP (default *TCP + UDP, or not sure*; *TCP only* blocks UDP). UDP-over-TCP encapsulation is deliberately not offered: it needs a compatible decapsulating peer on the far side, adds head-of-line blocking that defeats QUIC congestion control, and cannot be made transparent to Hysteria2/TUIC. A relay forwards UDP to a UDP-capable destination or refuses.

Checks before saving: address and port validity, port conflicts (TCP and UDP separately), and forwarding loops (the relay's own listening port or public entry, or a chain of local relays leading back to it). Forwarding to another port on the same server is allowed, and a destination that merely shares the server's public IP is not treated as a loop: on NAT VPS hosts that IP is shared. When the destination is the public entry of a node on this server, Rout offers to switch to `127.0.0.1:<listening port>` instead, because many networks cannot hairpin (connect to their own public address). Reachability: a local destination is checked for a listening socket; a remote TCP destination gets a real connection attempt, which proves the port is reachable, not that the proxy protocol works. UDP has no handshake and is never reported as verified.

After saving, Rout prints the client endpoint and, when the destination is a known node or a pasted link, a share link rewritten to the relay entry: only the address and port change; UUID, Reality public key, short ID, SNI, fingerprint, flow and every other parameter are kept byte for byte. **Test relay** runs the [layered diagnosis](#diagnostics) and can include a full protocol test through the relay. **Edit relay** changes destination, entry, transport, name or state; **Delete relay** defaults to No. Relays created by older versions keep working; their destination type is inferred.

## Outbound proxies

Outbound proxies decide how a node reaches the internet. **Direct connection** (no proxy) is built in. Relays have no outbound proxy: they forward traffic unchanged to their destination.

Outbound proxies → **Create**: choose SOCKS5, HTTP CONNECT, HTTPS CONNECT (certificate verification) or **Remote server**, then enter `IP:port:username:password` (IPv6: `[addr]:port:user:pass`; passwords may contain colons). Proxies are listed and selected **by number** (`Name — KIND — host:port — usage`), with Direct connection offered right after the stored ones and *New outbound proxy* last, so an exit can also be created while choosing one for a node. Their stable internal IDs never change and never need to be typed.

**Remote server exits.** Traffic leaves from another VPS/NAT's public IP. That only works if something on the far side carries it out, so Rout accepts exactly two forms and reuses what it already has:

| What the remote server runs | How it is used |
| --- | --- |
| A node (a Rout node on another VPS: VLESS Reality, AnyTLS, Trojan, Shadowsocks, Hysteria2, TUIC) | Paste its share link; sing-box dials it as the outbound |
| An authenticated SOCKS5 / HTTP / HTTPS proxy | `IP:port:user:password`; accounts are mandatory, open proxies are not accepted |

A bare TCP/UDP **port mapping is not an exit**: the connection would be forwarded but the destination would still see this server's IP, so Rout explains this and points to Relays. Nothing here opens a listener or a proxy on this server. A Remote server is **verified with a real request before it is saved**; if the check fails you are told which layer failed and nothing is stored unless you explicitly answer *Save anyway*. Hysteria2/TUIC links need UDP to the remote server: asked once, and a TCP-only NAT is refused with the message above. Certificate-pinned Hysteria2 links are refused (the pinned engine cannot verify them). Node-link credentials live only in `state.json` (mode 0600) and backups; they are never printed, logged or shown by *View*.

- **Test** runs the layered diagnosis of the exit: address resolution (both families), connection to the proxy or remote server, protocol/credential handshake (a rejected password is reported as such), and the observed exit address per family.
- **View** shows type, endpoint, transport needs, capabilities and everything that references the exit (nodes, AI Smart Routing), without credentials.
- **Assign to nodes** changes only the nodes you pick, in one transaction, after testing the proxy once. Nodes that cannot use a proxy (UDP-only Shadowsocks) are skipped with the reason. You can also pick the outbound while creating nodes.
- **Edit** updates every node using the exit transactionally and nothing else (other exits and unrelated nodes are untouched); renaming alone restarts nothing. An exit that points back at an entry of this server is refused as a routing loop.
- **Delete** is refused while any node or AI Smart Routing uses the exit, and names them, so nothing silently falls back to the VPS IP.

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

Main menu → **AI Smart Routing** (also the panel's *AI Routing* page): *Enable / Disable*, *Select inbound nodes*, *Select AI exit*, *View AI rules*, *Test configuration*, *Status and diagnostics*, *Apply changes*. Also `rout ai [status|test|apply]`.

- **Choosing the AI exit** (*Select AI exit*) offers four ways, all ending in something that really carries the traffic out:
  1. **an existing outbound proxy**: SOCKS5, HTTP or HTTPS CONNECT, a Remote server, or a relay chain;
  2. **through an existing port forward** (v0.5.1): AI traffic → a Rout relay on this server → the SOCKS5 / HTTP(S) proxy or node at the relay's target → Internet. The relay is referenced by its stable ID; a bare forward is never treated as an exit (the end must be a real proxy, and its credentials are asked for);
  3. **a remote node share link** (VLESS Reality, AnyTLS, Trojan, Shadowsocks, Hysteria2, TUIC; the existing Remote server exit);
  4. **a new exit chain**: creates a loopback-only relay on this server (with its own outbound IPv4/IPv6 policy) or uses a forwarder port on another server, plus the proxy at its end, in one flow.

  Whatever is chosen is tested layer by layer (inbound nodes, relay, relay target, proxy handshake, authentication, a real request) and the **observed exit IP** is shown. No address is hard-coded. An exit or relay chain that points back at a Rout entry on this server is refused as a routing loop; an exit, or a relay that an exit chain uses, cannot be deleted, disabled or retargeted while in use (the message names the dependant).

```text
Client → US VPS · Rout inbound ──┬─ everything else → the node's original exit (US IP)
                                 └─ AI domains → Rout relay (TCP) → Canada SOCKS5 → Internet (Canada IP)
```
- **Inbound binding is explicit and isolated.** Nothing is selected by default and an empty selection binds nothing (never "all"). Rout runs one sing-box process per node, so only the configuration files of bound nodes receive AI rules; an unbound node's file is not rewritten and its service is not restarted. Bindings use the node's stable ID and every rule also matches the node's own inbound. Deleting a node removes it from the binding; a stale ID found in `state.json` is reported and ignored, never widened.
- **Disabling** restores each bound node's original configuration byte-for-byte and keeps the exit and bindings. Enabling needs a selected exit.
- **Rules** (`internal/rout/ai_rules.go`, versioned; `rule_set_version` is saved) cover OpenAI/ChatGPT, Claude/Anthropic, Gemini, Google AI Studio, Hugging Face, GitHub Copilot and Cursor, as domain suffixes dedicated to those products. Whole-company domains (google.com, github.com, googleapis.com…) are deliberately absent. **View AI rules** lists them.
- **Order of rules on a bound node:** explicit AI domain match → sniff TLS/HTTP/supported QUIC → AI domain match again → the node's existing rules. Identified AI UDP is rejected. A node with its own outbound proxy keeps it for non-AI traffic.
- **If the AI exit fails, AI connections fail.** There is no silent fallback to the original exit. If the exit disappears from the configuration, AI domains of bound nodes are rejected until a new exit is chosen.
- **Safe changes:** every change goes through the same transaction as node edits: validation of references, `sing-box check` of each changed configuration in a staging directory, an automatic backup of `state.json`, atomic writes, a health check of every restarted service, and automatic rollback of files, state and services on failure. Only the bound nodes whose effective routing changes are restarted.

Limits (also shown in the menu): matching is by domain. DNS is not hijacked or forced through Canada; client DNS/DoH/DoT keeps its behavior. Sniffing is limited to one second and supported protocols. Connections that expose no domain (IP-only without sniffable TLS/HTTP/QUIC data, ECH-encrypted handshakes) take the original route. The AI exit is TCP-only, so identified AI QUIC is rejected; TCP fallback depends on the client. Unrecognized QUIC may take the original route. This does not guarantee zero leakage. The Copilot token endpoint `api.github.com` is not routed, to avoid sending ordinary GitHub traffic to the AI exit. A domain list cannot guarantee complete coverage; new AI products need a rule-set update followed by *Apply changes*. *Test configuration* validates the configuration and probes the exit; its routing simulation evaluates rules and makes no real request.

## Web management panel

```sh
sudo rout            # 8 → 1 One-click install / initialize panel
sudo rout web setup  # the same wizard as a command
```

The wizard detects the distribution, architecture, init system and the public IPv4/IPv6 addresses (IPv6-only and NAT hosts are recognized), sets the admin password (generated and shown **once**, or typed twice and never echoed), installs the loopback-only `rout-web` service on `127.0.0.1:8790` and checks that it answers. If you enter an admin domain it then deploys HTTPS without any manual Caddyfile edit: it checks the A/AAAA records against this server (an IPv6-only server needs only AAAA), asks before installing Caddy or starting a stopped one, writes a separate Rout-owned site file next to the subscription site, validates it with `caddy validate`, reloads Caddy, and verifies the local service, the Host allow-list, the certificate, the public HTTPS endpoint and the login page. Failures of validation or reload are rolled back; a certificate that is still being issued keeps the valid configuration and `rout web https repair` (or menu 8 → 6) resumes. The subscription domain is never reused: for `hk.example.com` the wizard suggests `panel.hk.example.com`. **Automatic HTTPS works on Debian/Ubuntu with systemd** (the real-Caddy test runs on Debian 12); on Alpine/OpenRC, other distributions and non-standard Caddy installs the panel installs and runs the same way, but Rout prints the Caddy site for you to add to your own proxy instead of editing anything (`rout web https DOMAIN`). Without a domain the panel stays reachable through an SSH tunnel. See [docs/WEB.md](docs/WEB.md).

## Subscriptions

A subscription is a private URL with two native formats: the unchanged Base64 node list (`GET /s/TOKEN`) and a complete Mihomo YAML configuration (`GET /s/TOKEN?format=mihomo`; `format=clash` is an alias for Mihomo, not legacy Clash). Both use the same token, selection and ordered node settings, without a converter service or a second subscription. It is a link-management feature, not a proxy client, and covers only nodes you select by hand. Menu: **Subscriptions** (the seventh entry).

1. **Create** — *Create subscription*: name it, pick nodes from the numbered list (several at once, e.g. `3 1 2`; the order you type is the subscription order), review, confirm. The access token is saved privately so **View subscriptions** can show complete Base64, Mihomo and Clash URLs later. Authentication still uses its SHA-256 in state.json. Nodes are never added automatically, and "all nodes" is not offered. A node may be in several subscriptions. Relays are listed only if they have a share link.
2. **Edit** — rename, add, remove, reorder, enable/disable. Edits keep the token. Links are generated per request from the current nodes, so renamed, moved or re-keyed nodes show up on the client's next update; disabled nodes are left out until re-enabled; deleted nodes are removed from every subscription.
3. **Serve** — *Subscription server settings → Enable*. The server is **off by default**, listens on `127.0.0.1:8787` (port configurable, loopback only), runs as the `rout-subscription` systemd/OpenRC service and starts at boot. It never opens a firewall port.
4. **Publish over HTTPS** — choose *Subscription server settings → Deploy / repair HTTPS automatically*. Enter your domain; Rout checks A/AAAA records and TCP 80/443, asks before installing Caddy from Debian/Ubuntu's signed apt repository, validates an isolated fragment and the shared layout, then verifies TLS and an authenticated subscription response. Caddy handles automatic certificate issuance/renewal. A working existing proxy is detected first: **Use existing HTTPS configuration** preserves it without taking ownership or restarting it. Optional adoption is limited to an explicitly confirmed, standalone simple imported fragment; shared/manual configurations remain external and cannot be deleted by Rout. Other platforms/layouts can keep their existing HTTPS proxy and set its public URL in the CLI.
5. **Import** — keep `https://sub.example.com/s/TOKEN` in Shadowrocket/Base64 clients. For Clash Verge Rev, FlClash or Mihomo Party, add `https://sub.example.com/s/TOKEN?format=mihomo` as a remote configuration. Use your configured domain/prefix, and append the query to the original saved URL. Newly created/rotated subscriptions keep all three complete URLs available under View subscriptions. Legacy hash-only entries show templates and recovery guidance. No token rotation, node reselection, client reimport or Caddy change is needed for existing Base64 clients. Mihomo responses use `application/yaml; charset=utf-8`; both formats use `Cache-Control: no-store`.
6. **Rotate** — *Rotate access token* invalidates the old URL immediately. The new URLs are displayed and saved for later viewing. *Delete* also revokes the URL at once.
7. **Data and expiry** — *Edit subscription → Data and expiry* (or `rout subscription plan`). Set a **shared data allowance** for the whole subscription (all its nodes draw from one pool), a **monthly reset day** and a **plan expiry date**. Clients then show the screenshot-style lines *Remaining data: 31.27 GB*, *Days until reset: 3*, *Plan expires: 2026-11-27* as three informational entries (first in the Base64 list; their own "📊 Info" group in Mihomo, never in Auto/Fallback) plus the standard `Subscription-Userinfo` usage bar. The entries are inert placeholders on a closed loopback port, in the language chosen in Settings. When the pool is used up, Rout stops the subscription's nodes (checked about every 5 seconds by the traffic monitor, so a few seconds of overshoot are possible; each node's own kernel limit still applies independently) and starts them again at the next reset; a node you restart by hand is stopped again. The expiry date is informational: it never disables a subscription, and once passed it shows the same day of the next month. A subscription without these settings is unchanged byte for byte. Needs `rout traffic install`; see [docs/SUBSCRIPTIONS.md](docs/SUBSCRIPTIONS.md#data-allowance-and-expiry).

**Upgrading from v0.3.4 preserves existing subscriptions and URLs.** IDs, names, token hashes, enabled state, selected nodes/order, local port and public domain are retained; no schema migration, token rotation, recreation or client reimport is needed. Hashes cannot recover the original plaintext token: use the complete URL already saved in Shadowrocket. Legacy hash-only entries show URL templates; newly saved tokens remain viewable. The newer installer/updater snapshots private persistence and refreshes only the subscription helper; the older v0.3.4 updater keeps its old helper serving, and opening the new subscription menu or running `sudo rout subscription refresh` updates it safely.

**DNS and ports:** all A/AAAA records must point to appropriate origin addresses. Cloudflare proxy records are identified as inconclusive origin evidence; DNS-only is preferable for initial issuance. Rout never stops nginx/Apache/other listeners or changes a node's port/firewall. Automatic management supports Debian/Ubuntu with systemd. Diagnostics separate loopback, reverse proxy, origin-local TLS, a request through public DNS from this server, and independent external verification. A root 404 is expected. Always check the original client subscription from an external network; local success does not prove public availability.

**Failure/removal:** deployment is transactional, with private backups, digest-verified ownership, atomic files and verified rollback where possible. Failures report incomplete rollback explicitly. Disabling/restarting the subscription service preserves Caddy; dedicated confirmed HTTPS removal preserves subscriptions, tokens, unrelated sites and certificates and never uninstalls shared Caddy. See [deployment, adoption, rollback and troubleshooting](docs/SUBSCRIPTIONS.md).

Responses are deliberately uniform: unknown, malformed, disabled, revoked or deleted tokens all get `404`; only `GET`/`HEAD` are accepted; if a valid subscription currently has no usable node it returns `503` (never an empty success that could wipe a client's list) and the reason is logged by node name. Details, troubleshooting and security limits: [docs/SUBSCRIPTIONS.md](docs/SUBSCRIPTIONS.md). Mihomo output includes ordered proxies, manual/auto/fallback groups and one `MATCH` rule; it does not configure DNS, TUN, listener ports or a management API. Importing a complete remote configuration replaces its rules: use client overrides or proxy-provider integration to retain your own routing preferences. Supported native conversions are VLESS Reality/Vision, Shadowsocks 2022, Hysteria2 and TUIC; supported relay links additionally cover plain/TLS VLESS, Trojan and their TCP/WS/gRPC transports. AnyTLS Reality, UDP-only SS, unsupported relay options and protocols absent from Rout (including VMess) are not guessed. Mixed selections omit incompatible nodes with comments, logs and a skipped-node count; no compatible node returns 503. Hysteria2/TUIC use the actual server certificate SHA256 pin, never unchecked TLS. Health checks are lazy at 600 seconds, with a configurable HTTPS test URL under Subscription server settings. No runtime dependency was added. **Surge** has its own output, `?format=surge`: the Surge lines of the subscription's Snell nodes (the only nodes Surge needs a list for; Snell has no share link, so Base64 and Mihomo skip them with a diagnostic instead of converting them). Other output formats, a web UI, arbitrary external node import and per-device tokens remain outside scope. Automated tests verify unchanged Base64 bytes/order, original tokens, real Mihomo configuration validation and live TCP/UDP traffic. Production VPS, Shadowrocket and desktop GUI behavior still require manual acceptance.

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

### Layered connectivity tests

`rout test ID` and *Test relay* / *Test outbound proxy* check one layer at a time and say which layer failed and why, instead of one generic "request failed":

| Layer | What is proved |
| --- | --- |
| 1 Local listening | The sockets are bound (read from the kernel's socket tables, per family and address); an IPv6-only entry with a stray IPv4 socket is flagged |
| 2 Destination resolution | What the name resolves to (IPv4 and IPv6), whether the outbound policy fits, a name that points back at this host |
| 3 Destination connectivity | A real TCP handshake with the family and address used and its latency; failures are told apart: DNS error, connection refused, timeout, no route, policy mismatch, loop. UDP: a QUIC Version Negotiation probe for Hysteria2/TUIC (any QUIC server must answer it); other UDP is never claimed verified |
| 4 Relay availability | A connection through the relay's own entry (each family it serves) reaches the destination: bytes arrive, or the connection stays open; a relay that accepts and immediately drops is a failure, not "listening ✓" |
| 5 Proxy protocol | TLS camouflage handshake for Reality links; SOCKS5/HTTP(S) credentials; with sing-box, the real client handshake (failure hints: Reality / authentication / TLS / refused / timeout) |
| 6 Real exit | A request through the whole chain: IPv4 exit, IPv6 exit, which family worked, failing stage and error |

If only a TCP port is reachable the report says `! The proxy protocol handshake has not been verified` and the verdict does not call the node usable. The exit address services are queried through the chain, so layer 6 needs Internet access from the VPS.

## Commands

```sh
rout                          # interactive menu
rout list | status            # nodes with links | service state
rout doctor [--fix]           # diagnostics
rout test ID                  # layered test: listening → resolution → connectivity → relay → protocol → real exit
rout export ID [FILE] | export all [FILE] | copy ID
rout restart|on|off|delete|logs ID
rout relays | outbounds | settings   # `exits` still works as an alias
rout ai [status|test|apply]   # AI Smart Routing menu | status | check configuration + end-to-end exit test | re-apply
rout web setup                # one-click panel install: service, password, domain, Caddy HTTPS
rout web https deploy DOMAIN [--install-caddy] [--start-caddy] [--accept-nat]
rout web https repair|status|remove   # resume / diagnose / remove the panel's HTTPS site
rout web [install|start|stop|restart|status|logs|uninstall|passwd|host]
rout subscription [list|status|restart|https|logs|plan|serve]   # subscriptions menu | list | server status | HTTPS deployment/diagnostics/removal, sanitized logs and restart | data allowance and expiry | server process
rout traffic                  # usage of all nodes
rout traffic show|manage|recover ID
rout traffic install          # install/update accounting (no node restarts)
rout cert [ID] | cert renew ID
rout apply                    # validate and re-apply all nodes
rout backup FILE | restore FILE
rout engines | update | uninstall | version | help
```

Global options work before or after the command: `--lang en|zh-CN|zh-TW`, `--home DIR`, `--bin-dir DIR`. `--service none` is for development only.

## Files, services and security

- Configuration `/etc/rout` (0700; files 0600): `state.json` (nodes, relays, outbound proxies and the optional `ai_routing` block), `traffic.json`, `settings.json` (language, server address and family, `backup_keep`, subscription server port and public URL). Subscriptions live in the optional `subscriptions` array of `state.json` (token hashes only). New token copies live separately in `secrets/subscription-tokens.json` (0600, parent 0700), excluded from state backups, diagnostics and HTTP access.
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
| IPv4-only / IPv6-only / dual stack | Supported; inbound family chosen per entry (IPv4 / IPv6 / dual stack), outbound family chosen per relay; detection and tests do not require IPv4 |
| Relays from older versions | Keep running on GOST with their old configuration; *Change network* moves one to the native forwarder |
| Downgrade after using the family settings or Remote server exits | Older Rout cannot read Remote server exits (`protocol: node`); restore a compatible backup first. Native relays would run as GOST relays with their saved listening address (dual stack and IPv6-only are then not honored) |
| Existing NAT-VPS mappings | Keep working; not offered for new setups (see Legacy NAT-VPS mappings) |
| OpenVZ / restricted LXC | Proxies work; accounting needs nftables + `CAP_NET_ADMIN` |

Real-host acceptance items outside CI: IPv6 reachability from real client networks, provider NAT reachability, behavior on the 1 GB VPS that reported the OOM kill, physical reboots and power loss, NIC offload and sustained high rates. Each node table adds a small per-packet cost; Rout is tuned for tens of nodes per host.

See [docs/AI_ROUTING.md](docs/AI_ROUTING.md) for reproducible real-network tests, US/Canada VPS acceptance commands and the release gate. No real VPS acceptance is claimed by automated local tests.

## Development and releases

Go 1.23+ (CI builds with the current stable Go); the only third-party Go dependency is `gopkg.in/yaml.v3`. The web panel is built with Node 22 from `web/` and embedded into the binary; see [docs/WEB.md](docs/WEB.md) and [docs/REMOTE_SUBSCRIPTIONS.md](docs/REMOTE_SUBSCRIPTIONS.md). Rout is original code, with workflow inspiration from [singbox-deploy](https://github.com/caigouzi121380/singbox-deploy). Forwarding and proxy engines are separately downloaded [GOST](https://github.com/go-gost/gost) and [sing-box](https://github.com/SagerNet/sing-box), under their own licenses.

```sh
go test -race ./... && go vet ./...
go build -o rout ./cmd/rout
./rout --home /tmp/rout-state --bin-dir /tmp/rout-engines --service none engines
ROUT_TEST_ENGINES=/tmp/rout-engines go test -race -count=1 -v ./internal/rout
```

Test layers: unit and simulated tests (fake meter, scripted English/Chinese UI) always run. Engine integration tests send real encrypted traffic for all five protocols, SOCKS5, HTTP and HTTPS CONNECT outbound proxies and TCP/UDP relays, including relays built through the interactive flow (`ROUT_TEST_ENGINES`). Kernel tests run real nftables in a disposable network namespace (`ROUT_TEST_NFT=1`), covering seal/reboot/crash recovery, batching, preservation of unknown historical tables, probe cleanup, multiple limited nodes, and upgrade/rollback against the published v0.2.1 binary. A Debian 12 container additionally checks real nftables 1.0.6 JSON/text compatibility and failure cleanup (see [traffic testing](docs/TRAFFIC.md#real-compatibility-regression-tests)). Init tests need a disposable root host: systemd (`ROUT_TEST_SYSTEMD=1`, `ROUT_TEST_TRAFFIC_SYSTEMD=1`) or OpenRC (`ROUT_TEST_OPENRC=1`). Native Hysteria URI tests use `scripts/test-native-hy2.sh`. Native Mihomo tests use the checksum-pinned core from `scripts/test-mihomo.sh` with `ROUT_TEST_MIHOMO`; they validate YAML and send real TCP/UDP traffic, including rejection of incorrect certificate pins. Real-systemd subscription upgrade tests exercise the published v0.3.4 binary and a helper built from the pinned v0.3.5 commit (that release has no binary assets). Engine-installation tests (download failure, corrupt archive, checksum mismatch, killed installer, concurrent installers, peak RSS of a 96 MiB engine against the old in-memory approach) run in every `go test`; IPv6 and dual-stack tests skip themselves on hosts without an IPv6 stack.

Three kinds of tests are kept apart. **Unit and simulated** tests (injected DNS/dialers, fake sockets, scripted UI, loopback sockets, the native forwarder run in-process) always run; they cover the family model, policies, dynamic domains, capability refusals, exits and migration, and they run IPv6 cases only where the host has IPv6. **Engine integration** tests (`ROUT_TEST_ENGINES`) start the official Snell v5 and v6 servers on the configuration Rout writes and check that they listen, and send real VLESS Reality, AnyTLS, Shadowsocks, Hysteria2 and TUIC traffic through the native forwarder, a remote-node exit with right and wrong credentials, and an IPv6-only node refusing IPv4 clients; the real `rout relay-serve` process is started and stopped, and under real systemd the relay runs in the hardened unit. **Real-network** tests (`ROUT_TEST_REALNET=1`) resolve and dial real public hosts with each outbound policy and probe a public QUIC server; they are off by default and skip on a machine without direct Internet access. None of these is a VPS/NAT acceptance test: loopback and CI success says nothing about a provider's NAT, firewall or IPv6 routing.

`install.sh` is tested as shipped (checksum, version, atomic replacement, missing release fails closed; `scripts/test-install.sh`, also run by `go test`), and a CI guard fails any push to `main` whose installer points at an unpublished release. CI runs everything above plus `govulncheck` and cross-compilation on every push. **Releases are published only from an explicit version tag** that matches the compiled version and `install.sh`; pushes to `main` never publish. Release publication verifies all updater assets and public downloads; existing releases are completed safely instead of skipped. An explicit repair workflow builds the original tag commit without moving it. See [release integrity and repair](docs/RELEASING.md).

```sh
# Only after exact-commit CI and real VPS acceptance, with the maintainer's approval.
# Publish BEFORE merging: main's install.sh pins this version (docs/RELEASING.md).
git tag -a v0.5.1 -m 'Rout v0.5.1' <verified-pr-head-sha>
git push origin v0.5.1
# ...wait for the release to be public, then merge the PR with a merge commit.
```
