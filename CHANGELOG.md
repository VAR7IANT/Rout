# Changelog

## v0.3.4

Release candidate preparation; not tagged or published.

- **Subscriptions.** Independent, token-protected Base64 share-link subscriptions for manually selected nodes (`GET /s/{token}`), managed from the new **Subscriptions** menu (seventh entry; existing menu numbers are unchanged) or `rout subscription [list|status|restart|serve]`. Create, list, rename, add/remove/reorder nodes, enable/disable, delete and rotate tokens. Nodes are never added automatically; a node may belong to several subscriptions; selection is stored as node IDs.
- **Data and tokens.** Optional `subscriptions` array in `state.json` (schema unchanged; v0.3.3 state loads as-is). Tokens are 256-bit `crypto/rand` values, shown once; only their SHA-256 is stored and compared in constant time. Rotation invalidates the old token atomically. Changes use the configuration lock, a fresh read, a backup and an atomic write, and never touch nodes, services or traffic accounting. Deleting a node removes it from all subscriptions.
- **Generation.** Links come from `Profile.URI()` per request, so renames, address/port and credential changes apply on the next fetch. Disabled and deleted nodes are skipped; failures are logged by node name. A valid subscription with no usable node returns `503`, never an empty `200`. Unknown, malformed, revoked and disabled tokens all return an identical `404`; only `GET`/`HEAD`; `text/plain` with `Cache-Control: no-store`.
- **Server.** Standard-library HTTP server, loopback only (`127.0.0.1:8787` by default), disabled until enabled, with timeouts, connection and in-flight limits and graceful shutdown. Runs as the separate `rout-subscription` systemd/OpenRC service from a copied helper binary (run `rout subscription restart` after `rout update`); the systemd unit has a read-only filesystem and no capabilities. Never opens ports, installs a proxy or requests certificates; only an `https://` public URL is accepted and otherwise a template with a warning is shown.
- **Docs and tests.** [docs/SUBSCRIPTIONS.md](docs/SUBSCRIPTIONS.md); English/Chinese translations; automated tests for lifecycle, tokens, output, HTTP behavior, concurrency, compatibility and menus. Real systemd/OpenRC start-up and real-client import still need manual acceptance. Out of scope: Clash/Mihomo/sing-box/Surge formats, web UI, external imports, per-device tokens.
- Installer default and version bumped to 0.3.4.

## v0.3.3

- Fix traffic installation and accounting on Debian 12 / nftables 1.0.6, whose JSON omits the table comment. Verify the exact target table's top-level text comment when absent, normalize it before hashing, and retain counter, chain, hook, rule and quota integrity checks. Single and batched reads use the same attestation.
- Refuse to overwrite or delete an existing table without verified Rout ownership. Preserve all historical orphan tables whose purpose cannot be proved; read-only `rout doctor` reports them even before monitoring is enabled. Only distinctly named, verified new installation probes can be offered for confirmed cleanup.
- Create installation probes exclusively and always attempt deferred cleanup after successful creation, including read/parse/permission failures; report cleanup errors with the exact table name. Failed probes never replace the helper or create a success marker. Failed service activation restores the previous helper, service definition and marker, with rollback errors reported.
- Preserve surviving kernel counters/quota consumption if the first sync has no journal, marking the history incomplete and finite nodes fail-closed. Keep recorded usage, billing cycles, quotas, dual-direction accounting and fail-closed leases unchanged. No state migration, usage reset, node recreation or engine changes.
- Add real Debian 12 nftables 1.0.6 tests and retain the newer Ubuntu nftables, systemd and Alpine/OpenRC regressions. Real nft JSON/text fixtures are checked in; unavailable kernel capabilities are explicitly skipped, never counted as coverage.

## v0.3.2

Release candidate preparation; not tagged or published.

- **AI Smart Routing.** Server-side routing of AI-service domains to a chosen outbound proxy, for explicitly selected inbound nodes only. Settings (`enabled`, `bound_inbound_ids`, `ai_outbound_id`, `rule_set_version`) are stored in `state.json` under `ai_routing`; unbound nodes' configuration files are never rewritten; disabling restores the original files; an empty binding binds nothing; deleted inbounds are pruned and stale references ignored; an unavailable AI exit fails closed instead of falling back. Versioned built-in rules for OpenAI/ChatGPT, Claude/Anthropic, Gemini, Google AI Studio, Hugging Face, GitHub Copilot and Cursor. All changes use the existing validate → back up → atomic write → health check → rollback transaction. `rout ai [status|test|apply]`
- **Menu refactoring.** Eight top-level entries became six: Quick create node, Manage nodes, AI Smart Routing, Port forwarding, Outbound proxies, Service & system. Selecting a node shows its connection link immediately; Quick create and *New node* share one implementation and can be cancelled at every step; Traffic and limits moved under Manage nodes; Services, Diagnostics, Updates and Settings moved under Service & system. Blue accent, ANSI-aware width handling, narrow-terminal wrapping of cards, hints and the status line
- **Secure AI exit transport:** explicit certificate-verified HTTPS CONNECT with TLS 1.2 minimum; existing HTTP/SOCKS5 remain unchanged with clear warnings and a documented authenticated SOCKS5-over-SSH procedure. No insecure TLS switch or plaintext retry. Proxy formatting/log output redacts credentials; service errors no longer forward raw init output.
- **Routing hardening:** normalize case and trailing-root-dot domain spellings (a real traffic test caught a suffix-matcher bypass); match explicit AI destinations before sniffing so a different HTTP Host/SNI cannot hide an already identified destination; bounded TLS/HTTP/QUIC sniffing then matches IP destinations. Enabling/applying rejects previously broken references instead of accepting a pre-existing fault. Quotas and billing cycles remain unchanged.
- **Real network coverage:** controlled proxies/origins and real sing-box processes test A/C binding, B isolation, both proxy address families, explicit domains, Host/SNI, UDP rejection, ordinary UDP, exit failures, disabling, HTTPS verification/authentication failures. Disposable systemd/OpenRC tests verify restart isolation and service-start rollback. Config/write rollback regressions remain covered.
- **Release preparation:** version/install/CI documentation aligned to 0.3.2; Linux amd64/arm64 assets include version.txt and verified SHA256 checksums. Installer rejects a checksum-valid binary with the wrong version before replacement. No tag, Release or VPS deployment is part of preparation.
- **Compatibility and limits:** optional `ai_routing` remains schema-compatible; old proxy transports and six menus are preserved. Older Rout cannot read the new `https` proxy protocol; explicitly restore compatible exits/backup before downgrade. Domain coverage, DNS, ECH, QUIC and pure-IP limitations and real VPS acceptance commands are in [docs/AI_ROUTING.md](docs/AI_ROUTING.md); no zero-leak or production acceptance claim.

## v0.3.1

Stability and usability release. Stored data is unchanged; v0.3.0 hosts upgrade in place.

- **Fix: engine installation killed on low-memory VPS.** The installer read the whole engine out of its archive into memory (peak 220–310 MiB for the 81 MB sing-box binary; OOM-killed at 160 MiB and below in a controlled cgroup test). Archives are now streamed to disk through a 256 KiB buffer with an incremental SHA256, the engine is streamed out of the verified archive, written data is flushed and dropped from the page cache every 8 MiB, and nothing is held in memory. Peak RSS is 44 MiB and no OOM kill occurs down to a 32 MiB limit
- Installation is atomic and safe: the staged binary must run before it replaces anything, a failure at any point leaves an existing engine untouched, staging directories are always removed (and stale ones left by a killed installer are reclaimed), and concurrent installers are serialized by a lock so the engine is downloaded once. `rout update` copies `rout.previous` by streaming instead of reading the binary into memory
- **No more NAT/VPS question.** Node creation, relay creation, server settings, prompts, help text and both translations no longer ask for a server type, NAT port ranges or public-to-private mappings. New entries use regular-VPS behavior: the public port equals the listening port, a free port is chosen automatically (TCP and UDP checked) and may be changed before saving
- Legacy NAT hosts keep working: saved NAT settings, existing NAT nodes and relays are read and run unchanged and are never migrated or rewritten; new entries on such a host follow the saved mapping with a notice; editing an existing NAT entry still asks for the provider-mapped public port; Settings → Server address → *Switch to a regular VPS* (confirmed) changes only the saved default
- **IPv4 / IPv6 / dual-stack.** Public addresses are detected per family (echo service, interface fallback) and link-local, unique-local, private, CGNAT and loopback addresses are never selected. IPv4-only and IPv6-only hosts need no question; dual-stack hosts choose IPv4 (default) or IPv6 once and the choice is remembered. A `::` listener is used only after a real test shows it also accepts IPv4, so one node and one set of credentials serve both families and a second link for the other address is shown (creation, copy link, export all, `rout list`). Newly typed public hosts are validated (no unspecified, multicast or link-local addresses; malformed dotted numbers such as `999.1.1.1` are rejected, while stored configurations keep the old, looser rule so they always load), IPv6 literals are bracketed in links and endpoints, relay destinations accept IPv6 literals, bracketed endpoints and IPv6 share links, and equivalent IPv6 spellings are recognised in loop checks. A node that listens on IPv4 only can be switched to `::` when an IPv6 public address is chosen
- **Simpler node creation:** detected address, base name once, one or more protocols, automatic ports and credentials, one confirmation listing every node with port and address, then complete links. Ports, custom credentials, Reality SNI and PEM certificates moved into *Change ports* / *Advanced options* of that confirmation; Reality targets are still verified from the server and self-signed HY2/TUIC certificates are the default
- **Simpler relay creation:** the saved server address is reused silently, the listening address is derived (no prompt), the destination host of a local relay is no longer asked, and the entry shows the listening address and public entry separately; remote destinations are never replaced by localhost
- Traffic accounting already covered `::` (inet tables), so dual-stack listeners are metered for both families
- New `scripts/measure-engine-memory.sh` measures an install inside a memory-limited cgroup
- Tests: download failure, corrupt/truncated archive, checksum mismatch, unrunnable engine, killed installer, concurrent installers, existing-engine preservation and temp-file cleanup; peak-RSS regression against the old in-memory approach; IPv4-only, IPv6-only and dual-stack setup, listener selection and links for all five protocols; IPv6 relay destinations; legacy NAT compatibility; automatic and manual ports with TCP/UDP conflicts; interactive defaults and cancel. Real-IPv6 and real-engine dual-stack tests skip themselves on hosts without IPv6

## v0.3.0

- Guided relay creation: Local machine or Remote relay server (remembered), the entry on the current server (listening address/port, and on NAT the separate mapped public port), the destination (local defaults to `127.0.0.1`; remote requires an explicit host and port and never reuses this server's public IP), then TCP, UDP or TCP+UDP with explanations
- Relay preview with the full path (client → public entry → listening port → destination, transport) before saving; client endpoint and rewritten share link after saving
- Relay checks: validation, NAT range, port conflicts, forwarding loops (own port, own public entry, chains of local relays; also enforced on commit); same-host forwarding allowed and a shared public IP never treated as a loop; real TCP reachability test; UDP never claimed as verified; offer to switch a relay aimed at this server's own node to `127.0.0.1`
- Relays menu: view, create, edit, test, delete; old relays load unchanged with an inferred type
- Relay entry reuses the saved server defaults: the planned listening address, free port and public endpoint are shown once and confirmed with Enter; answering `n` overrides address and port, and editing a relay's entry asks for each value. New ports are checked free for both TCP and UDP before the transport is chosen
- New main menu: Nodes, Relays, Outbound proxies, Traffic and limits, Services, Settings, Diagnostics, Updates, Quit; `b` goes back and `q` quits from any menu; numeric input unchanged
- ROUT banner once per interactive session (six-row logo in a blue gradient, "Support by VAR7IANT" and the version centered beneath it, narrow-terminal fallback); never for commands or pipes; honours `NO_COLOR` and `TERM=dumb`
- Terminology: "outbound proxy" replaces "exit"; "Quit" replaces "Exit"; relay destination, outbound proxy, listening port and public port are named consistently in Chinese and English
- Outbound proxies: numbered list with Direct connection; create, edit, test, delete, assign to chosen nodes in one transaction; IDs unchanged; nodes that cannot use a proxy (UDP-only Shadowsocks) are skipped with the reason
- One input normalizer for every prompt: case-insensitive and full-width tolerant; `[Y/n]` defaults for ordinary prompts, `[y/N]` for deletions; typed words (`reset`, `uninstall`) for irreversible actions
- Traffic limits in GB: a plain number is GB, MB/TB suffixes accepted, `0` or empty means unlimited; no reset word when setting a limit; the view shows upload, download, total, limit, remaining and next reset with the decimal-unit note
- Node cards show protocol, status, listening port, public endpoint, outbound, usage and limit
- Fix: relay share links rewritten from Shadowsocks 2022 links lost SIP002 percent-encoding of the key
- Traffic display truncates instead of rounding, so usage never appears to reach a limit early; nodes without accounting show their limit state
- Tests: engine integration tests wait for the engine's listeners (polled every 100 ms, 5 s limit, early-exit detection with logs) instead of a fixed 120 ms delay, which was flaky on cold hosts

## v0.2.2

- Fix Alpine/musl hosts: the pinned default sing-box build is glibc-linked and could not run there; Rout now selects the pinned, checksum-verified static musl build when the glibc loader is absent, and replaces an installed engine that cannot execute (run `rout apply` or `rout engines` on affected hosts)
- Fix limited nodes staying paused after a normal monitor restart or reboot: graceful shutdown now seals an exact checkpoint (gate closed before the final read) that the monitor verifies and resumes automatically, with exact usage and remaining budget; same-boot v0.2.1 checkpoints are verified too; quota-paused nodes stay paused across reboots
- Keep fail-closed behavior for crashes and unverifiable checkpoints, and add `rout traffic recover ID` / "Resume with known usage", which keeps usage as a marked lower bound; enabling a new cap on a gapped cycle offers keep/reset/cancel
- Fix random "another rout is modifying configuration" failures and rolled-back commits under monitor activity: bounded lock waits, shorter critical sections
- Fix lease starvation: service start/stop runs outside the traffic lock, renewal failures no longer become permanent faults, all leases are renewed in one nft transaction (100 nodes: 3.5 s → 51 ms per poll), reads are batched with per-node fallback
- Unlimited nodes fail open on meter errors and are never paused; orphaned Rout tables are cleaned up; unchanged checkpoints are not rewritten
- Health checks require a stable process with listening sockets; init-system output is included in errors; unchanged unit files are not rewritten
- systemd engines run with a capability bounding set and kernel protections (verified for all five protocols and TCP/UDP relays); OpenRC respawns and logs are bounded, and OpenRC nodes order softly after the network (`use net`) so a missing or restarting net provider can neither block nor stop them
- HY2/TUIC certificates: validity in list/status/doctor, warnings before expiry, `rout cert renew ID`, 10-year self-signed certificates; one expired certificate no longer blocks `rout apply` for other nodes
- Shadowsocks 2022 links follow SIP002 (percent-encoded userinfo); reject UDP-only Shadowsocks with a TCP-only exit; Reality targets are checked for TLS 1.3/HTTP/2 from the server
- IPv4 and IPv6 public address detection and tests work independently (IPv6-only hosts supported)
- New `rout doctor [--fix]`, `rout export all`, `rout cert`; redesigned bilingual menus with numbered exits, credential-free pickers, link export, saved server reuse and safe batch naming; global flags in any position
- Automatic backups keep the newest 20 (configurable) and handle low disk space
- `rout update` refuses downgrades, checks the staged version, keeps `rout.previous` and refreshes the monitor helper
- CI: tag-only releases with build-provenance attestations, govulncheck, current stable Go, systemd sandbox, Alpine/OpenRC and real v0.2.1 upgrade/rollback tests

## v0.2.1

- Add per-listener IPv4/IPv6 TCP/UDP accounting with exact known L3 byte counters, decimal MB/GB/TB display and bidirectional billing
- Default all old/new nodes to unlimited; expose legacy/unknown intervals instead of fabricated historical totals
- Add explicit independent node quotas using shared kernel nftables quotas and expiring health permits; stop only the exhausted node and guard init-manager restarts
- Separate manual enable/disable from durable quota/fault pauses; retain limits through ordinary edits, apply and configuration rollback
- Add monthly billing days 1–31, local/IANA timezones, last-day clamping, rollover recovery, clock-rollback protection and double-confirmed manual reset
- Add atomic fsynced/checksummed private traffic state, absolute-counter reconciliation, separate lock-safe heartbeats, conservative cold-boot/error handling and explicit corrupt-state recovery
- Add bilingual Traffic Management, monitor setup, upgrade/rollback documentation, and an independent helper for systemd/OpenRC guards
- Preserve all v0.2.0 node creation, protocol, exit sharing, link export, language and NAT workflows
- Expand tests with real kernel counters/quotas, native five-protocol entry traffic, shared exits, listener isolation, DNAT, killed monitors, long configuration locks and actual systemd lifecycle/guard checks

## v0.2.0

- One server-type/base-name prompt per batch, NAT port ranges and automatic protocol suffixes
- Reusable independent SOCKS5/HTTP exits and complete node management/link display
- Persistent Simplified Chinese/English UI and automatic HY2 TLS/password generation
- Transactional preflight/rollback and protocol/systemd regression coverage
