# Changelog

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
