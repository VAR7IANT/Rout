# Changelog

## v0.2.2

- Fix Alpine/musl hosts: the pinned default sing-box build is glibc-linked and could not run there; Rout now selects the pinned, checksum-verified static musl build when the glibc loader is absent, and replaces an installed engine that cannot execute (run `rout apply` or `rout engines` on affected hosts)
- Fix limited nodes staying paused after a normal monitor restart or reboot: graceful shutdown now seals an exact checkpoint (gate closed before the final read) that the monitor verifies and resumes automatically, with exact usage and remaining budget; same-boot v0.2.1 checkpoints are verified too; quota-paused nodes stay paused across reboots
- Keep fail-closed behavior for crashes and unverifiable checkpoints, and add `rout traffic recover ID` / "Resume with known usage", which keeps usage as a marked lower bound; enabling a new cap on a gapped cycle offers keep/reset/cancel
- Fix random "another rout is modifying configuration" failures and rolled-back commits under monitor activity: bounded lock waits, shorter critical sections
- Fix lease starvation: service start/stop runs outside the traffic lock, renewal failures no longer become permanent faults, all leases are renewed in one nft transaction (100 nodes: 3.5 s → 51 ms per poll), reads are batched with per-node fallback
- Unlimited nodes fail open on meter errors and are never paused; orphaned Rout tables are cleaned up; unchanged checkpoints are not rewritten
- Health checks require a stable process with listening sockets; init-system output is included in errors; unchanged unit files are not rewritten
- systemd engines run with a capability bounding set and kernel protections (verified for all five protocols and TCP/UDP relays); OpenRC respawns and logs are bounded
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
