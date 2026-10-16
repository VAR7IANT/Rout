# Changelog

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
