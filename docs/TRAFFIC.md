# Traffic accounting and quotas

## Scope and prerequisites

Every managed listener, including unlimited nodes and raw relays, is metered once monitoring is installed. Existing v0.2.0 nodes remain unlimited. Nothing can reconstruct traffic before installation: legacy nodes explicitly show an incomplete cycle and the observation start time. New nodes created with monitoring active start at zero. A legacy/incomplete node needs a confirmed accounting reset or the next billing cycle before a reliable finite allowance can be issued.

The implementation uses Linux **nftables**, not a sing-box statistics API, interface-wide counters, a database, or traffic estimates. Required kernel/userspace features: `inet` input/output hooks, named counters and quotas, timeout sets, table comments and JSON listing. Root with `CAP_NET_ADMIN` is required. Restricted NAT containers/OpenVZ hosts may not grant it: statistics are then unavailable, not fictitious zero usage, and finite quota setup is refused. Existing unlimited proxy services continue to work.

Install `nftables` (`apt install nftables` or `apk add nftables`), then run:

```sh
sudo rout traffic install
sudo rout traffic                 # All entries, without printing share credentials
sudo rout traffic show NODE_ID
sudo rout traffic manage NODE_ID   # Or Node Management -> Traffic management
sudo rout traffic recover NODE_ID  # Resume a fault-paused node, keeping known usage
```

The normal installer installs this small dependency and enables the monitor for the default installation directory. The first interactive menu also attempts setup after language selection. `ROUT_SETUP_TRAFFIC=0` skips installer setup. Custom installation paths require explicit setup with matching `--home` / `--bin-dir`. `--service none` is test-only and cannot install production services.

## Exact accounting definition

| Field | Measurement point |
| --- | --- |
| Upload | Client -> local node listener: packets reaching Rout's input hook and passing its admission gate |
| Download | Local node listener -> client: packets reaching Rout's output hook and passing its admission gate |
| Charged total | Upload bytes + download bytes, for that listener only |
| Units | 1 MB = 1,000,000 B; 1 GB = 1,000,000,000 B; 1 TB = 1,000,000,000,000 B |

The counter unit is the **Linux L3 `skb->len` at the nftables hook**, not application payload or a packet capture's Ethernet frame size. Byte integers are stored exactly; the UI also prints exact byte values alongside human-readable decimal units. TCP/UDP and IPv4/IPv6 share the same mechanism. Match the local socket port and, where applicable, local listen address, **after inbound DNAT and before outbound SNAT**. The advertised public/NAT port is not counted a second time.

Includes IP/TCP/UDP headers, encrypted protocol/TLS/QUIC overhead, retransmissions, ACKs and unauthenticated/failed-handshake traffic that passes the gate. Excludes packets dropped by the quota/lease gate, other services' traffic, and the separate node-to-origin/proxy-exit leg. HTTP/SOCKS exit traffic is therefore not double billed, and several nodes sharing one exit retain independent counters. Traffic deliberately traversing two managed nodes is attributed once to each logical node, not mistaken for a shared exit.

Rout's rules run at priority 300 and never accept traffic around another firewall's drop. A later host firewall/network-stack decision may still discard an admitted packet. GRO/GSO, fragmentation/reassembly, tunnel encapsulation, link-layer overhead and traffic denied before Rout all make this different from bytes on a physical wire. Local diagnostic connections/probes to a node also consume that node's allowance.

**These are not VPS-provider invoice counters.** Providers may count both physical legs, dropped incoming traffic, Ethernet/tunnel overhead, other services, different directions, units and billing windows. Provider totals can exceed Rout totals, including after a quota has stopped client forwarding. Rout cannot prevent an external sender from continuing to send packets to a dropped port.

## Enforcement and fault handling

Each node has a private `inet rout_<home-hash>_<node-id>` table. Two directional counters and one shared named byte quota cover all that node's entry transports. No TUN/default route, global firewall flush, per-interface limit or shared-exit switch is used. The current architecture has a separate engine process per node; classification is listener-based, not process-wide, and remains isolated if test listeners share a process.

An unlimited node has **no quota and no expiring permit**. Only an explicit positive user limit creates the quota and the 15-second kernel health lease. The limit applies to the current cycle's already-recorded bidirectional usage, not only future bytes. Raising/cancelling a quota is explicit; raising a quota cannot erase a metering gap. Confirmed reset requires both `y` and the literal `RESET` in the UI.

The kernel shared quota updates atomically across directions/CPUs and drops the packet that would exceed its remaining budget, including packets on existing TCP/UDP flows. Successful admission counters are after that gate; denied attempts do not inflate reported upload/download. Consequently the last indivisible packet/SKB may exhaust the quota while admitted totals are slightly below it. At the accounted admission point there is no polling-rate-times-bandwidth overshoot; the gate does not wait for a 5-second userspace check. Already-admitted packets may still be in flight or socket buffers. Do not reinterpret this as a zero-overshoot guarantee for application delivery or physical/provider bytes; neither has a universal byte bound without bounds on buffers, offload sizes and external traffic.

The monitor observes exhaustion and stops **only** that node's engine/service, terminating its sockets. Normal detection cadence is 5 seconds plus processing/service-stop latency. Service-stop errors do not release the kernel gate. Service start/stop commands always run **after** the traffic lock is released: enforcement is already in the kernel, so a slow init system can never delay other nodes' lease renewals. An explicit manual pause is the existing `enabled` flag; automatic quota/fault/sealed pauses live in `traffic.json`, so a new cycle cannot undo a user's manual pause.

Finite-node systemd `ExecStartPre` / OpenRC `start_pre` checks a separately installed guard executable, current boot, durable record, quota, rule hash and the generated listener configuration. `rout on`, `rout restart`, `rout apply`, service restarts and old backups do not clear usage or an exhausted flag. systemd also orders the node after the monitor. The helper remains independent of replacing the main manager binary.

Only successfully checkpointed, structurally verified meters get a renewed lease. All leases are renewed in one nft transaction per poll. SIGKILL/hang/disk-write failures leave the hard quota active; if monitoring stays unavailable, finite admission closes within the remaining **15-second lease**, even without a running monitor. The lease length is unchanged in v0.2.2: renewals no longer wait behind service commands, which removes the cause of spurious expiry without widening the unpersisted window. A failed renewal simply lets the lease expire (counters stay exact) and is retried; it does not become a permanent fault. Unlimited nodes have no lease and are never paused for a monitoring fault — if their meter cannot be rebuilt, the table is removed (fail open) and the gap is marked. Verified-counter heartbeats use a separate cross-process lock so a long unrelated configuration operation cannot expire other nodes' permits. All locks use bounded waits; a holder that never releases produces an explicit timeout, not a hang.

### Restart, reboot and crash recovery

| Event | Finite node afterwards | Usage |
| --- | --- | --- |
| Graceful monitor stop/restart, normal shutdown/reboot | Resumes automatically after verification | Exact; remaining budget exact |
| Same-boot upgrade from a v0.2.1 monitor | Resumes automatically after verification | Exact |
| Quota exhausted before the restart | Stays quota-paused until the next cycle | Exact |
| SIGKILL, crash, power loss, or a checkpoint that cannot be verified | Fail-closed pause (`fault`) | Known bytes kept; the gap is unknown |
| Corrupt/unreadable `traffic.json` | Fail-closed pause | Recover only by confirmed reset/unlimited |

**Sealed checkpoint.** On graceful shutdown the monitor first closes the node's kernel gate (drop), then reads and persists the final counters, records the generation hash and marks the record `sealed`. No byte can be admitted after the seal. On start, only the monitor may reopen a seal, and only if it verifies that the kernel cannot have admitted bytes since: in the same boot the frozen table must still exist with identical counters and structure; after a reboot no Rout table for the node may exist (a table restored by a firewall loader is not trusted). The kernel generation is then rebuilt from the persisted counters and quota, so the remaining budget is exact. Any failed verification produces `fault`. The same rule restores quota-paused nodes across reboots. v0.2.1 wrote its graceful checkpoint as `fault` without a gap; within the same boot it is verified the same way, across a reboot it stays a fault.

**Explicit recovery.** For a fault-paused node, `rout traffic recover ID` (or Traffic management → Resume with known usage) reopens the node **without** resetting anything: known usage stays, the cycle remains marked incomplete and its total is a lower bound, and the quota continues from it. The bytes during the gap (at most the last uncheckpointed seconds) are not counted; this is shown before confirmation. A confirmed reset (`y` + `RESET`) or the next billing cycle are the alternatives. Enabling a **new** cap on a cycle that already has a gap asks whether to keep known usage, reset, or cancel.

If counters/rules disappear, decrease or change shape unexpectedly, finite nodes are protectively paused and the gap is shown explicitly; unknown history is never reported as measured zero. A same-boot monitor crash can recover still-valid kernel counters without losing or adding the last snapshot twice.

The monitor removes only orphaned tables of its own installation (Rout comment, this home's prefix, no matching node). `rout doctor` lists them and `rout doctor --fix` removes them after confirmation.

An administrator deleting all firewall rules, changing engine configuration outside Rout, bypassing the local input/output hooks through another namespace/TUN/offload, replacing the guard, or killing all protection mechanisms is outside the enforcement boundary. Unexpected rule deletion has a detection/stop window; no universal byte maximum can be promised without a known link-rate bound. Do not run `nft flush ruleset` or a firewall reload that removes Rout's tables. Host/container firewall persistence and boot ordering must be checked on the actual VPS.

## Persistence and billing windows

Go standard library only. `/etc/rout/traffic.json` is an atomically renamed, file+directory-fsynced, SHA256-checksummed JSON journal (`0600`, parent directory `0700`). It contains counters and control state, no node passwords, private keys or share URIs. Both the manager and monitor use cross-process file locks; only one monitor runs for a configuration directory. Snapshots contain absolute kernel totals and cycle baselines, **never repeatedly accumulated deltas**. Invalid/negative/decreasing counters and sum overflow are rejected.

Checkpoint cadence is 5 seconds plus work/I/O/scheduling latency; shutdown also checkpoints. Polls whose counters and control state are unchanged skip the fsynced rewrite; the journal is still refreshed at least every 15 seconds as monitor liveness for start guards. On a healthy warm restart, counters in the kernel cover bytes since the last file write. A power loss/reboot can lose that interval from statistics; a prolonged disk failure or unlimited monitor outage can make the interval longer. A conditional byte-loss bound is `aggregate measured rate × uncheckpointed duration`; without a rate/duration bound there is no honest fixed MB bound. Incomplete usage is displayed as a known lower bound, never estimated. Finite nodes do not receive a new same-cycle allowance after such a gap.

The default billing day is the 1st, in the server's local timezone. Per-node settings support days 1–31 and IANA timezones (timezone data is embedded for minimal Alpine systems). Out-of-range month dates clamp to its last day, including leap-year February. Boundaries are civil midnights, not fixed 30-day durations. The monitor advances to the current window after offline months, once, and resets upload/download baselines plus the shared quota. Unlimited nodes also reset. At a boundary, application happens at the first successful monitor reconciliation (normally within one poll plus processing); counters do not contain per-packet timestamps, so bytes around that sampling boundary cannot be retrospectively divided at an exact nanosecond. A busy configuration transaction may delay a reset, not grant extra quota.

Persisted cycle bounds and a last-seen wall-clock high-water mark prevent duplicate reset/recovery after clock rollback. An incorrect forward time jump can advance a window once; correcting time backward does not mint another one, and resets wait for the clock to catch up. Keep the host clock synchronized. Changing billing day/timezone schedules the next future boundary but **does not clear current usage**. Manually paused nodes remain paused after rollover; only quota/fault-paused, manually enabled nodes are eligible to restart.

Missing/corrupt/unreadable state and disk-full errors never silently create a fresh finite budget. A confirmed reset/unlimited recovery can quarantine corrupt readable state in a private backup and explicitly restart that node's observation; other finite nodes remain protected, and unavailable history stays marked incomplete. Permission/disk failures still need operator repair. Configuration backups contain limits, not a live kernel-counter snapshot; see [upgrade/rollback guidance](UPGRADING.md).

## Verification boundary

Automated coverage includes real nftables rules in disposable Linux network namespaces: exact IPv4/IPv6 UDP L3 byte counts; 99%, 100%, over-limit attempts; existing TCP/UDP and new connection drops; same-process listener isolation; local DNAT; two nodes sharing one SOCKS exit; native encrypted traffic and quota cuts for VLESS/AnyTLS/SS/HY2/TUIC with direct/SOCKS5/HTTP exits; killed-monitor lease expiry, warm recovery, and long configuration-lock heartbeats. Root/systemd tests verify actual engine stop, direct `systemctl start` rejection, metadata/unrelated PID preservation and reset-driven service recovery. Unit tests cover calendar/timezone/clock cases, integrity faults, persistence failures, confirmation and compatibility.

Kernel tests also cover sealed restart/reboot recovery with exact remaining budgets, crash fail-closed plus known-usage recovery, quota persistence across reboot, batched-read equivalence with single-table reads, orphan cleanup that never touches foreign tables, three simultaneous limited nodes beyond one lease period, and a real upgrade from and rollback to the published v0.2.1 monitor. Simulated (fake-meter) tests cover lock contention, slow service commands running outside the traffic lock, renewal failures, unlimited fail-open and redundant-write avoidance. CI performs kernel, systemd and OpenRC tests.

**Performance.** Measured in a network namespace with nft 1.0.9: per-node lease renewal took 0.9 s for 50 and 3.5 s for 100 limited nodes per poll; the single batched transaction takes 31 ms and 51 ms. Each node still owns its own table with input/output base chains, which keeps per-node isolation and atomic replacement; small-packet loopback throughput is unaffected at 10 nodes and drops noticeably beyond about 30. A single-table design is a candidate for a future release once live-counter migration can be proven safe. Synthetic clock/kernel-generation loss exercises recovery logic but is **not** a physical VPS power-cycle test. Alpine/OpenRC boot/lifecycle, provider-side NAT/IPv6 firewall behavior, physical reboot/power loss, NIC offload and sustained high-rate/many-node performance remain real-host acceptance items.
