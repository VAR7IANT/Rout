# Upgrading to v0.2.1 and rollback safety

1. Keep your v0.2.0 configuration backup (`sudo rout backup /root/rout-before-021.json`). Backups contain authentication/private keys; protect them.
2. Install `nftables` on the VPS. Confirm the provider/container grants `CAP_NET_ADMIN`. Do not replace your host firewall configuration or enable a global `flush ruleset` cron job.
3. Run `sudo rout update`, or use the README installer targeting v0.2.1.
4. Run `sudo rout traffic install`, then `sudo rout traffic`. Monitor installation attaches accounting to existing listeners **without restarting nodes**. The installer and first menu attempt this automatically for normal installations.
5. Verify traffic with a real external client and compare entry-port changes. Old nodes stay **unlimited**; their first partial cycle is marked incomplete because pre-upgrade bytes cannot be recovered.
6. To enable a cap on a partial/gapped cycle, confirm an explicit reset (`y`, then `RESET`) or wait for the next cycle. Check each node's local/public ports, clock, reset day and timezone first. A local test is not a public NAT reachability test.

The pinned sing-box/GOST versions and node IDs, credentials, ports, individual services, naming, exits and saved language are unchanged. No database or API port is added. Entry admission rules are the only new firewall changes and are restricted to Rout-owned tables/listeners.

## Files and backup

- `state.json`: configuration. A missing `traffic` field means unlimited, day 1, server-local timezone. A policy example is `"traffic":{"limit_bytes":100000000000,"billing_day":31,"timezone":"Asia/Hong_Kong"}`. Use the UI, not live manual JSON edits, for policy changes.
- `traffic.json`: exact known kernel snapshots/baselines, cycle bounds, boot identity, rule hashes, incomplete/blocked/pending state and integrity checksum. Do not delete/edit it to clear a cap. Copy it securely alongside the configuration for disaster-recovery evidence; a cold boot still protects finite nodes because any last uncheckpointed bytes are unknown.
- `settings.json`: language/server defaults, unchanged.
- `traffic.enabled`: monitoring installation marker, not an unlimited/limited switch.
- `/opt/rout/bin/rout-traffic-v1`: independent monitor/start guard. Service name: `rout-traffic-<home-hash>_monitor`.

If statistics are unavailable, **do not assume 0 B**. Unlimited nodes keep working. Finite nodes may be protectively paused; repair nftables/permissions/disk errors, inspect the UI reason, then wait for a new cycle or explicitly confirm reset/cancellation. An expired/exhausted guard cannot be bypassed by starting the service directly.

## Rolling back

Unlimited-only configurations remain schema 1 and are readable by v0.2.0. The first finite policy seals the configuration as **schema 2**. This is deliberate: v0.2.0 must reject it rather than ignore quota fields and rewrite unguarded services. The seal is not automatically removed even after cancelling all caps. The independent monitor/guard and kernel rules remain installed when the manager executable is replaced.

Ordinary edits/apply/restore retain an existing node's current policy. A backup omitting a presently limited node is rejected instead of accidentally deleting protection. Usage is not rolled back with configuration backups. Importing limited configuration on another machine, or restoring without a valid live kernel generation, results in a protective pause, not a new free same-cycle allowance.

There is no automatic quota-preserving conversion to old managers. Stay on v0.2.1 or a compatible successor for sealed configurations. Do not manually force `schema:1`, remove guards, flush tables, or start an old bare engine to work around a cap. Intentional operator cancellation/deletion is a separate, explicit action, not a protection bypass supported by the update flow.

Monitor shutdown checkpoints and pauses finite nodes; restarting after an intentional shutdown may require a new cycle or a confirmed reset. Simply replacing the manager does not stop that independent running monitor. After a future compatible upgrade, reinstall/update the monitor helper as that version's upgrade guide instructs.

## Real-host acceptance checklist

- Debian/Ubuntu systemd or Alpine OpenRC: old unlimited node PIDs survive setup; a limited node cannot pass traffic after quota or start through its init manager while blocked
- Reach the actual advertised IPv4/IPv6/NAT port from a separate client; verify upload + download and compare provider accounting only after aligning scope/units/timezone
- Check reboot, disk-full/recovery, corrupt-journal recovery and guard ordering with the host's firewall loader
- Verify month/day-31 and timezone settings; manual pauses must survive a reset
- Exercise sustained rate, NIC offload and the intended node count before depending on the quota for a provider's billing limit
