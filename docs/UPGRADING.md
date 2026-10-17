# Upgrading and rollback safety

## To v0.3.0

Run `sudo rout update` (from v0.2.2) or rerun the README installer; from v0.2.1, also follow the steps below. The upgrade restarts only the traffic monitor: limited nodes are sealed and resume automatically with their usage, and other nodes keep running.


The interactive menus and wording change; stored data does not. `state.json` keeps its schema and every existing ID. A relay gains an optional `relay_mode` (`local`/`remote`) only when it is created or edited; relays without it keep working and their type is inferred from the destination (loopback = local). `settings.json` may gain `relay_mode` (the last relay type chosen). Older versions ignore both fields, so rolling back keeps every node, relay and outbound proxy. `rout exits` remains an alias of `rout outbounds`. Recording a relay's type never restarts it.

## From v0.2.1 (introduced in v0.2.2)

1. Optional but recommended: `sudo rout backup /root/rout-before-022.json` (contains credentials/private keys; protect it).
2. Run `sudo rout update` (this run still uses the v0.2.1 updater), or rerun the README installer.
3. **Immediately run `sudo rout traffic install`** — before any reboot. The v0.2.1 updater does not refresh the monitor helper; until you do, the old monitor keeps running and would treat a reboot the v0.2.1 way. Installing the helper restarts **only the monitor**: the v0.2.1 monitor writes its graceful checkpoint, and the v0.2.2 monitor verifies it in the same boot and resumes limited nodes automatically with their usage. Unlimited nodes are not restarted. The installer script does this step for you.

From v0.2.2 on, `rout update` refuses downgrades, checks that the staged binary reports the release version, keeps the previous manager at `/usr/local/bin/rout.previous`, and refreshes the helper itself.
4. Run `sudo rout doctor` to confirm services, ports, certificates, the monitor and its checkpoint.
5. Existing services keep their v0.2.1 unit files until they change. Run `sudo rout apply` when convenient to rewrite every unit with the new sandbox and health checks (this restarts every node once; an unchanged node with an expired certificate is skipped and reported).

Nothing is migrated destructively: node IDs, ports, keys, credentials, certificates, exits, names, language, server defaults, usage, cycles and limits are unchanged. `state.json` keeps its schema (1 for unlimited-only, 2 once a finite limit exists). `traffic.json` gains no new fields; a new block reason `sealed` is used. `settings.json` may gain `backup_keep`, which older versions ignore.

Behavior changes to be aware of:

- **Alpine hosts:** v0.2.0/v0.2.1 installed the glibc-linked sing-box build, which cannot run on musl, so sing-box nodes never started there. v0.2.2 detects this and installs the pinned static musl build; run `sudo rout apply` once after upgrading.
- Shadowsocks 2022 share links now follow SIP002 for AEAD-2022 (`ss://method:percent-encoded-key@host:port`) instead of Base64 userinfo. The credentials are identical; clients that imported the old link keep working, and the old form remains importable for relays.
- Newly generated HY2/TUIC self-signed certificates are valid for 10 years (existing certificates are untouched; renew them with `rout cert renew ID`).
- Automatic backups keep the newest 20 (Settings → Automatic backup retention).
- Lock contention now waits (up to 30 s for configuration changes) instead of failing immediately.
- New UDP-only Shadowsocks nodes cannot be bound to an outbound proxy (it could never carry traffic). An existing entry still loads; switch it to Direct connection or use a TCP+UDP mapping.
- Pushes to `main` no longer publish releases; releases come from version tags.

## Files

- `state.json`: configuration. A missing `traffic` field means unlimited, day 1, server-local timezone. Use the UI, not live manual JSON edits, for policy changes.
- `traffic.json`: exact kernel snapshots/baselines, cycle bounds, boot identity, rule hashes, incomplete/blocked/pending state and an integrity checksum. Do not delete/edit it to clear a cap.
- `settings.json`: language, server defaults, backup retention.
- `traffic.enabled`: monitoring installation marker.
- `/opt/rout/bin/rout-traffic-v1`: monitor and start-guard helper. Service: `rout-traffic-<home-hash>_monitor`.

If statistics are unavailable, **do not assume 0 B**. Unlimited nodes keep working. Finite nodes may be protectively paused; repair nftables/permissions/disk errors, then use `rout traffic recover ID` (keeps known usage), a confirmed reset, or wait for the next cycle.

## Rolling back

```sh
sudo mv /usr/local/bin/rout.previous /usr/local/bin/rout
sudo rout traffic install   # puts the matching helper back in place
```

Tested against the published v0.2.1 monitor: it reads the v0.2.2 journal and keeps a `sealed` node paused (it does not know how to verify a seal), so a rollback can never bypass a limit; on v0.2.1 such a node needs a confirmed reset or the next cycle. Unlimited-only configurations remain schema 1 and are readable by v0.2.0. Configurations with a finite limit stay sealed as schema 2 and are rejected by v0.2.0, by design. Do not manually force `schema:1`, remove guards, flush tables, or start an old bare engine to work around a cap.

## Real-host acceptance checklist

- Debian/Ubuntu systemd or Alpine OpenRC: unlimited node PIDs survive `rout traffic install`; a limited node cannot pass traffic after its quota or start through its init manager while blocked
- Reboot: limited nodes resume with the same usage; `rout doctor` shows no gap
- Reach the advertised IPv4/IPv6/NAT port from a separate client; compare provider accounting only after aligning scope/units/timezone
- Check disk-full recovery, corrupt-journal recovery and guard ordering with the host's firewall loader
- Verify month/day-31 and timezone settings; manual pauses must survive a reset
- Exercise sustained rate, NIC offload and the intended node count before relying on a quota for a provider's billing limit
