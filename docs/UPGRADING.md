# Upgrading and rollback safety

## To v0.3.9

No migration; existing subscriptions, tokens, nodes, relays and traffic state are unchanged, and a subscription without a data plan returns the same bytes as before. New optional per-subscription data allowance, reset day and expiry (see [Data allowance and expiry](SUBSCRIPTIONS.md#data-allowance-and-expiry)). Run `rout update`: the updater refreshes the traffic monitor and the subscription helper, which are the two processes that need the new version. Setting a finite allowance moves `state.json` to the protected schema (schema 2, as node limits already do) and adds `subscription-traffic.json`; an older manager ignores the plan, so after a downgrade the allowance is not enforced and not shown, and the journal is left unused. Rollback: restore the previous manager and refresh its helper and monitor; remove the allowance first if you do not want it silently lost on the next restore.

## To v0.3.8

No migration. State, subscriptions, tokens, nodes, relays and traffic accounting are unchanged. The interactive menu gains section titles, status badges, breadcrumbs and a status panel with the same menu numbers; Enter no longer quits the main menu. Relay loop checks now follow TCP and UDP chains independently, and subscription responses carry the stored name as the client title (existing subscriptions gain it after `sudo rout subscription refresh`). Run `rout update`; the existing updater/installer works as before.

## To v0.3.7

Existing nodes, subscription IDs/hashes, selections/order, URLs, local port, public domain, Caddy ownership, routing and traffic state need no migration. Node Management now shows complete links immediately, using the original link generator. Existing command/export and HTTP subscription formats stay unchanged.

Tokens created or explicitly rotated by v0.3.7 are saved in `secrets/subscription-tokens.json` under the configured home (0600 file, 0700 directory). **Subscriptions → View subscriptions** shows full Base64/Mihomo/Clash URLs after restarting Rout or rebooting. Authentication still reads hashes from `state.json`, independently of that private file. Do not include `secrets/` in shared backups; ordinary state/upgrade/HTTPS backups exclude it. A full VPS migration needs a separate private copy if you want to keep URL retrieval.

Older hash-only subscriptions retain their existing tokens and client URLs. They show templates and guidance, not recovered plaintext. Keep the saved client URL. Only an explicit confirmed **Rotate access token** creates a recoverable replacement and invalidates the old URL. No upgrade or read-only view does this automatically.

Before publication, use a checksum-verified v0.3.7 CI artifact with the staged-binary upgrade procedure below (use `rout-v037` as the staged filename), then `sudo rout subscription refresh`. After publication, the existing updater/installer works as before. No reinstall, node restart or subscription recreation is required. For rollback, restore the previous manager and refresh its helper; older managers ignore the separate token file and continue authenticating existing hashes. A token explicitly rotated by an older manager will be hash-only when returning to v0.3.7.

## To v0.3.6

v0.3.5 subscriptions need no migration, recreation, token rotation, node reselection or Caddy changes. `/s/TOKEN` still returns the same Base64 bytes for an unchanged selection. Append `?format=mihomo` to the full URL already saved in your client for native Mihomo YAML; `format=clash` is an alias for modern Mihomo. The original URL continues working in Shadowrocket.

After publication, upgrade through `sudo rout update` or the installer. Before publication, download the exact reviewed commit's CI artifact, verify its checksums and stage the matching architecture's binary as `./rout-v036`:

```sh
./rout-v036 version
sudo ./rout-v036 subscription prepare-upgrade
sudo cp -p /usr/local/bin/rout /usr/local/bin/rout.previous
sudo install -m 755 ./rout-v036 /usr/local/bin/.rout-v036-stage
sudo mv -f /usr/local/bin/.rout-v036-stage /usr/local/bin/rout
sudo rout subscription refresh
sudo rout version
sudo rout subscription list
sudo rout subscription status
```

Use the same `--home`/`--bin-dir` flags on every command for a custom installation. A still-running v0.3.5 helper ignores the format query and returns Base64; confirm the helper was refreshed before importing YAML. Refresh restarts only a changed subscription helper, preserving configured port, public URL, disabled startup and an intentionally stopped service.

No existing persistence field is rewritten by this upgrade. The optional `subscription.mihomo_test_url` appears in `settings.json` only when explicitly set; older managers safely ignore it. State schema, subscription IDs/names/token hashes/selections/order, credentials, AI bindings, traffic data and relay configurations remain unchanged. No YAML snapshots are stored, no converter/core is installed at runtime, and Caddy ownership metadata/configuration is unchanged.

Native AnyTLS Reality cannot be represented by the tested Mihomo core. Mixed selections omit it with explicit diagnostics; a selection with no compatible node returns 503. Base64 stays available. Check [format/protocol coverage](SUBSCRIPTIONS.md#native-formats-and-imports) before importing the new format. Complete remote configurations have minimal default rules; retain personal routing through client overrides.

For rollback, restore the previous manager and run `sudo rout subscription restart` to refresh its helper. Original Base64 URLs and token hashes remain compatible. Mihomo query support requires the v0.3.6 helper; clients using YAML need that helper or must switch back to their original Base64-capable client URL. Never delete persistence files or rotate tokens to perform an upgrade/rollback.

## To v0.3.5

Existing v0.3.4 subscriptions require no migration or recreation. IDs, names, verification hashes, previously issued token validity, selected node IDs/order, enabled states, response bytes, public base URL and loopback port are preserved. No node/AI/traffic/relay state or Caddy configuration is modified by an ordinary upgrade. Keep the original Shadowrocket entry and URL.

After publication, use `sudo rout update` or rerun the installer. v0.3.5 installer/newer updater snapshots private subscription persistence before replacement and refreshes only an enabled subscription helper when needed, preserving stopped state and disabled startup. The **v0.3.4 updater cannot know the new helper-refresh command**: its old helper continues serving unchanged URLs. Open subscription management in the new CLI or run `sudo rout subscription refresh` to refresh it; this takes a private backup and never calls Caddy. `sudo rout subscription restart` is an explicit restart, not required for token/data compatibility.

Before publication, the default installer cannot download unpublished v0.3.5 assets. Use the exact-commit CI artifact or build the reviewed commit. On the VPS, with the candidate binary staged as `./rout-v035`:

```sh
./rout-v035 version
sudo ./rout-v035 subscription prepare-upgrade
sudo cp -p /usr/local/bin/rout /usr/local/bin/rout.previous
sudo install -m 755 ./rout-v035 /usr/local/bin/.rout-v035-stage
sudo mv -f /usr/local/bin/.rout-v035-stage /usr/local/bin/rout
sudo rout subscription refresh
sudo rout subscription status
sudo rout subscription https status
```

Use the same `--home`/`--bin-dir` flags on every command for a custom installation. Persistent data stays in place; never delete `state.json`/`settings.json`, recreate subscriptions or rotate tokens to perform this upgrade. Backup snapshots include original bytes/modes/UID/GID and contain secrets; keep the backup directory private.

For the existing `xhx.oioio.uk` deployment, keep the working Caddy site. In **Subscription server settings → Deploy / repair HTTPS**, accept the existing domain, then choose **Use existing HTTPS configuration**. This verifies the existing endpoint without rewriting/reloading Caddy or transferring deletion rights. Optional adoption requires explicit confirmation and a proven isolated fragment; a site in the main/shared Caddyfile remains external.

Verify the original Shadowrocket entry over mobile data: refresh it without deleting/reimporting, check the node names/order, then connect to the existing Reality node and check the existing AI routing. Local diagnostics explicitly do not prove external reachability. Public ACME issuance and actual client/VPS acceptance are not claimed by automated tests.

Rollback the manager with `sudo mv /usr/local/bin/rout.previous /usr/local/bin/rout`, then `sudo rout subscription restart` to refresh its helper. v0.3.4 reads the unchanged subscription schema and original tokens. It does not understand the separate HTTPS ownership file or manage Caddy, so leave working HTTPS configuration intact. If a deployment rollback reports incomplete recovery, follow the exact private snapshot/resource instructions and validate Caddy before reloading; do not restore an old whole database over newer subscription edits.

See [SUBSCRIPTIONS.md](SUBSCRIPTIONS.md) for ownership, DNS/ports, automatic renewal, diagnostics, removal and manual fallbacks.

## To v0.3.4

Adds subscriptions. Nothing is required on upgrade: `state.json`, nodes, outbounds, AI routing, relays, traffic data and node services are unchanged, and the subscription server stays disabled until you enable it. The optional `subscriptions` array and `subscription` settings key appear only after you use the feature. To use a newer binary in an already running subscription server, run `sudo rout subscription restart` after `rout update` (the service runs a copy under `/opt/rout/bin`). To go back to v0.3.3, disable the server first (`Subscriptions → Subscription server settings → Disable`); v0.3.3 ignores the new fields and drops them on its next state write, and the pre-change backups keep them. See [SUBSCRIPTIONS.md](SUBSCRIPTIONS.md).

## To v0.3.3

This candidate fixes traffic monitoring on Debian 12 with nftables 1.0.6. The installer on main targets unpublished v0.3.3 and fails safely until release assets exist; use a locally built binary or the CI artifact for pre-release verification. Do not tag during preparation.

After installing the matching manager binary, run `sudo rout traffic install`, then `sudo rout doctor` and `sudo rout traffic show NODE_ID`. Repeating installation is safe: the private probe is removed even when verification fails; errors name any table that could not be removed. The helper changes only after the probe succeeds, service failures roll back installation files, and a new success marker is written only after successful activation.

`state.json`, `traffic.json`, node IDs, credentials, cycles and limits are unchanged. Existing counted bytes are retained. No reset, `rout apply`, engine reinstall or recreation of nodes is needed. Only a changed monitor helper is restarted; finite nodes resume after their sealed checkpoints verify.

Historical tables left by failed v0.3.2 installations use the same naming scheme as formal nodes, so their purpose cannot be inferred safely. They are now preserved and reported by read-only `rout doctor`, including before monitoring is installed. Follow [the diagnostic procedure](TRAFFIC.md#ownership-compatibility-and-historical-tables); never flush or bulk-delete `rout_*` tables. New `probe_` tables have distinct names and can be cleaned by `rout doctor --fix` only after ownership/structure verification and confirmation.

## To v0.3.2 (menu refactoring and AI routing hardening)

- **Data formats:** `state.json` gains an optional `ai_routing` object (`enabled`, `bound_inbound_ids`, `ai_outbound_id`, `rule_set_version`). Hosts that never use AI Smart Routing keep a byte-identical file and byte-identical node configurations, so nothing restarts on upgrade.
- **Rolling back:** back up before upgrading. v0.3.1 and earlier do not understand `https` outbound entries and will refuse to load them. Before downgrade, explicitly move HTTPS users to tested compatible exits and remove HTTPS entries, or restore a pre-upgrade compatible backup. This can remove transport protection: never auto-convert HTTPS to plaintext. Older versions also drop `ai_routing` on their next save; disable AI routing first and keep a separate backup if its settings are needed. Do not describe downgrade as preserving AI protection.
- **Menus:** the main menu has six entries; see the README for where each former entry moved. All commands (`rout list`, `rout restart ID`, `rout outbounds`, …) are unchanged.
- Enabling AI routing restarts only the bound nodes whose effective routing changes. Unbound nodes and relays are neither rewritten nor restarted.

- Existing HTTP/SOCKS5 connections remain unchanged and unencrypted unless separately tunneled. HTTPS CONNECT is opt-in and verifies the proxy host against the system CA store. Follow [AI transport security and acceptance](AI_ROUTING.md); do not change a working proxy to HTTPS until the remote endpoint supports it.
- Updating the manager does not apply new AI rules or restart nodes. Use **AI Smart Routing → Apply changes** after reviewing the new behavior; only bound nodes are reapplied. No DNS policy is changed.
- v0.3.2 is the previous published release; current preparation and installer instructions are in the v0.3.3 section above.

## To v0.3.1

Run `sudo rout update` (from v0.2.2 or later) or rerun the README installer. Nothing restarts except the traffic monitor helper, as in every release; nodes and relays keep running untouched.

- **Existing data stays compatible.** `state.json` keeps its schema, IDs, ports, keys and the `nat` flag of every entry. New IPv6 node entries may carry optional `ipv4_mapped` capability metadata; older versions ignore it. `settings.json` may gain optional `family`, `ipv4` and `ipv6` fields inside `server`; v0.3.0 ignores them, so rolling back keeps everything.
- **Legacy NAT hosts:** saved NAT settings and existing NAT nodes and relays are read and run exactly as before; nothing is migrated or rewritten. The NAT/VPS question is gone, so a host whose saved settings are in NAT mode keeps allocating new entries from the saved mapping (a notice appears at creation) and editing an existing NAT entry still asks for the provider-mapped public port. To use regular-VPS behavior for new entries choose Settings → Server address → *Switch to a regular VPS* and confirm; existing NAT entries are not touched. There is no menu to create new NAT mappings; an unusual NAT setup that must be created from scratch has to be written into `settings.json` by hand (`server.nat`, `local_start`, `local_end`, `public_start`, `network`).
- **Existing nodes** keep `0.0.0.0` or `::` as their listening address. A dual-stack host only gains a second link for nodes that already listen on `::` (new nodes now recommend IPv4; choose Dual-stack during creation to serve both families after local probes for the selected protocols' transports succeed); to make an older IPv4-only node reachable over IPv6, choose Edit node → Change port or public address → public address, enter the IPv6 address and accept the offer to listen on `::` (restarts only that node).
- **New node listeners** are selected from local socket capabilities, separately from the public address used in share links. IPv4 is recommended whenever available, followed by dual-stack, then IPv6; Enter accepts the recommended option. Private/NAT IPv4 does not require a detected public IPv4. Legacy NAT mappings and explicit interface bindings are retained. Saved wildcard defaults do not override the recommendation for new nodes. New IPv6 listeners record whether IPv4-mapped connections were supported so IPv6-only sockets do not advertise an IPv4 alternate link; this optional metadata does not alter existing nodes.
- **Saved server settings** from v0.3.0 are reused silently instead of through a confirmation question. Use Settings → Server address to re-detect addresses, which also stores the IPv4 and IPv6 addresses needed for the second link.
- **Engines** already installed are not touched. A missing or non-executable engine is reinstalled by the new streaming installer; a failed install never replaces a working engine.
- Roll back with `sudo mv /usr/local/bin/rout.previous /usr/local/bin/rout`.

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
