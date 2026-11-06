# Telegram Bot remote management (v0.6.0)

Bind **one Telegram bot** (Bot Token + your Chat ID) on every Rout server and, from a single chat, turn *AI Smart Routing* on or off and switch each server's AI exit with buttons — no SSH. One bot manages many servers; each server is controlled separately.

```
🤖 Rout Control                      🌐 US-GIA
Connected servers: 3                 Server status:  🟢 online
Select a server:                     AI routing:     🟢 on
  🟢 US-GIA                          Current AI exit: US-Exit-01 (SOCKS5)
  🟢 CA-Exit                         Bound inbounds: 3
  🟢 JP-Tokyo                        [Turn off AI routing]
  [🔄 Refresh]                       [🔀 Switch AI exit]  [🧪 Test AI exit]
                                     [📊 Check status]    [⬅️ Back to server list]
```

Everything the bot can do is a call into the same functions the menu and the panel use (`SetAIEnabled`, `SetAIExit`, `AIStatus`, the AI exit test), so validation, the `Commit` transaction and rollback are identical. It never edits `state.json`, never runs a shell, and never returns an outbound password, node key, Reality private key or subscription token.

## Quick start

**One server.** Main menu → *AI Smart Routing* → *Telegram Bot management* → *Bind a Telegram Bot*. Enter the Bot Token (hidden input) and your Chat ID. That is all: the server name defaults to the host name (rename it later), the service is installed and started, and `/start` in your bot shows the server. A single server opens **no listening port**.

How to get the two values: create a bot with [@BotFather](https://t.me/BotFather) (that is the token); find your numeric user ID, e.g. with [@userinfobot](https://t.me/userinfobot) (that is the Chat ID); open your bot once and send `/start` so it is allowed to write to you. Only a **private chat with you** is supported (a positive ID); group and channel IDs are refused.

**More servers, same bot.**

1. On the first server, *Telegram Bot management → Multi-server mode*: pick a TCP port and make sure it is reachable from your other servers (firewall / cloud security group). If this server is behind NAT, enter the externally reachable `address:port` yourself.
2. On every other server bind with the **same Token and Chat ID**. The server finds the hub through the pinned (encrypted) announcement in your chat, shows the hub's certificate fingerprint and asks you to compare it with the one in the hub's *View binding status*. Confirm.
3. Telegram shows **"A new server asks to join"** with the new server's fingerprint. Compare it with that server's *View binding status* and press **Allow**. Only then can the server be controlled.

The other servers need **no inbound port**: they connect out to the hub.

Command line (same code): `rout telegram [bind|status|test|unbind|multi on|off|approve|reject|revoke|rename|serve|refresh]`. The token is read from `ROUT_TELEGRAM_TOKEN` or a hidden prompt, never from an argument. Panel: *AI Routing → Telegram Bot*.

## Why there is a hub

Telegram lets exactly one process consume a bot's updates: two `getUpdates` loops on one token fight each other (HTTP 409), and a webhook is a single URL. Giving every server the same token therefore cannot, by itself, let each server answer the same chat. Rout does not pretend otherwise:

* The **first server that binds becomes the hub**. It is the only `getUpdates` consumer for the token. It never deletes or overwrites a webhook and reports a conflict (and keeps its hands off) if another program is using the bot.
* Every other server is an **agent**. It dials the hub over **mutually authenticated TLS 1.3**, long-polls for commands, runs them locally and posts the result. Agents never talk to Telegram's update stream.
* Two credentials alone do **not** give servers a trust relationship. The token is only an *entry ticket and a way to find the hub*; machine identity is a per-server certificate that **you approve in Telegram** (below).
* The hub is a control point, not a traffic point. If it is down, the other servers keep serving proxy traffic exactly as before; they just cannot be controlled from Telegram until it is back.

The Bot Token is never sent to a third party and is never uploaded to a central service. Servers share it only because you typed it on each of them; the hub additionally pushes a *replacement* token to servers you already approved (see Token replacement).

## How servers find and trust each other

| Step | Mechanism |
| --- | --- |
| Discovery | The hub publishes `{hub id, name, endpoints, certificate fingerprint}` as one **pinned message in your private chat**, AES-256-GCM encrypted and authenticated with a key derived (HKDF-SHA256) from the Bot Token. The chat shows an opaque string; only a token holder can read or forge it. |
| Hub identity | The announced fingerprint is shown to **you**, who compares it with the hub's menu before confirming. The agent then **pins** the hub certificate. If the hub's certificate ever differs, the agent refuses to connect (`hub_changed`) and waits for a deliberate local *Re-trust control hub*. A forged announcement cannot redirect an already bound server. |
| Agent identity | Each server generates its own ECDSA P-256 certificate at bind time. The hub identifies agents **only by certificate fingerprint**. |
| Admission | An agent proves it holds the token (`HMAC(nonce, server id, its fingerprint)` with an HKDF key; the nonce is hub-issued, single-use, bound to that certificate, valid 2 minutes). That only filters strangers: the hub then asks **you** in Telegram (**Allow / Reject**). Reject or *Remove this server* adds the certificate to a revoked list; it is told so and stops. |
| Hijack protection | A different certificate claiming an approved server's ID is refused (409). |
| Transport | TLS 1.3 only, client certificate required, hub certificate pinned, 1 MiB request bodies, per-address rate limits on the unauthenticated endpoints. |

## What can be commanded

A closed set — there is no generic "run" command, no file access, no way to ask for a secret:

| Command | Effect on the server |
| --- | --- |
| `status` | Read `AIStatus`: AI on/off, current exit **name**, bound-inbound count, and the exits as `{id, name, kind, usable, problem}` |
| `set_enabled` | `SetAIEnabled(true/false)` (target state, so it is idempotent) |
| `set_exit` | `SetAIExit(exit id)` — only an exit that **already exists on that server**; commands carry IDs, never addresses or credentials |
| `test` | The existing AI exit test, shown as sanitized steps |
| `set_credentials` | A hub-approved replacement of Token / Chat ID, applied only after Telegram itself accepts them |

Every command has a random ID, an expiry, is validated on arrival and is de-duplicated by ID (a redelivered command is answered from a cache, not run twice). Disabling AI routing keeps the selected exit and the bindings; switching an exit changes only the **bound** inbounds and re-renders only them. Failures roll back through Rout's `Commit`, and the message you see states what is still in effect.

Exit names, kinds and "usable / why not" are shown; hosts, ports, users, passwords and links are not. Text that crosses the wire or reaches the chat is additionally scrubbed (URLs, IP addresses, `password=…` patterns, long key-like strings, the token) and HTML-escaped.

## Authorization and replay protection in the chat

* Accepted only from a **private** chat whose ID equals the configured Chat ID **and** whose sender ID equals it (not a bot). Everything else is refused and audited: a stranger's private chat gets one polite refusal per minute and no information; groups, channels and bots are ignored.
* Every button carries an HMAC (keyed from the token, bound to the chat) and is limited to 64 bytes; a forged, truncated or re-aimed button is "no longer valid". Server IDs inside the data are part of the MAC, so a button for server A cannot be turned into one for B.
* Switching an exit shows a confirmation; the confirmation is **single-use**, expires in 5 minutes and is bound to the message it was shown on. Toggles carry the target state, not "toggle".
* Callback IDs are de-duplicated; the update offset is saved only after an update was handled; one operation per server at a time (a double tap says "busy"); buttons are rate-limited (30 per 10 s).
* The audit log `telegram-audit.log` (0600, rotated at 256 KiB) records who (masked), what and the outcome — never tokens, addresses or credentials.

## Files, services and lifecycle

| Item | Detail |
| --- | --- |
| `/etc/rout/telegram.json` | Token, Chat ID, this server's private key and pinned peers. **0600**, in the 0700 config directory. **Not** part of `state.json`, `rout backup` or the panel's backup bundle, and listed in the permission check/repair. |
| `telegram-status.json`, `telegram-audit.log` | Runtime state and audit trail. No secrets. |
| Service | `rout-telegram` (systemd or OpenRC), running a private copy `rout-telegram-v1` of the manager so `rout update` never swaps the binary under it; `Restart=always`, enabled at boot, same sandbox options as the panel service. Logs: `journalctl -u rout-telegram` / `/var/log/rout-telegram.log`; the panel's log viewer knows the unit. |
| Reboot / restart | Everything is read from disk: no re-binding, no second approval; agents reconnect with back-off and jitter; the hub keeps its port and offset. |
| Upgrade | `rout update` refreshes the helper copy and restarts the service only on hosts that bound a bot. The configuration format is versioned. |
| Token / Chat ID change | Menu / panel on the **hub**. Telegram must accept the new values first. The hub republishes its announcement under the new token (the old one is withdrawn), and each approved server takes the new credentials from the hub over the authenticated channel when it next connects (offline servers sync when they return). If the hub's address changes in the same moment as the token, a server that can neither read the new announcement nor reach the old address must be re-bound locally. |
| Unbind | Menu / panel / `rout telegram unbind`: the service stops first, an agent tells the hub to forget it (revoking its certificate), a hub unpins and deletes its announcement, then token, private key, status and audit files are deleted. A server removed from the hub's list, or unbound, can never be commanded again. |
| Uninstall | `rout uninstall` unbinds first (best effort for the Telegram side), then removes the service, helper and all files. |
| Hub replaced | If the hub VPS is gone, bind another server with *"the old hub is gone"* (`rout telegram bind --hub`). Servers pinned to the old hub stop (`hub_changed`) until you *Re-trust control hub* on each and approve them again. |
| Telegram or hub unreachable | Proxy nodes, relays, subscriptions and AI routing keep running untouched; the service only retries. |

## Network prerequisites and NAT

* **Outbound** HTTPS to `api.telegram.org` from every server.
* **Multi-server only:** one **inbound TCP port** on the hub reachable from the other servers. Rout never changes a firewall. Choose it in *Multi-server mode* (or `rout telegram multi on --port N`).
* Hub behind NAT: forward a port yourself and enter the public `address:port` as the advertised address. IPv6-only is fine (the announcement carries bracketed IPv6 endpoints).
* Agents behind NAT need nothing.

## Threat model in short

| Threat | Mitigation |
| --- | --- |
| Someone messages the bot / adds it to a group | Private chat + Chat ID + sender ID check; strangers learn nothing; audited |
| Forged or replayed button / update | HMAC on callback data, single-use confirmations, callback de-dup, offset after handling |
| Token leaked | An attacker cannot pass the Chat-ID check and cannot become an approved server (you must press Allow for their fingerprint); they could run a rogue hub for **new** binds, which is why the hub fingerprint is shown to you and pinned; bound servers ignore announcements that differ from their pin. Revoke the token at BotFather and use *Change Bot Token*. |
| Man in the middle between servers | TLS 1.3 with mutual authentication and certificate pinning in both directions |
| A network stranger talking to the hub port | Needs a client certificate and an approved fingerprint; enrollment needs the token proof *and* your approval |
| Compromised hub | It can issue only the closed command set and only select exits that already exist on a server; it cannot read credentials or run code |
| Secrets in chat, logs, backups | Allow-listed projection, scrubbing, 0600 files outside backups, token never printed by the menu, CLI, panel or errors |
| Telegram rate limits / outages | `retry_after` honoured, back-off, status shows the cause; proxies unaffected |

## Not verified / known limits

Automated tests use an in-process fake Telegram Bot API with real mutually authenticated TLS between real hub and agent code; see below. **Not verified** because they need real infrastructure: the live Telegram service (pinning and `getChat` of a private chat's pinned message, rate limits, message-edit corner cases), several real VPSs across a real network, NAT/firewall reachability, real systemd/OpenRC runs of the new unit, and real phone clients. Other limits: groups/channels are not supported; there is one hub per bot token; a hub address change at the same time as a token change needs a local re-bind; the dedupe cache is in memory (a process restart between executing a command and reporting it can re-run an idempotent command, which then reports "nothing changed").

## Automated tests

`go test ./internal/rout -run 'Telegram'` (also under `-race`): single-server bind / toggle / switch / test; three servers on one bot with isolation (an operation on one never changes another, a button for one cannot be aimed at another); agent offline shown as offline and restored on reconnect; wrong chat, wrong sender, group, bot, forged and duplicated callbacks and reused confirmations change nothing; unusable and unknown exits are refused with the real reason (UI and direct); failed switch / failed enable roll back state and files and say so; Rout restart keeps binding and control without a second approval; token replacement reaches approved servers and the old token's announcement dies; unbind, revoke and hub unbind leave no channel (listener closed, announcement withdrawn, old identity refused); enrollment attacks (wrong token, replayed or stolen nonce, hijacked server ID, unknown certificate, TLS 1.2, no certificate); pinned-hub mismatch and hub replacement; webhook and competing-consumer handling (never deletes); secrets never reach Telegram text, status file or audit log; service unit text; menu, CLI and panel API (re-authentication on every change, token write-only).
