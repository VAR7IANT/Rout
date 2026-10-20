# Subscriptions (v0.3.4)

A subscription is an independent, token-protected URL that returns a standard Base64 list of share links for nodes you chose. Rout only generates the list; it does not run a local proxy client and never changes routing, firewall rules or node services.

## Data model

`state.json` gains an optional `subscriptions` array (absent until the first subscription exists, so older state files load unchanged and `schema` stays 1/2):

| Field | Meaning |
| --- | --- |
| `id` | Stable 12-hex ID |
| `name` | Unique (case-insensitive), 1–80 characters |
| `node_ids` | Ordered list of node IDs (never indexes); at most 200 |
| `token_hash` | SHA-256 of the access token (hex). The token is never stored |
| `enabled` | Disabled subscriptions answer `404` |
| `created_at` | UTC timestamp |

Server settings (`settings.json`, key `subscription`): `enabled` (default off), `port` (default 8787, 1024–65535), `public_url` (`https://` only).

Subscription edits take the normal configuration lock, re-read the state under the lock, apply one change, validate, write the usual pre-change backup and replace `state.json` atomically (0600). They never touch node files, services or traffic accounting, and a concurrent monitor or CLI write cannot be overwritten. A node deletion removes the node from every subscription in the same transaction. A downgrade to a Rout older than v0.3.4 ignores the field and drops it on its next write; the backup taken before each change preserves it.

## Tokens

43 characters (256 bits from `crypto/rand`, base64url). Shown only on creation and rotation. Verification hashes the presented token and compares it with every stored hash in constant time, without early exit. Rotation swaps the hash in one atomic write, so the old URL stops working immediately; ordinary edits never change it. Tokens are not logged. A lost token cannot be recovered; rotate it.

## Request handling

`GET /s/{token}` (and `HEAD`). Everything else is `404`; other methods are `405`.

1. The token must be 43 base64url characters, otherwise `404`.
2. The state is re-read when `state.json` changed on disk (inode, mtime, size), so CLI changes apply on the next request without restart or locking.
3. No match, disabled subscription → `404`, identical for all cases.
4. Selected IDs are resolved in saved order. Deleted and disabled nodes are skipped; every other node uses `Profile.URI()` (the same code as `rout export`; IPv6 hosts are bracketed, Hysteria2 certificate pins and TUIC parameters are preserved). A node whose link cannot be built is skipped and logged by name.
5. Links are joined with `\n`, Base64-encoded (standard alphabet, padded) and returned as `text/plain; charset=utf-8` with `Cache-Control: no-store`.
6. If nothing remains: `503` with `Retry-After`, not an empty `200`. If `state.json` is unreadable: `503` without detail (logged once per change).

Limits: header read 5 s, request 10 s, write 10 s, idle 30 s, headers 8 KiB, 64 requests in flight (`503` beyond), 256 connections. Shutdown is graceful (5 s). Logs go to stderr/journal and contain only subscription IDs, node names and generic errors.

## Service

`rout subscription serve` is the server process (it exits with an error unless enabled in settings, and refuses non-loopback binds). *Subscription server settings → Enable* checks the port (free, not used by a node), saves settings, installs the unit and waits until the port accepts connections; failure restores the previous settings and removes a unit that was newly added. Disabling removes the unit and keeps subscriptions.

* systemd unit `rout-subscription.service` (custom `--home` gets a hashed suffix): `ProtectSystem=strict` (the server cannot write anywhere), empty `CapabilityBoundingSet`, `NoNewPrivileges`, `RestrictAddressFamilies=AF_INET AF_INET6`, kernel/cgroup protections, `Restart=on-failure`, enabled at boot.
* OpenRC script `rout-subscription` with `supervise-daemon` and a 600-mode log in `/var/log` rotated at start.
* The unit runs `/opt/rout/bin/rout-subscription-v1`, a copy of the manager binary, so replacing `/usr/local/bin/rout` does not disturb a running server. After `rout update`, run `sudo rout subscription restart` to move it to the new version.
* Existing node services, the traffic monitor and their units are not modified.

## HTTPS reverse proxy

The server speaks plain HTTP on loopback only. Terminate TLS with a proxy you manage and forward `/s/` to `127.0.0.1:PORT`:

```
# Caddy
sub.example.com { reverse_proxy 127.0.0.1:8787 }

# nginx (certificate directives omitted)
location /s/ { proxy_pass http://127.0.0.1:8787; }
```

Rout does not open ports, install proxies or request certificates. Configure the public URL (`https://` only) so the CLI can print complete URLs. Keep proxy access logs off or redacted for `/s/`: the token is in the path.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| `404` | Token typo, rotated/deleted/disabled subscription, wrong path (`/s/TOKEN` exactly) |
| `503 no available nodes` | `rout subscription list` shows which selected nodes are disabled or deleted; the server log names them |
| `503 temporarily unavailable` | `state.json` unreadable; run `rout doctor` |
| Connection refused | `rout subscription status`; `journalctl -u rout-subscription` or `/var/log/rout-subscription.log`; port conflict |
| Works locally, fails remotely | Reverse proxy/DNS/certificate; Rout never exposes the port itself |
| Client shows stale nodes | Client update interval; the server itself caches nothing |

## Security limits

* Whoever holds the URL can read every selected node's credentials. Treat it like the links themselves; use HTTPS only and rotate on suspicion.
* One token per subscription; there are no per-device tokens or expiry. Rate limiting is only the global in-flight/connection cap (a reverse proxy sees all clients from one address). Token guessing is infeasible by entropy, not by throttling.
* Hashes are unsalted SHA-256 of a 256-bit random secret, which is sufficient for high-entropy tokens but not for human-chosen ones.
* The loopback server trusts its reverse proxy; do not publish the port directly.
* A client that ignores `503`/`404` status codes is outside Rout's control.
* Base64 share-link output only. Live compatibility with specific clients has not been verified by automated tests.

## Test coverage

`internal/rout/subscription_test.go` covers lifecycle, persistence, manual-selection rules, token storage/rotation, Base64 order and content for all link types and IPv4/IPv6, dynamic node changes, no-node `503`, authentication/method/path handling, read-only behavior, concurrent readers and writers (run under `-race`), real listener start/stop and bind errors, settings validation, unit/script contents, pre-v0.3.4 state compatibility with AI routing, and the English/Chinese menu flows. Real systemd/OpenRC start-up of the subscription service and real-client import are **not** covered by automated tests (see the release notes for the manual acceptance list).
