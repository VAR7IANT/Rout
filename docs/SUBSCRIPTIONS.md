# Subscriptions and HTTPS (v0.3.7)

A subscription dynamically returns either the original Base64 share links or native Mihomo YAML for the nodes you explicitly selected. It does not change proxy protocols, credentials, AI bindings, routing, traffic accounting or relay settings.

## Native formats and imports

The same existing token authenticates both formats, using the saved public URL and optional path prefix:

```text
https://sub.example.com/s/TOKEN                 # Base64 (unchanged default)
https://sub.example.com/s/TOKEN?format=base64   # explicit Base64
https://sub.example.com/s/TOKEN?format=mihomo   # complete native Mihomo YAML
https://sub.example.com/s/TOKEN?format=clash    # alias for Mihomo
```

Keep the original saved URL in Shadowrocket and other Base64 clients. In Clash Verge Rev, FlClash or Mihomo Party, create a remote configuration from that same URL with `?format=mihomo` appended. This does not create a Rout subscription or rotate its token. `clash` requires a modern Mihomo core; it does not imply compatibility with the discontinued Clash core. Existing templates and newly shown URLs use the actual configured domain/prefix, never a fixed domain.

Open **Subscriptions → View subscriptions** to see full Base64, Mihomo and Clash URLs for tokens created or explicitly rotated in v0.3.7. Each URL is printed on its own untruncated line, using the configured public domain/prefix. Legacy hash-only entries show templates and explain that the original token cannot be recovered. Keep using your previously saved URL, or explicitly choose **Rotate access token**, confirm the warning and update clients to the new URL. Listing or changing formats never rotates a token.

Requests still require a valid enabled token and share the same connection/concurrency limits. Unknown/disabled tokens retain the uniform 404, including with an invalid format. Authenticated unsupported, empty, repeated or malformed format parameters return a fixed HTTP 400 without echoing the URL/token. Unknown unrelated query keys remain ignored. Successful Mihomo responses use UTF-8 `application/yaml`, no-store/nosniff/no-referrer headers and correct GET/HEAD lengths. The default Base64 bytes and response headers are unchanged for unchanged selections.

### Protocol coverage and failure behavior

| Rout model | Native Mihomo representation |
| --- | --- |
| VLESS Reality Vision | UUID, TCP, TLS, actual SNI, Vision flow, canonical Chrome fingerprint, Reality public key/short ID; modern key-share support for Rout's pinned sing-box |
| Shadowsocks 2022 | Actual cipher/password and public endpoint; TCP-only entries disable UDP |
| Hysteria2 | Actual password/SNI and SHA256 fingerprint of the configured server leaf certificate |
| TUIC v5 | Actual UUID/password/SNI, canonical h3 ALPN/bbr congestion control and server certificate fingerprint |
| Share-link relays | Forwarded public endpoint/NAT port with original credentials/TLS identity; supported VLESS plain/TLS/Reality, Trojan, SS, Hysteria2 and TUIC links; representable TCP/WS/gRPC, ALPN, browser fingerprint, certificate pin and protocol options are retained |

Rout has no VMess node/relay model; this release does not invent one. Mihomo v1.19.32 cannot express Rout's **AnyTLS Reality** backend; it is explicitly omitted, never converted to plain AnyTLS. UDP-only Shadowsocks, unchecked insecure TLS, unknown/duplicate relay parameters, unsupported ciphers/transports and a separate gRPC authority that Mihomo cannot preserve are also diagnosed. Plain TLS AnyTLS relay links are supported where representable.

Selections are never altered in storage. Mixed selections produce supported nodes in the original order, a safe diagnostic comment for each omission and `X-Rout-Skipped-Nodes`. The CLI and sanitized service logs show the reasons by node ID. If no node can be exported, return HTTP 503 with actionable diagnostics, never an empty successful configuration that could erase a client's list. Existing Base64 handling remains independent.

Native QUIC nodes use exact certificate pinning, including self-signed certificates, rather than `skip-cert-verify`. Certificates must be valid when exported. Mihomo's leaf-pin verification authenticates the exact certificate; it does not rely on a separate client CA file. A replaced node certificate requires refreshing the subscription to obtain its new pin. Neither server private keys nor public certificate PEMs are included. Reality output enables Mihomo's modern X25519/ML-KEM key shares, tested against Rout's pinned sing-box 1.14.3; do not assume interoperability with older external Reality implementations.

### Groups, names and routing preferences

The generated configuration includes `proxies`, `proxy-groups` and `rules`:

1. **🚀 Proxy** — manual selection, original nodes first, then Auto, Fallback and DIRECT.
2. **⚡ Auto** — lazy latency selection, 600-second interval.
3. **🛡️ Fallback** — lazy failover, 600-second interval.

Names and country flags are retained without IP geolocation. Duplicate or reserved names receive stable node-ID suffixes; all group references use those exact names. Dynamic strings are serialized as quoted JSON-compatible YAML flow values, preventing YAML tags/aliases/key injection, control-character injection and implicit scalar coercion. A real Mihomo core validates this YAML syntax and its proxy/group configuration in CI; no YAML/converter runtime dependency was added.

The only default rule is `MATCH,🚀 Proxy`. No DNS, TUN, controller, listener port, geographic rule set or server-side routing is configured. Importing any complete remote configuration replaces that profile's rules; keep personal routing in the client's override/merge layer or use its proxy-provider integration. GUI-specific merge/provider behavior still needs manual verification.

Health checks default to `https://www.gstatic.com/generate_204`. Change the HTTPS URL in **Subscription server settings → Mihomo health-check URL** or:

```sh
sudo rout subscription mihomo-test-url https://your-health.example/check
sudo rout subscription mihomo-test-url default
```

This optional `settings.json` field is written only after explicit configuration. The server does not fetch the URL; clients perform the checks. Credentials/query parameters/fragments and non-HTTPS URLs are refused. Changing it needs no restart and does not touch Caddy, subscriptions or node credentials. Mihomo may run an initial health check; subsequent checks are lazy at the configured 600-second interval.

## Data allowance and expiry

Each subscription can carry an optional plan: a **shared data allowance** (one pool for all its nodes), a **monthly reset day** (1–31, short months clamp; optional IANA timezone, default the server's) and a **plan expiry date**. Menu: *Edit subscription → Data and expiry*. Command line:

```sh
sudo rout subscription plan                       # every subscription's plan and usage
sudo rout subscription plan ID limit 100          # GB; 500MB / 2TB accepted; 0 = unlimited
sudo rout subscription plan ID reset-day 1
sudo rout subscription plan ID expires 2026-11-27 # none clears it
sudo rout subscription plan ID reset              # start a new cycle now, usage to zero
sudo rout subscription plan ID clear              # remove allowance, reset day and expiry
```

A finite allowance needs traffic monitoring (`sudo rout traffic install`), which supplies the per-node counters. Editing only the expiry date does not.

### What clients see

Subscriptions with a plan add informational entries and a header; a subscription without one is unchanged, byte for byte.

| Entry | Shown when |
| --- | --- |
| `剩余流量：31.27 GB` / `Remaining data: 31.27 GB` | allowance set (decimal units, truncated like the traffic screens) |
| `距离下次重置剩余：3 天` / `Days until reset: 3` | allowance set; days are rounded up |
| `套餐到期：2026-11-27` / `Plan expires: 2026-11-27` | expiry set |

The text follows the language selected in Settings. In the Base64 list the entries come first, as `trojan://rout-info@127.0.0.1:1#NAME` placeholders (no credentials, a closed loopback port). In Mihomo output they are inert `trojan` proxies in a separate `📊 Info` select group; the `🚀 Proxy`, `⚡ Auto` and `🛡️ Fallback` groups and the `MATCH` rule never reference them, so no health check or default selection can pick one. Clients that read the standard `Subscription-Userinfo: upload=…; download=…; total=…; expire=…` header (Clash Verge Rev, Stash, Shadowrocket, Hiddify and others) show a usage bar from the same numbers; only `expire` is sent when no allowance is set. A running subscription helper must be refreshed once after upgrading (`sudo rout subscription refresh`; opening the subscription menu does it too).

### How the allowance is counted and enforced

* Every managed node is already metered in the kernel. The traffic monitor adds each member node's **growth since its previous poll** (upload and download separately) to the subscription's own cycle total in the private journal `subscription-traffic.json` (0600, SHA256 checksum, never read for authentication). Traffic a node used before it joined the subscription, or before the allowance was created, is not charged. A node in several subscriptions is charged to each.
* When the total reaches the allowance the monitor stops the subscription's nodes and remembers them. Their service state is checked every poll (about 5 seconds), so a node restarted by hand, by `rout restart` or after a reboot is stopped again within one poll. This is **not** a per-packet kernel gate like a node's own limit: a few seconds of traffic can exceed the pool, and a node briefly runs after a reboot until the monitor's first poll. Node-level limits keep working independently on top of it.
* At the next reset day (or after raising/removing the limit, resetting, or removing the node from the subscription) exactly the nodes the pool stopped are started again, unless another exhausted allowance or the node's own quota still blocks them. A node you have disabled stays disabled. Start attempts that fail are retried every 30 seconds.
* The subscription itself keeps answering while the pool is empty, so clients see `Remaining data: 0 B` and the dates.
* Reset boundaries follow the same rules as node cycles: civil midnight in the plan's timezone, a clock set back cannot mint a cycle, changing the reset day only reschedules the next boundary and does not clear usage. A counter that goes backwards (monitoring restarted) is charged in full and the cycle is flagged as a lower bound.
* A damaged or tampered journal stops the pool step with an error (it is never read as an empty, fresh allowance); `sudo rout subscription plan ID reset` keeps a private copy and rebuilds it.
* Backups contain the plan (in `state.json`) but not the usage journal; after a restore the first poll starts a new baseline. Setting a limit moves `state.json` to the protected schema, like node limits, so an old backup cannot silently drop it.

### Expiry

The expiry date is informational. Passing it **never disables or restricts** a subscription: the shown date simply renews to the same day of the next month (a date of the 31st is clamped in short months). Only pausing the subscription yourself (*Disable subscription*) blocks its link.

Not verified here: the entries and usage bar in real Shadowrocket, Clash Verge Rev, FlClash or Mihomo Party, and enforcement on a physical VPS (tests use a simulated journal, not live nftables counters).

## Display name

Every successful subscription response includes the subscription's stored name as `Profile-Title: base64:<UTF-8 name>` (read by Hiddify/Happ-style clients) and `Content-Disposition: attachment; filename="<ASCII fallback>"; filename*=UTF-8''<percent-encoded name>` (Clash Verge reads `filename*` from its source). Control characters are stripped, so names with Chinese, spaces or quotes are header-safe. Renaming takes effect on the next fetch; tokens and URLs do not change. A helper started before this change must be refreshed (`sudo rout subscription refresh`). Verified: HTTP headers only; no desktop/mobile client was run. Shadowrocket's handling is not verified.

## Existing v0.3.4 subscriptions survive an upgrade

There is **no subscription schema migration**. The optional `subscriptions` array in `state.json` retains each ID, name, ordered `node_ids`, `token_hash`, `enabled` and `created_at`. `settings.json` retains the subscription enablement, loopback port and public base URL. An unchanged selection produces the same Base64 body, names and order. Existing Shadowrocket URLs continue authenticating; do not delete/recreate subscriptions, rotate tokens, reselect nodes or reimport clients during an upgrade.

Authentication still uses SHA-256 verification hashes of 256-bit random tokens in `state.json`. The same token authorizes all formats. v0.3.7 also keeps a local token copy in `/etc/rout/secrets/subscription-tokens.json`, with mode 0600 inside a 0700 directory (under `--home` for custom installs). This plain JSON file is for the owner’s CLI only; no encryption key, database, manager endpoint or external service is added. It is never read by the HTTP handler or diagnostics, and is excluded from `rout backup`, automatic state backups and upgrade/HTTPS snapshots. These backups still contain existing node credentials and should remain private.

The token copy is written atomically before its state hash is committed. The previous valid copy is retained across an interrupted rotation; obsolete copies are pruned on the next creation/rotation. Revoked tokens cannot authenticate, even while a private copy remains. Missing/corrupt/insecure token storage never changes HTTP authentication or silently rotates tokens. A corrupt file or wrong permissions blocks new creation/rotation with a sanitized error, while existing URLs continue working.

The private file survives normal upgrades/restarts because the home directory stays in place. For a full server migration, copy `secrets/` separately and privately, preserving its permissions; a state-only backup preserves authentication but cannot restore plaintext copies. **Legacy plaintext tokens cannot be reconstructed from hashes.** Read-only views never initialize missing token storage. Ordinary edits and HTTPS operations never rotate tokens.

The installer and newer updater create private, idempotent pre-upgrade snapshots, then refresh only the subscription helper when necessary. They do not recreate a database. Snapshots preserve original bytes, mode, UID and GID and are stored under `/etc/rout/backups` (0700; files 0600). Helper refresh preserves a deliberately stopped service and disabled boot startup. The subscription helper remains `/opt/rout/bin/rout-subscription-v1`.

The **v0.3.4 updater predates automatic subscription refresh**. Its old helper keeps serving the same original URLs after the manager update. Opening subscription management in the newer CLI refreshes that helper; `sudo rout subscription refresh` performs the same operation explicitly. Neither operation touches Caddy, node services, node credentials or subscription records.

## One-click HTTPS

Menu: **Subscriptions → Subscription server settings**:

1. Enable / change local port
2. Configure public HTTPS URL
3. Deploy / repair HTTPS automatically
4. HTTPS status and diagnostics
5. Restart subscription service
6. Disable subscription service
7. Remove Rout-managed HTTPS configuration
8. Mihomo health-check URL
0. Back (`b` also returns; `q` quits)

The local HTTP service is off until enabled and always binds `127.0.0.1` (default 8787). The actual configured port is used by the proxy. No firewall rule is added, and no proxy node's port is changed.

Automatic deployment is supported on **Debian and Ubuntu with systemd**, using Caddy from the distribution's signed apt repository. If Caddy is absent, installation requires a separate explicit confirmation. No downloaded shell installer is executed. Other platforms retain the subscription server and may use externally managed HTTPS; automatic installation/management has no untested fallback.

Enter a DNS hostname such as `sub.example.com`, without a scheme, port or path. Rout resolves every A/AAAA record and compares it with detected public/interface addresses. Correct stale records, including an AAAA record pointing elsewhere on an IPv4-only server, and wait for DNS propagation. Multiple local public addresses and both IP families are supported.

Cloudflare proxy ranges are reported as **origin comparison inconclusive**, not an origin mismatch or proof of correctness. DNS-only mode is preferable for initial certificate issuance; check the origin address and Full (strict) mode before re-enabling the proxy. Rout does not change Cloudflare settings.

TCP 80 and 443 must be reachable from the Internet and available to the verified Caddy service. Rout reports listener owners and refuses conflicts with nginx, Apache, unknown processes or Rout nodes. It never stops them. Provider firewalls/NAT mappings remain your responsibility.

Caddy handles automatic certificate issuance and renewal. Rout validates the generated fragment and complete Caddyfile, atomically writes an isolated fragment, reloads Caddy and verifies TLS and the authenticated response before saving the public URL. Caddy is enabled at boot. The generated site proxies only `/s/*`; `/` deliberately returns 404. Access logging is discarded for the owned site and proxy errors have a generic response so token paths are not logged.

## Existing HTTPS and ownership

A manually configured deployment such as:

```caddyfile
sub.example.com {
    reverse_proxy 127.0.0.1:8787
}
```

remains external. Detection checks installed/running Caddy, its active configuration where available, the configured domain/upstream and an authenticated synthetic response. A working endpoint can also be used externally when its nonstandard proxy layout cannot safely be inspected. Detection does not install another Caddy, duplicate a domain block, reload a working proxy or transfer ownership.

The CLI offers **Use existing HTTPS configuration**, **Inspect configuration summary**, and **Attempt safe adoption**. Using the existing endpoint saves its base URL only when needed. It grants no deletion rights. Inspection does not dump shared configurations, keys or token URLs.

Safe adoption requires an explicitly confirmed, separately imported file containing exactly one simple domain-to-loopback `reverse_proxy` block. Root/shared files, multiple sites, snippets, complex handlers, symlinks, manual certificates and uncertain import layouts remain external. Adoption preserves the existing fragment bytes and does not reload Caddy. If adoption is unavailable, continue using external mode.

For management, Rout proves that the normal systemd Caddyfile configuration matches the active Caddy configuration. A disabled/custom admin API, JSON-based configuration, nonstandard unit, stale disk configuration or uncertain ownership prevents automatic edits. Keep using the verified endpoint externally, or reconcile the layout yourself before retrying. Do not overwrite a shared Caddyfile to satisfy this check.

A new deployment appends one marked absolute import and preserves the existing Caddyfile bytes and imported sites. The fragment lives under `/etc/caddy/rout-<home-hash>/`. Ownership, content digest, domain aliases and last error live in the separate private `/etc/rout/subscription-https.json`; this is not subscription storage. External edits to an owned fragment invalidate automatic modification/removal rights until reviewed.

## Verification and diagnostics

```sh
sudo rout subscription status
sudo rout subscription https status
```

Diagnostics distinguish:

- The init-managed subscription service and its loopback response.
- Installed/running reverse proxy, TCP listener owners and configuration ownership.
- Origin-local HTTPS negotiation, normal certificate validation and expiration.
- An authenticated request through public DNS **from the server itself**.
- Verification from an **independent external network**, which is explicitly unverified unless an independent checker is available.

Local success is not proof of external reachability. `/` returning 404 is normal. Verify the existing subscription over a mobile network in Shadowrocket after upgrading. A configuration write or a process accepting TCP is never labeled a verified public subscription.

The controlled diagnostic route `/s/_rout_probe` requires a fresh 256-bit bearer credential sent in an HTTP header. Only its hash, a two-minute expiry and an inert synthetic Base64 response are temporarily stored (0600). The file is cleaned on completion and expires after a crash. The probe cannot export real nodes. Ordinary `/s/{access_token}` authentication and output are unchanged. Existing user tokens are never read, placed in command arguments or logged for diagnosis.

Caddy's automatic renewal policy and certificate expiry are shown; the last actual renewal event is not independently asserted. External proxy access/error logs remain outside Rout ownership: keep `/s/` token paths redacted or disabled there. Rout's own service log viewer is bounded and redacts token-shaped paths.

## Service controls and port changes

```sh
sudo rout subscription enable 8787
sudo rout subscription start
sudo rout subscription stop              # temporary stop; keeps boot settings
sudo rout subscription restart
sudo rout subscription refresh            # update helper only when needed
sudo rout subscription startup off        # keep running, disable boot startup
sudo rout subscription startup on
sudo rout subscription logs               # sanitized, bounded output
sudo rout subscription disable            # persistent disable; data retained
```

Disabling the subscription service does not stop Caddy or remove HTTPS configuration. Restarting it does not rewrite HTTPS settings. Changing the local port checks conflicts and, for a verified Rout-owned HTTPS site, updates its upstream and verifies both sides. Failure restores the previous settings, helper/unit and owned proxy configuration. An externally managed public URL prevents an automatic port change: preserve the old port or explicitly update that external proxy first.

A managed domain change retains the previous owned hostname as an alias so old client URLs remain reachable. A manually changed public base URL cannot guarantee the old domain remains reachable; clients may need their URL updated. The token itself remains valid.

## Transactions, recovery and removal

Pre-change snapshots include the affected proxy files and private persistence files with their original ownership/modes. Normal deployment never writes `state.json`. Unrelated concurrent configuration is not restored from an old whole-database snapshot. The public URL is changed only after verification.

Validation, reload, certificate or response failure restores the previous owned resources and public URL. Rout verifies restored file bytes and, when applicable, the active Caddy configuration. Concurrent external edits are preserved rather than overwritten. A rollback failure is reported as **incomplete**, with the failed resource and private recovery snapshot; do not assume the endpoint was restored merely because files were copied. After review, restore only the affected owned files, run `sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile`, then reload Caddy and check diagnostics. Do not blindly restore an old `state.json` over subsequent node/subscription edits.

A newly installed Caddy package is retained after a failed deployment; its prior stopped/disabled state is restored. Shared Caddy is never uninstalled automatically.

Use **Remove Rout-managed HTTPS configuration** (or `sudo rout subscription https remove`) and explicitly confirm the domain list. Only a digest-verified owned/adopted fragment can be removed. A harmless placeholder remains so exact imports stay valid. Caddy, unrelated sites, TLS certificates, subscriptions, tokens, selections and the saved public URL are preserved. External configurations cannot be automatically removed.

## Manual fallback and troubleshooting

For unsupported layouts/platforms, keep the loopback service and configure your existing reverse proxy to forward `/s/` to its actual `127.0.0.1:PORT`. Configure its TLS and token-safe logging, then set the public HTTPS base URL through Rout. This does not transfer ownership.

| Symptom | Check |
| --- | --- |
| HTTPS protocol/connection error while loopback works | Caddy/proxy listener, DNS, certificate issuance, provider firewall/NAT and TCP 80/443 |
| DNS mismatch | Every A/AAAA record, all server public addresses, propagation; distinguish Cloudflare proxy addresses |
| 404 at `/` | Expected; use authenticated diagnostics or the original client subscription |
| 404 at `/s/TOKEN` | Original saved token, disabled/deleted subscription, wrong prefix or explicit prior token rotation |
| Probe unavailable after a v0.3.4 update | `sudo rout subscription refresh`; old user tokens remain valid |
| 503 | Local service stopped, state unreadable, or no selected node currently available; never treated as an empty success |
| External site cannot be adopted | Keep external mode; only a standalone simple imported fragment is eligible |
| Owned file changed externally | Preserve it and inspect its ownership/digest; Rout refuses to erase the change |
| Rollback incomplete | Inspect the exact private snapshot and resource named in the error, validate/reload after review, then test the original URL |

## Test boundaries

Unit/race tests cover v0.3.4 persistence, token validity, ordering/Base64 output, URL preservation, DNS families/Cloudflare, conflicts, ownership/adoption, rollback, port changes, diagnostics, bilingual menus and routing/traffic invariance. Isolated real Caddy tests cover a fresh signed-package installation, automatic private test-CA certificates, real TLS responses, preservation of an unrelated site and saved URL, repair/restart/removal, error-log redaction and failed replacement rollback. Disposable systemd CI tests upgrade the checksum-verified v0.3.4 release binary and a helper built from the pinned v0.3.5 release commit (which has no binary assets), and verify the original token/body and persisted Reality/AI/traffic/relay state, restart and boot-state preservation.

The pinned Mihomo v1.19.32 core also validates generated configurations and sends real TCP/UDP traffic through VLESS Reality Vision, SS, Hysteria2 and TUIC, including rejection of wrong pins. GUI clients (Clash Verge Rev, FlClash and Mihomo Party) have not been exercised here. These tests do not claim public ACME issuance on your domain, real Shadowrocket interaction or production verification. Check public certificate issuance, external reachability, mobile client refresh and existing proxy/AI behavior on the actual VPS before release.
