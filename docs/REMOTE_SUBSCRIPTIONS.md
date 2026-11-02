# Third-party subscription import and aggregation (v0.5.0)

Rout can import subscriptions from other providers (or other Rout instances), keep them as separate **sources**, and combine chosen nodes from any source together with local nodes into an **aggregate** subscription. Imported nodes are never mixed into Rout's own node list.

## Accepted inputs

- Base64 share-link lists (plain or Base64-encoded)
- Mihomo / Clash YAML (`proxies:`)
- A single share link
- Another Rout instance's subscription URL (Base64 or `?format=mihomo`)

Supported protocols: VLESS (TCP/WS/gRPC, TLS, Reality, Vision flow), Shadowsocks (including 2022), Trojan, Hysteria2, TUIC v5, AnyTLS.

**Not supported** (reported as parse issues, never guessed): VMess, ShadowsocksR, Hysteria v1, WireGuard, SOCKS/HTTP proxies, sing-box JSON, and transports/options that Rout cannot express. A node is imported only when every field that matters for connecting (TLS/Reality/auth/transport) is preserved; otherwise it is listed under the source's issues with the reason.

## Sources

Each source has a name, note, tags, URL (stored in a 0600 file, redacted everywhere else), refresh interval and per-node enable switches. The page shows last success, valid/total counts and parse errors. A failed refresh keeps the last good snapshot and records the error. Snapshots are replaced atomically.

Limits: response ≤ 8 MiB by default (hard cap 32 MiB), YAML ≤ 3 MiB with node-count and nesting checks, at most 2000 nodes per source, 30 s timeout, at most 3 concurrent refreshes, never two jobs for the same source. Scheduled refresh runs per source on its configured interval (with a stable jitter) inside `rout-web` and resumes after a restart using persisted status. Refreshing never restarts proxies.

YAML is parsed under one complexity budget: aliases and merge keys (`<<`) are expanded with cycle detection (a self-referencing alias or merge sequence is rejected with a readable diagnostic), every visited node counts against a fixed limit, nesting depth is capped, and the refresh context is polled so a timed-out or cancelled refresh stops and frees its concurrency slot. Ordinary anchors, aliases and merges keep working.

The source definitions file (`remote/sources.json`) is limited to 8 MiB serialized. Every change (add, edit, delete, import, restore) is size-checked before an atomic replace and refused with an explanatory message if the result could not be read back; a refused change leaves the file untouched. A file that an earlier build left over the limit can still be shrunk by deleting or editing sources, but never grown.

## Fetch safety (SSRF)

Only `http`/`https` URLs. The fetcher resolves the hostname, rejects loopback, private, link-local, multicast, unspecified and cloud-metadata ranges (IPv4 and IPv6, including IPv4-mapped), connects only to the validated address (defeats DNS rebinding), and revalidates every redirect (maximum 5) the same way. Content is treated as untrusted data: it is parsed, never executed, and echoed only after sanitising.

## Aggregates

A subscription may now hold items of three kinds: a local node, a whole source, or specific nodes of a source. Order is explicit and editable; items can be renamed, deduplicated (by protocol + server + port + credential identity) and appear in several aggregates. Sources and local nodes are never modified. Output formats: Base64 and Mihomo YAML on the existing `/s/TOKEN` URL (`?format=mihomo`). Nodes that cannot be represented in a format are omitted and listed in a compatibility report (shown in the panel and returned by the API), never emitted as pseudo-valid configuration. sing-box JSON and Quantumult X output are not implemented.

Entries that share protocol, server, port and credential but differ in any connection setting (WebSocket path, SNI, flow, ...) are different connection choices and are all imported; only an exact repeat (same settings, possibly another name) counts as a duplicate. Each variant gets a node ID and fingerprint derived from its connection settings, independent of the order the provider lists them, so aggregates can include or de-duplicate them independently. A node whose endpoint is unique keeps an identity that does not depend on its other settings. If a provider later adds a second variant of an endpoint, the existing node's ID changes once, because it is no longer the only one.

A subscription without remote items produces byte-identical output to v0.4.0.

## Failure isolation

A source that is down, malformed or slow only affects its own entries in aggregates (the last good snapshot is used). Local nodes, local-only subscriptions and `/s/TOKEN` for them are unaffected.

## Verification status

Parsing, aggregation and output are covered by unit and API tests, including malicious/oversized YAML, redirect SSRF, DNS rebinding with a fake resolver and concurrent refresh. Output was parsed back with the same parsers. Real third-party providers and real Clash/Shadowrocket clients have **not** been tested in this release.
