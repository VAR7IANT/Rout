# Node outbound IP family

Per-node control of which IP family a node uses to reach the Internet: **Auto** (default), **IPv4 first**, **IPv6 first**, **IPv4 only**, **IPv6 only**. It is independent of the inbound listen mode (a phone can connect to an IPv4 listener while the node leaves over IPv6) and of the VPS's default route; nothing outside the node's own sing-box process is changed.

- [1. Policies](#1-policies)
- [2. How it is enforced](#2-how-it-is-enforced-and-what-sing-box-1143-does-and-does-not-do)
- [3. Outbound proxies](#3-outbound-proxies-what-the-policy-can-and-cannot-mean)
- [4. Where to set it](#4-where-to-set-it)
- [5. Egress test](#5-egress-test)
- [6. Persistence and upgrades](#6-persistence-and-upgrades)
- [7. Limits](#7-limits-and-what-was-not-verified)
- [8. Tests](#8-tests)

## 1. Policies

| Policy | Stored value | Behaviour |
| --- | --- | --- |
| Auto | *(unset)* | Exactly what earlier versions did. The generated configuration is byte-for-byte the old one (75 configurations compared against the previous release: all identical). |
| IPv4 first | `ipv4_first` | Names resolve to A records first; AAAA is used when IPv4 fails. IPv6 literals are allowed. |
| IPv6 first | `ipv6_first` | Names resolve to AAAA records first; A is used when IPv6 fails. **This is not IPv6 only.** IPv4 literals are allowed. |
| IPv4 only | `ipv4_only` | IPv6 is never used. IPv6 literals and AAAA-only names are **refused explicitly**. |
| IPv6 only | `ipv6_only` | IPv4 is never used. IPv4 literals, IPv4-mapped IPv6 literals (`::ffff:a.b.c.d`) and A-only names are **refused explicitly**. A DNS failure never produces an IPv4 attempt. |

The field is the node's existing `outbound_policy` (`state.json`). A node that never chose one does not write the key at all; "Auto" is stored as unset, so an Auto node's `state.json` and `config.json` are unchanged by this feature. (Relays have always had their own `outbound_policy`, with their own engine and rules; that is unchanged and `SetNodeOutboundPolicy` refuses a relay.)

## 2. How it is enforced, and what sing-box 1.14.3 does and does not do

A "DNS prefers IPv6" setting is **not** an IPv6-only guarantee, and this is what Rout was checked against with the pinned engine (sing-box v1.14.3, real binary, not documentation):

| Observation (real engine) | Consequence |
| --- | --- |
| `dial.domain_resolver.strategy = ipv6_only` makes an **A-only name** fail to resolve — the connection fails and nothing falls back to IPv4. | Used for names. |
| The same setting does **not** stop a client that asks for an **IPv4 literal** (`203.0.113.9`): the connection is made over IPv4. | A resolver strategy alone is not "IPv6 only". |
| The deprecated outbound `domain_strategy` is **fatal** in 1.14.3 (`sing-box check` refuses it). | Never generated. |
| sing-box folds an IPv4-mapped IPv6 literal (`::ffff:a.b.c.d`) to IPv4 before routing. | The family rule catches it too. |
| A UDP association picks one address family when the session starts. | See §7. |

So an "only" policy on a Direct node has two parts, both written by Rout, never by hand:

```jsonc
// outbound "egress"
{ "type": "direct", "tag": "egress",
  "domain_resolver": { "server": "rout-egress-dns", "strategy": "ipv6_only" } }   // names
// dns
{ "servers": [ { "type": "local", "tag": "rout-egress-dns" } ] }                 // the system resolver, as before
// route.rules (just before the ordinary entry -> egress route)
{ "inbound": ["entry"], "ip_version": 4, "action": "reject" }                    // literals
```

IPv4 only is the mirror image (`ipv4_only`, `ip_version: 6`). "First" policies set only `prefer_ipv4` / `prefer_ipv6` on the resolver and add no rule. Order matters and is tested: the IPv6-inbound guard stays first, AI-routing rules come before the family rule (AI traffic follows the AI exit, not the node's policy), and the family rule precedes the ordinary route. Reality/TLS, certificates and protocols are not involved; `config.json` is regenerated from `state.json` on every change, `rout apply` and restore, and is never edited by hand.

Real-engine tests that prove it (`internal/rout/node_egress_integration_test.go`): each mutation below makes tests fail —

* remove the `ip_version` rule → IPv4 literals and IPv4-mapped literals get through under IPv6 only;
* downgrade `ipv6_only` to `prefer_ipv6` ("DNS prefers IPv6" posing as IPv6 only) → A-only names and the IPv4 half of a dual-stack name get through;
* drop the resolver → every non-Auto policy loses its name behaviour.

## 3. Outbound proxies: what the policy can and cannot mean

When a node has an outbound proxy (SOCKS5, HTTP CONNECT, HTTPS CONNECT, a remote node), Rout dials the **proxy server**; the proxy dials the website. So:

* the policy governs only how this server connects **to the proxy server** (the proxy's `domain_resolver` carries it);
* **no destination-family rule is generated** — which family the proxy uses towards the website is the proxy's decision and Rout cannot enforce it;
* nothing claims otherwise: the panel shows *Not enforced* with an explanation, the menu and the diagnosis print the same note, and the egress test reports "could not be verified" for that part instead of a pass;
* nothing falls back silently: if the proxy cannot be reached over the allowed family, the connection fails (it never becomes a Direct connection), and UDP stays rejected on a proxy node as before;
* a **literal** proxy address of the forbidden family (an IPv4 proxy with IPv6 only) can never be reached, so Rout refuses to save that combination.

| Exit | IPv4 only / IPv6 only means | Website-side family |
| --- | --- | --- |
| Direct | enforced (names and literals) | the node's own |
| SOCKS5 / HTTP / HTTPS CONNECT | family used to reach the proxy server only | the proxy's decision, not enforced |
| Remote node (node link) | family used to reach the remote node only | the remote node's own policy, not enforced |

To control the family of the final exit, set the policy on the node that actually connects to the website (for a remote node, on that server).

## 4. Where to set it

**Terminal.** *Create node → Confirm → Advanced options → Outbound IP family* offers the five choices with fixed numbers (`1 Auto … 5 IPv6 only`, default 1). Quick create asks nothing and stores Auto. *Manage nodes → choose a node → Outbound IP family* (the new last entry; existing numbers are unchanged) offers *Change*, *Test IPv6 egress* and *Show outbound IPs*. A family the VPS has no route for is annotated, not hidden; choosing IPv6 only on an IPv4-only VPS (or the reverse) asks for explicit confirmation, because every connection would fail. The node card shows `IP family: IPv6 only` only for non-Auto nodes.

**Web panel.** *Nodes → New nodes* has an *Outbound IP family* field; the node drawer has the same selector, the current value, whether it is enforced, a *Save policy* button (restarts only that node) and the egress test. It works on phones. API: `GET /api/nodes` (`outbound_policies`, and per node `outbound_policy`, `outbound_scope`, `outbound_enforced`, `outbound_note`), `POST /api/nodes` (`outbound_policy`, `force`), `PUT /api/nodes/{id}/outbound-policy` (`{policy, force}`; `409 no_route` until confirmed), `POST /api/nodes/{id}/egress-test` (`{quick}`).

Both go through `SetNodeOutboundPolicy`: validate (including `sing-box check`), rewrite only that node's configuration, restart only that node, and restore state and files if anything fails. UUID, port, certificate and subscription links are not touched.

## 5. Egress test

*Test IPv6 egress* / `POST /api/nodes/{id}/egress-test` measures, not assumes:

* **Host network test** — this server's own routes, DNS and public addresses, **without the node**. Always labelled as such; it is never shown as the node's behaviour.
* **Node egress test** — requests through the node's own inbound with a temporary sing-box client, the same path the protocol test uses, so they leave through the node's real outbound with its real policy: the address seen per family, and a request to a **bare IP address** of each family (what a resolver strategy alone does not cover).

For an "only" policy it passes only when the allowed family works through the node **and** the forbidden family fails through the node **while the same kind of request succeeds from the host** (the control). If the host cannot do it either, the result is **inconclusive**, never a pass. The temporary client lives for a bounded time, so a measurement that outlasts it is **aborted** and reported as inconclusive: a request that failed because the client was gone is never read as the node refusing a family (a failure only counts if the client is verified alive afterwards). A node that leaks (policy stored, running configuration without the rule) fails, which is tested end to end. Results are `pass`, `fail` or `inconclusive`; a *Show outbound IPs* look carries no verdict.

## 6. Persistence and upgrades

* Stored per node in the existing profile; no new file, no migration. Old states, backups (`rout backup`, `--full`, the panel bundle) and restores load as Auto; a policy survives restart, `rout apply`, backup/restore and a new process.
* `rout update` replaces the program only. The policy lives in `state.json`, so the new program regenerates the same configuration; `rout apply` after the update rewrites it from the state.
* Relay `outbound_policy`, NAT-VPS hosts, AI smart routing, subscriptions, exits and the other nodes are untouched by a change (compared byte-for-byte in tests).
* **Downgrade.** The previous release (v0.5.1) already accepts a valid `outbound_policy` on any profile, so it loads a state that contains node policies, but it does **not** apply the field to nodes: after a downgrade (or restoring such a state into the older program) those nodes leave with the old, unrestricted behaviour. Nothing breaks loudly, so set nodes back deliberately before downgrading if the restriction matters, and re-check with *Test IPv6 egress* after any version change.

## 7. Limits and what was not verified

* **UDP** (Hysteria2, TUIC, UDP over SOCKS): a session selects its address family once, when it starts; there is no per-packet fallback. "First" policies therefore fall back between sessions, not within one.
* **Reality handshake** and the **AI exit** connection are outside the policy (the first is the camouflage server's dial; the second is the AI route's own exit).
* A failing DNS server makes names fail; Rout does not invent an address.
* **Proxy exits**: see §3 — the website-side family is not enforced and cannot be verified from here.
* The sandbox used for development has **no IPv6**. Tests that need an IPv6 listener or route (`::1` origins, the IPv6-success side of IPv6 only, the IPv6 side of IPv4 only) skip there and run in CI on GitHub's runners. Tests that prove the *exclusion* (IPv4 refused under IPv6 only) run everywhere.
* **Not done:** a real dual-stack VPS (the acceptance scenario below), real providers, real phones. Loopback results are not production acceptance.

Acceptance scenario for a real VPS: dual-stack host, VLESS Reality node, inbound IPv4, outbound Direct, IPv6 only. A phone connects over IPv4 → VLESS works; IPv6 sites work and see the VPS's IPv6 address; an IPv4-only site fails (no silent IPv4 fallback); the setting survives a Rout restart; `rout apply` keeps it; the panel shows and changes it; *Test IPv6 egress* reports a pass.

## 8. Tests

`internal/rout/node_egress_test.go` (configuration shape, legacy parity, validation, route check, rollback), `node_egress_integration_test.go` (real sing-box: IPv6 only / IPv4 only / IPv6 first / IPv4 first / Auto, A-only, AAAA-only, dual-stack, IPv4/IPv6/IPv4-mapped literals, DNS failure, no-fallback counters on the origins, the resolver-alone question, proxy exits, a real Reality client, policy switching, the egress test against a leaking node), `node_egress_ui_test.go` (menus, diagnosis, the egress verdicts), `node_egress_web_test.go` (API), `node_egress_compat_test.go` (state format, apply, restart, backup/restore, relays, NAT, AI routing), and `web/src/pages/NodeEgress.test.tsx`.
