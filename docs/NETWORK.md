# Address families, relay engine, TCP/UDP capability and layered tests

This document explains how Rout separates the address family a relay *accepts* connections on from the family it *uses* to reach its destination, why relays have their own forwarder, what a NAT can and cannot carry, and what each kind of test proves. Everything here is for hosts you operate; none of it creates an open proxy.

## 1. The model

Two settings, stored on the relay, independent of each other:

| Field | Values | Meaning |
| --- | --- | --- |
| `inbound_mode` | `ipv4`, `ipv6`, `dual` | Which families the entry accepts connections on |
| `outbound_policy` | `ipv4_first`, `ipv6_first`, `ipv4_only`, `ipv6_only`, `auto` | Which families it may use to reach the destination |
| `engine` | `native` (absent = legacy GOST) | Which forwarder runs it |
| `target_network` | `tcp` (absent = unknown) | The destination is known to accept TCP only |

A profile written by an older version has none of these. Its mode is derived from its listening address exactly as that version behaved: `0.0.0.0` → IPv4, a specific address → its own family, `::` → dual stack unless the creation-time probe recorded that IPv4 does not reach it. Nothing is rewritten on load.

### Why the old behavior forced dual stack

* `Settings → Server address` picked a listening wildcard once (`::` whenever the host had a global IPv6 address and a working dual-stack socket) and relays copied it without asking. A dual-stack host therefore could not get an IPv4-only relay.
* The node menu mapped its **IPv6** option to the same `::` listener as **dual stack** and recorded "also serves IPv4", so IPv6-only could not be selected on a capable host.
* A node switched to an IPv6 public address was upgraded to `::` after a default-yes question.
* GOST, the relay engine, binds `::` with a dual-stack socket (`network = "tcp"`), never IPv6-only, and offers no way to restrict the families it dials.

### Sockets

A native entry binds one *explicit* socket per family and transport. Go sets `IPV6_V6ONLY` on every `tcp6`/`udp6` socket, so the result does not depend on `net.ipv6.bindv6only`, on a wildcard fallback, or on probing a dual-stack socket.

| Mode | Sockets (TCP shown; UDP the same with `udp4`/`udp6`) |
| --- | --- |
| `ipv4` | `tcp4 0.0.0.0:P` |
| `ipv6` | `tcp6 [::]:P` (IPv6 only) |
| `dual` | `tcp4 0.0.0.0:P` **and** `tcp6 [::]:P` |

Dual stack is offered only when an IPv4 and an IPv6 socket can really share a port on this host (they are bound and released at creation). If any socket cannot be bound, the relay does not start half-bound: the service stops with an error naming the failing family, and every socket already opened is closed. Changing a relay's family restarts it; the old sockets are released when it stops (a stopping relay also closes its live tunnels).

sing-box nodes cannot set `IPV6_V6ONLY`. An explicit **IPv6** node listens on `::` and its first routing rule rejects every IPv4 source (`0.0.0.0/0`), so IPv4 clients complete no session; the socket itself still accepts IPv4 connections at the TCP level. This is the engine's limit, stated rather than hidden. Dual-stack nodes stay a single verified `::` listener (a second `0.0.0.0` listener would collide with a dual-stack wildcard).

## 2. Outbound policy and DNS

| Policy | Resolves | Tries |
| --- | --- | --- |
| `ipv4_first` | A and AAAA | IPv4 addresses, then IPv6 as a fallback |
| `ipv6_first` | A and AAAA | IPv6 addresses, then IPv4 as a fallback |
| `ipv4_only` | A only | IPv4 only; a literal IPv6 destination is refused when the relay is saved (and at dial time) |
| `ipv6_only` | AAAA only | IPv6 only; a literal IPv4 destination is refused |
| `auto` | A and AAAA | Addresses the kernel has a route to (checked per destination, loopback needs none), interleaved IPv6-first with a 250 ms head start (Happy Eyeballs), the family that worked last for this host first |

IPv4-mapped IPv6 literals (`::ffff:192.0.2.1`) count as IPv4. A family is never "tried and failed silently": the `only` policies never open a socket of the other family.

DNS is cached for 30 s per name (Go does not expose record TTLs, so the lifetime is a fixed upper bound), a failed lookup for 3 s. A dial that fails on every cached address invalidates the name and resolves once more before giving up, so a destination with a dynamic address recovers without waiting for the cache. When a refresh fails, the previous answer is reused for up to ten minutes; the layered test reports its age. Concurrent connections share one lookup, which runs detached from any single caller.

Loop protection: the forwarder refuses to connect to its own listening port on a local address, `relayLoop` rejects chains at save time, and the layered test reports a name that resolves to this host.

## 3. TCP and UDP capability

A plain TCP port mapping can carry TCP and nothing else.

| Protocol | Transport |
| --- | --- |
| VLESS (Reality), AnyTLS, Trojan | TCP |
| Shadowsocks | TCP and/or UDP |
| Hysteria2, TUIC (QUIC) | UDP |
| SSH, HTTP/HTTPS | TCP |

Rout therefore refuses, with an explicit message, a UDP protocol aimed at a destination that only accepts TCP (declared by the user for a manual destination, or contradicted by the link). It never writes UDP into a TCP socket.

**UDP-over-TCP was evaluated and is not implemented.** An honest implementation needs a decapsulating peer on the far side; an arbitrary NAT or third-party server has none, and Rout does not install software on remote hosts. It also turns QUIC's datagrams into an ordered byte stream, so one lost TCP segment stalls every QUIC packet behind it, defeating QUIC's own loss recovery and congestion control, and Hysteria2's performance modes do not survive it. If both ends are under your control, a compatible tunnel of your own (for example a GOST relay tunnel configured on both ends; Rout does not test it) can carry the UDP service, and Rout will then forward to the tunnel's TCP entry as an ordinary TCP relay.

Remote server exits use the same table: a Hysteria2/TUIC node needs UDP to the remote server, so it is refused when the NAT is declared TCP-only, and its test uses the QUIC probe.

## 4. Remote server exits

An exit is stored once (`state.json`, mode 0600) and referenced by ID. A *Remote server* is an exit whose far end is a real service:

* `protocol: node` + `link`: the share link of a node on the remote host. `URIOutbound` converts it to the sing-box outbound (tag `egress`) and the node's own route sends everything there; UDP from clients is rejected like for every outbound proxy. A link that cannot be converted fails closed (an outbound to a closed local port), never to a direct connection.
* an authenticated SOCKS5/HTTP/HTTPS proxy (`kind: remote`); accounts are mandatory.

Not accepted: a bare port mapping (the destination would still see this server's IP), unauthenticated proxies, certificate-pinned Hysteria2 links. Credentials are redacted from logs (`rout logs`) and never printed by lists, *View* or diagnostics.

Deleting an exit is refused while a node or AI Smart Routing references it; editing one rewrites only the nodes that reference it.

## 5. Layered diagnosis

| Layer | Function | Evidence |
| --- | --- | --- |
| 1 Local listening | `layerListen` | `/proc/net/{tcp,tcp6,udp,udp6}` entries for the expected family/address/port; service state; stray sockets outside the mode |
| 2 Destination resolution | `layerTarget` | Resolver output split by family, policy match, stale-answer notice, self-loop |
| 3 Destination connectivity | `layerTarget`, `quicVersionProbe` | TCP handshake with the address and family used; classified errors; QUIC Version Negotiation (RFC 9000 §6) for UDP protocols |
| 4 Relay availability | `probeThroughTCP` | Connection to the relay's own entry per family: bytes from the destination, or a connection that stays open; an immediate close is a failure |
| 5 Proxy protocol | `layerProtocol`, `proxyHandshake` | TLS camouflage handshake (Reality), SOCKS5/HTTP(S) credential exchange, sing-box client handshake |
| 6 Real exit | `layerExit` | Exit address per family through the chain; failure stage and cause |

A QUIC server that does not answer the probe (UDP filtered, obfuscation) is *inconclusive*, never a pass. Layers 5–6 need the pinned sing-box and, for the exit address, Internet access from the host.

## 6. What each kind of test proves

| Kind | Where | What it proves | What it does not |
| --- | --- | --- | --- |
| Unit / simulated | every `go test` | Logic: the family model, orderings, refusals, config generation, persistence, migration, compatibility, scripted CLI flows, diagnostics against scripted DNS/dialers and real loopback sockets | Anything about a real network |
| Engine integration | `ROUT_TEST_ENGINES` (CI installs the pinned engines) | Real VLESS Reality, AnyTLS, Shadowsocks, Hysteria2 and TUIC traffic through the native forwarder; remote-node exit with right and wrong credentials; an IPv6-only node refusing IPv4 clients; `rout relay-serve` as a process; the hardened systemd unit (`ROUT_TEST_SYSTEMD=1`) | A provider's NAT, firewall or IPv6 routing |
| Real network | `ROUT_TEST_REALNET=1` | Each outbound policy dials a real dual-stack host over the intended family; a public QUIC server answers the probe; a full diagnosis of a relay to a public host | Your own VPS/NAT unless you run it there |

IPv6 socket tests (`IPv6-only entry refuses IPv4`, `dual stack uses two sockets`, `IPv4 in → IPv6 out`) need an IPv6 stack and skip themselves without one; on hosts without IPv6 the same flows are covered with an injected bind probe, and the real-socket assertions run in CI where `::1` exists.

## AI exits through relays (v0.5.1)

A relay is a port forward, not an exit (see [AI_ROUTING.md](AI_ROUTING.md#ai-exits-through-a-relay-v051)). AI Smart Routing can dial its exit **through** a relay: the bound node's AI outbound connects to the relay's own listener on loopback (`127.0.0.1` for an IPv4 or `0.0.0.0` listener, `::1` for `::`), and the relay forwards to the real proxy with its own outbound policy. Typical uses:

| Situation | Chain |
| --- | --- |
| The proxy is reachable from this host only over IPv6 (or only over IPv4) | loopback relay with `ipv6_only` (or `ipv4_only`) → proxy |
| The proxy is behind a NAT or IPv6-only box that maps a port to it | *forwarder on another server* (`via_address`) → proxy |
| A remote node should be reached through a specific path | relay → remote node link (SNI and host parameters are kept) |

Only TCP crosses the chain; a Hysteria2/TUIC end needs a relay that forwards UDP and a target that is not TCP-only. Relays created for a chain by the AI menu listen on `127.0.0.1` only and are never published to clients.

## Panel HTTPS on IPv6-only and NAT hosts (v0.5.1)

The panel backend listens on `127.0.0.1:8790`; Caddy serves the public side on whatever families the host has. On an **IPv6-only** server only an AAAA record is needed and Let's Encrypt validates over IPv6 (HTTP-01 on TCP 80 / TLS-ALPN-01 on TCP 443); an A record pointing elsewhere makes validation fail and is reported. On a **NAT** host (the public address is not on an interface) issuance works only when the provider forwards public TCP 80 and 443 unchanged to this host; a NAT VPS with only high mapped ports cannot get a certificate by HTTP-01/TLS-ALPN-01 and should use the SSH tunnel. Rout detects this, explains it and asks for explicit confirmation; it never modifies the host firewall.
