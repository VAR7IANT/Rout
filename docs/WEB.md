# Web management panel (v0.5.1)

The panel is a separate service, `rout-web`, that serves a React + TypeScript single-page app and a JSON API from the same Go binary (`rout web serve`). It manages nodes, relays, exits, subscriptions, third-party sources and the system. The terminal menu and all CLI commands keep working and share the same state files.

## Quick start

```sh
sudo rout          # main menu 8 → 1 "One-click install / initialize panel"
sudo rout web setup  # the same wizard as a command
```

The wizard is safe to run again at any time. It:

1. detects the distribution, architecture and init system (systemd or OpenRC), and the public IPv4/IPv6 addresses, recognizing IPv6-only and NAT hosts;
2. sets the admin password if none exists — generated and printed **once** (save it), or typed twice and never echoed; it is never written to a log;
3. installs or refreshes the `rout-web` service on `127.0.0.1:8790` and checks that it answers;
4. asks for an admin domain. Leave it empty to use only an SSH tunnel. With a domain it deploys HTTPS (next section) and ends with:

```text
✓ Rout Web installed successfully
✓ Web service working
✓ IPv6 network working
✓ DNS verified
✓ HTTPS certificate valid
✓ Reverse proxy working
✓ Login page reachable
Management panel:
  https://panel.example.com
Status: running
```

Main menu 8 also offers start/stop/restart, status and address, set/change domain, set/reset password, HTTPS deployment and repair, logs/diagnostics and uninstall. Every action returns to the same page. The classic commands keep working: `rout web passwd --generate|--stdin`, `rout web install [--port N]`, `rout web start|stop|restart|status|logs|uninstall`, `rout web host add|remove NAME`, `rout web https DOMAIN` (prints a Caddy snippet only), `rout web serve`.

Without a domain the panel listens on `127.0.0.1:8790` only. There is no public admin port. Reach it with an SSH tunnel:

```sh
ssh -L 8790:127.0.0.1:8790 user@your-vps
# then open http://127.0.0.1:8790/
```

The password can only be set from the CLI, never through the API. It is stored as PBKDF2-HMAC-SHA256 (600000 iterations) in `web.json` (mode 0600).

## Pages

| Page | Contents |
| --- | --- |
| Dashboard | CPU, memory, disk, network, IPv4/IPv6 availability, node/relay/exit/subscription counts and states, live and cumulative traffic, alerts, certificate status, quota reminders |
| Nodes | list, search/filter, bulk start/stop/delete, create/edit (VLESS Reality, AnyTLS, Hysteria2, SS2022, TUIC, Snell v5 / v6 beta; local IPv4/IPv6, NAT relay, SOCKS5/HTTP/remote exit), share link and QR, connection/traffic test |
| AI Routing | enable/disable, inbound node checklist, AI exit selection (existing exit, through an existing relay, remote node link, forwarder on another server), path preview for ordinary and AI traffic, end-to-end exit test with the observed exit IP, rule simulation, identification limits |
| Relays & exits | local/remote/NAT relays, TCP/UDP, IPv4/IPv6/dual listen, outbound policy, SOCKS5/HTTP(S)/remote-node exits and relay chains, which exits/AI depend on a relay, references and delete protection, entry → exit path, layered tests |
| Subscriptions | CRUD, enable/disable, node add/remove/sort, plan (quota, reset, expiry), Base64 and Mihomo URLs, QR, token rotation, aggregates (local + remote items) |
| Sources | third-party subscriptions: add, refresh, per-node enable, parse issues, tags |
| System | version/update status, service control, logs, backup and restore, subscription HTTPS status, panel HTTPS health (DNS, ports, Caddy, ACME, certificate, Host allow-list, login page) with a re-authenticated repair, panel settings, sessions and audit log |

Interface languages: 简体中文, 繁體中文, English. The interface is terminal-styled (monospace, dark by default whatever the system setting; a light "paper" theme can be chosen in the sidebar, or in the menu on phones). `Ctrl K` / `⌘K` opens a command palette that jumps to any page, switches language or theme, and signs out; `/` focuses the filter of a list page. The layout adapts from 320 px phones to desktop: tables turn into cards, the side navigation becomes a bottom tab bar, long IPv6 addresses, domains and links wrap instead of widening the page.

## Security model

- **Authentication.** Server-side sessions kept in memory (idle timeout 60 min, absolute 12 h, at most 20 sessions; all configurable within bounds). Restarting `rout-web` signs everyone out. The browser holds only the cookie `rout_session` (`HttpOnly`, `SameSite=Strict`, `Secure` over HTTPS or when a loopback proxy sets `X-Forwarded-Proto: https`). No credential is placed in `localStorage` or `sessionStorage`; the CSRF token is kept in memory.
- **CSRF.** Every state-changing request needs a matching `Origin` (or `Sec-Fetch-Site: same-origin`/`Referer`), the `X-CSRF-Token` header and `Content-Type: application/json`.
- **Host allow-list.** Requests with an unknown `Host` get `421`. Add names with `rout web host`.
- **Login rate limit.** Failed logins are limited per address and globally with `Retry-After`; a successful login rotates the session.
- **Re-authentication.** Dangerous operations (restore, restart services, rotate tokens, reveal secrets, delete, change panel settings) require the password again within the last 5 minutes (`403 reauth_required`). The UI prompts for it and retries.
- **No secrets in responses.** Passwords, tokens, private keys and remote-source credentials are redacted in every view; reveal endpoints are explicit, re-authenticated and audited. Remote-source URLs are stored with credentials in a 0600 file and redacted in logs.
- **No shell from input.** User input never reaches a command line; service actions are a fixed set of verbs.
- **Headers.** Strict CSP (no inline script), `X-Content-Type-Options`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` on the API.
- **Audit.** The last security-relevant actions are kept in an in-memory ring buffer shown under System.
- **Privilege.** `rout-web` runs as root (like the manager) because it manages services and files. It is not sandboxed by systemd `ProtectSystem`. Keep it on loopback.

## HTTPS for the panel

`rout web https deploy panel.example.com` (or the wizard / menu 8 → 6) deploys and verifies HTTPS with Caddy. `--install-caddy` and `--start-caddy` give the consent the menu asks for interactively; `--accept-nat` confirms that a NAT forwards public TCP 80/443 to this host. `rout web https repair` re-runs the deployment for the recorded domain, `rout web https status` prints the diagnosis, `rout web https remove` removes the panel site.

**Where automatic deployment works.** Exactly this combination, which is what the code checks before it touches anything: systemd as the init system, `ID=debian` or `ID=ubuntu` in `/etc/os-release`, and Caddy either absent (Rout may install the distribution's `caddy` package after you confirm) or already running as the `caddy` systemd service from `/etc/caddy/Caddyfile` (`--config /etc/caddy/Caddyfile`, no `--resume`, a root-owned, not group/world-writable file whose adapted form equals the running configuration). The real-Caddy test runs on **Debian 12** (Caddy 2.6.x from apt); Ubuntu and derivatives are expected to behave the same but are not exercised by CI.

**Everywhere else it is manual, and Rout says so instead of pretending.** On Alpine/OpenRC, other distributions (including Debian/Ubuntu derivatives whose `ID` differs), Docker/snap/binary Caddy, API-configured or `--resume` Caddy and non-standard services, `rout web setup` still installs and starts the panel (systemd or OpenRC) and the menu prints the Caddy snippet; `rout web https deploy` refuses with a clear message. Run `rout web https DOMAIN` (records the domain in the Host allow-list and prints the snippet), put the site into your own reverse proxy, validate it with your proxy's own tool, and reload. Rout then neither installs, edits nor removes anything of that proxy, and `rout web https status` reports the site as *external*.

What the deployment does, in order (nothing is changed until every check passes):

- **Panel service** must answer on loopback.
- **Domain**: an ASCII DNS name, not one used by Rout's subscription site (`hk.example.com` → `panel.hk.example.com` is suggested; two sites with the same name would make Caddy reject its whole configuration with *ambiguous site definition*), and not already defined in Caddy.
- **DNS**: every A/AAAA record must point at this server. An IPv6-only server needs only AAAA and an extra A record is reported (it would make issuance fail). The records to create are printed. While DNS is wrong nothing is written and no certificate is requested.
- **NAT**: a public address that is not on an interface means a NAT. ACME needs public TCP 80 and 443 to reach this host; a NAT VPS that maps only high ports cannot obtain a certificate this way. Rout says so and asks for confirmation; it never claims such a host can be deployed. Use the SSH tunnel there. Rout never changes the host firewall.
- **Ports**: TCP 80/443 must be free or held by this Caddy. Nothing else is stopped.
- **Caddy**: installed from the distribution repository only after consent. A stopped Caddy is started only after consent, because that activates every site in its Caddyfile. The service must use `/etc/caddy/Caddyfile`, Rout must be able to prove the running configuration equals that file, and automatic HTTPS must not be disabled globally.
- **Files**: the site goes into `/etc/caddy/rout-XXXXXXXX/panel.caddy` — the same Rout directory and the same single `import` line as the subscription site (never a second import). The fragment is validated alone, then the whole layout with `caddy validate`; the Caddyfile, the fragment, `web-https.json` and `web.json` are backed up first to `/etc/rout/backups/subscription-panel-https-*.json`; writes use private temporary files and atomic renames that keep mode and ownership. Other sites, imports, certificates and the subscription site are never edited.
- **Activation**: the domain is added to the Host allow-list with Secure cookies, Caddy is reloaded (or started), and the loaded configuration must equal the validated one.
- **Verification**: the loopback service, the Host allow-list, HTTPS through this server's port 443, HTTPS through public DNS and the login page are checked separately. `caddy validate` succeeding is never taken as HTTPS working.

Remove, redeploy and repair: `rout web https remove` replaces `panel.caddy` with a placeholder, reloads Caddy, drops the domain from the Host allow-list (hosts you allowed by hand stay) and clears the Secure-cookie policy the deployment forced when nothing else needs it, so an SSH-tunnel login over plain HTTP keeps working. The placeholder is still Rout's: its digest is recorded, so `rout web https deploy DOMAIN` — the same domain or another one — replaces it, and a placeholder that was deleted is simply recreated. A placeholder that was **edited**, or any other file that is not what Rout recorded, is never overwritten; the command says so and leaves it alone. `rout web https repair` resumes the site that exists (pending certificate, stopped service); after an explicit removal there is nothing to resume, so it asks for `rout web https deploy DOMAIN` instead of resurrecting a site you removed. Removing twice is a no-op. None of this touches the subscription site, its URL, its token or the subscription state.

Failure handling: if validation or the reload fails, the files, `web.json` and the previous active configuration are restored and verified, and a Caddy started or installed by this run is stopped again. If Caddy accepted the configuration but the certificate is not issued yet (DNS still propagating, ACME rate limit, firewall), the valid configuration is **kept** — Caddy keeps retrying on its own and nothing else is affected — the state is recorded as *pending* with the failing layer, and `rout web https repair` resumes. Repeating a deployment that already works changes nothing and reloads nothing. Rout edits or removes only a fragment whose bytes still match the digest it recorded in `web-https.json`; an edited fragment is kept and reported.

Diagnosis (`rout web https status`, menu 8 → 7, System page) separates the layers: network facts (IPv4/IPv6, NAT, IPv6-only), panel service, DNS, TCP 80/443 owners, Caddy and its site, reachability of the Let's Encrypt **production** and **staging** directories (reported separately; an unreachable staging CA says nothing about production), the certificate (issuer, expiry), the Host allow-list, public HTTPS and the login page. Caddy's recent journal is classified, never printed: NXDOMAIN/DNS problems, `caddy_legacy_user_removed` (Caddy's data directory owned by a removed user: check `/var/lib/caddy` or reinstall the package), `tls: alert internal error` (no certificate yet), connection resets, ACME timeouts, rate limits, *unauthorized* and *ambiguous site definition*. Only lines for the panel's domain are used.

The site proxies to `127.0.0.1:8790`, sets `X-Forwarded-Proto`, adds HSTS, removes the `Server` header and caps request bodies at 26 MB (the restore limit is 24 MiB). The panel backend keeps listening on IPv4 loopback while Caddy serves the public side over IPv4 and/or IPv6. TLS adds no authentication: the panel's own login is the only credential unless you restrict access further (IP allow-list in front, VPN). `rout web https remove` replaces the fragment with a placeholder and reloads; certificates, the subscription site and other sites stay. The real-Caddy test (`TestIntegrationPanelCaddyDeployment`, run in CI inside a disposable Debian container with Caddy's local CA) validates and serves the generated site next to a subscription site and an unrelated site; public ACME issuance itself cannot be tested in CI.

## Settings and backup

System → Panel settings changes port (1024–65535), session idle and absolute lifetime. A restart is required for the port. System → Backup creates the same archive as `rout backup --full`, now including third-party sources, snapshots and aggregate items (never the web password hash). Restore shows a dry-run plan first, requires typing `RESTORE`, a recent re-authentication and fixes file permissions; maximum archive size 24 MiB. A full backup is always generated within that limit: if the imported node lists would make it larger they are left out (the backup says so and the restore plan warns; refresh the sources afterwards), and if even the state and source definitions do not fit, the backup is refused with a message instead of producing a file no restore could read.

## Build from source

```sh
cd web && npm ci && npm run check   # typecheck, tests, build into ../internal/webui/dist
cd .. && go build ./cmd/rout
```

`dist` is embedded with `go:embed`; without it the panel answers `503` with a "not built" page. CI and `scripts/release.sh` both build and require it.
