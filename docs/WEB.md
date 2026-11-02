# Web management panel (v0.5.0)

The panel is a separate service, `rout-web`, that serves a React + TypeScript single-page app and a JSON API from the same Go binary (`rout web serve`). It manages nodes, relays, exits, subscriptions, third-party sources and the system. The terminal menu and all CLI commands keep working and share the same state files.

## Quick start

```sh
sudo rout web passwd --generate    # sets the admin password, prints it once
sudo rout web install              # installs and starts the rout-web service
sudo rout web status
```

The panel listens on `127.0.0.1:8790` only. There is no public admin port. Reach it with an SSH tunnel:

```sh
ssh -L 8790:127.0.0.1:8790 user@your-vps
# then open http://127.0.0.1:8790/
```

`rout web passwd --stdin` reads the password from standard input. The password can only be set from the CLI, never through the API. It is stored as PBKDF2-HMAC-SHA256 (600000 iterations) in `web.json` (mode 0600).

Other commands: `rout web start|stop|restart|logs|uninstall`, `rout web host <name>` (allow another Host header), `rout web https <domain>` (prints a Caddy snippet), `rout web serve` (foreground).

## Pages

| Page | Contents |
| --- | --- |
| Dashboard | CPU, memory, disk, network, IPv4/IPv6 availability, node/relay/exit/subscription counts and states, live and cumulative traffic, alerts, certificate status, quota reminders |
| Nodes | list, search/filter, bulk start/stop/delete, create/edit (VLESS Reality, AnyTLS, Hysteria2, SS2022, TUIC; local IPv4/IPv6, NAT relay, SOCKS5/HTTP/remote exit), share link and QR, connection/traffic test |
| Relays & exits | local/remote/NAT relays, TCP/UDP, IPv4/IPv6/dual listen, outbound policy, SOCKS5/HTTP(S)/remote-node exits, references and delete protection, entry → exit path, layered tests |
| Subscriptions | CRUD, enable/disable, node add/remove/sort, plan (quota, reset, expiry), Base64 and Mihomo URLs, QR, token rotation, aggregates (local + remote items) |
| Sources | third-party subscriptions: add, refresh, per-node enable, parse issues, tags |
| System | version/update status, service control, logs, backup and restore, subscription HTTPS status, panel settings, sessions and audit log |

Interface languages: 简体中文, 繁體中文, English. Light and dark theme follow the system by default and can be switched in the header. The layout is desktop first; tables turn into cards on a phone.

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

Prefer the SSH tunnel. To publish it, put it behind a reverse proxy that you control and restrict by IP or an additional authentication layer. `rout web https panel.example.com` prints a Caddy snippet that proxies to `127.0.0.1:8790` and sets `X-Forwarded-Proto`, adds HSTS and caps request bodies at 26 MB (the restore limit is 24 MiB); add the domain with `rout web host panel.example.com`, paste the snippet into your Caddyfile and reload Caddy. Rout does not install or edit Caddy for the panel. (The existing `rout subscription https` is separate and only concerns subscription URLs.) The snippet has not been validated with a real Caddy binary (none was available in the build environment); run `caddy validate` before reloading. The snippet adds TLS only, not authentication: the panel's own login is the only credential unless you add IP restrictions or another layer in front.

## Settings and backup

System → Panel settings changes port (1024–65535), session idle and absolute lifetime. A restart is required for the port. System → Backup creates the same archive as `rout backup --full`, now including third-party sources, snapshots and aggregate items (never the web password hash). Restore shows a dry-run plan first, requires typing `RESTORE`, a recent re-authentication and fixes file permissions; maximum archive size 24 MiB.

## Build from source

```sh
cd web && npm ci && npm run check   # typecheck, tests, build into ../internal/webui/dist
cd .. && go build ./cmd/rout
```

`dist` is embedded with `go:embed`; without it the panel answers `503` with a "not built" page. CI and `scripts/release.sh` both build and require it.
