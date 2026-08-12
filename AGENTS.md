# Irongrid DNS — Agent Memory

This file is the persistent memory for AI agents working on this project. Load
it at the start of every session before doing anything else, and keep it
updated when the project or its conventions change.

## What this project is

Irongrid DNS is a self-hosted, privacy-focused DNS blocker (Pi-hole / AdGuard
Home style) written in Go. It is the user's own home/LAN DNS server, deployed
live on a VPS. It does NOT have external contributors — this is a single-user
personal project, so anything not private to the server can be committed
freely, but production configs, passwords, and live-server state must never
be written into the repo.

**Stack:** Go backend (`cmd/irongrid`, `internal/*`) + React/Vite dashboard
(`web/`, embedded into the binary via `web/dist`) + Dragonfly (Redis-compatible)
as the cache and query-log store.

**Key internal packages:** `internal/dnsserver` (UDP/TCP/DoT/DoH/DoH3/DoQ
listeners), `internal/filter` (blocklists, AdGuard regex rules, allow/block),
`internal/cache` (L1 in-process + L2 Dragonfly), `internal/dhcp` (built-in
DHCPv4/v6), `internal/config` (YAML schema), `internal/api` (REST + embedded
dashboard), `internal/tunnel` (cloudflared), `internal/acme` (Let's Encrypt),
`internal/geoip` (country blocking + honeypots), `internal/recursive`
(iterative resolver), `internal/update` (self-updater).

## The live server (production — be careful)

- Host: VPS `vps-d8a8ff20` (this machine). **The repo lives at
  `/home/ubuntu/Irongrid-DNS` and is the working copy.**
- Service: systemd unit `irongrid`; binary at `/usr/local/bin/irongrid`;
  config at `/home/ubuntu/irongrid.yaml`; data dir `/home/ubuntu/data`.
- Public hostname: `adguard2.eoghan-net.com` (dashboard + DoH on :443, DoT on
  :853, plain DNS on :53/udp+tcp). The web UI serves on :443 with web_tls.
- **Deploying** (user-approved pattern; only after asking, since it restarts a
  live DNS service):
  ```bash
  cd /home/ubuntu/Irongrid-DNS && export PATH=$PATH:/usr/local/go/bin
  make build
  cp /usr/local/bin/irongrid /usr/local/bin/irongrid.bak-<commit>   # rollback point
  cp irongrid /usr/local/bin/irongrid.new && mv -f /usr/local/bin/irongrid.new /usr/local/bin/irongrid
  systemctl restart irongrid && sleep 5 && systemctl is-active irongrid
  ```
  Note: `cp` straight onto the running binary fails with "text file busy";
  the `.new` + `mv -f` dance is required. After restart the API can take a
  few seconds to answer — probe with retries.
- **Dashboard auth:** username `eoghan`; the password is bcrypt-hashed in
  `web.password` in the config — the user pastes it per-session when needed
  for screenshots/API calls. Never write it to the repo.
- Verifying the live API:
  `curl -sk -u 'eoghan:<PASS>' https://adguard2.eoghan-net.com/api/status --resolve adguard2.eoghan-net.com:443:127.0.0.1`

## Git / release conventions (user's explicit rules)

1. **NEVER push tags except version tags (`vX.Y.Z`).** The user was explicit:
   "stop pushing main tags, only version tags". No tag on routine
   `commit and push` requests. Only create/tag a release when the user asks
   for a new tag, and confirm the version number first (they once selected
   two versions by accident — always resolve to a single tag).
2. **`release.yml` fires only on `v*` tag pushes.** It cross-compiles 6
   platforms, runs golangci-lint + govulncheck + full race tests, generates a
   changelog, creates a GitHub Release, and pushes multi-arch GHCR images.
3. **`bench.yml` does NOT run on main pushes** (removed; PRs + manual only).
4. Plain pushes to `main` must produce **no workflow runs** — the user
   complained twice about this. Double-check any new workflow's triggers.
5. Commit messages: conventional prefix (`feat:`, `fix:`, `docs:`,
   `style:`, `perf:`, `ci:`, `chore:`), detailed body. Commit + push together
   when asked.
6. `web/dist/index.html` is a committed placeholder (its assets are
   gitignored, rebuilt in CI). Include the regenerated index.html in commits
   that touch the frontend, matching the repo's convention.

## Build / test / lint

- Go: `make build`, `go build ./...`, `go test -race ./...` (the release
  pipeline uses `go test -race ./...` — it's the real gate).
- golangci-lint v2 (CI uses v2.12.2):
  `export PATH=$PATH:/usr/local/go/bin && export PATH=$PATH:$(go env GOPATH)/bin`
  then `golangci-lint run ./...`. Install with
  `go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2`
  (note the `/v2/` module path — the old v1 path errors).
- Frontend: `cd web && npm run build`, `npm run lint`, `npm test` (vitest),
  `npm run format:check` (prettier — the repo is prettier-formatted; run
  `npm run format` after edits if format:check fails).
- golangci-lint caught real bugs in CI before: errcheck, staticcheck QF1001
  (De Morgan rewrites), unused symbols. Run it before tagging a release.

## Screenshot workflow (README assets)

- Screenshots live in `assets/screenshots/` (6 PNGs: login, dashboard, query
  log, blocklists, DHCP, settings) and are referenced from README.md.
- **Rule (user request): screenshots must show fabricated/dummy data, never
  real network traffic** (real queries, domains, client IPs, leases,
  hostnames, ASNs, blocklist configs). Captured with Playwright + route
  interception: a `page.route('**/api/**')` handler fulfills `/api/stats`,
  `/api/status`, `/api/tls`, `/api/config`, `/api/log`, `/api/log/hostnames`,
  `/api/log/asn`, `/api/lists`, `/api/lists/catalog`, `/api/dhcp/leases`,
  `/api/geo/*`, `/api/rate/*` with structurally-identical dummy payloads.
  The login page needs no dummy data.
- Playwright environment: `mkdir -p /tmp/shot && cd /tmp/shot && npm init -y
  && npm i playwright@latest`; the Chromium cache persists in
  `~/.cache/ms-playwright` across sessions, so only the npm package needs
  reinstalling. Launch with `--ignore-certificate-errors` and
  `--host-resolver-rules=MAP adguard2.eoghan-net.com 127.0.0.1`. Login via
  the real form (`input[name="username"]`, `input[name="password"]`). Capture
  at 1600x1000. Always verify the DOM shows the dummy data before shooting,
  and clean up `/tmp/shot` afterwards.
- To screenshot a *new* UI feature, the live server must first be redeployed
  (it runs a stale build otherwise) — ask the user first.

## Frontend conventions

- React 19 + Vite; no UI framework — hand-rolled CSS in `web/src/styles.css`
  with CSS variables (`--bg`, `--surface`, `--cyan`, `--emerald`, `--rose`,
  `--amber`); dark theme only.
- Views are lazy-loaded by path (`/dashboard`, `/log`, `/blocklists`,
  `/lists`, `/rewrites`, `/tools`, `/client-groups`, `/tls`, `/tunnel`,
  `/dhcp`, `/changelog`, `/settings`), grouped into labelled sidebar
  sections (Overview / Ad blocking / Diagnostics / Network / Server / System).
- Recent UI work: beginner-friendly pass — grouped nav + per-view
  plain-English subtitles, a config-driven "Getting started" checklist on the
  dashboard (persists ticks in localStorage), and a jump-nav over Settings'
  sections. `.btn` labels are centred via the base class (inline-flex +
  justify-content:center); nav items stay left-aligned by design.
- User cares about polish: hover states, transitions, keyboard focus, touch
  visibility (no hover-dependent affordances), and accessibility (aria-labels,
  text + color, not color alone).

## Ops / support features already built (don't rebuild)

Config backup/restore (GET/POST /api/config/backup|restore, zip with
zip-slip/bomb guards, Settings → Backup & restore), built-in DHCP server +
dashboard page, AdGuard regex blocklist rules, split-horizon `upstream_routes`,
DNS cookies (RFC 7873), DoH3, cache warmer + prefetch + serve-stale, honeypot
auto-blocking with firewall drops, rate-limit auto-block, geo blocking,
AbuseIPDB reporting, self-updater, conditional client groups, recursive://
upstream, system tuning (SO_REUSEPORT, fd limits, sysctls), bench tooling
(`bench/dnsload`, `bench/reuseport`, `bench/udpsockets`).

## Current state (update after each release)

- HEAD: `992307b` (style: centre button labels)
- Latest tags: `v1.14.1` → `v1.14.0` → `v1.13.2`
- The live server runs the build deployed during the v1.14.0 UI screenshots
  round — it may be behind HEAD if later commits (button centering) weren't
  redeployed. Check `curl .../api/status` version before assuming what's live.

## Working style

- Ask before: deploying/restarting the live service, pushing tags (confirm
  version), or anything irreversible.
- Do not: run effectful commands (git push, commits) unless asked; commit +
  push when the user says "commit and push".
- Keep the repo tree clean: verify `git status` before finishing a session.
- Tests must pass before tagging: full `go test -race ./...`, golangci-lint
  0 issues, `web` build + lint + test.
