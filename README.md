# Irongrid DNS

A fast, self-hosted, ad-blocking DNS server written in pure Go — a single
self-contained binary with a modern web dashboard. Built to replace slow
commercial ad-blocking DNS with sub-millisecond local responses.

## Install in one line

**Linux / macOS** (amd64 & arm64 — downloads the latest release, verifies the
SHA-256 checksum, installs to `/usr/local/bin`, installs + starts
**Dragonfly** — the required cache — for you, and then **launches the
interactive setup wizard** so you can configure upstreams, blocklists,
dashboard login, TLS, and more):

```bash
curl -fsSL https://raw.githubusercontent.com/eoghan2t9/Irongrid-DNS/main/install.sh | bash
```

**Windows** (PowerShell — same checksum-verified install, added to your PATH,
followed by the interactive setup wizard):

```powershell
irm https://raw.githubusercontent.com/eoghan2t9/Irongrid-DNS/main/install.ps1 | iex
```

The wizard launches automatically whenever an interactive terminal is
detected (it re-opens `/dev/tty`, so it also works when piped via
`curl … | bash` from a terminal). In non-interactive contexts (CI, Docker)
— or with `--no-wizard` / `-NoWizard` — it is skipped and the default config
is used instead.

**Docker** (compose bundle with Dragonfly included):

```bash
curl -fsSL -o docker-compose.yml https://raw.githubusercontent.com/eoghan2t9/Irongrid-DNS/main/docker-compose.yml
curl -fsSL -o irongrid.example.yaml https://raw.githubusercontent.com/eoghan2t9/Irongrid-DNS/main/irongrid.example.yaml
cp irongrid.example.yaml irongrid.yaml
docker compose up -d
```

Or pull the pre-built image straight from GHCR (needs a separate Dragonfly):

```bash
docker run -d --name dragonfly --restart unless-stopped \
  -p 127.0.0.1:6379:6379 \
  docker.dragonflydb.io/dragonfly/dragonfly --cache_mode=true --maxmemory=512mb --proactor_threads=2
docker run -d --name irongrid --restart unless-stopped \
  -p 53:53/udp -p 53:53/tcp -p 853:853/tcp -p 853:853/udp -p 443:443/tcp -p 8080:8080 \
  -v "$PWD/irongrid.yaml:/app/irongrid.yaml:ro" \
  ghcr.io/eoghan2t9/irongrid-dns:latest
```

### Dragonfly is included

The one-line installers set up **DragonflyDB** (the required cache) for you:

| Platform | How Dragonfly is installed |
|---|---|
| **Linux** | Native binary from the official Dragonfly release + a **systemd service** (falls back to a background process without root/systemd) |
| **macOS** | Docker container (`docker run -d --name dragonfly …`) — Dragonfly has no native macOS build |
| **Windows** | Docker container (WSL2) — Dragonfly has no native Windows build |

It listens on `127.0.0.1:6379`, matching the default `cache.addr` in the
config. Skip it with `--skip-dragonfly` if you already run a Redis-compatible
server — a live Redis/KeyDB/Dragonfly on 6379 is detected and used as-is.

### What the one-line installer does

1. Installs the **Irongrid binary** (checksum-verified) to `/usr/local/bin` (or `~/.local/bin`).
2. Installs and starts **Dragonfly** (see above).
3. Writes a **default `irongrid.yaml`** (skipped if one already exists).
4. Installs **Irongrid as a startup service** — systemd on Linux,
   launchd on macOS, an elevated logon scheduled task on Windows
   (it runs while a user is logged in; Linux needs root; use
   `--no-service` to skip).
5. Launches the **interactive setup wizard** (`irongrid install
   --with-dragonfly`) so you can configure everything in the TUI — skipped
   automatically when no terminal is available, or with `--no-wizard`
   (`-NoWizard` on Windows).

```bash
# Customise the locations:
curl -fsSL https://raw.githubusercontent.com/eoghan2t9/Irongrid-DNS/main/install.sh | bash -s -- \
  --config /etc/irongrid/irongrid.yaml --data /var/lib/irongrid --no-service
```

### After installing

1. **Dragonfly and the service are already running** — the dashboard is at
   **http://localhost:8080** (default login `admin` / `irongrid`).
2. If you finished the wizard, your chosen config is already in place and the
   service was restarted to apply it. Re-run the wizard anytime with
   `irongrid install` to change things.

The wizard writes a ready-to-use config and installs the service for your
platform (systemd / launchd / Windows service / Docker).

## Update in one line

- **Binary installs** — re-run the one-liner; it replaces your binary with
  the newest version (same checksum verification).
- **Docker** — `docker compose pull && docker compose up -d`
- **In the dashboard** — Irongrid checks GitHub Releases automatically on
  load and pops up the **latest changelog** when a new version is out, with a
  direct download link and the terminal update command. The **⬆ Updates**
  button in the top bar re-checks any time.

## Features

| | |
|---|---|
| ⚡ **Performance** | DragonflyDB-backed response cache (hard requirement), typical answers served in < 1 ms |
| 🌐 **All protocols** | DNS over **UDP**, **TCP**, **TLS (DoT)**, **HTTPS (DoH, RFC 8484)** and **QUIC (DoQ, RFC 9250)** |
| 🛡️ **Blocking** | Hosts files, Adblock syntax (`\|\|domain^`, `@@` exceptions), plain domains, wildcards (`*.domain`), and IP rules |
| ✅ **Allow list** | Whitelist entries override *any* blocklist, including IP addresses |
| 📜 **Blocklists** | Add unlimited remote/local lists, per-list auto-update, one-click refresh, curated one-click presets |
| 🪵 **Full query log** | Every allowed/blocked/cached request with client, reason, upstream, latency — stored in pure-Go SQLite |
| 📊 **Dashboard** | Modern React UI: live stats, protocol breakdown, top blocked domains, log explorer, live config editing |
| 🔄 **Built-in updater** | Checks GitHub Releases, pops up the changelog, offers the download |
| 🔐 **TLS manager** | In-dashboard certificate management: view, generate self-signed, upload CA certs, download — applied live to DoT/DoH/DoQ |
| 🪪 **Let's Encrypt (ACME)** | Zero-config auto-issuance + renewal for your domains via HTTP-01, or run the dashboard itself over HTTPS (`web_tls`) |
| 🔗 **Cloudflare Tunnel** | cloudflared compiled **into the binary** (imported as Go modules) — no external install, managed from the dashboard |
| 📱 **Android Private DNS** | DoT/DoH on your own domain via the tunnel, with auto-generated or custom TLS certificates |
| 🐳 **Cross-platform** | Linux, macOS, Windows (single static binary) plus Docker + Dragonfly Compose |

## Architecture

```
                    ┌─────────────────────────── Irongrid DNS ───────────────────────────┐
                    │                                                                     │
  UDP:53 ─────────► │  ┌──────────┐   ┌────────────┐   ┌───────────┐   ┌───────────────┐  │
  TCP:53 ─────────► │  │  Listener │──►│  Filter    │──►│  Cache    │──►│  Upstreams    │  │
  DoT:853 ────────► │  │  (5 protos)│  │  engine    │  │  Dragonfly│  │  udp/tcp/tls/  │  │
  DoH:443 ────────► │  └──────────┘   └────────────┘  │  (Redis)   │  │  https/quic    │  │
  DoQ:853 ────────► │                    │  whitelist │  └──────────┘  └───────────────┘  │
                    │                    ▼            │                │                   │
                    │              Query log (SQLite)◄┴────────────────┘                   │
                    │  Dashboard (React, embedded) ◄── REST API ◄── cloudflared (embedded) │
                    └──────────────────────────────────────────────────────────────────────┘
```

Every response passes through: **filter → cache → upstream → log**. Blocked
queries never touch an upstream, so they are answered instantly.

## Installation options

### 1. Interactive TUI wizard (recommended)

Build the binary, then run the setup wizard. It asks about deployment mode,
listeners, upstreams, cache, blocking presets, dashboard credentials and TLS,
and writes a ready-to-use `irongrid.yaml` plus the service files.

```bash
make web      # build the dashboard (embedded into the binary)
make install  # builds ./irongrid and launches `irongrid install`
```

or manually:

```bash
make build
./irongrid install                       # writes ./irongrid.yaml
./irongrid install -config /etc/irongrid/irongrid.yaml -data /var/lib/irongrid
```

The wizard supports **Linux, macOS, Windows and Docker** targets:

| Choice | What it sets |
|---|---|
| Deployment | `docker` (container + bundled Dragonfly) or `native` (binary on this machine) |
| Service manager | systemd unit, launchd plist, Windows elevated logon task (Go binaries don't speak the SCM protocol, so a scheduled task with `/RL HIGHEST` is used instead of `sc.exe`), or none |
| Protocols | UDP/TCP on :53, DoT on :853, DoH on :443, DoQ on :853 |
| Upstreams | Cloudflare, Google, Quad9 presets or custom (`udp://`, `tls://`, `https://`, `quic://`) |
| Cache | Dragonfly address (+ optional password) |
| Blocklists | Pick curated presets: OISD, Hagezi, StevenBlack, AdGuard, EasyList, 1Hosts… |
| Allow lists | One-click whitelist presets: OS updates, dev/CI, cloud, banking, IoT, news |
| Dashboard | Web UI username + password (bcrypt-hashed on save) |
| TLS | Self-signed cert SANs (swap in a CA cert later) |

Service files are written to `deploy/` next to the config, and the wizard
prints the exact install command for your platform:

- **Linux** — `sudo cp deploy/irongrid.service /etc/systemd/system/ && sudo systemctl enable --now irongrid`
- **macOS** — `cp deploy/com.irongrid.dns.plist ~/Library/LaunchAgents/ && launchctl load ~/Library/LaunchAgents/com.irongrid.dns.plist`
- **Windows** — run `deploy/install-irongrid-service.bat` as Administrator (installs an elevated logon scheduled task — plain Go binaries don't implement the SCM protocol, so `sc.exe` would leave the service stuck in START_PENDING; the task runs while you're logged in)
- **Docker** — `cd deploy && docker compose up -d`

### 2. Docker Compose (Dragonfly included)

```bash
cp irongrid.example.yaml irongrid.yaml
# set your web.password, optionally add blocklists
docker compose up -d --build
```

### 3. Native (Go 1.26+)

```bash
# 1. Start Dragonfly (Redis protocol) — required
docker run -d --name dragonfly -p 6379:6379 docker.dragonflydb.io/dragonfly/dragonfly

# 2. Build and run
make web      # build the dashboard (embedded into the binary)
make build    # single binary: ./irongrid
./irongrid -config irongrid.yaml -data data
```

Point your router or device at the server:

- DNS server: `53`
- Private DNS (Android): `dns.example.com` (DoT) or `https://dns.example.com/dns-query` (DoH)
- Dashboard: `http://<server>:8080`

### Pre-made blocklist & allow-list presets

Both the wizard and the dashboard come with a curated catalog of presets,
served by `GET /api/lists/catalog` and shared by every entry point:

- **Blocklists** — OISD Big/Full, Hagezi Multi PRO, StevenBlack, AdGuard DNS
  filter, EasyList, EasyPrivacy, 1Hosts (Lite/Pro/Xtra), yoyo.org, AdAway,
  NoTracking, plus category lists: **adult** (Hagezi Adult, 1Hosts Xtra,
  Sinfonietta), **gambling** (Hagezi), **social media** (Hagezi) and
  **security** (Hagezi phishing/scam/threat-intel/crypto/fake).
- **Allow lists** — OS & security updates, Development & CI, Cloud &
  collaboration, Banking & payments, Smart home & IoT, News & reference,
  Gaming, Streaming & music, Social media.

In the **Blocklists** page, presets appear as quick-add buttons; in the
**Lists** page, allow-list presets add their domains to the Allow list with one
click (they override every blocklist).

### Wizard: auto-start Dragonfly

`irongrid install --with-dragonfly` probes the configured `cache.addr` and,
if nothing answers, starts Dragonfly for you (native binary + background
process on Linux, Docker on macOS/Windows). Combine it with the scripted mode
for a fully unattended install.

### Scripted / unattended installs

The wizard falls back to accessible line-based rendering when stdin is not a
terminal, and `IRONGRID_ACCESSIBLE=1` forces that mode even on a TTY — which
makes the installer fully scriptable for CI or unattended provisioning:

```bash
printf '2\n4\n0\n0.0.0.0\n1\n\nlocalhost:6379\n\n0\n0\nadmin\ntestpass123\ntestpass123\nlocalhost\ny\n' | \
  IRONGRID_ACCESSIBLE=1 ./irongrid install -config irongrid.yaml -data data
```

Each line answers one prompt in order: deployment (1=Docker, 2=Native),
service manager, protocols, listen address, upstream preset, custom
upstreams, Dragonfly address/password, blocklists, allow lists, username,
password + confirmation, TLS hosts, and the final confirm (`y`). The same
path is covered by an end-to-end test in `internal/installer`.

## Built-in updater

The dashboard checks `https://api.github.com/repos/eoghan2t9/Irongrid-DNS/releases/latest`
shortly after loading (`GET /api/update/check`). When a newer version exists:

- A **popup shows the latest changelog**, your version → new version, the
  release date, and links to download the binary for your platform or view
  the release notes.
- **⬆ Updates** in the top bar re-checks manually; an amber dot appears while
  a new version is pending.
- **Don't show again** remembers the dismissed version (per browser).

The check is read-only and fails quietly (no popup) when offline or
rate-limited. Releases are published by tagging:

```bash
git tag v1.0.0 && git push origin v1.0.0
```

## Building releases

Tag a release to build static binaries for **Linux, macOS and Windows** (amd64
+ arm64) on GitHub Actions, generate a changelog, attach binaries with
checksums, and push the **`ghcr.io/eoghan2t9/irongrid-dns`** container image
(Linux amd64 + arm64):

```bash
git tag v1.0.0
git push origin v1.0.0
```

Or build them locally with:

```bash
make release   # cross-compiles all 6 targets into dist/
```

## Configuration

See [irongrid.example.yaml](irongrid.example.yaml). A default config is
written automatically on first launch. Key options:

| Option | Meaning |
|---|---|
| `server.listen_*` | Per-protocol listen addresses; empty string disables |
| `upstreams` | Forwarders — `udp://`, `tcp://`, `tls://`, `https://`, `quic://` |
| `cache.addr` | Dragonfly endpoint — **server will not start without it** |
| `filter.blocklists` | Remote URLs or `file://` paths, with per-list `auto_update` |
| `filter.whitelist` | Always-allow entries (override blocklists, incl. IPs) |
| `filter.block_response` | `nxdomain`, `refused`, or a blackhole IP like `0.0.0.0` |
| `tls.cert_file/key_file` | Your Let's Encrypt / CA cert for DoT/DoH/DoQ (else self-signed) |
| `tls.acme` | Automatic Let's Encrypt issuance: `enabled`, `email`, `domains`, `staging`, `http01_port`, and `dns01` (DNS TXT issuance via Cloudflare, DigitalOcean, Hetzner, GoDaddy or AWS Route53 — no open port needed) |
| `server.web_tls` | Serve the dashboard + API over HTTPS using the same TLS certificate |
| `server.web_redirect` | With `web_tls`, also serve plain HTTP on `web_redirect_port` that 301s to HTTPS |
| `tunnel` | Baked-in cloudflared settings |

## Cloudflare Tunnel (baked in)

cloudflared is imported as Go modules and compiled into the binary — there is
no external `cloudflared` process to install. Use it from the **Tunnel** page
in the dashboard or via config:

```yaml
tunnel:
  enabled: true
  token: "your-zero-trust-tunnel-token"   # named tunnel
  # OR quick_tunnel: true                  # free trycloudflare.com hostname
```

### Android Private DNS setup

1. Create a tunnel in Cloudflare Zero Trust, copy its token into the Tunnel page, start it.
2. Route your hostname (`dns.example.com`) to `https://localhost:443` (your DoH listener) or `tls://localhost:853`.
3. Get a trusted certificate for `dns.example.com` — either:
   - **Automatic**: enable `tls.acme` in the config or via the **TLS** page in the dashboard. Irongrid
     obtains a Let's Encrypt certificate for you (HTTP-01 on port 80 — point `dns.example.com` at this
     server first) and renews it automatically.
   - **Manual**: set `tls.cert_file`/`tls.key_file` to your Let's Encrypt / CA cert.
4. On your phone: **Settings → Network & internet → Private DNS → Private DNS provider hostname** → `dns.example.com`.

To verify the certificate is trusted, download it from the TLS page (`GET /api/tls/cert`) and check its
issuer — a Let's Encrypt chain means phones will accept it without extra steps.

## API

The dashboard uses a JSON REST API (HTTP Basic auth):

```
GET  /api/status            server, listeners, cache, tunnel status
GET  /api/stats             counters, protocol split, top blocked
GET  /api/log?limit&action&domain&qtype   query log
DELETE /api/log             clear query log
GET/POST /api/lists         manage blocklists
GET  /api/lists/catalog     curated blocklist & allow-list presets (used by the wizard and UI)
POST /api/lists/refresh     update all lists
GET/POST /api/filter/{whitelist,blacklist}   allow/block entries
POST /api/filter/check      test a domain or IP
POST /api/cache/flush       clear Dragonfly cache
GET/POST /api/tunnel/*      tunnel lifecycle + logs
GET/PUT /api/config         read / update the full config (live-apply + restart notes)
POST /api/config/reload     apply listener/cache/TLS/upstream changes in-process (no restart)
GET  /api/diag/dns?name=…   resolve through your upstreams
GET  /api/update/check      check GitHub Releases for a newer version + changelog
GET  /api/tls               current certificate details (subject, SANs, expiry, fingerprint)
POST /api/tls/generate      generate a self-signed cert (hosts, key type/bits, validity) and apply it
POST /api/tls/upload        upload a CA-signed cert + key pair and apply it
GET  /api/tls/cert          download the active certificate (for clients to trust)
POST /api/tls/acme/issue    trigger an immediate Let's Encrypt issuance/renewal (HTTP-01 or DNS-01)
```

### TLS config reference

```yaml
server:
  web_tls: false            # serve the dashboard + API over HTTPS (uses the TLS cert)

tls:
  cert_file: ""            # CA-signed cert (PEM); empty = use cert_dir/cert.pem
  key_file: ""             # matching private key (PEM)
  generate_self_signed: true
  self_signed_hosts: ["localhost", "dns.example.com"]
  cert_dir: data/certs     # where cert.pem/key.pem (and the ACME account key) live
  acme:
    enabled: false
    email: "you@example.com"       # required for Let's Encrypt registration
    domains: ["dns.example.com"]   # public hostnames to cover
    staging: false                  # true = test with the Let's Encrypt staging CA
    http01_port: 80                 # port the HTTP-01 challenge listener binds
    renew_before_days: 30           # renew when < 30 days remain
    dns01:                          # optional: issue via DNS TXT instead of HTTP-01
      provider: cloudflare          #   one of: cloudflare, digitalocean, hetzner, godaddy, route53
      cloudflare_token: ""         #   Cloudflare API token (Zone:DNS:Edit)
      # digitalocean_token: ""      #   DigitalOcean personal access token (DNS:edit)
      # hetzner_token: ""           #   Hetzner DNS API token (zone write access)
      # godaddy_key: ""             #   GoDaddy API key + secret (domain DNS access)
      # godaddy_secret: ""
      # aws_access_key_id: ""       #   AWS Route53: access key + secret (Route53:ChangeResourceRecordSets)
      # aws_secret_access_key: ""
      propagation_wait_sec: 60      #   wait for TXT records to propagate
```

**HTTP-01 vs DNS-01:** HTTP-01 needs the domain to answer on port 80 at this server. DNS-01
creates a `_acme-challenge` TXT record through your DNS provider's API and works anywhere —
ideal behind a tunnel or NAT. Supported providers: **Cloudflare**, **DigitalOcean**, **Hetzner**,
**GoDaddy**, and **AWS Route53** (all implemented in-process with zero extra dependencies;
Route53 uses SigV4 signing over the standard API).
When `server.web_tls` is on, `server.web_redirect: true` adds a plain-HTTP listener
(`web_redirect_port`, default 80) that 301s every request to `https://<host>/`.

The **TLS** page in the dashboard wraps all of this: view the current certificate (SANs, expiry,
fingerprint), generate or upload one, trigger ACME issuance, and download the cert for clients. When
`web_tls` is enabled the whole dashboard runs on `https://<host>:<web_listen>`.

## Development

Requirements: **Go 1.26+** and **Node.js 22+** (Node 22 LTS or newer — Vite 8
requires Node `^20.19 || >=22.12`). The Docker build uses `node:22-alpine`
and `golang:1.26-alpine` automatically.

```bash
make test     # go vet + go test (includes a DoQ round-trip integration test)
make web      # install deps and rebuild the React dashboard
make build    # rebuild the binary with the dashboard embedded
```

## License

Apache-2.0
