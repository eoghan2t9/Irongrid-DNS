# Irongrid DNS

A fast, self-hosted, ad-blocking DNS server written in pure Go — a single
self-contained binary with a modern web dashboard. Built to replace slow
commercial ad-blocking DNS with sub-millisecond local responses.

## Features

| | |
|---|---|
| ⚡ **Performance** | DragonflyDB-backed response cache (hard requirement), typical answers served in < 1 ms |
| 🌐 **All protocols** | DNS over **UDP**, **TCP**, **TLS (DoT)**, **HTTPS (DoH, RFC 8484)** and **QUIC (DoQ, RFC 9250)** |
| 🛡️ **Blocking** | Hosts files, Adblock syntax (`\|\|domain^`, `@@` exceptions), plain domains, wildcards (`*.domain`), and IP rules |
| ✅ **Allow list** | Whitelist entries override *any* blocklist, including IP addresses |
| 📜 **Blocklists** | Add unlimited remote/local lists, per-list auto-update, one-click refresh |
| 🪵 **Full query log** | Every allowed/blocked/cached request with client, reason, upstream, latency — stored in pure-Go SQLite |
| 📊 **Dashboard** | Modern React UI: live stats, protocol breakdown, top blocked domains, log explorer |
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

## Quick start

### With Docker (Dragonfly included)

```bash
cp irongrid.example.yaml irongrid.yaml
# set your web.password, optionally add blocklists
docker compose up -d --build
```

### Native (Go 1.26+)

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
3. Obtain a real certificate for `dns.example.com` (e.g. Let's Encrypt) and set `tls.cert_file`/`tls.key_file`.
4. On your phone: **Settings → Network & internet → Private DNS → Private DNS provider hostname** → `dns.example.com`.

## API

The dashboard uses a JSON REST API (HTTP Basic auth):

```
GET  /api/status            server, listeners, cache, tunnel status
GET  /api/stats             counters, protocol split, top blocked
GET  /api/log?limit&action&domain&qtype   query log
DELETE /api/log             clear query log
GET/POST /api/lists         manage blocklists
POST /api/lists/refresh     update all lists
GET/POST /api/filter/{whitelist,blacklist}   allow/block entries
POST /api/filter/check      test a domain or IP
POST /api/cache/flush       clear Dragonfly cache
GET/POST /api/tunnel/*      tunnel lifecycle + logs
GET/PUT /api/config         read / update the full config (live-apply + restart notes)
GET  /api/diag/dns?name=…   resolve through your upstreams
```

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
