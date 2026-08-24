#!/usr/bin/env bash
#
# Irongrid DNS — one-line installer (Linux / macOS, and Windows via Git Bash)
#
#   curl -fsSL https://raw.githubusercontent.com/eoghan2t9/Irongrid-DNS/main/install.sh | bash
#
# Downloads the latest Irongrid DNS release binary for your platform, verifies
# its SHA-256 checksum against the published SHA256SUMS.txt, and installs it.
# It also:
#   - installs and starts DragonflyDB (the required cache): a native binary +
#     systemd service on Linux, or a Docker container on macOS/Windows
#     (Dragonfly publishes no native builds for those platforms)
#   - writes a default irongrid.yaml if none exists
#   - installs Irongrid itself as a startup service when possible
#     (systemd on Linux, launchd on macOS)
#
# Options:
#   --version <tag>     install a specific release tag (default: latest)
#   --dir <path>        install binaries into a custom directory
#   --config <path>     config file to create (default: ./irongrid.yaml)
#   --data <dir>        runtime data directory (default: ./data)
#   --no-service        do not install Irongrid as a startup service
#   --no-wizard         skip the interactive setup wizard (TUI)
#   --skip-verify       skip checksum verification (not recommended)
#   --skip-dragonfly    do not install/start Dragonfly
#   --no-v3             always install the baseline build, even if this CPU
#                        supports the faster GOAMD64=v3 build
#   -h, --help          show this help
#
# In an interactive terminal the script launches the interactive TUI setup
# wizard (`irongrid install`), which now handles the whole install itself:
# Dragonfly, the config, binary placement and the startup service. In
# non-interactive contexts (piped curl|bash in CI, --no-wizard, or an existing
# config) the script keeps its built-in Dragonfly + default-config + service
# steps instead.
#
set -euo pipefail

REPO="eoghan2t9/Irongrid-DNS"
DFLY_REPO="dragonflydb/dragonfly"
DFLY_IMAGE="docker.dragonflydb.io/dragonfly/dragonfly"
VERSION=""
INSTALL_DIR=""
CONFIG_PATH="irongrid.yaml"
DATA_DIR="data"
SKIP_VERIFY=0
SKIP_DRAGONFLY=0
INSTALL_SERVICE=1
SKIP_WIZARD=0
NO_V3=0

die() { echo "error: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "required tool missing: $1"; }

# Help is a heredoc so it works even when the script is piped via curl|bash
# (where "$0" is not the script file).
usage() {
  cat <<'EOF'
Irongrid DNS - one-line installer (Linux / macOS, and Windows via Git Bash)

  curl -fsSL https://raw.githubusercontent.com/eoghan2t9/Irongrid-DNS/main/install.sh | bash

Installs Irongrid DNS + DragonflyDB (the required cache), writes a default
config, and installs Irongrid as a startup service:
  - Linux:    native Dragonfly binary + systemd service
  - macOS:    Dragonfly in Docker (no native macOS build exists)
  - Windows:  Dragonfly in Docker (no native Windows build exists)

Options:
  --version <tag>     install a specific release tag (default: latest)
  --dir <path>        install binaries into a custom directory
  --config <path>     config file to create (default: ./irongrid.yaml)
  --data <dir>        runtime data directory (default: ./data)
  --no-service        do not install Irongrid as a startup service
  --no-wizard         skip the interactive setup wizard (TUI)
  --skip-verify       skip checksum verification (not recommended)
  --skip-dragonfly    do not install/start Dragonfly
  --no-v3             always install the baseline build, even if this CPU
                       supports the faster GOAMD64=v3 build
  -h, --help          show this help
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --version)
      [ $# -ge 2 ] || die "--version requires a value"; VERSION="$2"; shift 2 ;;
    --dir)
      [ $# -ge 2 ] || die "--dir requires a value"; INSTALL_DIR="$2"; shift 2 ;;
    --config)
      [ $# -ge 2 ] || die "--config requires a value"; CONFIG_PATH="$2"; shift 2 ;;
    --data)
      [ $# -ge 2 ] || die "--data requires a value"; DATA_DIR="$2"; shift 2 ;;
    --no-service) INSTALL_SERVICE=0; shift ;;
    --no-wizard) SKIP_WIZARD=1; shift ;;
    --skip-verify) SKIP_VERIFY=1; shift ;;
    --skip-dragonfly) SKIP_DRAGONFLY=1; shift ;;
    --no-v3) NO_V3=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1 (run with --help)" ;;
  esac
done

need curl

# ---- detect platform ----
case "$(uname -s)" in
  Linux*) OS=linux ;;
  Darwin*) OS=darwin ;;
  MINGW*|MSYS*|CYGWIN*) OS=windows ;;
  *) die "unsupported OS: $(uname -s) (on Windows use: irm .../install.ps1 | iex)" ;;
esac
case "$(uname -m)" in
  x86_64|amd64|AMD64) ARCH=amd64 ;;
  aarch64|arm64|ARM64) ARCH=arm64 ;;
  *) die "unsupported architecture: $(uname -m)" ;;
esac

# supports_goamd64_v3 detects whether this CPU supports the x86-64-v3
# microarchitecture level (AVX, AVX2, BMI1, BMI2, F16C, FMA, LZCNT, MOVBE,
# OSXSAVE) that Irongrid's "-v3" release binaries are compiled for — the
# same feature set internal/update's built-in updater checks (via
# klauspost/cpuid/v2's X64Level), kept consistent across the whole project.
# A wrong "yes" here crashes the binary on its very first run with an
# illegal instruction fault, so every branch below fails closed: anything
# uncertain (unreadable /proc/cpuinfo, missing sysctl, an OS with no
# reliable source here) is treated as "no", never as "yes".
supports_goamd64_v3() {
  [ "$ARCH" = amd64 ] || return 1
  case "$OS" in
    linux)
      [ -r /proc/cpuinfo ] || return 1
      local flags f
      flags=" $(awk -F: '/^flags/{print $2; exit}' /proc/cpuinfo) "
      # osxsave is checked implicitly, not as a literal token: the kernel
      # only ever reports "avx" once it has verified XSAVE/OSXSAVE are
      # functional (arch/x86/kernel/cpu/cpuid-deps.c), but some kernel/
      # hypervisor combinations don't also print "osxsave" as its own flag
      # even though it's guaranteed present whenever avx is. lzcnt is
      # checked as either "lzcnt" or "abm": Intel CPUs report LZCNT support
      # under the (borrowed) AMD "abm" flag name instead of a discrete
      # "lzcnt" token — verified against this machine's own real CPU flags.
      for f in avx avx2 bmi1 bmi2 f16c fma movbe; do
        case "$flags" in
          *" $f "*) ;;
          *) return 1 ;;
        esac
      done
      case "$flags" in
        *" lzcnt "*|*" abm "*) ;;
        *) return 1 ;;
      esac
      ;;
    darwin)
      command -v sysctl >/dev/null 2>&1 || return 1
      local all f
      # Apple splits these across three separate sysctl namespaces, and
      # spells the base AVX flag "AVX1.0" rather than "AVX".
      all=" $(sysctl -n machdep.cpu.features 2>/dev/null) $(sysctl -n machdep.cpu.leaf7_features 2>/dev/null) $(sysctl -n machdep.cpu.extfeatures 2>/dev/null) "
      for f in AVX1.0 AVX2 BMI1 BMI2 F16C FMA LZCNT MOVBE OSXSAVE; do
        case "$all" in
          *" $f "*) ;;
          *) return 1 ;;
        esac
      done
      ;;
    *)
      # windows (Git Bash): no reliable CPU-feature source in a plain POSIX
      # shell here — stay on baseline. install.ps1 is the documented
      # Windows install path and has its own (better) detection.
      return 1
      ;;
  esac
  return 0
}

# Root access: we are root, or have passwordless sudo, or (interactive
# terminal only) can prompt for a sudo password. Never hang a piped install
# on a password prompt.
ROOT=()
if [ "$(id -u)" != 0 ]; then
  if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    ROOT=(sudo -n)
  elif command -v sudo >/dev/null 2>&1 && [ -t 0 ] && sudo true 2>/dev/null; then
    ROOT=(sudo)
  fi
fi
run_root() { if [ "${#ROOT[@]}" -gt 0 ]; then "${ROOT[@]}" "$@"; else "$@"; fi }
has_root() { [ "$(id -u)" = 0 ] || [ "${#ROOT[@]}" -gt 0 ]; }
# 1 if an interactive terminal is reachable: stdin is a tty, or /dev/tty can
# be opened (covers `curl ... | bash`, where stdin is the pipe, not the tty).
has_tty() {
  [ -t 0 ] && return 0
  (exec </dev/tty) 2>/dev/null
}

abs_path() {
  case "$1" in
    /*) echo "$1" ;;
    *) echo "$PWD/$1" ;;
  esac
}
CONFIG_ABS="$(abs_path "$CONFIG_PATH")"
DATA_ABS="$(abs_path "$DATA_DIR")"

# If the interactive wizard is going to run, it owns Dragonfly, the config and
# the startup service — the script only has to install the binary. Existing
# configs are always left untouched (the wizard is skipped for them).
CONFIG_EXISTED=0
[ -f "$CONFIG_ABS" ] && CONFIG_EXISTED=1
WIZARD_WILL_RUN=0
if [ "$SKIP_WIZARD" -eq 0 ] && [ "$CONFIG_EXISTED" -eq 0 ] && has_tty; then
  WIZARD_WILL_RUN=1
fi

EXT=""
[ "$OS" = windows ] && EXT=".exe"
ASSET="irongrid-${OS}-${ARCH}${EXT}"
V3_ASSET="irongrid-${OS}-${ARCH}-v3${EXT}"

# ---- resolve latest release tag for a GitHub repo (greedy .* takes the
#      last "tag_name" in the JSON, which is the only one) ----
latest_tag() {
  curl -fsSL "https://api.github.com/repos/$1/releases/latest" \
    | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1
}

# ---- install Irongrid DNS ----
if [ -z "$VERSION" ]; then
  echo "==> querying latest release of $REPO ..."
  VERSION="$(latest_tag "$REPO")"
fi
[ -n "$VERSION" ] || die "could not determine the latest version (network or rate limit?)"

BASE="https://github.com/$REPO/releases/download/$VERSION"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Fetched unconditionally (even with --skip-verify) and before the binary
# download: it's also how we know whether this release actually has a -v3
# asset for this platform, not just whether the CPU could run one.
# --skip-verify only skips the hash *comparison* further down.
curl -fsSL -o "$TMP/SHA256SUMS.txt" "$BASE/SHA256SUMS.txt"

if [ "$NO_V3" -ne 1 ] && supports_goamd64_v3 && awk -v a="$V3_ASSET" '$2 == a { found=1 } END { exit !found }' "$TMP/SHA256SUMS.txt"; then
  ASSET="$V3_ASSET"
  echo "==> installing Irongrid DNS $VERSION ($OS/$ARCH, GOAMD64=v3 build)"
else
  echo "==> installing Irongrid DNS $VERSION ($OS/$ARCH)"
fi

echo "==> downloading $ASSET ..."
curl -fsSL -o "$TMP/$ASSET" "$BASE/$ASSET"

if [ "$SKIP_VERIFY" -ne 1 ]; then
  echo "==> verifying SHA-256 checksum ..."
  expected="$(awk -v asset="$ASSET" '$2 == asset { print $1 }' "$TMP/SHA256SUMS.txt")"
  [ -n "$expected" ] || die "no checksum found for $ASSET in SHA256SUMS.txt"
  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$TMP/$ASSET" | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    actual="$(shasum -a 256 "$TMP/$ASSET" | awk '{print $1}')"
  else
    die "neither sha256sum nor shasum found — re-run with --skip-verify"
  fi
  [ "$expected" = "$actual" ] || die "checksum mismatch — download may be corrupt; refusing to install"
  echo "==> checksum OK ($actual)"
else
  echo "==> checksum verification skipped"
fi

if [ -n "$INSTALL_DIR" ]; then
  DEST="$INSTALL_DIR"
elif [ "$(id -u)" = 0 ] || [ -w /usr/local/bin ]; then
  DEST="/usr/local/bin"
else
  DEST="$HOME/.local/bin"
fi
mkdir -p "$DEST"
install -m 0755 "$TMP/$ASSET" "$DEST/irongrid${EXT}"
echo "==> installed to $DEST/irongrid${EXT}"

VERSION_OUT="$("$DEST/irongrid${EXT}" -version 2>/dev/null || true)"
[ -n "$VERSION_OUT" ] && echo "    $VERSION_OUT"

# ---- Dragonfly: the cache Irongrid requires ----
# Linux gets a native binary + systemd service. macOS/Windows have no native
# Dragonfly build, so a Docker container is used when Docker is available.
DFLY_STARTED=0
# Auto-compute Dragonfly flags from system specs: 25%% of host RAM for
# maxmemory (clamped to 256mb-32gb), proactor_threads = min(CPUs, 8) floor 2.
# Dragonfly requires >= 256MiB per proactor thread at startup.
detect_dragonfly_flags() {
  local cpus mem_bytes mem_pct maxmem threads min_per_thread=268435456  # 256 MiB

  # CPU count: nproc (Linux), sysctl (macOS), fallback 2
  cpus=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 2)
  [ "$cpus" -lt 2 ] && cpus=2
  [ "$cpus" -gt 8 ] && cpus=8
  threads=$cpus

  # Memory: /proc/meminfo (Linux), sysctl hw.memsize (macOS), fallback 512 MiB
  if [ -r /proc/meminfo ]; then
    mem_bytes=$(awk '/^MemTotal:/{print $2 * 1024}' /proc/meminfo 2>/dev/null)
  elif command -v sysctl >/dev/null 2>&1; then
    mem_bytes=$(sysctl -n hw.memsize 2>/dev/null)
  fi
  [ -z "$mem_bytes" ] || [ "$mem_bytes" -eq 0 ] && mem_bytes=$((512 * 1024 * 1024))

  # 25%% of host RAM, clamped to 256 MiB - 32 GiB
  mem_pct=$((mem_bytes / 4))
  [ "$mem_pct" -lt $((256 * 1024 * 1024)) ] && mem_pct=$((256 * 1024 * 1024))
  [ "$mem_pct" -gt $((32 * 1024 * 1024 * 1024)) ] && mem_pct=$((32 * 1024 * 1024 * 1024))

  # Ensure maxmemory >= 256 MiB x proactor_threads
  min_for_threads=$((threads * min_per_thread))
  [ "$mem_pct" -lt "$min_for_threads" ] && mem_pct=$min_for_threads

  # Format as "512mb" / "2gb"
  if [ $((mem_pct %% (1024 * 1024 * 1024))) -eq 0 ]; then
    maxmem="$((mem_pct / (1024 * 1024 * 1024)))gb"
  else
    maxmem="$((mem_pct / (1024 * 1024)))mb"
  fi

  DFLY_MAXMEM="$maxmem"
  DFLY_THREADS="$threads"
}
detect_dragonfly_flags

DFLY_FLAGS="--port=6379 --bind=127.0.0.1 --cache_mode=true --maxmemory=$DFLY_MAXMEM --proactor_threads=$DFLY_THREADS --snapshot_cron=\"0 * * * \"\" --dbfilename=irongrid-dump"
# In Docker the container must NOT bind to 127.0.0.1 -- docker-proxy reaches
# the container via its eth0 IP, so --bind would make the published port
# refuse connections. The host-side -p 127.0.0.1:6379:6379 mapping already
# keeps the port private.
# --snapshot_cron + --dbfilename give hourly persistence (the query log and
# cache survive a hard crash; a graceful restart snapshots anyway).
DFLY_DOCKER_FLAGS="--port=6379 --cache_mode=true --maxmemory=$DFLY_MAXMEM --proactor_threads=$DFLY_THREADS --snapshot_cron=\"0 * * * \"\" --dbfilename=irongrid-dump"

# 1 if a Redis-compatible server answers PING on the given local port.
# The read is bounded (-t) so a socket that accepts but is still initialising
# cannot hang the probe.
port_answers_redis() {
  # The reply is "+PONG\r\n"; read -r keeps the trailing CR, so match a
  # prefix with [[ == ]] instead of exact equality. pong is pre-initialised
  # so a timed-out read can't hit an unbound-variable error under set -u.
  local pong=""
  (exec 3<>"/dev/tcp/127.0.0.1/$1" \
      && printf 'PING\r\n' >&3 \
      && IFS= read -t 1 -r pong <&3 \
      && [[ "$pong" == +PONG* ]]) 2>/dev/null
}
# 1 if anything at all is listening on the given local port.
port_busy() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
install_dragonfly() {
  [ "$SKIP_DRAGONFLY" -eq 1 ] && { echo "==> Dragonfly skipped (--skip-dragonfly)"; return 0; }
  # If a Redis-compatible server already answers on 6379 (servers often run
  # Redis/KeyDB/Dragonfly already), just use it — never leave a crash-looping
  # unit fighting over the port.
  if port_answers_redis 6379; then
    echo "==> a Redis-compatible server already answers on 127.0.0.1:6379 — using it"
    DFLY_STARTED=1
    return 0
  fi
  if port_busy 6379; then
    echo "!! port 6379 is in use by a process that is not a Redis server."
    echo "   Set cache.addr to a free port in irongrid.yaml (or free 6379 and re-run)."
    return 0
  fi
  case "$OS" in
    linux) install_dragonfly_linux ;;
    darwin|windows) install_dragonfly_docker ;;
  esac
}

install_dragonfly_linux() {
  echo "==> installing Dragonfly (native binary + service) ..."
  case "$ARCH" in
    amd64) DFLY_ARCH=x86_64 ;;
    arm64) DFLY_ARCH=aarch64 ;;
  esac
  DFLY_VERSION="$(latest_tag "$DFLY_REPO")" || true
  if [ -z "$DFLY_VERSION" ]; then
    echo "!! could not resolve the latest Dragonfly release; falling back to Docker"
    install_dragonfly_docker
    return 0
  fi

  DFLY_URL="https://github.com/$DFLY_REPO/releases/download/$DFLY_VERSION/dragonfly-$DFLY_ARCH.tar.gz"
  echo "==> downloading Dragonfly $DFLY_VERSION ($DFLY_ARCH) ..."
  need tar
  if ! curl -fsSL -o "$TMP/dragonfly.tar.gz" "$DFLY_URL"; then
    echo "!! native Dragonfly download failed; falling back to Docker"
    install_dragonfly_docker
    return 0
  fi
  tar -xzf "$TMP/dragonfly.tar.gz" -C "$TMP"

  if has_root; then
    DFLY_BIN="/usr/local/bin/dragonfly"
    DFLY_DATA="/var/lib/dragonfly"
  else
    DFLY_BIN="$DEST/dragonfly"
    DFLY_DATA="$HOME/.local/share/dragonfly"
  fi

  run_root install -m 0755 "$TMP/dragonfly-$DFLY_ARCH" "$DFLY_BIN"
  run_root mkdir -p "$DFLY_DATA"
  echo "    $(run_root "$DFLY_BIN" --version 2>/dev/null | head -1 || echo "dragonfly installed")"

  if has_root && systemd_available; then
    echo "==> installing systemd service ..."
    # Reset any stale failed/auto-restarting instance before swapping the unit.
    run_root systemctl stop dragonfly >/dev/null 2>&1 || true
    run_root systemctl reset-failed dragonfly >/dev/null 2>&1 || true
    run_root tee /etc/systemd/system/dragonfly.service >/dev/null <<EOF
[Unit]
Description=DragonflyDB - Redis-compatible cache for Irongrid DNS
After=network.target

[Service]
ExecStart=$DFLY_BIN $DFLY_FLAGS --dir=$DFLY_DATA
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
    run_root systemctl daemon-reload
    run_root systemctl enable dragonfly >/dev/null 2>&1 || true
    run_root systemctl restart dragonfly
    if wait_for_dragonfly; then
      DFLY_STARTED=1
      echo "==> Dragonfly service enabled and running (systemctl status dragonfly)"
    else
      echo "!! Dragonfly service installed but did not answer PING — check: systemctl status dragonfly"
    fi
    return 0
  fi

  echo "==> starting Dragonfly in the background (no root/systemd service) ..."
  mkdir -p "$DFLY_DATA"
  nohup "$DFLY_BIN" $DFLY_FLAGS --dir="$DFLY_DATA" >"$DFLY_DATA/dragonfly.log" 2>&1 &
  if wait_for_dragonfly; then DFLY_STARTED=1; fi
}

install_dragonfly_docker() {
  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    echo "==> starting Dragonfly in Docker (no native $OS build exists) ..."
    docker rm -f dragonfly >/dev/null 2>&1 || true
    docker run -d --name dragonfly --restart unless-stopped \
      -p 127.0.0.1:6379:6379 \
      -v "$DFLY_DATA:/data" \
      "$DFLY_IMAGE" $DFLY_DOCKER_FLAGS >/dev/null
    if wait_for_dragonfly; then DFLY_STARTED=1; fi
  else
    echo "!! Dragonfly has no native $OS build and Docker was not found."
    if [ "$OS" = darwin ]; then
      echo "   Install Docker Desktop: https://www.docker.com/products/docker-desktop/"
    else
      echo "   Install Docker Desktop (WSL2 backend): https://www.docker.com/products/docker-desktop/"
    fi
    echo "   then run:  docker run -d --name dragonfly --restart unless-stopped -p 127.0.0.1:6379:6379 -v \"\$DFLY_DATA:/data\" $DFLY_IMAGE $DFLY_DOCKER_FLAGS"
  fi
}

systemd_available() { [ -d /run/systemd/system ] || command -v systemctl >/dev/null 2>&1; }

# PING over the Redis protocol: a bare TCP connect is not enough — the
# listen socket can open moments before a startup failure kills the process.
wait_for_dragonfly() {
  for _ in $(seq 1 30); do
    if port_answers_redis 6379; then return 0; fi
    sleep 0.5
  done
  echo "!! Dragonfly did not answer PING on 127.0.0.1:6379 — check its logs"
  return 1
}

if [ "$WIZARD_WILL_RUN" -eq 1 ]; then
  echo "==> Dragonfly install deferred to the interactive wizard"
else
  install_dragonfly
fi

# ---- default config ----
# Write a ready-to-run default config when none exists, so the server can be
# started straight after installing. cache.addr always points at localhost:6379
# (where the Dragonfly above is served). When the interactive wizard is about
# to run, it writes the config itself.
if [ "$WIZARD_WILL_RUN" -eq 1 ]; then
  echo "==> config will be written by the interactive wizard"
elif [ ! -f "$CONFIG_ABS" ]; then
  echo "==> writing default config to $CONFIG_ABS"
  mkdir -p "$(dirname "$CONFIG_ABS")"
  cat >"$CONFIG_ABS" <<EOF
# Irongrid DNS configuration (default, generated by the installer).
# The dashboard can edit everything here live — see README for details.
# Encrypted listeners (DoT/DoH/DoQ) are off by default to avoid port
# conflicts; enable them in the dashboard or with: irongrid install
server:
  listen_udp: "0.0.0.0:53"     # plain DNS over UDP
  listen_tcp: "0.0.0.0:53"     # plain DNS over TCP
  listen_dot: ""               # DNS over TLS ("" disables)
  listen_doh: ""               # DNS over HTTPS
  listen_doq: ""               # DNS over QUIC
  doh_path: "/dns-query"
  web_listen: "0.0.0.0:8080"   # dashboard + REST API
  timeout_sec: 5

upstreams:
  - "udp://1.1.1.1:53"
  - "udp://8.8.8.8:53"

cache:
  addr: "localhost:6379"       # Dragonfly endpoint (installed by this script)
  password: ""
  db: 0
  ttl: 6h
  negative_ttl: 1m
  failure_ttl: 5s
  l1_entries: 4096

tls:
  cert_file: ""
  key_file: ""
  generate_self_signed: true
  self_signed_hosts:
    - "localhost"
  cert_dir: "data/certs"

filter:
  block_response: "nxdomain"
  block_ttl: 600
  blocklists: []
  whitelist: []
  blacklist: []

log:
  query_log_file: "data/querylog.db"  # legacy; the log lives in Dragonfly (stream irongrid:log)
  retention_days: 30
  verbose: true

web:
  username: "admin"
  password: ""                 # default login is admin / irongrid — change it!

tunnel:
  enabled: false
EOF
else
  echo "==> config already exists at $CONFIG_ABS (leaving it untouched)"
fi

# ---- Irongrid as a startup service ----
install_irongrid_service() {
  [ "$INSTALL_SERVICE" -eq 1 ] || { echo "==> service install skipped (--no-service)"; return 0; }
  case "$OS" in
    linux) install_irongrid_systemd ;;
    darwin) install_irongrid_launchd ;;
    windows) echo "==> service install handled by install.ps1 on Windows" ;;
  esac
}

# ---- host kernel tuning (Linux only) ----
# The kernel clamps SO_RCVBUF/SO_SNDBUF to net.core.rmem_max/wmem_max
# (default ~208 KiB), which would silently gut Irongrid's 2 MiB DNS socket
# buffers. Raising the ceilings is a privileged host change, so this runs
# only when root is available; without root the in-process best-effort write
# at boot logs the same hint instead. Docker containers get the effect via
# docker-compose.yml's sysctls.
apply_kernel_sysctls() {
  [ "$OS" = linux ] || return 0
  has_root || { echo "==> kernel socket tuning skipped (no root — container sysctls apply instead)"; return 0; }
  local CONF=/etc/sysctl.d/99-irongrid.conf
  echo "==> tuning kernel socket buffers (net.core.*) ..."
  run_root tee "$CONF" >/dev/null <<EOF
# Irongrid DNS — raise the kernel socket-buffer ceilings so the DNS
# server's 2 MiB socket buffers actually take effect.
net.core.rmem_max = 4194304
net.core.wmem_max = 4194304
net.core.somaxconn = 65535
EOF
  if run_root sysctl --system >/dev/null 2>&1 || run_root sysctl -p "$CONF" >/dev/null 2>&1; then
    echo "==> kernel socket tuning applied ($CONF)"
  else
    echo "!! could not apply kernel socket tuning — apply manually: sysctl -p $CONF"
  fi
}

install_irongrid_systemd() {
  if ! { has_root && systemd_available; }; then
    echo "!! not installing Irongrid as a service (no root or no systemd)"
    echo "   run it manually:  $DEST/irongrid -config $CONFIG_ABS -data $DATA_ABS"
    return 0
  fi
  echo "==> installing Irongrid systemd service ..."
  # Reset any stale failed/auto-restarting instance before swapping the unit.
  run_root systemctl stop irongrid >/dev/null 2>&1 || true
  run_root systemctl reset-failed irongrid >/dev/null 2>&1 || true
  run_root mkdir -p "$DATA_ABS"
  run_root tee /etc/systemd/system/irongrid.service >/dev/null <<EOF
[Unit]
Description=Irongrid DNS - ad-blocking DNS server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$DEST/irongrid -config $CONFIG_ABS -data $DATA_ABS
WorkingDirectory=$DATA_ABS
# WorkingDirectory resolves relative paths in the config (data/certs, data/querylog.db)
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
ProtectSystem=full
PrivateTmp=true
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
  run_root systemctl daemon-reload
  run_root systemctl enable irongrid >/dev/null 2>&1 || true
  run_root systemctl start irongrid 2>/dev/null || true
  # Poll is-active for up to 10s: a Type=simple unit that dies instantly
  # (e.g. a missing WorkingDirectory — status 200/CHDIR) reports "activating"
  # right after start, so a single sleep can race with its 3s restart loop —
  # while a slow first start (cert generation, initial blocklist download)
  # may take a few seconds to become active legitimately.
  ACTIVE=""
  for _ in $(seq 1 10); do
    [ "$(run_root systemctl is-active irongrid 2>/dev/null || echo failed)" = "active" ] && { ACTIVE=1; break; }
    sleep 1
  done
  if [ -n "$ACTIVE" ]; then
    echo "==> Irongrid service enabled and running (systemctl status irongrid)"
  else
    echo "!! Irongrid service installed but not active — check: systemctl status irongrid"
    echo "   (a common cause is a missing data dir: mkdir -p $DATA_ABS && systemctl restart irongrid)"
  fi
}

install_irongrid_launchd() {
  echo "==> installing Irongrid launchd agent ..."
  mkdir -p "$DATA_ABS" "$HOME/Library/LaunchAgents"
  local label="com.irongrid.dns"
  local plist="$HOME/Library/LaunchAgents/$label.plist"
  cat >"$plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>$label</string>
  <key>ProgramArguments</key>
  <array>
    <string>$DEST/irongrid</string>
    <string>-config</string>
    <string>$CONFIG_ABS</string>
    <string>-data</string>
    <string>$DATA_ABS</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>WorkingDirectory</key>
  <string>$DATA_ABS</string>
  <key>StandardOutPath</key>
  <string>$DATA_ABS/irongrid.log</string>
  <key>StandardErrorPath</key>
  <string>$DATA_ABS/irongrid.log</string>
</dict>
</plist>
EOF
  if launchctl load "$plist" 2>/dev/null; then
    echo "==> Irongrid launchd agent loaded (com.irongrid.dns)"
  else
    echo "   launchd plist written to $plist — load it with: launchctl load $plist"
  fi
}

# Kernel socket tuning is a host-level change, independent of whether the
# wizard or the script's own steps install the startup service — run it in
# both paths (the function self-guards on OS and root availability).
apply_kernel_sysctls

if [ "$WIZARD_WILL_RUN" -eq 1 ]; then
  echo "==> startup service install deferred to the interactive wizard"
else
  install_irongrid_service
fi

# ---- interactive setup wizard (TUI) ----
# Launch `irongrid install`, which handles the whole install (Dragonfly, the
# config, binary placement and the startup service). This needs a real
# terminal: when piped via `curl | bash` stdin is the (already drained) pipe,
# so we re-open /dev/tty for the wizard — and when no terminal exists at all
# (CI, Docker, etc.) we skip it and keep the default config written above.
run_wizard() {
  if [ "$SKIP_WIZARD" -eq 1 ]; then
    echo "==> setup wizard skipped (--no-wizard)"
    return 0
  fi
  if [ "$CONFIG_EXISTED" -eq 1 ]; then
    echo "==> config already existed - wizard skipped to leave it untouched"
    echo "    (re-run it anytime with: $DEST/irongrid${EXT} install)"
    return 0
  fi
  if ! has_tty; then
    echo "==> no interactive terminal detected - keeping the default config"
    echo "    (re-run the wizard anytime with: $DEST/irongrid${EXT} install)"
    return 0
  fi
  echo
  echo "==> launching the interactive setup wizard ..."
  echo "    it handles Dragonfly, the config, and the startup service"
  # Re-open stdin from the terminal so the wizard works even when this script
  # was piped via `curl ... | bash`. IMPORTANT: no stderr redirect on this
  # exec — an exec redirection persists for the whole shell, so 2>/dev/null
  # here would also hide the wizard's own error output.
  if ! exec </dev/tty; then
    echo "!! could not open the terminal - keeping the default config"
    return 0
  fi
  # The wizard installs Dragonfly itself when asked, so --with-dragonfly is not
  # passed here (older release binaries don't define that flag anyway).
  # Propagate the script's skip flags into the wizard.
  export IRONGRID_SKIP_DRAGONFLY=0 IRONGRID_NO_SERVICE=0
  [ "$SKIP_DRAGONFLY" -eq 1 ] && export IRONGRID_SKIP_DRAGONFLY=1
  [ "$INSTALL_SERVICE" -eq 0 ] && export IRONGRID_NO_SERVICE=1
  if ! "$DEST/irongrid${EXT}" install --config "$CONFIG_ABS" --data "$DATA_ABS"; then
    echo "   (wizard did not complete - no config was written; re-run it, or use --no-wizard for the default setup)"
  fi
  # Restart a startup service so the wizard's config takes effect right away.
  if [ "$INSTALL_SERVICE" -eq 1 ]; then
    if [ "$OS" = linux ] && has_root && systemd_available; then
      # The unit's WorkingDirectory is $DATA_ABS — systemd chdirs into it
      # before exec'ing the process, so a missing data dir makes the service
      # exit with status 200/CHDIR and crash-loop. Make sure it exists (the
      # wizard may have been run with an older binary that didn't create it).
      run_root mkdir -p "$DATA_ABS"
      if run_root systemctl restart irongrid >/dev/null 2>&1; then
        # Poll is-active for up to 10s: a unit that dies instantly reports
        # "activating" right after start, so a single sleep can race its 3s
        # restart loop — while a slow first start may take a few seconds to
        # become active legitimately.
        ACTIVE=""
        for _ in $(seq 1 10); do
          [ "$(run_root systemctl is-active irongrid 2>/dev/null || echo failed)" = "active" ] && { ACTIVE=1; break; }
          sleep 1
        done
        if [ -n "$ACTIVE" ]; then
          echo "==> Irongrid service restarted with the new config"
        else
          echo "!! Irongrid service did not stay up after restart — check: systemctl status irongrid"
          echo "   (a common cause is a bad directive in the unit file or a missing data dir)"
        fi
      else
        echo "   restart the Irongrid service to apply the new config"
      fi
    elif [ "$OS" = darwin ] && command -v launchctl >/dev/null 2>&1; then
      launchctl kickstart -k "gui/$(id -u)/com.irongrid.dns" >/dev/null 2>&1 \
        && echo "==> Irongrid launchd agent restarted with the new config" \
        || echo "   reload the launchd agent to apply the new config (launchctl unload/load com.irongrid.dns)"
    fi
  fi
}
run_wizard

# If the wizard just ran, reflect whether it left a cache running at 6379.
if [ "$WIZARD_WILL_RUN" -eq 1 ] && port_answers_redis 6379; then
  DFLY_STARTED=1
fi

echo
echo "Next steps:"
if [ "$DFLY_STARTED" -eq 1 ]; then
  echo "  ✓ Dragonfly cache is running on 127.0.0.1:6379"
else
  echo "  ! Start Dragonfly (required cache) - see the notes above or docker-compose.yml"
fi
if [ -f "$CONFIG_ABS" ]; then
  echo "  ✓ Config: $CONFIG_ABS"
else
  echo "  ! Config not written yet - run the wizard: $DEST/irongrid${EXT} install"
fi
echo "  1. If the service above is not running, start it:"
echo "       $DEST/irongrid -config $CONFIG_ABS -data $DATA_ABS"
echo "  2. Customise setup anytime with the wizard: $DEST/irongrid${EXT} install"
echo "  3. Dashboard:      http://localhost:8080  (default login: admin / irongrid)"
echo "  4. Point devices at this machine's port 53 (UDP/TCP)"
