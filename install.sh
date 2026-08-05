#!/usr/bin/env bash
#
# Irongrid DNS — one-line installer (Linux / macOS, and Windows via Git Bash)
#
#   curl -fsSL https://raw.githubusercontent.com/eoghan2t9/Irongrid-DNS/main/install.sh | bash
#
# Downloads the latest Irongrid DNS release binary for your platform, verifies
# its SHA-256 checksum against the published SHA256SUMS.txt, and installs it.
# It also installs and starts DragonflyDB (the required cache): a native
# binary + systemd service on Linux, or a Docker container on macOS/Windows
# (Dragonfly publishes no native builds for those platforms). Options:
#
#   --version <tag>     install a specific release tag (default: latest)
#   --dir <path>        install into a custom directory
#   --skip-verify       skip checksum verification (not recommended)
#   --skip-dragonfly    do not install/start Dragonfly
#   -h, --help          show this help
#
set -euo pipefail

REPO="eoghan2t9/Irongrid-DNS"
DFLY_REPO="dragonflydb/dragonfly"
DFLY_IMAGE="docker.dragonflydb.io/dragonfly/dragonfly"
VERSION=""
INSTALL_DIR=""
SKIP_VERIFY=0
SKIP_DRAGONFLY=0

die() { echo "error: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "required tool missing: $1"; }

# Help is a heredoc so it works even when the script is piped via curl|bash
# (where "$0" is not the script file).
usage() {
  cat <<'EOF'
Irongrid DNS - one-line installer (Linux / macOS, and Windows via Git Bash)

  curl -fsSL https://raw.githubusercontent.com/eoghan2t9/Irongrid-DNS/main/install.sh | bash

Installs Irongrid DNS and DragonflyDB (the required cache):
  - Linux:    native Dragonfly binary + systemd service
  - macOS:    Dragonfly in Docker (no native macOS build exists)
  - Windows:  Dragonfly in Docker (no native Windows build exists)

Options:
  --version <tag>     install a specific release tag (default: latest)
  --dir <path>        install into a custom directory
  --skip-verify       skip checksum verification (not recommended)
  --skip-dragonfly    do not install/start Dragonfly
  -h, --help          show this help
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --version)
      [ $# -ge 2 ] || die "--version requires a value"; VERSION="$2"; shift 2 ;;
    --dir)
      [ $# -ge 2 ] || die "--dir requires a value"; INSTALL_DIR="$2"; shift 2 ;;
    --skip-verify) SKIP_VERIFY=1; shift ;;
    --skip-dragonfly) SKIP_DRAGONFLY=1; shift ;;
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

EXT=""
[ "$OS" = windows ] && EXT=".exe"
ASSET="irongrid-${OS}-${ARCH}${EXT}"

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
echo "==> installing Irongrid DNS $VERSION ($OS/$ARCH)"

BASE="https://github.com/$REPO/releases/download/$VERSION"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "==> downloading $ASSET ..."
curl -fsSL -o "$TMP/$ASSET" "$BASE/$ASSET"

if [ "$SKIP_VERIFY" -ne 1 ]; then
  echo "==> verifying SHA-256 checksum ..."
  curl -fsSL -o "$TMP/SHA256SUMS.txt" "$BASE/SHA256SUMS.txt"
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
# --maxmemory must be >= 256MiB per proactor thread; 2 threads x 256MiB =
# 512mb. Pinning --proactor_threads makes the flag combination valid on any
# machine (the default of one thread per core can exceed it).
DFLY_FLAGS="--port=6379 --bind=127.0.0.1 --cache_mode=true --maxmemory=512mb --proactor_threads=2"
# In Docker the container must NOT bind to 127.0.0.1 — docker-proxy reaches
# the container via its eth0 IP, so --bind would make the published port
# refuse connections. The host-side -p 127.0.0.1:6379:6379 mapping already
# keeps the port private.
DFLY_DOCKER_FLAGS="--port=6379 --cache_mode=true --maxmemory=512mb --proactor_threads=2"

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

  # Dragonfly publishes no checksums, so verify the binary responds instead.
  # Root access: we are root, or have passwordless sudo, or (interactive
  # terminal only) can prompt for a sudo password. Otherwise fall back to a
  # background process — never hang a piped install on a password prompt.
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
      "$DFLY_IMAGE" $DFLY_DOCKER_FLAGS >/dev/null
    if wait_for_dragonfly; then DFLY_STARTED=1; fi
  else
    echo "!! Dragonfly has no native $OS build and Docker was not found."
    if [ "$OS" = darwin ]; then
      echo "   Install Docker Desktop: https://www.docker.com/products/docker-desktop/"
    else
      echo "   Install Docker Desktop (WSL2 backend): https://www.docker.com/products/docker-desktop/"
    fi
    echo "   then run:  docker run -d --name dragonfly --restart unless-stopped -p 127.0.0.1:6379:6379 $DFLY_IMAGE $DFLY_DOCKER_FLAGS"
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

install_dragonfly

echo
echo "Next steps:"
if [ "$DFLY_STARTED" -eq 1 ]; then
  echo "  ✓ Dragonfly cache is running on 127.0.0.1:6379"
else
  echo "  ! Start Dragonfly (required cache) - see the notes above or docker-compose.yml"
fi
echo "  1. Run the setup wizard:     $DEST/irongrid install"
echo "  2. Start the server:         $DEST/irongrid -config irongrid.yaml -data data"
echo "  3. Dashboard:                http://localhost:8080"
