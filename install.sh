#!/usr/bin/env bash
#
# Irongrid DNS — one-line installer (Linux / macOS, and Windows via Git Bash)
#
#   curl -fsSL https://raw.githubusercontent.com/eoghan2t9/Irongrid-DNS/main/install.sh | bash
#
# Downloads the latest release binary for your platform, verifies its SHA-256
# checksum against the published SHA256SUMS.txt, and installs it. Options:
#
#   --version <tag>   install a specific release tag (default: latest)
#   --dir <path>      install into a custom directory
#   --skip-verify     skip checksum verification (not recommended)
#
set -euo pipefail

REPO="eoghan2t9/Irongrid-DNS"
VERSION=""
INSTALL_DIR=""
SKIP_VERIFY=0

die() { echo "error: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "required tool missing: $1"; }

# Help is a heredoc so it works even when the script is piped via curl|bash
# (where "$0" is not the script file).
usage() {
  cat <<'EOF'
Irongrid DNS - one-line installer (Linux / macOS, and Windows via Git Bash)

  curl -fsSL https://raw.githubusercontent.com/eoghan2t9/Irongrid-DNS/main/install.sh | bash

Options:
  --version <tag>   install a specific release tag (default: latest)
  --dir <path>      install into a custom directory
  --skip-verify     skip checksum verification (not recommended)
  -h, --help        show this help
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --version)
      [ $# -ge 2 ] || die "--version requires a value"; VERSION="$2"; shift 2 ;;
    --dir)
      [ $# -ge 2 ] || die "--dir requires a value"; INSTALL_DIR="$2"; shift 2 ;;
    --skip-verify) SKIP_VERIFY=1; shift ;;
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

# ---- resolve release version ----
if [ -z "$VERSION" ]; then
  echo "==> querying latest release of $REPO ..."
  VERSION="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
    | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"
fi
[ -n "$VERSION" ] || die "could not determine the latest version (network or rate limit?)"
echo "==> installing Irongrid DNS $VERSION ($OS/$ARCH)"

BASE="https://github.com/$REPO/releases/download/$VERSION"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# ---- download + verify ----
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

# ---- install ----
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

echo
echo "Next steps:"
echo "  1. Start Dragonfly (required cache) — e.g. docker run -d --name dragonfly -p 6379:6379 docker.dragonflydb.io/dragonfly/dragonfly"
echo "  2. Run the setup wizard:     $DEST/irongrid install"
echo "  3. Start the server:         $DEST/irongrid -config irongrid.yaml -data data"
echo "  4. Dashboard:                http://localhost:8080"
