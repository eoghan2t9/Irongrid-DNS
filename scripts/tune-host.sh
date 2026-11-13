#!/usr/bin/env bash
# Apply Linux host/NIC/CPU performance tweaks for Irongrid DNS.
# Usage: sudo ./scripts/tune-host.sh [iface] [--notrack]
set -euo pipefail

IFACE=""
NOTRACK=0
for arg in "$@"; do
  case "$arg" in
    --notrack) NOTRACK=1 ;;
    *) IFACE="$arg" ;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  echo "error: run as root (sudo $0 $*)" >&2
  exit 1
fi

echo "==> Writing /etc/sysctl.d/99-irongrid.conf"
cat >/etc/sysctl.d/99-irongrid.conf <<'EOF'
net.core.rmem_max = 4194304
net.core.wmem_max = 4194304
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 16384
net.core.netdev_budget = 600
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_fastopen = 3
vm.swappiness = 1
EOF
sysctl --system >/dev/null || true

if [[ -w /sys/kernel/mm/transparent_hugepage/enabled ]]; then
  echo "==> Setting Transparent Huge Pages to madvise"
  echo madvise >/sys/kernel/mm/transparent_hugepage/enabled || true
fi

if command -v cpupower >/dev/null 2>&1; then
  echo "==> Setting CPU governor to performance"
  cpupower frequency-set -g performance >/dev/null 2>&1 || true
elif compgen -G "/sys/devices/system/cpu/cpu*/cpufreq/scaling_governor" >/dev/null; then
  echo "==> Setting scaling_governor to performance"
  for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
    echo performance >"$g" 2>/dev/null || true
  done
fi

if [[ -z "$IFACE" ]] && command -v ip >/dev/null 2>&1; then
  IFACE=$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')
fi

if [[ -n "$IFACE" ]] && command -v ethtool >/dev/null 2>&1; then
  CORES=$(nproc)
  echo "==> Tuning NIC $IFACE (RSS combined=$CORES, rx/tx ring=4096)"
  ethtool -L "$IFACE" combined "$CORES" 2>/dev/null || true
  ethtool -G "$IFACE" rx 4096 tx 4096 2>/dev/null || true
fi

if [[ "$NOTRACK" -eq 1 ]] && command -v iptables >/dev/null 2>&1; then
  echo "==> Adding iptables raw NOTRACK rules for DNS port 53"
  for proto in udp tcp; do
    iptables -t raw -C PREROUTING -p "$proto" --dport 53 -j NOTRACK 2>/dev/null || \
      iptables -t raw -A PREROUTING -p "$proto" --dport 53 -j NOTRACK
    iptables -t raw -C OUTPUT -p "$proto" --sport 53 -j NOTRACK 2>/dev/null || \
      iptables -t raw -A OUTPUT -p "$proto" --sport 53 -j NOTRACK
  done
fi

echo "Done."
