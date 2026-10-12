#!/usr/bin/env bash
# INS3201 - Co lap / khoi phuc mang Victim (buoc isolate cua playbook)
# Dung: sudo bash scripts/network_isolate.sh isolate|restore [interface]   (mac dinh ens33)
set -euo pipefail
ACTION="${1:-}"; IFACE="${2:-ens33}"
case "$ACTION" in
  isolate) ip link set "$IFACE" down && echo "[+] $IFACE DOWN - da co lap mang" ;;
  restore) ip link set "$IFACE" up   && echo "[+] $IFACE UP - da bat lai mang" ;;
  *) echo "Usage: $0 isolate|restore [interface]"; exit 1 ;;
esac
ip -br link show "$IFACE"
