#!/usr/bin/env bash
# INS3201 - Thu thap bang chung (Giai doan 3). Chay: sudo bash scripts/collect_evidence.sh [thu_muc_quet_yara]
set -uo pipefail
[ "$EUID" -eq 0 ] || { echo "Can chay bang sudo"; exit 1; }

OUT="evidence/$(date +%Y%m%d_%H%M%S)"
YARA_RULE="$(dirname "$0")/../detection/ransomware_detection.yar"
SCAN_DIR="${1:-/home/ubuntu}"
mkdir -p "$OUT"

date -u +"%Y-%m-%dT%H:%M:%SZ"          > "$OUT/collected_at_utc.txt"
auditctl -l                            > "$OUT/auditctl_rules.txt" 2>&1
ausearch -k mass_rename -i             > "$OUT/ausearch_mass_rename.txt" 2>&1
ausearch -k ransomware_monitor -i      > "$OUT/ausearch_ransomware_monitor.txt" 2>&1
ausearch -k file_deletion -i           > "$OUT/ausearch_file_deletion.txt" 2>&1
ausearch -k mass_rename --format text  > "$OUT/ausearch_mass_rename_text.txt" 2>&1
ps -ef --forest                        > "$OUT/ps_forest.txt"
[ -f /var/log/ransomware_alert.log ] && cp /var/log/ransomware_alert.log "$OUT/"
[ -f /home/ubuntu/.bash_history ] && grep -i python /home/ubuntu/.bash_history > "$OUT/bash_history_python.txt"
yara -r "$YARA_RULE" "$SCAN_DIR"       > "$OUT/yara_scan.txt" 2>&1

# Bao toan toan ven bang chung
( cd "$OUT" && sha256sum * > SHA256SUMS.txt )
echo "[+] Da luu bang chung vao $OUT"
