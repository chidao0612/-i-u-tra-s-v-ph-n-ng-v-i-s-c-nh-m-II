#!/usr/bin/env bash
# INS3201 - Nap audit.rules. Chay tu thu muc goc repo: bash scripts/setup_audit.sh
set -euo pipefail
RULES_SRC="$(dirname "$0")/../config/audit.rules"
RULES_DST="/etc/audit/rules.d/audit.rules"

[ -f "$RULES_DST" ] && sudo cp "$RULES_DST" "$RULES_DST.bak.$(date +%s)"
sudo cp "$RULES_SRC" "$RULES_DST"
sudo augenrules --load
echo "[+] Rules dang hoat dong:"
sudo auditctl -l
