#!/usr/bin/env bash
# INS3201 - Cai cong cu tren Victim VM (Ubuntu Server 22.04). Chay: bash scripts/setup_victim.sh
set -euo pipefail

sudo apt-get update
sudo apt-get upgrade -y
sudo apt-get install -y build-essential python3 python3-pip python3-dev git
pip3 install "cryptography>=41.0"

sudo apt-get install -y auditd audispd-plugins
sudo systemctl enable --now auditd

sudo apt-get install -y yara libyara-dev
# Luu y: bien moi truong phai dat SAU sudo
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y tshark

# Thu muc du lieu thu nghiem (khop TARGET_DIR trong cac script)
DATA_DIR="/home/ubuntu/data"
mkdir -p "$DATA_DIR"
for i in $(seq 1 30); do
  echo "Tai lieu thu nghiem so $i" > "$DATA_DIR/document_$i.txt"
done

echo "[+] auditd status:"; sudo auditctl -s | head -n 3
echo "[+] Xong. Buoc tiep theo: bash scripts/setup_audit.sh, roi chup snapshot Baseline_Clean_State."
