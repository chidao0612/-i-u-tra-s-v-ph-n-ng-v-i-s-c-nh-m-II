# Dựng Lab trên VMware Workstation

## 1. Mạng Host-only (Virtual Network Editor, quyền Administrator)
Add Network → **VMnet2** → Host-only → **bỏ** "Use local DHCP service" (nên bỏ cả "Connect a host virtual adapter") → Subnet `192.168.56.0` / `255.255.255.0`.

## 2. Máy ảo
| VM | ISO | Cấu hình | Network |
|---|---|---|---|
| Victim_Ubuntu_Server | Ubuntu Server 22.04 LTS | 2 vCPU, 4 GB, 30 GB | Custom: VMnet2 |
| Attacker_Kali | Kali 2023.x/2024.x | 2 vCPU, 2 GB, 20 GB | Custom: VMnet2 |

Mỗi VM chỉ **1 card mạng**. Cài OpenSSH khi cài Ubuntu.

## 3. IP tĩnh
Victim – `/etc/netplan/00-installer-config.yaml` (tên card có thể là `ens33`/`ens160`, kiểm tra bằng `ip a`):
```yaml
network:
  version: 2
  ethernets:
    ens33:
      dhcp4: no
      addresses: [192.168.56.101/24]
```
`sudo netplan apply`

Attacker:
```bash
sudo nmcli con mod "Wired connection 1" ipv4.addresses 192.168.56.102/24 ipv4.method manual
sudo nmcli con up "Wired connection 1"
```

## 4. Kiểm tra cách ly
```bash
ping -c 3 192.168.56.102   # phải thông
ping -c 3 8.8.8.8          # PHẢI timeout
```

## 5. Cài công cụ, nạp rules, chụp snapshot
```bash
bash scripts/setup_victim.sh        # → snapshot Baseline_Clean_State
bash scripts/setup_audit.sh
sudo cp config/ins3201-monitor.service /etc/systemd/system/   # tuỳ chọn: chạy monitor nền
sudo systemctl daemon-reload && sudo systemctl enable --now ins3201-monitor
# → snapshot After_Monitoring_Setup
```
Snapshot bằng dòng lệnh (host): `vmrun -T ws snapshot "<.vmx>" "Baseline_Clean_State"`; rollback: `vmrun -T ws revertToSnapshot "<.vmx>" "Baseline_Clean_State"`.
Nếu dùng service, nhớ chép `scripts/monitor.py` về `/home/ubuntu/monitor.py`.
