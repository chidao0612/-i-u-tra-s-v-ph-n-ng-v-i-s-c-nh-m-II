# Incident Timeline

Sinh tự động từ log thật:
```bash
sudo python3 scripts/build_timeline.py > docs/INCIDENT_TIMELINE_RESULT.md
```
Mẫu (thay bằng số liệu thật quan sát được):

| Thời gian (UTC+7) | Tiến trình / Syscall | Hành vi ghi nhận | Mức rủi ro |
|---|---|---|---|
|  14:00:05 | python3 simulate_events.py | Bắt đầu đổi tên file trong /home/ubuntu/data/ | Trung bình |
|  14:00:06 | sys_rename (auditd) | N lời gọi rename trong X giây | Cao/Nghiêm trọng |
|  14:00:07 | monitor.py (Alert) | Vượt ngưỡng N=20/T=5s, CRITICAL ALERT | Xử lý ngay |

Đối chiếu thêm: `sudo ausearch -k mass_rename --start today -i`, `/var/log/ransomware_alert.log`, thư mục `evidence/`.
