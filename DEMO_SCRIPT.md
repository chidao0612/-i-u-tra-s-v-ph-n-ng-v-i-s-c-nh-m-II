# Kịch bản video demo (4 phân cảnh)
Quay bằng OBS Studio, 2 cửa sổ terminal song song, phụ đề tiếng Việt.

| # | Nội dung | Lệnh |
|---|---|---|
| 0 | Giới thiệu mạng cô lập, snapshot | `ping 8.8.8.8` (timeout), Snapshot Manager |
| 1 | Kích hoạt sự kiện | `python3 scripts/simulate_events.py` |
| 2 | Phát hiện thời gian thực | `sudo python3 scripts/monitor.py` → CRITICAL ALERT đỏ |
| 3 | Điều tra & timeline | `sudo bash scripts/collect_evidence.sh`, `yara -r ...`, `python3 scripts/build_timeline.py` |
| 4 | Khôi phục | Kịch bản A: `python3 scripts/decrypt.py`; Kịch bản B: Revert snapshot `Baseline_Clean_State`; hoàn tác mô phỏng: `simulate_events.py --undo` |

Chạy monitor **trước** khi chạy simulate. Mỗi lần demo lại: revert snapshot hoặc `--undo`.
