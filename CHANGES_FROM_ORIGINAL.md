# Điểm đã sửa so với tài liệu hướng dẫn gốc

| # | Vấn đề trong bản gốc | Sửa |
|---|---|---|
| 1 | YARA `$header = { 00 10 [256] }`: khóa RSA-2048 mã hóa dài 256 = `0x0100` nên 2 byte đầu là `01 00`, không phải `00 10`; ngoài ra YARA không cho jump `[256]` ở cuối chuỗi hex | Dùng `uint16be(0) == 0x0100` |
| 2 | Ngưỡng entropy 7.5: file ~300 byte (file thử nhỏ) chỉ đạt ~7.3 | Hạ còn 7.0 |
| 3 | STIX 2.1 bundle có `spec_version` (2.1 không dùng ở bundle); indicator thiếu `created`/`modified` bắt buộc; hash lấy từ file `.yar` | Bỏ `spec_version` ở bundle, thêm created/modified, `gen_stix.py` tính hash thật |
| 4 | CACAO: `spec_version` là `"1.0"` (không phải `cacao-1.0`); kiểu step là `single` (không có `single-action`/`action`); thiếu step `start`, `commands`, `created_by`, `created`, `modified` | Viết lại playbook, có `if-condition` cho kịch bản A/B |
| 5 | `monitor.py` nhận diện bằng chuỗi `"rename"` + `key="..."`: dễ sót nếu nhiều rule cùng khớp (key ghi dạng hex) | Nhận diện theo số hiệu syscall x86_64 (82/264/316), khử trùng lặp theo serial, in PID nghi ngờ |
| 6 | `DEBIAN_FRONTEND=... sudo apt-get`: biến môi trường có thể bị sudo loại bỏ | `sudo DEBIAN_FRONTEND=... apt-get` |
| 7 | Hướng dẫn nhắc "tạo keypair test ở Phần E.3" nhưng phần đó không có | Thêm `gen_rsa_keypair.py` |
| 8 | `simulate_events.py` có dòng thừa `design` (lỗi dán) | Đã loại bỏ, thêm `--dir`, `--delay`, danh sách thư mục cấm |

## Giới hạn còn lại
- Không có `encrypt.py` → muốn chạy thật `decrypt.py` cần mẫu `.LOCKED` do giảng viên/thành viên phụ trách cung cấp (khóa công khai sinh từ `gen_rsa_keypair.py`).
- Luật YARA và playbook CACAO chưa được chạy bằng YARA/validator chính thức trong môi trường soạn; hãy chạy `yara` trên VM và `scripts/validate_json.py` để xác nhận.
