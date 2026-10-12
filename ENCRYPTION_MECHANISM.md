# Cơ chế mã hóa lai (mô tả khái niệm)

> Repo **không** chứa `encrypt.py` chạy được. Mã mô phỏng (nếu có) do thành viên phụ trách (Vũ Thị Thu Hương) hoặc giảng viên cung cấp và giữ ngoài repo.

## Thuật toán
Hybrid Encryption: **AES-256-CBC** mã hóa dữ liệu, **RSA-2048 (OAEP, SHA-256)** bảo vệ khóa AES.

## Luồng xử lý (pseudocode)
```
với mỗi file trong thư mục mục tiêu:
    key  <- 32 byte ngẫu nhiên          # dùng 1 lần / file
    iv   <- 16 byte ngẫu nhiên
    data <- PKCS7_pad(đọc(file), 128 bit)
    ct   <- AES_256_CBC_encrypt(key, iv, data)
    ekey <- RSA_OAEP_encrypt(public_key, key)
    ghi(file, len(ekey) [2 byte BE] || ekey || iv || ct)
    đổi đuôi thành .LOCKED
cuối cùng: tạo file ghi chú (READ_ME_NOW.txt) – chỉ minh họa UX
```

## Cấu trúc file đầu ra
| Offset | Độ dài | Nội dung |
|---|---|---|
| 0 | 2 byte | độ dài khóa mã hóa (RSA-2048 → 256 = `0x0100`) |
| 2 | 256 byte | khóa AES mã hóa bằng RSA |
| 258 | 16 byte | IV |
| 274 | còn lại | ciphertext (bội số 16 byte) |

`scripts/decrypt.py` đảo ngược đúng cấu trúc này; luật YARA `Ransomware_Encrypted_File_INS3201` dựa vào 2 byte đầu `0x0100`.
