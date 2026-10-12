#!/usr/bin/env python3
"""
Sinh cap khoa RSA-2048 cho lab INS3201 (de test decrypt.py).
  - Khoa rieng: /home/ubuntu/rsa_private_key.pem  (quyen 0600, KHONG commit len git)
  - Khoa cong khai: /home/ubuntu/rsa_public_key.pem
Khoa cong khai nay la khoa ma bo mau ma hoa duoc kiem soat (do giang vien / thanh vien phu trach cap) phai dung.
"""
import argparse
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--private", default="/home/ubuntu/rsa_private_key.pem")
    ap.add_argument("--public", default="/home/ubuntu/rsa_public_key.pem")
    args = ap.parse_args()

    for p in (args.private, args.public):
        if os.path.exists(p):
            raise SystemExit(f"[!] {p} da ton tai - khong ghi de. Xoa thu cong neu that su muon tao lai.")

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    fd = os.open(args.private, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))

    with open(args.public, "wb") as f:
        f.write(key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo))

    print(f"[+] Khoa rieng : {args.private} (0600)")
    print(f"[+] Khoa cong khai: {args.public}")


if __name__ == "__main__":
    main()
