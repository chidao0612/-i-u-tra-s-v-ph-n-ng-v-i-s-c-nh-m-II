#!/usr/bin/env python3
"""
Data Recovery Script - INS3201 (Nhom 2)
Dao nguoc ma hoa lai AES-256-CBC + RSA-2048 (OAEP-SHA256) khi co khoa rieng RSA.

Cau truc file .LOCKED:
    [do dai khoa ma hoa (2 byte, big-endian)][khoa AES ma hoa bang RSA][IV (16 byte)][ciphertext]

Dung:
    python3 decrypt.py                       # giai ma /home/ubuntu/data/
    python3 decrypt.py --dry-run             # chi kiem tra, KHONG ghi file
    python3 decrypt.py --dir X --key K.pem   # chi dinh thu muc / khoa rieng
"""
import argparse
import os
import sys

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_private_key

DEFAULT_DIR = "/home/ubuntu/data/"
DEFAULT_KEY = "/home/ubuntu/rsa_private_key.pem"
EXTENSION = ".LOCKED"


def decrypt_bytes(data, rsa_private_key):
    """Tra ve plaintext tu noi dung mot file .LOCKED."""
    if len(data) < 2:
        raise ValueError("file qua ngan")
    key_len = int.from_bytes(data[:2], byteorder="big")
    if key_len == 0 or len(data) < 2 + key_len + 16:
        raise ValueError("cau truc file khong hop le")

    encrypted_key = data[2:2 + key_len]
    iv = data[2 + key_len:2 + key_len + 16]
    ciphertext = data[2 + key_len + 16:]

    aes_key = rsa_private_key.decrypt(
        encrypted_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    decryptor = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def decrypt_file(path, rsa_private_key, dry_run=False, keep=False):
    with open(path, "rb") as f:
        data = f.read()
    plaintext = decrypt_bytes(data, rsa_private_key)
    if dry_run:
        return len(plaintext)

    original = path[:-len(EXTENSION)]
    tmp = original + ".tmp_recover"
    with open(tmp, "wb") as f:           # ghi file tam roi doi ten: tranh mat du lieu neu loi giua chung
        f.write(plaintext)
    os.replace(tmp, original)
    if not keep:
        os.remove(path)
    return len(plaintext)


def main():
    ap = argparse.ArgumentParser(description="INS3201 data recovery (AES-256-CBC + RSA-2048)")
    ap.add_argument("--dir", default=DEFAULT_DIR, help="thu muc can khoi phuc")
    ap.add_argument("--key", default=DEFAULT_KEY, help="duong dan khoa rieng RSA (PEM)")
    ap.add_argument("--dry-run", action="store_true", help="chi kiem tra giai ma duoc hay khong")
    ap.add_argument("--keep", action="store_true", help="giu lai file .LOCKED sau khi giai ma")
    args = ap.parse_args()

    try:
        with open(args.key, "rb") as kf:
            rsa_private_key = load_pem_private_key(kf.read(), password=None)
    except (OSError, ValueError) as e:
        print(f"[ERROR] Khong doc duoc khoa rieng '{args.key}': {e}")
        return 2

    ok = fail = 0
    for root, _dirs, files in os.walk(args.dir):
        for name in files:
            if not name.endswith(EXTENSION):
                continue
            path = os.path.join(root, name)
            try:
                size = decrypt_file(path, rsa_private_key, args.dry_run, args.keep)
                tag = "DRY-RUN OK" if args.dry_run else "OK"
                print(f"[{tag}] {name} ({size} bytes)")
                ok += 1
            except Exception as e:  # noqa: BLE001
                print(f"[ERROR] Failed to decrypt {name}: {e}")
                fail += 1

    print(f"[*] Hoan tat: {ok} thanh cong, {fail} loi")
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
