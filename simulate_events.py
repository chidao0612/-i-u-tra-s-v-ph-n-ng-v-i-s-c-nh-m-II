#!/usr/bin/env python3
"""
Safe Detection Test Harness - INS3201 (Nhom 2)
Doi ten hang loat file trong thu muc muc tieu de kich hoat luat auditd 'mass_rename'
va monitor.py. KHONG doc / ghi de / ma hoa / xoa noi dung file. Hoan tac day du bang --undo.

Dung:
    python3 simulate_events.py            # doi ten  file -> file.SIMTEST
    python3 simulate_events.py --undo     # khoi phuc ten goc
"""
import argparse
import os
import sys
import time

TARGET_DIR = "/home/ubuntu/data/"
MARK_EXT = ".SIMTEST"
FORBIDDEN = {"/", "/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/boot", "/var", "/root", "/home", "/proc", "/sys", "/dev"}


def _check_dir(path):
    real = os.path.realpath(path)
    if real in FORBIDDEN or not os.path.isdir(real):
        raise SystemExit(f"[!] Thu muc khong hop le hoac bi cam: {real}")
    return real


def simulate(target, delay):
    names = [n for n in sorted(os.listdir(target))
             if os.path.isfile(os.path.join(target, n)) and not n.endswith(MARK_EXT)]
    print(f"[*] Renaming {len(names)} files in {target} to trigger detection...")
    for name in names:
        src = os.path.join(target, name)
        os.rename(src, src + MARK_EXT)
        time.sleep(delay)          # 0.05s ~ 20 rename/giay, khop nguong N=20 / T=5s
    print("[*] Done. Check monitor.py output and /var/log/ransomware_alert.log")


def undo(target):
    names = [n for n in sorted(os.listdir(target)) if n.endswith(MARK_EXT)]
    print(f"[*] Restoring {len(names)} original filenames...")
    for name in names:
        src = os.path.join(target, name)
        dst = src[:-len(MARK_EXT)]
        if os.path.exists(dst):
            print(f"[!] Bo qua {name}: file goc da ton tai")
            continue
        os.rename(src, dst)
    print("[*] Restored.")


def main():
    ap = argparse.ArgumentParser(description="INS3201 safe rename-burst simulator")
    ap.add_argument("--undo", action="store_true", help="hoan tac")
    ap.add_argument("--dir", default=TARGET_DIR, help="thu muc muc tieu")
    ap.add_argument("--delay", type=float, default=0.05, help="giay giua 2 lan rename")
    args = ap.parse_args()

    target = _check_dir(args.dir)
    if args.undo:
        undo(target)
    else:
        simulate(target, args.delay)


if __name__ == "__main__":
    sys.exit(main())
