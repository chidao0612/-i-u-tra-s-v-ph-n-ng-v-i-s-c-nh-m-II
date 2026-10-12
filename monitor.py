#!/usr/bin/env python3
"""
Real-time Monitoring Engine - INS3201 (Nhom 2)
Phat hien hanh vi doi ten file hang loat (giong ransomware) tu /var/log/audit/audit.log.

Cua so truot T = 5 giay, nguong N = 20 lan rename => CRITICAL ALERT.
Nhan dien rename theo SO HIEU SYSCALL x86_64 (82 rename, 264 renameat, 316 renameat2),
khong phu thuoc truong key= (khi nhieu rule cung khop, auditd co the ghi key dang hex).
Moi su kien (serial) chi duoc dem mot lan.

Dung:
    sudo python3 monitor.py                          # theo doi truc tiep
    sudo python3 monitor.py --replay                 # quet toan bo log hien co roi thoat
    sudo python3 monitor.py --window 5 --threshold 20
"""
import argparse
import os
import re
import sys
import time
from collections import Counter, deque

AUDIT_LOG = "/var/log/audit/audit.log"
ALERT_LOG = "/var/log/ransomware_alert.log"
WINDOW_SIZE = 5      # T (giay)
THRESHOLD = 20       # N (so file)

RENAME_SYSCALLS = {"82", "264", "316"}
ARCH_X86_64 = "c000003e"

RE_MSG = re.compile(r"msg=audit\((\d+(?:\.\d+)?):(\d+)\)")
RE_SYSCALL = re.compile(r"\bsyscall=(\d+)")
RE_ARCH = re.compile(r"\barch=([0-9a-fA-F]+)")
RE_PID = re.compile(r"\bpid=(\d+)")
RE_COMM = re.compile(r'\bcomm="([^"]*)"')


def parse_rename_event(line):
    """Tra ve (timestamp, serial, pid, comm) neu dong la SYSCALL rename x86_64, nguoc lai None."""
    if "type=SYSCALL" not in line:
        return None
    m = RE_MSG.search(line)
    s = RE_SYSCALL.search(line)
    a = RE_ARCH.search(line)
    if not (m and s and a):
        return None
    if a.group(1).lower() != ARCH_X86_64 or s.group(1) not in RENAME_SYSCALLS:
        return None
    pid = RE_PID.search(line)
    comm = RE_COMM.search(line)
    return float(m.group(1)), m.group(2), pid.group(1) if pid else "?", comm.group(1) if comm else "?"


class Detector:
    def __init__(self, window=WINDOW_SIZE, threshold=THRESHOLD):
        self.window = window
        self.threshold = threshold
        self.events = deque()            # (ts, pid, comm)
        self._seen = set()
        self._seen_order = deque(maxlen=8192)

    def feed(self, ev):
        ts, serial, pid, comm = ev
        if serial in self._seen:
            return None
        if len(self._seen_order) == self._seen_order.maxlen:
            self._seen.discard(self._seen_order[0])
        self._seen.add(serial)
        self._seen_order.append(serial)

        self.events.append((ts, pid, comm))
        while self.events and ts - self.events[0][0] > self.window:
            self.events.popleft()

        if len(self.events) >= self.threshold:
            top = Counter((p, c) for _, p, c in self.events).most_common(1)[0]
            alert = {
                "count": len(self.events),
                "window": self.window,
                "pid": top[0][0],
                "comm": top[0][1],
            }
            self.events.clear()
            return alert
        return None


def format_alert(a):
    return (f"[CRITICAL ALERT] POSSIBLE RANSOMWARE DETECTED! "
            f"{a['count']} rename operations in {a['window']} seconds! "
            f"Suspect: pid={a['pid']} comm={a['comm']}")


def emit(alert, alert_log):
    msg = format_alert(alert)
    print("\033[91m" + msg + "\033[0m", flush=True)
    try:
        with open(alert_log, "a") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S %z')} - {msg}\n")
    except PermissionError:
        print(f"[!] Khong ghi duoc {alert_log} (can sudo)", file=sys.stderr)


def follow(path):
    f = open(path, "r", errors="replace")
    f.seek(0, os.SEEK_END)
    inode = os.fstat(f.fileno()).st_ino
    while True:
        line = f.readline()
        if line:
            yield line
            continue
        time.sleep(0.2)
        try:                                  # xu ly log rotation
            if os.stat(path).st_ino != inode:
                f.close()
                f = open(path, "r", errors="replace")
                inode = os.fstat(f.fileno()).st_ino
        except FileNotFoundError:
            pass


def main():
    ap = argparse.ArgumentParser(description="INS3201 ransomware-behaviour monitor")
    ap.add_argument("--log", default=AUDIT_LOG)
    ap.add_argument("--alert-log", default=ALERT_LOG)
    ap.add_argument("--window", type=float, default=WINDOW_SIZE, help="T (giay)")
    ap.add_argument("--threshold", type=int, default=THRESHOLD, help="N (so rename)")
    ap.add_argument("--replay", action="store_true", help="doc toan bo log tu dau roi thoat")
    args = ap.parse_args()

    det = Detector(args.window, args.threshold)
    try:
        if args.replay:
            lines = open(args.log, "r", errors="replace")
            n_alert = 0
            for line in lines:
                ev = parse_rename_event(line)
                if ev and (alert := det.feed(ev)):
                    emit(alert, args.alert_log)
                    n_alert += 1
            print(f"[*] Replay xong: {n_alert} canh bao")
            return 0

        print(f"[*] INS3201 Monitoring Engine running... (N={args.threshold}, T={args.window}s)", flush=True)
        for line in follow(args.log):
            ev = parse_rename_event(line)
            if ev and (alert := det.feed(ev)):
                emit(alert, args.alert_log)
    except PermissionError:
        print(f"[!] Khong doc duoc {args.log}. Chay bang: sudo python3 monitor.py", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n[*] Dung giam sat.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
