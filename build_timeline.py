#!/usr/bin/env python3
"""
Dung bang Incident Timeline (UTC+7) tu audit.log + ransomware_alert.log.
Dung:  sudo python3 scripts/build_timeline.py > docs/INCIDENT_TIMELINE_RESULT.md
Tuy chon: --gap 5 (giay tach 2 dot rename)  --min-count 5 (bo qua dot nho)
"""
import argparse
import os
import re
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from monitor import AUDIT_LOG, ALERT_LOG, THRESHOLD, parse_rename_event  # noqa: E402

TZ7 = timezone(timedelta(hours=7))
RE_ALERT = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?: ([+-]\d{4}))? - (.*)$")


def load_events(path):
    seen, events = set(), []
    with open(path, "r", errors="replace") as f:
        for line in f:
            ev = parse_rename_event(line)
            if ev and ev[1] not in seen:
                seen.add(ev[1])
                events.append(ev)
    return sorted(events)


def group_bursts(events, gap):
    bursts, cur = [], []
    for ev in events:
        if cur and ev[0] - cur[-1][0] > gap:
            bursts.append(cur)
            cur = []
        cur.append(ev)
    if cur:
        bursts.append(cur)
    return bursts


def fmt(ts):
    return datetime.fromtimestamp(ts, TZ7).strftime("%H:%M:%S")


def load_alerts(path):
    rows = []
    if not os.path.exists(path):
        return rows
    with open(path, "r", errors="replace") as f:
        for line in f:
            m = RE_ALERT.match(line.strip())
            if not m:
                continue
            base = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
            tz = datetime.strptime(m.group(2), "%z").tzinfo if m.group(2) else TZ7
            dt = base.replace(tzinfo=tz)
            rows.append((dt.timestamp(), m.group(3)))
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--audit-log", default=AUDIT_LOG)
    ap.add_argument("--alert-log", default=ALERT_LOG)
    ap.add_argument("--gap", type=float, default=5.0)
    ap.add_argument("--min-count", type=int, default=5)
    args = ap.parse_args()

    rows = []
    for b in group_bursts(load_events(args.audit_log), args.gap):
        if len(b) < args.min_count:
            continue
        start, end = b[0][0], b[-1][0]
        top = Counter((p, c) for _, _, p, c in b).most_common(1)[0][0]
        dur = max(end - start, 0.001)
        level = "Cao/Nghiêm trọng" if len(b) >= THRESHOLD else "Trung bình"
        rows.append((start, f"{top[1]} (pid {top[0]})", "Bắt đầu đổi tên file hàng loạt", "Trung bình"))
        rows.append((end, "sys_rename (auditd)",
                     f"{len(b)} lời gọi rename trong {dur:.1f} giây (~{len(b)/dur:.0f}/giây)", level))
    for ts, msg in load_alerts(args.alert_log):
        rows.append((ts, "monitor.py (Alert)", msg, "Xử lý ngay"))

    rows.sort(key=lambda r: r[0])
    print("| Thời gian (UTC+7) | Tiến trình / Syscall | Hành vi ghi nhận | Mức rủi ro |")
    print("|---|---|---|---|")
    if not rows:
        print("| _(không có dữ liệu)_ | | | |")
    for ts, proc, what, risk in rows:
        print(f"| {fmt(ts)} | {proc} | {what} | {risk} |")


if __name__ == "__main__":
    main()
