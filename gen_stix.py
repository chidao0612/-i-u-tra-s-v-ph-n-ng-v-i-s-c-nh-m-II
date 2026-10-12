#!/usr/bin/env python3
"""
Sinh goi STIX 2.1 (intel/threat_indicator.json) voi hash SHA-256 THAT.
Dung:  python3 scripts/gen_stix.py [file_tinh_hash ...]
Mac dinh: tinh hash cua scripts/simulate_events.py va detection/ransomware_detection.yar.
Chay lai sau moi lan sua file de hash khop.
"""
import hashlib
import json
import os
import sys
import uuid
from datetime import datetime, timezone

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
OUT = os.path.join(ROOT, "intel", "threat_indicator.json")


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    files = sys.argv[1:] or [
        os.path.join(ROOT, "scripts", "simulate_events.py"),
        os.path.join(ROOT, "detection", "ransomware_detection.yar"),
    ]
    ts = now()
    identity_id = f"identity--{uuid.uuid4()}"
    objects = [{
        "type": "identity", "spec_version": "2.1", "id": identity_id,
        "created": ts, "modified": ts,
        "name": "Nhom 2 - INS3201", "identity_class": "group",
    }]
    for p in files:
        digest = sha256(p)
        name = os.path.basename(p)
        objects.append({
            "type": "indicator", "spec_version": "2.1", "id": f"indicator--{uuid.uuid4()}",
            "created": ts, "modified": ts, "created_by_ref": identity_id,
            "name": f"INS3201 artifact hash: {name}",
            "description": f"SHA-256 cua {name} trong lab INS3201 (moi truong co lap).",
            "indicator_types": ["malicious-activity"],
            "pattern": f"[file:hashes.'SHA-256' = '{digest}']",
            "pattern_type": "stix",
            "valid_from": ts,
        })
    yar = os.path.join(ROOT, "detection", "ransomware_detection.yar")
    with open(yar, encoding="utf-8") as f:
        objects.append({
            "type": "indicator", "spec_version": "2.1", "id": f"indicator--{uuid.uuid4()}",
            "created": ts, "modified": ts, "created_by_ref": identity_id,
            "name": "INS3201 YARA rules", "indicator_types": ["malicious-activity"],
            "pattern": f.read(), "pattern_type": "yara", "valid_from": ts,
        })

    bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(bundle, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print(f"[+] Da ghi {OUT} ({len(objects)} objects)")


if __name__ == "__main__":
    main()
