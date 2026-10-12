#!/usr/bin/env python3
"""Kiem tra nhanh cau truc STIX 2.1 va CACAO 1.0 (khong thay the validator chinh thuc).
Dung: python3 scripts/validate_json.py intel/threat_indicator.json playbook/ir_playbook.json"""
import json
import re
import sys

UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
TS = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$"
STEP_TYPES = {"start", "end", "single", "playbook", "parallel", "if-condition", "while-condition", "switch-condition"}


def check_stix(d):
    errs = []
    if d.get("type") != "bundle" or not re.fullmatch(rf"bundle--{UUID}", d.get("id", "")):
        errs.append("bundle: type/id sai")
    if "spec_version" in d:
        errs.append("bundle: STIX 2.1 khong dung spec_version o cap bundle")
    for o in d.get("objects", []):
        t = o.get("type", "?")
        if o.get("spec_version") != "2.1":
            errs.append(f"{t}: thieu spec_version 2.1")
        if not re.fullmatch(rf"{t}--{UUID}", o.get("id", "")):
            errs.append(f"{t}: id khong hop le")
        for k in ("created", "modified"):
            if not re.match(TS, o.get(k, "")):
                errs.append(f"{t}: {k} sai dinh dang")
        if t == "indicator":
            for k in ("pattern", "pattern_type", "valid_from"):
                if k not in o:
                    errs.append(f"indicator: thieu {k}")
    return errs


def check_cacao(d):
    errs = []
    for k in ("type", "spec_version", "id", "name", "playbook_types", "created_by", "created", "modified", "workflow_start", "workflow"):
        if k not in d:
            errs.append(f"playbook: thieu {k}")
    if d.get("spec_version") != "1.0":
        errs.append("playbook: spec_version phai la '1.0'")
    wf = d.get("workflow", {})
    if d.get("workflow_start") not in wf:
        errs.append("workflow_start khong tro toi step ton tai")
    elif wf[d["workflow_start"]].get("type") != "start":
        errs.append("workflow_start phai la step type 'start'")
    if not any(s.get("type") == "end" for s in wf.values()):
        errs.append("thieu step 'end'")
    for sid, s in wf.items():
        if not re.fullmatch(rf"step--{UUID}", sid):
            errs.append(f"{sid}: id step khong hop le")
        if s.get("type") not in STEP_TYPES:
            errs.append(f"{sid}: type '{s.get('type')}' khong hop le")
        for f in ("on_completion", "on_true", "on_false"):
            if f in s and s[f] not in wf:
                errs.append(f"{sid}: {f} tro toi step khong ton tai")
        if s.get("type") == "single" and not s.get("commands"):
            errs.append(f"{sid}: step single can commands")
    return errs


def main():
    bad = 0
    for p in sys.argv[1:]:
        d = json.load(open(p, encoding="utf-8"))
        errs = check_stix(d) if d.get("type") == "bundle" else check_cacao(d) if d.get("type") == "playbook" else ["khong nhan dien duoc loai"]
        print(f"{'OK ' if not errs else 'LOI'} {p}")
        for e in errs:
            print("   -", e)
        bad += bool(errs)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
