#!/usr/bin/env python3
"""Verify the committed Pb-22 feed acceptance receipt."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FEED = ROOT / "feed" / "suricata" / "pb22.rules"
RECEIPT = ROOT / "feed" / "validation-results.json"
EXPECTED = {
    "redflick": {},
    "sliver": {"9955000": 4},
    "cav3rn": {"9955001": 1, "9955002": 1, "9955003": 1},
    "wmi-authentic": {"9955009": 1},
    "wmi-combined": {"9955009": 7},
    "wmi-combined-autofp": {"9955009": 7},
    "wmi-recovery-positive": {"9955009": 1, "9955010": 1},
    "wmi-recovery-positive-autofp": {"9955009": 1, "9955010": 1},
    "wmi-recovery-split-negative": {},
    "wmi-recovery-wrong-interface": {"9955009": 1, "9955010": 1},
}

receipt = json.loads(RECEIPT.read_text(encoding="utf-8"))
actual_hash = hashlib.sha256(FEED.read_bytes()).hexdigest()
if receipt.get("rule_sha256") != actual_hash:
    raise SystemExit("validation receipt does not match the generated feed")
seen = set()
for run in receipt.get("runs", []):
    name = run.get("name")
    if name not in EXPECTED:
        raise SystemExit(f"unexpected validation run: {name}")
    seen.add(name)
    if run.get("ok") is not True or run.get("diagnostics") != "(none)":
        raise SystemExit(f"validation run is not clean: {name}")
    if run.get("rules_enabled_count") != 6:
        raise SystemExit(f"wrong enabled rule count: {name}")
    if run.get("sid_counts") != EXPECTED[name]:
        raise SystemExit(f"unexpected SID counts for {name}: {run.get('sid_counts')}")
if seen != set(EXPECTED):
    raise SystemExit(f"missing validation runs: {sorted(set(EXPECTED) - seen)}")
print(f"validated receipt for {len(EXPECTED)} PCAPs and feed {actual_hash}")
