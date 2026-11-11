#!/usr/bin/env python3
"""Build and verify the deterministic Pb-22 Suricata feed."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "feed" / "source" / "pb22.rules"
OUTPUT = ROOT / "feed" / "suricata" / "pb22.rules"
POLICY = ROOT / "feed" / "sid-allocation.json"
LICENSE = ROOT / "feed" / "LICENSE"
CHECKSUMS = ROOT / "feed" / "SHA256SUMS"
SID_RE = re.compile(r"\bsid\s*:\s*(\d+)\s*;")
REV_RE = re.compile(r"\brev\s*:\s*(\d+)\s*;")
MSG_RE = re.compile(r'\bmsg\s*:\s*"([^"]+)"\s*;')


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def render() -> tuple[bytes, bytes, list[dict[str, object]]]:
    policy = json.loads(POLICY.read_text(encoding="utf-8"))
    lines = []
    records = []
    seen = set()
    for number, raw in enumerate(SOURCE.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "\n" in line or "\r" in line or not line.startswith(("alert ", "drop ", "reject ", "pass ")):
            raise SystemExit(f"invalid logical rule at source line {number}")
        sid_match = SID_RE.search(line)
        rev_match = REV_RE.search(line)
        msg_match = MSG_RE.search(line)
        if not (sid_match and rev_match and msg_match and line.endswith(")")):
            raise SystemExit(f"missing msg/sid/rev/closing parenthesis at source line {number}")
        sid = int(sid_match.group(1))
        if sid in seen:
            raise SystemExit(f"duplicate SID {sid}")
        if not int(policy["sid_start"]) <= sid <= int(policy["sid_end"]):
            raise SystemExit(f"SID {sid} is outside the declared allocation")
        seen.add(sid)
        lines.append(line)
        records.append({"sid": sid, "rev": int(rev_match.group(1)), "msg": msg_match.group(1)})
    if len(lines) != int(policy["rule_count"]):
        raise SystemExit(f"expected {policy['rule_count']} rules, found {len(lines)}")

    header = [
        "# Pb-22 Open Suricata Rules",
        "# License: BSD-3-Clause; see ../LICENSE",
        "# Source: https://github.com/Pb-22/Network_Detections",
        f"# Status: {policy['status']}",
        "# Temporary local-use SIDs must be replaced after public SID allocation.",
        "",
    ]
    output = ("\n".join(header + lines) + "\n").encode("utf-8")
    license_bytes = LICENSE.read_bytes()
    checksum_text = (
        f"{sha256(license_bytes)}  feed/LICENSE\n"
        f"{sha256(output)}  feed/suricata/pb22.rules\n"
    ).encode("utf-8")
    return output, checksum_text, records


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    output, checksums, records = render()
    if args.check:
        mismatches = []
        if not OUTPUT.exists() or OUTPUT.read_bytes() != output:
            mismatches.append(str(OUTPUT.relative_to(ROOT)))
        if not CHECKSUMS.exists() or CHECKSUMS.read_bytes() != checksums:
            mismatches.append(str(CHECKSUMS.relative_to(ROOT)))
        if mismatches:
            raise SystemExit("generated files are stale: " + ", ".join(mismatches))
    else:
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_bytes(output)
        CHECKSUMS.write_bytes(checksums)
    print(json.dumps({"rules": records, "feed_sha256": sha256(output)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
