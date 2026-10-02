"""Record a result verified after the exact fixture passes through an Agent."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "test-cases" / "manifest.json"
OUTPUT = ROOT / "reports" / "actual"


def main() -> int:
    parser = argparse.ArgumentParser(description="Save an Agent-verified Wazuh result for one exact fixture.")
    parser.add_argument("--case-id", required=True)
    state = parser.add_mutually_exclusive_group(required=True)
    state.add_argument("--alert", action="store_true")
    state.add_argument("--no-alert", action="store_true")
    parser.add_argument("--rule-id")
    parser.add_argument("--level", type=int)
    parser.add_argument("--notes", default="")
    args = parser.parse_args()

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8-sig"))
    valid_ids = {item["case_id"] for item in manifest["cases"]}
    if args.case_id not in valid_ids:
        parser.error(f"unknown case id: {args.case_id}")
    if args.alert and not args.rule_id:
        parser.error("--alert requires --rule-id")
    if args.no_alert and args.rule_id:
        parser.error("--no-alert cannot be combined with --rule-id")

    result = {
        "case_id": args.case_id,
        "alert": bool(args.alert),
        "rule_id": args.rule_id,
        "level": args.level,
        "notes": args.notes,
    }
    OUTPUT.mkdir(parents=True, exist_ok=True)
    path = OUTPUT / f"{args.case_id}.json"
    path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
