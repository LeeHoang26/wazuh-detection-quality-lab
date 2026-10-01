"""Validate the curated fixture corpus without third-party dependencies."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "test-cases" / "manifest.json"
SECRET_PATTERNS = [
    re.compile(r"(?i)(telegram[_ -]?bot[_ -]?token|domain[_ -]?pass|password)\s*[:=]"),
    re.compile(r"(?i)BEGIN (RSA|OPENSSH|PRIVATE) KEY"),
]


def fail(message: str, errors: list[str]) -> None:
    errors.append(message)


def main() -> int:
    errors: list[str] = []
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8-sig"))
    cases = manifest.get("cases", [])
    seen: set[str] = set()

    for item in cases:
        case_id = item.get("case_id")
        if not case_id:
            fail("manifest case is missing case_id", errors)
            continue
        if case_id in seen:
            fail(f"duplicate case_id: {case_id}", errors)
        seen.add(case_id)

        fixture_path = ROOT / item["fixture"]
        if not fixture_path.exists():
            fail(f"missing fixture: {item['fixture']}", errors)
            continue

        try:
            fixture = json.loads(fixture_path.read_text(encoding="utf-8-sig"))
        except json.JSONDecodeError as exc:
            fail(f"invalid JSON in {fixture_path}: {exc}", errors)
            continue

        for required in ("case_id", "kind", "detection_id", "data", "expected"):
            if required not in fixture:
                fail(f"{case_id}: missing fixture field {required}", errors)

        if fixture.get("case_id") != case_id:
            fail(f"{case_id}: fixture case_id does not match manifest", errors)
        if fixture.get("kind") not in {"positive", "negative", "edge"}:
            fail(f"{case_id}: kind must be positive, negative, or edge", errors)
        expected = fixture.get("expected", {})
        if not isinstance(expected.get("alert"), bool):
            fail(f"{case_id}: expected.alert must be boolean", errors)
        if expected.get("alert") and not expected.get("rule_id"):
            fail(f"{case_id}: alerting fixture needs expected.rule_id", errors)
        if not expected.get("alert") and expected.get("rule_id") is not None:
            fail(f"{case_id}: non-alerting fixture must have rule_id null", errors)

        raw = fixture_path.read_text(encoding="utf-8-sig")
        for pattern in SECRET_PATTERNS:
            if pattern.search(raw):
                fail(f"{case_id}: possible secret pattern found", errors)

    expected_counts = {"positive": 5, "negative": 5, "edge": 5}
    actual_counts = {kind: sum(1 for item in cases if item.get("kind") == kind) for kind in expected_counts}
    for kind, expected_count in expected_counts.items():
        if actual_counts[kind] != expected_count:
            fail(f"expected {expected_count} {kind} cases, found {actual_counts[kind]}", errors)

    if errors:
        print("FIXTURE VALIDATION FAILED")
        for error in errors:
            print(f"- {error}")
        return 1

    print(f"FIXTURE VALIDATION PASSED: {len(cases)} cases")
    print(f"positive={actual_counts['positive']} negative={actual_counts['negative']} edge={actual_counts['edge']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
