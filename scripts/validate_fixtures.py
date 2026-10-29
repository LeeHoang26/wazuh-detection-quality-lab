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


def validate(root: Path = ROOT, manifest_path: Path | None = None) -> tuple[list[str], list[dict]]:
    errors: list[str] = []
    manifest_path = manifest_path or root / "test-cases" / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError) as exc:
        return [f"cannot read manifest: {exc}"], []
    if not isinstance(manifest, dict) or not isinstance(manifest.get("cases"), list):
        return ["manifest must be an object with a cases list"], []
    if set(manifest) != {"schema_version", "description", "cases"} or manifest.get("schema_version") != 2:
        fail("manifest must use schema_version 2 and declared fields only", errors)
    cases = manifest.get("cases", [])
    seen: set[str] = set()
    listed: set[Path] = set()

    for item in cases:
        if not isinstance(item, dict):
            fail("manifest case must be an object", errors)
            continue
        if set(item) != {"case_id", "fixture", "kind", "detection_id", "expected", "expected_profiles"}:
            fail("manifest case has missing or unknown fields", errors)
        case_id = item.get("case_id")
        if not isinstance(case_id, str) or not case_id:
            fail("manifest case is missing case_id", errors)
            continue
        if case_id in seen:
            fail(f"duplicate case_id: {case_id}", errors)
        seen.add(case_id)

        if not isinstance(item.get("fixture"), str):
            fail(f"{case_id}: fixture path must be a string", errors)
            continue
        fixture_path = (root / item["fixture"]).resolve()
        if not fixture_path.is_relative_to((root / "fixtures").resolve()):
            fail(f"{case_id}: fixture path must stay inside fixtures/", errors)
            continue
        if fixture_path in listed:
            fail(f"{case_id}: duplicate fixture path", errors)
        listed.add(fixture_path)
        if not fixture_path.exists():
            fail(f"missing fixture: {item['fixture']}", errors)
            continue

        try:
            fixture = json.loads(fixture_path.read_text(encoding="utf-8-sig"))
        except (OSError, ValueError) as exc:
            fail(f"invalid JSON in {fixture_path}: {exc}", errors)
            continue

        if not isinstance(fixture, dict):
            fail(f"{case_id}: fixture must be an object", errors)
            continue
        for required in ("case_id", "kind", "detection_id", "data", "expected", "expected_profiles"):
            if required not in fixture:
                fail(f"{case_id}: missing fixture field {required}", errors)

        for field in ("case_id", "kind", "detection_id", "expected", "expected_profiles"):
            if fixture.get(field) != item.get(field):
                fail(f"{case_id}: fixture {field} does not match manifest", errors)
        if fixture.get("kind") not in {"positive", "negative", "edge"}:
            fail(f"{case_id}: kind must be positive, negative, or edge", errors)
        expected = fixture.get("expected", {})
        if not isinstance(expected, dict):
            fail(f"{case_id}: expected must be an object", errors)
            continue
        if not isinstance(expected.get("alert"), bool):
            fail(f"{case_id}: expected.alert must be boolean", errors)
        if expected.get("alert") and not expected.get("rule_id"):
            fail(f"{case_id}: alerting fixture needs expected.rule_id", errors)
        if not expected.get("alert") and expected.get("rule_id") is not None:
            fail(f"{case_id}: non-alerting fixture must have rule_id null", errors)
        if expected.get("alert") and fixture.get("detection_id") != f"DET-{expected.get('rule_id')}":
            fail(f"{case_id}: expected rule does not match detection_id", errors)
        profiles = fixture.get("expected_profiles")
        if not isinstance(profiles, dict) or set(profiles) != {"baseline", "safety"}:
            fail(f"{case_id}: expected_profiles must declare baseline and safety", errors)
            continue
        for profile, contract in profiles.items():
            if not isinstance(contract, dict) or set(contract) != {"outcome", "action", "predicted_rule"}:
                fail(f"{case_id}: invalid {profile} contract fields", errors)
                continue
            valid_outcomes = {"TP"} if expected.get("alert") else {"TN", "FP"}
            if contract.get("outcome") not in valid_outcomes:
                fail(f"{case_id}: invalid {profile} outcome contract", errors)
            if contract.get("action") not in {"investigate", "manual_review", "no_alert"}:
                fail(f"{case_id}: invalid {profile} action contract", errors)
            if (contract.get("outcome") == "TN") != (contract.get("action") == "no_alert"):
                fail(f"{case_id}: {profile} outcome and action disagree", errors)
            contract_rule = contract.get("predicted_rule")
            if contract.get("outcome") == "TN":
                if contract_rule is not None:
                    fail(f"{case_id}: {profile} TN contract must have predicted_rule null", errors)
            elif fixture.get("detection_id") != f"DET-{contract_rule}":
                fail(f"{case_id}: {profile} predicted_rule does not match detection_id", errors)

        raw = fixture_path.read_text(encoding="utf-8-sig")
        for pattern in SECRET_PATTERNS:
            if pattern.search(raw):
                fail(f"{case_id}: possible secret pattern found", errors)

    for orphan in sorted((root / "fixtures").rglob("*.json")):
        if orphan.resolve() not in listed:
            fail(f"orphan fixture: {orphan.relative_to(root)}", errors)
    expected_counts = {"positive": 5, "negative": 7, "edge": 5}
    actual_counts = {kind: sum(1 for item in cases if isinstance(item, dict) and item.get("kind") == kind) for kind in expected_counts}
    for kind, expected_count in expected_counts.items():
        if actual_counts[kind] != expected_count:
            fail(f"expected {expected_count} {kind} cases, found {actual_counts[kind]}", errors)

    return errors, cases


def main() -> int:
    errors, cases = validate()
    if errors:
        print("FIXTURE VALIDATION FAILED")
        for error in errors:
            print(f"- {error}")
        return 1

    print(f"FIXTURE VALIDATION PASSED: {len(cases)} cases")
    actual_counts = {kind: sum(item["kind"] == kind for item in cases) for kind in ("positive", "negative", "edge")}
    print(f"positive={actual_counts['positive']} negative={actual_counts['negative']} edge={actual_counts['edge']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
