"""Run an offline detection regression report for the curated corpus.

The matcher is deliberately small and mirrors the baseline Wazuh field
conditions. It is an offline quality check, not a replacement for Wazuh.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from validate_fixtures import validate

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "test-cases" / "manifest.json"
GUID = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
KNOWN_WRITERS = {"msmpeng.exe", "mpcmdrun.exe", "searchindexer.exe", "searchprotocolhost.exe", "vssvc.exe"}


def executable_is(image: str, names: set[str]) -> bool:
    """Match a process basename exactly at a Windows/Unix path boundary."""
    return bool(re.search(r"(?i)(?:^|[\\/])(?:" + "|".join(re.escape(name) for name in sorted(names)) + r")$", image))


def eventdata(fixture: dict[str, Any]) -> dict[str, Any]:
    return fixture.get("data", {}).get("win", {}).get("eventdata", {})


def event_id(fixture: dict[str, Any]) -> str:
    return str(fixture.get("data", {}).get("win", {}).get("system", {}).get("eventID", ""))


def baseline_match(fixture: dict[str, Any]) -> tuple[str | None, str]:
    data = eventdata(fixture)
    eid = event_id(fixture)
    if eid == "4769" and data.get("ticketEncryptionType") == "0x17":
        return "100100", "Event 4769 with RC4 ticket encryption"
    if eid == "4768" and data.get("preAuthType") == "0" and data.get("ticketEncryptionType") == "0x17":
        return "100101", "Event 4768 with disabled pre-authentication and RC4"
    if eid == "4662" and GUID.lower() in str(data.get("properties", "")).lower():
        return "100102", "Event 4662 contains the replication GUID"
    parent = str(data.get("parentImage", ""))
    image = str(data.get("image", ""))
    if eid == "1" and executable_is(parent, {"wmiprvse.exe", "wsmprovhost.exe"}) and executable_is(image, {"cmd.exe", "powershell.exe", "powershell_ise.exe"}):
        return "100300", "Suspicious remote-shell parent-child lineage"
    if eid == "11" and re.search(r"(?i)(_financial_payroll_2026|_confidential_contract)", str(data.get("targetFilename", ""))):
        return "100200", "Canary filename was touched"
    return None, "No baseline rule condition matched"


def safety_match(fixture: dict[str, Any]) -> tuple[str | None, str]:
    rule_id, reason = baseline_match(fixture)
    data = eventdata(fixture)
    if rule_id == "100200" and not re.search(r"(?i)(?:^|[\\/])!(?:_financial_payroll_2026|_confidential_contract)\.txt$", str(data.get("targetFilename", ""))):
        return None, "Outside canary scope: target is not an exact protected TXT basename"
    return rule_id, reason


def expected_for_profile(fixture: dict[str, Any], profile: str) -> dict[str, Any]:
    profiles = fixture.get("expected_profiles", {})
    if profile not in profiles:
        raise ValueError(f"fixture {fixture.get('case_id')} has no {profile} profile contract")
    return {**fixture["expected"], **profiles[profile]}


def triage_decision(fixture: dict[str, Any], profile: str, rule_id: str | None, reason: str) -> tuple[str, str]:
    data = eventdata(fixture)
    system = fixture.get("data", {}).get("win", {}).get("system", {})
    computer = system.get("computer", data.get("computer", ""))
    if rule_id == "100100" and not all(data.get(key) for key in ("serviceName", "targetUserName", "ipAddress")):
        return "manual_review", "Manual review: Kerberos identity or source context is incomplete"
    if rule_id == "100300" and not data.get("commandLine"):
        return "manual_review", "Manual review: remote shell command line is missing"
    if rule_id == "100300" and not any(data.get(key) for key in ("user", "ipAddress", "sourceIp")):
        return "manual_review", "Manual review: remote shell identity/source context needs correlation"
    if rule_id == "100200" and executable_is(str(data.get("image", "")), KNOWN_WRITERS):
        return "manual_review", "Alert retained: security/indexing executable name requires identity verification"
    # This tuple identifies a synthetic review candidate, not a trusted identity.
    if (profile == "safety" and rule_id == "100102"
            and str(data.get("subjectUserName", "")).upper() == "DC01$"
            and data.get("subjectUserSid") == "S-1-5-18"
            and str(data.get("subjectDomainName", "")).upper() == "LAB"
            and str(computer).upper() in {"DC01", "DC01.LAB.LOCAL"}):
        return "manual_review", "Alert retained: lab DC identity and SYSTEM context; legitimacy remains unverified"
    if reason.startswith("Manual review:"):
        return "manual_review", reason
    return ("investigate" if rule_id else "no_alert"), reason


def load_actual(actual_dir: Path | None, case_id: str) -> dict[str, Any] | None:
    if not actual_dir:
        return None
    path = actual_dir / f"{case_id}.json"
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8-sig"))


def actual_rule(actual: dict[str, Any] | None) -> str | None:
    if not actual:
        return None
    if not bool(actual.get("alert", bool(actual.get("rule_id")))):
        return None
    rule_id = actual.get("rule_id")
    return str(rule_id) if rule_id else "unknown"


def outcome(predicted_rule: str | None, expected: dict[str, Any]) -> str:
    predicted = predicted_rule is not None
    expected_alert = bool(expected.get("alert"))
    if predicted and expected_alert:
        return "TP" if predicted_rule == str(expected.get("rule_id")) else "WRONG_RULE"
    if predicted and not expected_alert:
        return "FP"
    if not predicted and expected_alert:
        return "FN"
    return "TN"


def markdown_report(profile: str, rows: list[dict[str, Any]], actual_count: int) -> str:
    standard = [row for row in rows if row["kind"] in {"positive", "negative"}]
    counts = Counter(row["offline_outcome"] for row in standard)
    tp, fp, fn, tn, wrong_rule = (counts[key] for key in ("TP", "FP", "FN", "TN", "WRONG_RULE"))
    precision = tp / (tp + fp + wrong_rule) if tp + fp + wrong_rule else 0
    recall = tp / (tp + fn + wrong_rule) if tp + fn + wrong_rule else 0
    actual_standard = [row for row in standard if row["actual_outcome"]]
    actual_counts = Counter(row["actual_outcome"] for row in actual_standard)
    actual_tp = actual_counts["TP"]
    actual_fp = actual_counts["FP"]
    actual_fn = actual_counts["FN"]
    actual_tn = actual_counts["TN"]
    actual_wrong_rule = actual_counts["WRONG_RULE"]
    actual_precision = actual_tp / (actual_tp + actual_fp + actual_wrong_rule) if actual_tp + actual_fp + actual_wrong_rule else 0
    actual_recall = actual_tp / (actual_tp + actual_fn + actual_wrong_rule) if actual_tp + actual_fn + actual_wrong_rule else 0
    lines = [
        f"# {profile.title()} Regression Report",
        "",
        "> This is a curated lab corpus. It is not a production SOC metric.",
        "",
        f"- Cases: {len(rows)}",
        f"- Recorded Wazuh result files: {actual_count}",
        f"- TP: {tp} | FP: {fp} | FN: {fn} | TN: {tn}",
        f"- WRONG_RULE: {wrong_rule}",
        f"- Precision: {precision:.1%}",
        f"- Recall: {recall:.1%}",
        f"- Manual-review decisions (all cases): {sum(row['decision'] == 'manual_review' for row in rows)}",
        f"- Outcome contract failures: {sum(row['offline_outcome'] != row['expected_outcome'] for row in rows)}",
        f"- Action contract failures: {sum(not row['action_match'] for row in rows)}",
        "",
        "## Actual Wazuh comparison",
        "",
    ]
    if actual_standard:
        lines += [
            f"- Cases with actual results: {len(actual_standard)} standard cases",
            f"- TP: {actual_tp} | FP: {actual_fp} | FN: {actual_fn} | TN: {actual_tn}",
            f"- WRONG_RULE: {actual_wrong_rule}",
            f"- Precision: {actual_precision:.1%}",
            f"- Recall: {actual_recall:.1%}",
        ]
    else:
        lines.append("- No actual Wazuh result files were supplied. The table will show `-` until `reports/actual/` is populated.")
    lines += [
        "",
        "## Case results",
        "",
        "| Case | Kind | Ground truth | Offline | Actual | Expected / observed outcome | Actual result | Expected / observed action | Reason |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in rows:
        expected = "alert" if row["expected_alert"] else "no alert"
        offline = row["predicted_rule"] or "no alert"
        actual = row["actual_rule"] or ("no alert" if row.get("actual") is not None else "-")
        actual_result = row["actual_outcome"] or "-"
        lines.append(f"| {row['case_id']} | {row['kind']} | {expected} / {row['expected_rule'] or '-'} | {offline} | {actual} | {row['expected_outcome']} / {row['offline_outcome']} | {actual_result} | {row['expected_action']} / {row['decision']} | {row['reason']} |")
    lines += [
        "",
        "## Interpretation",
        "",
        "- Baseline profile models the repository rules, including exact executable boundaries and the historical broad canary filename condition. It is not the live Manager ruleset.",
        "- Safety canary detection uses the same exact protected TXT basename condition as the XML candidate. Python triage retains alerts with incomplete context or security/indexing executable names for manual review; those review decisions are not XML conditions.",
        "- The DC review candidate retains rule 100102. Manual review is not suppression and does not improve detection precision or recall.",
        "- Non-TXT targets, including shortcuts at any path, are outside the safety canary scope. An executable name never suppresses an alert.",
        "- Explicit profile contracts allow the recorded baseline false positives without relabeling them as true negatives. Unexpected outcomes, missing expected detections, wrong rules and action mismatches fail the runner.",
        "- WRONG_RULE stays visible as a separate count and contributes to both precision and recall denominators as a wrong alert and missed expected-rule detection.",
        "- Edge cases are useful for manual-review decisions and are not mixed into the precision/recall denominator.",
        "- Actual Wazuh results require the exact fixture to pass through a Windows Agent and be checked in Discover; pasted JSON only checks the generic decoder.",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", choices=("baseline", "safety"), default="baseline")
    parser.add_argument("--actual-dir", type=Path, default=ROOT / "reports" / "actual")
    args = parser.parse_args(argv)

    validation_errors, cases = validate(ROOT, MANIFEST)
    if validation_errors:
        print("FIXTURE VALIDATION FAILED")
        for error in validation_errors:
            print(f"- {error}")
        return 1
    rows: list[dict[str, Any]] = []
    for item in cases:
        fixture = json.loads((ROOT / item["fixture"]).read_text(encoding="utf-8-sig"))
        matcher = baseline_match if args.profile == "baseline" else safety_match
        predicted_rule, reason = matcher(fixture)
        decision, reason = triage_decision(fixture, args.profile, predicted_rule, reason)
        expected = expected_for_profile(fixture, args.profile)
        actual = load_actual(args.actual_dir, item["case_id"])
        expected_outcome = expected.get("outcome")
        offline_outcome = outcome(predicted_rule, expected)
        rows.append({
            "case_id": item["case_id"],
            "kind": item["kind"],
            "expected_alert": bool(expected.get("alert")),
            "expected_rule": expected.get("rule_id"),
            "expected_action": expected.get("action"),
            "expected_outcome": expected_outcome,
            "expected_offline_rule": expected.get("predicted_rule"),
            "predicted_rule": predicted_rule,
            "reason": reason,
            "decision": decision,
            "offline_outcome": offline_outcome,
            "action_match": decision == expected.get("action"),
            "actual": actual,
            "actual_rule": actual_rule(actual),
            "actual_outcome": outcome(actual_rule(actual), expected) if actual else None,
        })

    report_name = f"{args.profile}-report.md"
    report_path = ROOT / "reports" / report_name
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(markdown_report(args.profile, rows, sum(row["actual"] is not None for row in rows)), encoding="utf-8")
    json_path = ROOT / "reports" / f"{args.profile}-results.json"
    json_path.write_text(json.dumps({"profile": args.profile, "rows": rows}, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {report_path}")
    print(f"wrote {json_path}")
    failures = []
    for row in rows:
        if row["expected_outcome"] != row["offline_outcome"]:
            failures.append(f"{row['case_id']}: expected {row['expected_outcome']} got {row['offline_outcome']}")
        if row["predicted_rule"] != row["expected_offline_rule"]:
            failures.append(f"{row['case_id']}: expected offline rule {row['expected_offline_rule']} got {row['predicted_rule']}")
        if not row["action_match"]:
            failures.append(f"{row['case_id']}: expected action {row['expected_action']} got {row['decision']}")
        if row["offline_outcome"] in {"FN", "WRONG_RULE"}:
            failures.append(f"{row['case_id']}: {row['offline_outcome']}")
        if row["actual_outcome"] in {"FN", "WRONG_RULE"}:
            failures.append(f"{row['case_id']}: actual {row['actual_outcome']}")
        if row["actual_outcome"] == "FP" and row["expected_outcome"] != "FP":
            failures.append(f"{row['case_id']}: unexpected actual FP")
        if row["actual_outcome"] == "FP" and row["actual_rule"] != row["expected_offline_rule"]:
            failures.append(f"{row['case_id']}: actual FP used an unexpected rule {row['actual_rule']}")
    if failures:
        print("REGRESSION FAILED")
        for failure in failures:
            print(f"- {failure}")
        return 1
    print("REGRESSION PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
