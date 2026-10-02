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
from pathlib import Path, PureWindowsPath
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "test-cases" / "manifest.json"
GUID = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"


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
    if eid == "1" and re.search(r"(?i)(wmiprvse|wsmprovhost)\.exe", parent) and re.search(r"(?i)(cmd|powershell|powershell_ise)\.exe", image):
        return "100300", "Suspicious remote-shell parent-child lineage"
    if eid == "11" and re.search(r"(?i)(_financial_payroll_2026|_confidential_contract)", str(data.get("targetFilename", ""))):
        return "100200", "Canary filename was touched"
    return None, "No baseline rule condition matched"


def safety_match(fixture: dict[str, Any]) -> tuple[str | None, str]:
    rule_id, reason = baseline_match(fixture)
    data = eventdata(fixture)
    if rule_id == "100100" and not all(data.get(key) for key in ("serviceName", "targetUserName", "ipAddress")):
        return None, "Manual review: Kerberos identity or source context is incomplete"
    if rule_id == "100300" and not data.get("commandLine"):
        return None, "Manual review: remote shell command line is missing"
    target = PureWindowsPath(str(data.get("targetFilename", "")))
    if (rule_id == "100200"
            and target.name.casefold() == "!_financial_payroll_2026.txt.lnk"
            and target.parent.match(r"C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent")):
        return None, "Outside canary scope: Recent-items shortcut, not the protected TXT file"
    if rule_id == "100200" and re.search(r"(?i)(MsMpEng|MpCmdRun|SearchIndexer|SearchProtocolHost|vssvc)\.exe", str(data.get("image", ""))):
        return None, "Suppressed: known-good security or indexing process touched the canary"
    return rule_id, reason


def expected_for_profile(fixture: dict[str, Any], profile: str) -> dict[str, Any]:
    expected = dict(fixture.get("expected", {}))
    if profile != "safety":
        return expected
    data = eventdata(fixture)
    baseline_rule = expected.get("rule_id")
    if baseline_rule == "100100" and not all(data.get(key) for key in ("serviceName", "targetUserName", "ipAddress")):
        expected.update(alert=False, rule_id=None, action="manual_review")
    if baseline_rule == "100300" and not data.get("commandLine"):
        expected.update(alert=False, rule_id=None, action="manual_review")
    if baseline_rule == "100200" and re.search(r"(?i)(MsMpEng|MpCmdRun|SearchIndexer|SearchProtocolHost|vssvc)\.exe", str(data.get("image", ""))):
        expected.update(alert=False, rule_id=None, action="no_alert")
    return expected


def triage_decision(fixture: dict[str, Any], profile: str, rule_id: str | None, reason: str) -> tuple[str, str]:
    data = eventdata(fixture)
    system = fixture.get("data", {}).get("win", {}).get("system", {})
    computer = system.get("computer", data.get("computer", ""))
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
    tp, fp, fn, tn = counts["TP"], counts["FP"], counts["FN"], counts["TN"]
    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0
    actual_standard = [row for row in standard if row["actual_outcome"]]
    actual_counts = Counter(row["actual_outcome"] for row in actual_standard)
    actual_tp = actual_counts["TP"]
    actual_fp = actual_counts["FP"]
    actual_fn = actual_counts["FN"]
    actual_tn = actual_counts["TN"]
    actual_precision = actual_tp / (actual_tp + actual_fp) if actual_tp + actual_fp else 0
    actual_recall = actual_tp / (actual_tp + actual_fn) if actual_tp + actual_fn else 0
    lines = [
        f"# {profile.title()} Regression Report",
        "",
        "> This is a curated lab corpus. It is not a production SOC metric.",
        "",
        f"- Cases: {len(rows)}",
        f"- Offline actual comparison files: {actual_count}",
        f"- TP: {tp} | FP: {fp} | FN: {fn} | TN: {tn}",
        f"- Precision: {precision:.1%}",
        f"- Recall: {recall:.1%}",
        f"- Manual-review decisions (all cases): {sum(row['decision'] == 'manual_review' for row in rows)}",
        "",
        "## Actual Wazuh comparison",
        "",
    ]
    if actual_standard:
        lines += [
            f"- Cases with actual results: {len(actual_standard)} standard cases",
            f"- TP: {actual_tp} | FP: {actual_fp} | FN: {actual_fn} | TN: {actual_tn}",
            f"- Precision: {actual_precision:.1%}",
            f"- Recall: {actual_recall:.1%}",
        ]
    else:
        lines.append("- No actual Wazuh result files were supplied. The table will show `-` until `reports/actual/` is populated.")
    lines += [
        "",
        "## Case results",
        "",
        "| Case | Kind | Expected | Offline | Actual | Offline result | Actual result | Decision | Reason |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in rows:
        expected = "alert" if row["expected_alert"] else "no alert"
        offline = row["predicted_rule"] or "no alert"
        actual = row["actual_rule"] or "-"
        actual_result = row["actual_outcome"] or "-"
        lines.append(f"| {row['case_id']} | {row['kind']} | {expected} / {row['expected_rule'] or '-'} | {offline} | {actual} | {row['offline_outcome']} | {actual_result} | {row['decision']} | {row['reason']} |")
    lines += [
        "",
        "## Interpretation",
        "",
        "- Baseline profile approximates the historical rule snapshot in this repository; it is not the live Manager ruleset.",
        "- Safety profile adds context checks for incomplete Kerberos/lateral-movement events and known-good canary writers.",
        "- The DC review candidate retains rule 100102. Manual review is not suppression and does not improve detection precision or recall.",
        "- The safety candidate excludes the named Recent-items shortcut from canary detection, regardless of process name. This is not a general shortcut or Explorer allowlist.",
        "- Edge cases are useful for manual-review decisions and are not mixed into the precision/recall denominator.",
        "- Actual Wazuh results require the exact fixture to pass through a Windows Agent and be checked in Discover; pasted JSON only checks the generic decoder.",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", choices=("baseline", "safety"), default="baseline")
    parser.add_argument("--actual-dir", type=Path)
    args = parser.parse_args()

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8-sig"))
    rows: list[dict[str, Any]] = []
    for item in manifest["cases"]:
        fixture = json.loads((ROOT / item["fixture"]).read_text(encoding="utf-8-sig"))
        matcher = baseline_match if args.profile == "baseline" else safety_match
        predicted_rule, reason = matcher(fixture)
        decision, reason = triage_decision(fixture, args.profile, predicted_rule, reason)
        expected = expected_for_profile(fixture, args.profile)
        actual = load_actual(args.actual_dir, item["case_id"])
        rows.append({
            "case_id": item["case_id"],
            "kind": item["kind"],
            "expected_alert": bool(expected.get("alert")),
            "expected_rule": expected.get("rule_id"),
            "predicted_rule": predicted_rule,
            "reason": reason,
            "decision": decision,
            "offline_outcome": outcome(predicted_rule, expected),
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
    return 0


if __name__ == "__main__":
    sys.exit(main())
