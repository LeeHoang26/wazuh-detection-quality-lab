from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"
MANIFEST_PATH = ROOT / "test-cases" / "manifest.json"

REPLICATION_GUID = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"


def event(event_id: str, eventdata: dict[str, Any]) -> dict[str, Any]:
    return {
        "win": {
            "system": {"eventID": event_id},
            "eventdata": eventdata,
        }
    }


def case(
    case_id: str,
    kind: str,
    detection_id: str,
    description: str,
    source: str,
    event_id: str,
    eventdata: dict[str, Any],
    alert: bool,
    rule_id: str | None,
    mitre: str | None,
    action: str,
    notes: str,
) -> dict[str, Any]:
    return {
        "case_id": case_id,
        "kind": kind,
        "detection_id": detection_id,
        "description": description,
        "source": source,
        "event_id": event_id,
        "data": event(event_id, eventdata),
        "expected": {
            "alert": alert,
            "rule_id": rule_id,
            "mitre": mitre,
            "action": action,
        },
        "notes": notes,
    }


CASES = [
    case(
        "POS-100100-001", "positive", "DET-100100",
        "Kerberoasting pattern using an RC4 service ticket",
        "windows_security", "4769",
        {"ticketEncryptionType": "0x17", "serviceName": "MSSQLSvc/db01.lab.local:1433", "targetUserName": "analyst01", "ipAddress": "192.0.2.40", "computer": "DC01"},
        True, "100100", "T1558.003", "alert_and_investigate",
        "A single RC4 request is a lab signal; production tuning should add frequency and context.",
    ),
    case(
        "POS-100101-001", "positive", "DET-100101",
        "AS-REP request for an account without Kerberos pre-authentication",
        "windows_security", "4768",
        {"preAuthType": "0", "ticketEncryptionType": "0x17", "targetUserName": "backupadmin", "ipAddress": "192.0.2.40", "computer": "DC01"},
        True, "100101", "T1558.004", "contain_identity_in_lab",
        "The lab validates identity containment; production response requires an approved IAM playbook.",
    ),
    case(
        "POS-100102-001", "positive", "DET-100102",
        "Directory replication access containing the DCSync replication GUID",
        "windows_security", "4662",
        {"properties": f"{REPLICATION_GUID}; CONTROL_ACCESS", "subjectUserName": "svc_backup", "ipAddress": "192.0.2.40", "computer": "DC01"},
        True, "100102", "T1003.006", "critical_investigation",
        "The replication GUID is the primary indicator used by the lab rule.",
    ),
    case(
        "POS-100300-001", "positive", "DET-100300",
        "WMI remote shell creates cmd.exe under WmiPrvSE.exe",
        "sysmon", "1",
        {"parentImage": r"C:\\Windows\\System32\\wbem\\WmiPrvSE.exe", "image": r"C:\\Windows\\System32\\cmd.exe", "commandLine": "cmd.exe /Q /c whoami", "computer": "WK01", "user": "HOANG\\Administrator", "processId": "2216"},
        True, "100300", "T1047", "correlate_and_isolate",
        "Sysmon provides process lineage; Security Event 4624 supplies the remote source context.",
    ),
    case(
        "POS-100200-001", "positive", "DET-100200",
        "Canary payroll file is modified by a simulated ransomware process",
        "sysmon", "11",
        {"targetFilename": r"C:\\Users\\Public\\!_financial_payroll_2026.txt", "image": r"C:\\Tools\\ransomware_simulator.exe", "processId": "4216", "computer": "WK01", "user": "HOANG\\Administrator"},
        True, "100200", "T1486", "suspend_dump_terminate",
        "The alert should preserve PID and filename context for follow-on triage.",
    ),
    case(
        "NEG-100100-001", "negative", "DET-100100",
        "Normal AES service ticket for an internal application",
        "windows_security", "4769",
        {"ticketEncryptionType": "0x12", "serviceName": "HTTP/app01.lab.local", "targetUserName": "svc_web", "ipAddress": "192.0.2.20", "computer": "DC01"},
        False, None, None, "no_alert",
        "AES ticket does not match the lab RC4 Kerberoasting rule.",
    ),
    case(
        "NEG-100101-001", "negative", "DET-100101",
        "Normal TGT request with pre-authentication enabled",
        "windows_security", "4768",
        {"preAuthType": "2", "ticketEncryptionType": "0x12", "targetUserName": "jdoe", "ipAddress": "192.0.2.20", "computer": "DC01"},
        False, None, None, "no_alert",
        "The event lacks both AS-REP indicators required by the rule.",
    ),
    case(
        "NEG-100102-001", "negative", "DET-100102",
        "Ordinary directory access without a replication permission GUID",
        "windows_security", "4662",
        {"properties": "READ_PROPERTY; WRITE_PROPERTY", "subjectUserName": "helpdesk01", "ipAddress": "192.0.2.20", "computer": "DC01"},
        False, None, None, "no_alert",
        "A generic 4662 event is not sufficient to identify DCSync.",
    ),
    case(
        "NEG-100300-001", "negative", "DET-100300",
        "Interactive administrator starts PowerShell from Explorer",
        "sysmon", "1",
        {"parentImage": r"C:\\Windows\\explorer.exe", "image": r"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "commandLine": "powershell.exe -File C:\\Admin\\backup.ps1", "computer": "WK01", "user": "HOANG\\Administrator", "processId": "2880"},
        False, None, None, "no_alert",
        "The parent-child relationship is common for an interactive local session.",
    ),
    case(
        "NEG-100200-001", "negative", "DET-100200",
        "Windows SearchIndexer writes to a normal document",
        "sysmon", "11",
        {"targetFilename": r"C:\\Users\\Public\\report.docx", "image": r"C:\\Windows\\System32\\SearchIndexer.exe", "processId": "1100", "computer": "WK01", "user": "NT AUTHORITY\\SYSTEM"},
        False, None, None, "no_alert",
        "The filename does not match the canary naming convention.",
    ),
    case(
        "EDGE-100300-001", "edge", "DET-100300",
        "WMI remote shell with no source IP in the Sysmon event",
        "sysmon", "1",
        {"parentImage": r"C:\\Windows\\System32\\wbem\\WmiPrvSE.exe", "image": r"C:\\Windows\\System32\\cmd.exe", "commandLine": "cmd.exe /Q /c whoami", "computer": "WK01", "processId": "3012"},
        True, "100300", "T1047", "manual_review",
        "Detection can fire, but source_ip_confidence is low until Event 4624 is correlated.",
    ),
    case(
        "EDGE-100100-001", "edge", "DET-100100",
        "RC4 service ticket is missing the requesting username",
        "windows_security", "4769",
        {"ticketEncryptionType": "0x17", "serviceName": "MSSQLSvc/db01.lab.local:1433", "ipAddress": "192.0.2.40", "computer": "DC01"},
        True, "100100", "T1558.003", "manual_review",
        "Detection confidence is reduced because the identity context is incomplete.",
    ),
    case(
        "EDGE-100102-001", "edge", "DET-100102",
        "DCSync replication GUID appears in uppercase",
        "windows_security", "4662",
        {"properties": f"{REPLICATION_GUID.upper()}; CONTROL_ACCESS", "subjectUserName": "svc_backup", "ipAddress": "192.0.2.40", "computer": "DC01"},
        True, "100102", "T1003.006", "critical_investigation",
        "The detection uses case-insensitive matching and should still fire.",
    ),
    case(
        "EDGE-100200-001", "edge", "DET-100200",
        "Defender touches a canary file during security scanning",
        "sysmon", "11",
        {"targetFilename": r"C:\\Users\\Public\\!_financial_payroll_2026.txt", "image": r"C:\\Program Files\\Windows Defender\\MsMpEng.exe", "processId": "900", "computer": "WK01", "user": "NT AUTHORITY\\SYSTEM"},
        True, "100200", "T1486", "manual_review",
        "The filename matches the rule, but the known Defender writer should not trigger destructive containment.",
    ),
    case(
        "EDGE-100300-002", "edge", "DET-100300",
        "WinRM remote PowerShell session lacks a command line",
        "sysmon", "1",
        {"parentImage": r"C:\\Windows\\System32\\wsmprovhost.exe", "image": r"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "computer": "WK01", "user": "HOANG\\Administrator", "processId": "4010"},
        True, "100300", "T1021.006", "manual_review",
        "Parent and child images are enough for the lab rule, but investigation context is incomplete.",
    ),
]


def main() -> None:
    for item in CASES:
        folder_name = "edge-cases" if item["kind"] == "edge" else item["kind"]
        folder = FIXTURES / folder_name
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / f"{item['case_id']}.json"
        path.write_text(json.dumps(item, indent=2) + "\n", encoding="utf-8")

    manifest = {
        "schema_version": 1,
        "description": "Expected outcomes for the curated detection regression corpus.",
        "cases": [
            {
                "case_id": item["case_id"],
                "fixture": str((Path("fixtures") / ("edge-cases" if item["kind"] == "edge" else item["kind"]) / f"{item['case_id']}.json")).replace("\\", "/"),
                "kind": item["kind"],
                "detection_id": item["detection_id"],
                "expected": item["expected"],
            }
            for item in CASES
        ],
    }
    MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"generated {len(CASES)} fixtures")


if __name__ == "__main__":
    main()
