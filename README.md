# Active Directory Detection Quality & Regression Lab

A small, reproducible lab for testing Wazuh/Sysmon detection quality against malicious, benign, and edge-case telemetry. It is designed to be performed manually in an isolated VMware lab before using the optional Python helpers.

The flagship repository demonstrates that detections can fire and response workflows can be validated. This repository answers the next SOC question: how do we know the rules are useful, safe, and still working after a change?

## Start here

This repository is not complete evidence until the VMware run has been performed. The generated fixtures and offline reports are preparation material, not screenshots of a real Wazuh run.

1. Read the separate beginner-friendly Vietnamese Word manual delivered next to this repository.
2. Work manually through VMware, Event Viewer, Sysmon and Wazuh Discover.
3. Record at least one positive, one negative and one edge-case result.
4. Add only sanitized screenshots and actual results after the lab has really been run.

The shorter [Markdown runbook](HUONG-DAN-VMWARE.md) is a technical reference. It is not a replacement for the Word manual.

## What is included

- Five detection hypotheses based on the Active Directory Detection & Response Lab.
- Seventeen sanitized JSON fixtures: five positive, seven negative, and five edge cases.
- A detection catalog describing event sources, required fields, ATT&CK mapping, and limitations.
- A dependency-free Python validator and regression runner.
- Baseline and safety-profile reports.
- A VMware/Wazuh runbook for comparing offline predictions with real EventChannel alerts.
- A separate 15-page Vietnamese click-by-click Word manual is provided outside the repository for the lab operator.

## Detection inventory

| Detection | Wazuh rule | Main data source | Quality question |
| --- | ---: | --- | --- |
| Kerberoasting | 100100 | Windows Security Event 4769 | Is one RC4 request enough evidence? |
| AS-REP Roasting | 100101 | Windows Security Event 4768 | Are both pre-auth and encryption fields present? |
| DCSync | 100102 | Windows Security Event 4662 | Does the replication GUID appear in the event? |
| Lateral Movement | 100300 | Sysmon Event 1 + Security Event 4624 | Can process lineage be correlated with a source IP? |
| Canary Ransomware | 100200 | Sysmon Event 11 | Can known-good writers be separated from a suspicious process? |

## Optional Python validation

Run this section after understanding the manual workflow. It does not replace VMware or Wazuh testing.

From the repository root, run one command at a time:

```powershell
python scripts/generate_fixtures.py
python scripts/validate_fixtures.py
python scripts/export_logtest_events.py
python scripts/run_regression.py --profile baseline
python scripts/run_regression.py --profile safety
```

The generated reports are written to `reports/baseline-report.md` and `reports/safety-report.md`.
The JSON event bodies for decoder inspection are written to `reports/logtest-inputs/`. They do not reproduce Windows EventChannel decoding in Ruleset Test.

These first reports are offline predictions. They exercise the same field conditions represented by the Wazuh rules; they do not claim that Wazuh itself ran on this Windows machine.

## Run against real Wazuh

Read the separate Vietnamese Word manual first. It explains which VMware machines to start, where to click in Event Viewer, how to inspect Sysmon, and how to verify real alerts in Wazuh Discover. It intentionally leaves screenshots for the real VMware run so the evidence is not fabricated.

The minimal JSON fixture decodes as `json` in Ruleset Test. The installed Windows rules use `<if_group>windows</if_group>`, whose base rule requires the `windows_eventchannel` decoder. Therefore, Phase 2 success on a pasted fixture does not prove Phase 3 rule matching. Use actual agent-collected EventChannel alerts to verify those rules.

For decoder inspection only, use the Ubuntu Wazuh Manager VM:

```bash
sudo /var/ossec/bin/wazuh-logtest
```

Paste one sanitized event at a time and inspect the decoded fields. Do not record a missing Phase 3 as a false negative for the Windows rule. Save a result in `reports/actual/` only after testing the exact fixture through the Windows EventChannel path and verifying the resulting alert or absence of one. Then run:

```powershell
python scripts/run_regression.py --profile baseline --actual-dir reports/actual
```

The report shows offline prediction and actual Wazuh coverage in separate columns. To save a result without manually editing JSON, use for example:

```powershell
python scripts/record_actual.py --case-id POS-100100-001 --alert --rule-id 100100 --level 8 --notes "Verified with agent-collected event"
```

The report separates offline prediction from actual Wazuh coverage and does not claim that a small lab corpus represents production performance. The live Manager's rule `100100` currently has level 8, while `detections/wazuh/baseline-rules.xml` is a historical source snapshot with level 12; do not install the snapshot over the live rules without reviewing the differences.

## Repository layout

```text
soc-detection-quality-and-regression-lab/
├── detection-catalog/       # Human-readable detection hypotheses
├── detections/wazuh/        # Baseline rule source copied from the flagship lab
├── fixtures/                # Positive, negative, and edge-case telemetry
├── test-cases/              # Expected outcomes
├── scripts/                 # Validation and reporting code
├── reports/                 # Generated baseline and safety reports
├── docs/                    # Methodology and limitations
├── HUONG-DAN-VMWARE.md      # Vietnamese step-by-step runbook
└── GLOSSARY.md              # Vietnamese beginner glossary
```

## Metrics

The runner reports true positives, false positives, false negatives, true negatives, precision, and recall for the curated positive/negative corpus. Edge cases are reported separately because they measure context quality and safety decisions.

The numbers describe this small lab corpus. They are not a production SOC measurement.

The `Decision` column is an offline triage recommendation. For `NEG-100102-002`, baseline and safety both retain rule `100102` and count one FP under the fixture's explicitly benign assumption. Safety marks the lab identity/host context for `manual_review`; this does not confirm the real DC activity was legitimate, suppress the alert, or improve the detection metrics. See [tuning notes](docs/tuning-notes.md).

The [canary shortcut case study](docs/canary-shortcut-case-study.md) links a privately retained Sysmon export to sanitized case `NEG-100200-002`. Baseline predicts an FP on a Recent-items shortcut; safety excludes that specific target from canary detection while retaining alerts on the TXT canary itself. These are offline results, not a deployed Wazuh tuning result.

The proposed Wazuh expression is in `detections/wazuh/canary-safe-candidate.xml`. It is a detection-only candidate and must be validated with the `100200` Active Response block disabled.

Live validation in the VMware lab succeeded after repairing WK01's domain secure channel: a Sysmon Event 11 for `Canary-Test-6\!_financial_payroll_2026.txt` reached Wazuh and matched `100200` level 12. The earlier `.txt.lnk` shortcut matched built-in rule `92200`, while the corrected canary candidate did not match it. The live TXT alert came from an Explorer copy operation, so it proves detection coverage rather than malicious intent.

Check that the review policy retains alerts when identity context changes and that shortcut filtering does not hide writes to the real canary:

```powershell
python -m unittest discover -s tests
```

## Evidence policy

Do not describe the offline reports as real Wazuh evidence. After completing the VMware run, add sanitized screenshots and files under `reports/actual/` locally, then review them before any future GitHub upload. Never include passwords, tokens, private IPs or unapproved internal hostnames.

## Portfolio positioning

The flagship lab shows Windows/Active Directory detection and response. This lab shows detection validation, false-positive analysis, telemetry-gap analysis, and regression discipline.

## Safety scope

This repository contains simulated and sanitized telemetry only. It does not disable accounts, block hosts, terminate processes, or send Telegram messages. The actual response handlers remain in the flagship repository and should be tested only in the isolated VMware lab.

Flagship lab: https://github.com/LeeHoang26/ad-threat-detection-and-response-lab
