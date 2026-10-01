# Active Directory Detection Quality & Regression Lab

A small, reproducible lab for testing Wazuh/Sysmon detection quality against malicious, benign, and edge-case telemetry.

The flagship repository demonstrates that detections can fire and response workflows can be validated. This repository answers the next SOC question: how do we know the rules are useful, safe, and still working after a change?

## What is included

- Five detection hypotheses based on the Active Directory Detection & Response Lab.
- Fifteen sanitized JSON fixtures: five positive, five negative, and five edge cases.
- A detection catalog describing event sources, required fields, ATT&CK mapping, and limitations.
- A dependency-free Python validator and regression runner.
- Baseline and safety-profile reports.
- A VMware/Wazuh runbook for replacing offline predictions with real `wazuh-logtest` results.

## Detection inventory

| Detection | Wazuh rule | Main data source | Quality question |
| --- | ---: | --- | --- |
| Kerberoasting | 100100 | Windows Security Event 4769 | Is one RC4 request enough evidence? |
| AS-REP Roasting | 100101 | Windows Security Event 4768 | Are both pre-auth and encryption fields present? |
| DCSync | 100102 | Windows Security Event 4662 | Does the replication GUID appear in the event? |
| Lateral Movement | 100300 | Sysmon Event 1 + Security Event 4624 | Can process lineage be correlated with a source IP? |
| Canary Ransomware | 100200 | Sysmon Event 11 | Can known-good writers be separated from a suspicious process? |

## Quick start on Windows

Run these commands from this repository root:

```powershell
python scripts/generate_fixtures.py
python scripts/validate_fixtures.py
python scripts/export_logtest_events.py
python scripts/run_regression.py --profile baseline
python scripts/run_regression.py --profile safety
```

The generated reports are written to `reports/baseline-report.md` and `reports/safety-report.md`.
The event bodies for the real Wazuh test are written to `reports/logtest-inputs/`.

These first reports are offline predictions. They exercise the same field conditions represented by the Wazuh rules; they do not claim that Wazuh itself ran on this Windows machine.

## Run against real Wazuh

Use the Ubuntu Wazuh Manager VM from the flagship lab:

```bash
sudo /var/ossec/bin/wazuh-logtest
```

Paste one sanitized event at a time and record the returned rule ID and level. Save each result in `reports/actual/` using the format described in `HUONG-DAN-VMWARE.md`, then run:

```powershell
python scripts/run_regression.py --profile baseline --actual-dir reports/actual
```

The report shows offline prediction and actual Wazuh coverage in separate columns. To save a result without manually editing JSON, use for example:

```powershell
python scripts/record_actual.py --case-id POS-100100-001 --alert --rule-id 100100 --level 12 --notes "Matched in wazuh-logtest"
```

The report separates offline prediction from actual Wazuh coverage and does not claim that a small lab corpus represents production performance.

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

## Portfolio positioning

The flagship lab shows Windows/Active Directory detection and response. This lab shows detection validation, false-positive analysis, telemetry-gap analysis, and regression discipline.

## Safety scope

This repository contains simulated and sanitized telemetry only. It does not disable accounts, block hosts, terminate processes, or send Telegram messages. The actual response handlers remain in the flagship repository and should be tested only in the isolated VMware lab.

Flagship lab: https://github.com/LeeHoang26/ad-threat-detection-and-response-lab
