# Baseline Regression Report

> This is a curated lab corpus. It is not a production SOC metric.

- Cases: 15
- Offline actual comparison files: 0
- TP: 5 | FP: 0 | FN: 0 | TN: 5
- Precision: 100.0%
- Recall: 100.0%

## Actual Wazuh comparison

- No actual Wazuh result files were supplied. The table will show `-` until `reports/actual/` is populated.

## Case results

| Case | Kind | Expected | Offline | Actual | Offline result | Actual result | Reason |
| --- | --- | --- | --- | --- | --- | --- | --- |
| POS-100100-001 | positive | alert / 100100 | 100100 | - | TP | - | Event 4769 with RC4 ticket encryption |
| POS-100101-001 | positive | alert / 100101 | 100101 | - | TP | - | Event 4768 with disabled pre-authentication and RC4 |
| POS-100102-001 | positive | alert / 100102 | 100102 | - | TP | - | Event 4662 contains the replication GUID |
| POS-100300-001 | positive | alert / 100300 | 100300 | - | TP | - | Suspicious remote-shell parent-child lineage |
| POS-100200-001 | positive | alert / 100200 | 100200 | - | TP | - | Canary filename was touched |
| NEG-100100-001 | negative | no alert / - | no alert | - | TN | - | No baseline rule condition matched |
| NEG-100101-001 | negative | no alert / - | no alert | - | TN | - | No baseline rule condition matched |
| NEG-100102-001 | negative | no alert / - | no alert | - | TN | - | No baseline rule condition matched |
| NEG-100300-001 | negative | no alert / - | no alert | - | TN | - | No baseline rule condition matched |
| NEG-100200-001 | negative | no alert / - | no alert | - | TN | - | No baseline rule condition matched |
| EDGE-100300-001 | edge | alert / 100300 | 100300 | - | TP | - | Suspicious remote-shell parent-child lineage |
| EDGE-100100-001 | edge | alert / 100100 | 100100 | - | TP | - | Event 4769 with RC4 ticket encryption |
| EDGE-100102-001 | edge | alert / 100102 | 100102 | - | TP | - | Event 4662 contains the replication GUID |
| EDGE-100200-001 | edge | alert / 100200 | 100200 | - | TP | - | Canary filename was touched |
| EDGE-100300-002 | edge | alert / 100300 | 100300 | - | TP | - | Suspicious remote-shell parent-child lineage |

## Interpretation

- Baseline profile mirrors the existing Wazuh field conditions.
- Safety profile adds context checks for incomplete Kerberos/lateral-movement events and known-good canary writers.
- Edge cases are useful for manual-review decisions and are not mixed into the precision/recall denominator.
- Actual Wazuh results must be recorded separately with `wazuh-logtest`.
