# Baseline Regression Report

> This is a curated lab corpus. It is not a production SOC metric.

- Cases: 17
- Offline actual comparison files: 0
- TP: 5 | FP: 2 | FN: 0 | TN: 5
- Precision: 71.4%
- Recall: 100.0%
- Manual-review decisions (all cases): 0

## Actual Wazuh comparison

- No actual Wazuh result files were supplied. The table will show `-` until `reports/actual/` is populated.

## Case results

| Case | Kind | Expected | Offline | Actual | Offline result | Actual result | Decision | Reason |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| POS-100100-001 | positive | alert / 100100 | 100100 | - | TP | - | investigate | Event 4769 with RC4 ticket encryption |
| POS-100101-001 | positive | alert / 100101 | 100101 | - | TP | - | investigate | Event 4768 with disabled pre-authentication and RC4 |
| POS-100102-001 | positive | alert / 100102 | 100102 | - | TP | - | investigate | Event 4662 contains the replication GUID |
| POS-100300-001 | positive | alert / 100300 | 100300 | - | TP | - | investigate | Suspicious remote-shell parent-child lineage |
| POS-100200-001 | positive | alert / 100200 | 100200 | - | TP | - | investigate | Canary filename was touched |
| NEG-100100-001 | negative | no alert / - | no alert | - | TN | - | no_alert | No baseline rule condition matched |
| NEG-100101-001 | negative | no alert / - | no alert | - | TN | - | no_alert | No baseline rule condition matched |
| NEG-100102-001 | negative | no alert / - | no alert | - | TN | - | no_alert | No baseline rule condition matched |
| NEG-100102-002 | negative | no alert / - | 100102 | - | FP | - | investigate | Event 4662 contains the replication GUID |
| NEG-100300-001 | negative | no alert / - | no alert | - | TN | - | no_alert | No baseline rule condition matched |
| NEG-100200-001 | negative | no alert / - | no alert | - | TN | - | no_alert | No baseline rule condition matched |
| NEG-100200-002 | negative | no alert / - | 100200 | - | FP | - | investigate | Canary filename was touched |
| EDGE-100300-001 | edge | alert / 100300 | 100300 | - | TP | - | investigate | Suspicious remote-shell parent-child lineage |
| EDGE-100100-001 | edge | alert / 100100 | 100100 | - | TP | - | investigate | Event 4769 with RC4 ticket encryption |
| EDGE-100102-001 | edge | alert / 100102 | 100102 | - | TP | - | investigate | Event 4662 contains the replication GUID |
| EDGE-100200-001 | edge | alert / 100200 | 100200 | - | TP | - | investigate | Canary filename was touched |
| EDGE-100300-002 | edge | alert / 100300 | 100300 | - | TP | - | investigate | Suspicious remote-shell parent-child lineage |

## Interpretation

- Baseline profile approximates the historical rule snapshot in this repository; it is not the live Manager ruleset.
- Safety profile adds context checks for incomplete Kerberos/lateral-movement events and known-good canary writers.
- The DC review candidate retains rule 100102. Manual review is not suppression and does not improve detection precision or recall.
- The safety candidate excludes the named Recent-items shortcut from canary detection, regardless of process name. This is not a general shortcut or Explorer allowlist.
- Edge cases are useful for manual-review decisions and are not mixed into the precision/recall denominator.
- Actual Wazuh results require the exact fixture to pass through a Windows Agent and be checked in Discover; pasted JSON only checks the generic decoder.
