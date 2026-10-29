# Baseline Regression Report

> This is a curated lab corpus. It is not a production SOC metric.

- Cases: 17
- Recorded Wazuh result files: 0
- TP: 5 | FP: 2 | FN: 0 | TN: 5
- WRONG_RULE: 0
- Precision: 71.4%
- Recall: 100.0%
- Manual-review decisions (all cases): 4
- Outcome contract failures: 0
- Action contract failures: 0

## Actual Wazuh comparison

- No actual Wazuh result files were supplied. The table will show `-` until `reports/actual/` is populated.

## Case results

| Case | Kind | Ground truth | Offline | Actual | Expected / observed outcome | Actual result | Expected / observed action | Reason |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| POS-100100-001 | positive | alert / 100100 | 100100 | - | TP / TP | - | investigate / investigate | Event 4769 with RC4 ticket encryption |
| POS-100101-001 | positive | alert / 100101 | 100101 | - | TP / TP | - | investigate / investigate | Event 4768 with disabled pre-authentication and RC4 |
| POS-100102-001 | positive | alert / 100102 | 100102 | - | TP / TP | - | investigate / investigate | Event 4662 contains the replication GUID |
| POS-100300-001 | positive | alert / 100300 | 100300 | - | TP / TP | - | investigate / investigate | Suspicious remote-shell parent-child lineage |
| POS-100200-001 | positive | alert / 100200 | 100200 | - | TP / TP | - | investigate / investigate | Canary filename was touched |
| NEG-100100-001 | negative | no alert / - | no alert | - | TN / TN | - | no_alert / no_alert | No baseline rule condition matched |
| NEG-100101-001 | negative | no alert / - | no alert | - | TN / TN | - | no_alert / no_alert | No baseline rule condition matched |
| NEG-100102-001 | negative | no alert / - | no alert | - | TN / TN | - | no_alert / no_alert | No baseline rule condition matched |
| NEG-100102-002 | negative | no alert / - | 100102 | - | FP / FP | - | investigate / investigate | Event 4662 contains the replication GUID |
| NEG-100300-001 | negative | no alert / - | no alert | - | TN / TN | - | no_alert / no_alert | No baseline rule condition matched |
| NEG-100200-001 | negative | no alert / - | no alert | - | TN / TN | - | no_alert / no_alert | No baseline rule condition matched |
| NEG-100200-002 | negative | no alert / - | 100200 | - | FP / FP | - | investigate / investigate | Canary filename was touched |
| EDGE-100300-001 | edge | alert / 100300 | 100300 | - | TP / TP | - | manual_review / manual_review | Manual review: remote shell identity/source context needs correlation |
| EDGE-100100-001 | edge | alert / 100100 | 100100 | - | TP / TP | - | manual_review / manual_review | Manual review: Kerberos identity or source context is incomplete |
| EDGE-100102-001 | edge | alert / 100102 | 100102 | - | TP / TP | - | investigate / investigate | Event 4662 contains the replication GUID |
| EDGE-100200-001 | edge | alert / 100200 | 100200 | - | TP / TP | - | manual_review / manual_review | Alert retained: security/indexing executable name requires identity verification |
| EDGE-100300-002 | edge | alert / 100300 | 100300 | - | TP / TP | - | manual_review / manual_review | Manual review: remote shell command line is missing |

## Interpretation

- Baseline profile models the repository rules, including exact executable boundaries and the historical broad canary filename condition. It is not the live Manager ruleset.
- Safety canary detection uses the same exact protected TXT basename condition as the XML candidate. Python triage retains alerts with incomplete context or security/indexing executable names for manual review; those review decisions are not XML conditions.
- The DC review candidate retains rule 100102. Manual review is not suppression and does not improve detection precision or recall.
- Non-TXT targets, including shortcuts at any path, are outside the safety canary scope. An executable name never suppresses an alert.
- Explicit profile contracts allow the recorded baseline false positives without relabeling them as true negatives. Unexpected outcomes, missing expected detections, wrong rules and action mismatches fail the runner.
- WRONG_RULE stays visible as a separate count and contributes to both precision and recall denominators as a wrong alert and missed expected-rule detection.
- Edge cases are useful for manual-review decisions and are not mixed into the precision/recall denominator.
- Actual Wazuh results require the exact fixture to pass through a Windows Agent and be checked in Discover; pasted JSON only checks the generic decoder.
