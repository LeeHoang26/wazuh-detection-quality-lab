# How the tests are scored

## What I wanted to know

I use the same small corpus to ask three questions:

1. Does the rule catch the suspicious activity it was written for?
2. Does it also fire on normal activity?
3. When context is missing or a legitimate process touches a canary, does the response decision remain cautious?

## The 17-case corpus

There are 5 positive, 7 negative, and 5 edge cases. The sixth negative case models an approved Domain Controller, `DC01$`, performing replication. I added it after seeing five alerts involving that account in the lab; each real alert still needs its own investigation before it can be called benign. The seventh negative case recreates Sysmon record 8390, whose target was a `.lnk` shortcut rather than the protected `.txt` file. See the [source and limitations](canary-shortcut-case-study.md). Every case has a stable ID, event ID, input fields, and expected outcome.

Both profiles run against the same 17 cases. The baseline has 2 false positives; the safety candidate has 1. Adding the shortcut case changed baseline precision from 83.3% on the earlier 16-case corpus to 71.4% on this corpus. That is a change in what was measured, not a regression in baseline code. The safety candidate reaches 83.3% by excluding the defined shortcut. I did not change the shortcut's expected label to improve the score.

The fixtures are sanitized simulations. They are not logs from a real victim and contain no real credentials.

## Scoring

The matcher reads fixture fields, predicts a rule ID, and compares it with `expected`:

- TP: the expected alert fired under the correct rule.
- FP: a negative case produced an alert.
- FN: a positive case produced no alert.
- TN: a negative case produced no alert.
- WRONG_RULE: an alert fired under the wrong rule.

Precision is `TP / (TP + FP)`; recall is `TP / (TP + FN)`. Only positive and negative cases contribute to those metrics. Edge cases are listed separately because their useful outcome is often `manual_review`, which a single precision or recall number would hide.

## Baseline and safety candidate

The baseline models the field conditions in the existing Wazuh rules. The safety candidate adds decision logic:

- Missing identity or source context lowers confidence.
- Missing command-line context should not trigger immediate host isolation.
- A known security process touching a canary is not, by itself, proof of ransomware.

The safety candidate is a test model, not a complete production policy.

## Actual Wazuh results

If a file is present in `reports/actual/`, the runner also compares the rule ID observed after the event passed through a Windows Agent and appeared in Discover. Pasting JSON into Ruleset Test shows that the `json` decoder can read the fields; it does not produce an actual result for a Windows rule expecting `windows_eventchannel`. Actual-result files are ignored by `.gitignore` because they may contain details from a personal environment.

Offline results show how the local model behaves. Actual results show how the Wazuh Manager in VMware decoded and matched an event. A disagreement between them is useful tuning evidence.
