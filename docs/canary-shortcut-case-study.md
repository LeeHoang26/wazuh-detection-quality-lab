# Canary shortcut scope test

## Observation

The privately retained export `Canary-shortcut-11-8390.evtx` contains one Sysmon Event 11, record 8390 from WK01. Windows Event Log reading on the host confirmed these fields:

- Event timestamp (UTC): `2026-09-20T07:05:33.2316129Z`.
- Process image: `C:\Windows\Explorer.EXE`.
- EventData ProcessId: `1148`, a historical identifier, not a current process target.
- Target: a user's `AppData\Roaming\Microsoft\Windows\Recent\!_financial_payroll_2026.txt.lnk`.
- Export SHA256: `8BED33BAC815750A3670B2C621B8DE7C857BFF9BBEDD7938A63176BC63099D96`.

The target is a Recent-items shortcut. This event does not show modification of the original TXT canary. `Canary_Detection` is the Sysmon filter name, not evidence of a Wazuh rule match. The user found five matching filenames; only the selected exported record was inspected here. The hash identifies the retained export; it does not independently establish the event's trustworthiness.

## Fixture and expected outcome

`NEG-100200-002` is a simplified, sanitized reconstruction, not a raw EventChannel replay. The username and domain are replaced by `labuser` and `LAB`. The filename, directory structure, process image and historical PID are preserved. The fixture uses the corpus's legacy `eventdata.computer` placement; the original event has `Computer` under `System`. The complete original EVTX and notes remain outside this repository.

Expected result: no canary-tampering alert for a shortcut target. This label is specific to this detection objective; it does not establish that every LNK file, or every process named Explorer, is harmless.

## Offline comparison

The historical baseline matches `_financial_payroll_2026` anywhere in the target string. It therefore predicts `100200` on this shortcut and receives an FP against the case's unchanged expected outcome.

The safety candidate excludes only `!_financial_payroll_2026.txt.lnk` directly under `C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent`. Windows path comparisons are case-insensitive. It does not exempt Explorer from detection: writes by Explorer to the actual TXT canary still match. Different directories, names and extensions retain the baseline behavior.

The XML candidate in `detections/wazuh/canary-safe-candidate.xml` has a different, narrower target scope than the Python safety profile: it requires the exact basename `!_financial_payroll_2026.txt` or `!_confidential_contract.txt`, in any directory. All `.lnk` targets fail this expression, whereas the Python profile excludes only the specific Recent-items shortcut. Python report metrics must not be attributed to the XML candidate.

The first installed expression incorrectly required the path separator immediately before `_financial...`, omitting the literal `!`. A real canary target therefore failed that expression. A later repository-only suffix workaround matched too broadly. The corrected XML retains the basename boundary and explicitly includes `!`. `tests/test_canary_xml.py` reads the regex directly from XML and checks real TXT paths, shortcuts and other filenames using Python's compatible regex subset; it does not validate Wazuh's decoder, PCRE2 engine or runtime. Keep the `100200` Active Response block disabled while validating the live rule.

With this case added, there are 17 fixtures: five positive, seven negative and five edge cases. On the 12 non-edge cases, baseline yields TP=5, FP=2, FN=0, TN=5; safety yields TP=5, FP=1, FN=0, TN=6. Precision changes from 71.4% to 83.3% in this curated offline corpus. The remaining FP is the hypothetical approved-DC scenario; review retains its alert.

## Live validation status

Initially the Manager did not list rule `100200`. The user subsequently disabled its canary Active Response binding, installed the candidate, corrected the literal `!` in the filename expression, and restarted the Manager successfully. A later live test created `C:\Users\Public\Canary-Test-6\!_financial_payroll_2026.txt` on WK01 through Explorer. Sysmon Event 11 was ingested through EventChannel and Wazuh generated rule `100200`, level 12. The Wazuh alert timestamp was `2026-10-02 23:02:46.680` local lab time and the event UtcTime was `2026-10-02 16:02:39.177Z`, a small ingestion delay.

The live alert's image was `C:\Windows\Explorer.EXE`, PID `5804`, and its target ended in the protected TXT filename. This proves the candidate detects a protected TXT write; it does not prove ransomware. A user copy operation can be legitimate, which is why Active Response remained disabled and why the candidate is detection-only.

A later shortcut event reached Wazuh and matched built-in rule `92200` at level 6, described as scripting file creation under a Windows Temp or User folder. That is evidence of Sysmon ingestion and a different rule match, not a false positive from candidate `100200`. The shortcut did not match the corrected candidate; the real TXT copy did. The live test used a different path from the sanitized fixtures, so it is recorded as validation evidence rather than an `reports/actual/` result for an existing case ID.

The existing response handler can select a PID from a recent matching filename, suspend it, dump it and terminate it. Its behavior needs separate verification and remediation before any live canary test. The offline scope change does not repair that handler or validate PID identity.

## Reproduce on the host

Run from the repository root, one command at a time:

```powershell
python scripts/validate_fixtures.py
python scripts/run_regression.py --profile baseline
python scripts/run_regression.py --profile safety
python -m unittest discover -s tests
```

Compare the `NEG-100200-002` row in both reports. The unit tests verify unchanged expected labels, retained detection on the real TXT target and narrow path scope.
