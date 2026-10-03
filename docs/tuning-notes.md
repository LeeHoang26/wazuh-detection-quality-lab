# Tuning notes

## Kerberoasting

An RC4 service-ticket request is worth investigating, but one request is not a verdict. Legacy applications can still use RC4. Before automating a response, I would look at request frequency, known service accounts, the username, source IP, and prior behavior.

If `targetUserName` or `ipAddress` is missing, the alert may still be useful. The decision should move to `manual_review`, not an immediate containment action.

## AS-REP Roasting

`preAuthType=0` together with the relevant encryption type can identify an AS-REP Roasting pattern. Disabling an account or changing its password, however, belongs in an approved IAM playbook. A detection alert alone is not authorization to lock a user out.

## DCSync

The replication GUID gives more context than Event 4662 alone. In production, an analyst also needs to know whether the subject is a Domain Controller or a service account authorized to replicate. That calls for a controlled allowlist and an investigation of the subject account.

In the lab, the Manager generated a level-14 `100102` alert for Event 4662 with a replication GUID, `subjectUserName=DC01$`, and `subjectUserSid=S-1-5-18`. This is a potential false positive to check against legitimate DC replication. The GUID alone does not prove unauthorized DCSync.

The safety candidate keeps the `100102` alert and marks one simulated combination for `manual_review`: account `DC01$`, domain `LAB`, SID `S-1-5-18`, and reporting host `DC01` or `DC01.lab.local`. This is a pattern to investigate, not a trusted-account list. If any field is missing or different, the decision stays `investigate`. Accounts ending in `$` are not broadly excluded.

The modeled legitimate-replication negative case remains an FP under both baseline and safety because the alert is still present. The Decision column tells the analyst what to review; it does not improve precision or recall. The five real `DC01$` alerts still need individual verification before any of them can be labeled benign.

## WMI and WinRM lateral movement

Parent-child relationships such as `WmiPrvSE.exe -> cmd.exe` and `wsmprovhost.exe -> powershell.exe` can reveal a remote shell. Sysmon Event 1 usually does not provide the source IP on its own, so I would correlate it with Security Event 4624 and network events.

If the command line is missing, keep the alert for investigation. Do not isolate a host automatically on process lineage alone when the context is incomplete.

## Ransomware canary

A canary filename match is a fast signal, but Defender, SearchIndexer, and backup processes can touch files legitimately. Any allowlist should use a full path, signer, hash, or process role rather than a broad filename exception.

A cautious response preserves evidence, records the PID and filename, checks whether other files changed, and reviews the process tree before suspending or terminating anything.

On WK01, Sysmon Event 11 recorded `Explorer.EXE` creating a `.lnk` shortcut in `Recent`; its name contained `_financial_payroll_2026`. A rule that matches only that substring treats the shortcut like the protected canary. Active Response had been configured for `100200` even though the rule was not yet loaded. The handler searches the ten most recent Event 11 records for a PID and then attempts suspension and termination. The exact path, extension, and process must be checked before enabling that response.

## Tuning ground rules

- Do not tune a rule solely to get a better precision score on 17 fixtures.
- Record why each rule change was made.
- Rerun both baseline and safety after every change.
- Any action that could disrupt a user needs manual approval or a clear playbook.

## Shortcut candidate

`NEG-100200-002` recreates exported WK01 record 8390 with sample username and domain values. The safety candidate excludes only `!_financial_payroll_2026.txt.lnk` directly under `C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent` from canary detection. An Explorer write to the actual `.txt` canary must still match. This narrows the protected file scope; it does not certify Explorer or shortcuts as safe. The [case study](canary-shortcut-case-study.md) records the source, hash, and boundary tests.
