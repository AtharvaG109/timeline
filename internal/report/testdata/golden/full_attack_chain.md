# Windows Incident Diff Report

## Executive Summary

This report summarizes 4 normalized events, 4 baseline-vs-incident candidate differences, 2 detection records, 2 correlation records. The highest-signal records include 1 critical and 2 high findings that are consistent with activity that requires validation.

## High-Confidence Attack Chain
1. 2024-05-06T20:01:44Z - Observed auth/successful_logon; user `ACME\alice`. Evidence: `evt-auth` from `Security.evtx`.
2. 2024-05-06T20:04:12Z - Observed process/process_created; user `ACME\alice`; process `C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe`; command `powershell.exe -EncodedCommand SQBFAFgA`; object `C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe`. Evidence: `evt-powershell` from `Security.evtx`.
3. 2024-05-06T20:06:30Z - Observed persistence/scheduled_task_created; user `ACME\alice`; process `C:/Users/alice/AppData/Roaming/updatecheck.exe`; object `C:/Users/alice/AppData/Roaming/updatecheck.exe`. Evidence: `evt-task` from `Security.evtx`.
4. 2024-05-06T20:09:55Z - Observed network/connected; process `C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe`; object `C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe`; destination `198.51.100.42:443`. Evidence: `evt-net` from `Sysmon.evtx`.


## New Critical and High Findings
| Severity | Finding | Evidence |
| --- | --- | --- |
| critical | new_persistence - Incident contains new persistence associated with a suspicious execution path. | `evt-task` from `Security.evtx` |
| high | new_cmdline - Incident contains a new encoded PowerShell command line candidate. | `evt-powershell` from `Security.evtx` |
| high | new_remote_logon - Incident contains a new remote logon pattern absent from the baseline. | `evt-auth` from `Security.evtx` |


## Baseline vs Incident Summary

| Category | Incident Events | New Candidate Activity |
| --- | ---: | ---: |
| Authentication | 1 | 1 |
| Execution | 1 | 1 |
| Network | 1 | 1 |
| Persistence | 1 | 1 |

## Timeline of Suspicious Activity
| Time UTC | Event ID | Summary | Source Path |
| --- | --- | --- | --- |
| 2024-05-06T20:01:44Z | `evt-auth` | Observed auth/successful_logon; user `ACME\alice`. | `Security.evtx` |
| 2024-05-06T20:04:12Z | `evt-powershell` | Observed process/process_created; user `ACME\alice`; process `C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe`; command `powershell.exe -EncodedCommand SQBFAFgA`; object `C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe`. | `Security.evtx` |
| 2024-05-06T20:06:30Z | `evt-task` | Observed persistence/scheduled_task_created; user `ACME\alice`; process `C:/Users/alice/AppData/Roaming/updatecheck.exe`; object `C:/Users/alice/AppData/Roaming/updatecheck.exe`. | `Security.evtx` |
| 2024-05-06T20:09:55Z | `evt-net` | Observed network/connected; process `C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe`; object `C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe`; destination `198.51.100.42:443`. | `Sysmon.evtx` |


## Authentication Findings
- 2024-05-06T20:01:44Z: Observed auth/successful_logon; user `ACME\alice`. Evidence `evt-auth` from `Security.evtx`.


## Execution Findings
- 2024-05-06T20:04:12Z: Observed process/process_created; user `ACME\alice`; process `C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe`; command `powershell.exe -EncodedCommand SQBFAFgA`; object `C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe`. Evidence `evt-powershell` from `Security.evtx`.


## Persistence Findings
- 2024-05-06T20:06:30Z: Observed persistence/scheduled_task_created; user `ACME\alice`; process `C:/Users/alice/AppData/Roaming/updatecheck.exe`; object `C:/Users/alice/AppData/Roaming/updatecheck.exe`. Evidence `evt-task` from `Security.evtx`.


## Network Findings
- 2024-05-06T20:09:55Z: Observed network/connected; process `C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe`; object `C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe`; destination `198.51.100.42:443`. Evidence `evt-net` from `Sysmon.evtx`.


## Browser and Download Findings
No browser or download findings were selected from the current database.


## ATT&CK Mapping
| Technique | Candidate Evidence |
| --- | --- |
| T1053.005 | `evt-task` |
| T1059.001 | `evt-powershell` |
| T1105 | `evt-net` |


## Evidence Table
| Event ID | Category | Action | Severity | Confidence | Source Path |
| --- | --- | --- | --- | --- | --- |
| `evt-auth` | auth | successful_logon | high | high | `Security.evtx` |
| `evt-powershell` | process | process_created | high | high | `Security.evtx` |
| `evt-task` | persistence | scheduled_task_created | critical | high | `Security.evtx` |
| `evt-net` | network | connected | medium | high | `Sysmon.evtx` |


## Artifact Coverage
| Artifact | Status | Notes |
| --- | --- | --- |
| evtx | Present | 2 artifact records; example `Security.evtx` |


## Limitations

- This report identifies evidence patterns consistent with suspicious activity. It does not prove malicious intent by itself. Findings should be validated against host, identity, and network context.
- Findings are candidates and require validation against environment context.
- Baseline coverage, artifact retention, and parser support can affect diff results.
- Report generation is read-only and does not mutate evidence data.
- This Markdown report is generated from SQLite records and does not include PDF or HTML output.

## Appendix

- Case ID: `case-incident`
- Baseline case ID: `case-baseline`
- Normalized events: 4
- Diff results: 4
- Detections: 2
- Event relations: 2

### Detection Records

| Rule ID | Rule Name | Event ID | Severity | Confidence | Rationale |
| --- | --- | --- | --- | --- | --- |
| persistence.scheduled_task_created | Scheduled task created | `evt-task` | high | high | candidate scheduled task persistence |
| powershell.encoded_command | Encoded PowerShell command | `evt-powershell` | high | high | candidate encoded command |

### Correlation Records

| Type | Source Event | Target Event | Confidence | Rationale |
| --- | --- | --- | --- | --- |
| process_network | `evt-powershell` | `evt-net` | medium | process execution and network connection are close in time |
| remote_logon_process | `evt-auth` | `evt-powershell` | medium | remote logon and process execution are close in time |
