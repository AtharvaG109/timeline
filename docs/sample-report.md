# Windows Incident Diff Report

## Executive Summary

This sample report describes activity in the incident database that is consistent with a candidate intrusion sequence and requires validation against case context. The highest-signal findings are new remote authentication, PowerShell execution, persistence-like scheduled task creation, and outbound network activity that were not observed in the baseline.

## High-Confidence Attack Chain

1. Candidate remote logon from `203.0.113.24` to host `WIN-WS01` using account `ACME\j.smith`.
2. New PowerShell execution occurred within five minutes of that logon.
3. A scheduled task named `UpdateCheck` was created after the PowerShell activity.
4. The same host later made outbound HTTPS connections to `198.51.100.42`.

Each step cites normalized event IDs and source paths below. The sequence is consistent with an attack chain, but it does not by itself establish intent.

## New Critical and High Findings

| Severity | Finding | Evidence |
| --- | --- | --- |
| critical | Candidate remote logon followed by process execution | `evt-9f0b2c9e7a4d1a33`, `evt-0c7e87a6bb19d044` from `C:\Windows\System32\winevt\Logs\Security.evtx` |
| high | Scheduled task creation not present in baseline | `evt-0db9f63b5e482f11` from `C:\Windows\System32\winevt\Logs\Microsoft-Windows-TaskScheduler%4Operational.evtx` |
| high | New outbound network destination | `evt-f41a2dd920a17049` from `C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx` |

## Baseline vs Incident Summary

| Category | Baseline | Incident | New Candidate Activity |
| --- | ---: | ---: | ---: |
| Authentication | 482 | 519 | 3 |
| Execution | 1,241 | 1,330 | 8 |
| Persistence | 12 | 14 | 1 |
| Network | 904 | 944 | 4 |
| Browser Downloads | 33 | 36 | 1 |

## Timeline of Suspicious Activity

| Time UTC | Event ID | Summary | Source Path |
| --- | --- | --- | --- |
| 2024-05-06T20:01:44Z | `evt-9f0b2c9e7a4d1a33` | Remote interactive logon candidate for `ACME\j.smith` | `C:\Windows\System32\winevt\Logs\Security.evtx` |
| 2024-05-06T20:04:12Z | `evt-0c7e87a6bb19d044` | PowerShell process execution with encoded command-like arguments | `C:\Windows\System32\winevt\Logs\Security.evtx` |
| 2024-05-06T20:07:39Z | `evt-0db9f63b5e482f11` | Scheduled task creation candidate: `UpdateCheck` | `C:\Windows\System32\winevt\Logs\Microsoft-Windows-TaskScheduler%4Operational.evtx` |
| 2024-05-06T20:09:55Z | `evt-f41a2dd920a17049` | New HTTPS destination `198.51.100.42:443` | `C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx` |

## Authentication Findings

Event `evt-9f0b2c9e7a4d1a33` is consistent with a successful remote logon from `203.0.113.24`. The source path is `C:\Windows\System32\winevt\Logs\Security.evtx`. This requires validation against VPN, help desk, and administrator activity records.

## Execution Findings

Event `evt-0c7e87a6bb19d044` records PowerShell execution by `ACME\j.smith` shortly after the remote logon candidate. The command line contains encoded command-like arguments. The source path is `C:\Windows\System32\winevt\Logs\Security.evtx`.

## Persistence Findings

Event `evt-0db9f63b5e482f11` records creation of scheduled task `UpdateCheck`. The task action references a user-writable path under `C:\Users\j.smith\AppData\Roaming`. The source path is `C:\Windows\System32\winevt\Logs\Microsoft-Windows-TaskScheduler%4Operational.evtx`.

## Network Findings

Event `evt-f41a2dd920a17049` records a new outbound HTTPS connection to `198.51.100.42:443`. This destination was not present in the baseline database. The source path is `C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx`.

## Browser and Download Findings

Event `evt-b93c4d77f05be013` is a candidate browser download to `C:\Users\j.smith\Downloads\invoice-viewer.exe`. The event source path is `C:\Users\j.smith\AppData\Local\Microsoft\Edge\User Data\Default\History`.

## ATT&CK Mapping

| Technique | Candidate Evidence |
| --- | --- |
| T1021.001 Remote Services: Remote Desktop Protocol | `evt-9f0b2c9e7a4d1a33` |
| T1059.001 Command and Scripting Interpreter: PowerShell | `evt-0c7e87a6bb19d044` |
| T1053.005 Scheduled Task/Job: Scheduled Task | `evt-0db9f63b5e482f11` |
| T1105 Ingress Tool Transfer | `evt-b93c4d77f05be013` |

## Evidence Table

| Event ID | Category | Action | Severity | Confidence | Source Path |
| --- | --- | --- | --- | --- | --- |
| `evt-9f0b2c9e7a4d1a33` | authentication | remote_logon | critical | high | `C:\Windows\System32\winevt\Logs\Security.evtx` |
| `evt-0c7e87a6bb19d044` | execution | process_start | high | medium | `C:\Windows\System32\winevt\Logs\Security.evtx` |
| `evt-0db9f63b5e482f11` | persistence | scheduled_task_create | high | high | `C:\Windows\System32\winevt\Logs\Microsoft-Windows-TaskScheduler%4Operational.evtx` |
| `evt-f41a2dd920a17049` | network | outbound_connect | high | medium | `C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx` |
| `evt-b93c4d77f05be013` | browser | download | medium | medium | `C:\Users\j.smith\AppData\Local\Microsoft\Edge\User Data\Default\History` |

## Artifact Coverage

| Artifact | Status | Notes |
| --- | --- | --- |
| Security EVTX | Present | Authentication and process creation events available |
| Sysmon EVTX | Present | Network telemetry available |
| Task Scheduler EVTX | Present | Task registration events available |
| Prefetch | Not provided | Execution frequency cannot be cross-checked in this sample |
| AmCache | Not provided | Program inventory cannot be cross-checked in this sample |

## Limitations

- This sample uses representative event IDs and source paths.
- Findings are candidates and require validation against environment context.
- Missing artifacts reduce confidence for execution and persistence interpretation.
- Baseline coverage and retention differences can affect diff results.

## Appendix

Report generated from normalized timeline, diff, detection, and correlation data. Report generation is read-only and does not mutate evidence data.
