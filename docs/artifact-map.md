# Artifact Map

This map describes the v0.1.0 artifact coverage and normalized event output.

| Artifact | Collector | Input Pattern | Event Categories | Notes |
| --- | --- | --- | --- | --- |
| Windows Security/System logs | `internal/collector/evtx` | supported `.evtx` fixture files containing Event XML | `auth`, `process`, `persistence`, `filesystem` | Supports selected Security, System, Sysmon, and PowerShell event IDs from exported Event XML. |
| Sysmon Operational log | `internal/collector/evtx` | Sysmon Event XML fixture records | `process`, `network`, `filesystem`, `registry` | Normalizes process creation, network connections, DNS queries, file creation, image loads, process access, and registry changes. |
| PowerShell logs | `internal/collector/evtx` | PowerShell Event XML fixture records | `process` | Normalizes engine start/stop, module logging, and script block logging. |
| Prefetch | `internal/collector/prefetch` | `.pf` fixture files | `process` | Emits execution evidence with run count and last-run timestamp when available. |
| AmCache | `internal/collector/amcache` | `AmCache.hve` fixture files | `process`, `filesystem` | Emits execution or observed file metadata and SHA1 when available. |
| Chrome and Edge History | `internal/collector/browser` | `History` SQLite databases | `browser` | Emits visit and download events. Converts WebKit timestamps. |
| Firefox history | `internal/collector/browser` | `places.sqlite` | `browser` | Emits visit events from `moz_places` and `moz_historyvisits`. |
| Scheduled Task XML | `internal/collector/scheduledtask` | task XML files under artifact directories | `persistence` | Extracts task path, author, principal, triggers, action command, arguments, and working directory. |
| Targeted filesystem metadata | `internal/collector/filesystem` | configured `--fs-path` roots | `filesystem` | Emits modification-time metadata for selected files only. No full artifact-root crawl by default. |

## Default Targeted Filesystem Paths

```text
C:\Users\
C:\Users\*\Downloads\
C:\Users\*\Desktop\
C:\Users\*\AppData\Local\Temp\
C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\
C:\ProgramData\
C:\Windows\Temp\
C:\Windows\System32\Tasks\
```

Use `--fs-path` repeatedly to narrow or extend metadata collection:

```sh
./bin/timeline ingest artifacts --os windows --out case.db --fs-path 'C:\Users\*\Downloads\' --fs-path 'C:\ProgramData\'
```

Path traversal attempts are rejected before walking.

## Correlation Coverage

Current correlations include:

- Prefetch execution to EVTX process creation by executable and close timestamp.
- AmCache execution metadata to Prefetch or EVTX by path or hash.
- Browser download to later file or process execution.

Correlations raise evidence strength when independent sources align, but still require case validation.

## Intentional Non-Goals

The artifact map excludes live response, disk image mounting, memory forensics, full disk crawling, cloud upload, and browser credential artifacts. Those areas conflict with the v0.1.0 safety and scope rules.
