# timeline

`timeline` is a Windows-first DFIR timeline diff engine. It ingests Windows forensic artifacts, normalizes evidence into a SQLite database, compares baseline and incident states, and renders concise Markdown reports for analyst review.

The project is a CLI tool. It does not run a web service and intentionally does not perform live response, disk image mounting, memory forensics, cloud upload, or full disk crawling in v0.1.

## Release Status

`timeline` is currently a v0.1.0 technical preview and portfolio release.

It demonstrates Windows artifact normalization, baseline-vs-incident diffing, rule-based detection, event correlation, and Markdown report generation. It should not yet be used as the sole tool for real incident response decisions.

## Quickstart

Build the CLI:

```sh
make build
```

View command help:

```sh
./bin/timeline --help
```

Validate a timeline database:

```sh
./bin/timeline verify case.db
```

v0.1.0 includes EVTX ingestion for exported Windows Event XML fixtures, Windows Prefetch fixture ingestion, AmCache fixture ingestion, Chrome/Edge/Firefox browser history ingestion, Scheduled Task XML ingestion, targeted filesystem metadata collection, EVTX/Prefetch/AmCache/browser execution correlation, SQLite event storage, YAML detection rules, filtered querying, JSON query output, JSONL export, fingerprint-based baseline-vs-incident diffing, Markdown incident report generation, release workflows, and a complete synthetic demo case.

## CLI

```text
timeline ingest <artifact-dir> --os windows --out <case.db>
timeline ingest <artifact-dir> --os windows --out <case.db> --strict
timeline diff <baseline.db> <incident.db> [--out <report.md>]
timeline report <case.db> --format md --out <report.md>
timeline query <case.db> [filters]
timeline export <case.db> --format jsonl --out <events.jsonl>
timeline verify <case.db>
timeline rules validate <rules-dir>
timeline version
```

Ingest supported Windows artifact fixtures:

```sh
make demo
./bin/timeline ingest testdata/fixtures/windows-evtx --os windows --out case.db
./bin/timeline ingest testdata/fixtures/windows-evtx --os windows --out case.db --rules rules
./bin/timeline ingest artifacts --os windows --out case.db --fs-path 'C:\Users\*\Downloads\'
./bin/timeline ingest artifacts --os windows --out case.db --strict
./bin/timeline query case.db --category auth
./bin/timeline query case.db --category process
./bin/timeline query case.db --category browser
./bin/timeline query case.db --category persistence
./bin/timeline query case.db --category filesystem
./bin/timeline query case.db --severity high
./bin/timeline query case.db --hash 0123456789abcdef
./bin/timeline query case.db --category process --format json
./bin/timeline export case.db --format jsonl --out events.jsonl
./bin/timeline diff baseline.db incident.db --out report.md
./bin/timeline report incident.db --format md --out incident-report.md
./bin/timeline rules validate ./rules
```

## Demo Case

Run the full synthetic demo from a fresh checkout:

```sh
make demo
```

The demo writes generated runtime files to `/tmp/timeline-demo-output/` by default:

```text
/tmp/timeline-demo-output/baseline.db
/tmp/timeline-demo-output/incident.db
/tmp/timeline-demo-output/report.md
/tmp/timeline-demo-output/events.jsonl
/tmp/timeline-demo-output/cli-output.txt
```

The generated report reconstructs a safe candidate chain:

1. Several failed logons.
2. One remote logon success.
3. Encoded PowerShell execution.
4. Browser download staging context.
5. Payload write under `C:\Users\Public`.
6. Scheduled task persistence.
7. New outbound network connection.

Example CLI output excerpt:

```text
diff complete: findings=20 critical=2 high=7 medium=10 low=1 info=0
critical  new_cmdline       ...  Incident contains encoded PowerShell and a new external network destination.
critical  new_persistence   ...  Incident contains new persistence associated with a suspicious execution path.
high      new_remote_logon  ...  Incident contains a new remote logon pattern absent from the baseline.
```

Use `DEMO_DIR=<path> make demo` to choose another output directory. Runtime `.db`, `.sqlite`, `.evtx`, and `demo-output/` paths are ignored by git.

The checked-in capture at `docs/screenshots/demo-cli-output.txt` shows representative demo command output without requiring generated databases in source control.

## How This Differs From Related Tools

- Plaso/log2timeline builds broad super-timelines across many artifact types. `timeline` focuses on Windows baseline-vs-incident diffing and concise attack-chain reports.
- Hayabusa and Chainsaw are strong Windows event log detection tools. `timeline` adds SQLite-backed normalization, cross-artifact correlation, and baseline comparison, but its EVTX coverage is narrower today.
- Velociraptor is a collection and response platform. `timeline` is an offline CLI that analyzes already-collected artifacts and does not perform live response or remote collection.

## Architecture

```text
CLI
 |
 v
app service
 |
 +--> collectors --> normalize --> domain events
 +--> diff
 +--> detect
 +--> correlate
 +--> report
 |
 v
store/domain
```

Key boundaries:

- Domain types do not import CLI, store, collector, or report packages.
- Store owns SQLite access and migrations.
- Collectors emit normalized `TimelineEvent` values and do not write reports.
- Detection rules operate on stored normalized events.
- Diff compares baseline and incident databases using fingerprints, not raw event IDs.
- Reports render existing data and must not mutate evidence.

Detailed architecture notes are in `docs/architecture.md`. The artifact coverage map is in `docs/artifact-map.md`.

## Evidence Model

The domain model defines `TimelineEvent`, `Actor`, `Object`, `Network`, `RawRef`, `Severity`, `Confidence`, and `EvidenceStrength`.

Event IDs are deterministic SHA-256 hashes over normalized event identity fields:

```text
schema_version, source_type, source_path, source_record_id,
timestamp_ns, category, action, actor_image, actor_cmdline,
object_path, net_dst_ip, net_dst_port
```

## SQLite Schema

Migrations create these tables:

- `schema_migrations`
- `cases`
- `artifacts`
- `events`
- `event_relations`
- `detections`
- `diff_results`

Indexes cover case/time, severity, category, process image, object path, network destination, session ID, and detection rule ID.

`timeline verify` checks the schema version, required tables and indexes, future-schema compatibility, event source paths, timestamp sanity, enum values, JSON fields, broken event relations, orphan detections, and artifact raw-reference JSON.

## Query and Export

Query supports these filters:

```text
--category
--severity
--confidence
--from
--to
--actor
--process
--object-path
--hash
--dst-ip
--limit
--format table
--format json
```

`--from` and `--to` accept RFC3339 timestamps or raw `timestamp_ns` values. Table output is the default. JSON output uses stable snake-case field names.

Export currently supports JSONL:

```sh
./bin/timeline export case.db --format jsonl --out events.jsonl
```

JSONL output contains one normalized event per line, sorted by `timestamp_ns` ascending.

## Diff Engine

The diff engine compares baseline and incident SQLite databases with normalized fingerprints instead of raw event IDs. Category-specific fingerprints cover:

- process
- auth
- network
- persistence
- browser
- filesystem
- registry
- scheduled task
- generic events

Fingerprint normalization lowercases paths, collapses repeated whitespace, and replaces usernames, GUIDs, long base64 blobs, timestamps, and random temp names with stable placeholders. Diff results are stored in the incident database `diff_results` table.

Supported diff result types:

- `new_process`
- `new_cmdline`
- `new_persistence`
- `new_remote_logon`
- `new_network_destination`
- `new_dns_query`
- `new_download`
- `new_file_write`
- `new_privilege_event`
- `new_detection`

Run a diff and print a summary:

```sh
./bin/timeline diff baseline.db incident.db
```

Write the complete Markdown report after saving diff results:

```sh
./bin/timeline diff baseline.db incident.db --out report.md
```

## Markdown Reports

Reports are generated from existing SQLite records and do not mutate evidence data. The renderer uses Go templates under `internal/report` and includes:

- Executive Summary
- High-Confidence Attack Chain
- New Critical and High Findings
- Baseline vs Incident Summary
- Timeline of Suspicious Activity
- Authentication Findings
- Execution Findings
- Persistence Findings
- Network Findings
- Browser and Download Findings
- ATT&CK Mapping
- Evidence Table
- Artifact Coverage
- Limitations
- Appendix

Render a report from an incident database:

```sh
./bin/timeline report incident.db --format md --out incident-report.md
```

Report wording is analyst-safe and uses cautious phrasing such as "consistent with", "candidate", "observed", and "requires validation".

## Detection Rules

Rules live in `/rules` and use YAML. Ingest loads `./rules` by default, or a custom directory with `--rules <dir>`.

Initial rule groups:

- `powershell.yml`
- `execution.yml`
- `persistence.yml`
- `auth.yml`
- `network.yml`
- `browser.yml`

Rules can raise event severity or confidence, add tags, add ATT&CK techniques, and write matches to the `detections` table. Rule wording is analyst-safe and uses candidate language.

## Prefetch Ingestion

Phase 5 scans artifact directories for `.pf` files and emits process execution events with:

- `category=process`
- `action=executed`
- `timestamp_source=prefetch_last_run`
- `confidence=medium`
- `evidence_strength=single_source`

When a Prefetch execution and EVTX process creation have matching executable names and close timestamps, `timeline` writes an `event_relations` row and upgrades matching evidence to `multi_source`.

## AmCache Ingestion

Phase 6 scans artifact directories for `AmCache.hve` fixture files and emits execution or file metadata events with:

- `category=process` and `action=executed` when execution metadata is present
- `category=filesystem` and `action=observed` for file metadata observations
- `timestamp_source=amcache`
- `confidence=medium`
- SHA1 values stored in `object.hash`

Publisher and product metadata are preserved as event tags. When AmCache metadata matches Prefetch or EVTX process evidence by path or hash, `timeline` writes `event_relations` rows and upgrades matching evidence to `multi_source`.

## Browser History Ingestion

Phase 10 scans artifact directories for Chrome and Edge `History` SQLite databases and Firefox `places.sqlite` databases. Browser visits emit:

- `category=browser`
- `action=visited`
- `timestamp_source=browser_history`

Chromium downloads emit:

- `category=browser`
- `action=downloaded`
- `timestamp_source=browser_download`
- URL, DNS name, target path, start time, and end time when available

Chrome and Edge WebKit timestamps are converted to Unix nanoseconds. Firefox visit timestamps are converted from Unix microseconds. When a downloaded executable or archive is followed by matching process or file evidence, `timeline` writes an `event_relations` row and upgrades matching evidence to `multi_source`.

## Scheduled Tasks and Filesystem Metadata

Phase 11 parses Scheduled Task XML files under artifact directories and emits persistence events with:

- `category=persistence`
- `action=created` or `action=configured`
- `timestamp_source=scheduled_task_xml`
- action executable, arguments, working directory, author or principal, triggers, task path, and ATT&CK `T1053.005`

The targeted filesystem collector records metadata only. It emits MACB-style modification-time events for selected files:

- `category=filesystem`
- `action=modified`
- `timestamp_source=filesystem_mtime`

The walker does not crawl the artifact root by default. It maps Windows-style targets into the artifact directory and only walks configured paths. Defaults are:

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

Use `--fs-path` multiple times to restrict or extend targeted filesystem metadata collection.

## Supported Boundaries

- EVTX ingestion supports exported Event XML fixture content in `.evtx` files.
- Prefetch ingestion supports the project fixture format for process execution metadata.
- AmCache ingestion supports the project fixture format for execution and file metadata.
- Artifact files larger than 64 MiB are rejected by the parser safety guard.
- Ingest rejects output paths inside the artifact directory unless `--allow-output-in-artifacts` is explicitly set.
- `--strict` fails ingest when supported collectors encounter malformed or unparsable artifacts.
- Browser ingestion supports Chrome/Edge History and Firefox places SQLite schemas. It does not parse cookies, saved passwords, browser cache, or private browsing recovery data.
- Scheduled Task XML parsing focuses on `Exec` actions. Other action types are not normalized yet.
- Filesystem metadata collection is targeted only and records portable modification-time evidence. It does not parse NTFS journal data or raw MFT records.
- Diff scoring is rule-based and local. It does not use external threat intelligence, ML scoring, or advanced anomaly modeling.
- Correlation is limited to EVTX/Prefetch/AmCache execution evidence and browser download-to-execution candidates.
- Report output is Markdown.

## Intentional Non-Goals

These are not implementation gaps for v0.1.0:

- HTTP servers, HTML dashboards, GraphQL, queues, Kubernetes, Postgres, Redis, and cloud dependencies.
- Live response, disk image mounting, memory forensics, and full disk crawling.
- External threat-intelligence downloads or online rule updates.
- Cookie, password, browser cache, or private browsing recovery.

## v0.1 Roadmap

1. Repository foundation, CLI, domain model, SQLite migrations, CI, and docs.
2. EVTX ingestion and parser fixture tests.
3. Query and JSONL export workflows.
4. YAML detection rules and rule validation.
5. Prefetch ingestion and EVTX correlation.
6. AmCache ingestion and execution metadata correlation.
7. Fingerprint-based baseline vs incident diff engine.
8. Correlation engine for v1 attack-chain candidates.
9. Markdown report rendering with golden output tests.
10. Chrome, Edge, and Firefox browser history ingestion.
11. Scheduled Task XML parsing and targeted filesystem metadata.
12. Synthetic baseline-vs-incident demo case and reproducible report path.
13. Hardening, release workflow, final docs, fuzz seeds, benchmarks, and v0.1.0 release readiness.

## Release Readiness

Release builds are produced by `.github/workflows/release.yml` for:

- Linux amd64 and arm64
- macOS amd64 and arm64
- Windows amd64

Local release snapshots are written to `/tmp/timeline-release` by default:

```sh
make release-snapshot
```

Before tagging v0.1.0, run:

```sh
make lint
make test
make test-race
make bench
make build
make demo
make release-snapshot
./bin/timeline --help
./bin/timeline ingest --help
./bin/timeline diff --help
./bin/timeline report --help
./bin/timeline query --help
./bin/timeline export --help
./bin/timeline verify --help
./bin/timeline rules validate --help
./bin/timeline version
```

Release and security docs:

- `SECURITY.md`
- `docs/architecture.md`
- `docs/artifact-map.md`
- `docs/limitations.md`
- `docs/performance.md`
- `docs/production-readiness.md`
- `docs/compatibility.md`
- `docs/adr/0001-windows-first.md`
- `docs/adr/0002-sqlite-case-store.md`
- `docs/adr/0003-deterministic-event-ids.md`
- `docs/adr/0004-raw-ref-instead-of-raw-blobs.md`
- `docs/adr/0005-baseline-diff-fingerprints.md`

## Development

```sh
make lint
make test
make test-race
make bench
make build
make demo
make release-snapshot
make clean
```

Forensic safety constraints:

- No network calls during analysis.
- Read artifact inputs read-only.
- Store raw references instead of raw artifact blobs by default.
- Use analyst-safe wording such as "consistent with", "candidate", and "requires validation".
