# AGENTS.md

## Project

`timeline` is a Windows-first DFIR timeline diff engine.

It ingests Windows forensic artifacts, normalizes them into a SQLite evidence database, compares baseline vs incident states, and generates a concise Markdown attack-chain report.

This is a CLI tool, not a web service.

## Core Rules

- Produce working Go code.
- Keep the repo buildable after every change.
- No stubs.
- No TODOs.
- No commented-out code.
- Never delete existing tests.
- Add or update tests for every behavior change.
- Preserve forensic safety: read-only artifact access, deterministic IDs, no network calls during analysis.
- Use analyst-safe wording. Never claim an event proves compromise.
- Do not add HTTP servers, Postgres, Redis, queues, Kubernetes, GraphQL, ORMs, or cloud dependencies.

## Stack

- Go
- Cobra CLI
- SQLite
- `log/slog`
- YAML rules
- Go templates for Markdown reports
- GitHub Actions CI

## Architecture

CLI -> app service -> collectors/diff/detect/correlate/report -> store/domain.

Domain types must not import CLI, store, collector, or report packages.

Store owns SQLite access and migrations.

Collectors emit normalized `TimelineEvent` values and do not write reports.

Detection rules operate on stored normalized events.

Diff compares baseline and incident databases using category-specific fingerprints, not raw event IDs.

Reports render existing diff, detection, correlation, and event data. Report generation must not mutate evidence data.

## Required Repository Layout

```text
/cmd/timeline/
/internal/app/
/internal/artifact/
/internal/collector/
/internal/domain/
/internal/normalize/
/internal/store/
/internal/detect/
/internal/diff/
/internal/correlate/
/internal/report/
/internal/export/
/internal/version/
/rules/
/docs/
/testdata/
/scripts/
/.github/workflows/
```

## Required CLI Commands

- `timeline ingest <artifact-dir> --os windows --out <case.db>`
- `timeline diff <baseline.db> <incident.db> --out <report.md>`
- `timeline report <case.db> --format md --out <report.md>`
- `timeline query <case.db> [filters]`
- `timeline export <case.db> --format jsonl --out <events.jsonl>`
- `timeline verify <case.db>`
- `timeline rules validate <rules-dir>`

Every command must return clear human-readable errors.

## Windows Artifact Priority

1. EVTX
2. Prefetch
3. AmCache
4. Diff engine
5. YAML detection rules
6. Correlation engine
7. Markdown report
8. Browser history
9. Scheduled Tasks
10. Targeted filesystem metadata

Do not implement live response, disk image mounting, memory forensics, or full disk crawling in v0.1.

## Required Event Fields

- `schema_version`
- `tool_version`
- `parser_name`
- `parser_version`
- `id`
- `case_id`
- `host_id` when known
- `source_type`
- `source_path`
- `source_record_id` when known
- `raw_ref`
- `timestamp_ns`
- `timestamp_precision`
- `timestamp_source`
- `category`
- `action`
- `severity`
- `confidence`
- `evidence_strength`
- `actor`
- `object`
- `network`
- `tags`
- `mitre_techniques`

Use deterministic SHA-256 event IDs.

Do not store raw artifact blobs in SQLite by default. Store `raw_ref`.

## SQLite

Use migrations.

Required tables:

- `schema_migrations`
- `cases`
- `artifacts`
- `events`
- `event_relations`
- `detections`
- `diff_results`

Indexes are required on:

- case/time
- severity
- category
- process image
- object path
- network destination
- session ID
- detection rule ID

Use explicit column lists. No `SELECT *`.

## Detection Rules

Rules live in `/rules` and use YAML.

Supported operators:

- `equals`
- `equals_ci`
- `contains`
- `contains_ci`
- `prefix`
- `suffix`
- `regex`
- `regex_ci`
- `in`
- `exists`
- `not_exists`

## Diff Engine

Compare baseline and incident using fingerprints.

Do not compare raw event IDs directly.

Normalize fingerprints by:

- lowercasing paths
- collapsing whitespace
- replacing usernames with `<USER>`
- replacing GUIDs with `<GUID>`
- replacing long base64 blobs with `<BASE64>`
- replacing timestamps with `<TIME>`
- replacing random temp names with `<RANDOM>`

Required diff types:

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

## Correlation

Implement these v1 correlations:

- failed logons -> successful logon
- successful remote logon -> process execution
- browser download -> file execution
- process execution -> network connection
- suspicious process -> persistence event
- persistence event -> later execution
- PowerShell script block -> process/network event

## Reports

Markdown report sections:

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

Reports must cite event IDs and source paths.

Use cautious wording:

- consistent with
- candidate
- requires validation

Do not write:

- proves compromise
- definitely malicious
- impossible legitimately

## Testing

Use unit tests, integration tests, golden report tests, parser fixture tests, and fuzz tests where practical.

Required test areas:

- timestamp conversion
- deterministic event IDs
- SQLite migrations
- malformed artifacts
- invalid YAML rules
- empty artifact directories
- query filters
- JSONL validity
- diff fingerprint normalization
- false-positive avoidance in correlation
- report golden output

## Required Makefile Targets

- `make lint`
- `make test`
- `make build`
- `make demo`
- `make clean`

## Security

- No network calls during analysis.
- Read artifacts read-only.
- Validate and clean all paths.
- Prevent path traversal.
- Never log secrets.
- Never emit stack traces to users.
- Do not commit generated `.db`, `.sqlite`, `.evtx`, large logs, or real user artifacts.

## After Each Phase

1. Run tests.
2. Update README if behavior changed.
3. Update docs if architecture changed.
4. Provide a short phase summary:
   - implemented
   - tests added
   - known limitations
   - next recommended phase
