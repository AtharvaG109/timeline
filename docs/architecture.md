# Architecture

`timeline` is a Windows-first DFIR timeline diff CLI. It ingests exported or collected artifact copies, normalizes records into a SQLite evidence database, compares baseline and incident states, applies local detection rules, correlates related evidence, and renders Markdown reports.

## Component Flow

```text
cmd/timeline
  |
  v
internal/app
  |
  +--> internal/collector/*
  |      |
  |      v
  |    internal/domain
  |
  +--> internal/detect
  +--> internal/diff
  +--> internal/correlate
  +--> internal/report
  +--> internal/export
  |
  v
internal/store
```

## Boundaries

- `cmd/timeline` owns Cobra command wiring and user-facing command flags.
- `internal/app` coordinates command workflows and converts lower-level errors into clear CLI errors.
- `internal/domain` defines normalized evidence types and deterministic event ID generation.
- `internal/store` owns SQLite access, migrations, verification, and query APIs.
- `internal/collector/*` reads artifact copies and emits normalized `TimelineEvent` values.
- `internal/detect` loads local YAML rules, evaluates events, and produces detection records.
- `internal/diff` compares baseline and incident databases with normalized fingerprints.
- `internal/correlate` links related evidence across collectors.
- `internal/report` renders read-only Markdown reports from stored data.
- `internal/export` serializes normalized events to JSONL.

Domain types do not import CLI, store, collector, or report packages. Collectors do not write reports. Reports do not mutate evidence data.

## Data Model

SQLite migrations create:

- `schema_migrations`
- `cases`
- `artifacts`
- `events`
- `event_relations`
- `detections`
- `diff_results`

Indexes cover case/time, severity, category, process image, object path, network destination, session ID, and detection rule ID. SQL queries use explicit column lists.

## Event Identity

Event IDs are deterministic SHA-256 values over:

```text
schema_version
source_type
source_path
source_record_id
timestamp_ns
category
action
actor_image
actor_cmdline
object_path
net_dst_ip
net_dst_port
```

Raw artifact blobs are not stored by default. Events store `raw_ref` values that point back to the source path and record identifier when available.

## Diff Design

Diff compares normalized fingerprints rather than raw event IDs. Fingerprints normalize paths, whitespace, usernames, GUIDs, base64-like blobs, timestamps, and random temporary names so baseline-vs-incident comparisons are stable across common environment noise.

## Safety Model

`timeline` analyzes local artifact copies only. It intentionally does not perform live response, full disk crawling by default, disk image mounting, memory forensics, external downloads, or cloud upload. Targeted filesystem metadata collection is limited to configured Windows-style paths under the artifact directory.
