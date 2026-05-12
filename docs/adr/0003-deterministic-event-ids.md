# ADR 0003: Deterministic Event IDs

## Status

Accepted for v0.1.0.

## Context

DFIR evidence needs stable identifiers so reports, detections, exports, and correlations can cite the same normalized event across repeated ingest runs. Random IDs make golden reports noisy and make analyst review harder.

## Decision

Generate event IDs with SHA-256 over normalized identity fields:

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

The ID is derived in `internal/domain` and stored on each `TimelineEvent`.

## Consequences

- Re-ingesting the same normalized artifact record produces the same event ID.
- Reports can cite evidence IDs that remain stable across repeated runs.
- Diff does not compare raw event IDs directly; it uses category-specific fingerprints to compare baseline and incident behavior.
- If parser normalization changes, event IDs may change and golden tests should be reviewed intentionally.
