# ADR 0002: SQLite Case Store

## Status

Accepted for v0.1.0.

## Context

`timeline` needs a local evidence store that is portable, easy to inspect, deterministic in tests, and practical for analysts who do not want to run services. The project is a CLI tool, not a web service.

## Decision

Use SQLite as the case store. The `internal/store` package owns migrations, validation, inserts, queries, detections, relations, and diff result persistence.

## Consequences

- A case database is a single local file that can be copied with the report.
- No Postgres, Redis, queues, cloud dependencies, or service setup is required.
- Tests can create and discard isolated databases quickly.
- Query performance relies on explicit indexes and bounded CLI result sets.
- SQLite schema changes must go through migrations and verification tests.
