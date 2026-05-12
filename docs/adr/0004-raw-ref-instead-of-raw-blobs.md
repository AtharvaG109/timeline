# ADR 0004: Raw References Instead of Raw Blobs

## Status

Accepted for v0.1.0.

## Context

Forensic artifacts can contain credentials, private user data, regulated data, and large binary records. Storing raw artifacts inside the SQLite case database by default would increase privacy risk, database size, and accidental disclosure risk.

## Decision

Store normalized event data and `raw_ref` metadata by default. `raw_ref` points back to the source path and record identifier when available. Do not store raw artifact blobs in SQLite by default.

## Consequences

- Case databases are smaller and easier to inspect.
- Analysts can trace normalized events back to the source artifact.
- The original evidence directory remains the source of truth for raw bytes.
- Any future raw-blob storage feature must be explicit, documented, and covered by security tests.
