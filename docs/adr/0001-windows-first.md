# ADR 0001: Windows-First Scope

## Status

Accepted for v0.1.0.

## Context

The project goal is a DFIR timeline diff engine that is useful for Windows endpoint investigations from a fresh clone. Windows artifacts such as EVTX, Prefetch, AmCache, browser history, Scheduled Tasks, and targeted filesystem metadata provide the strongest initial signal for baseline-vs-incident comparison.

## Decision

`timeline` is Windows-first for v0.1.0. The CLI accepts `--os windows` for ingest, normalizes Windows artifact records into a shared domain model, and keeps non-Windows artifact parsing outside the first release.

## Consequences

- The first release can focus tests, docs, demo data, and report wording around one operating system.
- Parser and normalization behavior can use Windows path and event semantics consistently.
- Cross-platform binaries are still built so analysts can run the CLI on macOS, Linux, or Windows against copied artifacts.
- Non-Windows artifact support requires a later ADR and test plan.
