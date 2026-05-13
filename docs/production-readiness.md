# Production Readiness

## Current Status

```text
RELEASE CANDIDATE
```

`timeline` is portfolio-ready and v0.1.0 release-candidate ready after the local hardening gates listed below. It is not yet production-ready for real incident response because native parser validation, signed release artifacts, and broader corpus validation are still pending.

Use this release-status wording:

```text
timeline is currently a v0.1.0 technical preview and portfolio release. It demonstrates Windows artifact normalization, baseline-vs-incident diffing, rule-based detection, event correlation, and Markdown report generation. It should not yet be used as the sole tool for real incident response decisions.
```

Do not use this wording yet:

```text
Production-ready for controlled Windows DFIR timeline-diff analysis.
```

## Production-Ready Definition

Production-ready means a security engineer can clone the repo, run the demo, ingest realistic Windows artifacts, inspect the generated SQLite database and Markdown report, trust that the tool does not mutate evidence, and understand exactly what the tool can and cannot conclude.

Production-ready does not mean the tool supports every artifact type. It means the supported workflow is reliable, tested, documented, and safe.

## Gates

### Gate 1: Correctness

- Native or otherwise defensible EVTX parsing validated against multiple realistic fixtures.
- Prefetch parsing validated across multiple Windows versions where possible.
- AmCache parsing validated against realistic hives.
- Browser timestamp conversion tested for Chrome, Edge, and Firefox.
- Stable deterministic event IDs.
- Diff fingerprinting ignores benign noise and preserves meaningful behavior.
- Detection rules have positive and negative tests.
- Correlation avoids unrelated links outside defined windows.

### Gate 2: Parser Robustness

- Malformed files do not crash the process.
- Empty and truncated files return clear outcomes.
- Oversized files follow documented policy.
- Unsupported records are skipped and counted.
- Parser boundary panics are recovered and converted into contextual errors where practical.
- Default mode continues with parser warnings.
- Strict mode fails ingest when supported collectors encounter malformed or unparsable artifacts.

### Gate 3: Forensic Safety

- No network calls during parsing.
- Artifacts are opened read-only.
- Output paths inside artifact directories are rejected unless `--allow-output-in-artifacts` is set.
- Path traversal is blocked.
- Raw blobs are not stored in SQLite by default.
- `raw_ref` preserves source path and record references when available.
- Reports use analyst-safe wording.

### Gate 4: Reproducibility

- Same input produces stable event IDs.
- Schema version, tool version, parser versions, and rule identity are recorded.
- Report generation is deterministic for the same database.
- JSONL export is stable and timestamp sorted.
- `timeline verify` checks schema, enums, timestamps, JSON fields, relations, detections, and future schema behavior.

### Gate 5: Scale and Performance

- Demo case remains quick from a fresh clone.
- 100k synthetic events remain usable for high-severity query coverage.
- 10k baseline plus 10k incident synthetic corpus exercises query, JSONL export, diff, and report generation in tests.
- 1M synthetic event ingest does not exhaust memory where practical.
- `docs/performance.md` contains measured numbers.

### Gate 6: Security Hardening

Required command set:

```sh
make lint
make test
make test-race
make security
```

`make security` runs pinned `staticcheck`, scoped `gosec`, and `govulncheck`. These tools require network access the first time they are downloaded.

### Gate 7: Release Engineering

- `timeline version` prints version metadata.
- Build flags inject version, commit, and date.
- GitHub CI passes remotely.
- Tagged release workflow builds cross-platform archives.
- Checksums are generated.
- `make release-snapshot` builds local cross-platform archives, checksums, and a Go module SBOM under `/tmp/timeline-release` by default.
- The GitHub release workflow generates release archives, `checksums.txt`, and `sbom-go-modules.json`.
- Signed checksums or signed artifacts are still required before production-ready status.

### Gate 8: Documentation

Required docs are present:

- `README.md`
- `SECURITY.md`
- `docs/architecture.md`
- `docs/artifact-map.md`
- `docs/sample-report.md`
- `docs/limitations.md`
- `docs/performance.md`
- `docs/production-readiness.md`
- `docs/compatibility.md`
- ADRs under `docs/adr/`

### Gate 9: Demo Quality

`make demo` must generate:

```text
baseline.db
incident.db
report.md
events.jsonl
```

The demo must remain synthetic and free of real credentials, malware, private logs, or sensitive user artifacts.

### Gate 10: Compatibility Policy

`docs/compatibility.md` documents database schema, rule schema, report stability, event ID stability, and parser behavior policy.

## Required Final Command Set

Do not call the project production-ready until this command set passes locally and remotely:

```sh
make lint
make test
make test-race
make bench
make security
make build
make demo
make release-snapshot
```

Then confirm:

- GitHub CI is green.
- Release workflow is green.
- Demo works from a fresh clone.
- Sample report is accurate.
- Artifact support table is honest.
- Limitations are documented.
- Generated evidence files are not committed.
- No secrets are committed.
- Release artifacts include checksums.
- SBOM exists.
- Signed checksums or signed artifacts exist where practical.
- Compatibility policy exists.

## Next Phases

1. Native EVTX parser hardening.
2. Prefetch and AmCache correctness.
3. Large-corpus and false-positive testing.
4. Performance and scale hardening.
5. Release hardening with signed checksums or signed binaries.
6. Compatibility and migration tests.
7. Final production-readiness review in `docs/production-readiness-review.md`.
