# Release Checklist

Use this checklist before publishing timeline changes or tagging a release.

## Local Gates

```bash
make lint
make test
make test-race
make build
make demo
make release-snapshot
```

Run `make security` before release candidates or security-sensitive changes.

## Forensic Safety Review

- Artifact access remains read-only.
- Event IDs remain deterministic.
- No network calls occur during analysis.
- Reports use wording such as `candidate`, `consistent with`, and `requires validation`.
- Generated `.db`, `.sqlite`, `.evtx`, `.jsonl`, archives, and real user artifacts are not committed.

## Release Readiness

- CI and release workflows pass.
- README command examples match CLI behavior.
- `SECURITY.md` and docs match the current support and evidence-handling model.
- Demo output is synthetic and regenerated from fixtures.
