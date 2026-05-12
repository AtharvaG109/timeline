# Security Policy

## Supported Version

`timeline` v0.1.0 is the supported release candidate.

## Reporting Security Issues

Report security issues privately to the repository owner. Do not attach real forensic artifacts, credentials, secrets, or private logs to public issues.

When reporting a problem, include:

- `timeline` version from `timeline --version`
- operating system and architecture
- command line used, with sensitive paths redacted
- sanitized fixture or minimal reproduction steps
- observed error text

## Forensic Safety Commitments

- Artifact inputs are read-only.
- Analysis does not make network calls.
- SQLite stores raw references by default, not raw artifact blobs.
- Event IDs are deterministic SHA-256 values derived from normalized event identity fields.
- Reports use analyst-safe wording and require validation against case context.
- User-facing errors should be concise and must not include stack traces.

## Artifact Handling

Do not commit generated databases, real EVTX files, Prefetch files, AmCache hives, large logs, memory dumps, packet captures, or private case material. Synthetic fixtures are allowed only when they contain no real user data and are small enough for source control review.

The `.gitignore` file blocks common generated and private forensic artifact extensions. Before publishing a release, run:

```sh
make lint
make test
make build
make demo
```

Also review `git status --short` and inspect staged files before committing.

## Dependency Policy

`timeline` is a local CLI. Do not add HTTP servers, cloud upload paths, queues, ORMs, Kubernetes manifests, or external threat-intelligence download behavior for v0.1.x.
