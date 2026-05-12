# Compatibility Policy

## Database Schema

- SQLite schema changes use explicit migrations.
- v0.x releases may include breaking schema changes.
- v1.0 and later releases should provide migration paths or clearly documented incompatibility.
- `timeline verify` rejects databases with missing required tables or indexes.
- Unsupported future schema versions fail clearly.

## Rule Schema

- Detection rules are YAML files under `rules/`.
- Rule schema changes must be documented in release notes.
- Invalid rules must fail validation with file context when possible.
- Future rule schema versions should be explicit before production-ready status is claimed.

## Reports

- Markdown report section names are part of the analyst-facing contract.
- Report byte-for-byte stability is not promised across minor releases.
- Reports must remain analyst-safe and cite event IDs and source paths.

## Event IDs

- Event IDs should remain stable for the same normalized event input.
- Parser normalization changes may change event IDs.
- Event ID affecting changes must be documented in release notes.

## Parser Behavior

- Unsupported records should be skipped and counted.
- Malformed artifacts should produce clear errors or parser warnings.
- Parser behavior changes must be covered by tests and documented in release notes.
