# ADR 0005: Baseline Diff Fingerprints

## Status

Accepted for v0.1.0.

## Context

Deterministic event IDs are useful for citation and reproducibility, but baseline-vs-incident comparison should not compare raw event IDs directly. Benign timestamp shifts, usernames, GUIDs, temporary names, and other environmental noise can make equivalent behavior look different.

## Decision

Diff compares category-specific normalized fingerprints. Fingerprint normalization lowercases paths, collapses repeated whitespace, and replaces usernames, GUIDs, long base64 strings, timestamps, and random temporary names with placeholders.

## Consequences

- Diffing is more stable across repeated activity and common environment noise.
- New behavior can be highlighted without depending on raw event IDs.
- Fingerprint normalization must be carefully tested to avoid hiding meaningful behavior.
- Parser or normalization changes that affect fingerprints must be documented in release notes.
