# Performance

This page records measured local performance for the current v0.1.0 technical-preview workflow. The numbers are not production scale claims.

## Environment

```text
goos: darwin
goarch: amd64
cpu: Intel(R) Core(TM) i7-8850H CPU @ 2.60GHz
```

## Benchmark Snapshot

Command:

```sh
make bench
```

Result:

```text
BenchmarkIngestWindowsFixture-12    38     31304981 ns/op    1892253 B/op    22305 allocs/op
BenchmarkQueryFixture-12            481     2202464 ns/op     111285 B/op     2049 allocs/op
```

## Required Before Controlled Production Use

The following are still required:

- ingest 100k synthetic events;
- ingest 1M synthetic events if practical;
- query high-severity events on large datasets;
- query by category on large datasets;
- JSONL export on large datasets;
- diff fingerprint generation on large datasets;
- Markdown report generation on larger incident databases;
- peak-memory measurement where practical;
- SQLite database size measurement.

Use:

```sh
make bench
```

The current `make bench` target covers the fixture ingest and query smoke benchmarks. It is a baseline, not a scale gate.
