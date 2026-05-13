# Performance

This page records measured local performance for the current v0.1.0 technical-preview workflow. The numbers are local gate results, not broad production scale claims.

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
BenchmarkIngestWindowsFixture-12      36    28260895 ns/op     1891610 B/op      22305 allocs/op
BenchmarkSyntheticLargeCase-12         1  1049817039 ns/op   137052520 B/op    4401216 allocs/op
BenchmarkQueryFixture-12             570     2068061 ns/op      110499 B/op       2042 allocs/op
```

## Coverage

The current benchmark gate covers:

- fixture ingest with EVTX-derived records, browser history, scheduled tasks, filesystem metadata, detections, and correlations;
- fixture query by category;
- high-severity process query over a synthetic 100k-event SQLite case.

The integration test suite also exercises a 10k baseline plus 10k incident synthetic corpus through query, JSONL export, diff, and report generation.

## Still Required Before Controlled Production Use

The following scale gates still need broader coverage:

- 1M synthetic event ingest without memory exhaustion;
- JSONL export benchmark on 100k and larger event sets;
- diff fingerprint benchmark on 100k and larger baseline/incident databases;
- Markdown report benchmark on larger incident databases;
- peak-memory measurement outside Go allocation counters;
- SQLite database size measurement across artifact mixes;
- repeated benchmark runs on Linux and Windows hosts.

Use this command for the current local gate:

```sh
make bench
```
