# Limitations

`timeline` is a v0.1.0 technical preview and portfolio release. It demonstrates the controlled Windows timeline-diff workflow, but it should not be used as the sole basis for real incident response decisions.

## Current Supported Boundaries

- EVTX ingestion supports exported Event XML fixture content in `.evtx` files.
- Prefetch ingestion supports the project fixture format for execution metadata.
- AmCache ingestion supports the project fixture format for execution and file metadata.
- Browser ingestion supports Chrome and Edge `History` databases and Firefox `places.sqlite`.
- Scheduled Task XML parsing focuses on `Exec` actions.
- Filesystem metadata collection is targeted and limited to configured paths.
- Reports are Markdown.
- Strict ingest fails after collector stats are available for supported malformed artifacts; more granular first-record strict failure remains part of parser-hardening work.

## Not Production-Ready Yet

Before controlled production use, the project needs:

- broader EVTX parser compatibility testing against realistic exported logs;
- Prefetch and AmCache validation against multiple Windows versions and realistic hives;
- larger false-positive corpora for detection, diff, and correlation;
- large-case performance validation;
- remotely confirmed CI and release workflow runs;
- signed checksums or signed artifacts where practical;
- compatibility and migration tests for future schema versions.

## Intentional Non-Goals

These are outside the v0.1.x scope:

- web dashboards and HTTP servers;
- cloud upload or external threat-intelligence downloads;
- live response agents;
- disk image mounting;
- memory forensics;
- full disk crawling by default;
- cookies, saved passwords, browser cache, or private browsing recovery;
- Kubernetes, queues, Redis, Postgres, GraphQL, or multi-user SaaS features.

## Analyst Wording

Reports identify evidence patterns consistent with suspicious activity. They do not prove malicious intent by themselves. Findings require validation against host, identity, network, and business context.
