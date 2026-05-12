# Demo Case Fixtures

This directory contains synthetic source artifacts for `make demo`.

- `baseline` contains a minimal benign Windows Event XML source.
- `incident` contains synthetic Windows Event XML, Scheduled Task XML, browser history metadata, and a safe text payload fixture.

The demo generator materializes ignored runtime artifacts under `demo-output/`, including SQLite databases and `.evtx`-named Event XML fixtures. The source files here use reserved domains and documentation IP ranges only.
