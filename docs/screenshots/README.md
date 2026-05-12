# Demo Text Captures

`make demo` writes generated demo artifacts and text captures under `/tmp/timeline-demo-output/` by default.

Expected generated files:

- `/tmp/timeline-demo-output/baseline.db`
- `/tmp/timeline-demo-output/incident.db`
- `/tmp/timeline-demo-output/report.md`
- `/tmp/timeline-demo-output/events.jsonl`
- `/tmp/timeline-demo-output/cli-output.txt`

Use `DEMO_DIR=<path> make demo` to write captures elsewhere. Generated SQLite databases and `.evtx`-named synthetic Event XML fixtures are ignored by git.
