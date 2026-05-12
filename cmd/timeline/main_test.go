package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"timeline/internal/app"
	"timeline/internal/domain"
	"timeline/internal/store"
)

func TestRootHelpOutput(t *testing.T) {
	cmd := newRootCommand(app.New(slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))))
	output := &bytes.Buffer{}
	cmd.SetOut(output)
	cmd.SetErr(output)
	cmd.SetArgs([]string{"--help"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("help returned error: %v", err)
	}

	help := output.String()
	for _, want := range []string{"timeline", "ingest", "diff", "report", "query", "export", "verify", "rules"} {
		if !strings.Contains(help, want) {
			t.Fatalf("help output missing %q:\n%s", want, help)
		}
	}
}

func TestRequiredCommandHelpOutput(t *testing.T) {
	commands := [][]string{
		{"ingest", "--help"},
		{"diff", "--help"},
		{"report", "--help"},
		{"query", "--help"},
		{"export", "--help"},
		{"verify", "--help"},
		{"rules", "validate", "--help"},
		{"version", "--help"},
	}
	for _, args := range commands {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			cmd := newRootCommand(app.New(slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))))
			output := &bytes.Buffer{}
			cmd.SetOut(output)
			cmd.SetErr(output)
			cmd.SetArgs(args)
			if err := cmd.Execute(); err != nil {
				t.Fatalf("help returned error: %v", err)
			}
			if !strings.Contains(output.String(), "Usage:") {
				t.Fatalf("help output missing Usage:\n%s", output.String())
			}
		})
	}
}

func TestVersionCommandOutput(t *testing.T) {
	cmd := newRootCommand(app.New(slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))))
	output := &bytes.Buffer{}
	cmd.SetOut(output)
	cmd.SetErr(output)
	cmd.SetArgs([]string{"version"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("version returned error: %v", err)
	}
	if !strings.Contains(output.String(), "timeline version=") || !strings.Contains(output.String(), "commit=") || !strings.Contains(output.String(), "date=") {
		t.Fatalf("version output missing metadata: %s", output.String())
	}
}

func TestVerifyEmptyDatabaseReturnsClearError(t *testing.T) {
	dbPath := t.TempDir() + "/empty.db"
	if err := os.WriteFile(dbPath, nil, 0o600); err != nil {
		t.Fatalf("create empty database: %v", err)
	}

	cmd := newRootCommand(app.New(slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))))
	output := &bytes.Buffer{}
	cmd.SetOut(output)
	cmd.SetErr(output)
	cmd.SetArgs([]string{"verify", dbPath})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected verify to reject an empty database")
	}
	if !strings.Contains(err.Error(), "database file is empty") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyInvalidDatabaseReturnsClearError(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "invalid.db")
	if err := os.WriteFile(dbPath, []byte("not sqlite"), 0o600); err != nil {
		t.Fatalf("create invalid database: %v", err)
	}

	cmd := newRootCommand(app.New(slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))))
	output := &bytes.Buffer{}
	cmd.SetOut(output)
	cmd.SetErr(output)
	cmd.SetArgs([]string{"verify", dbPath})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected verify to reject an invalid database")
	}
	if !strings.Contains(err.Error(), "database validation failed") {
		t.Fatalf("unexpected error: %v", err)
	}
	assertNoStackTrace(t, err.Error()+output.String())
}

func TestIngestMissingArtifactDirectoryReturnsClearError(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "case.db")
	cmd := newRootCommand(app.New(slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))))
	output := &bytes.Buffer{}
	cmd.SetOut(output)
	cmd.SetErr(output)
	cmd.SetArgs([]string{"ingest", filepath.Join(t.TempDir(), "missing"), "--os", "windows", "--out", dbPath, "--rules", "../../rules"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected missing artifact directory error")
	}
	if !strings.Contains(err.Error(), "artifact directory is not readable") {
		t.Fatalf("unexpected error: %v", err)
	}
	assertNoStackTrace(t, err.Error()+output.String())
}

func TestIngestRejectsFilesystemPathTraversal(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "case.db")
	cmd := newRootCommand(app.New(slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))))
	output := &bytes.Buffer{}
	cmd.SetOut(output)
	cmd.SetErr(output)
	cmd.SetArgs([]string{"ingest", t.TempDir(), "--os", "windows", "--out", dbPath, "--rules", "../../rules", "--fs-path", `..\outside`})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected path traversal error")
	}
	if !strings.Contains(err.Error(), "path traversal") {
		t.Fatalf("unexpected error: %v", err)
	}
	assertNoStackTrace(t, err.Error()+output.String())
}

func TestIngestRejectsOutputInsideArtifactDirectory(t *testing.T) {
	artifactDir := t.TempDir()
	dbPath := filepath.Join(artifactDir, "case.db")
	cmd := newRootCommand(app.New(slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))))
	output := &bytes.Buffer{}
	cmd.SetOut(output)
	cmd.SetErr(output)
	cmd.SetArgs([]string{"ingest", artifactDir, "--os", "windows", "--out", dbPath, "--rules", "../../rules"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected output path safety error")
	}
	if !strings.Contains(err.Error(), "output path must not be inside the artifact directory") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestStrictIngestFailsOnMalformedArtifact(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "case.db")
	cmd := newRootCommand(app.New(slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))))
	output := &bytes.Buffer{}
	cmd.SetOut(output)
	cmd.SetErr(output)
	cmd.SetArgs([]string{"ingest", "../../testdata/fixtures/windows-evtx", "--os", "windows", "--out", dbPath, "--rules", "../../rules", "--strict"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected strict ingest to fail on malformed fixture artifacts")
	}
	if !strings.Contains(err.Error(), "strict ingest failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestIngestAndQueryFixtures(t *testing.T) {
	dbPath, output, service := ingestFixtureDB(t)

	ctx := context.Background()
	db, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()
	authEvents, err := store.QueryEvents(ctx, db, store.QueryFilters{Category: "auth"})
	if err != nil {
		t.Fatalf("query auth events: %v", err)
	}
	if len(authEvents) != 1 {
		t.Fatalf("auth events = %d", len(authEvents))
	}
	processEvents, err := store.QueryEvents(ctx, db, store.QueryFilters{Category: "process"})
	if err != nil {
		t.Fatalf("query process events: %v", err)
	}
	if len(processEvents) != 5 {
		t.Fatalf("process events = %d", len(processEvents))
	}
	relations, err := store.QueryEventRelations(ctx, db)
	if err != nil {
		t.Fatalf("query event relations: %v", err)
	}
	if len(relations) == 0 {
		t.Fatal("expected Prefetch/EVTX event relation")
	}
	prefetchEvents, err := store.QueryEvents(ctx, db, store.QueryFilters{Category: "process", Process: "powershell"})
	if err != nil {
		t.Fatalf("query Prefetch process events: %v", err)
	}
	if !hasMultiSourcePrefetch(prefetchEvents) {
		t.Fatalf("Prefetch event was not upgraded to multi_source: %+v", prefetchEvents)
	}
	hashEvents, err := store.QueryEvents(ctx, db, store.QueryFilters{Hash: "0123456789abcdef"})
	if err != nil {
		t.Fatalf("query hash events: %v", err)
	}
	if !hasMultiSourceAmCache(hashEvents) {
		t.Fatalf("AmCache event was not queryable by hash or upgraded to multi_source: %+v", hashEvents)
	}
	detections, err := store.QueryDetections(ctx, db)
	if err != nil {
		t.Fatalf("query detections: %v", err)
	}
	if !hasDetection(detections, "powershell.encoded_command") {
		t.Fatalf("missing encoded PowerShell detection: %+v", detections)
	}
	if !hasDetection(detections, "persistence.scheduled_task_created") {
		t.Fatalf("missing scheduled task detection: %+v", detections)
	}
	highEvents, err := store.QueryEvents(ctx, db, store.QueryFilters{Severity: "high", Process: "powershell"})
	if err != nil {
		t.Fatalf("query high PowerShell events: %v", err)
	}
	if len(highEvents) == 0 {
		t.Fatal("encoded PowerShell fixture did not upgrade to high severity")
	}

	output.Reset()
	queryCmd := newRootCommand(service)
	queryCmd.SetOut(output)
	queryCmd.SetErr(output)
	queryCmd.SetArgs([]string{"query", dbPath, "--category", "auth"})
	if err := queryCmd.Execute(); err != nil {
		t.Fatalf("query returned error: %v", err)
	}
	if !strings.Contains(output.String(), "successful_logon") {
		t.Fatalf("query output missing auth event:\n%s", output.String())
	}

	output.Reset()
	hashCmd := newRootCommand(service)
	hashCmd.SetOut(output)
	hashCmd.SetErr(output)
	hashCmd.SetArgs([]string{"query", dbPath, "--hash", "0123456789abcdef", "--format", "json"})
	if err := hashCmd.Execute(); err != nil {
		t.Fatalf("hash query returned error: %v", err)
	}
	if !strings.Contains(output.String(), `"source_type": "amcache"`) {
		t.Fatalf("hash query output missing AmCache event:\n%s", output.String())
	}
}

func TestQueryJSONOutputAndInvalidTimestamp(t *testing.T) {
	dbPath, output, service := ingestFixtureDB(t)

	output.Reset()
	queryCmd := newRootCommand(service)
	queryCmd.SetOut(output)
	queryCmd.SetErr(output)
	queryCmd.SetArgs([]string{"query", dbPath, "--category", "process", "--format", "json"})
	if err := queryCmd.Execute(); err != nil {
		t.Fatalf("query JSON returned error: %v", err)
	}
	var rows []map[string]any
	if err := json.Unmarshal(output.Bytes(), &rows); err != nil {
		t.Fatalf("query JSON is invalid: %v\n%s", err, output.String())
	}
	if len(rows) != 5 {
		t.Fatalf("JSON rows = %d", len(rows))
	}
	if rows[0]["category"] != "process" {
		t.Fatalf("first JSON category = %v", rows[0]["category"])
	}

	output.Reset()
	badTimeCmd := newRootCommand(service)
	badTimeCmd.SetOut(output)
	badTimeCmd.SetErr(output)
	badTimeCmd.SetArgs([]string{"query", dbPath, "--from", "not-a-time"})
	err := badTimeCmd.Execute()
	if err == nil {
		t.Fatal("expected invalid timestamp error")
	}
	if !strings.Contains(err.Error(), "invalid --from timestamp") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExportJSONL(t *testing.T) {
	dbPath, output, service := ingestFixtureDB(t)
	outPath := filepath.Join(t.TempDir(), "events.jsonl")

	output.Reset()
	exportCmd := newRootCommand(service)
	exportCmd.SetOut(output)
	exportCmd.SetErr(output)
	exportCmd.SetArgs([]string{"export", dbPath, "--format", "jsonl", "--out", outPath})
	if err := exportCmd.Execute(); err != nil {
		t.Fatalf("export returned error: %v", err)
	}
	content, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read JSONL: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(lines) != 11 {
		t.Fatalf("JSONL lines = %d", len(lines))
	}
	var previous float64 = -1
	for _, line := range lines {
		if strings.HasSuffix(strings.TrimSpace(line), ",") {
			t.Fatalf("JSONL line has trailing comma: %s", line)
		}
		var row map[string]any
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			t.Fatalf("invalid JSONL line: %v\n%s", err, line)
		}
		timestamp, ok := row["timestamp_ns"].(float64)
		if !ok {
			t.Fatalf("missing timestamp_ns in line: %s", line)
		}
		if timestamp < previous {
			t.Fatalf("JSONL not sorted: %f after %f", timestamp, previous)
		}
		previous = timestamp
	}
}

func TestDiffCommandWritesReportAndResults(t *testing.T) {
	dir := t.TempDir()
	baselinePath := filepath.Join(dir, "baseline.db")
	incidentPath := filepath.Join(dir, "incident.db")
	reportPath := filepath.Join(dir, "report.md")
	createDiffFixtureDB(t, baselinePath, "baseline", []domain.TimelineEvent{
		diffTestProcess("base-1", "baseline", 100, "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe", "powershell.exe -NoProfile"),
	})
	createDiffFixtureDB(t, incidentPath, "incident", []domain.TimelineEvent{
		diffTestProcess("incident-1", "incident", 200, "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe", "powershell.exe -NoProfile -EncodedCommand SQBFAFgA"),
	})

	output := &bytes.Buffer{}
	service := app.New(slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	service.SetOutput(output)
	cmd := newRootCommand(service)
	cmd.SetOut(output)
	cmd.SetErr(output)
	cmd.SetArgs([]string{"diff", baselinePath, incidentPath, "--out", reportPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("diff returned error: %v\n%s", err, output.String())
	}
	if !strings.Contains(output.String(), "diff complete: findings=1") || !strings.Contains(output.String(), "high") {
		t.Fatalf("diff output missing summary/high finding:\n%s", output.String())
	}
	report, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("read diff report: %v", err)
	}
	if !strings.Contains(string(report), "## Executive Summary") || !strings.Contains(string(report), "new_cmdline") || !strings.Contains(string(report), "requires validation") {
		t.Fatalf("report missing diff content:\n%s", string(report))
	}
	ctx := context.Background()
	db, err := store.Open(ctx, incidentPath)
	if err != nil {
		t.Fatalf("open incident db: %v", err)
	}
	defer db.Close()
	results, err := store.QueryDiffResults(ctx, db)
	if err != nil {
		t.Fatalf("query diff results: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("diff results = %d", len(results))
	}
	if results[0].DiffType != "new_cmdline" || results[0].Severity != domain.SeverityHigh {
		t.Fatalf("unexpected diff result: %+v", results[0])
	}
}

func TestReportCommandWritesCompleteReport(t *testing.T) {
	dbPath, output, service := ingestFixtureDB(t)
	reportPath := filepath.Join(t.TempDir(), "incident-report.md")
	output.Reset()
	cmd := newRootCommand(service)
	cmd.SetOut(output)
	cmd.SetErr(output)
	cmd.SetArgs([]string{"report", dbPath, "--format", "md", "--out", reportPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("report returned error: %v\n%s", err, output.String())
	}
	content, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	report := string(content)
	for _, section := range []string{
		"## Executive Summary",
		"## High-Confidence Attack Chain",
		"## Evidence Table",
		"## Artifact Coverage",
		"## Appendix",
	} {
		if !strings.Contains(report, section) {
			t.Fatalf("report missing section %q:\n%s", section, report)
		}
	}
	if !strings.Contains(report, "Security.evtx") || !strings.Contains(report, "requires validation") {
		t.Fatalf("report missing evidence or analyst-safe wording:\n%s", report)
	}
	if !strings.Contains(output.String(), "report complete") {
		t.Fatalf("report command output missing success text: %s", output.String())
	}
}

func TestIngestBrowserFixtureAndCorrelation(t *testing.T) {
	dir := t.TempDir()
	historyPath := filepath.Join(dir, "Chrome", "Default", "History")
	createCLIChromiumHistoryFixture(t, historyPath)
	prefetchPath := filepath.Join(dir, "PAYLOAD.EXE-1234ABCD.pf")
	if err := os.WriteFile(prefetchPath, []byte("ExecutableName: C:\\Users\\alice\\Downloads\\payload.exe\nRunCount: 1\nLastRun: 2024-05-06T20:10:00Z\n"), 0o600); err != nil {
		t.Fatalf("write Prefetch fixture: %v", err)
	}

	dbPath := filepath.Join(t.TempDir(), "case.db")
	output := &bytes.Buffer{}
	service := app.New(slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	service.SetOutput(output)
	cmd := newRootCommand(service)
	cmd.SetOut(output)
	cmd.SetErr(output)
	cmd.SetArgs([]string{"ingest", dir, "--os", "windows", "--out", dbPath, "--rules", "../../rules"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("ingest returned error: %v\n%s", err, output.String())
	}
	if !strings.Contains(output.String(), "browser_files=1") {
		t.Fatalf("ingest output missing browser file count:\n%s", output.String())
	}

	ctx := context.Background()
	db, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()
	browserEvents, err := store.QueryEvents(ctx, db, store.QueryFilters{Category: "browser"})
	if err != nil {
		t.Fatalf("query browser events: %v", err)
	}
	if len(browserEvents) != 2 {
		t.Fatalf("browser events = %d", len(browserEvents))
	}
	if !hasBrowserAction(browserEvents, "visited") || !hasBrowserAction(browserEvents, "downloaded") {
		t.Fatalf("missing browser visit or download event: %+v", browserEvents)
	}
	relations, err := store.QueryEventRelations(ctx, db)
	if err != nil {
		t.Fatalf("query event relations: %v", err)
	}
	if !hasRelationType(relations, "browser_download_execution_match") {
		t.Fatalf("missing browser download correlation: %+v", relations)
	}

	output.Reset()
	queryCmd := newRootCommand(service)
	queryCmd.SetOut(output)
	queryCmd.SetErr(output)
	queryCmd.SetArgs([]string{"query", dbPath, "--category", "browser"})
	if err := queryCmd.Execute(); err != nil {
		t.Fatalf("query returned error: %v", err)
	}
	if !strings.Contains(output.String(), "downloaded") {
		t.Fatalf("query output missing browser download:\n%s", output.String())
	}
}

func TestIngestScheduledTaskAndTargetedFilesystem(t *testing.T) {
	dir := t.TempDir()
	taskPath := filepath.Join(dir, "Windows", "System32", "Tasks", "CacheTask.xml")
	if err := os.MkdirAll(filepath.Dir(taskPath), 0o755); err != nil {
		t.Fatalf("create task dir: %v", err)
	}
	if err := os.WriteFile(taskPath, []byte(cliScheduledTaskXML), 0o600); err != nil {
		t.Fatalf("write scheduled task fixture: %v", err)
	}
	downloadPath := filepath.Join(dir, "Users", "alice", "Downloads", "payload.exe")
	if err := os.MkdirAll(filepath.Dir(downloadPath), 0o755); err != nil {
		t.Fatalf("create download dir: %v", err)
	}
	if err := os.WriteFile(downloadPath, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write filesystem fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "root-payload.exe"), []byte("ignored"), 0o600); err != nil {
		t.Fatalf("write root fixture: %v", err)
	}

	dbPath := filepath.Join(t.TempDir(), "case.db")
	output := &bytes.Buffer{}
	service := app.New(slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	service.SetOutput(output)
	cmd := newRootCommand(service)
	cmd.SetOut(output)
	cmd.SetErr(output)
	cmd.SetArgs([]string{"ingest", dir, "--os", "windows", "--out", dbPath, "--rules", "../../rules", "--fs-path", `C:\Users\*\Downloads\`})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("ingest returned error: %v\n%s", err, output.String())
	}
	if !strings.Contains(output.String(), "scheduled_task_files=1") || !strings.Contains(output.String(), "filesystem_files=1") {
		t.Fatalf("ingest output missing Phase 11 counts:\n%s", output.String())
	}

	ctx := context.Background()
	db, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()
	persistenceEvents, err := store.QueryEvents(ctx, db, store.QueryFilters{Category: "persistence"})
	if err != nil {
		t.Fatalf("query persistence events: %v", err)
	}
	if len(persistenceEvents) != 1 || persistenceEvents[0].TimestampSource != "scheduled_task_xml" {
		t.Fatalf("scheduled task event not normalized: %+v", persistenceEvents)
	}
	filesystemEvents, err := store.QueryEvents(ctx, db, store.QueryFilters{Category: "filesystem"})
	if err != nil {
		t.Fatalf("query filesystem events: %v", err)
	}
	if len(filesystemEvents) != 1 {
		t.Fatalf("filesystem events = %d: %+v", len(filesystemEvents), filesystemEvents)
	}
	if filesystemEvents[0].Object.Path != `C:\Users\alice\Downloads\payload.exe` {
		t.Fatalf("filesystem object path = %q", filesystemEvents[0].Object.Path)
	}
	if strings.Contains(filesystemEvents[0].Object.Path, "root-payload") {
		t.Fatalf("filesystem walker crawled root file: %+v", filesystemEvents[0])
	}
}

func TestRulesValidateCommand(t *testing.T) {
	output := &bytes.Buffer{}
	service := app.New(slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	service.SetOutput(output)
	cmd := newRootCommand(service)
	cmd.SetOut(output)
	cmd.SetErr(output)
	cmd.SetArgs([]string{"rules", "validate", "../../rules"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("rules validate returned error: %v", err)
	}
	if !strings.Contains(output.String(), "rules valid") {
		t.Fatalf("rules validate output missing success text: %s", output.String())
	}
}

func TestMakeDemoGeneratesReport(t *testing.T) {
	repoRoot := filepath.Clean(filepath.Join("..", ".."))
	demoDir := filepath.Join(t.TempDir(), "demo")
	cmd := exec.Command("make", "demo", "DEMO_DIR="+demoDir)
	cmd.Dir = repoRoot
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("make demo failed: %v\n%s", err, string(output))
	}
	for _, path := range []string{
		filepath.Join(demoDir, "baseline.db"),
		filepath.Join(demoDir, "incident.db"),
		filepath.Join(demoDir, "report.md"),
		filepath.Join(demoDir, "events.jsonl"),
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("expected generated demo file %s: %v\n%s", path, err, string(output))
		}
		if info.Size() == 0 {
			t.Fatalf("generated demo file is empty: %s", path)
		}
	}
	reportContent, err := os.ReadFile(filepath.Join(demoDir, "report.md"))
	if err != nil {
		t.Fatalf("read demo report: %v", err)
	}
	report := string(reportContent)
	for _, want := range []string{
		"## High-Confidence Attack Chain",
		"failed_logon",
		"successful_logon",
		"Encoded PowerShell",
		"C:\\Users\\Public\\demo-payload.exe",
		"scheduled_task",
		"network_connection",
		"Browser and Download Findings",
	} {
		if !strings.Contains(report, want) {
			t.Fatalf("demo report missing %q:\n%s", want, report)
		}
	}
}

func TestGeneratedDemoDatabaseFilesAreIgnored(t *testing.T) {
	content, err := os.ReadFile(filepath.Join("..", "..", ".gitignore"))
	if err != nil {
		t.Fatalf("read .gitignore: %v", err)
	}
	ignore := string(content)
	for _, want := range []string{"*.db", "*.sqlite", "*.evtx", "*.pf", "*.hve", "*.log", "*.jsonl", ".env", "*.pem", "*.key", "demo-output/", "dist/"} {
		if !strings.Contains(ignore, want) {
			t.Fatalf(".gitignore missing %q:\n%s", want, ignore)
		}
	}
}

func TestProductionReadinessDocsExist(t *testing.T) {
	required := []string{
		"README.md",
		"SECURITY.md",
		"LICENSE",
		"docs/architecture.md",
		"docs/artifact-map.md",
		"docs/sample-report.md",
		"docs/limitations.md",
		"docs/performance.md",
		"docs/production-readiness.md",
		"docs/compatibility.md",
		"docs/adr/0001-windows-first.md",
		"docs/adr/0002-sqlite-case-store.md",
		"docs/adr/0003-deterministic-event-ids.md",
		"docs/adr/0004-raw-ref-instead-of-raw-blobs.md",
		"docs/adr/0005-baseline-diff-fingerprints.md",
	}
	for _, path := range required {
		content, err := os.ReadFile(filepath.Join("..", "..", path))
		if err != nil {
			t.Fatalf("missing required doc %s: %v", path, err)
		}
		if len(strings.TrimSpace(string(content))) == 0 {
			t.Fatalf("required doc is empty: %s", path)
		}
	}
}

func TestDemoFixturesContainNoRealSecrets(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "demo-case")
	forbidden := []string{"password", "secret", "token", "apikey", "begin private key", "authorization:"}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		lower := strings.ToLower(string(content))
		for _, needle := range forbidden {
			if strings.Contains(lower, needle) {
				t.Fatalf("demo fixture %s contains forbidden secret marker %q", path, needle)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scan demo fixtures: %v", err)
	}
}

func TestRepositoryContainsNoHighRiskSecretMarkers(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`-----BEGIN (RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----`),
		regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		regexp.MustCompile(`(?i)(api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*['"][^'"]{12,}['"]`),
		regexp.MustCompile(`(?i)authorization:\s*bearer\s+[a-z0-9._~+/=-]{20,}`),
	}
	skipDirs := map[string]bool{
		".git":   true,
		".cache": true,
		"bin":    true,
		"dist":   true,
	}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if skipDirs[entry.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Size() > 1<<20 {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, pattern := range patterns {
			if pattern.Match(content) {
				t.Fatalf("high-risk secret marker found in %s", path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scan repository secret markers: %v", err)
	}
}

func BenchmarkIngestWindowsFixture(b *testing.B) {
	repoRoot := filepath.Clean(filepath.Join("..", ".."))
	artifactDir := filepath.Join(repoRoot, "testdata", "fixtures", "windows-evtx")
	rulesDir := filepath.Join(repoRoot, "rules")
	service := app.New(slog.New(slog.NewTextHandler(ioDiscard{}, nil)))
	service.SetOutput(nil)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		dbPath := filepath.Join(b.TempDir(), "case.db")
		if err := service.Ingest(context.Background(), app.IngestOptions{
			ArtifactDir: artifactDir,
			OS:          "windows",
			OutPath:     dbPath,
			RulesDir:    rulesDir,
		}); err != nil {
			b.Fatalf("ingest fixture: %v", err)
		}
	}
}

func BenchmarkQueryFixture(b *testing.B) {
	dbPath, _, service := ingestFixtureDBForBenchmark(b)
	service.SetOutput(nil)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := service.Query(context.Background(), app.QueryOptions{
			CaseDB:  dbPath,
			Filters: []string{"category=process", "limit=100"},
		}); err != nil {
			b.Fatalf("query fixture: %v", err)
		}
	}
}

func ingestFixtureDBForBenchmark(tb testing.TB) (string, *bytes.Buffer, *app.Service) {
	tb.Helper()
	dbPath := filepath.Join(tb.TempDir(), "case.db")
	output := &bytes.Buffer{}
	service := app.New(slog.New(slog.NewTextHandler(ioDiscard{}, nil)))
	service.SetOutput(output)
	cmd := newRootCommand(service)
	cmd.SetOut(output)
	cmd.SetErr(output)
	cmd.SetArgs([]string{"ingest", "../../testdata/fixtures/windows-evtx", "--os", "windows", "--out", dbPath, "--rules", "../../rules"})
	if err := cmd.Execute(); err != nil {
		tb.Fatalf("ingest returned error: %v\n%s", err, output.String())
	}
	return dbPath, output, service
}

func assertNoStackTrace(t *testing.T, text string) {
	t.Helper()
	for _, marker := range []string{"goroutine ", "panic:", ".go:"} {
		if strings.Contains(text, marker) {
			t.Fatalf("user-facing output contains stack trace marker %q:\n%s", marker, text)
		}
	}
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) {
	return len(p), nil
}

func ingestFixtureDB(t *testing.T) (string, *bytes.Buffer, *app.Service) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "case.db")
	output := &bytes.Buffer{}
	service := app.New(slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	service.SetOutput(output)
	cmd := newRootCommand(service)
	cmd.SetOut(output)
	cmd.SetErr(output)
	cmd.SetArgs([]string{"ingest", "../../testdata/fixtures/windows-evtx", "--os", "windows", "--out", dbPath, "--rules", "../../rules"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("ingest returned error: %v\n%s", err, output.String())
	}
	if !strings.Contains(output.String(), "events skipped=1") {
		t.Fatalf("ingest output did not include skipped count:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "malformed_amcache=1") {
		t.Fatalf("ingest output did not include malformed AmCache count:\n%s", output.String())
	}
	return dbPath, output, service
}

func createDiffFixtureDB(t *testing.T, dbPath string, caseID string, events []domain.TimelineEvent) {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("open diff fixture db: %v", err)
	}
	defer db.Close()
	if err := store.ApplyMigrations(ctx, db); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	if err := store.EnsureCase(ctx, db, store.Case{ID: caseID, Name: caseID, OS: "windows"}); err != nil {
		t.Fatalf("ensure case: %v", err)
	}
	if err := store.InsertEvents(ctx, db, events); err != nil {
		t.Fatalf("insert diff events: %v", err)
	}
}

func diffTestProcess(sourceRecordID string, caseID string, timestamp int64, image string, cmdline string) domain.TimelineEvent {
	event := domain.TimelineEvent{
		SchemaVersion:      "1",
		ToolVersion:        "test",
		ParserName:         "test",
		ParserVersion:      "test",
		CaseID:             caseID,
		SourceType:         "evtx",
		SourcePath:         "Security.evtx",
		SourceRecordID:     sourceRecordID,
		RawRef:             domain.RawRef{Type: "evtx_record", URI: "Security.evtx"},
		TimestampNS:        timestamp,
		TimestampPrecision: domain.TimestampPrecisionNanosecond,
		TimestampSource:    "test",
		Category:           "process",
		Action:             "process_created",
		Severity:           domain.SeverityMedium,
		Confidence:         domain.ConfidenceHigh,
		EvidenceStrength:   domain.EvidenceStrong,
		Actor:              domain.Actor{User: "ACME\\alice", Image: image, Cmdline: cmdline},
		Object:             domain.Object{Type: "process", Path: image},
		Tags:               []string{"windows", "process"},
	}
	event.ID = domain.GenerateEventID(event)
	return event
}

func hasDetection(detections []store.Detection, ruleID string) bool {
	for _, detection := range detections {
		if detection.RuleID == ruleID {
			return true
		}
	}
	return false
}

func hasMultiSourcePrefetch(events []domain.TimelineEvent) bool {
	for _, event := range events {
		if event.SourceType == "prefetch" && event.EvidenceStrength == domain.EvidenceMultiSource {
			return true
		}
	}
	return false
}

func hasMultiSourceAmCache(events []domain.TimelineEvent) bool {
	for _, event := range events {
		if event.SourceType == "amcache" && event.EvidenceStrength == domain.EvidenceMultiSource {
			return true
		}
	}
	return false
}

func hasBrowserAction(events []domain.TimelineEvent, action string) bool {
	for _, event := range events {
		if event.Action == action {
			return true
		}
	}
	return false
}

func hasRelationType(relations []store.EventRelation, relationType string) bool {
	for _, relation := range relations {
		if relation.Type == relationType {
			return true
		}
	}
	return false
}

func createCLIChromiumHistoryFixture(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create browser fixture dir: %v", err)
	}
	ctx := context.Background()
	db, err := store.Open(ctx, path)
	if err != nil {
		t.Fatalf("open browser fixture db: %v", err)
	}
	defer db.Close()
	execCLIFixtureSQL(t, db, `CREATE TABLE urls (
		id INTEGER PRIMARY KEY,
		url TEXT NOT NULL,
		title TEXT,
		visit_count INTEGER,
		last_visit_time INTEGER
	)`)
	execCLIFixtureSQL(t, db, `CREATE TABLE visits (
		id INTEGER PRIMARY KEY,
		url INTEGER,
		visit_time INTEGER
	)`)
	execCLIFixtureSQL(t, db, `CREATE TABLE downloads (
		id INTEGER PRIMARY KEY,
		target_path TEXT,
		current_path TEXT,
		start_time INTEGER,
		end_time INTEGER
	)`)
	execCLIFixtureSQL(t, db, `CREATE TABLE downloads_url_chains (
		id INTEGER,
		chain_index INTEGER,
		url TEXT
	)`)
	visitTime := cliWebKitTime(time.Date(2024, 5, 6, 20, 4, 12, 0, time.UTC))
	downloadStart := cliWebKitTime(time.Date(2024, 5, 6, 20, 5, 0, 0, time.UTC))
	downloadEnd := cliWebKitTime(time.Date(2024, 5, 6, 20, 5, 3, 0, time.UTC))
	execCLIFixtureSQL(t, db, `INSERT INTO urls (id, url, title, visit_count, last_visit_time) VALUES (1, 'https://example.test/', 'Example', 1, ?)`, visitTime)
	execCLIFixtureSQL(t, db, `INSERT INTO visits (id, url, visit_time) VALUES (10, 1, ?)`, visitTime)
	execCLIFixtureSQL(t, db, `INSERT INTO downloads (id, target_path, current_path, start_time, end_time) VALUES (20, 'C:\Users\alice\Downloads\payload.exe', 'C:\Users\alice\Downloads\payload.exe', ?, ?)`, downloadStart, downloadEnd)
	execCLIFixtureSQL(t, db, `INSERT INTO downloads_url_chains (id, chain_index, url) VALUES (20, 0, 'https://downloads.example.test/payload.exe')`)
}

func execCLIFixtureSQL(t *testing.T, db *sql.DB, statement string, args ...any) {
	t.Helper()
	if _, err := db.Exec(statement, args...); err != nil {
		t.Fatalf("exec browser fixture SQL %q: %v", statement, err)
	}
}

func cliWebKitTime(t time.Time) int64 {
	return t.UTC().UnixMicro() + 11644473600000000
}

const cliScheduledTaskXML = `
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2024-05-06T20:06:00Z</Date>
    <Author>ACME\alice</Author>
    <URI>\Microsoft\Windows\Updates\CacheTask</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <StartBoundary>2024-05-06T20:07:00Z</StartBoundary>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>ACME\alice</UserId>
    </Principal>
  </Principals>
  <Actions Context="Author">
    <Exec>
      <Command>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Command>
      <Arguments>-NoProfile -ExecutionPolicy Bypass -File C:\ProgramData\cache.ps1</Arguments>
      <WorkingDirectory>C:\ProgramData</WorkingDirectory>
    </Exec>
  </Actions>
</Task>`
