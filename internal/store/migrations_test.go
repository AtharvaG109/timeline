package store

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

func TestApplyMigrationsCreatesRequiredSchema(t *testing.T) {
	ctx := context.Background()
	dbPath := t.TempDir() + "/case.db"
	db, err := Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("Open error: %v", err)
	}
	defer db.Close()

	if err := ApplyMigrations(ctx, db); err != nil {
		t.Fatalf("ApplyMigrations error: %v", err)
	}
	if err := VerifyDatabase(ctx, dbPath); err != nil {
		t.Fatalf("VerifyDatabase error: %v", err)
	}

	for _, table := range requiredTables {
		var name string
		err := db.QueryRowContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&name)
		if err != nil {
			t.Fatalf("table %s missing: %v", table, err)
		}
	}

	for _, index := range requiredIndexes {
		var name string
		err := db.QueryRowContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'index' AND name = ?`, index).Scan(&name)
		if err != nil {
			t.Fatalf("index %s missing: %v", index, err)
		}
	}
}

func TestVerifyDatabaseRejectsEmptyFile(t *testing.T) {
	ctx := context.Background()
	dbPath := t.TempDir() + "/empty.db"
	if err := os.WriteFile(dbPath, nil, 0o600); err != nil {
		t.Fatalf("create empty db: %v", err)
	}

	err := VerifyDatabase(ctx, dbPath)
	if err == nil {
		t.Fatal("expected empty database error")
	}
}

func TestVerifyDatabaseRejectsMissingTables(t *testing.T) {
	ctx := context.Background()
	dbPath := t.TempDir() + "/invalid.db"
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE unrelated (id TEXT PRIMARY KEY)`); err != nil {
		t.Fatalf("create unrelated table: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}

	err = VerifyDatabase(ctx, dbPath)
	if err == nil {
		t.Fatal("expected schema validation error")
	}
}

func TestVerifyDatabaseRejectsFutureSchema(t *testing.T) {
	ctx := context.Background()
	dbPath := t.TempDir() + "/future.db"
	db, err := Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("Open error: %v", err)
	}
	if err := ApplyMigrations(ctx, db); err != nil {
		t.Fatalf("ApplyMigrations error: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT OR REPLACE INTO schema_migrations (version, name) VALUES (?, ?)`, CurrentSchemaVersion+1, "future"); err != nil {
		t.Fatalf("insert future schema: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}

	err = VerifyDatabase(ctx, dbPath)
	if err == nil {
		t.Fatal("expected future schema validation error")
	}
	if !strings.Contains(err.Error(), "newer than supported") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyDatabaseRejectsCorruptEventJSON(t *testing.T) {
	dbPath := t.TempDir() + "/case.db"
	db, err := Open(context.Background(), dbPath)
	if err != nil {
		t.Fatalf("Open error: %v", err)
	}
	if err := ApplyMigrations(context.Background(), db); err != nil {
		t.Fatalf("ApplyMigrations error: %v", err)
	}
	if err := EnsureCase(context.Background(), db, Case{ID: "case-1", Name: "case", OS: "windows"}); err != nil {
		t.Fatalf("EnsureCase error: %v", err)
	}
	_, err = db.ExecContext(context.Background(), `INSERT INTO events (
		id,
		schema_version,
		tool_version,
		parser_name,
		parser_version,
		case_id,
		source_type,
		source_path,
		raw_ref_json,
		timestamp_ns,
		timestamp_precision,
		timestamp_source,
		category,
		action,
		severity,
		confidence,
		evidence_strength,
		actor_json,
		object_json,
		network_json,
		tags_json,
		mitre_techniques_json
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"event-1",
		"1",
		"test",
		"test",
		"test",
		"case-1",
		"evtx",
		"Security.evtx",
		"{",
		1,
		"nanosecond",
		"test",
		"auth",
		"successful_logon",
		"medium",
		"high",
		"single_source",
		"{}",
		"{}",
		"{}",
		"[]",
		"[]",
	)
	if err != nil {
		t.Fatalf("insert corrupt event: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}

	err = VerifyDatabase(context.Background(), dbPath)
	if err == nil {
		t.Fatal("expected corrupt JSON validation error")
	}
	if !strings.Contains(err.Error(), "corrupt JSON") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyDatabaseRejectsBrokenRelationsAndOrphanDetections(t *testing.T) {
	ctx := context.Background()
	dbPath := t.TempDir() + "/case.db"
	db, err := Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("Open error: %v", err)
	}
	if err := ApplyMigrations(ctx, db); err != nil {
		t.Fatalf("ApplyMigrations error: %v", err)
	}
	if err := EnsureCase(ctx, db, Case{ID: "case-1", Name: "case", OS: "windows"}); err != nil {
		t.Fatalf("EnsureCase error: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO event_relations (id, case_id, src_event_id, dst_event_id, relation_type, confidence, rationale) VALUES (?, ?, ?, ?, ?, ?, ?)`, "rel-1", "case-1", "missing-src", "missing-dst", "test", "medium", "test"); err != nil {
		t.Fatalf("insert broken relation: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO detections (id, case_id, event_id, rule_id, rule_name, severity, confidence, evidence_strength, rationale) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, "det-1", "case-1", "missing-event", "rule", "Rule", "medium", "medium", "single_source", "test"); err != nil {
		t.Fatalf("insert orphan detection: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}

	err = VerifyDatabase(ctx, dbPath)
	if err == nil {
		t.Fatal("expected relation validation error")
	}
	if !strings.Contains(err.Error(), "event relations with missing source events") {
		t.Fatalf("unexpected error: %v", err)
	}
}
