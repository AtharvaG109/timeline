package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"timeline/internal/domain"

	_ "modernc.org/sqlite"
)

const CurrentSchemaVersion = 1

var requiredTables = []string{
	"schema_migrations",
	"cases",
	"artifacts",
	"events",
	"event_relations",
	"detections",
	"diff_results",
}

var requiredIndexes = []string{
	"idx_events_case_time",
	"idx_events_severity",
	"idx_events_category",
	"idx_events_actor_image",
	"idx_events_object_path",
	"idx_events_network_destination",
	"idx_events_session_id",
	"idx_detections_rule_id",
}

var migrationStatements = []string{
	`CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY,
		name TEXT NOT NULL,
		applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
	)`,
	`CREATE TABLE IF NOT EXISTS cases (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		os TEXT NOT NULL,
		created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
		metadata_json TEXT NOT NULL DEFAULT '{}'
	)`,
	`CREATE TABLE IF NOT EXISTS artifacts (
		id TEXT PRIMARY KEY,
		case_id TEXT NOT NULL,
		source_type TEXT NOT NULL,
		source_path TEXT NOT NULL,
		raw_ref_json TEXT NOT NULL DEFAULT '{}',
		sha256 TEXT,
		size_bytes INTEGER,
		created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
		FOREIGN KEY (case_id) REFERENCES cases(id)
	)`,
	`CREATE TABLE IF NOT EXISTS events (
		id TEXT PRIMARY KEY,
		schema_version TEXT NOT NULL,
		tool_version TEXT NOT NULL,
		parser_name TEXT NOT NULL,
		parser_version TEXT NOT NULL,
		case_id TEXT NOT NULL,
		host_id TEXT,
		source_type TEXT NOT NULL,
		source_path TEXT NOT NULL,
		source_record_id TEXT,
		raw_ref_json TEXT NOT NULL DEFAULT '{}',
		timestamp_ns INTEGER NOT NULL,
		timestamp_precision TEXT NOT NULL,
		timestamp_source TEXT NOT NULL,
		category TEXT NOT NULL,
		action TEXT NOT NULL,
		severity TEXT NOT NULL,
		confidence TEXT NOT NULL,
		evidence_strength TEXT NOT NULL,
		actor_json TEXT NOT NULL DEFAULT '{}',
		actor_image TEXT,
		actor_cmdline TEXT,
		actor_session_id TEXT,
		object_json TEXT NOT NULL DEFAULT '{}',
		object_path TEXT,
		network_json TEXT NOT NULL DEFAULT '{}',
		network_dst_ip TEXT,
		network_dst_port INTEGER,
		tags_json TEXT NOT NULL DEFAULT '[]',
		mitre_techniques_json TEXT NOT NULL DEFAULT '[]',
		created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
		FOREIGN KEY (case_id) REFERENCES cases(id)
	)`,
	`CREATE TABLE IF NOT EXISTS event_relations (
		id TEXT PRIMARY KEY,
		case_id TEXT NOT NULL,
		src_event_id TEXT NOT NULL,
		dst_event_id TEXT NOT NULL,
		relation_type TEXT NOT NULL,
		confidence TEXT NOT NULL,
		rationale TEXT NOT NULL,
		created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
		FOREIGN KEY (case_id) REFERENCES cases(id),
		FOREIGN KEY (src_event_id) REFERENCES events(id),
		FOREIGN KEY (dst_event_id) REFERENCES events(id)
	)`,
	`CREATE TABLE IF NOT EXISTS detections (
		id TEXT PRIMARY KEY,
		case_id TEXT NOT NULL,
		event_id TEXT NOT NULL,
		rule_id TEXT NOT NULL,
		rule_name TEXT NOT NULL,
		severity TEXT NOT NULL,
		confidence TEXT NOT NULL,
		evidence_strength TEXT NOT NULL,
		rationale TEXT NOT NULL,
		created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
		FOREIGN KEY (case_id) REFERENCES cases(id),
		FOREIGN KEY (event_id) REFERENCES events(id)
	)`,
	`CREATE TABLE IF NOT EXISTS diff_results (
		id TEXT PRIMARY KEY,
		baseline_case_id TEXT NOT NULL,
		incident_case_id TEXT NOT NULL,
		diff_type TEXT NOT NULL,
		fingerprint TEXT NOT NULL,
		incident_event_id TEXT,
		severity TEXT NOT NULL,
		confidence TEXT NOT NULL,
		rationale TEXT NOT NULL,
		created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
	)`,
	`CREATE INDEX IF NOT EXISTS idx_events_case_time ON events (case_id, timestamp_ns)`,
	`CREATE INDEX IF NOT EXISTS idx_events_severity ON events (severity)`,
	`CREATE INDEX IF NOT EXISTS idx_events_category ON events (category)`,
	`CREATE INDEX IF NOT EXISTS idx_events_actor_image ON events (actor_image)`,
	`CREATE INDEX IF NOT EXISTS idx_events_object_path ON events (object_path)`,
	`CREATE INDEX IF NOT EXISTS idx_events_network_destination ON events (network_dst_ip, network_dst_port)`,
	`CREATE INDEX IF NOT EXISTS idx_events_session_id ON events (actor_session_id)`,
	`CREATE INDEX IF NOT EXISTS idx_detections_rule_id ON detections (rule_id)`,
	`INSERT OR IGNORE INTO schema_migrations (version, name) VALUES (1, 'phase_1_foundation')`,
}

func Open(ctx context.Context, path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open SQLite database: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("connect SQLite database: %w", err)
	}
	return db, nil
}

func OpenReadOnly(ctx context.Context, path string) (*sql.DB, error) {
	cleanPath, err := cleanDatabasePath(path)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", "file:"+cleanPath+"?mode=ro")
	if err != nil {
		return nil, fmt.Errorf("open SQLite database read-only: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("connect SQLite database read-only: %w", err)
	}
	return db, nil
}

func ApplyMigrations(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return errors.New("database handle is nil")
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin migration transaction: %w", err)
	}
	defer tx.Rollback()

	for _, statement := range migrationStatements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("apply migration statement: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migrations: %w", err)
	}
	return nil
}

func VerifyDatabase(ctx context.Context, path string) error {
	cleanPath, err := cleanDatabasePath(path)
	if err != nil {
		return err
	}

	info, err := os.Stat(cleanPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("database file does not exist: %s", cleanPath)
		}
		return fmt.Errorf("inspect database file: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("database path is a directory: %s", cleanPath)
	}
	if info.Size() == 0 {
		return fmt.Errorf("database file is empty: %s", cleanPath)
	}

	db, err := OpenReadOnly(ctx, cleanPath)
	if err != nil {
		return err
	}
	defer db.Close()

	missing, err := missingTables(ctx, db)
	if err != nil {
		return err
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required tables: %s", strings.Join(missing, ", "))
	}

	missing, err = missingIndexes(ctx, db)
	if err != nil {
		return err
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required indexes: %s", strings.Join(missing, ", "))
	}

	var version int
	err = db.QueryRowContext(ctx, `SELECT MAX(version) FROM schema_migrations`).Scan(&version)
	if err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if version > CurrentSchemaVersion {
		return fmt.Errorf("schema version %d is newer than supported version %d", version, CurrentSchemaVersion)
	}
	if version < CurrentSchemaVersion {
		return fmt.Errorf("schema version %d is older than required version %d", version, CurrentSchemaVersion)
	}
	if err := verifySemanticIntegrity(ctx, db); err != nil {
		return err
	}

	return nil
}

func verifySemanticIntegrity(ctx context.Context, db *sql.DB) error {
	if err := requireZeroCount(ctx, db, `SELECT COUNT(id) FROM events WHERE TRIM(source_path) = ''`, "events missing source paths"); err != nil {
		return err
	}
	if err := requireZeroCount(ctx, db, `SELECT COUNT(id) FROM events WHERE timestamp_ns < 0`, "events with invalid negative timestamps"); err != nil {
		return err
	}
	if err := requireZeroCount(ctx, db, `SELECT COUNT(event_relations.id) FROM event_relations LEFT JOIN events src ON src.id = event_relations.src_event_id WHERE src.id IS NULL`, "event relations with missing source events"); err != nil {
		return err
	}
	if err := requireZeroCount(ctx, db, `SELECT COUNT(event_relations.id) FROM event_relations LEFT JOIN events dst ON dst.id = event_relations.dst_event_id WHERE dst.id IS NULL`, "event relations with missing target events"); err != nil {
		return err
	}
	if err := requireZeroCount(ctx, db, `SELECT COUNT(detections.id) FROM detections LEFT JOIN events ON events.id = detections.event_id WHERE events.id IS NULL`, "orphan detections"); err != nil {
		return err
	}
	if err := verifyEventEnumsAndJSON(ctx, db); err != nil {
		return err
	}
	if err := verifyArtifactJSON(ctx, db); err != nil {
		return err
	}
	return nil
}

func requireZeroCount(ctx context.Context, db *sql.DB, query string, label string) error {
	var count int
	if err := db.QueryRowContext(ctx, query).Scan(&count); err != nil {
		return fmt.Errorf("verify %s: %w", label, err)
	}
	if count > 0 {
		return fmt.Errorf("database validation failed: %s=%d", label, count)
	}
	return nil
}

func verifyEventEnumsAndJSON(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, `SELECT
		id,
		timestamp_precision,
		severity,
		confidence,
		evidence_strength,
		raw_ref_json,
		actor_json,
		object_json,
		network_json,
		tags_json,
		mitre_techniques_json
	FROM events
	ORDER BY id ASC`)
	if err != nil {
		return fmt.Errorf("query events for validation: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var id string
		var precision string
		var severity string
		var confidence string
		var evidence string
		jsonFields := make([]string, 6)
		if err := rows.Scan(&id, &precision, &severity, &confidence, &evidence, &jsonFields[0], &jsonFields[1], &jsonFields[2], &jsonFields[3], &jsonFields[4], &jsonFields[5]); err != nil {
			return fmt.Errorf("scan event validation row: %w", err)
		}
		event := domain.TimelineEvent{
			TimestampPrecision: domain.TimestampPrecision(precision),
			Severity:           domain.Severity(severity),
			Confidence:         domain.Confidence(confidence),
			EvidenceStrength:   domain.EvidenceStrength(evidence),
		}
		if err := event.ValidateEnums(); err != nil {
			return fmt.Errorf("event %s has invalid enum: %w", id, err)
		}
		for _, field := range jsonFields {
			if !json.Valid([]byte(field)) {
				return fmt.Errorf("event %s contains corrupt JSON fields", id)
			}
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate event validation rows: %w", err)
	}
	return nil
}

func verifyArtifactJSON(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, `SELECT
		id,
		raw_ref_json
	FROM artifacts
	ORDER BY id ASC`)
	if err != nil {
		return fmt.Errorf("query artifacts for validation: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var id string
		var rawRef string
		if err := rows.Scan(&id, &rawRef); err != nil {
			return fmt.Errorf("scan artifact validation row: %w", err)
		}
		if !json.Valid([]byte(rawRef)) {
			return fmt.Errorf("artifact %s contains corrupt raw_ref JSON", id)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate artifact validation rows: %w", err)
	}
	return nil
}

func missingTables(ctx context.Context, db *sql.DB) ([]string, error) {
	missing := make([]string, 0)
	for _, table := range requiredTables {
		var name string
		err := db.QueryRowContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&name)
		if errors.Is(err, sql.ErrNoRows) {
			missing = append(missing, table)
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("inspect table %s: %w", table, err)
		}
	}
	return missing, nil
}

func missingIndexes(ctx context.Context, db *sql.DB) ([]string, error) {
	missing := make([]string, 0)
	for _, index := range requiredIndexes {
		var name string
		err := db.QueryRowContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'index' AND name = ?`, index).Scan(&name)
		if errors.Is(err, sql.ErrNoRows) {
			missing = append(missing, index)
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("inspect index %s: %w", index, err)
		}
	}
	return missing, nil
}

func cleanDatabasePath(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("database path is empty")
	}
	clean := filepath.Clean(path)
	if strings.Contains(clean, "\x00") {
		return "", errors.New("database path contains an invalid character")
	}
	return clean, nil
}
