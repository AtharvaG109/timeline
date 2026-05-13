package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"timeline/internal/domain"
)

type Case struct {
	ID   string
	Name string
	OS   string
}

type Artifact struct {
	ID         string
	CaseID     string
	SourceType string
	SourcePath string
	RawRefJSON string
	SizeBytes  int64
}

type QueryFilters struct {
	Category      string
	Severity      string
	Confidence    string
	FromTimestamp int64
	ToTimestamp   int64
	HasFrom       bool
	HasTo         bool
	Actor         string
	Process       string
	ObjectPath    string
	Hash          string
	DstIP         string
	Limit         int
}

type Detection struct {
	ID               string
	CaseID           string
	EventID          string
	RuleID           string
	RuleName         string
	Severity         domain.Severity
	Confidence       domain.Confidence
	EvidenceStrength domain.EvidenceStrength
	Rationale        string
}

type EventRelation struct {
	ID         string
	CaseID     string
	SourceID   string
	TargetID   string
	Type       string
	Confidence domain.Confidence
	Rationale  string
}

type DiffResult struct {
	ID              string
	BaselineCaseID  string
	IncidentCaseID  string
	DiffType        string
	Fingerprint     string
	IncidentEventID string
	Severity        domain.Severity
	Confidence      domain.Confidence
	Rationale       string
}

func StableCaseID(artifactDir string, outPath string) string {
	sum := sha256.Sum256([]byte(filepath.Clean(artifactDir) + "\x00" + filepath.Clean(outPath)))
	return hex.EncodeToString(sum[:16])
}

func StableArtifactID(caseID string, sourcePath string) string {
	sum := sha256.Sum256([]byte(caseID + "\x00" + filepath.Clean(sourcePath)))
	return hex.EncodeToString(sum[:16])
}

func EnsureCase(ctx context.Context, db *sql.DB, c Case) error {
	if strings.TrimSpace(c.ID) == "" {
		return fmt.Errorf("case id is required")
	}
	if strings.TrimSpace(c.Name) == "" {
		return fmt.Errorf("case name is required")
	}
	if strings.TrimSpace(c.OS) == "" {
		return fmt.Errorf("case os is required")
	}
	_, err := db.ExecContext(ctx, `INSERT OR IGNORE INTO cases (
		id,
		name,
		os,
		metadata_json
	) VALUES (?, ?, ?, ?)`, c.ID, c.Name, c.OS, "{}")
	if err != nil {
		return fmt.Errorf("insert case: %w", err)
	}
	return nil
}

func InsertArtifact(ctx context.Context, db *sql.DB, artifact Artifact) error {
	_, err := db.ExecContext(ctx, `INSERT OR IGNORE INTO artifacts (
		id,
		case_id,
		source_type,
		source_path,
		raw_ref_json,
		size_bytes
	) VALUES (?, ?, ?, ?, ?, ?)`,
		artifact.ID,
		artifact.CaseID,
		artifact.SourceType,
		artifact.SourcePath,
		artifact.RawRefJSON,
		artifact.SizeBytes,
	)
	if err != nil {
		return fmt.Errorf("insert artifact: %w", err)
	}
	return nil
}

func QueryArtifacts(ctx context.Context, db *sql.DB) ([]Artifact, error) {
	rows, err := db.QueryContext(ctx, `SELECT
		id,
		case_id,
		source_type,
		source_path,
		raw_ref_json,
		COALESCE(size_bytes, 0)
	FROM artifacts
	ORDER BY source_type ASC, source_path ASC`)
	if err != nil {
		return nil, fmt.Errorf("query artifacts: %w", err)
	}
	defer rows.Close()

	artifacts := make([]Artifact, 0)
	for rows.Next() {
		var artifact Artifact
		if err := rows.Scan(
			&artifact.ID,
			&artifact.CaseID,
			&artifact.SourceType,
			&artifact.SourcePath,
			&artifact.RawRefJSON,
			&artifact.SizeBytes,
		); err != nil {
			return nil, fmt.Errorf("scan artifact: %w", err)
		}
		artifacts = append(artifacts, artifact)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate artifacts: %w", err)
	}
	return artifacts, nil
}

func InsertEvents(ctx context.Context, db *sql.DB, events []domain.TimelineEvent) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin event insert transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `INSERT OR REPLACE INTO events (
		id,
		schema_version,
		tool_version,
		parser_name,
		parser_version,
		case_id,
		host_id,
		source_type,
		source_path,
		source_record_id,
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
		actor_image,
		actor_cmdline,
		actor_session_id,
		object_json,
		object_path,
		network_json,
		network_dst_ip,
		network_dst_port,
		tags_json,
		mitre_techniques_json
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare event insert: %w", err)
	}
	defer stmt.Close()

	for _, event := range events {
		if event.ID == "" {
			event.ID = domain.GenerateEventID(event)
		}
		if err := event.ValidateEnums(); err != nil {
			return fmt.Errorf("validate event %s: %w", event.ID, err)
		}
		rawRefJSON, err := marshalJSON(event.RawRef)
		if err != nil {
			return fmt.Errorf("marshal raw ref for event %s: %w", event.ID, err)
		}
		actorJSON, err := marshalJSON(event.Actor)
		if err != nil {
			return fmt.Errorf("marshal actor for event %s: %w", event.ID, err)
		}
		objectJSON, err := marshalJSON(event.Object)
		if err != nil {
			return fmt.Errorf("marshal object for event %s: %w", event.ID, err)
		}
		networkJSON, err := marshalJSON(event.Network)
		if err != nil {
			return fmt.Errorf("marshal network for event %s: %w", event.ID, err)
		}
		tagsJSON, err := marshalJSON(event.Tags)
		if err != nil {
			return fmt.Errorf("marshal tags for event %s: %w", event.ID, err)
		}
		mitreJSON, err := marshalJSON(event.MITRETechniques)
		if err != nil {
			return fmt.Errorf("marshal mitre techniques for event %s: %w", event.ID, err)
		}

		_, err = stmt.ExecContext(ctx,
			event.ID,
			event.SchemaVersion,
			event.ToolVersion,
			event.ParserName,
			event.ParserVersion,
			event.CaseID,
			nullString(event.HostID),
			event.SourceType,
			event.SourcePath,
			nullString(event.SourceRecordID),
			rawRefJSON,
			event.TimestampNS,
			string(event.TimestampPrecision),
			event.TimestampSource,
			event.Category,
			event.Action,
			string(event.Severity),
			string(event.Confidence),
			string(event.EvidenceStrength),
			actorJSON,
			nullString(event.Actor.Image),
			nullString(event.Actor.Cmdline),
			nullString(event.Actor.SessionID),
			objectJSON,
			nullString(event.Object.Path),
			networkJSON,
			nullString(event.Network.DstIP),
			nullInt(event.Network.DstPort),
			tagsJSON,
			mitreJSON,
		)
		if err != nil {
			return fmt.Errorf("insert event %s: %w", event.ID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit event inserts: %w", err)
	}
	return nil
}

func QueryEvents(ctx context.Context, db *sql.DB, filters QueryFilters) ([]domain.TimelineEvent, error) {
	limit := filters.Limit
	if limit > 1000 {
		limit = 1000
	}

	query := `SELECT
		id,
		schema_version,
		tool_version,
		parser_name,
		parser_version,
		case_id,
		COALESCE(host_id, ''),
		source_type,
		source_path,
		COALESCE(source_record_id, ''),
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
	FROM events`
	clauses := make([]string, 0)
	args := []any{}
	if strings.TrimSpace(filters.Category) != "" {
		clauses = append(clauses, `category = ?`)
		args = append(args, strings.TrimSpace(filters.Category))
	}
	if strings.TrimSpace(filters.Severity) != "" {
		clauses = append(clauses, `severity = ?`)
		args = append(args, strings.TrimSpace(filters.Severity))
	}
	if strings.TrimSpace(filters.Confidence) != "" {
		clauses = append(clauses, `confidence = ?`)
		args = append(args, strings.TrimSpace(filters.Confidence))
	}
	if filters.HasFrom {
		clauses = append(clauses, `timestamp_ns >= ?`)
		args = append(args, filters.FromTimestamp)
	}
	if filters.HasTo {
		clauses = append(clauses, `timestamp_ns <= ?`)
		args = append(args, filters.ToTimestamp)
	}
	if strings.TrimSpace(filters.Actor) != "" {
		clauses = append(clauses, `actor_json LIKE ?`)
		args = append(args, likeContains(filters.Actor))
	}
	if strings.TrimSpace(filters.Process) != "" {
		clauses = append(clauses, `(actor_image LIKE ? OR actor_cmdline LIKE ?)`)
		pattern := likeContains(filters.Process)
		args = append(args, pattern, pattern)
	}
	if strings.TrimSpace(filters.ObjectPath) != "" {
		clauses = append(clauses, `object_path LIKE ?`)
		args = append(args, likeContains(filters.ObjectPath))
	}
	if strings.TrimSpace(filters.Hash) != "" {
		clauses = append(clauses, `object_json LIKE ?`)
		args = append(args, likeContains(filters.Hash))
	}
	if strings.TrimSpace(filters.DstIP) != "" {
		clauses = append(clauses, `network_dst_ip = ?`)
		args = append(args, strings.TrimSpace(filters.DstIP))
	}
	if len(clauses) > 0 {
		// #nosec G202 -- clauses are fixed literals selected from QueryFilters and values are bound as parameters.
		query += ` WHERE ` + strings.Join(clauses, ` AND `)
	}
	query += ` ORDER BY timestamp_ns ASC, id ASC`
	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit)
	}

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query events: %w", err)
	}
	defer rows.Close()

	events := make([]domain.TimelineEvent, 0)
	for rows.Next() {
		var event domain.TimelineEvent
		var rawRefJSON string
		var actorJSON string
		var objectJSON string
		var networkJSON string
		var tagsJSON string
		var mitreJSON string
		var precision string
		var severity string
		var confidence string
		var evidence string
		err := rows.Scan(
			&event.ID,
			&event.SchemaVersion,
			&event.ToolVersion,
			&event.ParserName,
			&event.ParserVersion,
			&event.CaseID,
			&event.HostID,
			&event.SourceType,
			&event.SourcePath,
			&event.SourceRecordID,
			&rawRefJSON,
			&event.TimestampNS,
			&precision,
			&event.TimestampSource,
			&event.Category,
			&event.Action,
			&severity,
			&confidence,
			&evidence,
			&actorJSON,
			&objectJSON,
			&networkJSON,
			&tagsJSON,
			&mitreJSON,
		)
		if err != nil {
			return nil, fmt.Errorf("scan event: %w", err)
		}
		event.TimestampPrecision = domain.TimestampPrecision(precision)
		event.Severity = domain.Severity(severity)
		event.Confidence = domain.Confidence(confidence)
		event.EvidenceStrength = domain.EvidenceStrength(evidence)
		if err := unmarshalJSON(rawRefJSON, &event.RawRef); err != nil {
			return nil, fmt.Errorf("decode raw ref for event %s: %w", event.ID, err)
		}
		if err := unmarshalJSON(actorJSON, &event.Actor); err != nil {
			return nil, fmt.Errorf("decode actor for event %s: %w", event.ID, err)
		}
		if err := unmarshalJSON(objectJSON, &event.Object); err != nil {
			return nil, fmt.Errorf("decode object for event %s: %w", event.ID, err)
		}
		if err := unmarshalJSON(networkJSON, &event.Network); err != nil {
			return nil, fmt.Errorf("decode network for event %s: %w", event.ID, err)
		}
		if err := unmarshalJSON(tagsJSON, &event.Tags); err != nil {
			return nil, fmt.Errorf("decode tags for event %s: %w", event.ID, err)
		}
		if err := unmarshalJSON(mitreJSON, &event.MITRETechniques); err != nil {
			return nil, fmt.Errorf("decode mitre techniques for event %s: %w", event.ID, err)
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate events: %w", err)
	}
	return events, nil
}

func CountEvents(ctx context.Context, db *sql.DB) (int, error) {
	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(id) FROM events`).Scan(&count); err != nil {
		return 0, fmt.Errorf("count events: %w", err)
	}
	return count, nil
}

func StableDetectionID(eventID string, ruleID string) string {
	sum := sha256.Sum256([]byte(eventID + "\x00" + ruleID))
	return hex.EncodeToString(sum[:16])
}

func StableEventRelationID(sourceID string, targetID string, relationType string) string {
	sum := sha256.Sum256([]byte(sourceID + "\x00" + targetID + "\x00" + relationType))
	return hex.EncodeToString(sum[:16])
}

func StableDiffResultID(baselineCaseID string, incidentCaseID string, diffType string, fingerprint string, incidentEventID string) string {
	sum := sha256.Sum256([]byte(baselineCaseID + "\x00" + incidentCaseID + "\x00" + diffType + "\x00" + fingerprint + "\x00" + incidentEventID))
	return hex.EncodeToString(sum[:16])
}

func QueryCaseID(ctx context.Context, db *sql.DB) (string, error) {
	var id string
	err := db.QueryRowContext(ctx, `SELECT
		id
	FROM cases
	ORDER BY created_at ASC, id ASC
	LIMIT 1`).Scan(&id)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("database has no case row")
		}
		return "", fmt.Errorf("query case id: %w", err)
	}
	return id, nil
}

func InsertEventRelations(ctx context.Context, db *sql.DB, relations []EventRelation) error {
	if len(relations) == 0 {
		return nil
	}
	stmt, err := db.PrepareContext(ctx, `INSERT OR REPLACE INTO event_relations (
		id,
		case_id,
		src_event_id,
		dst_event_id,
		relation_type,
		confidence,
		rationale
	) VALUES (?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare event relation insert: %w", err)
	}
	defer stmt.Close()

	for _, relation := range relations {
		id := relation.ID
		if id == "" {
			id = StableEventRelationID(relation.SourceID, relation.TargetID, relation.Type)
		}
		_, err := stmt.ExecContext(ctx,
			id,
			relation.CaseID,
			relation.SourceID,
			relation.TargetID,
			relation.Type,
			string(relation.Confidence),
			relation.Rationale,
		)
		if err != nil {
			return fmt.Errorf("insert event relation %s: %w", id, err)
		}
	}
	return nil
}

func QueryEventRelations(ctx context.Context, db *sql.DB) ([]EventRelation, error) {
	rows, err := db.QueryContext(ctx, `SELECT
		id,
		case_id,
		src_event_id,
		dst_event_id,
		relation_type,
		confidence,
		rationale
	FROM event_relations
	ORDER BY relation_type ASC, src_event_id ASC, dst_event_id ASC`)
	if err != nil {
		return nil, fmt.Errorf("query event relations: %w", err)
	}
	defer rows.Close()

	relations := make([]EventRelation, 0)
	for rows.Next() {
		var relation EventRelation
		var confidence string
		if err := rows.Scan(
			&relation.ID,
			&relation.CaseID,
			&relation.SourceID,
			&relation.TargetID,
			&relation.Type,
			&confidence,
			&relation.Rationale,
		); err != nil {
			return nil, fmt.Errorf("scan event relation: %w", err)
		}
		relation.Confidence = domain.Confidence(confidence)
		relations = append(relations, relation)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate event relations: %w", err)
	}
	return relations, nil
}

func ReplaceDiffResults(ctx context.Context, db *sql.DB, baselineCaseID string, incidentCaseID string, results []DiffResult) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin diff result transaction: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `DELETE FROM diff_results WHERE baseline_case_id = ? AND incident_case_id = ?`, baselineCaseID, incidentCaseID); err != nil {
		return fmt.Errorf("clear previous diff results: %w", err)
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO diff_results (
		id,
		baseline_case_id,
		incident_case_id,
		diff_type,
		fingerprint,
		incident_event_id,
		severity,
		confidence,
		rationale
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare diff result insert: %w", err)
	}
	defer stmt.Close()

	for _, result := range results {
		id := result.ID
		if strings.TrimSpace(id) == "" {
			id = StableDiffResultID(result.BaselineCaseID, result.IncidentCaseID, result.DiffType, result.Fingerprint, result.IncidentEventID)
		}
		_, err := stmt.ExecContext(ctx,
			id,
			result.BaselineCaseID,
			result.IncidentCaseID,
			result.DiffType,
			result.Fingerprint,
			nullString(result.IncidentEventID),
			string(result.Severity),
			string(result.Confidence),
			result.Rationale,
		)
		if err != nil {
			return fmt.Errorf("insert diff result %s: %w", id, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit diff results: %w", err)
	}
	return nil
}

func QueryDiffResults(ctx context.Context, db *sql.DB) ([]DiffResult, error) {
	rows, err := db.QueryContext(ctx, `SELECT
		id,
		baseline_case_id,
		incident_case_id,
		diff_type,
		fingerprint,
		COALESCE(incident_event_id, ''),
		severity,
		confidence,
		rationale
	FROM diff_results
	ORDER BY diff_type ASC, fingerprint ASC`)
	if err != nil {
		return nil, fmt.Errorf("query diff results: %w", err)
	}
	defer rows.Close()

	results := make([]DiffResult, 0)
	for rows.Next() {
		var result DiffResult
		var severity string
		var confidence string
		if err := rows.Scan(
			&result.ID,
			&result.BaselineCaseID,
			&result.IncidentCaseID,
			&result.DiffType,
			&result.Fingerprint,
			&result.IncidentEventID,
			&severity,
			&confidence,
			&result.Rationale,
		); err != nil {
			return nil, fmt.Errorf("scan diff result: %w", err)
		}
		result.Severity = domain.Severity(severity)
		result.Confidence = domain.Confidence(confidence)
		results = append(results, result)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate diff results: %w", err)
	}
	return results, nil
}

func ApplyDetections(ctx context.Context, db *sql.DB, events []domain.TimelineEvent, detections []Detection) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin detection transaction: %w", err)
	}
	defer tx.Rollback()

	updateStmt, err := tx.PrepareContext(ctx, `UPDATE events SET
		severity = ?,
		confidence = ?,
		evidence_strength = ?,
		tags_json = ?,
		mitre_techniques_json = ?
	WHERE id = ?`)
	if err != nil {
		return fmt.Errorf("prepare event detection update: %w", err)
	}
	defer updateStmt.Close()

	for _, event := range events {
		tagsJSON, err := marshalJSON(event.Tags)
		if err != nil {
			return fmt.Errorf("marshal updated tags for event %s: %w", event.ID, err)
		}
		mitreJSON, err := marshalJSON(event.MITRETechniques)
		if err != nil {
			return fmt.Errorf("marshal updated mitre techniques for event %s: %w", event.ID, err)
		}
		_, err = updateStmt.ExecContext(ctx,
			string(event.Severity),
			string(event.Confidence),
			string(event.EvidenceStrength),
			tagsJSON,
			mitreJSON,
			event.ID,
		)
		if err != nil {
			return fmt.Errorf("update event %s after detection: %w", event.ID, err)
		}
	}

	detectionStmt, err := tx.PrepareContext(ctx, `INSERT OR REPLACE INTO detections (
		id,
		case_id,
		event_id,
		rule_id,
		rule_name,
		severity,
		confidence,
		evidence_strength,
		rationale
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare detection insert: %w", err)
	}
	defer detectionStmt.Close()

	for _, detection := range detections {
		id := detection.ID
		if strings.TrimSpace(id) == "" {
			id = StableDetectionID(detection.EventID, detection.RuleID)
		}
		_, err = detectionStmt.ExecContext(ctx,
			id,
			detection.CaseID,
			detection.EventID,
			detection.RuleID,
			detection.RuleName,
			string(detection.Severity),
			string(detection.Confidence),
			string(detection.EvidenceStrength),
			detection.Rationale,
		)
		if err != nil {
			return fmt.Errorf("insert detection %s: %w", id, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit detections: %w", err)
	}
	return nil
}

func QueryDetections(ctx context.Context, db *sql.DB) ([]Detection, error) {
	rows, err := db.QueryContext(ctx, `SELECT
		id,
		case_id,
		event_id,
		rule_id,
		rule_name,
		severity,
		confidence,
		evidence_strength,
		rationale
	FROM detections
	ORDER BY rule_id ASC, event_id ASC`)
	if err != nil {
		return nil, fmt.Errorf("query detections: %w", err)
	}
	defer rows.Close()

	detections := make([]Detection, 0)
	for rows.Next() {
		var detection Detection
		var severity string
		var confidence string
		var evidenceStrength string
		if err := rows.Scan(
			&detection.ID,
			&detection.CaseID,
			&detection.EventID,
			&detection.RuleID,
			&detection.RuleName,
			&severity,
			&confidence,
			&evidenceStrength,
			&detection.Rationale,
		); err != nil {
			return nil, fmt.Errorf("scan detection: %w", err)
		}
		detection.Severity = domain.Severity(severity)
		detection.Confidence = domain.Confidence(confidence)
		detection.EvidenceStrength = domain.EvidenceStrength(evidenceStrength)
		detections = append(detections, detection)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate detections: %w", err)
	}
	return detections, nil
}

func marshalJSON(value any) (string, error) {
	content, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return string(content), nil
}

func unmarshalJSON(content string, value any) error {
	if strings.TrimSpace(content) == "" {
		content = "{}"
	}
	return json.Unmarshal([]byte(content), value)
}

func nullString(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}

func nullInt(value int) any {
	if value == 0 {
		return nil
	}
	return value
}

func likeContains(value string) string {
	return "%" + strings.TrimSpace(value) + "%"
}
