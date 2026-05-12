package store

import (
	"context"
	"database/sql"
	"testing"

	"timeline/internal/domain"
)

func TestInsertAndQueryEvents(t *testing.T) {
	ctx, db := setupEventStore(t)

	event := domain.TimelineEvent{
		SchemaVersion:      "1",
		ToolVersion:        "test",
		ParserName:         "evtx-xml",
		ParserVersion:      "test",
		CaseID:             "case-1",
		SourceType:         "evtx",
		SourcePath:         "Security.evtx",
		SourceRecordID:     "101",
		RawRef:             domain.RawRef{Type: "evtx_record", URI: "Security.evtx"},
		TimestampNS:        1715025600000000000,
		TimestampPrecision: domain.TimestampPrecisionNanosecond,
		TimestampSource:    "System.TimeCreated.SystemTime",
		Category:           "auth",
		Action:             "successful_logon",
		Severity:           domain.SeverityMedium,
		Confidence:         domain.ConfidenceHigh,
		EvidenceStrength:   domain.EvidenceStrong,
		Actor:              domain.Actor{User: "alice", SessionID: "0x3e7"},
		Network:            domain.Network{SrcIP: "203.0.113.24"},
		Tags:               []string{"windows", "authentication"},
	}
	event.ID = domain.GenerateEventID(event)

	if err := InsertEvents(ctx, db, []domain.TimelineEvent{event}); err != nil {
		t.Fatalf("InsertEvents error: %v", err)
	}
	events, err := QueryEvents(ctx, db, QueryFilters{Category: "auth"})
	if err != nil {
		t.Fatalf("QueryEvents error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %d", len(events))
	}
	if events[0].ID != event.ID {
		t.Fatalf("event id = %q", events[0].ID)
	}
	if events[0].Actor.User != "alice" {
		t.Fatalf("actor user = %q", events[0].Actor.User)
	}
}

func TestInsertAndQueryArtifacts(t *testing.T) {
	ctx, db := setupEventStore(t)
	artifact := Artifact{
		ID:         "artifact-1",
		CaseID:     "case-1",
		SourceType: "evtx",
		SourcePath: "Security.evtx",
		RawRefJSON: "{}",
		SizeBytes:  42,
	}
	if err := InsertArtifact(ctx, db, artifact); err != nil {
		t.Fatalf("InsertArtifact error: %v", err)
	}
	got, err := QueryArtifacts(ctx, db)
	if err != nil {
		t.Fatalf("QueryArtifacts error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("artifacts = %d", len(got))
	}
	if got[0].SourcePath != "Security.evtx" || got[0].SizeBytes != 42 {
		t.Fatalf("unexpected artifact: %+v", got[0])
	}
}

func TestQueryFilters(t *testing.T) {
	ctx, db := setupEventStore(t)
	events := []domain.TimelineEvent{
		testEvent("auth-1", 100, "auth", "successful_logon", domain.SeverityHigh, domain.ConfidenceHigh, "alice", "C:/Windows/System32/lsass.exe", "", "", "203.0.113.24"),
		testEvent("process-1", 200, "process", "process_created", domain.SeverityMedium, domain.ConfidenceHigh, "alice", "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe", "powershell.exe -NoProfile", "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe", ""),
		testEventWithHash("file-1", 300, "filesystem", "file_created", domain.SeverityLow, domain.ConfidenceMedium, "bob", "C:/Windows/System32/cmd.exe", "cmd.exe /c copy", "C:/Users/bob/AppData/Local/Temp/dropper.exe", "", "feedfacefeedfacefeedfacefeedfacefeedface"),
	}
	if err := InsertEvents(ctx, db, events); err != nil {
		t.Fatalf("InsertEvents error: %v", err)
	}

	cases := []struct {
		name    string
		filters QueryFilters
		want    int
	}{
		{name: "category", filters: QueryFilters{Category: "auth"}, want: 1},
		{name: "severity", filters: QueryFilters{Severity: "high"}, want: 1},
		{name: "confidence", filters: QueryFilters{Confidence: "medium"}, want: 1},
		{name: "time range", filters: QueryFilters{HasFrom: true, FromTimestamp: 150, HasTo: true, ToTimestamp: 250}, want: 1},
		{name: "actor", filters: QueryFilters{Actor: "bob"}, want: 1},
		{name: "process", filters: QueryFilters{Process: "powershell"}, want: 1},
		{name: "object path", filters: QueryFilters{ObjectPath: "dropper.exe"}, want: 1},
		{name: "hash", filters: QueryFilters{Hash: "feedface"}, want: 1},
		{name: "dst ip", filters: QueryFilters{DstIP: "203.0.113.24"}, want: 1},
		{name: "empty results", filters: QueryFilters{Category: "registry"}, want: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := QueryEvents(ctx, db, tc.filters)
			if err != nil {
				t.Fatalf("QueryEvents error: %v", err)
			}
			if len(got) != tc.want {
				t.Fatalf("events = %d, want %d", len(got), tc.want)
			}
		})
	}
}

func TestQueryLimitAndTimestampOrdering(t *testing.T) {
	ctx, db := setupEventStore(t)
	events := []domain.TimelineEvent{
		testEvent("late", 300, "process", "process_created", domain.SeverityMedium, domain.ConfidenceHigh, "alice", "b.exe", "b.exe", "b.exe", ""),
		testEvent("early", 100, "process", "process_created", domain.SeverityMedium, domain.ConfidenceHigh, "alice", "a.exe", "a.exe", "a.exe", ""),
		testEvent("middle", 200, "process", "process_created", domain.SeverityMedium, domain.ConfidenceHigh, "alice", "c.exe", "c.exe", "c.exe", ""),
	}
	if err := InsertEvents(ctx, db, events); err != nil {
		t.Fatalf("InsertEvents error: %v", err)
	}

	got, err := QueryEvents(ctx, db, QueryFilters{Limit: 2})
	if err != nil {
		t.Fatalf("QueryEvents error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("events = %d, want 2", len(got))
	}
	if got[0].TimestampNS != 100 || got[1].TimestampNS != 200 {
		t.Fatalf("events not ordered by timestamp: %d, %d", got[0].TimestampNS, got[1].TimestampNS)
	}
}

func TestApplyDetectionsWritesTableAndUpdatesEvents(t *testing.T) {
	ctx, db := setupEventStore(t)
	event := testEvent("encoded", 100, "process", "process_created", domain.SeverityMedium, domain.ConfidenceMedium, "alice", "powershell.exe", "powershell.exe -EncodedCommand SQBFAFgA", "powershell.exe", "")
	if err := InsertEvents(ctx, db, []domain.TimelineEvent{event}); err != nil {
		t.Fatalf("InsertEvents error: %v", err)
	}
	event.Severity = domain.SeverityHigh
	event.Confidence = domain.ConfidenceHigh
	event.Tags = []string{"windows", "encoded-command"}
	event.MITRETechniques = []string{"T1059.001"}
	detection := Detection{
		CaseID:           event.CaseID,
		EventID:          event.ID,
		RuleID:           "powershell.encoded_command",
		RuleName:         "Encoded PowerShell command",
		Severity:         domain.SeverityHigh,
		Confidence:       domain.ConfidenceHigh,
		EvidenceStrength: domain.EvidenceStrong,
		Rationale:        "candidate encoded command",
	}

	if err := ApplyDetections(ctx, db, []domain.TimelineEvent{event}, []Detection{detection}); err != nil {
		t.Fatalf("ApplyDetections error: %v", err)
	}
	detections, err := QueryDetections(ctx, db)
	if err != nil {
		t.Fatalf("QueryDetections error: %v", err)
	}
	if len(detections) != 1 {
		t.Fatalf("detections = %d", len(detections))
	}
	if detections[0].RuleID != "powershell.encoded_command" {
		t.Fatalf("rule id = %q", detections[0].RuleID)
	}
	events, err := QueryEvents(ctx, db, QueryFilters{Severity: "high"})
	if err != nil {
		t.Fatalf("QueryEvents error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("high severity events = %d", len(events))
	}
	if !containsStoreTestString(events[0].Tags, "encoded-command") || !containsStoreTestString(events[0].MITRETechniques, "T1059.001") {
		t.Fatalf("event tags/mitre not updated: %+v %+v", events[0].Tags, events[0].MITRETechniques)
	}
}

func TestInsertAndQueryEventRelations(t *testing.T) {
	ctx, db := setupEventStore(t)
	relation := EventRelation{
		CaseID:     "case-1",
		SourceID:   "prefetch-event",
		TargetID:   "evtx-event",
		Type:       "prefetch_evtx_process_match",
		Confidence: domain.ConfidenceMedium,
		Rationale:  "matching executable and close timestamp",
	}
	if err := InsertEventRelations(ctx, db, []EventRelation{relation}); err != nil {
		t.Fatalf("InsertEventRelations error: %v", err)
	}
	relations, err := QueryEventRelations(ctx, db)
	if err != nil {
		t.Fatalf("QueryEventRelations error: %v", err)
	}
	if len(relations) != 1 {
		t.Fatalf("relations = %d", len(relations))
	}
	if relations[0].Type != "prefetch_evtx_process_match" {
		t.Fatalf("relation type = %q", relations[0].Type)
	}
}

func TestReplaceAndQueryDiffResults(t *testing.T) {
	ctx, db := setupEventStore(t)
	results := []DiffResult{
		{
			BaselineCaseID:  "baseline",
			IncidentCaseID:  "case-1",
			DiffType:        "new_cmdline",
			Fingerprint:     "fingerprint-1",
			IncidentEventID: "event-1",
			Severity:        domain.SeverityHigh,
			Confidence:      domain.ConfidenceHigh,
			Rationale:       "candidate encoded command",
		},
	}
	if err := ReplaceDiffResults(ctx, db, "baseline", "case-1", results); err != nil {
		t.Fatalf("ReplaceDiffResults error: %v", err)
	}
	got, err := QueryDiffResults(ctx, db)
	if err != nil {
		t.Fatalf("QueryDiffResults error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("diff results = %d", len(got))
	}
	if got[0].DiffType != "new_cmdline" || got[0].Severity != domain.SeverityHigh {
		t.Fatalf("unexpected diff result: %+v", got[0])
	}
	if err := ReplaceDiffResults(ctx, db, "baseline", "case-1", nil); err != nil {
		t.Fatalf("ReplaceDiffResults clear error: %v", err)
	}
	got, err = QueryDiffResults(ctx, db)
	if err != nil {
		t.Fatalf("QueryDiffResults after clear error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("diff results after clear = %d", len(got))
	}
}

func setupEventStore(t *testing.T) (context.Context, *sql.DB) {
	t.Helper()
	ctx := context.Background()
	dbPath := t.TempDir() + "/case.db"
	db, err := Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("Open error: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := ApplyMigrations(ctx, db); err != nil {
		t.Fatalf("ApplyMigrations error: %v", err)
	}
	if err := EnsureCase(ctx, db, Case{ID: "case-1", Name: "fixture", OS: "windows"}); err != nil {
		t.Fatalf("EnsureCase error: %v", err)
	}
	return ctx, db
}

func testEvent(sourceRecordID string, timestamp int64, category string, action string, severity domain.Severity, confidence domain.Confidence, actorUser string, image string, cmdline string, objectPath string, dstIP string) domain.TimelineEvent {
	event := domain.TimelineEvent{
		SchemaVersion:      "1",
		ToolVersion:        "test",
		ParserName:         "test",
		ParserVersion:      "test",
		CaseID:             "case-1",
		SourceType:         "evtx",
		SourcePath:         "fixture.evtx",
		SourceRecordID:     sourceRecordID,
		RawRef:             domain.RawRef{Type: "evtx_record", URI: "fixture.evtx"},
		TimestampNS:        timestamp,
		TimestampPrecision: domain.TimestampPrecisionNanosecond,
		TimestampSource:    "test",
		Category:           category,
		Action:             action,
		Severity:           severity,
		Confidence:         confidence,
		EvidenceStrength:   domain.EvidenceStrong,
		Actor:              domain.Actor{User: actorUser, Image: image, Cmdline: cmdline, SessionID: "0x1"},
		Object:             domain.Object{Type: category, Path: objectPath},
		Network:            domain.Network{DstIP: dstIP, DstPort: 443},
	}
	event.ID = domain.GenerateEventID(event)
	return event
}

func testEventWithHash(sourceRecordID string, timestamp int64, category string, action string, severity domain.Severity, confidence domain.Confidence, actorUser string, image string, cmdline string, objectPath string, dstIP string, hash string) domain.TimelineEvent {
	event := testEvent(sourceRecordID, timestamp, category, action, severity, confidence, actorUser, image, cmdline, objectPath, dstIP)
	event.Object.Hash = hash
	event.ID = domain.GenerateEventID(event)
	return event
}

func containsStoreTestString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
