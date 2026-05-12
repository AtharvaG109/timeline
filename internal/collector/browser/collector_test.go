package browser

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"timeline/internal/domain"

	_ "modernc.org/sqlite"
)

func TestWebKitTimeToUnixNS(t *testing.T) {
	ts := time.Date(2024, 5, 6, 20, 4, 12, 345000000, time.UTC)
	webkit := ts.UnixMicro() + webkitUnixOffsetUS
	got := WebKitTimeToUnixNS(webkit)
	if got != ts.UnixNano() {
		t.Fatalf("WebKitTimeToUnixNS = %d, want %d", got, ts.UnixNano())
	}
}

func TestParseChromeHistoryVisitsAndDownloads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Chrome", "Default", "History")
	createChromiumHistoryFixture(t, path, "https://example.test/index.html", "Example", "https://downloads.example.test/payload.exe", `C:\Users\alice\Downloads\payload.exe`)

	events, ok, err := ParseFile(path, "case-1")
	if err != nil {
		t.Fatalf("parse Chrome History: %v", err)
	}
	if !ok {
		t.Fatal("Chrome History fixture was not parsed")
	}
	if len(events) != 2 {
		t.Fatalf("events = %d", len(events))
	}
	visit := findBrowserEvent(events, "visited")
	if visit == nil {
		t.Fatalf("missing visit event: %+v", events)
	}
	if visit.SourceType != "browser_chrome" || visit.Category != "browser" || visit.TimestampSource != "browser_history" {
		t.Fatalf("unexpected visit normalization: %+v", *visit)
	}
	if visit.Network.DNSName != "example.test" {
		t.Fatalf("visit DNS name = %q", visit.Network.DNSName)
	}
	download := findBrowserEvent(events, "downloaded")
	if download == nil {
		t.Fatalf("missing download event: %+v", events)
	}
	if download.Object.Path != `C:\Users\alice\Downloads\payload.exe` || download.Network.DNSName != "downloads.example.test" {
		t.Fatalf("unexpected download normalization: %+v", *download)
	}
	if download.Severity != domain.SeverityMedium || download.Confidence != domain.ConfidenceMedium {
		t.Fatalf("unexpected download scoring: %+v", *download)
	}
}

func TestParseEdgeHistorySchemaCompatible(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Edge", "Default", "History")
	createChromiumHistoryFixture(t, path, "https://edge.example.test/", "Edge", "", "")

	events, ok, err := ParseFile(path, "case-1")
	if err != nil {
		t.Fatalf("parse Edge History: %v", err)
	}
	if !ok || len(events) != 1 {
		t.Fatalf("Edge History parsed ok=%v events=%d", ok, len(events))
	}
	if events[0].SourceType != "browser_edge" {
		t.Fatalf("source type = %q", events[0].SourceType)
	}
}

func TestParseFirefoxPlacesVisits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Firefox", "Profiles", "default", "places.sqlite")
	createFirefoxPlacesFixture(t, path)

	events, ok, err := ParseFile(path, "case-1")
	if err != nil {
		t.Fatalf("parse Firefox places.sqlite: %v", err)
	}
	if !ok || len(events) != 1 {
		t.Fatalf("Firefox places parsed ok=%v events=%d", ok, len(events))
	}
	event := events[0]
	if event.SourceType != "browser_firefox" || event.Action != "visited" || event.Network.DNSName != "mozilla.example.test" {
		t.Fatalf("unexpected Firefox event: %+v", event)
	}
}

func TestMalformedSQLiteDatabaseDoesNotCrash(t *testing.T) {
	path := filepath.Join(t.TempDir(), "History")
	if err := os.WriteFile(path, []byte("not sqlite"), 0o600); err != nil {
		t.Fatalf("write malformed fixture: %v", err)
	}
	events, ok, err := ParseFile(path, "case-1")
	if err != nil {
		t.Fatalf("malformed database returned error: %v", err)
	}
	if ok || len(events) != 0 {
		t.Fatalf("malformed database parsed ok=%v events=%d", ok, len(events))
	}
}

func createChromiumHistoryFixture(t *testing.T, path string, visitURL string, title string, downloadURL string, targetPath string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create fixture dir: %v", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open fixture db: %v", err)
	}
	defer db.Close()
	execFixtureSQL(t, db, `CREATE TABLE urls (
		id INTEGER PRIMARY KEY,
		url TEXT NOT NULL,
		title TEXT,
		visit_count INTEGER,
		last_visit_time INTEGER
	)`)
	execFixtureSQL(t, db, `CREATE TABLE visits (
		id INTEGER PRIMARY KEY,
		url INTEGER,
		visit_time INTEGER
	)`)
	execFixtureSQL(t, db, `CREATE TABLE downloads (
		id INTEGER PRIMARY KEY,
		target_path TEXT,
		current_path TEXT,
		start_time INTEGER,
		end_time INTEGER
	)`)
	execFixtureSQL(t, db, `CREATE TABLE downloads_url_chains (
		id INTEGER,
		chain_index INTEGER,
		url TEXT
	)`)
	visitTime := webkitFixtureTime(time.Date(2024, 5, 6, 20, 4, 12, 0, time.UTC))
	execFixtureSQL(t, db, `INSERT INTO urls (id, url, title, visit_count, last_visit_time) VALUES (1, ?, ?, 2, ?)`, visitURL, title, visitTime)
	execFixtureSQL(t, db, `INSERT INTO visits (id, url, visit_time) VALUES (10, 1, ?)`, visitTime)
	if downloadURL != "" || targetPath != "" {
		startTime := webkitFixtureTime(time.Date(2024, 5, 6, 20, 5, 0, 0, time.UTC))
		endTime := webkitFixtureTime(time.Date(2024, 5, 6, 20, 5, 3, 0, time.UTC))
		execFixtureSQL(t, db, `INSERT INTO downloads (id, target_path, current_path, start_time, end_time) VALUES (20, ?, ?, ?, ?)`, targetPath, targetPath, startTime, endTime)
		execFixtureSQL(t, db, `INSERT INTO downloads_url_chains (id, chain_index, url) VALUES (20, 0, ?)`, downloadURL)
	}
}

func createFirefoxPlacesFixture(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create fixture dir: %v", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open fixture db: %v", err)
	}
	defer db.Close()
	execFixtureSQL(t, db, `CREATE TABLE moz_places (
		id INTEGER PRIMARY KEY,
		url TEXT NOT NULL,
		title TEXT,
		visit_count INTEGER,
		last_visit_date INTEGER
	)`)
	execFixtureSQL(t, db, `CREATE TABLE moz_historyvisits (
		id INTEGER PRIMARY KEY,
		place_id INTEGER,
		visit_date INTEGER
	)`)
	visitTime := time.Date(2024, 5, 7, 9, 15, 0, 0, time.UTC).UnixMicro()
	execFixtureSQL(t, db, `INSERT INTO moz_places (id, url, title, visit_count, last_visit_date) VALUES (1, 'https://mozilla.example.test/', 'Mozilla', 3, ?)`, visitTime)
	execFixtureSQL(t, db, `INSERT INTO moz_historyvisits (id, place_id, visit_date) VALUES (30, 1, ?)`, visitTime)
}

func execFixtureSQL(t *testing.T, db *sql.DB, statement string, args ...any) {
	t.Helper()
	if _, err := db.Exec(statement, args...); err != nil {
		t.Fatalf("exec fixture SQL %q: %v", statement, err)
	}
}

func webkitFixtureTime(t time.Time) int64 {
	return t.UTC().UnixMicro() + webkitUnixOffsetUS
}

func findBrowserEvent(events []domain.TimelineEvent, action string) *domain.TimelineEvent {
	for i := range events {
		if events[i].Action == action {
			return &events[i]
		}
	}
	return nil
}
