package browser

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"timeline/internal/artifact"
	"timeline/internal/domain"
	"timeline/internal/version"

	_ "modernc.org/sqlite"
)

const (
	parserName           = "browser-sqlite"
	parserVersion        = "0.10.0"
	webkitUnixOffsetUS   = int64(11644473600000000)
	timestampPrecisionNS = domain.TimestampPrecisionMicrosecond
)

type Stats struct {
	FilesParsed           int
	EventsEmitted         int
	MalformedFilesSkipped int
	ParseErrors           int
}

type Result struct {
	Events []domain.TimelineEvent
	Files  []string
	Stats  Stats
}

type BrowserKind string

const (
	BrowserChrome  BrowserKind = "chrome"
	BrowserEdge    BrowserKind = "edge"
	BrowserFirefox BrowserKind = "firefox"
)

type VisitRecord struct {
	RecordID   string
	URL        string
	Title      string
	VisitCount int
	Timestamp  int64
}

type DownloadRecord struct {
	RecordID   string
	URL        string
	TargetPath string
	StartNS    int64
	EndNS      int64
}

func CollectDirectory(ctx context.Context, root string, caseID string) (Result, error) {
	cleanRoot := filepath.Clean(root)
	info, err := os.Stat(cleanRoot)
	if err != nil {
		return Result{}, fmt.Errorf("inspect artifact directory: %w", err)
	}
	if !info.IsDir() {
		return Result{}, fmt.Errorf("artifact path is not a directory: %s", cleanRoot)
	}

	result := Result{}
	err = filepath.WalkDir(cleanRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("walk artifact directory: %w", walkErr)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.IsDir() || !isBrowserDatabase(entry.Name()) {
			return nil
		}
		events, ok, err := ParseFile(path, caseID)
		if err != nil {
			result.Stats.ParseErrors++
			return nil
		}
		if !ok {
			result.Stats.MalformedFilesSkipped++
			return nil
		}
		result.Files = append(result.Files, path)
		result.Events = append(result.Events, events...)
		result.Stats.FilesParsed++
		result.Stats.EventsEmitted += len(events)
		return nil
	})
	if err != nil {
		return Result{}, err
	}
	return result, nil
}

func ParseFile(path string, caseID string) ([]domain.TimelineEvent, bool, error) {
	cleanPath := filepath.Clean(path)
	kind, ok := inferBrowserKind(cleanPath)
	if !ok {
		return nil, false, nil
	}
	if err := artifact.CheckReadableFile(cleanPath); err != nil {
		return nil, false, err
	}
	db, err := openReadOnly(cleanPath)
	if err != nil {
		return nil, false, nil
	}
	defer db.Close()

	var events []domain.TimelineEvent
	switch kind {
	case BrowserFirefox:
		visits, ok, err := parseFirefoxVisits(db)
		if err != nil {
			return nil, false, nil
		}
		if !ok {
			return nil, false, nil
		}
		for _, visit := range visits {
			events = append(events, normalizeVisit(cleanPath, caseID, kind, visit))
		}
	default:
		visits, ok, err := parseChromiumVisits(db)
		if err != nil {
			return nil, false, nil
		}
		if ok {
			for _, visit := range visits {
				events = append(events, normalizeVisit(cleanPath, caseID, kind, visit))
			}
		}
		downloads, err := parseChromiumDownloads(db)
		if err != nil {
			return nil, false, nil
		}
		for _, download := range downloads {
			events = append(events, normalizeDownload(cleanPath, caseID, kind, download))
		}
	}
	if len(events) == 0 {
		return nil, false, nil
	}
	for _, event := range events {
		if err := event.ValidateEnums(); err != nil {
			return nil, false, err
		}
	}
	return events, true, nil
}

func WebKitTimeToUnixNS(timestampUS int64) int64 {
	if timestampUS <= 0 {
		return 0
	}
	return (timestampUS - webkitUnixOffsetUS) * 1000
}

func FirefoxTimeToUnixNS(timestampUS int64) int64 {
	if timestampUS <= 0 {
		return 0
	}
	return timestampUS * 1000
}

func parseChromiumVisits(db *sql.DB) ([]VisitRecord, bool, error) {
	hasURLs, err := tableExists(db, "urls")
	if err != nil || !hasURLs {
		return nil, false, err
	}
	hasVisits, err := tableExists(db, "visits")
	if err != nil {
		return nil, false, err
	}
	if hasVisits {
		rows, err := db.Query(`SELECT
			CAST(visits.id AS TEXT),
			urls.url,
			COALESCE(urls.title, ''),
			COALESCE(urls.visit_count, 0),
			COALESCE(visits.visit_time, 0)
		FROM visits
		INNER JOIN urls ON visits.url = urls.id
		ORDER BY visits.visit_time ASC, visits.id ASC`)
		if err != nil {
			return nil, false, err
		}
		defer rows.Close()
		return scanChromiumVisitRows(rows)
	}
	rows, err := db.Query(`SELECT
		CAST(urls.id AS TEXT),
		urls.url,
		COALESCE(urls.title, ''),
		COALESCE(urls.visit_count, 0),
		COALESCE(urls.last_visit_time, 0)
	FROM urls
	WHERE COALESCE(urls.last_visit_time, 0) > 0
	ORDER BY urls.last_visit_time ASC, urls.id ASC`)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	return scanChromiumVisitRows(rows)
}

func scanChromiumVisitRows(rows *sql.Rows) ([]VisitRecord, bool, error) {
	records := make([]VisitRecord, 0)
	for rows.Next() {
		var record VisitRecord
		var timestampUS int64
		if err := rows.Scan(&record.RecordID, &record.URL, &record.Title, &record.VisitCount, &timestampUS); err != nil {
			return nil, false, err
		}
		record.Timestamp = WebKitTimeToUnixNS(timestampUS)
		if strings.TrimSpace(record.URL) != "" {
			records = append(records, record)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	return records, len(records) > 0, nil
}

func parseChromiumDownloads(db *sql.DB) ([]DownloadRecord, error) {
	hasDownloads, err := tableExists(db, "downloads")
	if err != nil || !hasDownloads {
		return nil, err
	}
	hasChains, err := tableExists(db, "downloads_url_chains")
	if err != nil {
		return nil, err
	}
	if hasChains {
		rows, err := db.Query(`SELECT
			CAST(downloads.id AS TEXT),
			COALESCE(downloads.target_path, ''),
			COALESCE(downloads.current_path, ''),
			COALESCE(downloads.start_time, 0),
			COALESCE(downloads.end_time, 0),
			COALESCE(downloads_url_chains.url, '')
		FROM downloads
		LEFT JOIN downloads_url_chains ON downloads.id = downloads_url_chains.id
		ORDER BY downloads.start_time ASC, downloads.id ASC, downloads_url_chains.chain_index ASC`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		return scanChromiumDownloadRows(rows)
	}
	rows, err := db.Query(`SELECT
		CAST(downloads.id AS TEXT),
		COALESCE(downloads.target_path, ''),
		COALESCE(downloads.current_path, ''),
		COALESCE(downloads.start_time, 0),
		COALESCE(downloads.end_time, 0),
		''
	FROM downloads
	ORDER BY downloads.start_time ASC, downloads.id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanChromiumDownloadRows(rows)
}

func scanChromiumDownloadRows(rows *sql.Rows) ([]DownloadRecord, error) {
	records := make([]DownloadRecord, 0)
	for rows.Next() {
		var record DownloadRecord
		var currentPath string
		var startUS int64
		var endUS int64
		if err := rows.Scan(&record.RecordID, &record.TargetPath, &currentPath, &startUS, &endUS, &record.URL); err != nil {
			return nil, err
		}
		if strings.TrimSpace(record.TargetPath) == "" {
			record.TargetPath = currentPath
		}
		record.StartNS = WebKitTimeToUnixNS(startUS)
		record.EndNS = WebKitTimeToUnixNS(endUS)
		if strings.TrimSpace(record.URL) != "" || strings.TrimSpace(record.TargetPath) != "" {
			records = append(records, record)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return records, nil
}

func parseFirefoxVisits(db *sql.DB) ([]VisitRecord, bool, error) {
	hasPlaces, err := tableExists(db, "moz_places")
	if err != nil || !hasPlaces {
		return nil, false, err
	}
	hasVisits, err := tableExists(db, "moz_historyvisits")
	if err != nil {
		return nil, false, err
	}
	if hasVisits {
		rows, err := db.Query(`SELECT
			CAST(moz_historyvisits.id AS TEXT),
			moz_places.url,
			COALESCE(moz_places.title, ''),
			COALESCE(moz_places.visit_count, 0),
			COALESCE(moz_historyvisits.visit_date, 0)
		FROM moz_historyvisits
		INNER JOIN moz_places ON moz_historyvisits.place_id = moz_places.id
		ORDER BY moz_historyvisits.visit_date ASC, moz_historyvisits.id ASC`)
		if err != nil {
			return nil, false, err
		}
		defer rows.Close()
		return scanFirefoxVisitRows(rows)
	}
	rows, err := db.Query(`SELECT
		CAST(moz_places.id AS TEXT),
		moz_places.url,
		COALESCE(moz_places.title, ''),
		COALESCE(moz_places.visit_count, 0),
		COALESCE(moz_places.last_visit_date, 0)
	FROM moz_places
	WHERE COALESCE(moz_places.last_visit_date, 0) > 0
	ORDER BY moz_places.last_visit_date ASC, moz_places.id ASC`)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	return scanFirefoxVisitRows(rows)
}

func scanFirefoxVisitRows(rows *sql.Rows) ([]VisitRecord, bool, error) {
	records := make([]VisitRecord, 0)
	for rows.Next() {
		var record VisitRecord
		var timestampUS int64
		if err := rows.Scan(&record.RecordID, &record.URL, &record.Title, &record.VisitCount, &timestampUS); err != nil {
			return nil, false, err
		}
		record.Timestamp = FirefoxTimeToUnixNS(timestampUS)
		if strings.TrimSpace(record.URL) != "" {
			records = append(records, record)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	return records, len(records) > 0, nil
}

func normalizeVisit(sourcePath string, caseID string, kind BrowserKind, record VisitRecord) domain.TimelineEvent {
	event := domain.TimelineEvent{
		SchemaVersion:      "1",
		ToolVersion:        version.Version,
		ParserName:         parserName,
		ParserVersion:      parserVersion,
		CaseID:             caseID,
		SourceType:         sourceType(kind),
		SourcePath:         sourcePath,
		SourceRecordID:     "visit:" + record.RecordID,
		RawRef:             domain.RawRef{Type: "browser_history", URI: sourcePath},
		TimestampNS:        record.Timestamp,
		TimestampPrecision: timestampPrecisionNS,
		TimestampSource:    "browser_history",
		Category:           "browser",
		Action:             "visited",
		Severity:           domain.SeverityLow,
		Confidence:         domain.ConfidenceMedium,
		EvidenceStrength:   domain.EvidenceSingleSource,
		Object:             domain.Object{Type: "url", Name: record.Title},
		Network:            domain.Network{URL: record.URL, DNSName: hostFromURL(record.URL)},
		Tags:               []string{"windows", "browser", string(kind), "visit_count:" + strconv.Itoa(record.VisitCount)},
	}
	event.ID = domain.GenerateEventID(event)
	return event
}

func normalizeDownload(sourcePath string, caseID string, kind BrowserKind, record DownloadRecord) domain.TimelineEvent {
	timestamp := record.StartNS
	precision := timestampPrecisionNS
	if timestamp == 0 {
		timestamp = record.EndNS
	}
	if timestamp == 0 {
		precision = domain.TimestampPrecisionUnknown
	}
	event := domain.TimelineEvent{
		SchemaVersion:      "1",
		ToolVersion:        version.Version,
		ParserName:         parserName,
		ParserVersion:      parserVersion,
		CaseID:             caseID,
		SourceType:         sourceType(kind),
		SourcePath:         sourcePath,
		SourceRecordID:     "download:" + record.RecordID,
		RawRef:             domain.RawRef{Type: "browser_download", URI: sourcePath},
		TimestampNS:        timestamp,
		TimestampPrecision: precision,
		TimestampSource:    "browser_download",
		Category:           "browser",
		Action:             "downloaded",
		Severity:           domain.SeverityMedium,
		Confidence:         domain.ConfidenceMedium,
		EvidenceStrength:   domain.EvidenceSingleSource,
		Object:             domain.Object{Type: "file", Path: record.TargetPath, Name: filepath.Base(strings.ReplaceAll(record.TargetPath, "\\", "/"))},
		Network:            domain.Network{URL: record.URL, DNSName: hostFromURL(record.URL)},
		Tags:               []string{"windows", "browser", string(kind), "download"},
	}
	if record.EndNS != 0 {
		event.Tags = append(event.Tags, "download_end_ns:"+strconv.FormatInt(record.EndNS, 10))
	}
	event.ID = domain.GenerateEventID(event)
	return event
}

func tableExists(db *sql.DB, table string) (bool, error) {
	var name string
	err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return name == table, nil
}

func openReadOnly(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro&immutable=1")
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func inferBrowserKind(path string) (BrowserKind, bool) {
	name := strings.ToLower(filepath.Base(path))
	switch name {
	case "places.sqlite":
		return BrowserFirefox, true
	case "history":
		lowerPath := strings.ToLower(filepath.ToSlash(path))
		if strings.Contains(lowerPath, "edge") {
			return BrowserEdge, true
		}
		return BrowserChrome, true
	default:
		return "", false
	}
}

func isBrowserDatabase(name string) bool {
	lower := strings.ToLower(name)
	return lower == "history" || lower == "places.sqlite"
}

func sourceType(kind BrowserKind) string {
	return "browser_" + string(kind)
}

func hostFromURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}
