package amcache

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"timeline/internal/artifact"
	"timeline/internal/domain"
	"timeline/internal/version"
)

const (
	parserName    = "amcache-text"
	parserVersion = "0.6.0"
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

type Record struct {
	Path         string
	SHA1         string
	Publisher    string
	Product      string
	TimestampNS  int64
	HasTimestamp bool
	Executed     bool
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
		if entry.IsDir() || !strings.EqualFold(entry.Name(), "AmCache.hve") {
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
	if err := artifact.CheckReadableFile(cleanPath); err != nil {
		return nil, false, err
	}
	content, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, false, fmt.Errorf("read AmCache file %s: %w", cleanPath, err)
	}
	records, ok, err := parseRecords(content)
	if err != nil {
		return nil, false, err
	}
	if !ok {
		return nil, false, nil
	}
	events := make([]domain.TimelineEvent, 0, len(records))
	for index, record := range records {
		event := normalizeRecord(cleanPath, caseID, index+1, record)
		if err := event.ValidateEnums(); err != nil {
			return nil, false, err
		}
		events = append(events, event)
	}
	return events, true, nil
}

func parseRecords(content []byte) ([]Record, bool, error) {
	if len(bytes.TrimSpace(content)) == 0 || bytes.IndexByte(content, 0) >= 0 {
		return nil, false, nil
	}
	records := make([]Record, 0)
	current := map[string]string{}
	flush := func() bool {
		if len(current) == 0 {
			return true
		}
		record, ok := recordFromMap(current)
		if !ok {
			return false
		}
		records = append(records, record)
		current = map[string]string{}
		return true
	}

	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			if !flush() {
				return nil, false, nil
			}
			continue
		}
		if strings.EqualFold(line, "[entry]") {
			if !flush() {
				return nil, false, nil
			}
			continue
		}
		if strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, false, nil
		}
		current[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
	}
	if err := scanner.Err(); err != nil {
		return nil, false, err
	}
	if !flush() {
		return nil, false, nil
	}
	if len(records) == 0 {
		return nil, false, nil
	}
	return records, true, nil
}

func recordFromMap(values map[string]string) (Record, bool) {
	record := Record{
		Path:      first(values, "path", "filepath", "executablepath"),
		SHA1:      strings.ToLower(first(values, "sha1", "hash")),
		Publisher: first(values, "publisher"),
		Product:   first(values, "product"),
	}
	if record.Path == "" && record.SHA1 == "" {
		return Record{}, false
	}
	if timestamp := first(values, "timestamp", "lastmodified", "lastrun"); timestamp != "" {
		t, err := time.Parse(time.RFC3339Nano, timestamp)
		if err != nil {
			return Record{}, false
		}
		record.TimestampNS = t.UTC().UnixNano()
		record.HasTimestamp = true
	}
	if executed := first(values, "executed", "execution"); executed != "" {
		parsed, err := strconv.ParseBool(executed)
		if err != nil {
			return Record{}, false
		}
		record.Executed = parsed
	}
	return record, true
}

func normalizeRecord(sourcePath string, caseID string, recordIndex int, record Record) domain.TimelineEvent {
	category := "filesystem"
	action := "observed"
	if record.Executed {
		category = "process"
		action = "executed"
	}
	precision := domain.TimestampPrecisionUnknown
	if record.HasTimestamp {
		precision = domain.TimestampPrecisionNanosecond
	}
	tags := []string{"windows", "amcache"}
	if record.Publisher != "" {
		tags = append(tags, "publisher:"+record.Publisher)
	}
	if record.Product != "" {
		tags = append(tags, "product:"+record.Product)
	}
	event := domain.TimelineEvent{
		SchemaVersion:      "1",
		ToolVersion:        version.Version,
		ParserName:         parserName,
		ParserVersion:      parserVersion,
		CaseID:             caseID,
		SourceType:         "amcache",
		SourcePath:         sourcePath,
		SourceRecordID:     strconv.Itoa(recordIndex),
		RawRef:             domain.RawRef{Type: "amcache_entry", URI: sourcePath},
		TimestampNS:        record.TimestampNS,
		TimestampPrecision: precision,
		TimestampSource:    "amcache",
		Category:           category,
		Action:             action,
		Severity:           domain.SeverityMedium,
		Confidence:         domain.ConfidenceMedium,
		EvidenceStrength:   domain.EvidenceSingleSource,
		Actor:              domain.Actor{Image: record.Path},
		Object: domain.Object{
			Type: "file",
			Path: record.Path,
			Name: filepath.Base(strings.ReplaceAll(record.Path, "\\", "/")),
			Hash: record.SHA1,
		},
		Tags: tags,
	}
	event.ID = domain.GenerateEventID(event)
	return event
}

func first(values map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(values[key]); value != "" {
			return value
		}
	}
	return ""
}
