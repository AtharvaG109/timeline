package prefetch

import (
	"bufio"
	"bytes"
	"context"
	"errors"
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
	parserName    = "prefetch-text"
	parserVersion = "0.5.0"
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
	ExecutableName  string
	RunCount        int
	LastRunNS       int64
	HasLastRun      bool
	ReferencedFiles []string
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
		if entry.IsDir() || !strings.EqualFold(filepath.Ext(entry.Name()), ".pf") {
			return nil
		}
		event, ok, err := ParseFile(path, caseID)
		if err != nil {
			result.Stats.ParseErrors++
			return nil
		}
		if !ok {
			result.Stats.MalformedFilesSkipped++
			return nil
		}
		result.Files = append(result.Files, path)
		result.Events = append(result.Events, event)
		result.Stats.FilesParsed++
		result.Stats.EventsEmitted++
		return nil
	})
	if err != nil {
		return Result{}, err
	}
	return result, nil
}

func ParseFile(path string, caseID string) (domain.TimelineEvent, bool, error) {
	cleanPath := filepath.Clean(path)
	if err := artifact.CheckReadableFile(cleanPath); err != nil {
		return domain.TimelineEvent{}, false, err
	}
	content, err := os.ReadFile(cleanPath)
	if err != nil {
		return domain.TimelineEvent{}, false, fmt.Errorf("read Prefetch file %s: %w", cleanPath, err)
	}
	record, ok, err := parseRecord(cleanPath, content)
	if err != nil {
		return domain.TimelineEvent{}, false, err
	}
	if !ok {
		return domain.TimelineEvent{}, false, nil
	}
	timestampPrecision := domain.TimestampPrecisionNanosecond
	if !record.HasLastRun {
		timestampPrecision = domain.TimestampPrecisionUnknown
	}
	event := domain.TimelineEvent{
		SchemaVersion:      "1",
		ToolVersion:        version.Version,
		ParserName:         parserName,
		ParserVersion:      parserVersion,
		CaseID:             caseID,
		SourceType:         "prefetch",
		SourcePath:         cleanPath,
		RawRef:             domain.RawRef{Type: "prefetch_file", URI: cleanPath},
		TimestampNS:        record.LastRunNS,
		TimestampPrecision: timestampPrecision,
		TimestampSource:    "prefetch_last_run",
		Category:           "process",
		Action:             "executed",
		Severity:           domain.SeverityMedium,
		Confidence:         domain.ConfidenceMedium,
		EvidenceStrength:   domain.EvidenceSingleSource,
		Actor: domain.Actor{
			Image: record.ExecutableName,
		},
		Object: domain.Object{
			Type: "process",
			Path: record.ExecutableName,
			Name: record.ExecutableName,
		},
		Tags: []string{"windows", "prefetch", "process"},
	}
	if record.RunCount > 0 {
		event.Tags = append(event.Tags, "run_count:"+strconv.Itoa(record.RunCount))
	}
	for _, referenced := range record.ReferencedFiles {
		if referenced != "" {
			event.Tags = append(event.Tags, "ref:"+referenced)
		}
	}
	event.ID = domain.GenerateEventID(event)
	if err := event.ValidateEnums(); err != nil {
		return domain.TimelineEvent{}, false, err
	}
	return event, true, nil
}

func parseRecord(path string, content []byte) (Record, bool, error) {
	if len(bytes.TrimSpace(content)) == 0 || bytes.IndexByte(content, 0) >= 0 {
		return Record{}, false, nil
	}
	record := Record{ExecutableName: executableFromFilename(path)}
	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			return Record{}, false, nil
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		switch key {
		case "executablename", "executable":
			record.ExecutableName = value
		case "runcount":
			runCount, err := strconv.Atoi(value)
			if err != nil {
				return Record{}, false, nil
			}
			record.RunCount = runCount
		case "lastrun", "lastrunutc":
			t, err := time.Parse(time.RFC3339Nano, value)
			if err != nil {
				return Record{}, false, nil
			}
			record.LastRunNS = t.UTC().UnixNano()
			record.HasLastRun = true
		case "referencedfile":
			record.ReferencedFiles = append(record.ReferencedFiles, value)
		}
	}
	if err := scanner.Err(); err != nil {
		return Record{}, false, err
	}
	if strings.TrimSpace(record.ExecutableName) == "" {
		return Record{}, false, errors.New("prefetch record missing executable name")
	}
	return record, true, nil
}

func executableFromFilename(path string) string {
	name := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	if before, _, ok := strings.Cut(name, "-"); ok {
		return before
	}
	return name
}
