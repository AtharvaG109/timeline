package scheduledtask

import (
	"context"
	"encoding/xml"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"timeline/internal/artifact"
	"timeline/internal/domain"
	"timeline/internal/version"
)

const (
	parserName    = "scheduled-task-xml"
	parserVersion = "0.11.0"
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
	TaskPath        string
	Author          string
	User            string
	Triggers        []Trigger
	ActionCommand   string
	ActionArguments string
	WorkingDir      string
	TimestampNS     int64
	HasTimestamp    bool
}

type Trigger struct {
	Type          string
	StartBoundary string
	Enabled       string
}

type taskXML struct {
	XMLName          xml.Name
	RegistrationInfo registrationInfoXML `xml:"RegistrationInfo"`
	Principals       principalsXML       `xml:"Principals"`
	Triggers         triggersXML         `xml:"Triggers"`
	Actions          actionsXML          `xml:"Actions"`
}

type registrationInfoXML struct {
	Date   string `xml:"Date"`
	Author string `xml:"Author"`
	URI    string `xml:"URI"`
}

type principalsXML struct {
	Principals []principalXML `xml:"Principal"`
}

type principalXML struct {
	UserID string `xml:"UserId"`
}

type triggersXML struct {
	Items []triggerXML `xml:",any"`
}

type triggerXML struct {
	XMLName       xml.Name
	StartBoundary string `xml:"StartBoundary"`
	Enabled       string `xml:"Enabled"`
}

type actionsXML struct {
	Execs []execXML `xml:"Exec"`
}

type execXML struct {
	Command          string `xml:"Command"`
	Arguments        string `xml:"Arguments"`
	WorkingDirectory string `xml:"WorkingDirectory"`
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
		if entry.IsDir() || !looksLikeTaskXML(path) {
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
		return nil, false, fmt.Errorf("read scheduled task XML %s: %w", cleanPath, err)
	}
	record, ok, err := ParseRecord(content, cleanPath)
	if err != nil {
		return nil, false, err
	}
	if !ok {
		return nil, false, nil
	}
	events := []domain.TimelineEvent{normalizeRecord(cleanPath, caseID, record)}
	if err := events[0].ValidateEnums(); err != nil {
		return nil, false, err
	}
	return events, true, nil
}

func ParseRecord(content []byte, sourcePath string) (Record, bool, error) {
	var parsed taskXML
	if err := xml.Unmarshal(content, &parsed); err != nil {
		return Record{}, false, fmt.Errorf("parse scheduled task XML %s: %w", sourcePath, err)
	}
	if parsed.XMLName.Local != "Task" {
		return Record{}, false, nil
	}
	if len(parsed.Actions.Execs) == 0 {
		return Record{}, false, nil
	}
	exec := parsed.Actions.Execs[0]
	if strings.TrimSpace(exec.Command) == "" {
		return Record{}, false, nil
	}
	record := Record{
		TaskPath:        firstNonEmpty(parsed.RegistrationInfo.URI, taskPathFromSource(sourcePath)),
		Author:          strings.TrimSpace(parsed.RegistrationInfo.Author),
		User:            firstPrincipalUser(parsed.Principals.Principals),
		ActionCommand:   strings.TrimSpace(exec.Command),
		ActionArguments: strings.TrimSpace(exec.Arguments),
		WorkingDir:      strings.TrimSpace(exec.WorkingDirectory),
	}
	if record.User == "" {
		record.User = record.Author
	}
	if parsed.RegistrationInfo.Date != "" {
		if timestamp, ok := parseTaskTimestamp(parsed.RegistrationInfo.Date); ok {
			record.TimestampNS = timestamp
			record.HasTimestamp = true
		}
	}
	for _, trigger := range parsed.Triggers.Items {
		item := Trigger{
			Type:          trigger.XMLName.Local,
			StartBoundary: strings.TrimSpace(trigger.StartBoundary),
			Enabled:       strings.TrimSpace(trigger.Enabled),
		}
		if item.Type != "" {
			record.Triggers = append(record.Triggers, item)
		}
		if !record.HasTimestamp && item.StartBoundary != "" {
			if timestamp, ok := parseTaskTimestamp(item.StartBoundary); ok {
				record.TimestampNS = timestamp
				record.HasTimestamp = true
			}
		}
	}
	return record, true, nil
}

func normalizeRecord(sourcePath string, caseID string, record Record) domain.TimelineEvent {
	precision := domain.TimestampPrecisionUnknown
	action := "configured"
	if record.HasTimestamp {
		precision = domain.TimestampPrecisionNanosecond
		action = "created"
	}
	cmdline := strings.TrimSpace(record.ActionCommand + " " + record.ActionArguments)
	tags := []string{"windows", "scheduled-task", "persistence"}
	if record.WorkingDir != "" {
		tags = append(tags, "working_dir:"+record.WorkingDir)
	}
	for _, trigger := range record.Triggers {
		tags = append(tags, "trigger:"+trigger.Type)
		if trigger.Enabled != "" {
			tags = append(tags, "trigger_enabled:"+trigger.Enabled)
		}
	}
	event := domain.TimelineEvent{
		SchemaVersion:      "1",
		ToolVersion:        version.Version,
		ParserName:         parserName,
		ParserVersion:      parserVersion,
		CaseID:             caseID,
		SourceType:         "scheduled_task_xml",
		SourcePath:         sourcePath,
		SourceRecordID:     record.TaskPath,
		RawRef:             domain.RawRef{Type: "scheduled_task_xml", URI: sourcePath},
		TimestampNS:        record.TimestampNS,
		TimestampPrecision: precision,
		TimestampSource:    "scheduled_task_xml",
		Category:           "persistence",
		Action:             action,
		Severity:           domain.SeverityMedium,
		Confidence:         domain.ConfidenceMedium,
		EvidenceStrength:   domain.EvidenceSingleSource,
		Actor: domain.Actor{
			User:    record.User,
			Image:   record.ActionCommand,
			Cmdline: cmdline,
		},
		Object: domain.Object{
			Type: "scheduled_task",
			Path: record.TaskPath,
			Name: filepath.Base(strings.ReplaceAll(record.TaskPath, "\\", "/")),
		},
		Tags:            tags,
		MITRETechniques: []string{"T1053.005"},
	}
	event.ID = domain.GenerateEventID(event)
	return event
}

func looksLikeTaskXML(path string) bool {
	name := strings.ToLower(filepath.Base(path))
	if filepath.Ext(name) == ".xml" {
		return true
	}
	normalized := strings.ToLower(filepath.ToSlash(path))
	return strings.Contains(normalized, "/windows/system32/tasks/")
}

func taskPathFromSource(path string) string {
	name := filepath.Base(path)
	if ext := filepath.Ext(name); ext != "" {
		name = strings.TrimSuffix(name, ext)
	}
	if name == "" || name == "." {
		name = "scheduled-task"
	}
	return `\` + name
}

func firstPrincipalUser(principals []principalXML) string {
	for _, principal := range principals {
		if value := strings.TrimSpace(principal.UserID); value != "" {
			return value
		}
	}
	return ""
}

func parseTaskTimestamp(value string) (int64, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05"} {
		timestamp, err := time.Parse(layout, value)
		if err == nil {
			return timestamp.UTC().UnixNano(), true
		}
	}
	return 0, false
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
