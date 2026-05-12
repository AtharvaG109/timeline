package evtx

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
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
	parserName    = "evtx-xml"
	parserVersion = "0.2.0"
)

type Stats struct {
	FilesParsed   int
	EventsEmitted int
	EventsSkipped int
	ParseErrors   int
}

type Result struct {
	Events []domain.TimelineEvent
	Files  []string
	Stats  Stats
}

type record struct {
	System struct {
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
		EventID struct {
			Value string `xml:",chardata"`
		} `xml:"EventID"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		Computer      string `xml:"Computer"`
		EventRecordID string `xml:"EventRecordID"`
		Channel       string `xml:"Channel"`
	} `xml:"System"`
	EventData struct {
		Data []eventData `xml:"Data"`
	} `xml:"EventData"`
	UserData struct {
		XMLName xml.Name
		Inner   string `xml:",innerxml"`
	} `xml:"UserData"`
}

type eventData struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:",chardata"`
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
		if entry.IsDir() {
			return nil
		}
		if !strings.EqualFold(filepath.Ext(entry.Name()), ".evtx") {
			return nil
		}
		if !isSupportedLogPath(path) {
			return nil
		}

		events, stats, err := ParseFile(path, caseID)
		result.Stats.FilesParsed += stats.FilesParsed
		result.Stats.EventsEmitted += stats.EventsEmitted
		result.Stats.EventsSkipped += stats.EventsSkipped
		result.Stats.ParseErrors += stats.ParseErrors
		if err != nil {
			return err
		}
		result.Events = append(result.Events, events...)
		result.Files = append(result.Files, path)
		return nil
	})
	if err != nil {
		return Result{}, err
	}
	return result, nil
}

func ParseFile(path string, caseID string) ([]domain.TimelineEvent, Stats, error) {
	cleanPath := filepath.Clean(path)
	if err := artifact.CheckReadableFile(cleanPath); err != nil {
		return nil, Stats{ParseErrors: 1}, err
	}
	content, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, Stats{ParseErrors: 1}, fmt.Errorf("read EVTX log %s: %w", cleanPath, err)
	}
	if len(bytes.TrimSpace(content)) == 0 {
		return nil, Stats{ParseErrors: 1}, fmt.Errorf("malformed EVTX log %s: file is empty", cleanPath)
	}
	if looksBinaryEVTX(content) {
		return nil, Stats{ParseErrors: 1}, fmt.Errorf("malformed EVTX log %s: binary EVTX records are not accepted by the Phase 2 fixture parser; provide exported Event XML", cleanPath)
	}

	records, err := parseXMLRecords(content)
	if err != nil {
		return nil, Stats{ParseErrors: 1}, fmt.Errorf("malformed EVTX log %s: %w", cleanPath, err)
	}

	stats := Stats{FilesParsed: 1}
	events := make([]domain.TimelineEvent, 0, len(records))
	for _, rec := range records {
		event, ok, err := NormalizeRecord(cleanPath, caseID, rec)
		if err != nil {
			stats.ParseErrors++
			return nil, stats, fmt.Errorf("normalize EVTX log %s record %s: %w", cleanPath, rec.System.EventRecordID, err)
		}
		if !ok {
			stats.EventsSkipped++
			continue
		}
		events = append(events, event)
		stats.EventsEmitted++
	}
	return events, stats, nil
}

func parseXMLRecords(content []byte) ([]record, error) {
	decoder := xml.NewDecoder(bytes.NewReader(content))
	records := make([]record, 0)
	for {
		token, err := decoder.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		start, ok := token.(xml.StartElement)
		if !ok || start.Name.Local != "Event" {
			continue
		}
		var rec record
		if err := decoder.DecodeElement(&rec, &start); err != nil {
			return nil, err
		}
		records = append(records, rec)
	}
	if len(records) == 0 {
		return nil, errors.New("no Event records found")
	}
	return records, nil
}

func NormalizeRecord(sourcePath string, caseID string, rec record) (domain.TimelineEvent, bool, error) {
	eventID, err := strconv.Atoi(strings.TrimSpace(rec.System.EventID.Value))
	if err != nil {
		return domain.TimelineEvent{}, false, fmt.Errorf("invalid event id %q", rec.System.EventID.Value)
	}

	values := dataMap(rec.EventData.Data)
	meta, ok := eventMetadata(eventID, rec.System.Provider.Name, rec.System.Channel)
	if !ok {
		return domain.TimelineEvent{}, false, nil
	}

	timestampNS, err := parseWindowsTime(rec.System.TimeCreated.SystemTime)
	if err != nil {
		return domain.TimelineEvent{}, false, err
	}

	event := domain.TimelineEvent{
		SchemaVersion:      "1",
		ToolVersion:        version.Version,
		ParserName:         parserName,
		ParserVersion:      parserVersion,
		CaseID:             caseID,
		HostID:             strings.TrimSpace(rec.System.Computer),
		SourceType:         "evtx",
		SourcePath:         sourcePath,
		SourceRecordID:     strings.TrimSpace(rec.System.EventRecordID),
		RawRef:             domain.RawRef{Type: "evtx_record", URI: sourcePath},
		TimestampNS:        timestampNS,
		TimestampPrecision: domain.TimestampPrecisionNanosecond,
		TimestampSource:    "System.TimeCreated.SystemTime",
		Category:           meta.category,
		Action:             meta.action,
		Severity:           meta.severity,
		Confidence:         meta.confidence,
		EvidenceStrength:   meta.evidence,
		Actor:              actorForEvent(eventID, values),
		Object:             objectForEvent(eventID, values),
		Network:            networkForEvent(eventID, values),
		Tags:               tagsForEvent(eventID),
		MITRETechniques:    mitreForEvent(eventID),
	}
	event.ID = domain.GenerateEventID(event)
	if err := event.ValidateEnums(); err != nil {
		return domain.TimelineEvent{}, false, err
	}
	return event, true, nil
}

func dataMap(items []eventData) map[string]string {
	values := make(map[string]string, len(items))
	for _, item := range items {
		name := strings.TrimSpace(item.Name)
		if name == "" {
			continue
		}
		values[name] = strings.TrimSpace(item.Value)
	}
	return values
}

type metadata struct {
	category   string
	action     string
	severity   domain.Severity
	confidence domain.Confidence
	evidence   domain.EvidenceStrength
}

func eventMetadata(eventID int, provider string, channel string) (metadata, bool) {
	if isSysmonProvider(provider) {
		return sysmonMetadata(eventID)
	}
	if isPowerShellProvider(provider, channel) {
		return powershellMetadata(eventID)
	}
	return windowsMetadata(eventID)
}

func windowsMetadata(eventID int) (metadata, bool) {
	switch eventID {
	case 4624:
		return meta("auth", "successful_logon", domain.SeverityMedium, domain.ConfidenceHigh, domain.EvidenceStrong), true
	case 4625:
		return meta("auth", "failed_logon", domain.SeverityLow, domain.ConfidenceHigh, domain.EvidenceStrong), true
	case 4634:
		return meta("auth", "logoff", domain.SeverityInfo, domain.ConfidenceHigh, domain.EvidenceModerate), true
	case 4648:
		return meta("auth", "explicit_credentials_used", domain.SeverityMedium, domain.ConfidenceHigh, domain.EvidenceStrong), true
	case 4672:
		return meta("auth", "special_privileges_assigned", domain.SeverityMedium, domain.ConfidenceHigh, domain.EvidenceStrong), true
	case 4688:
		return meta("process", "process_created", domain.SeverityMedium, domain.ConfidenceHigh, domain.EvidenceStrong), true
	case 4697:
		return meta("persistence", "service_installed", domain.SeverityHigh, domain.ConfidenceHigh, domain.EvidenceStrong), true
	case 4698:
		return meta("persistence", "scheduled_task_created", domain.SeverityHigh, domain.ConfidenceHigh, domain.EvidenceStrong), true
	case 4702:
		return meta("persistence", "scheduled_task_updated", domain.SeverityMedium, domain.ConfidenceHigh, domain.EvidenceStrong), true
	case 4720:
		return meta("account", "user_account_created", domain.SeverityHigh, domain.ConfidenceHigh, domain.EvidenceStrong), true
	case 4728:
		return meta("account", "privileged_group_member_added", domain.SeverityHigh, domain.ConfidenceHigh, domain.EvidenceStrong), true
	case 4732:
		return meta("account", "local_group_member_added", domain.SeverityHigh, domain.ConfidenceHigh, domain.EvidenceStrong), true
	case 7045:
		return meta("persistence", "service_installed", domain.SeverityHigh, domain.ConfidenceHigh, domain.EvidenceStrong), true
	default:
		return metadata{}, false
	}
}

func sysmonMetadata(eventID int) (metadata, bool) {
	switch eventID {
	case 1:
		return meta("process", "process_created", domain.SeverityMedium, domain.ConfidenceHigh, domain.EvidenceStrong), true
	case 3:
		return meta("network", "network_connection", domain.SeverityMedium, domain.ConfidenceHigh, domain.EvidenceStrong), true
	case 7:
		return meta("process", "image_loaded", domain.SeverityLow, domain.ConfidenceMedium, domain.EvidenceModerate), true
	case 10:
		return meta("process", "process_access", domain.SeverityMedium, domain.ConfidenceMedium, domain.EvidenceModerate), true
	case 11:
		return meta("filesystem", "file_created", domain.SeverityMedium, domain.ConfidenceHigh, domain.EvidenceStrong), true
	case 12:
		return meta("registry", "registry_object_changed", domain.SeverityMedium, domain.ConfidenceHigh, domain.EvidenceStrong), true
	case 13:
		return meta("registry", "registry_value_set", domain.SeverityMedium, domain.ConfidenceHigh, domain.EvidenceStrong), true
	case 22:
		return meta("network", "dns_query", domain.SeverityMedium, domain.ConfidenceHigh, domain.EvidenceStrong), true
	default:
		return metadata{}, false
	}
}

func powershellMetadata(eventID int) (metadata, bool) {
	switch eventID {
	case 400:
		return meta("powershell", "engine_start", domain.SeverityLow, domain.ConfidenceHigh, domain.EvidenceModerate), true
	case 403:
		return meta("powershell", "engine_stop", domain.SeverityInfo, domain.ConfidenceHigh, domain.EvidenceModerate), true
	case 4103:
		return meta("powershell", "module_logging", domain.SeverityMedium, domain.ConfidenceHigh, domain.EvidenceStrong), true
	case 4104:
		return meta("powershell", "script_block_logging", domain.SeverityHigh, domain.ConfidenceHigh, domain.EvidenceStrong), true
	default:
		return metadata{}, false
	}
}

func meta(category string, action string, severity domain.Severity, confidence domain.Confidence, evidence domain.EvidenceStrength) metadata {
	return metadata{category: category, action: action, severity: severity, confidence: confidence, evidence: evidence}
}

func actorForEvent(eventID int, values map[string]string) domain.Actor {
	actor := domain.Actor{
		User:      first(values, "SubjectUserName", "TargetUserName", "User", "UserName"),
		Image:     first(values, "NewProcessName", "Image", "ProcessName", "Application"),
		Cmdline:   first(values, "CommandLine", "ProcessCommandLine", "ScriptBlockText", "HostApplication"),
		SessionID: first(values, "LogonId", "TargetLogonId", "SubjectLogonId", "LogonGuid"),
	}
	actor.PID = parseWindowsInt(first(values, "NewProcessId", "ProcessId", "ProcessID"))
	actor.ParentPID = parseWindowsInt(first(values, "ParentProcessId", "ParentProcessID"))
	if eventID == 4624 || eventID == 4625 || eventID == 4634 {
		actor.User = first(values, "TargetUserName", "SubjectUserName")
	}
	return actor
}

func objectForEvent(eventID int, values map[string]string) domain.Object {
	switch eventID {
	case 4688, 1:
		return domain.Object{Type: "process", Path: first(values, "NewProcessName", "Image"), Name: first(values, "ProcessName", "Image")}
	case 4697, 7045:
		return domain.Object{Type: "service", Path: first(values, "ServiceFileName", "ImagePath"), Name: first(values, "ServiceName")}
	case 4698, 4702:
		return domain.Object{Type: "scheduled_task", Path: first(values, "TaskContent"), Name: first(values, "TaskName")}
	case 4720:
		return domain.Object{Type: "account", Name: first(values, "TargetUserName")}
	case 4728, 4732:
		return domain.Object{Type: "group", Name: first(values, "TargetUserName", "GroupName")}
	case 7:
		return domain.Object{Type: "image", Path: first(values, "ImageLoaded")}
	case 10:
		return domain.Object{Type: "process", Path: first(values, "TargetImage"), Name: first(values, "TargetProcessGUID")}
	case 11:
		return domain.Object{Type: "file", Path: first(values, "TargetFilename")}
	case 12, 13:
		return domain.Object{Type: "registry", Path: first(values, "TargetObject")}
	case 22:
		return domain.Object{Type: "dns", Name: first(values, "QueryName")}
	case 4103, 4104:
		return domain.Object{Type: "script", Name: first(values, "ScriptBlockId", "CommandInvocation")}
	default:
		return domain.Object{Type: first(values, "ObjectType"), Path: first(values, "ObjectName")}
	}
}

func networkForEvent(eventID int, values map[string]string) domain.Network {
	if eventID == 3 {
		return domain.Network{
			SrcIP:   first(values, "SourceIp", "SourceIP"),
			SrcPort: parseWindowsInt(first(values, "SourcePort")),
			DstIP:   first(values, "DestinationIp", "DestinationIP"),
			DstPort: parseWindowsInt(first(values, "DestinationPort")),
			DNSName: first(values, "DestinationHostname"),
		}
	}
	if eventID == 22 {
		return domain.Network{
			DNSName: first(values, "QueryName"),
			DstIP:   first(values, "QueryResults"),
		}
	}
	if eventID == 4624 || eventID == 4625 {
		return domain.Network{
			SrcIP:   first(values, "IpAddress", "WorkstationName"),
			SrcPort: parseWindowsInt(first(values, "IpPort")),
		}
	}
	return domain.Network{}
}

func tagsForEvent(eventID int) []string {
	switch eventID {
	case 4624, 4625, 4634, 4648, 4672:
		return []string{"windows", "security", "authentication"}
	case 4688, 1:
		return []string{"windows", "process"}
	case 4697, 4698, 4702, 7045:
		return []string{"windows", "persistence"}
	case 4103, 4104:
		return []string{"windows", "powershell"}
	default:
		return []string{"windows"}
	}
}

func mitreForEvent(eventID int) []string {
	switch eventID {
	case 4688, 1:
		return []string{"T1059"}
	case 4698, 4702:
		return []string{"T1053.005"}
	case 7045, 4697:
		return []string{"T1543.003"}
	case 4103, 4104:
		return []string{"T1059.001"}
	default:
		return nil
	}
}

func first(values map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(values[key]); value != "" {
			return value
		}
	}
	return ""
}

func parseWindowsInt(value string) int {
	value = strings.TrimSpace(value)
	if value == "" || value == "-" {
		return 0
	}
	base := 10
	if strings.HasPrefix(value, "0x") || strings.HasPrefix(value, "0X") {
		base = 0
	}
	parsed, err := strconv.ParseInt(value, base, 64)
	if err != nil {
		return 0
	}
	return int(parsed)
}

func parseWindowsTime(value string) (int64, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, errors.New("missing SystemTime")
	}
	t, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return 0, fmt.Errorf("parse SystemTime %q: %w", value, err)
	}
	return t.UTC().UnixNano(), nil
}

func isSupportedLogPath(path string) bool {
	normalized := strings.ToLower(filepath.ToSlash(path))
	base := strings.ToLower(filepath.Base(path))
	if base == "security.evtx" || base == "system.evtx" || base == "windows powershell.evtx" {
		return true
	}
	if strings.Contains(normalized, "microsoft-windows-powershell") && strings.HasSuffix(normalized, "operational.evtx") {
		return true
	}
	if strings.Contains(normalized, "microsoft-windows-sysmon") && strings.HasSuffix(normalized, "operational.evtx") {
		return true
	}
	return false
}

func isSysmonProvider(provider string) bool {
	return strings.Contains(strings.ToLower(provider), "sysmon")
}

func isPowerShellProvider(provider string, channel string) bool {
	provider = strings.ToLower(provider)
	channel = strings.ToLower(channel)
	return strings.Contains(provider, "powershell") || strings.Contains(channel, "powershell")
}

func looksBinaryEVTX(content []byte) bool {
	trimmed := bytes.TrimSpace(content)
	if bytes.HasPrefix(trimmed, []byte("ElfFile")) {
		return true
	}
	return bytes.IndexByte(trimmed, 0) >= 0
}
