package diff

import (
	"strings"
	"testing"

	"timeline/internal/domain"
	"timeline/internal/store"
)

func TestFingerprintNormalization(t *testing.T) {
	normalized := NormalizeValue(`C:\Users\Alice\AppData\Local\Temp\ABCD1234EF.exe {2f1a0b00-03d8-4a49-b8f8-6ef23f47c512} U0dWc2JHOGdWMjl5YkdRPQ== 2024-05-06T20:04:10Z ACME\bob`)
	for _, want := range []string{"c:/users/<USER>", "<RANDOM>.exe", "<GUID>", "<BASE64>", "<TIME>", "<USER>"} {
		if !strings.Contains(normalized, want) {
			t.Fatalf("normalized value missing %q: %s", want, normalized)
		}
	}
	if strings.Contains(normalized, "  ") {
		t.Fatalf("whitespace was not collapsed: %q", normalized)
	}
}

func TestTimestampOnlyDifferencesIgnored(t *testing.T) {
	baseline := processEvent("base", 100, "C:/Windows/System32/notepad.exe", "notepad.exe")
	incident := processEvent("incident", 200, "C:/Windows/System32/notepad.exe", "notepad.exe")

	result := Compare([]domain.TimelineEvent{baseline}, []domain.TimelineEvent{incident}, nil, nil)
	if result.Summary.Total != 0 {
		t.Fatalf("findings = %d, want 0: %+v", result.Summary.Total, result.Findings)
	}
}

func TestProcessDiffNewEncodedPowerShellHigh(t *testing.T) {
	baseline := processEvent("base", 100, "C:/Windows/System32/notepad.exe", "notepad.exe")
	incident := processEvent("incident", 200, "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe", "powershell.exe -EncodedCommand SQBFAFgA")

	result := Compare([]domain.TimelineEvent{baseline}, []domain.TimelineEvent{incident}, nil, nil)
	finding := requireFinding(t, result, TypeNewProcess)
	if finding.Severity != domain.SeverityHigh {
		t.Fatalf("severity = %q", finding.Severity)
	}
}

func TestProcessDiffNewCommandLine(t *testing.T) {
	baseline := processEvent("base", 100, "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe", "powershell.exe -NoProfile")
	incident := processEvent("incident", 200, "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe", "powershell.exe -NoProfile -EncodedCommand SQBFAFgA")

	result := Compare([]domain.TimelineEvent{baseline}, []domain.TimelineEvent{incident}, nil, nil)
	finding := requireFinding(t, result, TypeNewCmdline)
	if finding.Severity != domain.SeverityHigh {
		t.Fatalf("severity = %q", finding.Severity)
	}
}

func TestAuthDiffRemoteLogon(t *testing.T) {
	incident := testEvent("auth", 100, "auth", "successful_logon")
	incident.Network.SrcIP = "203.0.113.24"

	result := Compare(nil, []domain.TimelineEvent{incident}, nil, nil)
	finding := requireFinding(t, result, TypeNewRemoteLogon)
	if finding.Severity != domain.SeverityHigh {
		t.Fatalf("severity = %q", finding.Severity)
	}
}

func TestNetworkDiffs(t *testing.T) {
	connection := testEvent("network", 100, "network", "connected")
	connection.Network.DstIP = "198.51.100.10"
	connection.Network.DstPort = 443
	dns := testEvent("dns", 200, "network", "dns_query")
	dns.Network.DNSName = "example.invalid"

	result := Compare(nil, []domain.TimelineEvent{connection, dns}, nil, nil)
	requireFinding(t, result, TypeNewNetworkDestination)
	requireFinding(t, result, TypeNewDNSQuery)
}

func TestPersistenceDiffScheduledTaskHigh(t *testing.T) {
	incident := testEvent("task", 100, "persistence", "scheduled_task_created")
	incident.Object.Path = `C:\Users\Public\updater.exe`

	result := Compare(nil, []domain.TimelineEvent{incident}, nil, nil)
	finding := requireFinding(t, result, TypeNewPersistence)
	if finding.Severity != domain.SeverityCritical {
		t.Fatalf("severity = %q", finding.Severity)
	}
}

func TestDetectionDiff(t *testing.T) {
	incident := processEvent("incident", 100, "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe", "powershell.exe -EncodedCommand SQBFAFgA")
	detection := store.Detection{
		CaseID:     "case-incident",
		EventID:    incident.ID,
		RuleID:     "powershell.encoded_command",
		RuleName:   "Encoded PowerShell command",
		Severity:   domain.SeverityHigh,
		Confidence: domain.ConfidenceHigh,
		Rationale:  "candidate encoded command",
	}

	result := Compare(nil, []domain.TimelineEvent{incident}, nil, []store.Detection{detection})
	finding := requireFinding(t, result, TypeNewDetection)
	if finding.Severity != domain.SeverityHigh {
		t.Fatalf("severity = %q", finding.Severity)
	}
}

func requireFinding(t *testing.T, result Result, diffType string) Finding {
	t.Helper()
	for _, finding := range result.Findings {
		if finding.DiffType == diffType {
			return finding
		}
	}
	t.Fatalf("missing finding %s in %+v", diffType, result.Findings)
	return Finding{}
}

func processEvent(sourceRecordID string, timestamp int64, image string, cmdline string) domain.TimelineEvent {
	event := testEvent(sourceRecordID, timestamp, "process", "process_created")
	event.Actor.Image = image
	event.Actor.Cmdline = cmdline
	event.Object.Type = "process"
	event.Object.Path = image
	event.ID = domain.GenerateEventID(event)
	return event
}

func testEvent(sourceRecordID string, timestamp int64, category string, action string) domain.TimelineEvent {
	event := domain.TimelineEvent{
		SchemaVersion:      "1",
		ToolVersion:        "test",
		ParserName:         "test",
		ParserVersion:      "test",
		CaseID:             "case-1",
		SourceType:         "evtx",
		SourcePath:         "fixture.evtx",
		SourceRecordID:     sourceRecordID,
		RawRef:             domain.RawRef{Type: "record", URI: "fixture.evtx"},
		TimestampNS:        timestamp,
		TimestampPrecision: domain.TimestampPrecisionNanosecond,
		TimestampSource:    "test",
		Category:           category,
		Action:             action,
		Severity:           domain.SeverityMedium,
		Confidence:         domain.ConfidenceMedium,
		EvidenceStrength:   domain.EvidenceSingleSource,
		Actor:              domain.Actor{User: "ACME\\alice"},
		Object:             domain.Object{Type: category},
		Tags:               []string{"windows"},
	}
	event.ID = domain.GenerateEventID(event)
	return event
}
