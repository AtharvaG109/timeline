package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"timeline/internal/domain"
	"timeline/internal/store"
)

func TestFullAttackChainGolden(t *testing.T) {
	got, err := Markdown(fullAttackChainInput())
	if err != nil {
		t.Fatalf("Markdown error: %v", err)
	}
	goldenPath := filepath.Join("testdata", "golden", "full_attack_chain.md")
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if got != string(want) {
		t.Fatalf("golden mismatch\n--- got ---\n%s\n--- want ---\n%s", got, string(want))
	}
}

func TestEmptyDatabaseReport(t *testing.T) {
	got, err := Markdown(Input{CaseID: "empty-case"})
	if err != nil {
		t.Fatalf("Markdown error: %v", err)
	}
	for _, section := range requiredSections() {
		if !strings.Contains(got, section) {
			t.Fatalf("missing section %q", section)
		}
	}
	if !strings.Contains(got, "The database contains no normalized events") {
		t.Fatalf("missing empty database summary:\n%s", got)
	}
}

func TestReportWithNoCriticalFindings(t *testing.T) {
	input := Input{
		CaseID: "case-low",
		Events: []domain.TimelineEvent{
			reportEvent("evt-low", "case-low", 1715025600000000000, "process", "process_created", domain.SeverityLow, domain.ConfidenceMedium, "C:/Windows/System32/notepad.exe"),
		},
	}
	got, err := Markdown(input)
	if err != nil {
		t.Fatalf("Markdown error: %v", err)
	}
	if !strings.Contains(got, "No critical or high findings are present") {
		t.Fatalf("missing no-critical wording:\n%s", got)
	}
	if strings.Contains(got, "proves compromise") || strings.Contains(got, "definitely malicious") || strings.Contains(got, "impossible legitimately") || strings.Contains(got, "guaranteed") {
		t.Fatalf("report contains banned wording:\n%s", got)
	}
}

func TestStableOrderingAndEvidencePresence(t *testing.T) {
	input := fullAttackChainInput()
	input.Events[0], input.Events[3] = input.Events[3], input.Events[0]
	first, err := Markdown(input)
	if err != nil {
		t.Fatalf("Markdown error: %v", err)
	}
	second, err := Markdown(input)
	if err != nil {
		t.Fatalf("Markdown second error: %v", err)
	}
	if first != second {
		t.Fatal("report output is not stable")
	}
	for _, value := range []string{"evt-auth", "evt-powershell", "evt-task", "evt-net", "Security.evtx", "Sysmon.evtx"} {
		if !strings.Contains(first, value) {
			t.Fatalf("report missing evidence value %q:\n%s", value, first)
		}
	}
}

func requiredSections() []string {
	return []string{
		"## Executive Summary",
		"## High-Confidence Attack Chain",
		"## New Critical and High Findings",
		"## Baseline vs Incident Summary",
		"## Timeline of Suspicious Activity",
		"## Authentication Findings",
		"## Execution Findings",
		"## Persistence Findings",
		"## Network Findings",
		"## Browser and Download Findings",
		"## ATT&CK Mapping",
		"## Evidence Table",
		"## Artifact Coverage",
		"## Limitations",
		"## Appendix",
	}
}

func fullAttackChainInput() Input {
	events := []domain.TimelineEvent{
		reportEvent("evt-auth", "case-incident", 1715025704000000000, "auth", "successful_logon", domain.SeverityHigh, domain.ConfidenceHigh, ""),
		reportEvent("evt-powershell", "case-incident", 1715025852000000000, "process", "process_created", domain.SeverityHigh, domain.ConfidenceHigh, "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"),
		reportEvent("evt-task", "case-incident", 1715025990000000000, "persistence", "scheduled_task_created", domain.SeverityCritical, domain.ConfidenceHigh, "C:/Users/alice/AppData/Roaming/updatecheck.exe"),
		reportEvent("evt-net", "case-incident", 1715026195000000000, "network", "connected", domain.SeverityMedium, domain.ConfidenceHigh, "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"),
	}
	events[0].Actor.User = "ACME\\alice"
	events[0].Network.SrcIP = "203.0.113.24"
	events[1].Actor.User = "ACME\\alice"
	events[1].Actor.Cmdline = "powershell.exe -EncodedCommand SQBFAFgA"
	events[1].MITRETechniques = []string{"T1059.001"}
	events[2].Actor.User = "ACME\\alice"
	events[2].MITRETechniques = []string{"T1053.005"}
	events[3].Network.DstIP = "198.51.100.42"
	events[3].Network.DstPort = 443
	events[3].MITRETechniques = []string{"T1105"}

	return Input{
		CaseID:         "case-incident",
		BaselineCaseID: "case-baseline",
		Events:         events,
		DiffResults: []store.DiffResult{
			reportDiff("case-baseline", "case-incident", "new_remote_logon", "evt-auth", domain.SeverityHigh, "Incident contains a new remote logon pattern absent from the baseline."),
			reportDiff("case-baseline", "case-incident", "new_cmdline", "evt-powershell", domain.SeverityHigh, "Incident contains a new encoded PowerShell command line candidate."),
			reportDiff("case-baseline", "case-incident", "new_persistence", "evt-task", domain.SeverityCritical, "Incident contains new persistence associated with a suspicious execution path."),
			reportDiff("case-baseline", "case-incident", "new_network_destination", "evt-net", domain.SeverityMedium, "Incident contains a new outbound destination."),
		},
		Detections: []store.Detection{
			{CaseID: "case-incident", EventID: "evt-powershell", RuleID: "powershell.encoded_command", RuleName: "Encoded PowerShell command", Severity: domain.SeverityHigh, Confidence: domain.ConfidenceHigh, Rationale: "candidate encoded command"},
			{CaseID: "case-incident", EventID: "evt-task", RuleID: "persistence.scheduled_task_created", RuleName: "Scheduled task created", Severity: domain.SeverityHigh, Confidence: domain.ConfidenceHigh, Rationale: "candidate scheduled task persistence"},
		},
		Relations: []store.EventRelation{
			{CaseID: "case-incident", SourceID: "evt-auth", TargetID: "evt-powershell", Type: "remote_logon_process", Confidence: domain.ConfidenceMedium, Rationale: "remote logon and process execution are close in time"},
			{CaseID: "case-incident", SourceID: "evt-powershell", TargetID: "evt-net", Type: "process_network", Confidence: domain.ConfidenceMedium, Rationale: "process execution and network connection are close in time"},
		},
		Artifacts: []store.Artifact{
			{ID: "artifact-security", CaseID: "case-incident", SourceType: "evtx", SourcePath: "Security.evtx", RawRefJSON: "{}", SizeBytes: 1000},
			{ID: "artifact-sysmon", CaseID: "case-incident", SourceType: "evtx", SourcePath: "Sysmon.evtx", RawRefJSON: "{}", SizeBytes: 1000},
		},
	}
}

func reportEvent(id string, caseID string, timestamp int64, category string, action string, severity domain.Severity, confidence domain.Confidence, image string) domain.TimelineEvent {
	return domain.TimelineEvent{
		SchemaVersion:      "1",
		ToolVersion:        "test",
		ParserName:         "test",
		ParserVersion:      "test",
		ID:                 id,
		CaseID:             caseID,
		SourceType:         "evtx",
		SourcePath:         sourcePathForCategory(category),
		SourceRecordID:     id,
		RawRef:             domain.RawRef{Type: "record", URI: sourcePathForCategory(category)},
		TimestampNS:        timestamp,
		TimestampPrecision: domain.TimestampPrecisionNanosecond,
		TimestampSource:    "test",
		Category:           category,
		Action:             action,
		Severity:           severity,
		Confidence:         confidence,
		EvidenceStrength:   domain.EvidenceSingleSource,
		Actor:              domain.Actor{Image: image},
		Object:             domain.Object{Type: category, Path: image},
		Network:            domain.Network{},
		Tags:               []string{"windows"},
	}
}

func reportDiff(baselineCaseID string, incidentCaseID string, diffType string, eventID string, severity domain.Severity, rationale string) store.DiffResult {
	return store.DiffResult{
		BaselineCaseID:  baselineCaseID,
		IncidentCaseID:  incidentCaseID,
		DiffType:        diffType,
		Fingerprint:     diffType + "-" + eventID,
		IncidentEventID: eventID,
		Severity:        severity,
		Confidence:      domain.ConfidenceHigh,
		Rationale:       rationale,
	}
}

func sourcePathForCategory(category string) string {
	if category == "network" {
		return "Sysmon.evtx"
	}
	return "Security.evtx"
}
