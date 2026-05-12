package detect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"timeline/internal/domain"
)

func TestEveryOperator(t *testing.T) {
	event := detectionTestEvent()
	cases := []Condition{
		{Field: "category", Op: "equals", Value: "process"},
		{Field: "actor.image", Op: "equals_ci", Value: "C:/WINDOWS/SYSTEM32/WINDOWSPOWERSHELL/V1.0/POWERSHELL.EXE"},
		{Field: "actor.cmdline", Op: "contains", Value: "-EncodedCommand"},
		{Field: "actor.cmdline", Op: "contains_ci", Value: "encodedcommand"},
		{Field: "object.path", Op: "prefix", Value: "C:/Users/alice"},
		{Field: "object.path", Op: "suffix", Value: "payload.exe"},
		{Field: "actor.cmdline", Op: "regex", Value: "SQBFAFgA"},
		{Field: "actor.cmdline", Op: "regex_ci", Value: "encodedcommand"},
		{Field: "category", Op: "in", In: []string{"auth", "process"}},
		{Field: "network.dst_ip", Op: "exists"},
		{Field: "network.url", Op: "not_exists"},
	}
	for _, tc := range cases {
		t.Run(tc.Op, func(t *testing.T) {
			if !matchesCondition(event, tc) {
				t.Fatalf("condition did not match: %+v", tc)
			}
		})
	}
}

func TestRegexBehavior(t *testing.T) {
	event := detectionTestEvent()
	if !matchesCondition(event, Condition{Field: "actor.cmdline", Op: "regex_ci", Value: `-encodedcommand\s+\S+`}) {
		t.Fatal("case-insensitive regex did not match")
	}
	if matchesCondition(event, Condition{Field: "actor.cmdline", Op: "regex", Value: `-encodedcommand\s+\S+`}) {
		t.Fatal("case-sensitive regex unexpectedly matched")
	}
}

func TestInvalidYAMLAndMissingRequiredFields(t *testing.T) {
	dir := t.TempDir()
	badYAML := filepath.Join(dir, "bad.yml")
	if err := os.WriteFile(badYAML, []byte("rules:\n  - id: ["), 0o600); err != nil {
		t.Fatalf("write invalid yaml: %v", err)
	}
	if _, err := LoadDirectory(dir); err == nil || !strings.Contains(err.Error(), badYAML) {
		t.Fatalf("expected invalid YAML with file context, got %v", err)
	}

	dir = t.TempDir()
	missing := filepath.Join(dir, "missing.yml")
	if err := os.WriteFile(missing, []byte("rules:\n  - id: missing.name\n    severity: high\n    confidence: high\n    match:\n      all:\n        - field: category\n          op: equals\n          value: process\n"), 0o600); err != nil {
		t.Fatalf("write missing field yaml: %v", err)
	}
	if _, err := LoadDirectory(dir); err == nil || !strings.Contains(err.Error(), "missing required field name") || !strings.Contains(err.Error(), missing) {
		t.Fatalf("expected missing field with file context, got %v", err)
	}
}

func TestSeverityConfidenceUpgradeBehavior(t *testing.T) {
	event := detectionTestEvent()
	event.Severity = domain.SeverityLow
	event.Confidence = domain.ConfidenceLow
	rules := RuleSet{Rules: []Rule{{
		ID:               "test.high",
		Name:             "High test",
		Severity:         domain.SeverityHigh,
		Confidence:       domain.ConfidenceHigh,
		EvidenceStrength: domain.EvidenceStrong,
		Tags:             []string{"detected"},
		MITRETechniques:  []string{"T1059.001"},
		Match: MatchBlock{All: []Condition{
			{Field: "actor.cmdline", Op: "contains_ci", Value: "encodedcommand"},
		}},
	}}}

	result := Apply(rules, []domain.TimelineEvent{event})
	if len(result.Detections) != 1 {
		t.Fatalf("detections = %d", len(result.Detections))
	}
	got := result.Events[0]
	if got.Severity != domain.SeverityHigh {
		t.Fatalf("severity = %q", got.Severity)
	}
	if got.Confidence != domain.ConfidenceHigh {
		t.Fatalf("confidence = %q", got.Confidence)
	}
	if !containsString(got.Tags, "detected") || !containsString(got.MITRETechniques, "T1059.001") {
		t.Fatalf("tags/mitre not merged: %+v %+v", got.Tags, got.MITRETechniques)
	}
}

func TestGoldenDetectionOutput(t *testing.T) {
	rules := RuleSet{Rules: []Rule{
		{
			ID:               "powershell.encoded_command",
			Name:             "Encoded PowerShell command",
			Severity:         domain.SeverityHigh,
			Confidence:       domain.ConfidenceHigh,
			EvidenceStrength: domain.EvidenceStrong,
			Match: MatchBlock{All: []Condition{
				{Field: "actor.cmdline", Op: "contains_ci", Value: "encodedcommand"},
			}},
		},
		{
			ID:               "execution.process",
			Name:             "Process event",
			Severity:         domain.SeverityMedium,
			Confidence:       domain.ConfidenceMedium,
			EvidenceStrength: domain.EvidenceModerate,
			Match: MatchBlock{All: []Condition{
				{Field: "category", Op: "equals", Value: "process"},
			}},
		},
	}}
	result := Apply(rules, []domain.TimelineEvent{detectionTestEvent()})
	lines := make([]string, 0, len(result.Detections))
	for _, detection := range result.Detections {
		lines = append(lines, detection.RuleID+"|"+string(detection.Severity)+"|"+string(detection.Confidence))
	}
	got := strings.Join(lines, "\n")
	want := "powershell.encoded_command|high|high\nexecution.process|medium|medium"
	if got != want {
		t.Fatalf("golden detection output mismatch\nwant:\n%s\ngot:\n%s", want, got)
	}
}

func detectionTestEvent() domain.TimelineEvent {
	event := domain.TimelineEvent{
		SchemaVersion:      "1",
		ToolVersion:        "test",
		ParserName:         "test",
		ParserVersion:      "test",
		CaseID:             "case-1",
		SourceType:         "evtx",
		SourcePath:         "Security.evtx",
		SourceRecordID:     "1",
		RawRef:             domain.RawRef{Type: "evtx_record", URI: "Security.evtx"},
		TimestampNS:        100,
		TimestampPrecision: domain.TimestampPrecisionNanosecond,
		TimestampSource:    "test",
		Category:           "process",
		Action:             "process_created",
		Severity:           domain.SeverityMedium,
		Confidence:         domain.ConfidenceMedium,
		EvidenceStrength:   domain.EvidenceModerate,
		Actor: domain.Actor{
			User:    "alice",
			Image:   "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
			Cmdline: "powershell.exe -NoProfile -EncodedCommand SQBFAFgA",
		},
		Object:  domain.Object{Type: "file", Path: "C:/Users/alice/AppData/Local/Temp/payload.exe"},
		Network: domain.Network{DstIP: "198.51.100.42"},
		Tags:    []string{"windows"},
	}
	event.ID = domain.GenerateEventID(event)
	return event
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
