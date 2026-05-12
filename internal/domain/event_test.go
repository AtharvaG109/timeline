package domain

import (
	"encoding/hex"
	"testing"
)

func TestEnumValidation(t *testing.T) {
	event := TimelineEvent{
		TimestampPrecision: TimestampPrecisionNanosecond,
		Severity:           SeverityHigh,
		Confidence:         ConfidenceHigh,
		EvidenceStrength:   EvidenceStrong,
	}
	if err := event.ValidateEnums(); err != nil {
		t.Fatalf("valid enums rejected: %v", err)
	}

	event.Severity = Severity("urgent")
	if err := event.ValidateEnums(); err == nil {
		t.Fatal("invalid severity accepted")
	}
}

func TestGenerateEventIDDeterministic(t *testing.T) {
	event := TimelineEvent{
		SchemaVersion:  "1",
		SourceType:     "evtx",
		SourcePath:     "C:/Windows/System32/winevt/Logs/Security.evtx",
		SourceRecordID: "4688",
		TimestampNS:    1715025600000000000,
		Category:       "process",
		Action:         "start",
		Actor: Actor{
			Image:   "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
			Cmdline: "powershell.exe -NoProfile",
		},
		Object: Object{
			Path: "C:/Users/alice/AppData/Local/Temp/a.ps1",
		},
		Network: Network{
			DstIP:   "203.0.113.10",
			DstPort: 443,
		},
	}

	id := GenerateEventID(event)
	if len(id) != 64 {
		t.Fatalf("id length = %d, want 64", len(id))
	}
	if _, err := hex.DecodeString(id); err != nil {
		t.Fatalf("id is not hex: %v", err)
	}
	if got := GenerateEventID(event); got != id {
		t.Fatalf("id is not deterministic: %s != %s", got, id)
	}

	event.CaseID = "different-case"
	if got := GenerateEventID(event); got != id {
		t.Fatalf("case id should not affect event id: %s != %s", got, id)
	}

	event.Network.DstPort = 8443
	if got := GenerateEventID(event); got == id {
		t.Fatal("changing a fingerprint field did not change event id")
	}
}
