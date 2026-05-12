package prefetch

import (
	"os"
	"path/filepath"
	"testing"

	"timeline/internal/domain"
)

func TestValidPrefetchFixture(t *testing.T) {
	event, ok, err := ParseFile(filepath.Join("..", "..", "..", "testdata", "fixtures", "windows-evtx", "POWERSHELL.EXE-1234ABCD.pf"), "case-1")
	if err != nil {
		t.Fatalf("ParseFile error: %v", err)
	}
	if !ok {
		t.Fatal("valid Prefetch fixture skipped")
	}
	if event.Category != "process" || event.Action != "executed" {
		t.Fatalf("unexpected event mapping: %s/%s", event.Category, event.Action)
	}
	if event.TimestampSource != "prefetch_last_run" {
		t.Fatalf("timestamp source = %q", event.TimestampSource)
	}
	if event.Confidence != domain.ConfidenceMedium {
		t.Fatalf("confidence = %q", event.Confidence)
	}
	if event.EvidenceStrength != domain.EvidenceSingleSource {
		t.Fatalf("evidence strength = %q", event.EvidenceStrength)
	}
}

func TestMalformedPrefetchFileSkipped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "BAD.EXE-11111111.pf")
	if err := os.WriteFile(path, []byte("bad line without delimiter"), 0o600); err != nil {
		t.Fatalf("write malformed fixture: %v", err)
	}
	_, ok, err := ParseFile(path, "case-1")
	if err != nil {
		t.Fatalf("ParseFile returned parse error instead of skip: %v", err)
	}
	if ok {
		t.Fatal("malformed Prefetch file emitted an event")
	}
}

func TestMissingTimestampBehavior(t *testing.T) {
	event, ok, err := ParseFile(filepath.Join("..", "..", "..", "testdata", "fixtures", "windows-evtx", "NOTEPAD.EXE-5678ABCD.pf"), "case-1")
	if err != nil {
		t.Fatalf("ParseFile error: %v", err)
	}
	if !ok {
		t.Fatal("missing timestamp fixture skipped")
	}
	if event.TimestampNS != 0 {
		t.Fatalf("timestamp = %d", event.TimestampNS)
	}
	if event.TimestampPrecision != domain.TimestampPrecisionUnknown {
		t.Fatalf("timestamp precision = %q", event.TimestampPrecision)
	}
}

func FuzzParsePrefetchRecord(f *testing.F) {
	f.Add("ExecutableName: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\nRunCount: 3\nLastRun: 2024-05-06T20:04:00Z\n")
	f.Add("bad line without delimiter")
	f.Add("")
	f.Fuzz(func(t *testing.T, content string) {
		_, _, _ = parseRecord("FUZZ.EXE-00000000.pf", []byte(content))
	})
}
