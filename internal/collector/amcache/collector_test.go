package amcache

import (
	"os"
	"path/filepath"
	"testing"

	"timeline/internal/domain"
)

func TestValidAmCacheFixture(t *testing.T) {
	events, ok, err := ParseFile(filepath.Join("..", "..", "..", "testdata", "fixtures", "windows-evtx", "AmCache.hve"), "case-1")
	if err != nil {
		t.Fatalf("ParseFile error: %v", err)
	}
	if !ok {
		t.Fatal("valid AmCache fixture skipped")
	}
	if len(events) != 2 {
		t.Fatalf("events = %d", len(events))
	}
	if events[0].Category != "process" || events[0].Action != "executed" {
		t.Fatalf("unexpected first event: %s/%s", events[0].Category, events[0].Action)
	}
	if events[0].TimestampSource != "amcache" {
		t.Fatalf("timestamp source = %q", events[0].TimestampSource)
	}
	if events[0].Confidence != domain.ConfidenceMedium {
		t.Fatalf("confidence = %q", events[0].Confidence)
	}
}

func TestMalformedAmCacheSkipped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "AmCache.hve")
	if err := os.WriteFile(path, []byte("not parseable"), 0o600); err != nil {
		t.Fatalf("write malformed fixture: %v", err)
	}
	_, ok, err := ParseFile(path, "case-1")
	if err != nil {
		t.Fatalf("ParseFile returned parse error instead of skip: %v", err)
	}
	if ok {
		t.Fatal("malformed AmCache file emitted events")
	}
}

func TestHashExtractionAndTimestampNormalization(t *testing.T) {
	events, ok, err := ParseFile(filepath.Join("..", "..", "..", "testdata", "fixtures", "windows-evtx", "AmCache.hve"), "case-1")
	if err != nil {
		t.Fatalf("ParseFile error: %v", err)
	}
	if !ok {
		t.Fatal("valid AmCache fixture skipped")
	}
	if events[0].Object.Hash != "0123456789abcdef0123456789abcdef01234567" {
		t.Fatalf("hash = %q", events[0].Object.Hash)
	}
	if events[0].TimestampNS != 1715025850000000000 {
		t.Fatalf("timestamp = %d", events[0].TimestampNS)
	}
	if events[0].TimestampPrecision != domain.TimestampPrecisionNanosecond {
		t.Fatalf("timestamp precision = %q", events[0].TimestampPrecision)
	}
}

func FuzzParseAmCacheRecords(f *testing.F) {
	f.Add("Path: C:\\Users\\Public\\demo-payload.exe\nSHA1: 0123456789abcdef0123456789abcdef01234567\nTimestamp: 2024-05-06T20:04:10Z\nExecuted: true\n")
	f.Add("not parseable")
	f.Add("")
	f.Fuzz(func(t *testing.T, content string) {
		_, _, _ = parseRecords([]byte(content))
	})
}
