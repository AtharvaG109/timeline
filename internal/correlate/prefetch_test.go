package correlate

import (
	"testing"

	"timeline/internal/domain"
)

func TestPrefetchProcessCorrelation(t *testing.T) {
	prefetch := relationTestEvent("prefetch-1", "prefetch", "executed", "POWERSHELL.EXE", 100)
	evtx := relationTestEvent("evtx-1", "evtx", "process_created", "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe", 100+int64(30*1_000_000_000))

	result := PrefetchProcess([]domain.TimelineEvent{prefetch, evtx})
	if len(result.Relations) != 1 {
		t.Fatalf("relations = %d", len(result.Relations))
	}
	if result.Events[0].EvidenceStrength != domain.EvidenceMultiSource {
		t.Fatalf("prefetch evidence strength = %q", result.Events[0].EvidenceStrength)
	}
	if result.Events[1].EvidenceStrength != domain.EvidenceMultiSource {
		t.Fatalf("evtx evidence strength = %q", result.Events[1].EvidenceStrength)
	}
}

func TestAmCacheExecutionCorrelation(t *testing.T) {
	amcache := relationTestEvent("amcache-1", "amcache", "executed", "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe", 90)
	amcache.Object.Hash = "0123456789abcdef0123456789abcdef01234567"
	prefetch := relationTestEvent("prefetch-1", "prefetch", "executed", "POWERSHELL.EXE", 100)
	evtx := relationTestEvent("evtx-1", "evtx", "process_created", "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe", 100)

	result := AmCacheExecution([]domain.TimelineEvent{amcache, prefetch, evtx})
	if len(result.Relations) != 2 {
		t.Fatalf("relations = %d", len(result.Relations))
	}
	if result.Events[0].EvidenceStrength != domain.EvidenceMultiSource {
		t.Fatalf("amcache evidence strength = %q", result.Events[0].EvidenceStrength)
	}
	if result.Events[1].EvidenceStrength != domain.EvidenceMultiSource {
		t.Fatalf("prefetch evidence strength = %q", result.Events[1].EvidenceStrength)
	}
	if result.Events[2].EvidenceStrength != domain.EvidenceMultiSource {
		t.Fatalf("evtx evidence strength = %q", result.Events[2].EvidenceStrength)
	}
}

func TestAmCacheHashCorrelation(t *testing.T) {
	amcache := relationTestEvent("amcache-1", "amcache", "observed", "C:/Temp/payload.exe", 90)
	amcache.Object.Hash = "feedfacefeedfacefeedfacefeedfacefeedface"
	evtx := relationTestEvent("evtx-1", "evtx", "process_created", "C:/Other/name.exe", 100)
	evtx.Object.Hash = "feedfacefeedfacefeedfacefeedfacefeedface"

	result := AmCacheExecution([]domain.TimelineEvent{amcache, evtx})
	if len(result.Relations) != 1 {
		t.Fatalf("relations = %d", len(result.Relations))
	}
	if result.Relations[0].Type != "amcache_evtx_execution_match" {
		t.Fatalf("relation type = %q", result.Relations[0].Type)
	}
}

func TestBrowserDownloadExecutionCorrelation(t *testing.T) {
	download := domain.TimelineEvent{
		ID:               "download-1",
		CaseID:           "case-1",
		SourceType:       "browser_chrome",
		TimestampNS:      100,
		Category:         "browser",
		Action:           "downloaded",
		EvidenceStrength: domain.EvidenceSingleSource,
		Object:           domain.Object{Type: "file", Path: `C:\Users\alice\Downloads\payload.exe`, Name: "payload.exe"},
		Network:          domain.Network{URL: "https://downloads.example.test/payload.exe"},
		Confidence:       domain.ConfidenceMedium,
		Severity:         domain.SeverityMedium,
	}
	execution := relationTestEvent("prefetch-1", "prefetch", "executed", `C:\Users\alice\Downloads\payload.exe`, 100+int64(10*60*1_000_000_000))

	result := BrowserDownloadExecution([]domain.TimelineEvent{download, execution})
	if len(result.Relations) != 1 {
		t.Fatalf("relations = %d", len(result.Relations))
	}
	if result.Relations[0].Type != "browser_download_execution_match" {
		t.Fatalf("relation type = %q", result.Relations[0].Type)
	}
	if result.Events[0].EvidenceStrength != domain.EvidenceMultiSource {
		t.Fatalf("download evidence strength = %q", result.Events[0].EvidenceStrength)
	}
	if result.Events[1].EvidenceStrength != domain.EvidenceMultiSource {
		t.Fatalf("execution evidence strength = %q", result.Events[1].EvidenceStrength)
	}
}

func relationTestEvent(id string, sourceType string, action string, image string, timestamp int64) domain.TimelineEvent {
	return domain.TimelineEvent{
		ID:                 id,
		CaseID:             "case-1",
		SourceType:         sourceType,
		TimestampNS:        timestamp,
		Category:           "process",
		Action:             action,
		EvidenceStrength:   domain.EvidenceSingleSource,
		Actor:              domain.Actor{Image: image},
		Object:             domain.Object{Path: image, Name: image},
		Confidence:         domain.ConfidenceMedium,
		Severity:           domain.SeverityMedium,
		TimestampPrecision: domain.TimestampPrecisionNanosecond,
	}
}
