package correlate

import (
	"net/url"
	"path/filepath"
	"strings"

	"timeline/internal/domain"
)

type Relation struct {
	CaseID     string
	SourceID   string
	TargetID   string
	Type       string
	Confidence domain.Confidence
	Rationale  string
}

type Result struct {
	Events    []domain.TimelineEvent
	Relations []Relation
}

func PrefetchProcess(events []domain.TimelineEvent) Result {
	updated := append([]domain.TimelineEvent(nil), events...)
	relations := make([]Relation, 0)
	for i, prefetchEvent := range updated {
		if prefetchEvent.SourceType != "prefetch" || prefetchEvent.Category != "process" || prefetchEvent.Action != "executed" {
			continue
		}
		for j, evtxEvent := range updated {
			if evtxEvent.SourceType != "evtx" || evtxEvent.Category != "process" || evtxEvent.Action != "process_created" {
				continue
			}
			if !sameExecutable(prefetchEvent, evtxEvent) || !timestampsClose(prefetchEvent.TimestampNS, evtxEvent.TimestampNS) {
				continue
			}
			updated[i].EvidenceStrength = domain.EvidenceMultiSource
			updated[j].EvidenceStrength = domain.EvidenceMultiSource
			relations = append(relations, Relation{
				CaseID:     prefetchEvent.CaseID,
				SourceID:   prefetchEvent.ID,
				TargetID:   evtxEvent.ID,
				Type:       "prefetch_evtx_process_match",
				Confidence: domain.ConfidenceMedium,
				Rationale:  "Prefetch execution and EVTX process creation have matching executable names and close timestamps.",
			})
			break
		}
	}
	return Result{Events: updated, Relations: relations}
}

func AmCacheExecution(events []domain.TimelineEvent) Result {
	updated := append([]domain.TimelineEvent(nil), events...)
	relations := make([]Relation, 0)
	for i, amcacheEvent := range updated {
		if amcacheEvent.SourceType != "amcache" {
			continue
		}
		for j, candidate := range updated {
			if candidate.ID == amcacheEvent.ID || candidate.SourceType == "amcache" {
				continue
			}
			if candidate.Category != "process" {
				continue
			}
			if !sameHashOrExecutable(amcacheEvent, candidate) {
				continue
			}
			updated[i].EvidenceStrength = domain.EvidenceMultiSource
			updated[j].EvidenceStrength = domain.EvidenceMultiSource
			relations = append(relations, Relation{
				CaseID:     amcacheEvent.CaseID,
				SourceID:   amcacheEvent.ID,
				TargetID:   candidate.ID,
				Type:       "amcache_" + candidate.SourceType + "_execution_match",
				Confidence: domain.ConfidenceMedium,
				Rationale:  "AmCache metadata and process evidence have matching executable path or hash.",
			})
		}
	}
	return Result{Events: updated, Relations: relations}
}

func BrowserDownloadExecution(events []domain.TimelineEvent) Result {
	updated := append([]domain.TimelineEvent(nil), events...)
	relations := make([]Relation, 0)
	for i, download := range updated {
		if download.Category != "browser" || download.Action != "downloaded" {
			continue
		}
		if !isDownloadedExecutableOrArchive(download) {
			continue
		}
		for j, candidate := range updated {
			if candidate.ID == download.ID {
				continue
			}
			if !isExecutionCandidate(candidate) {
				continue
			}
			if !downloadMatchesCandidate(download, candidate) || !timestampAfterWithin(download.TimestampNS, candidate.TimestampNS, 24*60*60*1_000_000_000) {
				continue
			}
			updated[i].EvidenceStrength = domain.EvidenceMultiSource
			updated[j].EvidenceStrength = domain.EvidenceMultiSource
			relations = append(relations, Relation{
				CaseID:     download.CaseID,
				SourceID:   download.ID,
				TargetID:   candidate.ID,
				Type:       "browser_download_execution_match",
				Confidence: domain.ConfidenceMedium,
				Rationale:  "Browser download evidence and later file or process evidence have a matching filename or path.",
			})
		}
	}
	return Result{Events: updated, Relations: relations}
}

func sameExecutable(a domain.TimelineEvent, b domain.TimelineEvent) bool {
	left := executableName(a.Object.Path)
	if left == "" {
		left = executableName(a.Actor.Image)
	}
	right := executableName(b.Object.Path)
	if right == "" {
		right = executableName(b.Actor.Image)
	}
	return left != "" && right != "" && strings.EqualFold(left, right)
}

func downloadMatchesCandidate(download domain.TimelineEvent, candidate domain.TimelineEvent) bool {
	downloadPath := normalizedPath(download.Object.Path)
	candidatePath := normalizedPath(candidate.Object.Path)
	if candidatePath == "" {
		candidatePath = normalizedPath(candidate.Actor.Image)
	}
	if downloadPath != "" && candidatePath != "" && downloadPath == candidatePath {
		return true
	}
	downloadName := downloadedName(download)
	if downloadName == "" {
		return false
	}
	candidateName := executableName(candidate.Object.Path)
	if candidateName == "" {
		candidateName = executableName(candidate.Actor.Image)
	}
	return candidateName != "" && strings.EqualFold(downloadName, candidateName)
}

func sameHashOrExecutable(a domain.TimelineEvent, b domain.TimelineEvent) bool {
	if a.Object.Hash != "" && b.Object.Hash != "" && strings.EqualFold(a.Object.Hash, b.Object.Hash) {
		return true
	}
	return sameExecutable(a, b)
}

func executableName(value string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	value = strings.ReplaceAll(value, "\\", "/")
	return strings.ToLower(filepath.Base(value))
}

func normalizedPath(value string) string {
	value = strings.TrimSpace(strings.ReplaceAll(value, "\\", "/"))
	if value == "" {
		return ""
	}
	return strings.ToLower(filepath.Clean(value))
}

func downloadedName(event domain.TimelineEvent) string {
	if name := executableName(event.Object.Path); name != "" && name != "." {
		return name
	}
	parsed, err := url.Parse(event.Network.URL)
	if err != nil {
		return ""
	}
	return executableName(parsed.Path)
}

func isDownloadedExecutableOrArchive(event domain.TimelineEvent) bool {
	name := downloadedName(event)
	switch strings.ToLower(filepath.Ext(name)) {
	case ".exe", ".msi", ".bat", ".cmd", ".ps1", ".dll", ".zip", ".rar", ".7z":
		return true
	default:
		return false
	}
}

func isExecutionCandidate(event domain.TimelineEvent) bool {
	if event.Category == "process" {
		switch event.Action {
		case "executed", "process_created":
			return true
		}
	}
	if event.Category == "filesystem" {
		switch event.Action {
		case "observed", "created", "file_created", "written":
			return true
		}
	}
	return false
}

func timestampsClose(a int64, b int64) bool {
	if a == 0 || b == 0 {
		return false
	}
	diff := a - b
	if diff < 0 {
		diff = -diff
	}
	return diff <= int64(5*60*1_000_000_000)
}

func timestampAfterWithin(first int64, second int64, window int64) bool {
	if first == 0 || second == 0 {
		return false
	}
	if second < first {
		return false
	}
	return second-first <= window
}
