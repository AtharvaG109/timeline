package filesystem

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"timeline/internal/domain"
	"timeline/internal/version"
)

const (
	parserName    = "targeted-filesystem"
	parserVersion = "0.11.0"
)

var DefaultTargetPaths = []string{
	`C:\Users\`,
	`C:\Users\*\Downloads\`,
	`C:\Users\*\Desktop\`,
	`C:\Users\*\AppData\Local\Temp\`,
	`C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\`,
	`C:\ProgramData\`,
	`C:\Windows\Temp\`,
	`C:\Windows\System32\Tasks\`,
}

type Stats struct {
	RootsConfigured int
	RootsWalked     int
	FilesObserved   int
	EventsEmitted   int
}

type Result struct {
	Events []domain.TimelineEvent
	Files  []string
	Stats  Stats
}

func CollectDirectory(ctx context.Context, root string, caseID string, configuredPaths []string) (Result, error) {
	cleanRoot := filepath.Clean(root)
	info, err := os.Stat(cleanRoot)
	if err != nil {
		return Result{}, fmt.Errorf("inspect artifact directory: %w", err)
	}
	if !info.IsDir() {
		return Result{}, fmt.Errorf("artifact path is not a directory: %s", cleanRoot)
	}
	targets := configuredPaths
	if len(targets) == 0 {
		targets = DefaultTargetPaths
	}
	result := Result{Stats: Stats{RootsConfigured: len(targets)}}
	seenRoots := map[string]struct{}{}
	for _, target := range targets {
		roots, err := resolveTargetRoots(cleanRoot, target)
		if err != nil {
			return Result{}, err
		}
		for _, resolved := range roots {
			if _, ok := seenRoots[resolved]; ok {
				continue
			}
			seenRoots[resolved] = struct{}{}
			if err := walkRoot(ctx, cleanRoot, target, resolved, caseID, &result); err != nil {
				return Result{}, err
			}
		}
	}
	return result, nil
}

func resolveTargetRoots(root string, target string) ([]string, error) {
	candidates, err := relativeCandidates(target)
	if err != nil {
		return nil, err
	}
	resolved := make([]string, 0)
	for _, candidate := range candidates {
		pattern := filepath.Join(root, filepath.FromSlash(candidate))
		if strings.Contains(candidate, "*") {
			matches, err := filepath.Glob(pattern)
			if err != nil {
				return nil, fmt.Errorf("resolve filesystem target %q: %w", target, err)
			}
			for _, match := range matches {
				if safeWithin(root, match) {
					resolved = appendIfExists(resolved, match)
				}
			}
			continue
		}
		if safeWithin(root, pattern) {
			resolved = appendIfExists(resolved, pattern)
		}
	}
	return resolved, nil
}

func relativeCandidates(target string) ([]string, error) {
	trimmed := strings.TrimSpace(target)
	if trimmed == "" {
		return nil, fmt.Errorf("filesystem target path is empty")
	}
	normalized := strings.ReplaceAll(trimmed, "\\", "/")
	decodedTraversal := strings.Contains(strings.ToLower(normalized), "%2e%2e") || strings.Contains(strings.ToLower(normalized), "%2e.") || strings.Contains(strings.ToLower(normalized), ".%2e")
	if decodedTraversal {
		return nil, fmt.Errorf("filesystem target %q contains path traversal", target)
	}
	drive := ""
	if len(normalized) >= 2 && normalized[1] == ':' {
		drive = strings.ToUpper(normalized[:1])
		normalized = normalized[2:]
	}
	normalized = strings.TrimLeft(normalized, "/")
	for _, part := range strings.Split(normalized, "/") {
		if part == ".." {
			return nil, fmt.Errorf("filesystem target %q contains path traversal", target)
		}
	}
	cleaned := filepath.ToSlash(filepath.Clean(filepath.FromSlash(normalized)))
	if cleaned == "." {
		cleaned = ""
	}
	if cleaned == "" && drive == "" {
		return nil, fmt.Errorf("filesystem target %q must not resolve to the artifact root", target)
	}
	if cleaned == "" {
		return []string{drive}, nil
	}
	if drive == "" {
		return []string{cleaned}, nil
	}
	return []string{cleaned, drive + "/" + cleaned}, nil
}

func appendIfExists(paths []string, path string) []string {
	if _, err := os.Stat(path); err == nil {
		return append(paths, filepath.Clean(path))
	}
	return paths
}

func safeWithin(root string, path string) bool {
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(path))
	if err != nil {
		return false
	}
	return rel == "." || (!strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != "..")
}

func walkRoot(ctx context.Context, artifactRoot string, target string, root string, caseID string, result *Result) error {
	info, err := os.Stat(root)
	if err != nil {
		return nil
	}
	result.Stats.RootsWalked++
	if !info.IsDir() {
		event := normalizeFileEvent(artifactRoot, target, root, info, caseID)
		result.Events = append(result.Events, event)
		result.Files = append(result.Files, root)
		result.Stats.FilesObserved++
		result.Stats.EventsEmitted++
		return nil
	}
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("walk filesystem target: %w", walkErr)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("inspect filesystem entry: %w", err)
		}
		event := normalizeFileEvent(artifactRoot, target, path, info, caseID)
		result.Events = append(result.Events, event)
		result.Files = append(result.Files, path)
		result.Stats.FilesObserved++
		result.Stats.EventsEmitted++
		return nil
	})
}

func normalizeFileEvent(artifactRoot string, target string, path string, info os.FileInfo, caseID string) domain.TimelineEvent {
	windowsPath := windowsPathForArtifact(artifactRoot, path)
	modified := info.ModTime().UTC()
	event := domain.TimelineEvent{
		SchemaVersion:      "1",
		ToolVersion:        version.Version,
		ParserName:         parserName,
		ParserVersion:      parserVersion,
		CaseID:             caseID,
		SourceType:         "filesystem",
		SourcePath:         filepath.Clean(path),
		SourceRecordID:     "modified:" + windowsPath,
		RawRef:             domain.RawRef{Type: "filesystem_metadata", URI: filepath.Clean(path)},
		TimestampNS:        modified.UnixNano(),
		TimestampPrecision: domain.TimestampPrecisionNanosecond,
		TimestampSource:    "filesystem_mtime",
		Category:           "filesystem",
		Action:             "modified",
		Severity:           domain.SeverityLow,
		Confidence:         domain.ConfidenceMedium,
		EvidenceStrength:   domain.EvidenceSingleSource,
		Object: domain.Object{
			Type: "file",
			Path: windowsPath,
			Name: filepath.Base(path),
		},
		Tags: []string{
			"windows",
			"filesystem",
			"macb",
			"macb:modified",
			"target:" + strings.TrimSpace(target),
			fmt.Sprintf("size:%d", info.Size()),
		},
	}
	event.ID = domain.GenerateEventID(event)
	return event
}

func windowsPathForArtifact(root string, path string) string {
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(path))
	if err != nil {
		rel = filepath.Base(path)
	}
	rel = filepath.ToSlash(rel)
	parts := strings.Split(rel, "/")
	if len(parts) > 1 && len(parts[0]) == 1 && strings.EqualFold(parts[0], "C") {
		rel = strings.Join(parts[1:], "/")
	}
	return `C:\` + strings.ReplaceAll(rel, "/", `\`)
}
