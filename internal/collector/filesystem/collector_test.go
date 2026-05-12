package filesystem

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTargetedFilesystemWalkerEmitsConfiguredPathsOnly(t *testing.T) {
	root := t.TempDir()
	download := filepath.Join(root, "Users", "alice", "Downloads", "payload.exe")
	desktop := filepath.Join(root, "Users", "alice", "Desktop", "note.txt")
	outside := filepath.Join(root, "Other", "ignored.exe")
	writeFixtureFile(t, download)
	writeFixtureFile(t, desktop)
	writeFixtureFile(t, outside)

	result, err := CollectDirectory(context.Background(), root, "case-1", []string{`C:\Users\*\Downloads\`})
	if err != nil {
		t.Fatalf("CollectDirectory: %v", err)
	}
	if result.Stats.RootsWalked != 1 {
		t.Fatalf("roots walked = %d", result.Stats.RootsWalked)
	}
	if len(result.Events) != 1 {
		t.Fatalf("events = %d: %+v", len(result.Events), result.Events)
	}
	event := result.Events[0]
	if event.Object.Path != `C:\Users\alice\Downloads\payload.exe` {
		t.Fatalf("object path = %q", event.Object.Path)
	}
	if strings.Contains(event.Object.Path, "Desktop") || strings.Contains(event.Object.Path, "Other") {
		t.Fatalf("walker emitted unconfigured path: %q", event.Object.Path)
	}
}

func TestFilesystemPathTraversalRejected(t *testing.T) {
	_, err := CollectDirectory(context.Background(), t.TempDir(), "case-1", []string{`..\outside`})
	if err == nil {
		t.Fatal("expected traversal path rejection")
	}
	if !strings.Contains(err.Error(), "path traversal") {
		t.Fatalf("unexpected error: %v", err)
	}
	_, err = CollectDirectory(context.Background(), t.TempDir(), "case-1", []string{`C:\Users\..\Windows`})
	if err == nil {
		t.Fatal("expected traversal path rejection for Windows path")
	}
	_, err = CollectDirectory(context.Background(), t.TempDir(), "case-1", []string{`%2e%2e\outside`})
	if err == nil {
		t.Fatal("expected URL-encoded traversal path rejection")
	}
}

func TestFilesystemMACBTimestampNormalization(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "Users", "alice", "Downloads", "payload.exe")
	writeFixtureFile(t, target)
	modified := time.Date(2024, 5, 6, 20, 8, 9, 123456789, time.UTC)
	if err := os.Chtimes(target, modified, modified); err != nil {
		t.Fatalf("set fixture times: %v", err)
	}

	result, err := CollectDirectory(context.Background(), root, "case-1", []string{`C:\Users\alice\Downloads\`})
	if err != nil {
		t.Fatalf("CollectDirectory: %v", err)
	}
	if len(result.Events) != 1 {
		t.Fatalf("events = %d", len(result.Events))
	}
	event := result.Events[0]
	if event.TimestampNS != modified.UnixNano() {
		t.Fatalf("timestamp_ns = %d, want %d", event.TimestampNS, modified.UnixNano())
	}
	if event.TimestampSource != "filesystem_mtime" || event.Action != "modified" {
		t.Fatalf("unexpected MACB event: %+v", event)
	}
	if !hasTag(event.Tags, "macb:modified") {
		t.Fatalf("missing MACB tag: %+v", event.Tags)
	}
}

func TestNoFullDiskCrawlByDefault(t *testing.T) {
	root := t.TempDir()
	writeFixtureFile(t, filepath.Join(root, "root-payload.exe"))
	result, err := CollectDirectory(context.Background(), root, "case-1", nil)
	if err != nil {
		t.Fatalf("CollectDirectory: %v", err)
	}
	if len(result.Events) != 0 {
		t.Fatalf("default walker emitted root file events: %+v", result.Events)
	}
	if result.Stats.RootsConfigured != len(DefaultTargetPaths) {
		t.Fatalf("configured defaults = %d", result.Stats.RootsConfigured)
	}
}

func writeFixtureFile(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create fixture dir: %v", err)
	}
	if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write fixture file: %v", err)
	}
}

func hasTag(tags []string, want string) bool {
	for _, tag := range tags {
		if tag == want {
			return true
		}
	}
	return false
}
