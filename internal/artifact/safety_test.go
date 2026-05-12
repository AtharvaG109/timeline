package artifact

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckReadableFileRejectsOversizedArtifact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "large.evtx")
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create fixture: %v", err)
	}
	if err := file.Truncate(MaxArtifactBytes + 1); err != nil {
		file.Close()
		t.Fatalf("grow fixture: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close fixture: %v", err)
	}

	err = CheckReadableFile(path)
	if err == nil {
		t.Fatal("expected oversized file to be rejected")
	}
	if !strings.Contains(err.Error(), "exceeds size limit") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckReadableFileRejectsDirectory(t *testing.T) {
	err := CheckReadableFile(t.TempDir())
	if err == nil {
		t.Fatal("expected directory to be rejected")
	}
	if !strings.Contains(err.Error(), "expected file") {
		t.Fatalf("unexpected error: %v", err)
	}
}
