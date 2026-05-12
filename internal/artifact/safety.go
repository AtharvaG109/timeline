package artifact

import (
	"fmt"
	"os"
	"path/filepath"
)

const MaxArtifactBytes int64 = 64 * 1024 * 1024

func CheckReadableFile(path string) error {
	cleanPath := filepath.Clean(path)
	info, err := os.Stat(cleanPath)
	if err != nil {
		return fmt.Errorf("inspect artifact file %s: %w", cleanPath, err)
	}
	if info.IsDir() {
		return fmt.Errorf("artifact path is a directory, expected file: %s", cleanPath)
	}
	if info.Size() > MaxArtifactBytes {
		return fmt.Errorf("artifact file %s exceeds size limit of %d bytes", cleanPath, MaxArtifactBytes)
	}
	return nil
}
