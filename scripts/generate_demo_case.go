package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const webkitUnixOffsetUS = int64(11644473600000000)

type browserFixture struct {
	Visits    []visitFixture    `json:"visits"`
	Downloads []downloadFixture `json:"downloads"`
}

type visitFixture struct {
	URL        string `json:"url"`
	Title      string `json:"title"`
	VisitTime  string `json:"visit_time"`
	VisitCount int    `json:"visit_count"`
}

type downloadFixture struct {
	URL        string `json:"url"`
	TargetPath string `json:"target_path"`
	StartTime  string `json:"start_time"`
	EndTime    string `json:"end_time"`
}

func main() {
	outDir := flag.String("out", filepath.Join("demo-output", "artifacts"), "output artifact directory")
	sourceDir := flag.String("source", filepath.Join("testdata", "demo-case"), "demo source fixture directory")
	flag.Parse()

	if err := generate(*sourceDir, *outDir); err != nil {
		fmt.Fprintf(os.Stderr, "generate demo case: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("demo artifacts generated: %s\n", filepath.Clean(*outDir))
}

func generate(sourceDir string, outDir string) error {
	cleanSource := filepath.Clean(sourceDir)
	cleanOut := filepath.Clean(outDir)
	if err := os.RemoveAll(cleanOut); err != nil {
		return fmt.Errorf("clean output directory: %w", err)
	}
	for _, caseName := range []string{"baseline", "incident"} {
		if err := materializeCase(filepath.Join(cleanSource, caseName), filepath.Join(cleanOut, caseName)); err != nil {
			return err
		}
	}
	return nil
}

func materializeCase(sourceRoot string, outRoot string) error {
	if err := os.MkdirAll(outRoot, 0o755); err != nil {
		return fmt.Errorf("create case output directory: %w", err)
	}
	if err := copyEventXML(filepath.Join(sourceRoot, "eventlogs"), outRoot); err != nil {
		return err
	}
	if err := copyScheduledTasks(filepath.Join(sourceRoot, "scheduled-tasks"), filepath.Join(outRoot, "Windows", "System32", "Tasks")); err != nil {
		return err
	}
	if err := copySafeFiles(filepath.Join(sourceRoot, "files"), outRoot); err != nil {
		return err
	}
	browserPath := filepath.Join(sourceRoot, "browser_history.json")
	if _, err := os.Stat(browserPath); err == nil {
		if err := createBrowserHistory(browserPath, filepath.Join(outRoot, "Chrome", "Default", "History")); err != nil {
			return err
		}
	}
	return nil
}

func copyEventXML(sourceRoot string, outRoot string) error {
	if _, err := os.Stat(sourceRoot); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("inspect event source directory: %w", err)
	}
	return filepath.WalkDir(sourceRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("walk event source directory: %w", walkErr)
		}
		if entry.IsDir() || !strings.EqualFold(filepath.Ext(entry.Name()), ".xml") {
			return nil
		}
		rel, err := filepath.Rel(sourceRoot, path)
		if err != nil {
			return fmt.Errorf("resolve event source path: %w", err)
		}
		targetRel := strings.TrimSuffix(rel, filepath.Ext(rel)) + ".evtx"
		return copyFile(path, filepath.Join(outRoot, targetRel))
	})
}

func copyScheduledTasks(sourceRoot string, outRoot string) error {
	if _, err := os.Stat(sourceRoot); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("inspect scheduled task source directory: %w", err)
	}
	return filepath.WalkDir(sourceRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("walk scheduled task source directory: %w", walkErr)
		}
		if entry.IsDir() || !strings.EqualFold(filepath.Ext(entry.Name()), ".xml") {
			return nil
		}
		return copyFile(path, filepath.Join(outRoot, entry.Name()))
	})
}

func copySafeFiles(sourceRoot string, outRoot string) error {
	if _, err := os.Stat(sourceRoot); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("inspect file source directory: %w", err)
	}
	return filepath.WalkDir(sourceRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("walk file source directory: %w", walkErr)
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(sourceRoot, path)
		if err != nil {
			return fmt.Errorf("resolve file source path: %w", err)
		}
		targetRel := rel
		if strings.HasSuffix(targetRel, ".safe.txt") {
			targetRel = strings.TrimSuffix(targetRel, ".safe.txt") + ".exe"
		}
		return copyFile(path, filepath.Join(outRoot, targetRel))
	})
}

func copyFile(source string, target string) error {
	content, err := os.ReadFile(source)
	if err != nil {
		return fmt.Errorf("read %s: %w", source, err)
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return fmt.Errorf("create target directory: %w", err)
	}
	if err := os.WriteFile(target, content, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", target, err)
	}
	return nil
}

func createBrowserHistory(source string, target string) error {
	content, err := os.ReadFile(source)
	if err != nil {
		return fmt.Errorf("read browser fixture: %w", err)
	}
	var fixture browserFixture
	if err := json.Unmarshal(content, &fixture); err != nil {
		return fmt.Errorf("parse browser fixture: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return fmt.Errorf("create browser history directory: %w", err)
	}
	db, err := sql.Open("sqlite", target)
	if err != nil {
		return fmt.Errorf("open browser history fixture: %w", err)
	}
	defer db.Close()
	statements := []string{
		`CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT NOT NULL, title TEXT, visit_count INTEGER, last_visit_time INTEGER)`,
		`CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER)`,
		`CREATE TABLE downloads (id INTEGER PRIMARY KEY, target_path TEXT, current_path TEXT, start_time INTEGER, end_time INTEGER)`,
		`CREATE TABLE downloads_url_chains (id INTEGER, chain_index INTEGER, url TEXT)`,
	}
	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			return fmt.Errorf("create browser history schema: %w", err)
		}
	}
	for i, visit := range fixture.Visits {
		id := i + 1
		visitTime, err := webkitTime(visit.VisitTime)
		if err != nil {
			return err
		}
		if _, err := db.Exec(`INSERT INTO urls (id, url, title, visit_count, last_visit_time) VALUES (?, ?, ?, ?, ?)`, id, visit.URL, visit.Title, visit.VisitCount, visitTime); err != nil {
			return fmt.Errorf("insert browser url: %w", err)
		}
		if _, err := db.Exec(`INSERT INTO visits (id, url, visit_time) VALUES (?, ?, ?)`, id, id, visitTime); err != nil {
			return fmt.Errorf("insert browser visit: %w", err)
		}
	}
	for i, download := range fixture.Downloads {
		id := i + 100
		startTime, err := webkitTime(download.StartTime)
		if err != nil {
			return err
		}
		endTime, err := webkitTime(download.EndTime)
		if err != nil {
			return err
		}
		if _, err := db.Exec(`INSERT INTO downloads (id, target_path, current_path, start_time, end_time) VALUES (?, ?, ?, ?, ?)`, id, download.TargetPath, download.TargetPath, startTime, endTime); err != nil {
			return fmt.Errorf("insert browser download: %w", err)
		}
		if _, err := db.Exec(`INSERT INTO downloads_url_chains (id, chain_index, url) VALUES (?, 0, ?)`, id, download.URL); err != nil {
			return fmt.Errorf("insert browser download URL: %w", err)
		}
	}
	return nil
}

func webkitTime(value string) (int64, error) {
	timestamp, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return 0, fmt.Errorf("parse fixture timestamp %q: %w", value, err)
	}
	return timestamp.UTC().UnixMicro() + webkitUnixOffsetUS, nil
}
