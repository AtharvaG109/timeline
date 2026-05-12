package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

type moduleEntry struct {
	Path     string `json:"path"`
	Version  string `json:"version"`
	Indirect bool   `json:"indirect,omitempty"`
	Sum      string `json:"sum,omitempty"`
	GoModSum string `json:"go_mod_sum,omitempty"`
}

type sbom struct {
	Format  string        `json:"format"`
	Modules []moduleEntry `json:"modules"`
}

func main() {
	modules, err := readModules("go.mod")
	if err != nil {
		fmt.Fprintf(os.Stderr, "generate sbom: %v\n", err)
		os.Exit(1)
	}
	sums, modSums, err := readSums("go.sum")
	if err != nil {
		fmt.Fprintf(os.Stderr, "generate sbom: %v\n", err)
		os.Exit(1)
	}
	for i := range modules {
		key := modules[i].Path + " " + modules[i].Version
		modules[i].Sum = sums[key]
		modules[i].GoModSum = modSums[key]
	}
	sort.Slice(modules, func(i, j int) bool {
		if modules[i].Path != modules[j].Path {
			return modules[i].Path < modules[j].Path
		}
		return modules[i].Version < modules[j].Version
	})
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(sbom{Format: "timeline-go-modules-v1", Modules: modules}); err != nil {
		fmt.Fprintf(os.Stderr, "generate sbom: %v\n", err)
		os.Exit(1)
	}
}

func readModules(path string) ([]moduleEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	modules := make([]moduleEntry, 0)
	inRequireBlock := false
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		if line == "require (" {
			inRequireBlock = true
			continue
		}
		if inRequireBlock && line == ")" {
			inRequireBlock = false
			continue
		}
		if strings.HasPrefix(line, "require ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "require "))
		} else if !inRequireBlock {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		modules = append(modules, moduleEntry{
			Path:     parts[0],
			Version:  parts[1],
			Indirect: strings.Contains(line, "// indirect"),
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return modules, nil
}

func readSums(path string) (map[string]string, map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()

	sums := map[string]string{}
	modSums := map[string]string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) != 3 {
			continue
		}
		modulePath := parts[0]
		version := parts[1]
		sum := parts[2]
		if strings.HasSuffix(version, "/go.mod") {
			version = strings.TrimSuffix(version, "/go.mod")
			modSums[modulePath+" "+version] = sum
			continue
		}
		sums[modulePath+" "+version] = sum
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}
	return sums, modSums, nil
}
