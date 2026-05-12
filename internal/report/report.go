package report

import (
	"bytes"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"text/template"
	"time"

	"timeline/internal/domain"
	"timeline/internal/store"
)

type Input struct {
	CaseID         string
	BaselineCaseID string
	Events         []domain.TimelineEvent
	Detections     []store.Detection
	Relations      []store.EventRelation
	DiffResults    []store.DiffResult
	Artifacts      []store.Artifact
}

type Document struct {
	CaseID             string
	BaselineCaseID     string
	ExecutiveSummary   string
	AttackChain        []ChainStep
	HighFindings       []FindingRow
	BaselineSummary    []SummaryRow
	Timeline           []EventRow
	Authentication     []EventRow
	Execution          []EventRow
	Persistence        []EventRow
	Network            []EventRow
	Browser            []EventRow
	MITRE              []MITRERow
	Evidence           []EventRow
	Artifacts          []ArtifactRow
	Detections         []DetectionRow
	Relations          []RelationRow
	TotalEvents        int
	TotalDiffs         int
	TotalDetections    int
	TotalRelations     int
	CriticalFindings   int
	HighFindingsCount  int
	HasAttackChain     bool
	HasHighFindings    bool
	HasTimeline        bool
	HasAuthentication  bool
	HasExecution       bool
	HasPersistence     bool
	HasNetwork         bool
	HasBrowser         bool
	HasMITRE           bool
	HasEvidence        bool
	HasArtifacts       bool
	HasDetections      bool
	HasRelations       bool
	HasDiffResults     bool
	NoCriticalFindings bool
}

type ChainStep struct {
	Index      int
	Time       string
	EventID    string
	SourcePath string
	Summary    string
}

type FindingRow struct {
	Severity   string
	Type       string
	EventID    string
	SourcePath string
	Rationale  string
}

type SummaryRow struct {
	Category       string
	IncidentEvents int
	NewCandidates  int
}

type EventRow struct {
	Time       string
	EventID    string
	Category   string
	Action     string
	Severity   string
	Confidence string
	SourcePath string
	Summary    string
}

type MITRERow struct {
	Technique string
	EventIDs  string
}

type ArtifactRow struct {
	Type   string
	Count  int
	Status string
	Notes  string
}

type DetectionRow struct {
	RuleID     string
	RuleName   string
	EventID    string
	Severity   string
	Confidence string
	Rationale  string
}

type RelationRow struct {
	Type       string
	SourceID   string
	TargetID   string
	Confidence string
	Rationale  string
}

var markdownTemplate = template.Must(template.New("markdown-report").Funcs(template.FuncMap{"code": code}).Parse(`# Windows Incident Diff Report

## Executive Summary

{{ .ExecutiveSummary }}

## High-Confidence Attack Chain

{{- if .HasAttackChain }}
{{- range .AttackChain }}
{{ .Index }}. {{ .Time }} - {{ .Summary }} Evidence: {{ code .EventID }} from {{ code .SourcePath }}.
{{- end }}
{{ else }}
No high-confidence multi-step attack chain was assembled from the current database. Available records may still indicate candidate activity that requires validation.
{{ end }}

## New Critical and High Findings

{{- if .HasHighFindings }}
| Severity | Finding | Evidence |
| --- | --- | --- |
{{- range .HighFindings }}
| {{ .Severity }} | {{ .Type }} - {{ .Rationale }} | {{ code .EventID }} from {{ code .SourcePath }} |
{{- end }}
{{ else }}
No critical or high findings are present in the current diff or detection records. This does not rule out lower-severity candidate activity.
{{ end }}

## Baseline vs Incident Summary

| Category | Incident Events | New Candidate Activity |
| --- | ---: | ---: |
{{- range .BaselineSummary }}
| {{ .Category }} | {{ .IncidentEvents }} | {{ .NewCandidates }} |
{{- end }}

## Timeline of Suspicious Activity

{{- if .HasTimeline }}
| Time UTC | Event ID | Summary | Source Path |
| --- | --- | --- | --- |
{{- range .Timeline }}
| {{ .Time }} | {{ code .EventID }} | {{ .Summary }} | {{ code .SourcePath }} |
{{- end }}
{{ else }}
No suspicious timeline rows were selected from diff, detection, or correlation records.
{{ end }}

## Authentication Findings

{{- if .HasAuthentication }}
{{- range .Authentication }}
- {{ .Time }}: {{ .Summary }} Evidence {{ code .EventID }} from {{ code .SourcePath }}.
{{- end }}
{{ else }}
No authentication findings were selected from the current database.
{{ end }}

## Execution Findings

{{- if .HasExecution }}
{{- range .Execution }}
- {{ .Time }}: {{ .Summary }} Evidence {{ code .EventID }} from {{ code .SourcePath }}.
{{- end }}
{{ else }}
No execution findings were selected from the current database.
{{ end }}

## Persistence Findings

{{- if .HasPersistence }}
{{- range .Persistence }}
- {{ .Time }}: {{ .Summary }} Evidence {{ code .EventID }} from {{ code .SourcePath }}.
{{- end }}
{{ else }}
No persistence findings were selected from the current database.
{{ end }}

## Network Findings

{{- if .HasNetwork }}
{{- range .Network }}
- {{ .Time }}: {{ .Summary }} Evidence {{ code .EventID }} from {{ code .SourcePath }}.
{{- end }}
{{ else }}
No network findings were selected from the current database.
{{ end }}

## Browser and Download Findings

{{- if .HasBrowser }}
{{- range .Browser }}
- {{ .Time }}: {{ .Summary }} Evidence {{ code .EventID }} from {{ code .SourcePath }}.
{{- end }}
{{ else }}
No browser or download findings were selected from the current database.
{{ end }}

## ATT&CK Mapping

{{- if .HasMITRE }}
| Technique | Candidate Evidence |
| --- | --- |
{{- range .MITRE }}
| {{ .Technique }} | {{ .EventIDs }} |
{{- end }}
{{ else }}
No ATT&CK techniques were present in selected normalized events.
{{ end }}

## Evidence Table

{{- if .HasEvidence }}
| Event ID | Category | Action | Severity | Confidence | Source Path |
| --- | --- | --- | --- | --- | --- |
{{- range .Evidence }}
| {{ code .EventID }} | {{ .Category }} | {{ .Action }} | {{ .Severity }} | {{ .Confidence }} | {{ code .SourcePath }} |
{{- end }}
{{ else }}
No normalized events are present in the database.
{{ end }}

## Artifact Coverage

{{- if .HasArtifacts }}
| Artifact | Status | Notes |
| --- | --- | --- |
{{- range .Artifacts }}
| {{ .Type }} | {{ .Status }} | {{ .Notes }} |
{{- end }}
{{ else }}
No artifact records are present in the database.
{{ end }}

## Limitations

- This report identifies evidence patterns consistent with suspicious activity. It does not prove malicious intent by itself. Findings should be validated against host, identity, and network context.
- Findings are candidates and require validation against environment context.
- Baseline coverage, artifact retention, and parser support can affect diff results.
- Report generation is read-only and does not mutate evidence data.
- This Markdown report is generated from SQLite records and does not include PDF or HTML output.

## Appendix

- Case ID: {{ code .CaseID }}
- Baseline case ID: {{ code .BaselineCaseID }}
- Normalized events: {{ .TotalEvents }}
- Diff results: {{ .TotalDiffs }}
- Detections: {{ .TotalDetections }}
- Event relations: {{ .TotalRelations }}
{{- if .HasDetections }}

### Detection Records

| Rule ID | Rule Name | Event ID | Severity | Confidence | Rationale |
| --- | --- | --- | --- | --- | --- |
{{- range .Detections }}
| {{ .RuleID }} | {{ .RuleName }} | {{ code .EventID }} | {{ .Severity }} | {{ .Confidence }} | {{ .Rationale }} |
{{- end }}
{{- end }}
{{- if .HasRelations }}

### Correlation Records

| Type | Source Event | Target Event | Confidence | Rationale |
| --- | --- | --- | --- | --- |
{{- range .Relations }}
| {{ .Type }} | {{ code .SourceID }} | {{ code .TargetID }} | {{ .Confidence }} | {{ .Rationale }} |
{{- end }}
{{- end }}
`))

func RenderMarkdown(w io.Writer, input Input) error {
	document := Build(input)
	return markdownTemplate.Execute(w, document)
}

func Markdown(input Input) (string, error) {
	var buf bytes.Buffer
	if err := RenderMarkdown(&buf, input); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func Build(input Input) Document {
	events := append([]domain.TimelineEvent(nil), input.Events...)
	sort.Slice(events, func(i, j int) bool {
		if events[i].TimestampNS != events[j].TimestampNS {
			return events[i].TimestampNS < events[j].TimestampNS
		}
		return events[i].ID < events[j].ID
	})

	diffs := append([]store.DiffResult(nil), input.DiffResults...)
	sort.Slice(diffs, func(i, j int) bool {
		leftRank := severityRank(diffs[i].Severity)
		rightRank := severityRank(diffs[j].Severity)
		if leftRank != rightRank {
			return leftRank > rightRank
		}
		if diffs[i].DiffType != diffs[j].DiffType {
			return diffs[i].DiffType < diffs[j].DiffType
		}
		if diffs[i].IncidentEventID != diffs[j].IncidentEventID {
			return diffs[i].IncidentEventID < diffs[j].IncidentEventID
		}
		return diffs[i].Fingerprint < diffs[j].Fingerprint
	})

	detections := append([]store.Detection(nil), input.Detections...)
	sort.Slice(detections, func(i, j int) bool {
		if detections[i].Severity != detections[j].Severity {
			return severityRank(detections[i].Severity) > severityRank(detections[j].Severity)
		}
		if detections[i].RuleID != detections[j].RuleID {
			return detections[i].RuleID < detections[j].RuleID
		}
		return detections[i].EventID < detections[j].EventID
	})

	relations := append([]store.EventRelation(nil), input.Relations...)
	sort.Slice(relations, func(i, j int) bool {
		if relations[i].Type != relations[j].Type {
			return relations[i].Type < relations[j].Type
		}
		if relations[i].SourceID != relations[j].SourceID {
			return relations[i].SourceID < relations[j].SourceID
		}
		return relations[i].TargetID < relations[j].TargetID
	})

	eventByID := map[string]domain.TimelineEvent{}
	for _, event := range events {
		eventByID[event.ID] = event
	}

	selected := selectedEventIDs(diffs, detections, relations)
	timeline := make([]EventRow, 0)
	evidence := make([]EventRow, 0, len(events))
	auth := make([]EventRow, 0)
	execution := make([]EventRow, 0)
	persistence := make([]EventRow, 0)
	network := make([]EventRow, 0)
	browser := make([]EventRow, 0)
	for _, event := range events {
		row := eventRow(event)
		evidence = append(evidence, row)
		if selected[event.ID] {
			timeline = append(timeline, row)
		}
		switch normalizedCategory(event) {
		case "auth":
			if selected[event.ID] || interestingAuth(event) {
				auth = append(auth, row)
			}
		case "process":
			if selected[event.ID] || interestingExecution(event) {
				execution = append(execution, row)
			}
		case "persistence", "scheduled_task", "registry":
			if selected[event.ID] || interestingPersistence(event) {
				persistence = append(persistence, row)
			}
		case "network":
			if selected[event.ID] || interestingNetwork(event) {
				network = append(network, row)
			}
		case "browser":
			if selected[event.ID] {
				browser = append(browser, row)
			}
		case "filesystem":
			if strings.Contains(strings.ToLower(event.Object.Path), "download") {
				browser = append(browser, row)
			}
		}
	}
	if len(timeline) == 0 && len(events) > 0 {
		for _, event := range events {
			if isHighSignal(event) {
				timeline = append(timeline, eventRow(event))
			}
		}
	}

	highFindings, criticalCount, highCount := findingRows(diffs, detections, eventByID)
	summary := summaryRows(events, diffs)
	mitre := mitreRows(events)
	artifacts := artifactRows(input.Artifacts)
	detectionRows := detectionRows(detections)
	relationRows := relationRows(relations)
	chain := attackChain(events, selected)

	caseID := input.CaseID
	if caseID == "" && len(events) > 0 {
		caseID = events[0].CaseID
	}
	if caseID == "" {
		caseID = "unknown"
	}
	baselineCaseID := input.BaselineCaseID
	if baselineCaseID == "" && len(diffs) > 0 {
		baselineCaseID = diffs[0].BaselineCaseID
	}
	if baselineCaseID == "" {
		baselineCaseID = "not recorded"
	}

	doc := Document{
		CaseID:             caseID,
		BaselineCaseID:     baselineCaseID,
		ExecutiveSummary:   executiveSummary(len(events), len(diffs), criticalCount, highCount, len(detections), len(relations)),
		AttackChain:        chain,
		HighFindings:       highFindings,
		BaselineSummary:    summary,
		Timeline:           limitEvents(timeline, 20),
		Authentication:     limitEvents(auth, 12),
		Execution:          limitEvents(execution, 12),
		Persistence:        limitEvents(persistence, 12),
		Network:            limitEvents(network, 12),
		Browser:            limitEvents(browser, 12),
		MITRE:              mitre,
		Evidence:           limitEvents(evidence, 25),
		Artifacts:          artifacts,
		Detections:         detectionRows,
		Relations:          relationRows,
		TotalEvents:        len(events),
		TotalDiffs:         len(diffs),
		TotalDetections:    len(detections),
		TotalRelations:     len(relations),
		CriticalFindings:   criticalCount,
		HighFindingsCount:  highCount,
		HasAttackChain:     len(chain) > 0,
		HasHighFindings:    len(highFindings) > 0,
		HasTimeline:        len(timeline) > 0,
		HasAuthentication:  len(auth) > 0,
		HasExecution:       len(execution) > 0,
		HasPersistence:     len(persistence) > 0,
		HasNetwork:         len(network) > 0,
		HasBrowser:         len(browser) > 0,
		HasMITRE:           len(mitre) > 0,
		HasEvidence:        len(evidence) > 0,
		HasArtifacts:       len(artifacts) > 0,
		HasDetections:      len(detectionRows) > 0,
		HasRelations:       len(relationRows) > 0,
		HasDiffResults:     len(diffs) > 0,
		NoCriticalFindings: criticalCount == 0,
	}
	return doc
}

func executiveSummary(eventCount int, diffCount int, criticalCount int, highCount int, detectionCount int, relationCount int) string {
	if eventCount == 0 {
		return "The database contains no normalized events. No incident sequence can be assessed from this evidence set, and this requires validation against artifact collection scope."
	}
	parts := []string{fmt.Sprintf("This report summarizes %d normalized events", eventCount)}
	if diffCount > 0 {
		parts = append(parts, fmt.Sprintf("%d baseline-vs-incident candidate differences", diffCount))
	}
	if detectionCount > 0 {
		parts = append(parts, fmt.Sprintf("%d detection records", detectionCount))
	}
	if relationCount > 0 {
		parts = append(parts, fmt.Sprintf("%d correlation records", relationCount))
	}
	summary := strings.Join(parts, ", ") + "."
	if criticalCount > 0 || highCount > 0 {
		summary += fmt.Sprintf(" The highest-signal records include %d critical and %d high findings that are consistent with activity that requires validation.", criticalCount, highCount)
	} else {
		summary += " No critical or high findings were present; lower-severity observed activity may still require validation."
	}
	return summary
}

func selectedEventIDs(diffs []store.DiffResult, detections []store.Detection, relations []store.EventRelation) map[string]bool {
	selected := map[string]bool{}
	for _, diff := range diffs {
		if diff.IncidentEventID != "" {
			selected[diff.IncidentEventID] = true
		}
	}
	for _, detection := range detections {
		if detection.EventID != "" {
			selected[detection.EventID] = true
		}
	}
	for _, relation := range relations {
		selected[relation.SourceID] = true
		selected[relation.TargetID] = true
	}
	return selected
}

func findingRows(diffs []store.DiffResult, detections []store.Detection, eventByID map[string]domain.TimelineEvent) ([]FindingRow, int, int) {
	rows := make([]FindingRow, 0)
	critical := 0
	high := 0
	for _, diff := range diffs {
		switch diff.Severity {
		case domain.SeverityCritical:
			critical++
		case domain.SeverityHigh:
			high++
		}
		if diff.Severity != domain.SeverityCritical && diff.Severity != domain.SeverityHigh {
			continue
		}
		event := eventByID[diff.IncidentEventID]
		rows = append(rows, FindingRow{
			Severity:   string(diff.Severity),
			Type:       diff.DiffType,
			EventID:    diff.IncidentEventID,
			SourcePath: event.SourcePath,
			Rationale:  cleanCell(diff.Rationale),
		})
	}
	if len(rows) == 0 {
		for _, detection := range detections {
			if detection.Severity != domain.SeverityCritical && detection.Severity != domain.SeverityHigh {
				continue
			}
			event := eventByID[detection.EventID]
			rows = append(rows, FindingRow{
				Severity:   string(detection.Severity),
				Type:       detection.RuleID,
				EventID:    detection.EventID,
				SourcePath: event.SourcePath,
				Rationale:  cleanCell(detection.Rationale),
			})
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Severity != rows[j].Severity {
			return severityRank(domain.Severity(rows[i].Severity)) > severityRank(domain.Severity(rows[j].Severity))
		}
		if rows[i].Type != rows[j].Type {
			return rows[i].Type < rows[j].Type
		}
		return rows[i].EventID < rows[j].EventID
	})
	return rows, critical, high
}

func summaryRows(events []domain.TimelineEvent, diffs []store.DiffResult) []SummaryRow {
	eventCounts := map[string]int{}
	for _, event := range events {
		eventCounts[summaryCategory(event)]++
	}
	diffCounts := map[string]int{}
	for _, diff := range diffs {
		diffCounts[diffCategory(diff.DiffType)]++
	}
	keys := map[string]bool{}
	for key := range eventCounts {
		keys[key] = true
	}
	for key := range diffCounts {
		keys[key] = true
	}
	if len(keys) == 0 {
		keys["No Events"] = true
	}
	ordered := make([]string, 0, len(keys))
	for key := range keys {
		ordered = append(ordered, key)
	}
	sort.Strings(ordered)
	rows := make([]SummaryRow, 0, len(ordered))
	for _, key := range ordered {
		rows = append(rows, SummaryRow{Category: key, IncidentEvents: eventCounts[key], NewCandidates: diffCounts[key]})
	}
	return rows
}

func eventRow(event domain.TimelineEvent) EventRow {
	return EventRow{
		Time:       timeString(event.TimestampNS),
		EventID:    event.ID,
		Category:   event.Category,
		Action:     event.Action,
		Severity:   string(event.Severity),
		Confidence: string(event.Confidence),
		SourcePath: event.SourcePath,
		Summary:    eventSummary(event),
	}
}

func eventSummary(event domain.TimelineEvent) string {
	fields := []string{event.Category + "/" + event.Action}
	if event.Actor.User != "" {
		fields = append(fields, "user "+code(event.Actor.User))
	}
	if event.Actor.Image != "" {
		fields = append(fields, "process "+code(event.Actor.Image))
	}
	if event.Actor.Cmdline != "" {
		fields = append(fields, "command "+code(event.Actor.Cmdline))
	}
	if event.Object.Path != "" {
		fields = append(fields, "object "+code(event.Object.Path))
	}
	if event.Network.DstIP != "" {
		target := event.Network.DstIP
		if event.Network.DstPort != 0 {
			target += ":" + strconv.Itoa(event.Network.DstPort)
		}
		fields = append(fields, "destination "+code(target))
	}
	if event.Network.DNSName != "" {
		fields = append(fields, "dns "+code(event.Network.DNSName))
	}
	return cleanCell("Observed " + strings.Join(fields, "; ") + ".")
}

func attackChain(events []domain.TimelineEvent, selected map[string]bool) []ChainStep {
	candidates := make([]domain.TimelineEvent, 0)
	for _, event := range events {
		if !selected[event.ID] && !isHighSignal(event) {
			continue
		}
		category := normalizedCategory(event)
		if !isHighSignal(event) && !interestingAuth(event) && !interestingExecution(event) && !interestingPersistence(event) && !interestingNetwork(event) && !interestingBrowser(event) && !interestingFilesystem(event) {
			continue
		}
		if category == "auth" || category == "process" || category == "persistence" || category == "scheduled_task" || category == "network" || category == "browser" || category == "filesystem" {
			candidates = append(candidates, event)
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].TimestampNS != candidates[j].TimestampNS {
			return candidates[i].TimestampNS < candidates[j].TimestampNS
		}
		return candidates[i].ID < candidates[j].ID
	})
	if len(candidates) < 2 {
		return nil
	}
	if len(candidates) > 12 {
		candidates = candidates[:12]
	}
	steps := make([]ChainStep, 0, len(candidates))
	for i, event := range candidates {
		steps = append(steps, ChainStep{
			Index:      i + 1,
			Time:       timeString(event.TimestampNS),
			EventID:    event.ID,
			SourcePath: event.SourcePath,
			Summary:    eventSummary(event),
		})
	}
	return steps
}

func mitreRows(events []domain.TimelineEvent) []MITRERow {
	techniques := map[string][]string{}
	for _, event := range events {
		for _, technique := range event.MITRETechniques {
			if strings.TrimSpace(technique) == "" {
				continue
			}
			techniques[technique] = append(techniques[technique], code(event.ID))
		}
	}
	keys := make([]string, 0, len(techniques))
	for key := range techniques {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	rows := make([]MITRERow, 0, len(keys))
	for _, key := range keys {
		sort.Strings(techniques[key])
		rows = append(rows, MITRERow{Technique: key, EventIDs: strings.Join(techniques[key], ", ")})
	}
	return rows
}

func artifactRows(artifacts []store.Artifact) []ArtifactRow {
	counts := map[string]int{}
	paths := map[string][]string{}
	for _, artifact := range artifacts {
		key := artifact.SourceType
		if strings.TrimSpace(key) == "" {
			key = "unknown"
		}
		counts[key]++
		paths[key] = append(paths[key], artifact.SourcePath)
	}
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	rows := make([]ArtifactRow, 0, len(keys))
	for _, key := range keys {
		sort.Strings(paths[key])
		note := fmt.Sprintf("%d artifact record", counts[key])
		if counts[key] != 1 {
			note += "s"
		}
		if len(paths[key]) > 0 {
			note += "; example " + code(paths[key][0])
		}
		rows = append(rows, ArtifactRow{Type: key, Count: counts[key], Status: "Present", Notes: note})
	}
	return rows
}

func detectionRows(detections []store.Detection) []DetectionRow {
	rows := make([]DetectionRow, 0, len(detections))
	for _, detection := range detections {
		rows = append(rows, DetectionRow{
			RuleID:     detection.RuleID,
			RuleName:   detection.RuleName,
			EventID:    detection.EventID,
			Severity:   string(detection.Severity),
			Confidence: string(detection.Confidence),
			Rationale:  cleanCell(detection.Rationale),
		})
	}
	return rows
}

func relationRows(relations []store.EventRelation) []RelationRow {
	rows := make([]RelationRow, 0, len(relations))
	for _, relation := range relations {
		rows = append(rows, RelationRow{
			Type:       relation.Type,
			SourceID:   relation.SourceID,
			TargetID:   relation.TargetID,
			Confidence: string(relation.Confidence),
			Rationale:  cleanCell(relation.Rationale),
		})
	}
	return rows
}

func limitEvents(rows []EventRow, limit int) []EventRow {
	if len(rows) <= limit {
		return rows
	}
	return rows[:limit]
}

func isHighSignal(event domain.TimelineEvent) bool {
	return event.Severity == domain.SeverityCritical || event.Severity == domain.SeverityHigh || len(event.MITRETechniques) > 0
}

func interestingAuth(event domain.TimelineEvent) bool {
	action := strings.ToLower(event.Action)
	return strings.Contains(action, "logon") || strings.Contains(action, "credential") || strings.Contains(action, "privilege")
}

func interestingExecution(event domain.TimelineEvent) bool {
	text := strings.ToLower(event.Actor.Image + " " + event.Actor.Cmdline + " " + event.Object.Path)
	return strings.Contains(text, "powershell") || strings.Contains(text, "cmd.exe") || strings.Contains(text, "rundll32") || strings.Contains(text, "regsvr32")
}

func interestingPersistence(event domain.TimelineEvent) bool {
	action := strings.ToLower(event.Action)
	return strings.Contains(action, "service") || strings.Contains(action, "task") || strings.Contains(action, "registry") || strings.Contains(action, "persistence")
}

func interestingNetwork(event domain.TimelineEvent) bool {
	return event.Network.DstIP != "" || event.Network.DNSName != "" || event.Network.URL != ""
}

func interestingBrowser(event domain.TimelineEvent) bool {
	return event.Category == "browser" && strings.EqualFold(event.Action, "downloaded")
}

func interestingFilesystem(event domain.TimelineEvent) bool {
	action := strings.ToLower(event.Action)
	return (strings.Contains(action, "created") || strings.Contains(action, "write")) && suspiciousReportPath(event.Object.Path)
}

func suspiciousReportPath(path string) bool {
	path = strings.ToLower(strings.ReplaceAll(path, "\\", "/"))
	return strings.Contains(path, "/users/public/") || strings.Contains(path, "/downloads/") || strings.Contains(path, "/temp/") || strings.Contains(path, "/startup/")
}

func normalizedCategory(event domain.TimelineEvent) string {
	category := strings.ToLower(event.Category)
	if category == "scheduled_task" || strings.Contains(strings.ToLower(event.Action), "scheduled_task") {
		return "scheduled_task"
	}
	return category
}

func summaryCategory(event domain.TimelineEvent) string {
	switch normalizedCategory(event) {
	case "auth":
		return "Authentication"
	case "process":
		return "Execution"
	case "persistence", "scheduled_task", "registry":
		return "Persistence"
	case "network":
		return "Network"
	case "browser":
		return "Browser Downloads"
	case "filesystem":
		return "Filesystem"
	default:
		return "Generic"
	}
}

func diffCategory(diffType string) string {
	switch diffType {
	case "new_remote_logon", "new_privilege_event":
		return "Authentication"
	case "new_process", "new_cmdline":
		return "Execution"
	case "new_persistence":
		return "Persistence"
	case "new_network_destination", "new_dns_query":
		return "Network"
	case "new_download":
		return "Browser Downloads"
	case "new_file_write":
		return "Filesystem"
	default:
		return "Generic"
	}
}

func timeString(timestampNS int64) string {
	if timestampNS == 0 {
		return "unknown"
	}
	return time.Unix(0, timestampNS).UTC().Format(time.RFC3339)
}

func severityRank(severity domain.Severity) int {
	switch severity {
	case domain.SeverityCritical:
		return 5
	case domain.SeverityHigh:
		return 4
	case domain.SeverityMedium:
		return 3
	case domain.SeverityLow:
		return 2
	default:
		return 1
	}
}

func cleanCell(value string) string {
	value = strings.ReplaceAll(value, "|", "\\|")
	value = strings.ReplaceAll(value, "\n", " ")
	return strings.TrimSpace(value)
}

func code(value string) string {
	if strings.TrimSpace(value) == "" {
		return "`not recorded`"
	}
	value = strings.ReplaceAll(value, "`", "'")
	return "`" + value + "`"
}
