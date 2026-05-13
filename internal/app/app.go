package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"timeline/internal/collector/amcache"
	"timeline/internal/collector/browser"
	"timeline/internal/collector/evtx"
	"timeline/internal/collector/filesystem"
	"timeline/internal/collector/prefetch"
	"timeline/internal/collector/scheduledtask"
	"timeline/internal/correlate"
	"timeline/internal/detect"
	diffengine "timeline/internal/diff"
	"timeline/internal/domain"
	jsonexport "timeline/internal/export"
	reportgen "timeline/internal/report"
	"timeline/internal/store"
)

type Service struct {
	logger *slog.Logger
	out    io.Writer
}

type IngestOptions struct {
	ArtifactDir            string
	OS                     string
	OutPath                string
	RulesDir               string
	FSPaths                []string
	Strict                 bool
	AllowOutputInArtifacts bool
}

type DiffOptions struct {
	BaselineDB string
	IncidentDB string
	OutPath    string
}

type ReportOptions struct {
	CaseDB  string
	Format  string
	OutPath string
}

type QueryOptions struct {
	CaseDB  string
	Filters []string
}

type ExportOptions struct {
	CaseDB  string
	Format  string
	OutPath string
}

type VerifyOptions struct {
	CaseDB string
}

type RulesValidateOptions struct {
	RulesDir string
}

func New(logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{logger: logger, out: os.Stdout}
}

func (s *Service) SetOutput(out io.Writer) {
	if out == nil {
		s.out = io.Discard
		return
	}
	s.out = out
}

func (s *Service) Ingest(ctx context.Context, opts IngestOptions) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if strings.ToLower(opts.OS) != "windows" {
		return fmt.Errorf("ingest supports --os windows in this phase")
	}
	if opts.ArtifactDir == "" || opts.OutPath == "" {
		return fmt.Errorf("ingest requires an artifact directory and --out path")
	}

	cleanArtifactDir := filepath.Clean(opts.ArtifactDir)
	cleanOutPath := filepath.Clean(opts.OutPath)
	if strings.Contains(cleanArtifactDir, "\x00") || strings.Contains(cleanOutPath, "\x00") {
		return fmt.Errorf("ingest paths contain an invalid character")
	}
	artifactInfo, err := os.Stat(cleanArtifactDir)
	if err != nil {
		return fmt.Errorf("artifact directory is not readable: %w", err)
	}
	if !artifactInfo.IsDir() {
		return fmt.Errorf("artifact path is not a directory: %s", cleanArtifactDir)
	}
	if !opts.AllowOutputInArtifacts && pathWithin(cleanArtifactDir, cleanOutPath) {
		return fmt.Errorf("output path must not be inside the artifact directory unless --allow-output-in-artifacts is set")
	}
	caseID := store.StableCaseID(cleanArtifactDir, cleanOutPath)

	evtxResult, err := evtx.CollectDirectory(ctx, cleanArtifactDir, caseID)
	if err != nil {
		return err
	}
	prefetchResult, err := prefetch.CollectDirectory(ctx, cleanArtifactDir, caseID)
	if err != nil {
		return err
	}
	amcacheResult, err := amcache.CollectDirectory(ctx, cleanArtifactDir, caseID)
	if err != nil {
		return err
	}
	browserResult, err := browser.CollectDirectory(ctx, cleanArtifactDir, caseID)
	if err != nil {
		return err
	}
	taskResult, err := scheduledtask.CollectDirectory(ctx, cleanArtifactDir, caseID)
	if err != nil {
		return err
	}
	filesystemResult, err := filesystem.CollectDirectory(ctx, cleanArtifactDir, caseID, opts.FSPaths)
	if err != nil {
		return err
	}
	if opts.Strict {
		if err := strictIngestError(evtxResult.Stats.ParseErrors, prefetchResult.Stats.ParseErrors, amcacheResult.Stats.ParseErrors, browserResult.Stats.ParseErrors, taskResult.Stats.ParseErrors, prefetchResult.Stats.MalformedFilesSkipped, amcacheResult.Stats.MalformedFilesSkipped, browserResult.Stats.MalformedFilesSkipped, taskResult.Stats.MalformedFilesSkipped); err != nil {
			return err
		}
	}
	eventsToInsert := append([]domain.TimelineEvent{}, evtxResult.Events...)
	eventsToInsert = append(eventsToInsert, prefetchResult.Events...)
	eventsToInsert = append(eventsToInsert, amcacheResult.Events...)
	eventsToInsert = append(eventsToInsert, browserResult.Events...)
	eventsToInsert = append(eventsToInsert, taskResult.Events...)
	eventsToInsert = append(eventsToInsert, filesystemResult.Events...)

	db, err := store.Open(ctx, cleanOutPath)
	if err != nil {
		return err
	}
	defer db.Close()

	if err := store.ApplyMigrations(ctx, db); err != nil {
		return err
	}
	if err := store.EnsureCase(ctx, db, store.Case{
		ID:   caseID,
		Name: filepath.Base(cleanOutPath),
		OS:   "windows",
	}); err != nil {
		return err
	}
	artifactPaths := make([]string, 0)
	artifactSourceTypes := map[string]string{}
	addArtifactPaths := func(sourceType string, paths []string) {
		for _, path := range paths {
			cleanPath := filepath.Clean(path)
			if _, exists := artifactSourceTypes[cleanPath]; exists {
				continue
			}
			artifactSourceTypes[cleanPath] = sourceType
			artifactPaths = append(artifactPaths, cleanPath)
		}
	}
	addArtifactPaths("evtx", evtxResult.Files)
	addArtifactPaths("prefetch", prefetchResult.Files)
	addArtifactPaths("amcache", amcacheResult.Files)
	addArtifactPaths("browser", browserResult.Files)
	addArtifactPaths("scheduled_task_xml", taskResult.Files)
	addArtifactPaths("filesystem", filesystemResult.Files)
	for _, path := range artifactPaths {
		info, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("inspect parsed artifact: %w", err)
		}
		if err := store.InsertArtifact(ctx, db, store.Artifact{
			ID:         store.StableArtifactID(caseID, path),
			CaseID:     caseID,
			SourceType: artifactSourceTypes[path],
			SourcePath: path,
			RawRefJSON: "{}",
			SizeBytes:  info.Size(),
		}); err != nil {
			return err
		}
	}
	if err := store.InsertEvents(ctx, db, eventsToInsert); err != nil {
		return err
	}
	events, err := store.QueryEvents(ctx, db, store.QueryFilters{})
	if err != nil {
		return err
	}
	correlationResult := correlate.PrefetchProcess(events)
	relations := append([]correlate.Relation{}, correlationResult.Relations...)
	if len(correlationResult.Relations) > 0 {
		if err := store.InsertEvents(ctx, db, correlationResult.Events); err != nil {
			return err
		}
	}
	events, err = store.QueryEvents(ctx, db, store.QueryFilters{})
	if err != nil {
		return err
	}
	amcacheCorrelationResult := correlate.AmCacheExecution(events)
	relations = append(relations, amcacheCorrelationResult.Relations...)
	if len(amcacheCorrelationResult.Relations) > 0 {
		if err := store.InsertEvents(ctx, db, amcacheCorrelationResult.Events); err != nil {
			return err
		}
	}
	events, err = store.QueryEvents(ctx, db, store.QueryFilters{})
	if err != nil {
		return err
	}
	browserCorrelationResult := correlate.BrowserDownloadExecution(events)
	relations = append(relations, browserCorrelationResult.Relations...)
	if len(browserCorrelationResult.Relations) > 0 {
		if err := store.InsertEvents(ctx, db, browserCorrelationResult.Events); err != nil {
			return err
		}
	}
	if err := store.InsertEventRelations(ctx, db, toStoreRelations(relations)); err != nil {
		return err
	}
	rulesDir := opts.RulesDir
	if strings.TrimSpace(rulesDir) == "" {
		rulesDir = "rules"
	}
	rules, err := detect.LoadDirectory(rulesDir)
	if err != nil {
		return err
	}
	events, err = store.QueryEvents(ctx, db, store.QueryFilters{})
	if err != nil {
		return err
	}
	detectionResult := detect.Apply(rules, events)
	if err := store.ApplyDetections(ctx, db, detectionResult.Events, toStoreDetections(detectionResult.Detections)); err != nil {
		return err
	}

	if s.out != nil {
		fmt.Fprintf(s.out, "ingest complete: evtx_files=%d prefetch_files=%d amcache_files=%d browser_files=%d scheduled_task_files=%d filesystem_files=%d events emitted=%d events skipped=%d malformed_prefetch=%d malformed_amcache=%d malformed_browser=%d malformed_scheduled_tasks=%d parse errors=%d relations=%d detections=%d\n",
			evtxResult.Stats.FilesParsed,
			prefetchResult.Stats.FilesParsed,
			amcacheResult.Stats.FilesParsed,
			browserResult.Stats.FilesParsed,
			taskResult.Stats.FilesParsed,
			filesystemResult.Stats.FilesObserved,
			len(eventsToInsert),
			evtxResult.Stats.EventsSkipped,
			prefetchResult.Stats.MalformedFilesSkipped,
			amcacheResult.Stats.MalformedFilesSkipped,
			browserResult.Stats.MalformedFilesSkipped,
			taskResult.Stats.MalformedFilesSkipped,
			evtxResult.Stats.ParseErrors+prefetchResult.Stats.ParseErrors+amcacheResult.Stats.ParseErrors+browserResult.Stats.ParseErrors+taskResult.Stats.ParseErrors,
			len(relations),
			len(detectionResult.Detections),
		)
	}
	return nil
}

func pathWithin(parent string, child string) bool {
	rel, err := filepath.Rel(filepath.Clean(parent), filepath.Clean(child))
	if err != nil {
		return false
	}
	return rel == "." || (!strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != "..")
}

func strictIngestError(parseCounts ...int) error {
	total := 0
	for _, count := range parseCounts {
		total += count
	}
	if total == 0 {
		return nil
	}
	return fmt.Errorf("strict ingest failed: malformed or unparsable artifacts=%d", total)
}

func (s *Service) Diff(ctx context.Context, opts DiffOptions) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if opts.BaselineDB == "" || opts.IncidentDB == "" {
		return fmt.Errorf("diff requires baseline and incident database paths")
	}
	if err := store.VerifyDatabase(ctx, opts.BaselineDB); err != nil {
		return fmt.Errorf("baseline database validation failed: %w", err)
	}
	if err := store.VerifyDatabase(ctx, opts.IncidentDB); err != nil {
		return fmt.Errorf("incident database validation failed: %w", err)
	}
	baselineDB, err := store.OpenReadOnly(ctx, filepath.Clean(opts.BaselineDB))
	if err != nil {
		return err
	}
	defer baselineDB.Close()
	incidentDB, err := store.Open(ctx, filepath.Clean(opts.IncidentDB))
	if err != nil {
		return err
	}
	defer incidentDB.Close()

	baselineCaseID, err := store.QueryCaseID(ctx, baselineDB)
	if err != nil {
		return fmt.Errorf("read baseline case: %w", err)
	}
	incidentCaseID, err := store.QueryCaseID(ctx, incidentDB)
	if err != nil {
		return fmt.Errorf("read incident case: %w", err)
	}
	baselineEvents, err := store.QueryEvents(ctx, baselineDB, store.QueryFilters{})
	if err != nil {
		return fmt.Errorf("query baseline events: %w", err)
	}
	incidentEvents, err := store.QueryEvents(ctx, incidentDB, store.QueryFilters{})
	if err != nil {
		return fmt.Errorf("query incident events: %w", err)
	}
	baselineDetections, err := store.QueryDetections(ctx, baselineDB)
	if err != nil {
		return fmt.Errorf("query baseline detections: %w", err)
	}
	incidentDetections, err := store.QueryDetections(ctx, incidentDB)
	if err != nil {
		return fmt.Errorf("query incident detections: %w", err)
	}

	result := diffengine.Compare(baselineEvents, incidentEvents, baselineDetections, incidentDetections)
	storeResults := diffengine.ToStoreResults(baselineCaseID, incidentCaseID, result.Findings)
	if err := store.ReplaceDiffResults(ctx, incidentDB, baselineCaseID, incidentCaseID, storeResults); err != nil {
		return err
	}
	if s.out != nil {
		fmt.Fprintf(s.out, "diff complete: findings=%d critical=%d high=%d medium=%d low=%d info=%d\n",
			result.Summary.Total,
			result.Summary.Critical,
			result.Summary.High,
			result.Summary.Medium,
			result.Summary.Low,
			result.Summary.Info,
		)
		for _, finding := range result.Findings {
			fmt.Fprintf(s.out, "%s\t%s\t%s\t%s\t%s\n",
				finding.Severity,
				finding.DiffType,
				finding.SourceEvent,
				finding.SourcePath,
				finding.Rationale,
			)
		}
	}
	if strings.TrimSpace(opts.OutPath) != "" {
		input, err := loadReportInput(ctx, incidentDB, baselineCaseID, incidentCaseID)
		if err != nil {
			return err
		}
		if err := writeMarkdownReport(filepath.Clean(opts.OutPath), input); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) Report(ctx context.Context, opts ReportOptions) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if opts.Format != "md" {
		return fmt.Errorf("report supports --format md in this phase")
	}
	if opts.CaseDB == "" || opts.OutPath == "" {
		return fmt.Errorf("report requires a case database and --out path")
	}
	if err := store.VerifyDatabase(ctx, opts.CaseDB); err != nil {
		return fmt.Errorf("database validation failed: %w", err)
	}
	db, err := store.OpenReadOnly(ctx, filepath.Clean(opts.CaseDB))
	if err != nil {
		return err
	}
	defer db.Close()
	caseID, err := store.QueryCaseID(ctx, db)
	if err != nil {
		caseID = "unknown"
	}
	input, err := loadReportInput(ctx, db, "", caseID)
	if err != nil {
		return err
	}
	if err := writeMarkdownReport(filepath.Clean(opts.OutPath), input); err != nil {
		return err
	}
	if s.out != nil {
		fmt.Fprintf(s.out, "report complete: out=%s\n", filepath.Clean(opts.OutPath))
	}
	return nil
}

func (s *Service) Query(ctx context.Context, opts QueryOptions) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if opts.CaseDB == "" {
		return fmt.Errorf("query requires a case database")
	}

	request, err := parseQueryRequest(opts.Filters)
	if err != nil {
		return err
	}
	if err := store.VerifyDatabase(ctx, opts.CaseDB); err != nil {
		return fmt.Errorf("database validation failed: %w", err)
	}
	db, err := store.OpenReadOnly(ctx, filepath.Clean(opts.CaseDB))
	if err != nil {
		return err
	}
	defer db.Close()

	events, err := store.QueryEvents(ctx, db, request.Filters)
	if err != nil {
		return err
	}
	if s.out == nil {
		return nil
	}
	if request.Format == "json" {
		encoder := json.NewEncoder(s.out)
		encoder.SetIndent("", "  ")
		return encoder.Encode(jsonexport.FromDomainSlice(events))
	}

	writer := tabwriter.NewWriter(s.out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(writer, "timestamp_ns\tcategory\taction\tseverity\tevent_id\tsource_path")
	for _, event := range events {
		fmt.Fprintf(writer, "%d\t%s\t%s\t%s\t%s\t%s\n",
			event.TimestampNS,
			event.Category,
			event.Action,
			event.Severity,
			event.ID,
			event.SourcePath,
		)
	}
	return writer.Flush()
}

func (s *Service) Export(ctx context.Context, opts ExportOptions) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if opts.Format != "jsonl" {
		return fmt.Errorf("export supports --format jsonl in this phase")
	}
	if opts.CaseDB == "" || opts.OutPath == "" {
		return fmt.Errorf("export requires a case database and --out path")
	}
	if err := store.VerifyDatabase(ctx, opts.CaseDB); err != nil {
		return fmt.Errorf("database validation failed: %w", err)
	}
	db, err := store.OpenReadOnly(ctx, filepath.Clean(opts.CaseDB))
	if err != nil {
		return err
	}
	defer db.Close()

	events, err := store.QueryEvents(ctx, db, store.QueryFilters{})
	if err != nil {
		return err
	}

	cleanOutPath := filepath.Clean(opts.OutPath)
	file, err := os.OpenFile(cleanOutPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("open export output: %w", err)
	}
	defer file.Close()

	if err := jsonexport.WriteJSONL(file, events); err != nil {
		return err
	}
	if s.out != nil {
		fmt.Fprintf(s.out, "export complete: events=%d out=%s\n", len(events), cleanOutPath)
	}
	return nil
}

func (s *Service) Verify(ctx context.Context, opts VerifyOptions) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if opts.CaseDB == "" {
		return fmt.Errorf("verify requires a case database")
	}
	if err := store.VerifyDatabase(ctx, opts.CaseDB); err != nil {
		return fmt.Errorf("database validation failed: %w", err)
	}
	return nil
}

func (s *Service) ValidateRules(ctx context.Context, opts RulesValidateOptions) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if opts.RulesDir == "" {
		return fmt.Errorf("rules validate requires a rules directory")
	}
	rules, err := detect.LoadDirectory(opts.RulesDir)
	if err != nil {
		return err
	}
	if s.out != nil {
		fmt.Fprintf(s.out, "rules valid: files=%d rules=%d\n", rules.FileCount, len(rules.Rules))
	}
	return nil
}

type queryRequest struct {
	Filters store.QueryFilters
	Format  string
}

func parseQueryRequest(filters []string) (queryRequest, error) {
	parsed := queryRequest{
		Filters: store.QueryFilters{Limit: 100},
		Format:  "table",
	}
	for _, filter := range filters {
		key, value, ok := strings.Cut(filter, "=")
		if !ok {
			return queryRequest{}, fmt.Errorf("invalid query filter %q; expected key=value", filter)
		}
		switch strings.TrimSpace(key) {
		case "category":
			parsed.Filters.Category = strings.ToLower(strings.TrimSpace(value))
		case "severity":
			severity := domain.Severity(strings.ToLower(strings.TrimSpace(value)))
			if !severity.Valid() {
				return queryRequest{}, fmt.Errorf("invalid query severity %q", value)
			}
			parsed.Filters.Severity = string(severity)
		case "confidence":
			confidence := domain.Confidence(strings.ToLower(strings.TrimSpace(value)))
			if !confidence.Valid() {
				return queryRequest{}, fmt.Errorf("invalid query confidence %q", value)
			}
			parsed.Filters.Confidence = string(confidence)
		case "from":
			timestamp, err := parseTimestampNS("from", value)
			if err != nil {
				return queryRequest{}, err
			}
			parsed.Filters.FromTimestamp = timestamp
			parsed.Filters.HasFrom = true
		case "to":
			timestamp, err := parseTimestampNS("to", value)
			if err != nil {
				return queryRequest{}, err
			}
			parsed.Filters.ToTimestamp = timestamp
			parsed.Filters.HasTo = true
		case "actor":
			parsed.Filters.Actor = strings.TrimSpace(value)
		case "process":
			parsed.Filters.Process = strings.TrimSpace(value)
		case "object_path", "object-path":
			parsed.Filters.ObjectPath = strings.TrimSpace(value)
		case "hash":
			parsed.Filters.Hash = strings.TrimSpace(value)
		case "dst_ip", "dst-ip":
			parsed.Filters.DstIP = strings.TrimSpace(value)
		case "limit":
			limit, err := strconv.Atoi(strings.TrimSpace(value))
			if err != nil || limit <= 0 {
				return queryRequest{}, fmt.Errorf("invalid query limit %q", value)
			}
			parsed.Filters.Limit = limit
		case "format":
			format := strings.TrimSpace(value)
			if format != "table" && format != "json" {
				return queryRequest{}, fmt.Errorf("query supports --format table or --format json")
			}
			parsed.Format = format
		default:
			return queryRequest{}, fmt.Errorf("unsupported query filter %q", key)
		}
	}
	if parsed.Filters.HasFrom && parsed.Filters.HasTo && parsed.Filters.FromTimestamp > parsed.Filters.ToTimestamp {
		return queryRequest{}, fmt.Errorf("invalid query time range: --from must be before or equal to --to")
	}
	return parsed, nil
}

func parseTimestampNS(flagName string, value string) (int64, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, fmt.Errorf("invalid --%s timestamp: value is empty", flagName)
	}
	if timestamp, err := strconv.ParseInt(value, 10, 64); err == nil {
		return timestamp, nil
	}
	timestamp, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return 0, fmt.Errorf("invalid --%s timestamp %q; expected RFC3339 or timestamp_ns", flagName, value)
	}
	return timestamp.UTC().UnixNano(), nil
}

func loadReportInput(ctx context.Context, db *sql.DB, baselineCaseID string, caseID string) (reportgen.Input, error) {
	events, err := store.QueryEvents(ctx, db, store.QueryFilters{})
	if err != nil {
		return reportgen.Input{}, fmt.Errorf("query report events: %w", err)
	}
	detections, err := store.QueryDetections(ctx, db)
	if err != nil {
		return reportgen.Input{}, fmt.Errorf("query report detections: %w", err)
	}
	relations, err := store.QueryEventRelations(ctx, db)
	if err != nil {
		return reportgen.Input{}, fmt.Errorf("query report correlations: %w", err)
	}
	diffResults, err := store.QueryDiffResults(ctx, db)
	if err != nil {
		return reportgen.Input{}, fmt.Errorf("query report diff results: %w", err)
	}
	artifacts, err := store.QueryArtifacts(ctx, db)
	if err != nil {
		return reportgen.Input{}, fmt.Errorf("query report artifacts: %w", err)
	}
	if caseID == "" {
		caseID, _ = store.QueryCaseID(ctx, db)
	}
	return reportgen.Input{
		CaseID:         caseID,
		BaselineCaseID: baselineCaseID,
		Events:         events,
		Detections:     detections,
		Relations:      relations,
		DiffResults:    diffResults,
		Artifacts:      artifacts,
	}, nil
}

func writeMarkdownReport(path string, input reportgen.Input) error {
	// #nosec G304 -- report output path is a user-requested destination, opened with restrictive file permissions.
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("open report output: %w", err)
	}
	if err := reportgen.RenderMarkdown(file, input); err != nil {
		if closeErr := file.Close(); closeErr != nil {
			return fmt.Errorf("render markdown report: %w; close report output: %v", err, closeErr)
		}
		return fmt.Errorf("render markdown report: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close report output: %w", err)
	}
	return nil
}

func toStoreDetections(detections []detect.Detection) []store.Detection {
	out := make([]store.Detection, 0, len(detections))
	for _, detection := range detections {
		out = append(out, store.Detection{
			CaseID:           detection.CaseID,
			EventID:          detection.EventID,
			RuleID:           detection.RuleID,
			RuleName:         detection.RuleName,
			Severity:         detection.Severity,
			Confidence:       detection.Confidence,
			EvidenceStrength: detection.EvidenceStrength,
			Rationale:        detection.Rationale,
		})
	}
	return out
}

func toStoreRelations(relations []correlate.Relation) []store.EventRelation {
	out := make([]store.EventRelation, 0, len(relations))
	for _, relation := range relations {
		out = append(out, store.EventRelation{
			CaseID:     relation.CaseID,
			SourceID:   relation.SourceID,
			TargetID:   relation.TargetID,
			Type:       relation.Type,
			Confidence: relation.Confidence,
			Rationale:  relation.Rationale,
		})
	}
	return out
}
