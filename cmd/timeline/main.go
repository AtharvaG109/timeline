package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"

	"github.com/spf13/cobra"

	"timeline/internal/app"
	"timeline/internal/version"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	service := app.New(logger)
	service.SetOutput(os.Stdout)
	root := newRootCommand(service)
	if err := root.ExecuteContext(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "timeline: %v\n", err)
		os.Exit(1)
	}
}

func newRootCommand(service *app.Service) *cobra.Command {
	root := &cobra.Command{
		Use:           "timeline",
		Short:         "Windows-first DFIR timeline diff engine",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version.Version,
	}

	root.AddCommand(newIngestCommand(service))
	root.AddCommand(newDiffCommand(service))
	root.AddCommand(newReportCommand(service))
	root.AddCommand(newQueryCommand(service))
	root.AddCommand(newExportCommand(service))
	root.AddCommand(newVerifyCommand(service))
	root.AddCommand(newRulesCommand(service))
	root.AddCommand(newVersionCommand())

	return root
}

func newIngestCommand(service *app.Service) *cobra.Command {
	var osName string
	var outPath string
	var rulesDir string
	var fsPaths []string
	var strict bool
	var allowOutputInArtifacts bool

	cmd := &cobra.Command{
		Use:   "ingest <artifact-dir>",
		Short: "Ingest Windows artifacts into a SQLite evidence database",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return service.Ingest(cmd.Context(), app.IngestOptions{
				ArtifactDir:            args[0],
				OS:                     osName,
				OutPath:                outPath,
				RulesDir:               rulesDir,
				FSPaths:                fsPaths,
				Strict:                 strict,
				AllowOutputInArtifacts: allowOutputInArtifacts,
			})
		},
	}
	cmd.Flags().StringVar(&osName, "os", "", "source operating system")
	cmd.Flags().StringVar(&outPath, "out", "", "output SQLite case database")
	cmd.Flags().StringVar(&rulesDir, "rules", "rules", "detection rules directory")
	cmd.Flags().StringArrayVar(&fsPaths, "fs-path", nil, "targeted Windows filesystem path to collect metadata from; may be repeated")
	cmd.Flags().BoolVar(&strict, "strict", false, "fail ingest when a malformed supported artifact is encountered")
	cmd.Flags().BoolVar(&allowOutputInArtifacts, "allow-output-in-artifacts", false, "allow writing the output database inside the artifact directory")
	_ = cmd.MarkFlagRequired("os")
	_ = cmd.MarkFlagRequired("out")
	return cmd
}

func newDiffCommand(service *app.Service) *cobra.Command {
	var outPath string

	cmd := &cobra.Command{
		Use:   "diff <baseline.db> <incident.db>",
		Short: "Compare baseline and incident databases",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return service.Diff(cmd.Context(), app.DiffOptions{
				BaselineDB: args[0],
				IncidentDB: args[1],
				OutPath:    outPath,
			})
		},
	}
	cmd.Flags().StringVar(&outPath, "out", "", "output Markdown report")
	return cmd
}

func newReportCommand(service *app.Service) *cobra.Command {
	var format string
	var outPath string

	cmd := &cobra.Command{
		Use:   "report <case.db>",
		Short: "Render a report from an evidence database",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return service.Report(cmd.Context(), app.ReportOptions{
				CaseDB:  args[0],
				Format:  format,
				OutPath: outPath,
			})
		},
	}
	cmd.Flags().StringVar(&format, "format", "md", "report format")
	cmd.Flags().StringVar(&outPath, "out", "", "output report path")
	_ = cmd.MarkFlagRequired("out")
	return cmd
}

func newQueryCommand(service *app.Service) *cobra.Command {
	var category string
	var severity string
	var confidence string
	var from string
	var to string
	var actor string
	var process string
	var objectPath string
	var hash string
	var dstIP string
	var limit int
	var format string

	cmd := &cobra.Command{
		Use:   "query <case.db> [filters]",
		Short: "Query normalized timeline events",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			filters := append([]string{}, args[1:]...)
			if category != "" {
				filters = append(filters, "category="+category)
			}
			if severity != "" {
				filters = append(filters, "severity="+severity)
			}
			if confidence != "" {
				filters = append(filters, "confidence="+confidence)
			}
			if from != "" {
				filters = append(filters, "from="+from)
			}
			if to != "" {
				filters = append(filters, "to="+to)
			}
			if actor != "" {
				filters = append(filters, "actor="+actor)
			}
			if process != "" {
				filters = append(filters, "process="+process)
			}
			if objectPath != "" {
				filters = append(filters, "object_path="+objectPath)
			}
			if hash != "" {
				filters = append(filters, "hash="+hash)
			}
			if dstIP != "" {
				filters = append(filters, "dst_ip="+dstIP)
			}
			if limit > 0 {
				filters = append(filters, "limit="+strconv.Itoa(limit))
			}
			if format != "" {
				filters = append(filters, "format="+format)
			}
			return service.Query(cmd.Context(), app.QueryOptions{
				CaseDB:  args[0],
				Filters: filters,
			})
		},
	}
	cmd.Flags().StringVar(&category, "category", "", "filter by normalized event category")
	cmd.Flags().StringVar(&severity, "severity", "", "filter by severity")
	cmd.Flags().StringVar(&confidence, "confidence", "", "filter by confidence")
	cmd.Flags().StringVar(&from, "from", "", "filter events at or after RFC3339 time or timestamp_ns")
	cmd.Flags().StringVar(&to, "to", "", "filter events at or before RFC3339 time or timestamp_ns")
	cmd.Flags().StringVar(&actor, "actor", "", "filter by actor content")
	cmd.Flags().StringVar(&process, "process", "", "filter by process image or command line")
	cmd.Flags().StringVar(&objectPath, "object-path", "", "filter by object path")
	cmd.Flags().StringVar(&hash, "hash", "", "filter by object hash")
	cmd.Flags().StringVar(&dstIP, "dst-ip", "", "filter by destination IP")
	cmd.Flags().IntVar(&limit, "limit", 100, "maximum events to print")
	cmd.Flags().StringVar(&format, "format", "table", "output format: table or json")
	return cmd
}

func newExportCommand(service *app.Service) *cobra.Command {
	var format string
	var outPath string

	cmd := &cobra.Command{
		Use:   "export <case.db>",
		Short: "Export normalized timeline events",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return service.Export(cmd.Context(), app.ExportOptions{
				CaseDB:  args[0],
				Format:  format,
				OutPath: outPath,
			})
		},
	}
	cmd.Flags().StringVar(&format, "format", "jsonl", "export format")
	cmd.Flags().StringVar(&outPath, "out", "", "output export path")
	_ = cmd.MarkFlagRequired("out")
	return cmd
}

func newVerifyCommand(service *app.Service) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify <case.db>",
		Short: "Validate a timeline SQLite database",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return service.Verify(cmd.Context(), app.VerifyOptions{CaseDB: args[0]})
		},
	}
	return cmd
}

func newRulesCommand(service *app.Service) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rules",
		Short: "Manage detection rules",
	}
	cmd.AddCommand(newRulesValidateCommand(service))
	return cmd
}

func newRulesValidateCommand(service *app.Service) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "validate <rules-dir>",
		Short: "Validate YAML detection rules",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return service.ValidateRules(cmd.Context(), app.RulesValidateOptions{RulesDir: args[0]})
		},
	}
	return cmd
}

func newVersionCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print timeline version metadata",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "timeline version=%s commit=%s date=%s\n", version.Version, version.Commit, version.Date)
		},
	}
	return cmd
}
