package detect

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"timeline/internal/domain"
)

type RuleSet struct {
	FileCount int
	Rules     []Rule
}

type RuleFile struct {
	Group string `yaml:"group"`
	Rules []Rule `yaml:"rules"`
}

type Rule struct {
	ID               string                  `yaml:"id"`
	Name             string                  `yaml:"name"`
	Description      string                  `yaml:"description"`
	Severity         domain.Severity         `yaml:"severity"`
	Confidence       domain.Confidence       `yaml:"confidence"`
	EvidenceStrength domain.EvidenceStrength `yaml:"evidence_strength"`
	Tags             []string                `yaml:"tags"`
	MITRETechniques  []string                `yaml:"mitre_techniques"`
	Match            MatchBlock              `yaml:"match"`
	Aggregate        string                  `yaml:"aggregate"`
	sourceFile       string
}

type MatchBlock struct {
	All []Condition `yaml:"all"`
	Any []Condition `yaml:"any"`
}

type Condition struct {
	Field string   `yaml:"field"`
	Op    string   `yaml:"op"`
	Value string   `yaml:"value"`
	In    []string `yaml:"in"`
}

type Result struct {
	Events     []domain.TimelineEvent
	Detections []Detection
}

type Detection struct {
	CaseID           string
	EventID          string
	RuleID           string
	RuleName         string
	Severity         domain.Severity
	Confidence       domain.Confidence
	EvidenceStrength domain.EvidenceStrength
	Rationale        string
}

var supportedOperators = map[string]struct{}{
	"equals":      {},
	"equals_ci":   {},
	"contains":    {},
	"contains_ci": {},
	"prefix":      {},
	"suffix":      {},
	"regex":       {},
	"regex_ci":    {},
	"in":          {},
	"exists":      {},
	"not_exists":  {},
}

var supportedAggregates = map[string]struct{}{
	"failed_logons_then_success": {},
}

func LoadDirectory(dir string) (RuleSet, error) {
	cleanDir := filepath.Clean(dir)
	entries, err := os.ReadDir(cleanDir)
	if err != nil {
		return RuleSet{}, fmt.Errorf("read rules directory %s: %w", cleanDir, err)
	}

	set := RuleSet{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			continue
		}
		path := filepath.Join(cleanDir, name)
		file, err := loadFile(path)
		if err != nil {
			return RuleSet{}, err
		}
		set.FileCount++
		for _, rule := range file.Rules {
			rule.sourceFile = path
			set.Rules = append(set.Rules, rule)
		}
	}
	if len(set.Rules) == 0 {
		return RuleSet{}, fmt.Errorf("rules directory %s has no YAML rules", cleanDir)
	}
	if err := validateRuleSet(set); err != nil {
		return RuleSet{}, err
	}
	return set, nil
}

func loadFile(path string) (RuleFile, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return RuleFile{}, fmt.Errorf("read rule file %s: %w", path, err)
	}
	var file RuleFile
	if err := yaml.Unmarshal(content, &file); err != nil {
		return RuleFile{}, fmt.Errorf("invalid YAML in %s: %w", path, err)
	}
	for i := range file.Rules {
		file.Rules[i].sourceFile = path
	}
	return file, nil
}

func validateRuleSet(set RuleSet) error {
	seen := make(map[string]string)
	for _, rule := range set.Rules {
		if strings.TrimSpace(rule.ID) == "" {
			return fmt.Errorf("%s: rule missing required field id", rule.sourceFile)
		}
		if prior := seen[rule.ID]; prior != "" {
			return fmt.Errorf("%s: duplicate rule id %s already defined in %s", rule.sourceFile, rule.ID, prior)
		}
		seen[rule.ID] = rule.sourceFile
		if strings.TrimSpace(rule.Name) == "" {
			return fmt.Errorf("%s: rule %s missing required field name", rule.sourceFile, rule.ID)
		}
		if !rule.Severity.Valid() {
			return fmt.Errorf("%s: rule %s has invalid severity %q", rule.sourceFile, rule.ID, rule.Severity)
		}
		if !rule.Confidence.Valid() {
			return fmt.Errorf("%s: rule %s has invalid confidence %q", rule.sourceFile, rule.ID, rule.Confidence)
		}
		if rule.EvidenceStrength == "" {
			rule.EvidenceStrength = domain.EvidenceModerate
		}
		if rule.EvidenceStrength != "" && !rule.EvidenceStrength.Valid() {
			return fmt.Errorf("%s: rule %s has invalid evidence_strength %q", rule.sourceFile, rule.ID, rule.EvidenceStrength)
		}
		if rule.Aggregate != "" {
			if _, ok := supportedAggregates[rule.Aggregate]; !ok {
				return fmt.Errorf("%s: rule %s has unsupported aggregate %q", rule.sourceFile, rule.ID, rule.Aggregate)
			}
		}
		if len(rule.Match.All) == 0 && len(rule.Match.Any) == 0 && rule.Aggregate == "" {
			return fmt.Errorf("%s: rule %s missing match conditions", rule.sourceFile, rule.ID)
		}
		for _, condition := range append(rule.Match.All, rule.Match.Any...) {
			if err := validateCondition(rule.sourceFile, rule.ID, condition); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateCondition(path string, ruleID string, condition Condition) error {
	if strings.TrimSpace(condition.Field) == "" {
		return fmt.Errorf("%s: rule %s has condition missing field", path, ruleID)
	}
	if _, ok := supportedOperators[condition.Op]; !ok {
		return fmt.Errorf("%s: rule %s condition on %s has unsupported operator %q", path, ruleID, condition.Field, condition.Op)
	}
	switch condition.Op {
	case "exists", "not_exists":
		return nil
	case "in":
		if len(condition.In) == 0 {
			return fmt.Errorf("%s: rule %s condition on %s requires in values", path, ruleID, condition.Field)
		}
	case "regex", "regex_ci":
		pattern := condition.Value
		if condition.Op == "regex_ci" {
			pattern = "(?i)" + pattern
		}
		if _, err := regexp.Compile(pattern); err != nil {
			return fmt.Errorf("%s: rule %s condition on %s has invalid regex: %w", path, ruleID, condition.Field, err)
		}
	default:
		if strings.TrimSpace(condition.Value) == "" {
			return fmt.Errorf("%s: rule %s condition on %s requires value", path, ruleID, condition.Field)
		}
	}
	return nil
}

func Apply(rules RuleSet, events []domain.TimelineEvent) Result {
	updated := make([]domain.TimelineEvent, 0, len(events))
	detections := make([]Detection, 0)
	for _, event := range events {
		next := event
		for _, rule := range rules.Rules {
			if rule.Aggregate != "" {
				continue
			}
			if !matchesRule(rule, next) {
				continue
			}
			next, detections = applyRuleToEvent(rule, next, detections)
		}
		updated = append(updated, next)
	}
	updated, detections = applyAggregateRules(rules, updated, detections)
	return Result{Events: updated, Detections: detections}
}

func applyRuleToEvent(rule Rule, event domain.TimelineEvent, detections []Detection) (domain.TimelineEvent, []Detection) {
	evidenceStrength := rule.EvidenceStrength
	if evidenceStrength == "" {
		evidenceStrength = domain.EvidenceModerate
	}
	event.Severity = maxSeverity(event.Severity, rule.Severity)
	event.Confidence = maxConfidence(event.Confidence, rule.Confidence)
	event.EvidenceStrength = maxEvidenceStrength(event.EvidenceStrength, evidenceStrength)
	event.Tags = mergeStrings(event.Tags, rule.Tags)
	event.MITRETechniques = mergeStrings(event.MITRETechniques, rule.MITRETechniques)
	detections = append(detections, Detection{
		CaseID:           event.CaseID,
		EventID:          event.ID,
		RuleID:           rule.ID,
		RuleName:         rule.Name,
		Severity:         rule.Severity,
		Confidence:       rule.Confidence,
		EvidenceStrength: evidenceStrength,
		Rationale:        rule.Description,
	})
	return event, detections
}

func applyAggregateRules(rules RuleSet, events []domain.TimelineEvent, detections []Detection) ([]domain.TimelineEvent, []Detection) {
	for _, rule := range rules.Rules {
		if rule.Aggregate != "failed_logons_then_success" {
			continue
		}
		for i, event := range events {
			if event.Category != "auth" || event.Action != "successful_logon" {
				continue
			}
			if failedLogonCountBeforeSuccess(events, event) < 3 {
				continue
			}
			events[i], detections = applyRuleToEvent(rule, event, detections)
		}
	}
	return events, detections
}

func failedLogonCountBeforeSuccess(events []domain.TimelineEvent, success domain.TimelineEvent) int {
	count := 0
	windowStart := success.TimestampNS - int64(15*60*1_000_000_000)
	for _, candidate := range events {
		if candidate.TimestampNS < windowStart || candidate.TimestampNS >= success.TimestampNS {
			continue
		}
		if candidate.Category != "auth" || candidate.Action != "failed_logon" {
			continue
		}
		sameUser := candidate.Actor.User != "" && strings.EqualFold(candidate.Actor.User, success.Actor.User)
		sameIP := candidate.Network.SrcIP != "" && candidate.Network.SrcIP == success.Network.SrcIP
		if sameUser || sameIP {
			count++
		}
	}
	return count
}

func matchesRule(rule Rule, event domain.TimelineEvent) bool {
	for _, condition := range rule.Match.All {
		if !matchesCondition(event, condition) {
			return false
		}
	}
	if len(rule.Match.Any) == 0 {
		return true
	}
	for _, condition := range rule.Match.Any {
		if matchesCondition(event, condition) {
			return true
		}
	}
	return false
}

func matchesCondition(event domain.TimelineEvent, condition Condition) bool {
	values := fieldValues(event, condition.Field)
	exists := false
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			exists = true
			break
		}
	}
	switch condition.Op {
	case "exists":
		return exists
	case "not_exists":
		return !exists
	}
	for _, value := range values {
		if matchValue(value, condition) {
			return true
		}
	}
	return false
}

func matchValue(value string, condition Condition) bool {
	switch condition.Op {
	case "equals":
		return value == condition.Value
	case "equals_ci":
		return strings.EqualFold(value, condition.Value)
	case "contains":
		return strings.Contains(value, condition.Value)
	case "contains_ci":
		return strings.Contains(strings.ToLower(value), strings.ToLower(condition.Value))
	case "prefix":
		return strings.HasPrefix(value, condition.Value)
	case "suffix":
		return strings.HasSuffix(value, condition.Value)
	case "regex":
		return regexp.MustCompile(condition.Value).MatchString(value)
	case "regex_ci":
		return regexp.MustCompile("(?i)" + condition.Value).MatchString(value)
	case "in":
		for _, candidate := range condition.In {
			if value == candidate {
				return true
			}
		}
	}
	return false
}

func fieldValues(event domain.TimelineEvent, field string) []string {
	switch field {
	case "id":
		return []string{event.ID}
	case "case_id":
		return []string{event.CaseID}
	case "host_id":
		return []string{event.HostID}
	case "source_type":
		return []string{event.SourceType}
	case "source_path":
		return []string{event.SourcePath}
	case "source_record_id":
		return []string{event.SourceRecordID}
	case "timestamp_source":
		return []string{event.TimestampSource}
	case "category":
		return []string{event.Category}
	case "action":
		return []string{event.Action}
	case "severity":
		return []string{string(event.Severity)}
	case "confidence":
		return []string{string(event.Confidence)}
	case "actor.user":
		return []string{event.Actor.User}
	case "actor.image":
		return []string{event.Actor.Image}
	case "actor.cmdline":
		return []string{event.Actor.Cmdline}
	case "actor.session_id":
		return []string{event.Actor.SessionID}
	case "object.type":
		return []string{event.Object.Type}
	case "object.path":
		return []string{event.Object.Path}
	case "object.name":
		return []string{event.Object.Name}
	case "network.src_ip":
		return []string{event.Network.SrcIP}
	case "network.dst_ip":
		return []string{event.Network.DstIP}
	case "network.dns_name":
		return []string{event.Network.DNSName}
	case "network.url":
		return []string{event.Network.URL}
	case "tags":
		return event.Tags
	case "mitre_techniques":
		return event.MITRETechniques
	default:
		return nil
	}
}

func maxSeverity(a domain.Severity, b domain.Severity) domain.Severity {
	if severityRank(b) > severityRank(a) {
		return b
	}
	return a
}

func maxConfidence(a domain.Confidence, b domain.Confidence) domain.Confidence {
	if confidenceRank(b) > confidenceRank(a) {
		return b
	}
	return a
}

func maxEvidenceStrength(a domain.EvidenceStrength, b domain.EvidenceStrength) domain.EvidenceStrength {
	if evidenceRank(b) > evidenceRank(a) {
		return b
	}
	return a
}

func severityRank(value domain.Severity) int {
	switch value {
	case domain.SeverityCritical:
		return 5
	case domain.SeverityHigh:
		return 4
	case domain.SeverityMedium:
		return 3
	case domain.SeverityLow:
		return 2
	case domain.SeverityInfo:
		return 1
	default:
		return 0
	}
}

func confidenceRank(value domain.Confidence) int {
	switch value {
	case domain.ConfidenceHigh:
		return 3
	case domain.ConfidenceMedium:
		return 2
	case domain.ConfidenceLow:
		return 1
	default:
		return 0
	}
}

func evidenceRank(value domain.EvidenceStrength) int {
	switch value {
	case domain.EvidenceMultiSource:
		return 4
	case domain.EvidenceStrong:
		return 3
	case domain.EvidenceModerate, domain.EvidenceSingleSource:
		return 2
	case domain.EvidenceWeak:
		return 1
	default:
		return 0
	}
}

func mergeStrings(base []string, additions []string) []string {
	seen := make(map[string]struct{}, len(base)+len(additions))
	out := make([]string, 0, len(base)+len(additions))
	for _, value := range append(base, additions...) {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
