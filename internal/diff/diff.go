package diff

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"timeline/internal/domain"
	"timeline/internal/store"
)

const (
	TypeNewProcess            = "new_process"
	TypeNewCmdline            = "new_cmdline"
	TypeNewPersistence        = "new_persistence"
	TypeNewRemoteLogon        = "new_remote_logon"
	TypeNewNetworkDestination = "new_network_destination"
	TypeNewDNSQuery           = "new_dns_query"
	TypeNewDownload           = "new_download"
	TypeNewFileWrite          = "new_file_write"
	TypeNewPrivilegeEvent     = "new_privilege_event"
	TypeNewDetection          = "new_detection"
)

type Result struct {
	Findings []Finding
	Summary  Summary
}

type Finding struct {
	DiffType     string
	Fingerprint  string
	Event        domain.TimelineEvent
	Detection    store.Detection
	Severity     domain.Severity
	Confidence   domain.Confidence
	Rationale    string
	SourcePath   string
	SourceEvent  string
	HasDetection bool
}

type Summary struct {
	Total    int
	Critical int
	High     int
	Medium   int
	Low      int
	Info     int
}

var (
	guidPattern       = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
	rfc3339Pattern    = regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}[t ][0-2]\d:[0-5]\d:[0-5]\d(?:\.\d+)?z?\b`)
	longTimePattern   = regexp.MustCompile(`\b\d{10,19}\b`)
	whitespacePattern = regexp.MustCompile(`\s+`)
	nonSpacePattern   = regexp.MustCompile(`\S+`)
	tempRandomPattern = regexp.MustCompile(`(?i)([/\\](?:temp|tmp)[/\\])(?:tmp)?[a-z0-9_-]{8,}(\.[a-z0-9]{1,8})?`)
	userPathPattern   = regexp.MustCompile(`(?i)(c:/users/)[^/\s"']+`)
	domainUserPattern = regexp.MustCompile(`\b[A-Z0-9_.-]{2,}\\[A-Za-z0-9_.-]+\b`)
)

func Compare(baselineEvents []domain.TimelineEvent, incidentEvents []domain.TimelineEvent, baselineDetections []store.Detection, incidentDetections []store.Detection) Result {
	baselineFingerprints := map[string]struct{}{}
	baselineProcessImages := map[string]struct{}{}
	for _, event := range baselineEvents {
		baselineFingerprints[Fingerprint(event)] = struct{}{}
		if event.Category == "process" {
			baselineProcessImages[processImageFingerprint(event)] = struct{}{}
		}
	}

	hasNewExternalConnection := incidentHasNewExternalConnection(baselineEvents, incidentEvents)
	findings := make([]Finding, 0)
	seen := map[string]struct{}{}
	for _, event := range incidentEvents {
		fingerprint := Fingerprint(event)
		if _, ok := baselineFingerprints[fingerprint]; ok {
			continue
		}
		diffType := eventDiffType(event, baselineProcessImages)
		if diffType == "" {
			continue
		}
		key := diffType + "\x00" + fingerprint
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		finding := Finding{
			DiffType:    diffType,
			Fingerprint: fingerprint,
			Event:       event,
			SourcePath:  event.SourcePath,
			SourceEvent: event.ID,
			Confidence:  event.Confidence,
		}
		finding.Severity, finding.Rationale = scoreEventFinding(event, diffType, hasNewExternalConnection)
		findings = append(findings, finding)
	}

	eventByID := map[string]domain.TimelineEvent{}
	for _, event := range incidentEvents {
		eventByID[event.ID] = event
	}
	baselineDetectionFingerprints := detectionFingerprints(baselineDetections, baselineEvents)
	for _, detection := range incidentDetections {
		event := eventByID[detection.EventID]
		fingerprint := DetectionFingerprint(detection, event)
		if _, ok := baselineDetectionFingerprints[fingerprint]; ok {
			continue
		}
		key := TypeNewDetection + "\x00" + fingerprint
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		severity := detection.Severity
		if severity == "" || !severity.Valid() {
			severity = event.Severity
		}
		if severity == "" || !severity.Valid() {
			severity = domain.SeverityMedium
		}
		confidence := detection.Confidence
		if confidence == "" || !confidence.Valid() {
			confidence = domain.ConfidenceMedium
		}
		rationale := "Incident database contains candidate detection " + detection.RuleID + " not present in the baseline."
		if strings.TrimSpace(detection.RuleName) != "" {
			rationale = "Incident database contains candidate detection " + detection.RuleID + " (" + detection.RuleName + ") not present in the baseline."
		}
		findings = append(findings, Finding{
			DiffType:     TypeNewDetection,
			Fingerprint:  fingerprint,
			Event:        event,
			Detection:    detection,
			Severity:     severity,
			Confidence:   confidence,
			Rationale:    rationale,
			SourcePath:   event.SourcePath,
			SourceEvent:  detection.EventID,
			HasDetection: true,
		})
	}

	sort.Slice(findings, func(i, j int) bool {
		left := severityRank(findings[i].Severity)
		right := severityRank(findings[j].Severity)
		if left != right {
			return left > right
		}
		if findings[i].DiffType != findings[j].DiffType {
			return findings[i].DiffType < findings[j].DiffType
		}
		return findings[i].Fingerprint < findings[j].Fingerprint
	})

	return Result{Findings: findings, Summary: summarize(findings)}
}

func ToStoreResults(baselineCaseID string, incidentCaseID string, findings []Finding) []store.DiffResult {
	results := make([]store.DiffResult, 0, len(findings))
	for _, finding := range findings {
		results = append(results, store.DiffResult{
			BaselineCaseID:  baselineCaseID,
			IncidentCaseID:  incidentCaseID,
			DiffType:        finding.DiffType,
			Fingerprint:     finding.Fingerprint,
			IncidentEventID: finding.SourceEvent,
			Severity:        finding.Severity,
			Confidence:      finding.Confidence,
			Rationale:       finding.Rationale,
		})
	}
	return results
}

func Fingerprint(event domain.TimelineEvent) string {
	category := fingerprintCategory(event)
	fields := []string{category, event.Action}
	switch category {
	case "process":
		fields = append(fields, event.Actor.Image, event.Actor.Cmdline, event.Object.Path, event.Object.Hash)
	case "auth":
		fields = append(fields, event.Actor.User, event.Actor.SessionID, event.Network.SrcIP, event.Network.DstIP, strings.Join(event.Tags, " "))
	case "network":
		fields = append(fields, event.Actor.Image, event.Network.DstIP, strconv.Itoa(event.Network.DstPort), event.Network.DNSName, event.Network.URL)
	case "persistence", "scheduled_task":
		fields = append(fields, event.Actor.User, event.Actor.Image, event.Actor.Cmdline, event.Object.Path, event.Object.Name)
	case "browser":
		fields = append(fields, event.Actor.User, event.Network.URL, event.Network.DNSName, event.Object.Path, event.Object.Name)
	case "filesystem":
		fields = append(fields, event.Action, event.Object.Path, event.Object.Name, event.Object.Hash)
	case "registry":
		fields = append(fields, event.Action, event.Object.Path, event.Object.Name)
	default:
		fields = append(fields, event.Category, event.Actor.User, event.Actor.Image, event.Actor.Cmdline, event.Object.Path, event.Network.DstIP, event.Network.DNSName)
	}
	return category + ":" + hashFields(fields...)
}

func DetectionFingerprint(detection store.Detection, event domain.TimelineEvent) string {
	return "detection:" + hashFields(detection.RuleID, Fingerprint(event))
}

func NormalizeValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	value = domainUserPattern.ReplaceAllString(value, "<USER>")
	value = replaceBase64Tokens(value)
	value = guidPattern.ReplaceAllString(value, "<GUID>")
	value = longTimePattern.ReplaceAllString(value, "<TIME>")
	value = strings.ReplaceAll(value, "\\", "/")
	value = strings.ToLower(value)
	value = rfc3339Pattern.ReplaceAllString(value, "<TIME>")
	value = replaceBase64Tokens(value)
	value = userPathPattern.ReplaceAllString(value, "${1}<USER>")
	value = tempRandomPattern.ReplaceAllString(value, "${1}<RANDOM>${2}")
	value = whitespacePattern.ReplaceAllString(value, " ")
	value = strings.ReplaceAll(value, "<user>", "<USER>")
	value = strings.ReplaceAll(value, "<guid>", "<GUID>")
	value = strings.ReplaceAll(value, "<base64>", "<BASE64>")
	value = strings.ReplaceAll(value, "<time>", "<TIME>")
	value = strings.ReplaceAll(value, "<random>", "<RANDOM>")
	return strings.TrimSpace(value)
}

func replaceBase64Tokens(value string) string {
	return nonSpacePattern.ReplaceAllStringFunc(value, func(token string) string {
		trimmed := strings.Trim(token, `"'`)
		if len(trimmed) < 24 || !isBase64Token(trimmed) {
			return token
		}
		return strings.Replace(token, trimmed, "<BASE64>", 1)
	})
}

func isBase64Token(value string) bool {
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '+' || r == '/' || r == '=' {
			continue
		}
		return false
	}
	return true
}

func fingerprintCategory(event domain.TimelineEvent) string {
	category := strings.ToLower(strings.TrimSpace(event.Category))
	action := strings.ToLower(event.Action)
	switch {
	case category == "scheduled_task" || strings.Contains(action, "scheduled_task"):
		return "scheduled_task"
	case category == "process":
		return "process"
	case category == "auth":
		return "auth"
	case category == "network":
		return "network"
	case category == "persistence":
		return "persistence"
	case category == "browser":
		return "browser"
	case category == "filesystem":
		return "filesystem"
	case category == "registry":
		return "registry"
	default:
		return "generic"
	}
}

func eventDiffType(event domain.TimelineEvent, baselineProcessImages map[string]struct{}) string {
	category := fingerprintCategory(event)
	action := strings.ToLower(event.Action)
	switch category {
	case "process":
		if _, ok := baselineProcessImages[processImageFingerprint(event)]; ok && strings.TrimSpace(event.Actor.Cmdline) != "" {
			return TypeNewCmdline
		}
		return TypeNewProcess
	case "auth":
		if isPrivilegeEvent(event) {
			return TypeNewPrivilegeEvent
		}
		if isRemoteLogon(event) {
			return TypeNewRemoteLogon
		}
		return ""
	case "network":
		if strings.TrimSpace(event.Network.DNSName) != "" || strings.Contains(action, "dns") {
			return TypeNewDNSQuery
		}
		return TypeNewNetworkDestination
	case "persistence", "scheduled_task":
		return TypeNewPersistence
	case "browser":
		return TypeNewDownload
	case "filesystem":
		if strings.Contains(action, "write") || strings.Contains(action, "created") || strings.Contains(action, "observed") {
			return TypeNewFileWrite
		}
	case "registry":
		if strings.Contains(action, "set") || strings.Contains(action, "created") || strings.Contains(action, "modified") {
			return TypeNewPersistence
		}
	}
	return ""
}

func scoreEventFinding(event domain.TimelineEvent, diffType string, hasNewExternalConnection bool) (domain.Severity, string) {
	if isPrivilegeEvent(event) {
		return domain.SeverityCritical, "Incident contains a new privileged user or privilege assignment event that requires validation."
	}
	if isServiceInstall(event) && !isAdminLike(event.Actor.User) {
		return domain.SeverityCritical, "Incident contains a new service installation by an account that is not administrator-like in the event metadata."
	}
	if diffType == TypeNewPersistence && suspiciousExecutionPath(event) {
		return domain.SeverityCritical, "Incident contains new persistence associated with a suspicious execution path."
	}
	processLike := diffType == TypeNewProcess || diffType == TypeNewCmdline
	if processLike && encodedPowerShell(event) && hasNewExternalConnection {
		return domain.SeverityCritical, "Incident contains encoded PowerShell and a new external network destination."
	}
	if diffType == TypeNewRemoteLogon {
		return domain.SeverityHigh, "Incident contains a new remote logon pattern absent from the baseline."
	}
	if processLike && encodedPowerShell(event) {
		return domain.SeverityHigh, "Incident contains a new encoded PowerShell command line candidate."
	}
	if processLike && isLOLBin(event) {
		return domain.SeverityHigh, "Incident contains a new LOLBin execution candidate."
	}
	if processLike && executableFromSuspiciousDirectory(event) {
		return domain.SeverityHigh, "Incident contains a new executable from Temp, Public, or Downloads."
	}
	if isScheduledTask(event) {
		return domain.SeverityHigh, "Incident contains a new scheduled task event."
	}
	if diffType == TypeNewDownload {
		return domain.SeverityMedium, "Incident contains a new browser download candidate."
	}
	if diffType == TypeNewNetworkDestination {
		return domain.SeverityMedium, "Incident contains a new outbound destination."
	}
	if diffType == TypeNewFileWrite && suspiciousExecutionPath(event) {
		return domain.SeverityMedium, "Incident contains a new file write in a suspicious directory."
	}
	if diffType == TypeNewProcess {
		return domain.SeverityLow, "Incident contains a new process path without stronger suspicious context."
	}
	if diffType == TypeNewRemoteLogon || diffType == TypeNewPrivilegeEvent {
		return domain.SeverityLow, "Incident contains new user activity without stronger suspicious correlation."
	}
	return domain.SeverityMedium, "Incident contains a new normalized event absent from the baseline."
}

func detectionFingerprints(detections []store.Detection, events []domain.TimelineEvent) map[string]struct{} {
	eventByID := map[string]domain.TimelineEvent{}
	for _, event := range events {
		eventByID[event.ID] = event
	}
	out := map[string]struct{}{}
	for _, detection := range detections {
		out[DetectionFingerprint(detection, eventByID[detection.EventID])] = struct{}{}
	}
	return out
}

func incidentHasNewExternalConnection(baselineEvents []domain.TimelineEvent, incidentEvents []domain.TimelineEvent) bool {
	baseline := map[string]struct{}{}
	for _, event := range baselineEvents {
		if fingerprintCategory(event) == "network" {
			baseline[Fingerprint(event)] = struct{}{}
		}
	}
	for _, event := range incidentEvents {
		if fingerprintCategory(event) != "network" || !isExternalIP(event.Network.DstIP) {
			continue
		}
		if _, ok := baseline[Fingerprint(event)]; !ok {
			return true
		}
	}
	return false
}

func processImageFingerprint(event domain.TimelineEvent) string {
	image := event.Actor.Image
	if strings.TrimSpace(image) == "" {
		image = event.Object.Path
	}
	return NormalizeValue(filepath.Base(strings.ReplaceAll(image, "\\", "/")))
}

func hashFields(fields ...string) string {
	normalized := make([]string, 0, len(fields))
	for _, field := range fields {
		normalized = append(normalized, NormalizeValue(field))
	}
	sum := sha256.Sum256([]byte(strings.Join(normalized, "\x00")))
	return hex.EncodeToString(sum[:])
}

func summarize(findings []Finding) Summary {
	summary := Summary{Total: len(findings)}
	for _, finding := range findings {
		switch finding.Severity {
		case domain.SeverityCritical:
			summary.Critical++
		case domain.SeverityHigh:
			summary.High++
		case domain.SeverityMedium:
			summary.Medium++
		case domain.SeverityLow:
			summary.Low++
		default:
			summary.Info++
		}
	}
	return summary
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

func isRemoteLogon(event domain.TimelineEvent) bool {
	action := strings.ToLower(event.Action)
	if strings.Contains(action, "remote_logon") {
		return true
	}
	if action == "successful_logon" && strings.TrimSpace(event.Network.SrcIP) != "" {
		return true
	}
	return containsFold(event.Tags, "remote_logon") || containsFold(event.Tags, "remote")
}

func isPrivilegeEvent(event domain.TimelineEvent) bool {
	action := strings.ToLower(event.Action)
	return strings.Contains(action, "privilege") ||
		strings.Contains(action, "privileged_group") ||
		strings.Contains(action, "group_membership") ||
		strings.Contains(action, "user_account_created")
}

func isServiceInstall(event domain.TimelineEvent) bool {
	action := strings.ToLower(event.Action)
	return strings.Contains(action, "service_installed") || strings.Contains(action, "service install")
}

func isScheduledTask(event domain.TimelineEvent) bool {
	return strings.Contains(strings.ToLower(event.Action), "scheduled_task") || strings.EqualFold(event.Category, "scheduled_task")
}

func isAdminLike(user string) bool {
	user = strings.ToLower(strings.TrimSpace(user))
	return user == "" || strings.Contains(user, "administrator") || strings.Contains(user, "admin") || strings.HasSuffix(user, "\\system") || user == "system" || strings.Contains(user, "local service")
}

func encodedPowerShell(event domain.TimelineEvent) bool {
	text := strings.ToLower(event.Actor.Image + " " + event.Actor.Cmdline + " " + event.Object.Path)
	return strings.Contains(text, "powershell") && (strings.Contains(text, "-encodedcommand") || strings.Contains(text, "-enc ") || containsFold(event.Tags, "encoded-command"))
}

func isLOLBin(event domain.TimelineEvent) bool {
	name := strings.ToLower(filepath.Base(strings.ReplaceAll(firstNonEmpty(event.Actor.Image, event.Object.Path, event.Object.Name), "\\", "/")))
	switch name {
	case "certutil.exe", "certutil", "rundll32.exe", "rundll32", "regsvr32.exe", "regsvr32", "mshta.exe", "mshta", "wmic.exe", "wmic", "powershell.exe", "powershell":
		return true
	default:
		return false
	}
}

func executableFromSuspiciousDirectory(event domain.TimelineEvent) bool {
	path := strings.ToLower(strings.ReplaceAll(firstNonEmpty(event.Object.Path, event.Actor.Image), "\\", "/"))
	if !(strings.HasSuffix(path, ".exe") || strings.Contains(path, ".exe ")) {
		return false
	}
	return strings.Contains(path, "/temp/") || strings.Contains(path, "/tmp/") || strings.Contains(path, "/public/") || strings.Contains(path, "/downloads/")
}

func suspiciousExecutionPath(event domain.TimelineEvent) bool {
	path := strings.ToLower(strings.ReplaceAll(firstNonEmpty(event.Object.Path, event.Actor.Image), "\\", "/"))
	return strings.Contains(path, "/temp/") || strings.Contains(path, "/tmp/") || strings.Contains(path, "/public/") || strings.Contains(path, "/downloads/") || strings.Contains(path, "/appdata/")
}

func isExternalIP(ip string) bool {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return false
	}
	return !parsed.IsPrivate() && !parsed.IsLoopback() && !parsed.IsLinkLocalUnicast() && !parsed.IsLinkLocalMulticast() && !parsed.IsUnspecified()
}

func containsFold(values []string, target string) bool {
	for _, value := range values {
		if strings.EqualFold(value, target) {
			return true
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func ValidateDiffType(diffType string) error {
	switch diffType {
	case TypeNewProcess, TypeNewCmdline, TypeNewPersistence, TypeNewRemoteLogon, TypeNewNetworkDestination, TypeNewDNSQuery, TypeNewDownload, TypeNewFileWrite, TypeNewPrivilegeEvent, TypeNewDetection:
		return nil
	default:
		return fmt.Errorf("unsupported diff type %q", diffType)
	}
}
