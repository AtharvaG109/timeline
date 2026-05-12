package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

func (s Severity) Valid() bool {
	switch s {
	case SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	default:
		return false
	}
}

type Confidence string

const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

func (c Confidence) Valid() bool {
	switch c {
	case ConfidenceLow, ConfidenceMedium, ConfidenceHigh:
		return true
	default:
		return false
	}
}

type EvidenceStrength string

const (
	EvidenceWeak         EvidenceStrength = "weak"
	EvidenceModerate     EvidenceStrength = "moderate"
	EvidenceStrong       EvidenceStrength = "strong"
	EvidenceSingleSource EvidenceStrength = "single_source"
	EvidenceMultiSource  EvidenceStrength = "multi_source"
)

func (e EvidenceStrength) Valid() bool {
	switch e {
	case EvidenceWeak, EvidenceModerate, EvidenceStrong, EvidenceSingleSource, EvidenceMultiSource:
		return true
	default:
		return false
	}
}

type TimestampPrecision string

const (
	TimestampPrecisionUnknown     TimestampPrecision = "unknown"
	TimestampPrecisionSecond      TimestampPrecision = "second"
	TimestampPrecisionMillisecond TimestampPrecision = "millisecond"
	TimestampPrecisionMicrosecond TimestampPrecision = "microsecond"
	TimestampPrecisionNanosecond  TimestampPrecision = "nanosecond"
)

func (p TimestampPrecision) Valid() bool {
	switch p {
	case TimestampPrecisionUnknown, TimestampPrecisionSecond, TimestampPrecisionMillisecond, TimestampPrecisionMicrosecond, TimestampPrecisionNanosecond:
		return true
	default:
		return false
	}
}

type RawRef struct {
	Type   string `json:"type"`
	URI    string `json:"uri"`
	Offset int64  `json:"offset"`
	Length int64  `json:"length"`
}

type Actor struct {
	User      string `json:"user"`
	Image     string `json:"image"`
	Cmdline   string `json:"cmdline"`
	PID       int    `json:"pid"`
	ParentPID int    `json:"parent_pid"`
	SessionID string `json:"session_id"`
}

type Object struct {
	Type string `json:"type"`
	Path string `json:"path"`
	Name string `json:"name"`
	Hash string `json:"hash"`
}

type Network struct {
	SrcIP   string `json:"src_ip"`
	SrcPort int    `json:"src_port"`
	DstIP   string `json:"dst_ip"`
	DstPort int    `json:"dst_port"`
	DNSName string `json:"dns_name"`
	URL     string `json:"url"`
}

type TimelineEvent struct {
	SchemaVersion      string
	ToolVersion        string
	ParserName         string
	ParserVersion      string
	ID                 string
	CaseID             string
	HostID             string
	SourceType         string
	SourcePath         string
	SourceRecordID     string
	RawRef             RawRef
	TimestampNS        int64
	TimestampPrecision TimestampPrecision
	TimestampSource    string
	Category           string
	Action             string
	Severity           Severity
	Confidence         Confidence
	EvidenceStrength   EvidenceStrength
	Actor              Actor
	Object             Object
	Network            Network
	Tags               []string
	MITRETechniques    []string
}

func (e TimelineEvent) ValidateEnums() error {
	if !e.TimestampPrecision.Valid() {
		return fmt.Errorf("invalid timestamp precision %q", e.TimestampPrecision)
	}
	if !e.Severity.Valid() {
		return fmt.Errorf("invalid severity %q", e.Severity)
	}
	if !e.Confidence.Valid() {
		return fmt.Errorf("invalid confidence %q", e.Confidence)
	}
	if !e.EvidenceStrength.Valid() {
		return fmt.Errorf("invalid evidence strength %q", e.EvidenceStrength)
	}
	return nil
}

func GenerateEventID(e TimelineEvent) string {
	fields := []string{
		e.SchemaVersion,
		e.SourceType,
		e.SourcePath,
		e.SourceRecordID,
		strconv.FormatInt(e.TimestampNS, 10),
		e.Category,
		e.Action,
		e.Actor.Image,
		e.Actor.Cmdline,
		e.Object.Path,
		e.Network.DstIP,
		strconv.Itoa(e.Network.DstPort),
	}
	sum := sha256.Sum256([]byte(strings.Join(fields, "\x00")))
	return hex.EncodeToString(sum[:])
}
