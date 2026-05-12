package export

import (
	"encoding/json"
	"fmt"
	"io"

	"timeline/internal/domain"
)

type Event struct {
	SchemaVersion      string                    `json:"schema_version"`
	ToolVersion        string                    `json:"tool_version"`
	ParserName         string                    `json:"parser_name"`
	ParserVersion      string                    `json:"parser_version"`
	ID                 string                    `json:"id"`
	CaseID             string                    `json:"case_id"`
	HostID             string                    `json:"host_id,omitempty"`
	SourceType         string                    `json:"source_type"`
	SourcePath         string                    `json:"source_path"`
	SourceRecordID     string                    `json:"source_record_id,omitempty"`
	RawRef             domain.RawRef             `json:"raw_ref"`
	TimestampNS        int64                     `json:"timestamp_ns"`
	TimestampPrecision domain.TimestampPrecision `json:"timestamp_precision"`
	TimestampSource    string                    `json:"timestamp_source"`
	Category           string                    `json:"category"`
	Action             string                    `json:"action"`
	Severity           domain.Severity           `json:"severity"`
	Confidence         domain.Confidence         `json:"confidence"`
	EvidenceStrength   domain.EvidenceStrength   `json:"evidence_strength"`
	Actor              domain.Actor              `json:"actor"`
	Object             domain.Object             `json:"object"`
	Network            domain.Network            `json:"network"`
	Tags               []string                  `json:"tags"`
	MITRETechniques    []string                  `json:"mitre_techniques"`
}

func FromDomain(event domain.TimelineEvent) Event {
	tags := event.Tags
	if tags == nil {
		tags = []string{}
	}
	mitreTechniques := event.MITRETechniques
	if mitreTechniques == nil {
		mitreTechniques = []string{}
	}
	return Event{
		SchemaVersion:      event.SchemaVersion,
		ToolVersion:        event.ToolVersion,
		ParserName:         event.ParserName,
		ParserVersion:      event.ParserVersion,
		ID:                 event.ID,
		CaseID:             event.CaseID,
		HostID:             event.HostID,
		SourceType:         event.SourceType,
		SourcePath:         event.SourcePath,
		SourceRecordID:     event.SourceRecordID,
		RawRef:             event.RawRef,
		TimestampNS:        event.TimestampNS,
		TimestampPrecision: event.TimestampPrecision,
		TimestampSource:    event.TimestampSource,
		Category:           event.Category,
		Action:             event.Action,
		Severity:           event.Severity,
		Confidence:         event.Confidence,
		EvidenceStrength:   event.EvidenceStrength,
		Actor:              event.Actor,
		Object:             event.Object,
		Network:            event.Network,
		Tags:               tags,
		MITRETechniques:    mitreTechniques,
	}
}

func FromDomainSlice(events []domain.TimelineEvent) []Event {
	out := make([]Event, 0, len(events))
	for _, event := range events {
		out = append(out, FromDomain(event))
	}
	return out
}

func WriteJSON(w io.Writer, events []domain.TimelineEvent) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(FromDomainSlice(events)); err != nil {
		return fmt.Errorf("write JSON events: %w", err)
	}
	return nil
}

func WriteJSONL(w io.Writer, events []domain.TimelineEvent) error {
	encoder := json.NewEncoder(w)
	for _, event := range events {
		if err := encoder.Encode(FromDomain(event)); err != nil {
			return fmt.Errorf("write JSONL event %s: %w", event.ID, err)
		}
	}
	return nil
}
