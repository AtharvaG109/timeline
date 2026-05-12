package evtx

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizeSupportedSecurityRecord(t *testing.T) {
	records, err := parseXMLRecords([]byte(successfulLogonXML))
	if err != nil {
		t.Fatalf("parseXMLRecords error: %v", err)
	}
	event, ok, err := NormalizeRecord("Security.evtx", "case-1", records[0])
	if err != nil {
		t.Fatalf("NormalizeRecord error: %v", err)
	}
	if !ok {
		t.Fatal("supported event was skipped")
	}
	if event.Category != "auth" || event.Action != "successful_logon" {
		t.Fatalf("unexpected event mapping: %s/%s", event.Category, event.Action)
	}
	if event.Actor.User != "alice" {
		t.Fatalf("actor user = %q", event.Actor.User)
	}
	if event.Network.SrcIP != "203.0.113.24" {
		t.Fatalf("source ip = %q", event.Network.SrcIP)
	}
	if event.SourceRecordID != "101" {
		t.Fatalf("record id = %q", event.SourceRecordID)
	}
	if event.RawRef.URI != "Security.evtx" {
		t.Fatalf("raw ref uri = %q", event.RawRef.URI)
	}
}

func TestUnsupportedEventIDIsSkipped(t *testing.T) {
	records, err := parseXMLRecords([]byte(unsupportedXML))
	if err != nil {
		t.Fatalf("parseXMLRecords error: %v", err)
	}
	_, ok, err := NormalizeRecord("Security.evtx", "case-1", records[0])
	if err != nil {
		t.Fatalf("NormalizeRecord error: %v", err)
	}
	if ok {
		t.Fatal("unsupported event was emitted")
	}
}

func TestRequiredEventIDsAreSupported(t *testing.T) {
	for _, eventID := range []int{4624, 4625, 4634, 4648, 4672, 4688, 4697, 4698, 4702, 4720, 4728, 4732, 7045} {
		if _, ok := windowsMetadata(eventID); !ok {
			t.Fatalf("Windows event %d is not supported", eventID)
		}
	}
	for _, eventID := range []int{1, 3, 7, 10, 11, 12, 13, 22} {
		if _, ok := sysmonMetadata(eventID); !ok {
			t.Fatalf("Sysmon event %d is not supported", eventID)
		}
	}
	for _, eventID := range []int{400, 403, 4103, 4104} {
		if _, ok := powershellMetadata(eventID); !ok {
			t.Fatalf("PowerShell event %d is not supported", eventID)
		}
	}
}

func TestMalformedXMLReturnsClearError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Security.evtx")
	if err := os.WriteFile(path, []byte("<Events><Event>"), 0o600); err != nil {
		t.Fatalf("write malformed fixture: %v", err)
	}
	_, stats, err := ParseFile(path, "case-1")
	if err == nil {
		t.Fatal("expected malformed XML error")
	}
	if stats.ParseErrors == 0 {
		t.Fatalf("parse errors not counted: %+v", stats)
	}
}

func TestParseFileCountsSkippedUnsupportedEvents(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Security.evtx")
	content := "<Events>" + successfulLogonXML + unsupportedXML + "</Events>"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	events, stats, err := ParseFile(path, "case-1")
	if err != nil {
		t.Fatalf("ParseFile error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %d", len(events))
	}
	if stats.EventsEmitted != 1 || stats.EventsSkipped != 1 || stats.FilesParsed != 1 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
}

func FuzzParseXMLRecords(f *testing.F) {
	f.Add([]byte("<Events>" + successfulLogonXML + "</Events>"))
	f.Add([]byte("<Events><Event></Event></Events>"))
	f.Add([]byte("<Events><Event>"))
	f.Fuzz(func(t *testing.T, content []byte) {
		_, _ = parseXMLRecords(content)
	})
}

const successfulLogonXML = `
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4624</EventID>
    <TimeCreated SystemTime="2024-05-06T20:01:44.123456789Z"/>
    <Computer>WIN-WS01</Computer>
    <EventRecordID>101</EventRecordID>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="TargetUserName">alice</Data>
    <Data Name="IpAddress">203.0.113.24</Data>
    <Data Name="IpPort">49152</Data>
    <Data Name="TargetLogonId">0x3e7</Data>
  </EventData>
</Event>`

const unsupportedXML = `
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>9999</EventID>
    <TimeCreated SystemTime="2024-05-06T20:02:44Z"/>
    <Computer>WIN-WS01</Computer>
    <EventRecordID>102</EventRecordID>
    <Channel>Security</Channel>
  </System>
</Event>`
