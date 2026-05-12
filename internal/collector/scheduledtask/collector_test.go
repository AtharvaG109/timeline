package scheduledtask

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"timeline/internal/domain"
)

func TestParseScheduledTaskXML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Task.xml")
	if err := os.WriteFile(path, []byte(taskXMLFixture), 0o600); err != nil {
		t.Fatalf("write task fixture: %v", err)
	}

	events, ok, err := ParseFile(path, "case-1")
	if err != nil {
		t.Fatalf("parse scheduled task XML: %v", err)
	}
	if !ok || len(events) != 1 {
		t.Fatalf("task parsed ok=%v events=%d", ok, len(events))
	}
	event := events[0]
	if event.Category != "persistence" || event.Action != "created" {
		t.Fatalf("unexpected event category/action: %+v", event)
	}
	if event.TimestampSource != "scheduled_task_xml" {
		t.Fatalf("timestamp source = %q", event.TimestampSource)
	}
	if event.Actor.User != `ACME\alice` {
		t.Fatalf("actor user = %q", event.Actor.User)
	}
	if event.Actor.Image != `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` {
		t.Fatalf("action executable = %q", event.Actor.Image)
	}
	if !strings.Contains(event.Actor.Cmdline, "-ExecutionPolicy Bypass") {
		t.Fatalf("action arguments missing from cmdline: %q", event.Actor.Cmdline)
	}
	if event.Object.Path != `\Microsoft\Windows\Updates\CacheTask` {
		t.Fatalf("task path = %q", event.Object.Path)
	}
	if event.TimestampNS != time.Date(2024, 5, 6, 20, 6, 0, 0, time.UTC).UnixNano() {
		t.Fatalf("timestamp_ns = %d", event.TimestampNS)
	}
	if event.EvidenceStrength != domain.EvidenceSingleSource {
		t.Fatalf("evidence strength = %q", event.EvidenceStrength)
	}
}

func TestTaskActionExtractionFromRecord(t *testing.T) {
	record, ok, err := ParseRecord([]byte(taskXMLFixture), "Task.xml")
	if err != nil {
		t.Fatalf("ParseRecord: %v", err)
	}
	if !ok {
		t.Fatal("expected task record")
	}
	if record.ActionCommand == "" || record.ActionArguments == "" || record.WorkingDir == "" {
		t.Fatalf("action fields were not extracted: %+v", record)
	}
	if len(record.Triggers) != 1 || record.Triggers[0].Type != "LogonTrigger" {
		t.Fatalf("triggers = %+v", record.Triggers)
	}
}

func TestNonTaskXMLIsSkipped(t *testing.T) {
	record, ok, err := ParseRecord([]byte(`<NotATask><Value>ignored</Value></NotATask>`), "other.xml")
	if err != nil {
		t.Fatalf("ParseRecord returned error: %v", err)
	}
	if ok || record.ActionCommand != "" {
		t.Fatalf("non-task XML parsed ok=%v record=%+v", ok, record)
	}
}

func FuzzParseScheduledTaskRecord(f *testing.F) {
	f.Add(taskXMLFixture)
	f.Add(`<NotATask><Value>ignored</Value></NotATask>`)
	f.Add(`<Task>`)
	f.Fuzz(func(t *testing.T, content string) {
		_, _, _ = ParseRecord([]byte(content), "FuzzTask.xml")
	})
}

const taskXMLFixture = `
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2024-05-06T20:06:00Z</Date>
    <Author>ACME\alice</Author>
    <URI>\Microsoft\Windows\Updates\CacheTask</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <StartBoundary>2024-05-06T20:07:00Z</StartBoundary>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>ACME\alice</UserId>
    </Principal>
  </Principals>
  <Actions Context="Author">
    <Exec>
      <Command>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Command>
      <Arguments>-NoProfile -ExecutionPolicy Bypass -File C:\ProgramData\cache.ps1</Arguments>
      <WorkingDirectory>C:\ProgramData</WorkingDirectory>
    </Exec>
  </Actions>
</Task>`
