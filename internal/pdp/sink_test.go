package pdp

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	sshproxyv1 "github.com/ssh-proxy-core/ssh-proxy-core/api/proto/sshproxy/v1"
)

func readSinkLines(t *testing.T, dir string) []map[string]interface{} {
	t.Helper()
	entries, err := filepath.Glob(filepath.Join(dir, "audit-*.jsonl"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	var records []map[string]interface{}
	for _, path := range entries {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			var record map[string]interface{}
			if err := json.Unmarshal([]byte(line), &record); err != nil {
				t.Fatalf("the sink wrote a line that is not valid JSON: %q", line)
			}
			records = append(records, record)
		}
	}
	return records
}

func TestFileEventSinkWritesReadableRecords(t *testing.T) {
	dir := t.TempDir()
	sink, err := NewFileEventSink(dir, true)
	if err != nil {
		t.Fatalf("NewFileEventSink: %v", err)
	}
	defer func() { _ = sink.Close() }()

	now := time.Now().UTC()
	err = sink.Publish(context.Background(), []*sshproxyv1.AuditEvent{
		{
			Id: "e1", Timestamp: timestamppb.New(now), EventType: "session.start",
			Username: "alice", SourceIp: "10.0.0.5", TargetHost: "web-1", TargetPort: 22,
			SessionId: "s1", UpstreamLogin: "deploy", NodeId: "node-a",
			Decision: "allow", RuleId: "rule-1", IntegrityHash: "h1",
		},
		{
			Id: "e2", Timestamp: timestamppb.New(now), EventType: "command",
			Username: "alice", SessionId: "s1", Command: "rm -rf /",
			Decision: "deny", IntegrityHash: "h2", PrevHash: "h1",
		},
	})
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}

	records := readSinkLines(t, dir)
	if len(records) != 2 {
		t.Fatalf("wrote %d records, want 2", len(records))
	}

	// The fields the existing audit query layer reads must be present, or the
	// events would arrive and then be invisible in the UI.
	for _, key := range []string{"id", "timestamp", "event_type", "username", "source_ip"} {
		if _, ok := records[0][key]; !ok {
			t.Errorf("record is missing %q, which the audit reader expects", key)
		}
	}
	if records[0]["session_id"] != "s1" || records[0]["target_host"] != "web-1" {
		t.Errorf("record = %+v", records[0])
	}
	if records[0]["upstream_login"] != "deploy" || records[0]["node_id"] != "node-a" {
		t.Errorf("structured fields were dropped: %+v", records[0])
	}

	// A command event should read as a sentence as well as carry structure.
	details, _ := records[1]["details"].(string)
	if !strings.Contains(details, "rm -rf /") {
		t.Errorf("details = %q, want it to describe the command", details)
	}
	if records[1]["command"] != "rm -rf /" || records[1]["decision"] != "deny" {
		t.Errorf("command record = %+v", records[1])
	}
	if records[1]["prev_hash"] != "h1" {
		t.Error("the integrity chain was not carried through to storage")
	}
}

func TestFileEventSinkRendersTypedRecords(t *testing.T) {
	dir := t.TempDir()
	sink, err := NewFileEventSink(dir, false)
	if err != nil {
		t.Fatalf("NewFileEventSink: %v", err)
	}
	defer func() { _ = sink.Close() }()

	err = sink.Publish(context.Background(), []*sshproxyv1.AuditEvent{
		{
			Id: "t1", EventType: "file.transfer", Username: "alice", Decision: "allow",
			FileTransfer: &sshproxyv1.FileTransferRecord{
				Direction: "upload", Path: "/srv/app/x.tar", Filename: "x.tar",
				Size: 1024, Protocol: "sftp", Allowed: true,
			},
		},
		{
			Id: "p1", EventType: "port.forward", Username: "alice", Decision: "deny",
			PortForward: &sshproxyv1.PortForwardRecord{
				Kind: "local", DestHost: "10.0.0.9", DestPort: 5432,
			},
		},
	})
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}

	records := readSinkLines(t, dir)
	if len(records) != 2 {
		t.Fatalf("wrote %d records, want 2", len(records))
	}

	transfer, ok := records[0]["file_transfer"].(map[string]interface{})
	if !ok {
		t.Fatalf("the transfer record was not preserved: %+v", records[0])
	}
	if transfer["path"] != "/srv/app/x.tar" || transfer["direction"] != "upload" {
		t.Errorf("transfer = %+v", transfer)
	}
	if details, _ := records[0]["details"].(string); !strings.Contains(details, "/srv/app/x.tar") {
		t.Errorf("details = %q, want a readable summary", details)
	}

	forward, ok := records[1]["port_forward"].(map[string]interface{})
	if !ok {
		t.Fatalf("the forward record was not preserved: %+v", records[1])
	}
	if forward["dest_host"] != "10.0.0.9" {
		t.Errorf("forward = %+v", forward)
	}
}

func TestFileEventSinkAppendsAcrossCalls(t *testing.T) {
	dir := t.TempDir()
	sink, err := NewFileEventSink(dir, false)
	if err != nil {
		t.Fatalf("NewFileEventSink: %v", err)
	}
	defer func() { _ = sink.Close() }()

	for i := 0; i < 3; i++ {
		if err := sink.Publish(context.Background(), []*sshproxyv1.AuditEvent{
			{Id: "e", EventType: "session.start", Username: "alice"},
		}); err != nil {
			t.Fatalf("Publish: %v", err)
		}
	}
	if got := len(readSinkLines(t, dir)); got != 3 {
		t.Fatalf("wrote %d records; later batches overwrote earlier ones", got)
	}
}

func TestFileEventSinkIgnoresEmptyBatches(t *testing.T) {
	dir := t.TempDir()
	sink, err := NewFileEventSink(dir, false)
	if err != nil {
		t.Fatalf("NewFileEventSink: %v", err)
	}
	defer func() { _ = sink.Close() }()

	if err := sink.Publish(context.Background(), nil); err != nil {
		t.Fatalf("Publish(nil): %v", err)
	}
	if entries, _ := filepath.Glob(filepath.Join(dir, "*.jsonl")); len(entries) != 0 {
		t.Fatal("an empty batch created a file")
	}
}

func TestNewFileEventSinkRequiresADirectory(t *testing.T) {
	if _, err := NewFileEventSink("", false); err == nil {
		t.Fatal("a sink without a directory should be refused")
	}
}

func TestSinkFilePermissions(t *testing.T) {
	dir := t.TempDir()
	sink, err := NewFileEventSink(dir, false)
	if err != nil {
		t.Fatalf("NewFileEventSink: %v", err)
	}
	defer func() { _ = sink.Close() }()

	if err := sink.Publish(context.Background(), []*sshproxyv1.AuditEvent{
		{Id: "e", EventType: "session.start", Username: "alice", Command: "cat /etc/shadow"},
	}); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	entries, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if len(entries) != 1 {
		t.Fatalf("expected one file, got %d", len(entries))
	}
	info, err := os.Stat(entries[0])
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("audit log permissions are %o; these records name users, hosts, and commands", perm)
	}
}
