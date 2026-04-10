package api

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

type fakeAuditQueueSink struct {
	mu     sync.Mutex
	events []auditBackupEvent
}

func (f *fakeAuditQueueSink) PublishBatch(_ context.Context, events []auditBackupEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, events...)
	return nil
}

func (f *fakeAuditQueueSink) Close() error {
	return nil
}

func (f *fakeAuditQueueSink) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.events)
}

func (f *fakeAuditQueueSink) snapshot() []auditBackupEvent {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]auditBackupEvent, len(f.events))
	copy(out, f.events)
	return out
}

func TestAuditQueueForwarderPersistsOffsetsAcrossRestarts(t *testing.T) {
	dir := t.TempDir()
	auditDir := filepath.Join(dir, "audit")
	if err := os.MkdirAll(auditDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(auditDir) error = %v", err)
	}
	auditPath := filepath.Join(auditDir, "audit-2024.jsonl")
	if err := os.WriteFile(auditPath, []byte(
		`{"id":"ev1","timestamp":"2024-01-15T10:00:00Z","event_type":"login","username":"alice","source_ip":"10.0.0.1"}`+"\n"+
			`{"id":"ev2","timestamp":"2024-01-15T11:00:00Z","event_type":"session_start","username":"bob","source_ip":"10.0.0.2"}`+"\n",
	), 0o600); err != nil {
		t.Fatalf("WriteFile(audit) error = %v", err)
	}

	cfg := &Config{
		DataDir:            dir,
		AuditQueueBackend:  "kafka",
		AuditQueueEndpoint: "kafka-1.example.com:9092,kafka-2.example.com:9092",
		AuditQueueTopic:    "ssh-proxy-audit",
	}

	sink1 := &fakeAuditQueueSink{}
	forwarder1, err := newAuditQueueForwarderWithFactory(cfg, func(*Config) (auditQueueSink, error) {
		return sink1, nil
	})
	if err != nil {
		t.Fatalf("newAuditQueueForwarderWithFactory() error = %v", err)
	}
	if err := forwarder1.SyncDir(auditDir); err != nil {
		t.Fatalf("forwarder1.SyncDir() error = %v", err)
	}
	if got := sink1.count(); got != 2 {
		t.Fatalf("sink1.count() = %d, want 2", got)
	}

	sink2 := &fakeAuditQueueSink{}
	forwarder2, err := newAuditQueueForwarderWithFactory(cfg, func(*Config) (auditQueueSink, error) {
		return sink2, nil
	})
	if err != nil {
		t.Fatalf("newAuditQueueForwarderWithFactory(restart) error = %v", err)
	}
	if err := forwarder2.SyncDir(auditDir); err != nil {
		t.Fatalf("forwarder2.SyncDir() error = %v", err)
	}
	if got := sink2.count(); got != 0 {
		t.Fatalf("sink2.count() after restart = %d, want 0 duplicate events", got)
	}

	file, err := os.OpenFile(auditPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("OpenFile(audit append) error = %v", err)
	}
	if _, err := file.WriteString(`{"id":"ev3","timestamp":"2024-01-15T12:00:00Z","event_type":"config_change","username":"admin","source_ip":"10.0.0.3"}` + "\n"); err != nil {
		_ = file.Close()
		t.Fatalf("WriteString(audit append) error = %v", err)
	}
	_ = file.Close()

	if err := forwarder2.SyncDir(auditDir); err != nil {
		t.Fatalf("forwarder2.SyncDir(append) error = %v", err)
	}
	if got := sink2.count(); got != 1 {
		t.Fatalf("sink2.count() after append = %d, want 1 new event", got)
	}
	if sink2.snapshot()[0].Event.ID != "ev3" {
		t.Fatalf("forwarded event id = %q, want ev3", sink2.snapshot()[0].Event.ID)
	}
}

func TestAuditQueueForwarderNormalizesLegacyLogForRabbitMQ(t *testing.T) {
	dir := t.TempDir()
	auditDir := filepath.Join(dir, "audit")
	if err := os.MkdirAll(auditDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(auditDir) error = %v", err)
	}
	legacyPath := filepath.Join(auditDir, "audit_20240115.log")
	if err := os.WriteFile(legacyPath, []byte(`{"timestamp":"2024-01-15T13:00:00Z","type":"AUTH_SUCCESS","session":42,"user":"carol","client":"10.0.0.3","target":"srv3"}`+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(legacy) error = %v", err)
	}

	cfg := &Config{
		DataDir:              dir,
		AuditQueueBackend:    "rabbitmq",
		AuditQueueEndpoint:   "amqp://guest:guest@mq.example.com:5672/%2f",
		AuditQueueExchange:   "audit.events",
		AuditQueueRoutingKey: "ssh-proxy.audit",
	}

	sink := &fakeAuditQueueSink{}
	forwarder, err := newAuditQueueForwarderWithFactory(cfg, func(*Config) (auditQueueSink, error) {
		return sink, nil
	})
	if err != nil {
		t.Fatalf("newAuditQueueForwarderWithFactory() error = %v", err)
	}
	if err := forwarder.SyncDir(auditDir); err != nil {
		t.Fatalf("forwarder.SyncDir() error = %v", err)
	}
	if got := sink.count(); got != 1 {
		t.Fatalf("sink.count() = %d, want 1", got)
	}
	event := sink.snapshot()[0]
	if event.Event.EventType != "auth_success" {
		t.Fatalf("forwarded event type = %q, want auth_success", event.Event.EventType)
	}
	if event.Event.SessionID != "42" {
		t.Fatalf("forwarded session id = %q, want 42", event.Event.SessionID)
	}
	if event.RawEvent == "" || event.SourceFile != legacyPath {
		t.Fatalf("forwarded envelope missing raw/source metadata: %+v", event)
	}
}
