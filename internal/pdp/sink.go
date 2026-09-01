package pdp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	sshproxyv1 "github.com/ssh-proxy-core/ssh-proxy-core/api/proto/sshproxy/v1"
)

// FileEventSink appends reported events to the audit log directory.
//
// Writing to files rather than straight to a database keeps one property that
// matters: the control plane accepting an event is a durable act, independent
// of whether Postgres, ClickHouse, or an object store happens to be reachable.
// The existing sync loops pick the files up and fan them out to whichever
// backends are configured, and each of those tracks its own progress, so one
// slow destination cannot hold up the others.
type FileEventSink struct {
	dir string

	mu       sync.Mutex
	file     *os.File
	fileDate string
	// sync forces each batch to durable storage before it is acknowledged. The
	// data plane keeps events spooled until acknowledged, so without this an
	// acknowledgement can outrun the write and a crash loses the difference.
	sync bool
}

// NewFileEventSink writes events into dir as newline-delimited JSON.
func NewFileEventSink(dir string, syncWrites bool) (*FileEventSink, error) {
	if dir == "" {
		return nil, fmt.Errorf("pdp: an audit log directory is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("pdp: create audit directory: %w", err)
	}
	return &FileEventSink{dir: dir, sync: syncWrites}, nil
}

// Publish appends a batch.
func (s *FileEventSink) Publish(_ context.Context, events []*sshproxyv1.AuditEvent) error {
	if len(events) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	file, err := s.currentFileLocked()
	if err != nil {
		return err
	}
	for _, event := range events {
		line, err := json.Marshal(auditEventJSON(event))
		if err != nil {
			// One malformed event must not reject the batch it travelled in,
			// which would make the sender retry the whole batch forever.
			continue
		}
		if _, err := file.Write(append(line, '\n')); err != nil {
			return fmt.Errorf("pdp: write audit event: %w", err)
		}
	}
	if s.sync {
		if err := file.Sync(); err != nil {
			return fmt.Errorf("pdp: sync audit log: %w", err)
		}
	}
	return nil
}

// currentFileLocked returns today's file, rolling over at midnight UTC so the
// retention and archival tooling has a natural unit to work with.
func (s *FileEventSink) currentFileLocked() (*os.File, error) {
	date := time.Now().UTC().Format("20060102")
	if s.file != nil && s.fileDate == date {
		return s.file, nil
	}
	if s.file != nil {
		_ = s.file.Close()
		s.file = nil
	}
	path := filepath.Join(s.dir, "audit-"+date+".jsonl")
	// 0600: these records name users, hosts, and commands.
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("pdp: open audit log: %w", err)
	}
	s.file = file
	s.fileDate = date
	return file, nil
}

// Close releases the current file.
func (s *FileEventSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil {
		return nil
	}
	err := s.file.Sync()
	if closeErr := s.file.Close(); err == nil {
		err = closeErr
	}
	s.file = nil
	return err
}

// auditEventJSON renders an event in the shape the audit query layer reads.
//
// The typed sub-records are flattened into the details field so that an
// existing reader keeps working, while the structured form is preserved
// alongside for anything that understands it.
func auditEventJSON(event *sshproxyv1.AuditEvent) map[string]interface{} {
	out := map[string]interface{}{
		"id":         event.GetId(),
		"event_type": event.GetEventType(),
		"username":   event.GetUsername(),
		"source_ip":  event.GetSourceIp(),
	}
	if ts := event.GetTimestamp(); ts != nil {
		out["timestamp"] = ts.AsTime().UTC().Format(time.RFC3339Nano)
	} else {
		out["timestamp"] = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if host := event.GetTargetHost(); host != "" {
		out["target_host"] = host
	}
	if sessionID := event.GetSessionId(); sessionID != "" {
		out["session_id"] = sessionID
	}
	if details := describeEvent(event); details != "" {
		out["details"] = details
	}

	// Structured fields, for readers that want more than a sentence.
	optional := map[string]interface{}{
		"node_id":        event.GetNodeId(),
		"upstream_login": event.GetUpstreamLogin(),
		"channel_type":   event.GetChannelType(),
		"decision":       event.GetDecision(),
		"rule_id":        event.GetRuleId(),
		"command":        event.GetCommand(),
		"integrity_hash": event.GetIntegrityHash(),
		"prev_hash":      event.GetPrevHash(),
	}
	for key, value := range optional {
		if text, ok := value.(string); ok && text != "" {
			out[key] = text
		}
	}
	if port := event.GetTargetPort(); port != 0 {
		out["target_port"] = port
	}
	if event.GetBytesIn() != 0 {
		out["bytes_in"] = event.GetBytesIn()
	}
	if event.GetBytesOut() != 0 {
		out["bytes_out"] = event.GetBytesOut()
	}
	if event.GetRiskScore() != 0 {
		out["risk_score"] = event.GetRiskScore()
	}
	if transfer := event.GetFileTransfer(); transfer != nil {
		out["file_transfer"] = map[string]interface{}{
			"direction": transfer.GetDirection(),
			"path":      transfer.GetPath(),
			"filename":  transfer.GetFilename(),
			"size":      transfer.GetSize(),
			"protocol":  transfer.GetProtocol(),
			"allowed":   transfer.GetAllowed(),
			"reason":    transfer.GetReason(),
		}
	}
	if forward := event.GetPortForward(); forward != nil {
		out["port_forward"] = map[string]interface{}{
			"kind":      forward.GetKind(),
			"dest_host": forward.GetDestHost(),
			"dest_port": forward.GetDestPort(),
		}
	}
	return out
}

// describeEvent renders a one-line summary, because the audit views and most
// alerting read a sentence rather than a structure.
func describeEvent(event *sshproxyv1.AuditEvent) string {
	if details := event.GetDetails(); details != "" {
		return details
	}
	switch {
	case event.GetCommand() != "":
		return event.GetDecision() + " command: " + event.GetCommand()
	case event.GetFileTransfer() != nil:
		transfer := event.GetFileTransfer()
		return fmt.Sprintf("%s %s %s (%d bytes)",
			event.GetDecision(), transfer.GetDirection(), transfer.GetPath(), transfer.GetSize())
	case event.GetPortForward() != nil:
		forward := event.GetPortForward()
		return fmt.Sprintf("%s %s forward to %s:%d",
			event.GetDecision(), forward.GetKind(), forward.GetDestHost(), forward.GetDestPort())
	default:
		return ""
	}
}
