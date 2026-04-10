package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/models"
)

func TestAuditArchiveUploadsAndFallsBackToObjectStorage(t *testing.T) {
	store := newFakeS3Server()
	server := httptest.NewServer(store)
	defer server.Close()

	dir := t.TempDir()
	auditDir := filepath.Join(dir, "audit")
	if err := os.MkdirAll(auditDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(auditDir) error = %v", err)
	}

	cfg := &Config{
		AdminUser:                          "admin",
		AdminPassHash:                      "test",
		SessionSecret:                      "secret",
		AuditLogDir:                        auditDir,
		AuditArchiveObjectStorageEnabled:   true,
		AuditArchiveObjectStorageEndpoint:  server.URL,
		AuditArchiveObjectStorageBucket:    "audit",
		AuditArchiveObjectStorageAccessKey: "access",
		AuditArchiveObjectStorageSecretKey: "secret",
		AuditArchiveObjectStoragePrefix:    "archive",
		DataDir:                            dir,
		ConfigFile:                         filepath.Join(dir, "config.ini"),
		ConfigVerDir:                       filepath.Join(dir, "config_versions"),
	}
	if err := os.WriteFile(cfg.ConfigFile, []byte(`{"listen_port": 2222}`), 0o600); err != nil {
		t.Fatalf("WriteFile(config) error = %v", err)
	}

	jsonlPath := filepath.Join(auditDir, "audit-20260409.jsonl")
	jsonlBody := []byte(`{"id":"ev1","timestamp":"2026-04-09T05:00:00Z","event_type":"login","username":"alice","source_ip":"10.0.0.1"}` + "\n")
	if err := os.WriteFile(jsonlPath, jsonlBody, 0o600); err != nil {
		t.Fatalf("WriteFile(jsonl) error = %v", err)
	}
	logPath := filepath.Join(auditDir, "commands_20260409.log")
	logBody := []byte(`{"timestamp":"2026-04-09T05:10:00Z","event":"command","user":"alice","client":"10.0.0.1","target":"srv1","command":"ls","session":"sess-1"}` + "\n")
	if err := os.WriteFile(logPath, logBody, 0o600); err != nil {
		t.Fatalf("WriteFile(log) error = %v", err)
	}

	api, err := New(&mockDP{}, cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = api.Close() })
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	if err := api.syncAuditArchive(context.Background()); err != nil {
		t.Fatalf("syncAuditArchive() error = %v", err)
	}
	if got := string(store.objectBody("archive/audit/audit-20260409.jsonl")); got != string(jsonlBody) {
		t.Fatalf("archived jsonl body = %q, want %q", got, jsonlBody)
	}
	if got := string(store.objectBody("archive/audit/commands_20260409.log")); got != string(logBody) {
		t.Fatalf("archived log body = %q, want %q", got, logBody)
	}

	events, err := api.loadAuditEvents()
	if err != nil {
		t.Fatalf("loadAuditEvents(local+archive) error = %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("loadAuditEvents(local+archive) count = %d, want 2", len(events))
	}

	if err := os.Remove(jsonlPath); err != nil {
		t.Fatalf("Remove(jsonl) error = %v", err)
	}
	if err := os.Remove(logPath); err != nil {
		t.Fatalf("Remove(log) error = %v", err)
	}

	rr := doRequest(mux, http.MethodGet, "/api/v2/audit/events", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/v2/audit/events status = %d body = %s", rr.Code, rr.Body.String())
	}
	resp := parseResponse(t, rr)
	data, err := json.Marshal(resp.Data)
	if err != nil {
		t.Fatalf("json.Marshal(resp.Data) error = %v", err)
	}
	var archived []models.AuditEvent
	if err := json.Unmarshal(data, &archived); err != nil {
		t.Fatalf("json.Unmarshal(archived events) error = %v", err)
	}
	if len(archived) != 2 {
		t.Fatalf("archived events count = %d, want 2", len(archived))
	}
	if archived[0].EventType != "command" || archived[1].EventType != "login" {
		t.Fatalf("unexpected archived events order: %+v", archived)
	}
	if archived[0].Timestamp.Before(archived[1].Timestamp) {
		t.Fatalf("events should be sorted newest first: %+v", archived)
	}
}
