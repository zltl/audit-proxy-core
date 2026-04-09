package api

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func enableSQLiteAuditStore(t *testing.T, api *API) {
	t.Helper()

	store, err := newAuditSQLStoreWithDriver("postgres", "sqlite", filepath.Join(t.TempDir(), "audit-store.db"))
	if err != nil {
		t.Fatalf("newAuditSQLStoreWithDriver(sqlite) error = %v", err)
	}
	api.auditStore = store
	api.config.AuditStoreBackend = "postgres"
	api.config.AuditStoreDatabaseURL = "sqlite-test"
}

func TestAuditStoreServesEventsAfterFilesRemoved(t *testing.T) {
	api, mux, _ := setupTestAPI(t)
	enableSQLiteAuditStore(t, api)

	rr := doRequest(mux, "GET", "/api/v2/audit/events", nil)
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	resp := parseResponse(t, rr)
	if resp.Total != 3 {
		t.Fatalf("expected 3 events, got %d", resp.Total)
	}

	entries, err := os.ReadDir(api.config.AuditLogDir)
	if err != nil {
		t.Fatalf("ReadDir(audit) error = %v", err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if err := os.Remove(filepath.Join(api.config.AuditLogDir, entry.Name())); err != nil {
			t.Fatalf("Remove(%s) error = %v", entry.Name(), err)
		}
	}

	rr = doRequest(mux, "GET", "/api/v2/audit/events", nil)
	if rr.Code != 200 {
		t.Fatalf("expected 200 after file removal, got %d: %s", rr.Code, rr.Body.String())
	}
	resp = parseResponse(t, rr)
	if resp.Total != 3 {
		t.Fatalf("expected persisted 3 events after file removal, got %d", resp.Total)
	}
}

func TestAuditStoreNormalizesLegacyAuditLogs(t *testing.T) {
	api, mux, _ := setupTestAPI(t)
	enableSQLiteAuditStore(t, api)

	legacyAuditPath := filepath.Join(api.config.AuditLogDir, "audit_20240115.log")
	if err := os.WriteFile(legacyAuditPath, []byte(`{"timestamp":"2024-01-15T13:00:00Z","type":"AUTH_SUCCESS","session":42,"user":"carol","client":"10.0.0.3","target":"srv3"}`+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(legacy audit) error = %v", err)
	}
	commandAuditPath := filepath.Join(api.config.AuditLogDir, "commands_20240115.log")
	if err := os.WriteFile(commandAuditPath, []byte(`{"timestamp":1705323600,"session":42,"user":"carol","upstream":"srv3","type":"command","command":"whoami"}`+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(command audit) error = %v", err)
	}

	rr := doRequest(mux, "GET", "/api/v2/audit/events", nil)
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	resp := parseResponse(t, rr)
	if resp.Total != 5 {
		t.Fatalf("expected 5 events after legacy import, got %d", resp.Total)
	}

	rr = doRequest(mux, "GET", "/api/v2/audit/search?q=whoami", nil)
	if rr.Code != 200 {
		t.Fatalf("expected 200 search, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "whoami") || !strings.Contains(rr.Body.String(), "command") {
		t.Fatalf("expected normalized command audit event, got %s", rr.Body.String())
	}

	rr = doRequest(mux, "GET", "/api/v2/audit/search?q=carol", nil)
	if rr.Code != 200 {
		t.Fatalf("expected 200 search, got %d: %s", rr.Code, rr.Body.String())
	}
	resp = parseResponse(t, rr)
	if resp.Total != 2 {
		t.Fatalf("expected 2 normalized legacy events for carol, got %d", resp.Total)
	}
}
