package api

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/models"
)

func TestRunDataMigrationImportsFileBackedStateIntoSQLStores(t *testing.T) {
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "config.ini")
	configStoreFile := filepath.Join(tempDir, "config_store.json")
	configVersionsDir := filepath.Join(tempDir, "config_versions")
	usersFile := filepath.Join(tempDir, "users.json")
	auditDir := filepath.Join(tempDir, "audit")
	storageDB := filepath.Join(tempDir, "storage.db")
	auditDB := filepath.Join(tempDir, "audit.db")

	if err := os.MkdirAll(configVersionsDir, 0o700); err != nil {
		t.Fatalf("MkdirAll(config_versions) error = %v", err)
	}
	if err := os.MkdirAll(auditDir, 0o700); err != nil {
		t.Fatalf("MkdirAll(audit) error = %v", err)
	}
	if err := os.WriteFile(configFile, []byte("[server]\nbind_addr = 0.0.0.0\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(config.ini) error = %v", err)
	}

	currentSnapshot := json.RawMessage(`{"server":{"bind_addr":"127.0.0.1"}}`)
	currentEntry := ConfigStoreEntry{
		Version:   "20240101-000000.000000000",
		Requester: "bootstrap",
		Source:    "bootstrap",
		UpdatedAt: time.Unix(1704067200, 0).UTC(),
		Snapshot:  currentSnapshot,
	}
	rawCurrent, err := json.MarshalIndent(currentEntry, "", "  ")
	if err != nil {
		t.Fatalf("Marshal(config store entry) error = %v", err)
	}
	if err := os.WriteFile(configStoreFile, rawCurrent, 0o600); err != nil {
		t.Fatalf("WriteFile(config_store.json) error = %v", err)
	}
	for _, item := range []struct {
		name string
		body string
	}{
		{name: "20240101-010101.000000000.json", body: `{"server":{"bind_addr":"10.0.0.1"}}`},
		{name: "20240101-020202.000000000.json", body: `{"server":{"bind_addr":"10.0.0.2"}}`},
	} {
		if err := os.WriteFile(filepath.Join(configVersionsDir, item.name), []byte(item.body), 0o600); err != nil {
			t.Fatalf("WriteFile(%s) error = %v", item.name, err)
		}
	}

	userFile := UserFile{
		Users: []UserRecord{{
			User: models.User{
				Username: "alice",
				Role:     "admin",
				Enabled:  true,
			},
			PassHash: "hash",
		}},
	}
	rawUsers, err := json.MarshalIndent(userFile, "", "  ")
	if err != nil {
		t.Fatalf("Marshal(users.json) error = %v", err)
	}
	if err := os.WriteFile(usersFile, rawUsers, 0o600); err != nil {
		t.Fatalf("WriteFile(users.json) error = %v", err)
	}

	auditLine := `{"id":"evt-1","timestamp":"2026-04-08T22:00:00Z","event_type":"login","username":"alice","source_ip":"10.0.0.5","target_host":"db-1"}`
	if err := os.WriteFile(filepath.Join(auditDir, "audit-20260408.jsonl"), []byte(auditLine+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(audit jsonl) error = %v", err)
	}

	cfg := &Config{
		DataDir:               tempDir,
		ConfigFile:            configFile,
		ConfigVerDir:          configVersionsDir,
		ConfigStoreBackend:    "postgres",
		UserStoreBackend:      "postgres",
		PostgresDriver:        "sqlite",
		PostgresDatabaseURL:   storageDB,
		AuditLogDir:           auditDir,
		AuditStoreBackend:     "postgres",
		AuditStoreDriver:      "sqlite",
		AuditStoreDatabaseURL: auditDB,
	}

	result, err := RunDataMigration(cfg, MigrationOptions{})
	if err != nil {
		t.Fatalf("RunDataMigration() error = %v", err)
	}
	if !result.ConfigCurrentImported {
		t.Fatalf("ConfigCurrentImported = false, want true")
	}
	if result.ConfigVersionImports != 2 {
		t.Fatalf("ConfigVersionImports = %d, want 2", result.ConfigVersionImports)
	}
	if result.UserImports != 1 {
		t.Fatalf("UserImports = %d, want 1", result.UserImports)
	}
	if result.AuditEventImports != 1 {
		t.Fatalf("AuditEventImports = %d, want 1", result.AuditEventImports)
	}
	if result.StorageSchemaVersion != 1 || result.AuditSchemaVersion != 1 || result.SessionMetadataSchemaVersion != 1 {
		t.Fatalf("schema versions = %+v, want all 1", result)
	}

	storage, err := newSQLStorage("sqlite", storageDB)
	if err != nil {
		t.Fatalf("newSQLStorage(sqlite verify) error = %v", err)
	}
	defer func() {
		_ = storage.Close()
	}()
	current, err := storage.LoadCurrentConfig()
	if err != nil {
		t.Fatalf("LoadCurrentConfig() error = %v", err)
	}
	if current == nil || current.Version != currentEntry.Version {
		t.Fatalf("LoadCurrentConfig() = %#v, want version %q", current, currentEntry.Version)
	}
	versions, err := storage.ListConfigVersions()
	if err != nil {
		t.Fatalf("ListConfigVersions() error = %v", err)
	}
	if len(versions) != 2 {
		t.Fatalf("ListConfigVersions() length = %d, want 2", len(versions))
	}
	userCount, err := storage.CountUsers()
	if err != nil {
		t.Fatalf("CountUsers() error = %v", err)
	}
	if userCount != 1 {
		t.Fatalf("CountUsers() = %d, want 1", userCount)
	}

	auditStore, err := newAuditSQLStoreWithDriver("postgres", "sqlite", auditDB)
	if err != nil {
		t.Fatalf("newAuditSQLStoreWithDriver(sqlite verify) error = %v", err)
	}
	defer func() {
		_ = auditStore.Close()
	}()
	eventCount, err := auditStore.EventCount()
	if err != nil {
		t.Fatalf("EventCount() error = %v", err)
	}
	if eventCount != 1 {
		t.Fatalf("EventCount() = %d, want 1", eventCount)
	}

	secondRun, err := RunDataMigration(cfg, MigrationOptions{})
	if err != nil {
		t.Fatalf("RunDataMigration(second run) error = %v", err)
	}
	if secondRun.ConfigCurrentImported || secondRun.ConfigVersionImports != 0 || secondRun.UserImports != 0 || secondRun.AuditEventImports != 0 {
		t.Fatalf("RunDataMigration(second run) = %+v, want idempotent zero imports", secondRun)
	}
}
