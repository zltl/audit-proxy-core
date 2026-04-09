package api

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/models"
)

func TestConfigStoreRoundTripsINISnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config_store.json")
	store := newConfigStore(path)
	snapshot := []byte("[server]\nbind_addr = 0.0.0.0\n")
	when := time.Unix(1710000000, 0).UTC()
	if err := store.Save(snapshot, "v1", "chg-1", "admin", "restore", when); err != nil {
		t.Fatalf("configStore.Save(INI) error = %v", err)
	}
	loaded := newConfigStore(path).Get()
	if loaded == nil {
		t.Fatal("configStore.Get() = nil")
	}
	if string(loaded.Snapshot) != string(snapshot) {
		t.Fatalf("loaded snapshot = %q, want %q", string(loaded.Snapshot), string(snapshot))
	}
}

func TestRunBackupAndRestoreRoundTrip(t *testing.T) {
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "config.ini")
	configVersionsDir := filepath.Join(tempDir, "config_versions")
	storageDB := filepath.Join(tempDir, "storage.db")
	auditDB := filepath.Join(tempDir, "audit.db")
	auditDir := filepath.Join(tempDir, "audit")
	backupPath := filepath.Join(tempDir, "backup.json")
	sessionsDB := filepath.Join(tempDir, "sessions.db")

	if err := os.MkdirAll(configVersionsDir, 0o700); err != nil {
		t.Fatalf("MkdirAll(config_versions) error = %v", err)
	}
	if err := os.MkdirAll(auditDir, 0o700); err != nil {
		t.Fatalf("MkdirAll(audit) error = %v", err)
	}

	materializedConfig := "[server]\nbind_addr = 127.0.0.1\nport = 2222\n"
	if err := os.WriteFile(configFile, []byte(materializedConfig), 0o600); err != nil {
		t.Fatalf("WriteFile(config.ini) error = %v", err)
	}

	cfg := &Config{
		DataDir:               tempDir,
		ConfigFile:            configFile,
		ConfigVerDir:          configVersionsDir,
		ConfigStoreBackend:    "postgres",
		UserStoreBackend:      "postgres",
		PostgresDriver:        "sqlite",
		PostgresDatabaseURL:   storageDB,
		AuditStoreBackend:     "postgres",
		AuditStoreDriver:      "sqlite",
		AuditStoreDatabaseURL: auditDB,
		AuditLogDir:           auditDir,
	}

	storage, err := newSQLStorage("sqlite", storageDB)
	if err != nil {
		t.Fatalf("newSQLStorage(sqlite) error = %v", err)
	}
	defer func() { _ = storage.Close() }()
	current := &ConfigStoreEntry{
		Version:   "cfg-v1",
		ChangeID:  "chg-1",
		Requester: "admin",
		Source:    "node-1",
		UpdatedAt: time.Unix(1710000000, 0).UTC(),
		Snapshot:  []byte(materializedConfig),
	}
	if err := storage.SaveCurrentConfig(current); err != nil {
		t.Fatalf("SaveCurrentConfig() error = %v", err)
	}
	if err := storage.SaveConfigVersion("v-001", []byte("[server]\nport = 2201\n"), time.Unix(1710000100, 0).UTC()); err != nil {
		t.Fatalf("SaveConfigVersion(v-001) error = %v", err)
	}
	if err := storage.SaveConfigVersion("v-002", []byte("[server]\nport = 2202\n"), time.Unix(1710000200, 0).UTC()); err != nil {
		t.Fatalf("SaveConfigVersion(v-002) error = %v", err)
	}
	if err := storage.ReplaceUsers([]models.User{{
		Username:   "alice",
		Role:       "admin",
		Enabled:    true,
		PassHash:   "hash",
		MFASecret:  "secret",
		MFAEnabled: true,
	}}); err != nil {
		t.Fatalf("ReplaceUsers() error = %v", err)
	}

	auditStore, err := newAuditSQLStoreWithDriver("postgres", "sqlite", auditDB)
	if err != nil {
		t.Fatalf("newAuditSQLStoreWithDriver(sqlite) error = %v", err)
	}
	defer func() { _ = auditStore.Close() }()
	if err := auditStore.ReplaceEvents([]auditBackupEvent{{
		Event: models.AuditEvent{
			ID:         "evt-1",
			Timestamp:  time.Unix(1710000300, 0).UTC(),
			EventType:  "login",
			Username:   "alice",
			SourceIP:   "10.0.0.8",
			TargetHost: "db-1",
		},
	}}); err != nil {
		t.Fatalf("auditStore.ReplaceEvents() error = %v", err)
	}

	sessionStore := newSessionMetadataStore(sessionsDB)
	if sessionStore == nil {
		t.Fatal("newSessionMetadataStore() = nil")
	}
	defer func() { _ = sessionStore.Close() }()
	if err := sessionStore.ReplaceBackupRows([]sessionMetadataBackupRow{{
		ID:            "sess-1",
		Username:      "alice",
		SourceIP:      "10.0.0.8",
		TargetHost:    "db-1",
		TargetPort:    22,
		StartUnix:     1710000400,
		BytesIn:       12,
		BytesOut:      34,
		Status:        "closed",
		LastSeenUnix:  1710000500,
		UpdatedUnix:   1710000500,
		RecordingFile: "session.cast",
	}}); err != nil {
		t.Fatalf("sessionStore.ReplaceBackupRows() error = %v", err)
	}

	backupResult, err := RunBackup(cfg, backupPath, BackupOptions{})
	if err != nil {
		t.Fatalf("RunBackup() error = %v", err)
	}
	if backupResult.ConfigVersionCount != 2 || backupResult.UserCount != 1 || backupResult.AuditEventCount != 1 || backupResult.SessionMetadataCount != 1 {
		t.Fatalf("RunBackup() counts = %+v", backupResult)
	}

	if err := storage.ReplaceCurrentConfig(nil); err != nil {
		t.Fatalf("ReplaceCurrentConfig(nil) error = %v", err)
	}
	if err := storage.ReplaceConfigVersions(nil); err != nil {
		t.Fatalf("ReplaceConfigVersions(nil) error = %v", err)
	}
	if err := storage.ReplaceUsers(nil); err != nil {
		t.Fatalf("ReplaceUsers(nil) error = %v", err)
	}
	if err := auditStore.ReplaceEvents(nil); err != nil {
		t.Fatalf("auditStore.ReplaceEvents(nil) error = %v", err)
	}
	if err := sessionStore.ReplaceBackupRows(nil); err != nil {
		t.Fatalf("sessionStore.ReplaceBackupRows(nil) error = %v", err)
	}
	if err := os.WriteFile(configFile, []byte("[server]\nport = 9999\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(config.ini overwrite) error = %v", err)
	}

	restoreResult, err := RunRestore(cfg, backupPath, BackupOptions{})
	if err != nil {
		t.Fatalf("RunRestore() error = %v", err)
	}
	if !restoreResult.ConfigCurrentRestored || restoreResult.ConfigVersionCount != 2 || restoreResult.UserCount != 1 || restoreResult.AuditEventCount != 1 || restoreResult.SessionMetadataCount != 1 {
		t.Fatalf("RunRestore() counts = %+v", restoreResult)
	}

	restoredCurrent, err := storage.LoadCurrentConfig()
	if err != nil {
		t.Fatalf("LoadCurrentConfig() error = %v", err)
	}
	if restoredCurrent == nil || restoredCurrent.Version != current.Version || string(restoredCurrent.Snapshot) != string(current.Snapshot) {
		t.Fatalf("restored current = %#v, want version %q snapshot %q", restoredCurrent, current.Version, string(current.Snapshot))
	}
	versions, err := storage.ListConfigVersionSnapshots()
	if err != nil {
		t.Fatalf("ListConfigVersionSnapshots() error = %v", err)
	}
	if len(versions) != 2 {
		t.Fatalf("ListConfigVersionSnapshots() length = %d, want 2", len(versions))
	}
	users, err := storage.ListUsers()
	if err != nil {
		t.Fatalf("ListUsers() error = %v", err)
	}
	if len(users) != 1 || users[0].Username != "alice" || users[0].PassHash != "hash" {
		t.Fatalf("restored users = %#v", users)
	}
	auditEvents, err := auditStore.ListEvents()
	if err != nil {
		t.Fatalf("auditStore.ListEvents() error = %v", err)
	}
	if len(auditEvents) != 1 || auditEvents[0].ID != "evt-1" {
		t.Fatalf("restored audit events = %#v", auditEvents)
	}
	rows, err := sessionStore.ListBackupRows()
	if err != nil {
		t.Fatalf("sessionStore.ListBackupRows() error = %v", err)
	}
	if len(rows) != 1 || rows[0].ID != "sess-1" {
		t.Fatalf("restored session rows = %#v", rows)
	}
	rawConfig, err := os.ReadFile(configFile)
	if err != nil {
		t.Fatalf("ReadFile(config.ini) error = %v", err)
	}
	if string(rawConfig) != materializedConfig {
		t.Fatalf("restored config.ini = %q, want %q", string(rawConfig), materializedConfig)
	}
	backupData, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatalf("ReadFile(backup.json) error = %v", err)
	}
	if !strings.Contains(string(backupData), "\"format_version\": 1") {
		t.Fatalf("backup bundle missing format_version: %s", string(backupData))
	}
}

func TestRunBackupAndRestoreWithFileBackends(t *testing.T) {
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "config.ini")
	configStorePath := filepath.Join(tempDir, "config_store.json")
	configVersionsDir := filepath.Join(tempDir, "config_versions")
	auditDir := filepath.Join(tempDir, "audit")
	backupPath := filepath.Join(tempDir, "file-backup.json")

	if err := os.MkdirAll(configVersionsDir, 0o700); err != nil {
		t.Fatalf("MkdirAll(config_versions) error = %v", err)
	}
	if err := os.MkdirAll(auditDir, 0o700); err != nil {
		t.Fatalf("MkdirAll(audit) error = %v", err)
	}

	configContent := "[server]\nport = 2022\n"
	if err := os.WriteFile(configFile, []byte(configContent), 0o600); err != nil {
		t.Fatalf("WriteFile(config.ini) error = %v", err)
	}
	store := newConfigStore(configStorePath)
	if err := store.Save([]byte(configContent), "file-v1", "chg-file", "operator", "local", time.Unix(1710000600, 0).UTC()); err != nil {
		t.Fatalf("configStore.Save() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(configVersionsDir, "file-v1.json"), []byte(configContent), 0o600); err != nil {
		t.Fatalf("WriteFile(config version) error = %v", err)
	}
	if err := writeUserFile(filepath.Join(tempDir, "users.json"), []models.User{{
		Username:   "bob",
		Role:       "operator",
		Enabled:    true,
		PassHash:   "hash-bob",
		AllowedIPs: []string{"10.0.0.0/24"},
	}}); err != nil {
		t.Fatalf("writeUserFile() error = %v", err)
	}
	auditRaw := `{"id":"evt-file","timestamp":"2026-04-09T01:00:00Z","event_type":"logout","username":"bob","source_ip":"10.0.0.9"}`
	if err := os.WriteFile(filepath.Join(auditDir, "audit-20260409.jsonl"), []byte(auditRaw+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(audit jsonl) error = %v", err)
	}

	cfg := &Config{
		DataDir:            tempDir,
		ConfigFile:         configFile,
		ConfigVerDir:       configVersionsDir,
		ConfigStoreBackend: "file",
		UserStoreBackend:   "file",
		AuditStoreBackend:  "file",
		AuditLogDir:        auditDir,
	}

	if _, err := RunBackup(cfg, backupPath, BackupOptions{Targets: []string{"config,users,audit"}}); err != nil {
		t.Fatalf("RunBackup(file backends) error = %v", err)
	}

	if err := os.Remove(configStorePath); err != nil {
		t.Fatalf("Remove(config_store.json) error = %v", err)
	}
	if err := os.Remove(filepath.Join(configVersionsDir, "file-v1.json")); err != nil {
		t.Fatalf("Remove(config version) error = %v", err)
	}
	if err := os.Remove(filepath.Join(tempDir, "users.json")); err != nil {
		t.Fatalf("Remove(users.json) error = %v", err)
	}
	if err := os.Remove(filepath.Join(auditDir, "audit-20260409.jsonl")); err != nil {
		t.Fatalf("Remove(audit file) error = %v", err)
	}

	if _, err := RunRestore(cfg, backupPath, BackupOptions{Targets: []string{"config,users,audit"}}); err != nil {
		t.Fatalf("RunRestore(file backends) error = %v", err)
	}

	restored := newConfigStore(configStorePath).Get()
	if restored == nil || restored.Version != "file-v1" || string(restored.Snapshot) != configContent {
		t.Fatalf("restored config store = %#v", restored)
	}
	users, err := readUserFile(filepath.Join(tempDir, "users.json"))
	if err != nil {
		t.Fatalf("readUserFile() error = %v", err)
	}
	if len(users) != 1 || users[0].Username != "bob" || users[0].PassHash != "hash-bob" {
		t.Fatalf("restored users = %#v", users)
	}
	auditData, err := os.ReadFile(filepath.Join(auditDir, "audit-restore.jsonl"))
	if err != nil {
		t.Fatalf("ReadFile(audit-restore.jsonl) error = %v", err)
	}
	if !strings.Contains(string(auditData), "\"evt-file\"") {
		t.Fatalf("restored audit file missing event: %s", string(auditData))
	}
}
