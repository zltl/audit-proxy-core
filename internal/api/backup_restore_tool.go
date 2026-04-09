package api

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/models"
)

const backupBundleFormatVersion = 1

type backupConfigCurrent struct {
	Version        string    `json:"version"`
	ChangeID       string    `json:"change_id,omitempty"`
	Requester      string    `json:"requester,omitempty"`
	Source         string    `json:"source,omitempty"`
	UpdatedAt      time.Time `json:"updated_at"`
	Snapshot       string    `json:"snapshot"`
	SnapshotFormat string    `json:"snapshot_format,omitempty"`
}

type backupConfigVersion struct {
	Version        string    `json:"version"`
	CreatedAt      time.Time `json:"created_at"`
	Snapshot       string    `json:"snapshot"`
	SnapshotFormat string    `json:"snapshot_format,omitempty"`
}

type backupBundleMetadata struct {
	ConfigStoreBackend           string `json:"config_store_backend,omitempty"`
	UserStoreBackend             string `json:"user_store_backend,omitempty"`
	AuditStoreBackend            string `json:"audit_store_backend,omitempty"`
	StorageSchemaVersion         int    `json:"storage_schema_version,omitempty"`
	AuditSchemaVersion           int    `json:"audit_schema_version,omitempty"`
	SessionMetadataSchemaVersion int    `json:"session_metadata_schema_version,omitempty"`
}

type backupBundle struct {
	FormatVersion      int                        `json:"format_version"`
	GeneratedAt        time.Time                  `json:"generated_at"`
	Targets            []string                   `json:"targets"`
	Metadata           backupBundleMetadata       `json:"metadata"`
	ConfigCurrent      *backupConfigCurrent       `json:"config_current,omitempty"`
	MaterializedConfig string                     `json:"materialized_config,omitempty"`
	MaterializedFormat string                     `json:"materialized_format,omitempty"`
	ConfigVersions     []backupConfigVersion      `json:"config_versions,omitempty"`
	Users              []UserRecord               `json:"users,omitempty"`
	AuditEvents        []auditBackupEvent         `json:"audit_events,omitempty"`
	SessionMetadata    []sessionMetadataBackupRow `json:"session_metadata,omitempty"`
}

type BackupOptions struct {
	Targets []string
}

type BackupResult struct {
	Path                         string
	SelectedTargets              []string
	ConfigCurrentIncluded        bool
	ConfigVersionCount           int
	UserCount                    int
	AuditEventCount              int
	SessionMetadataCount         int
	StorageSchemaVersion         int
	AuditSchemaVersion           int
	SessionMetadataSchemaVersion int
	Skipped                      []string
}

type RestoreResult struct {
	Path                         string
	SelectedTargets              []string
	ConfigCurrentRestored        bool
	ConfigVersionCount           int
	UserCount                    int
	AuditEventCount              int
	SessionMetadataCount         int
	StorageSchemaVersion         int
	AuditSchemaVersion           int
	SessionMetadataSchemaVersion int
	Skipped                      []string
}

func (r BackupResult) SummaryLines() []string {
	lines := []string{
		fmt.Sprintf("backup file: %s", r.Path),
		fmt.Sprintf("backup targets: %s", strings.Join(r.SelectedTargets, ", ")),
		fmt.Sprintf("config current included: %t", r.ConfigCurrentIncluded),
		fmt.Sprintf("config versions backed up: %d", r.ConfigVersionCount),
		fmt.Sprintf("users backed up: %d", r.UserCount),
		fmt.Sprintf("audit events backed up: %d", r.AuditEventCount),
		fmt.Sprintf("session metadata rows backed up: %d", r.SessionMetadataCount),
		fmt.Sprintf("sql storage schema version: %d", r.StorageSchemaVersion),
		fmt.Sprintf("audit store schema version: %d", r.AuditSchemaVersion),
		fmt.Sprintf("session metadata schema version: %d", r.SessionMetadataSchemaVersion),
	}
	return append(lines, r.Skipped...)
}

func (r RestoreResult) SummaryLines() []string {
	lines := []string{
		fmt.Sprintf("restore file: %s", r.Path),
		fmt.Sprintf("restore targets: %s", strings.Join(r.SelectedTargets, ", ")),
		fmt.Sprintf("config current restored: %t", r.ConfigCurrentRestored),
		fmt.Sprintf("config versions restored: %d", r.ConfigVersionCount),
		fmt.Sprintf("users restored: %d", r.UserCount),
		fmt.Sprintf("audit events restored: %d", r.AuditEventCount),
		fmt.Sprintf("session metadata rows restored: %d", r.SessionMetadataCount),
		fmt.Sprintf("sql storage schema version: %d", r.StorageSchemaVersion),
		fmt.Sprintf("audit store schema version: %d", r.AuditSchemaVersion),
		fmt.Sprintf("session metadata schema version: %d", r.SessionMetadataSchemaVersion),
	}
	return append(lines, r.Skipped...)
}

func RunBackup(cfg *Config, path string, opts BackupOptions) (BackupResult, error) {
	var result BackupResult
	if cfg == nil {
		return result, fmt.Errorf("api config is required")
	}
	if strings.TrimSpace(path) == "" {
		return result, fmt.Errorf("backup path is required")
	}
	targets, err := normalizeMigrationTargets(opts.Targets)
	if err != nil {
		return result, err
	}
	result.Path = path
	result.SelectedTargets = targets

	poolSettings, err := sqlPoolSettingsFromConfig(cfg)
	if err != nil {
		return result, err
	}

	var storage *sqlStorage
	if needsSQLStorageTarget(targets) && (storeBackendIsPostgres(cfg.ConfigStoreBackend) || storeBackendIsPostgres(cfg.UserStoreBackend)) {
		storage, err = newSQLStorageWithOptions(defaultSQLDriver("pgx", cfg.PostgresDriver), cfg.PostgresDatabaseURL, nil, poolSettings)
		if err != nil {
			return result, err
		}
		defer func() { _ = storage.Close() }()
		result.StorageSchemaVersion, _ = storage.SchemaVersion()
	}

	var auditStore *auditSQLStore
	if hasMigrationTarget(targets, "audit") && auditStoreUsesSQL(cfg.AuditStoreBackend) {
		auditDSN := strings.TrimSpace(cfg.AuditStoreDatabaseURL)
		if auditDSN == "" {
			auditDSN = cfg.PostgresDatabaseURL
		}
		auditStore, err = newAuditSQLStoreWithDriverOptions(cfg.AuditStoreBackend, defaultSQLDriver("pgx", cfg.AuditStoreDriver), auditDSN, nil, poolSettings)
		if err != nil {
			return result, err
		}
		defer func() { _ = auditStore.Close() }()
		result.AuditSchemaVersion, _ = auditStore.SchemaVersion()
	}

	var sessionStore *sessionMetadataStore
	if hasMigrationTarget(targets, "session-metadata") {
		sessionStore = newSessionMetadataStore(dataFilePath(cfg.DataDir, "sessions.db"))
		if sessionStore == nil {
			return result, fmt.Errorf("failed to initialize session metadata store")
		}
		defer func() { _ = sessionStore.Close() }()
		result.SessionMetadataSchemaVersion, _ = sessionStore.SchemaVersion()
	}

	bundle := backupBundle{
		FormatVersion: backupBundleFormatVersion,
		GeneratedAt:   time.Now().UTC(),
		Targets:       append([]string(nil), targets...),
		Metadata: backupBundleMetadata{
			ConfigStoreBackend:           cfg.ConfigStoreBackend,
			UserStoreBackend:             cfg.UserStoreBackend,
			AuditStoreBackend:            cfg.AuditStoreBackend,
			StorageSchemaVersion:         result.StorageSchemaVersion,
			AuditSchemaVersion:           result.AuditSchemaVersion,
			SessionMetadataSchemaVersion: result.SessionMetadataSchemaVersion,
		},
	}

	if hasMigrationTarget(targets, "config") {
		current, materializedFormat, materializedConfig, versions, skipped, err := collectConfigBackup(cfg, storage)
		if err != nil {
			return result, err
		}
		bundle.ConfigCurrent = current
		bundle.MaterializedConfig = materializedConfig
		bundle.MaterializedFormat = materializedFormat
		bundle.ConfigVersions = versions
		result.ConfigCurrentIncluded = current != nil
		result.ConfigVersionCount = len(versions)
		result.Skipped = append(result.Skipped, skipped...)
	}

	if hasMigrationTarget(targets, "users") {
		users, skipped, err := collectUserBackup(cfg, storage)
		if err != nil {
			return result, err
		}
		bundle.Users = users
		result.UserCount = len(users)
		result.Skipped = append(result.Skipped, skipped...)
	}

	if hasMigrationTarget(targets, "audit") {
		events, skipped, err := collectAuditBackup(cfg, auditStore)
		if err != nil {
			return result, err
		}
		bundle.AuditEvents = events
		result.AuditEventCount = len(events)
		result.Skipped = append(result.Skipped, skipped...)
	}

	if hasMigrationTarget(targets, "session-metadata") {
		rows, err := sessionStore.ListBackupRows()
		if err != nil {
			return result, err
		}
		bundle.SessionMetadata = rows
		result.SessionMetadataCount = len(rows)
	}

	if err := writeBackupBundle(path, bundle); err != nil {
		return result, err
	}
	return result, nil
}

func RunRestore(cfg *Config, path string, opts BackupOptions) (RestoreResult, error) {
	var result RestoreResult
	if cfg == nil {
		return result, fmt.Errorf("api config is required")
	}
	if strings.TrimSpace(path) == "" {
		return result, fmt.Errorf("restore path is required")
	}
	bundle, err := readBackupBundle(path)
	if err != nil {
		return result, err
	}
	targets, err := normalizeMigrationTargets(opts.Targets)
	if err != nil {
		return result, err
	}
	result.Path = path
	result.SelectedTargets = targets

	poolSettings, err := sqlPoolSettingsFromConfig(cfg)
	if err != nil {
		return result, err
	}

	var storage *sqlStorage
	if needsSQLStorageTarget(targets) && (storeBackendIsPostgres(cfg.ConfigStoreBackend) || storeBackendIsPostgres(cfg.UserStoreBackend)) {
		storage, err = newSQLStorageWithOptions(defaultSQLDriver("pgx", cfg.PostgresDriver), cfg.PostgresDatabaseURL, nil, poolSettings)
		if err != nil {
			return result, err
		}
		defer func() { _ = storage.Close() }()
	}

	var auditStore *auditSQLStore
	if hasMigrationTarget(targets, "audit") && auditStoreUsesSQL(cfg.AuditStoreBackend) {
		auditDSN := strings.TrimSpace(cfg.AuditStoreDatabaseURL)
		if auditDSN == "" {
			auditDSN = cfg.PostgresDatabaseURL
		}
		auditStore, err = newAuditSQLStoreWithDriverOptions(cfg.AuditStoreBackend, defaultSQLDriver("pgx", cfg.AuditStoreDriver), auditDSN, nil, poolSettings)
		if err != nil {
			return result, err
		}
		defer func() { _ = auditStore.Close() }()
	}

	if hasMigrationTarget(targets, "config") {
		restored, versionCount, skipped, err := restoreConfigBackup(cfg, storage, bundle)
		if err != nil {
			return result, err
		}
		result.ConfigCurrentRestored = restored
		result.ConfigVersionCount = versionCount
		result.Skipped = append(result.Skipped, skipped...)
	}

	if hasMigrationTarget(targets, "users") {
		count, skipped, err := restoreUserBackup(cfg, storage, bundle.Users)
		if err != nil {
			return result, err
		}
		result.UserCount = count
		result.Skipped = append(result.Skipped, skipped...)
	}

	if hasMigrationTarget(targets, "audit") {
		count, skipped, err := restoreAuditBackup(cfg, auditStore, bundle.AuditEvents)
		if err != nil {
			return result, err
		}
		result.AuditEventCount = count
		result.Skipped = append(result.Skipped, skipped...)
	}

	if hasMigrationTarget(targets, "session-metadata") {
		sessionStore := newSessionMetadataStore(dataFilePath(cfg.DataDir, "sessions.db"))
		if sessionStore == nil {
			return result, fmt.Errorf("failed to initialize session metadata store")
		}
		defer func() { _ = sessionStore.Close() }()
		if err := sessionStore.ReplaceBackupRows(bundle.SessionMetadata); err != nil {
			return result, err
		}
		result.SessionMetadataCount = len(bundle.SessionMetadata)
		result.SessionMetadataSchemaVersion, _ = sessionStore.SchemaVersion()
	}

	if storage != nil {
		result.StorageSchemaVersion, _ = storage.SchemaVersion()
	}
	if auditStore != nil {
		result.AuditSchemaVersion, _ = auditStore.SchemaVersion()
	}
	return result, nil
}

func collectConfigBackup(cfg *Config, storage *sqlStorage) (*backupConfigCurrent, string, string, []backupConfigVersion, []string, error) {
	skipped := []string{}
	var current *ConfigStoreEntry
	var err error
	if storeBackendIsPostgres(cfg.ConfigStoreBackend) {
		if storage == nil {
			return nil, "", "", nil, skipped, fmt.Errorf("config backup requires SQL storage")
		}
		current, err = storage.LoadCurrentConfig()
		if err != nil {
			return nil, "", "", nil, skipped, err
		}
	} else {
		current = newConfigStore(dataFilePath(cfg.DataDir, "config_store.json")).Get()
	}

	materializedConfig, materializedFormat, err := readMaterializedConfig(cfg.ConfigFile)
	if err != nil {
		return nil, "", "", nil, skipped, err
	}
	if materializedConfig == "" && current != nil {
		if rendered, renderErr := renderMaterializedConfig(current.Snapshot); renderErr == nil {
			materializedConfig = rendered
			materializedFormat = configFormatINI
		}
	}
	if current == nil && materializedConfig != "" {
		current, err = deriveConfigStoreEntryFromMaterialized(materializedConfig)
		if err != nil {
			return nil, "", "", nil, skipped, err
		}
	}

	var versions []backupConfigVersion
	if storeBackendIsPostgres(cfg.ConfigStoreBackend) {
		snapshots, err := storage.ListConfigVersionSnapshots()
		if err != nil {
			return nil, "", "", nil, skipped, err
		}
		versions = make([]backupConfigVersion, 0, len(snapshots))
		for _, item := range snapshots {
			versions = append(versions, backupConfigVersion{
				Version:        item.Version,
				CreatedAt:      item.CreatedAt,
				Snapshot:       string(item.Snapshot),
				SnapshotFormat: firstNonEmpty(detectConfigFormat(item.Snapshot), "text"),
			})
		}
	} else {
		versions, err = readFileConfigVersions(cfg)
		if err != nil {
			return nil, "", "", nil, skipped, err
		}
	}
	return toBackupConfigCurrent(current), materializedFormat, materializedConfig, versions, skipped, nil
}

func collectUserBackup(cfg *Config, storage *sqlStorage) ([]UserRecord, []string, error) {
	skipped := []string{}
	if storeBackendIsPostgres(cfg.UserStoreBackend) {
		if storage == nil {
			return nil, skipped, fmt.Errorf("user backup requires SQL storage")
		}
		users, err := storage.ListUsers()
		if err != nil {
			return nil, skipped, err
		}
		return userRecordsFromModels(users), skipped, nil
	}
	records, err := readUserFile(dataFilePath(cfg.DataDir, "users.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return []UserRecord{}, skipped, nil
		}
		return nil, skipped, err
	}
	return records, skipped, nil
}

func collectAuditBackup(cfg *Config, auditStore *auditSQLStore) ([]auditBackupEvent, []string, error) {
	skipped := []string{}
	if auditStore != nil {
		events, err := auditStore.ListBackupEvents()
		return events, skipped, err
	}
	if !auditStoreUsesSQL(cfg.AuditStoreBackend) {
		events, err := readAuditBackupEventsFromDir(cfg.AuditLogDir)
		return events, skipped, err
	}
	return []auditBackupEvent{}, append(skipped, "skipped audit backup: audit backend is SQL but store is unavailable"), nil
}

func restoreConfigBackup(cfg *Config, storage *sqlStorage, bundle backupBundle) (bool, int, []string, error) {
	skipped := []string{}
	current := fromBackupConfigCurrent(bundle.ConfigCurrent)
	if current == nil && strings.TrimSpace(bundle.MaterializedConfig) != "" {
		derived, err := deriveConfigStoreEntryFromMaterialized(bundle.MaterializedConfig)
		if err != nil {
			return false, 0, skipped, err
		}
		current = derived
	}

	if storeBackendIsPostgres(cfg.ConfigStoreBackend) {
		if storage == nil {
			return false, 0, skipped, fmt.Errorf("config restore requires SQL storage")
		}
		if err := storage.ReplaceCurrentConfig(current); err != nil {
			return false, 0, skipped, err
		}
		if err := storage.ReplaceConfigVersions(fromBackupConfigVersions(bundle.ConfigVersions)); err != nil {
			return false, 0, skipped, err
		}
	} else {
		if err := replaceFileConfigCurrent(dataFilePath(cfg.DataDir, "config_store.json"), current); err != nil {
			return false, 0, skipped, err
		}
		if err := replaceFileConfigVersions(cfg, bundle.ConfigVersions); err != nil {
			return false, 0, skipped, err
		}
	}

	switch {
	case strings.TrimSpace(bundle.MaterializedConfig) != "" && strings.TrimSpace(cfg.ConfigFile) != "":
		if err := writeConfigFile(cfg.ConfigFile, bundle.MaterializedConfig); err != nil {
			return current != nil, len(bundle.ConfigVersions), skipped, err
		}
	case current != nil && strings.TrimSpace(cfg.ConfigFile) != "":
		rendered, err := renderMaterializedConfig(current.Snapshot)
		if err != nil {
			return current != nil, len(bundle.ConfigVersions), skipped, err
		}
		if err := writeConfigFile(cfg.ConfigFile, rendered); err != nil {
			return current != nil, len(bundle.ConfigVersions), skipped, err
		}
	default:
		skipped = append(skipped, "skipped config.ini restore: config_file path is empty")
	}
	return current != nil, len(bundle.ConfigVersions), skipped, nil
}

func restoreUserBackup(cfg *Config, storage *sqlStorage, users []UserRecord) (int, []string, error) {
	skipped := []string{}
	modelUsers := modelsFromUserRecords(users)
	if storeBackendIsPostgres(cfg.UserStoreBackend) {
		if storage == nil {
			return 0, skipped, fmt.Errorf("user restore requires SQL storage")
		}
		if err := storage.ReplaceUsers(modelUsers); err != nil {
			return 0, skipped, err
		}
		return len(modelUsers), skipped, nil
	}
	if err := writeUserFile(dataFilePath(cfg.DataDir, "users.json"), modelUsers); err != nil {
		return 0, skipped, err
	}
	return len(modelUsers), skipped, nil
}

func restoreAuditBackup(cfg *Config, auditStore *auditSQLStore, events []auditBackupEvent) (int, []string, error) {
	skipped := []string{}
	if auditStore != nil {
		if err := auditStore.ReplaceEvents(events); err != nil {
			return 0, skipped, err
		}
		return len(events), skipped, nil
	}
	if err := replaceAuditFiles(cfg.AuditLogDir, events); err != nil {
		return 0, skipped, err
	}
	return len(events), skipped, nil
}

func writeBackupBundle(path string, bundle backupBundle) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func readBackupBundle(path string) (backupBundle, error) {
	var bundle backupBundle
	data, err := os.ReadFile(path)
	if err != nil {
		return bundle, err
	}
	if err := json.Unmarshal(data, &bundle); err != nil {
		return bundle, err
	}
	if bundle.FormatVersion != backupBundleFormatVersion {
		return bundle, fmt.Errorf("unsupported backup format version %d", bundle.FormatVersion)
	}
	return bundle, nil
}

func toBackupConfigCurrent(entry *ConfigStoreEntry) *backupConfigCurrent {
	if entry == nil {
		return nil
	}
	return &backupConfigCurrent{
		Version:        entry.Version,
		ChangeID:       entry.ChangeID,
		Requester:      entry.Requester,
		Source:         entry.Source,
		UpdatedAt:      entry.UpdatedAt,
		Snapshot:       string(entry.Snapshot),
		SnapshotFormat: firstNonEmpty(detectConfigFormat(entry.Snapshot), "text"),
	}
}

func fromBackupConfigCurrent(entry *backupConfigCurrent) *ConfigStoreEntry {
	if entry == nil {
		return nil
	}
	return &ConfigStoreEntry{
		Version:   entry.Version,
		ChangeID:  entry.ChangeID,
		Requester: entry.Requester,
		Source:    entry.Source,
		UpdatedAt: entry.UpdatedAt,
		Snapshot:  append([]byte(nil), []byte(entry.Snapshot)...),
	}
}

func fromBackupConfigVersions(items []backupConfigVersion) []configVersionSnapshot {
	result := make([]configVersionSnapshot, 0, len(items))
	for _, item := range items {
		result = append(result, configVersionSnapshot{
			Version:   item.Version,
			CreatedAt: item.CreatedAt,
			Snapshot:  append([]byte(nil), []byte(item.Snapshot)...),
		})
	}
	return result
}

func deriveConfigStoreEntryFromMaterialized(raw string) (*ConfigStoreEntry, error) {
	doc, err := parseConfigDocument([]byte(raw), "")
	if err != nil {
		return nil, err
	}
	normalized, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	return &ConfigStoreEntry{
		Version:   time.Now().UTC().Format("20060102-150405.000000000"),
		Requester: "backup-restore",
		Source:    "materialized-config",
		UpdatedAt: time.Now().UTC(),
		Snapshot:  normalized,
	}, nil
}

func renderMaterializedConfig(snapshot []byte) (string, error) {
	doc, err := parseConfigDocument(snapshot, "")
	if err != nil {
		return "", err
	}
	rendered, err := renderConfigDocument(doc, configFormatINI)
	if err != nil {
		return "", err
	}
	return string(rendered), nil
}

func readMaterializedConfig(path string) (string, string, error) {
	if strings.TrimSpace(path) == "" {
		return "", "", nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", "", nil
		}
		return "", "", err
	}
	return string(data), firstNonEmpty(detectConfigFormat(data), configFormatINI), nil
}

func readFileConfigVersions(cfg *Config) ([]backupConfigVersion, error) {
	api := &API{config: cfg}
	entries, err := os.ReadDir(api.configVersionDir())
	if err != nil {
		if os.IsNotExist(err) {
			return []backupConfigVersion{}, nil
		}
		return nil, err
	}
	versions := make([]backupConfigVersion, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		version := strings.TrimSuffix(entry.Name(), filepath.Ext(entry.Name()))
		raw, err := os.ReadFile(filepath.Join(api.configVersionDir(), entry.Name()))
		if err != nil {
			return nil, err
		}
		versions = append(versions, backupConfigVersion{
			Version:        version,
			CreatedAt:      parseConfigVersionTimestamp(version, info.ModTime().UTC()),
			Snapshot:       string(raw),
			SnapshotFormat: firstNonEmpty(detectConfigFormat(raw), "text"),
		})
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i].Version < versions[j].Version })
	return versions, nil
}

func replaceFileConfigCurrent(path string, entry *ConfigStoreEntry) error {
	if entry == nil || len(entry.Snapshot) == 0 {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	store := newConfigStore(path)
	return store.Save(entry.Snapshot, entry.Version, entry.ChangeID, entry.Requester, entry.Source, entry.UpdatedAt)
}

func replaceFileConfigVersions(cfg *Config, items []backupConfigVersion) error {
	api := &API{config: cfg}
	dir := api.configVersionDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil {
			return err
		}
	}
	for _, item := range items {
		if err := validateConfigVersionKey(item.Version); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, item.Version+".json"), []byte(item.Snapshot), 0o600); err != nil {
			return err
		}
	}
	return nil
}

func writeConfigFile(path, content string) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0o600)
}

func userRecordsFromModels(users []models.User) []UserRecord {
	records := make([]UserRecord, 0, len(users))
	for _, user := range users {
		records = append(records, UserRecord{
			User:      user,
			PassHash:  user.PassHash,
			MFASecret: user.MFASecret,
		})
	}
	return records
}

func modelsFromUserRecords(records []UserRecord) []models.User {
	users := make([]models.User, 0, len(records))
	for _, record := range records {
		user := record.User
		user.PassHash = record.PassHash
		user.MFASecret = record.MFASecret
		users = append(users, user)
	}
	return users
}

func readAuditBackupEventsFromDir(dir string) ([]auditBackupEvent, error) {
	if strings.TrimSpace(dir) == "" {
		return []auditBackupEvent{}, fmt.Errorf("audit log directory not configured")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []auditBackupEvent{}, nil
		}
		return nil, err
	}
	events := make([]auditBackupEvent, 0)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".jsonl") && !strings.HasSuffix(name, ".log") {
			continue
		}
		path := filepath.Join(dir, name)
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 0, 1<<20), 1<<20)
		var offset int64
		for scanner.Scan() {
			line := scanner.Bytes()
			currentOffset := offset
			offset += int64(len(line)) + 1
			trimmed := strings.TrimSpace(string(line))
			if trimmed == "" {
				continue
			}
			event, err := parseAuditLogLine(path, currentOffset, []byte(trimmed))
			if err != nil || event == nil {
				continue
			}
			events = append(events, auditBackupEvent{
				Event:      *event,
				RawEvent:   trimmed,
				SourceFile: path,
			})
		}
		if err := scanner.Err(); err != nil {
			_ = file.Close()
			return nil, err
		}
		_ = file.Close()
	}
	sort.Slice(events, func(i, j int) bool {
		if events[i].Event.Timestamp.Equal(events[j].Event.Timestamp) {
			return events[i].Event.ID > events[j].Event.ID
		}
		return events[i].Event.Timestamp.After(events[j].Event.Timestamp)
	})
	return events, nil
}

func replaceAuditFiles(dir string, events []auditBackupEvent) error {
	if strings.TrimSpace(dir) == "" {
		return fmt.Errorf("audit log directory not configured")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".jsonl") && !strings.HasSuffix(name, ".log") {
			continue
		}
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			return err
		}
	}
	if len(events) == 0 {
		return nil
	}
	file, err := os.OpenFile(filepath.Join(dir, "audit-restore.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	for _, item := range events {
		raw := item.RawEvent
		if strings.TrimSpace(raw) == "" {
			payload, err := json.Marshal(item.Event)
			if err != nil {
				return err
			}
			raw = string(payload)
		}
		if _, err := file.WriteString(raw + "\n"); err != nil {
			return err
		}
	}
	return file.Sync()
}
