package api

import (
	"fmt"
	"strings"
)

var migrationTargetOrder = []string{"config", "users", "audit", "session-metadata"}

type MigrationOptions struct {
	Targets []string
}

type MigrationResult struct {
	SelectedTargets              []string
	Skipped                      []string
	ConfigCurrentImported        bool
	ConfigVersionImports         int
	UserImports                  int
	AuditEventImports            int
	StorageSchemaVersion         int
	AuditSchemaVersion           int
	SessionMetadataSchemaVersion int
}

func (r MigrationResult) SummaryLines() []string {
	lines := []string{
		fmt.Sprintf("migration targets: %s", strings.Join(r.SelectedTargets, ", ")),
		fmt.Sprintf("sql storage schema version: %d", r.StorageSchemaVersion),
		fmt.Sprintf("audit store schema version: %d", r.AuditSchemaVersion),
		fmt.Sprintf("session metadata schema version: %d", r.SessionMetadataSchemaVersion),
		fmt.Sprintf("config current imported: %t", r.ConfigCurrentImported),
		fmt.Sprintf("config versions imported: %d", r.ConfigVersionImports),
		fmt.Sprintf("users imported: %d", r.UserImports),
		fmt.Sprintf("audit events imported: %d", r.AuditEventImports),
	}
	lines = append(lines, r.Skipped...)
	return lines
}

func RunDataMigration(cfg *Config, opts MigrationOptions) (MigrationResult, error) {
	var result MigrationResult
	if cfg == nil {
		return result, fmt.Errorf("api config is required")
	}
	targets, err := normalizeMigrationTargets(opts.Targets)
	if err != nil {
		return result, err
	}
	result.SelectedTargets = targets

	poolSettings, err := sqlPoolSettingsFromConfig(cfg)
	if err != nil {
		return result, err
	}

	var storage *sqlStorage
	if needsSQLStorageTarget(targets) &&
		(storeBackendIsPostgres(cfg.ConfigStoreBackend) || storeBackendIsPostgres(cfg.UserStoreBackend)) {
		storage, err = newSQLStorageWithOptions(
			defaultSQLDriver("pgx", cfg.PostgresDriver),
			cfg.PostgresDatabaseURL,
			nil,
			poolSettings,
		)
		if err != nil {
			return result, err
		}
		defer func() {
			_ = storage.Close()
		}()
		result.StorageSchemaVersion, _ = storage.SchemaVersion()
	}

	if hasMigrationTarget(targets, "config") {
		if !storeBackendIsPostgres(cfg.ConfigStoreBackend) {
			result.Skipped = append(result.Skipped, "skipped config migration: config_store_backend is not postgres")
		} else if storage == nil {
			return result, fmt.Errorf("config migration requires SQL storage")
		} else {
			beforeCurrent, err := storage.LoadCurrentConfig()
			if err != nil {
				return result, err
			}
			beforeVersions, err := storage.ListConfigVersions()
			if err != nil {
				return result, err
			}
			migrationAPI := &API{
				config:      cfg,
				storageDB:   storage,
				configStore: newConfigStore(dataFilePath(cfg.DataDir, "config_store.json")),
			}
			if err := migrationAPI.bootstrapPostgresConfigStore(); err != nil {
				return result, err
			}
			afterCurrent, err := storage.LoadCurrentConfig()
			if err != nil {
				return result, err
			}
			afterVersions, err := storage.ListConfigVersions()
			if err != nil {
				return result, err
			}
			result.ConfigCurrentImported = beforeCurrent == nil && afterCurrent != nil
			if len(afterVersions) > len(beforeVersions) {
				result.ConfigVersionImports = len(afterVersions) - len(beforeVersions)
			}
		}
	}

	if hasMigrationTarget(targets, "users") {
		if !storeBackendIsPostgres(cfg.UserStoreBackend) {
			result.Skipped = append(result.Skipped, "skipped user migration: user_store_backend is not postgres")
		} else if storage == nil {
			return result, fmt.Errorf("user migration requires SQL storage")
		} else {
			beforeUsers, err := storage.CountUsers()
			if err != nil {
				return result, err
			}
			if _, err := newUserStore(dataFilePath(cfg.DataDir, "users.json"), storage, true); err != nil {
				return result, err
			}
			afterUsers, err := storage.CountUsers()
			if err != nil {
				return result, err
			}
			if afterUsers > beforeUsers {
				result.UserImports = afterUsers - beforeUsers
			}
		}
	}

	if hasMigrationTarget(targets, "audit") {
		if !auditStoreUsesSQL(cfg.AuditStoreBackend) {
			result.Skipped = append(result.Skipped, "skipped audit migration: audit_store_backend is not SQL-backed")
		} else {
			auditDSN := strings.TrimSpace(cfg.AuditStoreDatabaseURL)
			if auditDSN == "" {
				auditDSN = cfg.PostgresDatabaseURL
			}
			auditStore, err := newAuditSQLStoreWithDriverOptions(
				cfg.AuditStoreBackend,
				defaultSQLDriver("pgx", cfg.AuditStoreDriver),
				auditDSN,
				nil,
				poolSettings,
			)
			if err != nil {
				return result, err
			}
			defer func() {
				_ = auditStore.Close()
			}()
			result.AuditSchemaVersion, _ = auditStore.SchemaVersion()
			beforeEvents, err := auditStore.EventCount()
			if err != nil {
				return result, err
			}
			if err := auditStore.SyncDir(cfg.AuditLogDir); err != nil {
				return result, err
			}
			afterEvents, err := auditStore.EventCount()
			if err != nil {
				return result, err
			}
			if afterEvents > beforeEvents {
				result.AuditEventImports = afterEvents - beforeEvents
			}
		}
	}

	if hasMigrationTarget(targets, "session-metadata") {
		sessionStore := newSessionMetadataStore(dataFilePath(cfg.DataDir, "sessions.db"))
		if sessionStore == nil {
			return result, fmt.Errorf("failed to initialize session metadata store")
		}
		defer func() {
			_ = sessionStore.Close()
		}()
		result.SessionMetadataSchemaVersion, _ = sessionStore.SchemaVersion()
	}

	return result, nil
}

func normalizeMigrationTargets(raw []string) ([]string, error) {
	selected := map[string]bool{}
	if len(raw) == 0 {
		return append([]string(nil), migrationTargetOrder...), nil
	}
	for _, item := range raw {
		for _, token := range strings.FieldsFunc(item, func(r rune) bool {
			return r == ',' || r == '\n' || r == '\r'
		}) {
			target := strings.ToLower(strings.TrimSpace(token))
			switch target {
			case "":
				continue
			case "all":
				return append([]string(nil), migrationTargetOrder...), nil
			case "config", "users", "audit", "session-metadata", "session_metadata":
				if target == "session_metadata" {
					target = "session-metadata"
				}
				selected[target] = true
			default:
				return nil, fmt.Errorf("unsupported migration target %q", target)
			}
		}
	}
	ordered := make([]string, 0, len(selected))
	for _, target := range migrationTargetOrder {
		if selected[target] {
			ordered = append(ordered, target)
		}
	}
	return ordered, nil
}

func hasMigrationTarget(targets []string, target string) bool {
	for _, item := range targets {
		if item == target {
			return true
		}
	}
	return false
}

func needsSQLStorageTarget(targets []string) bool {
	return hasMigrationTarget(targets, "config") || hasMigrationTarget(targets, "users")
}
