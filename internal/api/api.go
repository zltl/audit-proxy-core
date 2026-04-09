package api

import (
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/cluster"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/collab"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/jit"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/models"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/sshca"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/threat"
)

// Config holds API-specific configuration.
type Config struct {
	AdminUser                       string
	AdminPassHash                   string
	SessionSecret                   string
	AuditLogDir                     string
	RecordingDir                    string
	RecordingObjectStorageEnabled   bool
	RecordingObjectStorageEndpoint  string
	RecordingObjectStorageBucket    string
	RecordingObjectStorageAccessKey string
	RecordingObjectStorageSecretKey string
	RecordingObjectStorageRegion    string
	RecordingObjectStoragePrefix    string
	RecordingObjectStorageUseSSL    bool
	DataDir                         string // directory for users.json etc.
	ConfigFile                      string // path to config.ini
	ConfigVerDir                    string // directory for config version history
	ConfigApprovalEnabled           bool
	ConfigStoreBackend              string // file or postgres for centralized config + versions
	UserStoreBackend                string // file or postgres for /api/v2/users persistence
	PostgresDriver                  string // internal/testing override; defaults to pgx
	PostgresDatabaseURL             string // DSN used when a *_backend is postgres
	PostgresReadDatabaseURLs        string // comma-separated read-replica DSNs for config/user reads
	AuditStoreBackend               string // file, postgres, or timescaledb for audit event indexing
	AuditStoreDriver                string // internal/testing override; defaults to pgx
	AuditStoreDatabaseURL           string // optional dedicated DSN for audit storage
	AuditStoreReadDatabaseURLs      string // comma-separated read-replica DSNs for audit queries
	DatabaseMaxOpenConns            int
	DatabaseMaxIdleConns            int
	DatabaseConnMaxLifetime         string
	DatabaseConnMaxIdleTime         string
	DatabaseReadAfterWriteWindow    string
}

// DataPlaneClient defines the interface for communicating with the C data plane.
type DataPlaneClient interface {
	GetHealth() (*models.HealthStatus, error)
	ListSessions() ([]models.Session, error)
	KillSession(id string) error
	GetMetrics() (string, error)
	ListUpstreams() ([]models.Server, error)
	ReloadConfig() error
	GetConfig() (map[string]interface{}, error)
	GetDrainStatus() (*models.DrainStatus, error)
	SetDrainMode(draining bool) (*models.DrainStatus, error)
}

// API is the REST API v2 handler group.
type API struct {
	dp                DataPlaneClient
	config            *Config
	users             *userStore
	servers           *serverStore
	jitStore          *jit.Store
	configChanges     *ConfigChangeStore
	configStore       *configStore
	storageDB         *sqlStorage
	auditStore        *auditSQLStore
	sessionMetadata   *sessionMetadataStore
	ca                *sshca.CA
	cluster           *cluster.Manager
	threat            *threat.Detector
	compliance        *complianceState
	siemState         *siemState
	discovery         *discoveryState
	collab            *collab.Manager
	collabMu          sync.RWMutex
	collabChats       map[string]*collab.ChatRoom
	collabRecordings  map[string]*collab.Recorder
	cmdCtrl           *cmdCtrlState
	sessionSyncMu     sync.Mutex
	sessionSyncOnce   sync.Once
	sessionSyncBg     atomic.Bool
	auditSyncMu       sync.Mutex
	auditSyncOnce     sync.Once
	auditSyncBg       atomic.Bool
	recordingStore    *recordingObjectStore
	recordingSyncOnce sync.Once
}

// userStore holds the in-memory user list backed by a JSON file.
type userStore struct {
	mu          sync.RWMutex
	users       map[string]models.User
	path        string
	sqlStore    *sqlStorage
	usePostgres bool
}

// New creates a new API instance.
func New(dp DataPlaneClient, cfg *Config) (*API, error) {
	var storage *sqlStorage
	var err error
	poolSettings, err := sqlPoolSettingsFromConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("api: parse database pool settings: %w", err)
	}
	mainReaderDSNs := []string(nil)
	if cfg != nil {
		mainReaderDSNs = cleanedDatabaseURLs([]string{cfg.PostgresReadDatabaseURLs})
	}
	postgresDriver := defaultSQLDriver("pgx", cfgPostgresDriver(cfg))
	var sharedPostgresCluster *sqlDBCluster
	if cfg != nil && (storeBackendIsPostgres(cfg.ConfigStoreBackend) || storeBackendIsPostgres(cfg.UserStoreBackend)) {
		sharedPostgresCluster, err = newSQLDBCluster(postgresDriver, cfg.PostgresDatabaseURL, mainReaderDSNs, poolSettings)
		if err != nil {
			return nil, fmt.Errorf("api: init postgres storage: %w", err)
		}
		storage, err = newSQLStorageFromCluster(sharedPostgresCluster)
		if err != nil {
			_ = sharedPostgresCluster.Close()
			return nil, fmt.Errorf("api: init postgres storage: %w", err)
		}
	}

	users, err := newUserStore(dataFilePath(cfg.DataDir, "users.json"), storage, storeBackendIsPostgres(cfg.UserStoreBackend))
	if err != nil {
		if storage != nil {
			_ = storage.Close()
		}
		return nil, fmt.Errorf("api: init users store: %w", err)
	}

	var auditStore *auditSQLStore
	if cfg != nil && auditStoreUsesSQL(cfg.AuditStoreBackend) {
		auditDSN := strings.TrimSpace(cfg.AuditStoreDatabaseURL)
		if auditDSN == "" {
			auditDSN = cfg.PostgresDatabaseURL
		}
		auditDriver := defaultSQLDriver("pgx", cfg.AuditStoreDriver)
		auditReaderDSNs := cleanedDatabaseURLs([]string{cfg.AuditStoreReadDatabaseURLs})
		if len(auditReaderDSNs) == 0 && strings.TrimSpace(auditDSN) == strings.TrimSpace(cfg.PostgresDatabaseURL) {
			auditReaderDSNs = append(auditReaderDSNs, mainReaderDSNs...)
		}
		if sharedPostgresCluster != nil &&
			auditDriver == postgresDriver &&
			strings.TrimSpace(auditDSN) == strings.TrimSpace(cfg.PostgresDatabaseURL) &&
			equalStringSlices(auditReaderDSNs, mainReaderDSNs) {
			auditStore, err = newAuditSQLStoreFromCluster(cfg.AuditStoreBackend, sharedPostgresCluster)
		} else {
			auditStore, err = newAuditSQLStoreWithDriverOptions(cfg.AuditStoreBackend, auditDriver, auditDSN, auditReaderDSNs, poolSettings)
		}
		if err != nil {
			if storage != nil {
				_ = storage.Close()
			}
			return nil, fmt.Errorf("api: init audit store: %w", err)
		}
	}

	a := &API{
		dp:      dp,
		config:  cfg,
		users:   users,
		servers: newServerStore(dataFilePath(cfg.DataDir, "servers.json")),
		configChanges: newConfigChangeStore(
			dataFilePath(cfg.DataDir, "config_changes.json"),
			24*time.Hour,
		),
		configStore:     newConfigStore(dataFilePath(cfg.DataDir, "config_store.json")),
		storageDB:       storage,
		auditStore:      auditStore,
		sessionMetadata: newSessionMetadataStore(dataFilePath(cfg.DataDir, "sessions.db")),
		recordingStore:  newRecordingObjectStore(cfg),
	}
	if err := a.bootstrapConfigStore(); err != nil {
		_ = a.Close()
		return nil, fmt.Errorf("api: bootstrap config store: %w", err)
	}
	return a, nil
}

func dataFilePath(baseDir, name string) string {
	if baseDir == "" {
		return name
	}
	return filepath.Join(baseDir, name)
}

func storeBackendIsPostgres(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "postgres", "postgresql":
		return true
	default:
		return false
	}
}

func auditStoreUsesSQL(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "postgres", "postgresql", "timescaledb":
		return true
	default:
		return false
	}
}

func sqlPoolSettingsFromConfig(cfg *Config) (sqlPoolSettings, error) {
	settings := defaultSQLPoolSettings(sqlDialectPostgres)
	if cfg == nil {
		return settings, nil
	}
	if cfg.DatabaseMaxOpenConns > 0 {
		settings.MaxOpenConns = cfg.DatabaseMaxOpenConns
	}
	if cfg.DatabaseMaxIdleConns > 0 {
		settings.MaxIdleConns = cfg.DatabaseMaxIdleConns
	}
	if value := strings.TrimSpace(cfg.DatabaseConnMaxLifetime); value != "" {
		duration, err := time.ParseDuration(value)
		if err != nil {
			return settings, err
		}
		settings.ConnMaxLifetime = duration
	}
	if value := strings.TrimSpace(cfg.DatabaseConnMaxIdleTime); value != "" {
		duration, err := time.ParseDuration(value)
		if err != nil {
			return settings, err
		}
		settings.ConnMaxIdleTime = duration
	}
	if value := strings.TrimSpace(cfg.DatabaseReadAfterWriteWindow); value != "" {
		duration, err := time.ParseDuration(value)
		if err != nil {
			return settings, err
		}
		settings.ReadAfterWriteWindow = duration
	}
	return settings, nil
}

func equalStringSlices(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func defaultSQLDriver(fallback, value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func cfgPostgresDriver(cfg *Config) string {
	if cfg == nil {
		return ""
	}
	return cfg.PostgresDriver
}

// RegisterRoutes registers all API v2 routes on the given mux.
func (a *API) RegisterRoutes(mux *http.ServeMux) {
	// Dashboard
	mux.HandleFunc("GET /api/v2/dashboard/stats", a.handleDashboardStats)
	mux.HandleFunc("GET /api/v2/dashboard/activity", a.handleDashboardActivity)

	// Sessions
	mux.HandleFunc("GET /api/v2/sessions", a.handleListSessions)
	mux.HandleFunc("GET /api/v2/sessions/{id}", a.handleGetSession)
	mux.HandleFunc("DELETE /api/v2/sessions/{id}", a.handleKillSession)
	mux.HandleFunc("POST /api/v2/sessions/bulk-kill", a.handleBulkKillSessions)
	mux.HandleFunc("GET /api/v2/sessions/{id}/recording", a.handleGetRecording)
	mux.HandleFunc("GET /api/v2/sessions/{id}/recording/download", a.handleDownloadRecording)

	// Users
	mux.HandleFunc("GET /api/v2/users", a.handleListUsers)
	mux.HandleFunc("POST /api/v2/users", a.handleCreateUser)
	mux.HandleFunc("GET /api/v2/users/{username}", a.handleGetUser)
	mux.HandleFunc("PUT /api/v2/users/{username}", a.handleUpdateUser)
	mux.HandleFunc("DELETE /api/v2/users/{username}", a.handleDeleteUser)
	mux.HandleFunc("PUT /api/v2/users/{username}/password", a.handleChangePassword)
	mux.HandleFunc("PUT /api/v2/users/{username}/mfa", a.handleConfigureMFA)
	mux.HandleFunc("GET /api/v2/users/{username}/mfa/qrcode", a.handleMFAQRCode)

	// Servers
	mux.HandleFunc("GET /api/v2/servers", a.handleListServers)
	mux.HandleFunc("POST /api/v2/servers", a.handleAddServer)
	mux.HandleFunc("GET /api/v2/servers/health", a.handleServersHealth)
	mux.HandleFunc("GET /api/v2/servers/{id}", a.handleGetServer)
	mux.HandleFunc("PUT /api/v2/servers/{id}", a.handleUpdateServer)
	mux.HandleFunc("DELETE /api/v2/servers/{id}", a.handleDeleteServer)
	mux.HandleFunc("PUT /api/v2/servers/{id}/maintenance", a.handleToggleMaintenance)

	// Audit
	mux.HandleFunc("GET /api/v2/audit/events", a.handleListAuditEvents)
	mux.HandleFunc("GET /api/v2/audit/events/{id}", a.handleGetAuditEvent)
	mux.HandleFunc("GET /api/v2/audit/search", a.handleSearchAudit)
	mux.HandleFunc("GET /api/v2/audit/export", a.handleExportAudit)
	mux.HandleFunc("GET /api/v2/audit/stats", a.handleAuditStats)

	// Config
	mux.HandleFunc("GET /api/v2/config", a.handleGetConfig)
	mux.HandleFunc("GET /api/v2/config/templates", a.handleListConfigTemplates)
	mux.HandleFunc("GET /api/v2/config/templates/{name}", a.handleGetConfigTemplate)
	mux.HandleFunc("GET /api/v2/config/export", a.handleExportConfig)
	mux.HandleFunc("POST /api/v2/config/import", a.handleImportConfig)
	mux.HandleFunc("PUT /api/v2/config", a.handleUpdateConfig)
	mux.HandleFunc("POST /api/v2/config/diff", a.handleDiffConfig)
	mux.HandleFunc("GET /api/v2/config/store", a.handleGetConfigStore)
	mux.HandleFunc("GET /api/v2/config/sync-status", a.handleConfigSyncStatus)
	mux.HandleFunc("POST /api/v2/config/changes", a.handleCreateConfigChange)
	mux.HandleFunc("GET /api/v2/config/changes", a.handleListConfigChanges)
	mux.HandleFunc("GET /api/v2/config/changes/{id}", a.handleGetConfigChange)
	mux.HandleFunc("POST /api/v2/config/changes/{id}/approve", a.handleApproveConfigChange)
	mux.HandleFunc("POST /api/v2/config/changes/{id}/deny", a.handleDenyConfigChange)
	mux.HandleFunc("GET /api/v2/config/versions", a.handleListConfigVersions)
	mux.HandleFunc("GET /api/v2/config/versions/{version}", a.handleGetConfigVersion)
	mux.HandleFunc("POST /api/v2/config/rollback", a.handleRollbackConfig)
	mux.HandleFunc("POST /api/v2/config/reload", a.handleReloadConfig)

	// System
	mux.HandleFunc("GET /api/v2/system/health", a.handleSystemHealth)
	mux.HandleFunc("GET /api/v2/system/info", a.handleSystemInfo)
	mux.HandleFunc("GET /api/v2/system/metrics", a.handleSystemMetrics)
	mux.HandleFunc("GET /api/v2/system/upgrade", a.handleSystemUpgradeStatus)
	mux.HandleFunc("PUT /api/v2/system/upgrade", a.handleSystemUpgrade)

	// SSH CA
	a.RegisterCARoutes(mux)

	// Discovery
	a.RegisterDiscoveryRoutes(mux)

	// Webhook debug
	a.RegisterWebhookDebugRoutes(mux)
}
