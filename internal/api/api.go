package api

import (
	"net/http"
	"sync"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/cluster"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/jit"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/models"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/sshca"
)

// Config holds API-specific configuration.
type Config struct {
	AdminUser     string
	AdminPassHash string
	SessionSecret string
	AuditLogDir   string
	RecordingDir  string
	DataDir       string // directory for users.json etc.
	ConfigFile    string // path to config.ini
	ConfigVerDir  string // directory for config version history
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
}

// API is the REST API v2 handler group.
type API struct {
	dp       DataPlaneClient
	config   *Config
	users    *userStore
	servers  *serverStore
	jitStore *jit.Store
	ca       *sshca.CA
	cluster  *cluster.Manager
}

// userStore holds the in-memory user list backed by a JSON file.
type userStore struct {
	mu    sync.RWMutex
	users map[string]models.User
	path  string
}

// New creates a new API instance.
func New(dp DataPlaneClient, cfg *Config) *API {
	a := &API{
		dp:      dp,
		config:  cfg,
		users:   newUserStore(cfg.DataDir + "/users.json"),
		servers: newServerStore(cfg.DataDir + "/servers.json"),
	}
	return a
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
	mux.HandleFunc("PUT /api/v2/config", a.handleUpdateConfig)
	mux.HandleFunc("GET /api/v2/config/versions", a.handleListConfigVersions)
	mux.HandleFunc("GET /api/v2/config/versions/{version}", a.handleGetConfigVersion)
	mux.HandleFunc("POST /api/v2/config/rollback", a.handleRollbackConfig)
	mux.HandleFunc("POST /api/v2/config/reload", a.handleReloadConfig)

	// System
	mux.HandleFunc("GET /api/v2/system/health", a.handleSystemHealth)
	mux.HandleFunc("GET /api/v2/system/info", a.handleSystemInfo)
	mux.HandleFunc("GET /api/v2/system/metrics", a.handleSystemMetrics)

	// SSH CA
	a.RegisterCARoutes(mux)
}
