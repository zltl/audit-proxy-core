// Package server wires together the HTTP server, template engine, route
// registration, and middleware chain for the SSH Proxy control-plane.
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/api"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/cluster"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/cmdctrl"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/collab"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/compliance"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/config"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/dataplane"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/dlp"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/grpcapi"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/jit"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/middleware"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/oidc"
	samlprovider "github.com/ssh-proxy-core/ssh-proxy-core/internal/saml"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/sshca"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/threat"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/ws"
	"github.com/ssh-proxy-core/ssh-proxy-core/web"
	"google.golang.org/grpc"
)

// Server is the top-level HTTP server for the control-plane.
type Server struct {
	config         *config.Config
	mux            *http.ServeMux
	dp             *dataplane.Client
	apiHandler     *api.API
	tmpl           *template.Template
	srv            *http.Server
	oidcProvider   *oidc.Provider
	oidcRoleMapper *oidc.RoleMapping
	samlProvider   *samlprovider.Provider
	clusterManager *cluster.Manager
	threatDetector *threat.Detector
	cliLogin       *cliLoginManager
	grpcBridge     *grpcapi.BridgeServer
	grpcServer     *grpc.Server
	grpcListener   net.Listener
	backgroundCtx  context.Context
	stopBackground context.CancelFunc
}

// New creates a fully-initialised Server.  It loads templates, builds the
// middleware chain, and registers every route.
func New(cfg *config.Config) (*Server, error) {
	dp := dataplane.New(cfg.DataPlaneAddr, cfg.DataPlaneToken)

	tmpl, err := loadTemplates()
	if err != nil {
		return nil, fmt.Errorf("server: load templates: %w", err)
	}

	backgroundCtx, stopBackground := context.WithCancel(context.Background())

	s := &Server{
		config:         cfg,
		mux:            http.NewServeMux(),
		dp:             dp,
		tmpl:           tmpl,
		cliLogin:       newCLILoginManager(),
		grpcBridge:     grpcapi.NewBridgeServer(dp),
		backgroundCtx:  backgroundCtx,
		stopBackground: stopBackground,
	}

	// Initialise OIDC provider when enabled.
	if cfg.OIDCEnabled {
		oidcCfg := &oidc.OIDCConfig{
			Issuer:       cfg.OIDCIssuer,
			ClientID:     cfg.OIDCClientID,
			ClientSecret: cfg.OIDCClientSecret,
			RedirectURL:  cfg.OIDCRedirectURL,
			Scopes:       cfg.OIDCScopes,
			RolesClaim:   cfg.OIDCRolesClaim,
		}
		provider, oidcErr := oidc.NewProvider(oidcCfg)
		if oidcErr != nil {
			return nil, fmt.Errorf("server: init OIDC: %w", oidcErr)
		}
		s.oidcProvider = provider

		rolesClaim := cfg.OIDCRolesClaim
		if rolesClaim == "" {
			rolesClaim = "groups"
		}
		defaultRole := "viewer"
		s.oidcRoleMapper = &oidc.RoleMapping{
			Claim:    rolesClaim,
			Mappings: cfg.OIDCRoleMappings,
			Default:  defaultRole,
		}
	}
	if cfg.SAMLEnabled {
		provider, samlErr := samlprovider.NewProvider(&samlprovider.Config{
			RootURL:            cfg.SAMLRootURL,
			EntityID:           cfg.SAMLEntityID,
			IDPMetadataURL:     cfg.SAMLIDPMetadataURL,
			IDPMetadataFile:    cfg.SAMLIDPMetadataFile,
			CertFile:           cfg.SAMLSPCert,
			KeyFile:            cfg.SAMLSPKey,
			UsernameAttribute:  cfg.SAMLUsernameAttribute,
			RolesAttribute:     cfg.SAMLRolesAttribute,
			RoleMappings:       cfg.SAMLRoleMappings,
			AllowIDPInitiated:  cfg.SAMLAllowIDPInitiated,
			DefaultRedirectURI: "/dashboard",
		})
		if samlErr != nil {
			return nil, fmt.Errorf("server: init SAML: %w", samlErr)
		}
		s.samlProvider = provider
	}

	if err := s.routes(); err != nil {
		stopBackground()
		return nil, err
	}

	handler := middleware.Chain(
		s.mux,
		middleware.HSTS(cfg.HSTSEnabled, cfg.HSTSIncludeSubdomains, cfg.HSTSPreload),
		middleware.Recovery,
		middleware.Logger,
		middleware.APIAudit(cfg.AuditLogDir, cfg.SessionSecret),
		middleware.RateLimit(10, 60),
		middleware.Compression,
		middleware.CSRF(cfg.SessionSecret),
		middleware.Auth(cfg.SessionSecret),
	)

	s.srv = &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	s.srv.TLSConfig, err = buildRuntimeTLSConfig(cfg)
	if err != nil {
		return nil, err
	}

	return s, nil
}

// Start begins listening.  If both TLSCert and TLSKey are configured it
// serves HTTPS; otherwise plain HTTP.
func (s *Server) Start() error {
	if err := s.startGRPC(); err != nil {
		return err
	}
	if s.srv.TLSConfig != nil &&
		(len(s.srv.TLSConfig.Certificates) > 0 || s.srv.TLSConfig.GetCertificate != nil) {
		log.Printf("control-plane listening on %s (runtime TLS)", s.config.ListenAddr)
		return s.srv.ListenAndServeTLS("", "")
	}
	if s.config.TLSCert != "" && s.config.TLSKey != "" {
		log.Printf("control-plane listening on %s (TLS)", s.config.ListenAddr)
		return s.srv.ListenAndServeTLS(s.config.TLSCert, s.config.TLSKey)
	}
	log.Printf("control-plane listening on %s", s.config.ListenAddr)
	return s.srv.ListenAndServe()
}

// Shutdown gracefully drains in-flight connections.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.threatDetector != nil {
		_ = s.threatDetector.Stop()
	}
	if s.clusterManager != nil {
		_ = s.clusterManager.Stop()
	}
	if s.stopBackground != nil {
		s.stopBackground()
	}
	if s.apiHandler != nil {
		_ = s.apiHandler.Close()
	}
	if s.grpcServer != nil {
		s.grpcServer.GracefulStop()
	}
	if s.grpcListener != nil {
		_ = s.grpcListener.Close()
	}
	return s.srv.Shutdown(ctx)
}

// GRPCAddr returns the actual gRPC listen address when the listener is active.
func (s *Server) GRPCAddr() string {
	if s.grpcListener == nil {
		return ""
	}
	return s.grpcListener.Addr().String()
}

// --------------------------------------------------------------------------
// Template loading
// --------------------------------------------------------------------------

// funcMap exposes helper functions to every template.
var funcMap = template.FuncMap{
	"formatTime":     formatTime,
	"formatDuration": formatDuration,
	"formatBytes":    formatBytes,
	"json":           toJSON,
	"safeHTML":       safeHTML,
	"add":            func(a, b int) int { return a + b },
	"sub":            func(a, b int) int { return a - b },
	"seq":            seq,
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.Format("2006-01-02 15:04:05")
}

func formatDuration(d string) string {
	dur, err := time.ParseDuration(d)
	if err != nil {
		return d
	}
	h := int(dur.Hours())
	m := int(dur.Minutes()) % 60
	sec := int(dur.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh%dm%ds", h, m, sec)
	}
	if m > 0 {
		return fmt.Sprintf("%dm%ds", m, sec)
	}
	return fmt.Sprintf("%ds", sec)
}

func formatBytes(b int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)
	switch {
	case b >= GB:
		return fmt.Sprintf("%.1f GB", float64(b)/float64(GB))
	case b >= MB:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(MB))
	case b >= KB:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(KB))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

func parseOptionalDuration(raw string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	return time.ParseDuration(raw)
}

func toJSON(v interface{}) template.JS {
	b, _ := json.Marshal(v)
	return template.JS(b) //nolint:gosec // intentional
}

func safeHTML(s string) template.HTML {
	return template.HTML(s) //nolint:gosec // intentional
}

// seq returns a slice [0, 1, …, n-1] useful for range loops in templates.
func seq(n int) []int {
	s := make([]int, n)
	for i := range s {
		s[i] = i
	}
	return s
}

// loadTemplates parses all templates from the embedded FS.
func loadTemplates() (*template.Template, error) {
	tmpl := template.New("").Funcs(funcMap)

	templateFS, err := fs.Sub(web.EmbeddedFS, "templates")
	if err != nil {
		return nil, fmt.Errorf("sub web/templates: %w", err)
	}

	err = fs.WalkDir(templateFS, ".", func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || !strings.HasSuffix(path, ".html") {
			return nil
		}
		data, readErr := fs.ReadFile(templateFS, path)
		if readErr != nil {
			return fmt.Errorf("read template %s: %w", path, readErr)
		}
		_, parseErr := tmpl.New(path).Parse(string(data))
		if parseErr != nil {
			return fmt.Errorf("parse template %s: %w", path, parseErr)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return tmpl, nil
}

// --------------------------------------------------------------------------
// Route registration
// --------------------------------------------------------------------------

// routes registers all HTTP handlers on the ServeMux.
func (s *Server) routes() error {
	// Static assets — served from the embedded FS (or external dir override).
	staticFS, err := fs.Sub(web.EmbeddedFS, "static")
	if err != nil {
		return fmt.Errorf("server: embedded static sub: %w", err)
	}
	if s.config.StaticDir != "" {
		s.mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.Dir(s.config.StaticDir))))
	} else {
		s.mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))
	}

	// Auth routes.
	s.mux.HandleFunc("GET /login", s.handleLoginPage)
	s.mux.HandleFunc("POST /login", s.handleLoginSubmit)
	s.mux.HandleFunc("POST /logout", s.handleLogout)
	s.mux.HandleFunc("GET /api/v1/auth/me", s.handleAuthMe)

	// OIDC routes (registered even if disabled — handlers check the flag).
	s.registerOIDCRoutes()
	s.registerSAMLRoutes()
	s.registerCLILoginRoutes()

	// Health (public).
	s.mux.HandleFunc("GET /api/v1/health", s.handleHealth)
	s.mux.HandleFunc("GET /api/openapi.json", s.handleOpenAPIJSON)
	s.mux.HandleFunc("GET /api/docs", s.handleAPIDocs)

	// REST API v2 — delegate to api package.
	apiCfg := &api.Config{
		AdminUser:                          s.config.AdminUser,
		AdminPassHash:                      s.config.AdminPassHash,
		SessionSecret:                      s.config.SessionSecret,
		AuditLogDir:                        s.config.AuditLogDir,
		RecordingDir:                       s.config.RecordingDir,
		RecordingObjectStorageEnabled:      s.config.RecordingObjectStorageEnabled,
		RecordingObjectStorageEndpoint:     s.config.RecordingObjectStorageEndpoint,
		RecordingObjectStorageBucket:       s.config.RecordingObjectStorageBucket,
		RecordingObjectStorageAccessKey:    s.config.RecordingObjectStorageAccessKey,
		RecordingObjectStorageSecretKey:    s.config.RecordingObjectStorageSecretKey,
		RecordingObjectStorageRegion:       s.config.RecordingObjectStorageRegion,
		RecordingObjectStoragePrefix:       s.config.RecordingObjectStoragePrefix,
		RecordingObjectStorageUseSSL:       s.config.RecordingObjectStorageUseSSL,
		AuditArchiveObjectStorageEnabled:   s.config.AuditArchiveObjectStorageEnabled,
		AuditArchiveObjectStorageEndpoint:  s.config.AuditArchiveObjectStorageEndpoint,
		AuditArchiveObjectStorageBucket:    s.config.AuditArchiveObjectStorageBucket,
		AuditArchiveObjectStorageAccessKey: s.config.AuditArchiveObjectStorageAccessKey,
		AuditArchiveObjectStorageSecretKey: s.config.AuditArchiveObjectStorageSecretKey,
		AuditArchiveObjectStorageRegion:    s.config.AuditArchiveObjectStorageRegion,
		AuditArchiveObjectStoragePrefix:    s.config.AuditArchiveObjectStoragePrefix,
		AuditArchiveObjectStorageUseSSL:    s.config.AuditArchiveObjectStorageUseSSL,
		DataDir:                            s.config.DataDir,
		ConfigFile:                         s.config.DataPlaneConfigFile,
		ConfigVerDir:                       filepath.Join(s.config.DataDir, "config_versions"),
		ConfigApprovalEnabled:              s.config.ConfigApprovalEnabled,
		ConfigStoreBackend:                 s.config.ConfigStoreBackend,
		UserStoreBackend:                   s.config.UserStoreBackend,
		PostgresDatabaseURL:                s.config.PostgresDatabaseURL,
		PostgresReadDatabaseURLs:           s.config.PostgresReadDatabaseURLs,
		AuditStoreBackend:                  s.config.AuditStoreBackend,
		AuditStoreDatabaseURL:              s.config.AuditStoreDatabaseURL,
		AuditStoreReadDatabaseURLs:         s.config.AuditStoreReadDatabaseURLs,
		AuditStoreEndpoint:                 s.config.AuditStoreEndpoint,
		AuditStoreToken:                    s.config.AuditStoreToken,
		AuditStoreUsername:                 s.config.AuditStoreUsername,
		AuditStorePassword:                 s.config.AuditStorePassword,
		AuditStoreIndex:                    s.config.AuditStoreIndex,
		AuditStoreInsecureTLS:              s.config.AuditStoreInsecureTLS,
		AuditQueueBackend:                  s.config.AuditQueueBackend,
		AuditQueueEndpoint:                 s.config.AuditQueueEndpoint,
		AuditQueueTopic:                    s.config.AuditQueueTopic,
		AuditQueueExchange:                 s.config.AuditQueueExchange,
		AuditQueueRoutingKey:               s.config.AuditQueueRoutingKey,
		DatabaseMaxOpenConns:               s.config.DatabaseMaxOpenConns,
		DatabaseMaxIdleConns:               s.config.DatabaseMaxIdleConns,
		DatabaseConnMaxLifetime:            s.config.DatabaseConnMaxLifetime,
		DatabaseConnMaxIdleTime:            s.config.DatabaseConnMaxIdleTime,
		DatabaseReadAfterWriteWindow:       s.config.DatabaseReadAfterWriteWindow,
		DLPClipboardAuditEnabled:           s.config.DLPClipboardAuditEnabled,
		JITChatOpsSlackSigningSecret:       s.config.JITChatOpsSlackSigningSecret,
	}
	apiHandler, err := api.New(s.dp, apiCfg)
	if err != nil {
		return fmt.Errorf("server: init api: %w", err)
	}
	s.apiHandler = apiHandler
	apiHandler.StartSessionMetadataSync(s.backgroundCtx, 5*time.Second)
	apiHandler.StartAuditSync(s.backgroundCtx, 5*time.Second)
	apiHandler.StartAuditArchiveSync(s.backgroundCtx, 5*time.Second)
	apiHandler.StartAuditQueueSync(s.backgroundCtx, 5*time.Second)
	apiHandler.StartRecordingArchiveSync(s.backgroundCtx, 5*time.Second)
	apiHandler.StartDiscoverySync(s.backgroundCtx, 5*time.Second)
	apiHandler.StartAutomationScheduler(s.backgroundCtx, 5*time.Second)
	apiHandler.RegisterRoutes(s.mux)
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete} {
		s.mux.Handle(method+" /api/v3/", s.handleAPIVersionAlias("/api/v3/", "/api/v2/"))
	}

	dataDir := apiCfg.DataDir
	if dataDir == "" {
		dataDir = s.config.DataDir
	}
	if dataDir == "" {
		dataDir = s.config.RecordingDir
	}

	caDir := filepath.Join(dataDir, "ca")
	if err := os.MkdirAll(caDir, 0o700); err != nil {
		return fmt.Errorf("server: ensure ca dir: %w", err)
	}
	ca, err := sshca.New(&sshca.CAConfig{
		HostKeyPath:    filepath.Join(caDir, "host_ca"),
		UserKeyPath:    filepath.Join(caDir, "user_ca"),
		RevocationPath: filepath.Join(caDir, "revocations.json"),
	})
	if err != nil {
		return fmt.Errorf("server: init ssh ca: %w", err)
	}
	apiHandler.SetCA(ca)

	if s.config.ClusterEnabled {
		clusterAPIAddr := s.config.ClusterAPIAddr
		if clusterAPIAddr == "" {
			clusterAPIAddr = s.config.ListenAddr
		}
		heartbeatInterval, err := parseOptionalDuration(s.config.ClusterHeartbeatInterval)
		if err != nil {
			return fmt.Errorf("server: invalid cluster heartbeat interval: %w", err)
		}
		electionTimeout, err := parseOptionalDuration(s.config.ClusterElectionTimeout)
		if err != nil {
			return fmt.Errorf("server: invalid cluster election timeout: %w", err)
		}
		syncInterval, err := parseOptionalDuration(s.config.ClusterSyncInterval)
		if err != nil {
			return fmt.Errorf("server: invalid cluster sync interval: %w", err)
		}
		clusterMgr, err := cluster.NewManager(&cluster.ClusterConfig{
			NodeID:            s.config.ClusterNodeID,
			NodeName:          s.config.ClusterNodeName,
			BindAddr:          s.config.ClusterBindAddr,
			APIAddr:           clusterAPIAddr,
			Region:            s.config.ClusterRegion,
			Zone:              s.config.ClusterZone,
			Seeds:             s.config.ClusterSeeds,
			HeartbeatInterval: heartbeatInterval,
			ElectionTimeout:   electionTimeout,
			SyncInterval:      syncInterval,
			TLSCert:           s.config.ClusterTLSCert,
			TLSKey:            s.config.ClusterTLSKey,
			TLSCA:             s.config.ClusterTLSCA,
		})
		if err != nil {
			return fmt.Errorf("server: init cluster manager: %w", err)
		}
		if err := clusterMgr.Start(s.backgroundCtx); err != nil {
			return fmt.Errorf("server: start cluster manager: %w", err)
		}
		s.clusterManager = clusterMgr
		apiHandler.SetCluster(clusterMgr)
		clusterMgr.SetConfigSyncApplier(apiHandler.ApplyClusterConfigSnapshot)
		apiHandler.RegisterClusterRoutes(s.mux)
	}

	// Just-in-time access requests.
	jitStore := jit.NewStore(dataDir, nil)
	jitNotifier, err := jit.NewNotifier(jit.NotifierConfig{
		SMTPAddr:               s.config.JITNotifySMTPAddr,
		SMTPUsername:           s.config.JITNotifySMTPUsername,
		SMTPPassword:           s.config.JITNotifySMTPPassword,
		EmailFrom:              s.config.JITNotifyEmailFrom,
		EmailTo:                s.config.JITNotifyEmailTo,
		SlackWebhookURL:        s.config.JITNotifySlackWebhookURL,
		DingTalkWebhookURL:     s.config.JITNotifyDingTalkWebhookURL,
		WeComWebhookURL:        s.config.JITNotifyWeComWebhookURL,
		TeamsWebhookURL:        s.config.JITNotifyTeamsWebhookURL,
		PagerDutyRoutingKey:    s.config.JITNotifyPagerDutyRoutingKey,
		OpsgenieAPIURL:         s.config.JITNotifyOpsgenieAPIURL,
		OpsgenieAPIKey:         s.config.JITNotifyOpsgenieAPIKey,
		SubjectTemplate:        s.config.JITNotifySubjectTemplate,
		BodyTemplate:           s.config.JITNotifyBodyTemplate,
		MessageSubjectTemplate: s.config.JITNotifyMessageSubjectTemplate,
		MessageBodyTemplate:    s.config.JITNotifyMessageBodyTemplate,
	})
	if err != nil {
		return fmt.Errorf("server: init jit notifier: %w", err)
	}
	if jitNotifier != nil {
		jitStore.SetNotifier(jitNotifier)
	}
	go jitStore.StartCleanupLoop(s.backgroundCtx, time.Minute)
	apiHandler.SetJIT(jitStore)
	apiHandler.RegisterJITRoutes(s.mux)
	if s.config.DLPTransferApprovalEnabled {
		approvalTimeout, err := time.ParseDuration(strings.TrimSpace(s.config.DLPTransferApprovalTimeout))
		if err != nil {
			return fmt.Errorf("server: invalid dlp transfer approval timeout: %w", err)
		}
		transferApprovalStore := api.NewTransferApprovalStore(
			filepath.Join(dataDir, "transfer_approvals.json"),
			api.ParseTransferApprovalRoles(s.config.DLPTransferApprovalRoles),
			approvalTimeout,
		)
		if jitNotifier != nil {
			transferApprovalStore.SetNotifier(jitNotifier)
		}
		apiHandler.SetTransferApprovals(transferApprovalStore)
		apiHandler.RegisterTransferApprovalRoutes(s.mux)
		if jitNotifier == nil {
			log.Printf("terminal dlp approvals enabled but no jit_notify_* sink configured; approval requests will not send notifications")
		}
	}

	// Command control — policy engine + real-time approvals.
	policyEngine := cmdctrl.NewPolicyEngine(dataDir)
	if err := policyEngine.LoadRules(); err != nil {
		log.Printf("cmdctrl: load rules: %v (starting with defaults)", err)
	}
	if len(policyEngine.ListRules()) == 0 {
		for _, r := range cmdctrl.DefaultRules() {
			_ = policyEngine.AddRule(r)
		}
	}
	approvalMgr := cmdctrl.NewApprovalManager(5*time.Minute, "")
	apiHandler.SetCmdCtrl(policyEngine, approvalMgr)
	apiHandler.RegisterCmdCtrlRoutes(s.mux)

	// Session collaboration.
	collabMgr := collab.NewManager()
	apiHandler.SetCollab(collabMgr)
	apiHandler.RegisterCollabRoutes(s.mux)

	// Threat detection and compliance reporting.
	var geoResolver threat.GeoResolver
	if strings.TrimSpace(s.config.GeoIPDataFile) != "" {
		resolver, err := threat.LoadStaticGeoResolver(strings.TrimSpace(s.config.GeoIPDataFile))
		if err != nil {
			return fmt.Errorf("server: load geoip data: %w", err)
		}
		geoResolver = resolver
	}
	threatDetector := threat.NewDetector(&threat.DetectorConfig{
		Enabled:     true,
		DataDir:     dataDir,
		GeoResolver: geoResolver,
	})
	_ = threatDetector.Start(s.backgroundCtx)
	s.threatDetector = threatDetector
	apiHandler.SetThreat(threatDetector)
	apiHandler.RegisterThreatRoutes(s.mux)
	apiHandler.StartThreatResponseLoop(s.backgroundCtx, threatDetector, api.ThreatResponseConfig{
		Enabled:       s.config.ThreatResponseEnabled,
		BlockSourceIP: s.config.ThreatResponseBlockSourceIP,
		KillSessions:  s.config.ThreatResponseKillSessions,
		Notify:        s.config.ThreatResponseNotify,
		MinSeverity:   threat.Severity(strings.TrimSpace(s.config.ThreatResponseMinSeverity)),
	}, jitNotifier)
	if s.config.ThreatResponseEnabled && s.config.ThreatResponseNotify && jitNotifier == nil {
		log.Printf("server: threat_response_notify is enabled but no jit_notify_* sink is configured")
	}

	complianceGen := compliance.NewReportGenerator(apiCfg.AuditLogDir, apiCfg.ConfigFile, dataDir)
	complianceGen.SetSubjectDataProvider(apiHandler.ComplianceDataProvider())
	complianceGen.SetQueryDataProvider(apiHandler.ComplianceDataProvider())
	apiHandler.SetCompliance(complianceGen)
	apiHandler.RegisterComplianceRoutes(s.mux)
	apiHandler.StartReportScheduler(s.backgroundCtx, api.ReportEmailConfig{
		SMTPAddr:     strings.TrimSpace(s.config.JITNotifySMTPAddr),
		SMTPUsername: strings.TrimSpace(s.config.JITNotifySMTPUsername),
		SMTPPassword: s.config.JITNotifySMTPPassword,
		EmailFrom:    strings.TrimSpace(s.config.JITNotifyEmailFrom),
	})

	// Page routes.
	s.mux.HandleFunc("GET /dashboard", s.handlePage("pages/dashboard.html", "Dashboard"))
	s.mux.HandleFunc("GET /sessions", s.handlePage("pages/sessions.html", "Sessions"))
	s.mux.HandleFunc("GET /users", s.handlePage("pages/users.html", "Users"))
	s.mux.HandleFunc("GET /servers", s.handlePage("pages/servers.html", "Servers"))
	s.mux.HandleFunc("GET /automation", s.handlePage("pages/automation.html", "Automation"))
	s.mux.HandleFunc("GET /audit", s.handlePage("pages/audit.html", "Audit Log"))
	s.mux.HandleFunc("GET /webhooks", s.handlePage("pages/webhooks.html", "Webhook Deliveries"))
	s.mux.HandleFunc("GET /settings", s.handlePage("pages/settings.html", "Settings"))
	s.mux.HandleFunc("GET /terminal", s.handlePage("pages/terminal.html", "Terminal"))

	// WebSocket terminal endpoint.
	s.mux.Handle("GET /ws/dashboard", s.handleDashboardStream())
	s.mux.Handle("GET /ws/sessions", s.handleSessionsStream())
	s.mux.Handle("GET /ws/sessions/{id}/live", s.handleSessionLiveStream())
	terminalHandler := &ws.TerminalHandler{
		ProxyAddr:               s.config.SSHProxyAddr,
		RecordingDir:            s.config.RecordingDir,
		RecordingBasePath:       terminalRecordingBasePath,
		TransferApprovalEnabled: s.config.DLPTransferApprovalEnabled,
		ClipboardAuditEnabled:   s.config.DLPClipboardAuditEnabled,
		TransferPolicy: dlp.NewFileTransferPolicy(dlp.FileTransferPolicyOptions{
			AllowNames:                dlp.ParsePatternList(s.config.DLPFileAllowNames),
			DenyNames:                 dlp.ParsePatternList(s.config.DLPFileDenyNames),
			AllowExtensions:           dlp.ParsePatternList(s.config.DLPFileAllowExtensions),
			DenyExtensions:            dlp.ParsePatternList(s.config.DLPFileDenyExtensions),
			AllowPaths:                dlp.ParsePatternList(s.config.DLPFileAllowPaths),
			DenyPaths:                 dlp.ParsePatternList(s.config.DLPFileDenyPaths),
			MaxUploadBytes:            s.config.DLPFileMaxUploadBytes,
			MaxDownloadBytes:          s.config.DLPFileMaxDownloadBytes,
			SensitiveScanEnabled:      s.config.DLPSensitiveScanEnabled,
			SensitiveDetectCreditCard: s.config.DLPSensitiveDetectCreditCard,
			SensitiveDetectCNIDCard:   s.config.DLPSensitiveDetectCNIDCard,
			SensitiveDetectAPIKey:     s.config.DLPSensitiveDetectAPIKey,
			SensitiveMaxScanBytes:     s.config.DLPSensitiveMaxScanBytes,
		}),
	}
	s.mux.Handle("GET /ws/terminal", terminalHandler)
	s.mux.HandleFunc("GET /api/v2/terminal/recordings/{id}/download", s.handleTerminalRecordingDownload(terminalHandler))

	// Catch-all: dashboard.
	s.mux.HandleFunc("GET /", s.handleIndex)
	return nil
}

// --------------------------------------------------------------------------
// Handlers
// --------------------------------------------------------------------------

// handleIndex renders the dashboard or redirects to login.
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		s.render(w, r, "pages/error.html", map[string]interface{}{
			"Title":      "Not Found",
			"StatusCode": 404,
			"Message":    "The page you are looking for does not exist.",
		})
		return
	}
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

// handlePage returns a handler that renders the named template with the given title.
func (s *Server) handlePage(tmplName, title string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.render(w, r, tmplName, map[string]interface{}{
			"Title": title,
		})
	}
}

// handleHealth returns a simple JSON health check.
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	// Try to reach the data plane — report its status alongside ours.
	dpHealth, err := s.dp.GetHealth()
	status := "healthy"
	if err != nil {
		status = "degraded"
	}
	resp := map[string]interface{}{
		"control_plane": status,
		"data_plane":    dpHealth,
	}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("health: encode: %v", err)
	}
}

// --------------------------------------------------------------------------
// Template rendering helper
// --------------------------------------------------------------------------

// render executes a named template inside the base layout and writes the
// result to w.  On error it logs and sends a 500 page.
func (s *Server) render(w http.ResponseWriter, r *http.Request, name string, data map[string]interface{}) {
	if data == nil {
		data = make(map[string]interface{})
	}
	if username := r.Header.Get("X-Auth-User"); username != "" {
		data["User"] = struct {
			Username string
		}{Username: username}
	}

	// Inject CSRF token for forms.
	if c, err := r.Cookie("csrf_token"); err == nil {
		data["CSRFToken"] = c.Value
	}

	t := s.tmpl.Lookup(name)
	if t == nil {
		// Fall back to a very simple page to avoid a nil-pointer panic.
		log.Printf("render: template %q not found", name)
		http.Error(w, "page not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.Execute(w, data); err != nil {
		log.Printf("render: execute %s: %v", name, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// respondJSON writes v as JSON with the given HTTP status code.
func respondJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("respondJSON: %v", err)
	}
}
