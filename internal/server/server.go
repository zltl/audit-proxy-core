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
	"net/http"
	"strings"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/api"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/cmdctrl"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/collab"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/config"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/dataplane"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/middleware"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/oidc"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/ws"
	"github.com/ssh-proxy-core/ssh-proxy-core/web"
)

// Server is the top-level HTTP server for the control-plane.
type Server struct {
	config         *config.Config
	mux            *http.ServeMux
	dp             *dataplane.Client
	tmpl           *template.Template
	srv            *http.Server
	oidcProvider   *oidc.Provider
	oidcRoleMapper *oidc.RoleMapping
}

// New creates a fully-initialised Server.  It loads templates, builds the
// middleware chain, and registers every route.
func New(cfg *config.Config) (*Server, error) {
	dp := dataplane.New(cfg.DataPlaneAddr, cfg.DataPlaneToken)

	tmpl, err := loadTemplates()
	if err != nil {
		return nil, fmt.Errorf("server: load templates: %w", err)
	}

	s := &Server{
		config: cfg,
		mux:    http.NewServeMux(),
		dp:     dp,
		tmpl:   tmpl,
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

	s.routes()

	handler := middleware.Chain(
		s.mux,
		middleware.Recovery,
		middleware.Logger,
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

	return s, nil
}

// Start begins listening.  If both TLSCert and TLSKey are configured it
// serves HTTPS; otherwise plain HTTP.
func (s *Server) Start() error {
	if s.config.TLSCert != "" && s.config.TLSKey != "" {
		log.Printf("control-plane listening on %s (TLS)", s.config.ListenAddr)
		return s.srv.ListenAndServeTLS(s.config.TLSCert, s.config.TLSKey)
	}
	log.Printf("control-plane listening on %s", s.config.ListenAddr)
	return s.srv.ListenAndServe()
}

// Shutdown gracefully drains in-flight connections.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
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
func (s *Server) routes() {
	// Static assets — served from the embedded FS (or external dir override).
	staticFS, err := fs.Sub(web.EmbeddedFS, "static")
	if err != nil {
		log.Fatalf("server: embedded static sub: %v", err)
	}
	if s.config.StaticDir != "" {
		s.mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir(s.config.StaticDir))))
	} else {
		s.mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))
	}

	// Auth routes.
	s.mux.HandleFunc("GET /login", s.handleLoginPage)
	s.mux.HandleFunc("POST /login", s.handleLoginSubmit)
	s.mux.HandleFunc("POST /logout", s.handleLogout)
	s.mux.HandleFunc("GET /api/v1/auth/me", s.handleAuthMe)

	// OIDC routes (registered even if disabled — handlers check the flag).
	s.registerOIDCRoutes()

	// Health (public).
	s.mux.HandleFunc("GET /api/v1/health", s.handleHealth)

	// REST API v2 — delegate to api package.
	apiCfg := &api.Config{
		AdminUser:     s.config.AdminUser,
		AdminPassHash: s.config.AdminPassHash,
		SessionSecret: s.config.SessionSecret,
		AuditLogDir:   s.config.AuditLogDir,
		RecordingDir:  s.config.RecordingDir,
	}
	apiHandler := api.New(s.dp, apiCfg)
	apiHandler.RegisterRoutes(s.mux)

	// Command control — policy engine + real-time approvals.
	dataDir := apiCfg.DataDir
	if dataDir == "" {
		dataDir = "."
	}
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

	// Page routes.
	s.mux.HandleFunc("GET /dashboard", s.handlePage("pages/dashboard.html", "Dashboard"))
	s.mux.HandleFunc("GET /sessions", s.handlePage("pages/sessions.html", "Sessions"))
	s.mux.HandleFunc("GET /users", s.handlePage("pages/users.html", "Users"))
	s.mux.HandleFunc("GET /servers", s.handlePage("pages/servers.html", "Servers"))
	s.mux.HandleFunc("GET /audit", s.handlePage("pages/audit.html", "Audit Log"))
	s.mux.HandleFunc("GET /settings", s.handlePage("pages/settings.html", "Settings"))
	s.mux.HandleFunc("GET /terminal", s.handlePage("pages/terminal.html", "Terminal"))

	// WebSocket terminal endpoint.
	s.mux.Handle("/ws/terminal", &ws.TerminalHandler{
		ProxyAddr: s.config.DataPlaneAddr,
	})

	// Catch-all: dashboard.
	s.mux.HandleFunc("GET /", s.handleIndex)
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
	data["User"] = r.Header.Get("X-Auth-User")

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
