package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/config"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/middleware"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/models"
)

type requestLog struct {
	mu      sync.Mutex
	entries []string
}

func (l *requestLog) add(method, path string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, method+" "+path)
}

func (l *requestLog) count(entry string) int {
	l.mu.Lock()
	defer l.mu.Unlock()

	count := 0
	for _, seen := range l.entries {
		if seen == entry {
			count++
		}
	}
	return count
}

func newAuthorizedDataPlaneServer(t *testing.T, token string, handler http.HandlerFunc) (*httptest.Server, *requestLog) {
	t.Helper()

	log := &requestLog{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.add(r.Method, r.URL.Path)
		if got := r.Header.Get("Authorization"); got != "Bearer "+token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		handler(w, r)
	}))
	t.Cleanup(srv.Close)

	return srv, log
}

func newControlPlaneTestServer(t *testing.T, dataPlaneURL, token string) (*config.Config, *httptest.Server) {
	t.Helper()

	cfg := &config.Config{
		ListenAddr:     "127.0.0.1:0",
		DataPlaneAddr:  dataPlaneURL,
		DataPlaneToken: token,
		SessionSecret:  "integration-test-secret",
		AdminUser:      "admin",
		AuditLogDir:    t.TempDir(),
		RecordingDir:   t.TempDir(),
		DataDir:        t.TempDir(),
	}

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ts := httptest.NewServer(srv.srv.Handler)
	t.Cleanup(func() {
		_ = srv.Shutdown(context.Background())
		ts.Close()
	})
	return cfg, ts
}

func newAuthenticatedClient(t *testing.T, baseURL, sessionSecret string) *http.Client {
	t.Helper()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New() error = %v", err)
	}

	u, err := url.Parse(baseURL)
	if err != nil {
		t.Fatalf("url.Parse(%q) error = %v", baseURL, err)
	}

	jar.SetCookies(u, []*http.Cookie{
		middleware.CreateSessionCookieWithRole("admin", "admin", sessionSecret, time.Hour),
	})

	client := &http.Client{Jar: jar}
	return client
}

func mustRequest(t *testing.T, client *http.Client, method, requestURL string, body io.Reader, headers map[string]string) *http.Response {
	t.Helper()

	req, err := http.NewRequest(method, requestURL, body)
	if err != nil {
		t.Fatalf("http.NewRequest(%s %s) error = %v", method, requestURL, err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do(%s %s) error = %v", method, requestURL, err)
	}
	return resp
}

func mustReadBody(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll() error = %v", err)
	}
	return body
}

func mustDecodeJSON[T any](t *testing.T, resp *http.Response) T {
	t.Helper()

	body := mustReadBody(t, resp)
	var v T
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatalf("json.Unmarshal(%s) error = %v", string(body), err)
	}
	return v
}

func mustFetchCSRFToken(t *testing.T, client *http.Client, baseURL string) string {
	t.Helper()

	resp := mustRequest(t, client, http.MethodGet, baseURL+"/api/v2/system/info", nil, nil)
	if resp.StatusCode != http.StatusOK {
		body := string(mustReadBody(t, resp))
		t.Fatalf("GET /api/v2/system/info status = %d body = %s", resp.StatusCode, body)
	}
	_ = mustReadBody(t, resp)

	token := resp.Header.Get("X-CSRF-Token")
	if token == "" {
		t.Fatal("missing X-CSRF-Token response header")
	}
	return token
}

func TestControlPlaneDataPlaneE2E(t *testing.T) {
	const token = "dp-secret-token"

	sessionStart := time.Date(2026, 4, 7, 15, 0, 0, 0, time.UTC)
	dataPlane, requests := newAuthorizedDataPlaneServer(t, token, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/health":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(models.HealthStatus{
				Status:  "healthy",
				Version: "0.3.0",
				Uptime:  "1h23m",
			})
		case r.Method == http.MethodGet && r.URL.Path == "/metrics":
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = io.WriteString(w, "ssh_proxy_active_sessions 1\n")
		case r.Method == http.MethodGet && r.URL.Path == "/sessions":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]models.Session{
				{
					ID:         "sess-active",
					Username:   "alice",
					SourceIP:   "10.0.0.1",
					TargetHost: "db.internal",
					TargetPort: 22,
					StartTime:  sessionStart,
					Duration:   "15m",
					Status:     "active",
				},
				{
					ID:         "sess-closed",
					Username:   "bob",
					SourceIP:   "10.0.0.2",
					TargetHost: "web.internal",
					TargetPort: 22,
					StartTime:  sessionStart.Add(-time.Hour),
					Duration:   "1h",
					Status:     "terminated",
				},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/upstreams":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]models.Server{
				{
					ID:        "srv-1",
					Name:      "primary-db",
					Host:      "db.internal",
					Port:      22,
					Status:    "online",
					Healthy:   true,
					Weight:    1,
					CheckedAt: sessionStart,
				},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/config/reload":
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	})

	cfg, controlPlane := newControlPlaneTestServer(t, dataPlane.URL, token)
	client := newAuthenticatedClient(t, controlPlane.URL, cfg.SessionSecret)
	csrfToken := mustFetchCSRFToken(t, client, controlPlane.URL)

	t.Run("system health proxies data plane status", func(t *testing.T) {
		resp := mustRequest(t, client, http.MethodGet, controlPlane.URL+"/api/v2/system/health", nil, nil)
		if resp.StatusCode != http.StatusOK {
			body := string(mustReadBody(t, resp))
			t.Fatalf("GET /api/v2/system/health status = %d body = %s", resp.StatusCode, body)
		}

		payload := mustDecodeJSON[struct {
			Success bool `json:"success"`
			Data    struct {
				Status    string `json:"status"`
				DataPlane string `json:"data_plane"`
			} `json:"data"`
		}](t, resp)

		if !payload.Success {
			t.Fatal("expected success=true")
		}
		if payload.Data.Status != "healthy" {
			t.Fatalf("status = %q, want healthy", payload.Data.Status)
		}
		if payload.Data.DataPlane != "healthy" {
			t.Fatalf("data_plane = %q, want healthy", payload.Data.DataPlane)
		}
	})

	t.Run("system metrics proxies raw dataplane output", func(t *testing.T) {
		resp := mustRequest(t, client, http.MethodGet, controlPlane.URL+"/api/v2/system/metrics", nil, nil)
		if resp.StatusCode != http.StatusOK {
			body := string(mustReadBody(t, resp))
			t.Fatalf("GET /api/v2/system/metrics status = %d body = %s", resp.StatusCode, body)
		}

		body := string(mustReadBody(t, resp))
		if !strings.Contains(body, "ssh_proxy_active_sessions 1") {
			t.Fatalf("metrics body = %q, want dataplane metric", body)
		}
	})

	t.Run("servers route returns dataplane upstreams", func(t *testing.T) {
		resp := mustRequest(t, client, http.MethodGet, controlPlane.URL+"/api/v2/servers?page=1&per_page=1", nil, nil)
		if resp.StatusCode != http.StatusOK {
			body := string(mustReadBody(t, resp))
			t.Fatalf("GET /api/v2/servers status = %d body = %s", resp.StatusCode, body)
		}

		payload := mustDecodeJSON[struct {
			Success bool            `json:"success"`
			Data    []models.Server `json:"data"`
			Total   int             `json:"total"`
			Page    int             `json:"page"`
			PerPage int             `json:"per_page"`
		}](t, resp)

		if !payload.Success {
			t.Fatal("expected success=true")
		}
		if payload.Total != 1 || payload.Page != 1 || payload.PerPage != 1 {
			t.Fatalf("pagination = total:%d page:%d per_page:%d", payload.Total, payload.Page, payload.PerPage)
		}
		if len(payload.Data) != 1 || payload.Data[0].ID != "srv-1" {
			t.Fatalf("servers data = %+v", payload.Data)
		}
	})

	t.Run("sessions route filters dataplane sessions", func(t *testing.T) {
		resp := mustRequest(t, client, http.MethodGet, controlPlane.URL+"/api/v2/sessions?status=active", nil, nil)
		if resp.StatusCode != http.StatusOK {
			body := string(mustReadBody(t, resp))
			t.Fatalf("GET /api/v2/sessions status = %d body = %s", resp.StatusCode, body)
		}

		payload := mustDecodeJSON[struct {
			Success bool             `json:"success"`
			Data    []models.Session `json:"data"`
			Total   int              `json:"total"`
		}](t, resp)

		if !payload.Success {
			t.Fatal("expected success=true")
		}
		if payload.Total != 1 || len(payload.Data) != 1 {
			t.Fatalf("filtered sessions = total:%d len:%d", payload.Total, len(payload.Data))
		}
		if payload.Data[0].ID != "sess-active" {
			t.Fatalf("session ID = %q, want sess-active", payload.Data[0].ID)
		}
	})

	t.Run("config reload forwards csrf-protected POST to dataplane", func(t *testing.T) {
		resp := mustRequest(
			t,
			client,
			http.MethodPost,
			controlPlane.URL+"/api/v2/config/reload",
			bytes.NewBufferString("{}"),
			map[string]string{
				"Content-Type": "application/json",
				"X-CSRF-Token": csrfToken,
			},
		)
		if resp.StatusCode != http.StatusOK {
			body := string(mustReadBody(t, resp))
			t.Fatalf("POST /api/v2/config/reload status = %d body = %s", resp.StatusCode, body)
		}

		payload := mustDecodeJSON[struct {
			Success bool `json:"success"`
			Data    struct {
				Message string `json:"message"`
			} `json:"data"`
		}](t, resp)

		if !payload.Success {
			t.Fatal("expected success=true")
		}
		if payload.Data.Message != "configuration reloaded" {
			t.Fatalf("message = %q, want configuration reloaded", payload.Data.Message)
		}
	})

	for _, entry := range []string{
		"GET /health",
		"GET /metrics",
		"GET /upstreams",
		"GET /sessions",
		"POST /config/reload",
	} {
		if requests.count(entry) != 1 {
			t.Fatalf("%s count = %d, want 1", entry, requests.count(entry))
		}
	}
}

func TestSystemMetricsReturnsBadGatewayWhenDataPlaneFails(t *testing.T) {
	const token = "dp-secret-token"

	dataPlane, _ := newAuthorizedDataPlaneServer(t, token, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/metrics" {
			http.Error(w, "dataplane unavailable", http.StatusInternalServerError)
			return
		}
		http.NotFound(w, r)
	})

	cfg, controlPlane := newControlPlaneTestServer(t, dataPlane.URL, token)
	client := newAuthenticatedClient(t, controlPlane.URL, cfg.SessionSecret)

	resp := mustRequest(t, client, http.MethodGet, controlPlane.URL+"/api/v2/system/metrics", nil, nil)
	if resp.StatusCode != http.StatusBadGateway {
		body := string(mustReadBody(t, resp))
		t.Fatalf("GET /api/v2/system/metrics status = %d body = %s", resp.StatusCode, body)
	}

	payload := mustDecodeJSON[struct {
		Success bool   `json:"success"`
		Error   string `json:"error"`
	}](t, resp)

	if payload.Success {
		t.Fatal("expected success=false")
	}
	if !strings.Contains(payload.Error, "failed to fetch metrics") {
		t.Fatalf("error = %q, want dataplane fetch message", payload.Error)
	}
}

func TestAPIVersionAliasDelegatesToV2Routes(t *testing.T) {
	const token = "dp-secret-token"

	dataPlane, requests := newAuthorizedDataPlaneServer(t, token, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/health":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(models.HealthStatus{Status: "healthy", Version: "0.3.0", Uptime: "5m"})
		case r.Method == http.MethodGet && r.URL.Path == "/sessions":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]models.Session{
				{
					ID:         "sess-alias",
					Username:   "alice",
					SourceIP:   "10.0.0.8",
					TargetHost: "db.internal",
					TargetPort: 22,
					StartTime:  time.Date(2026, 4, 8, 9, 0, 0, 0, time.UTC),
					Duration:   "10m",
					Status:     "active",
				},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/upstreams":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]models.Server{})
		case r.Method == http.MethodPost && r.URL.Path == "/config/reload":
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	})

	cfg, controlPlane := newControlPlaneTestServer(t, dataPlane.URL, token)
	client := newAuthenticatedClient(t, controlPlane.URL, cfg.SessionSecret)
	csrfToken := mustFetchCSRFToken(t, client, controlPlane.URL)

	resp := mustRequest(t, client, http.MethodGet, controlPlane.URL+"/api/v3/sessions/sess-alias", nil, nil)
	if resp.StatusCode != http.StatusOK {
		body := string(mustReadBody(t, resp))
		t.Fatalf("GET /api/v3/sessions/sess-alias status = %d body = %s", resp.StatusCode, body)
	}
	payload := mustDecodeJSON[struct {
		Success bool           `json:"success"`
		Data    models.Session `json:"data"`
	}](t, resp)
	if !payload.Success || payload.Data.ID != "sess-alias" {
		t.Fatalf("unexpected v3 session payload: %+v", payload)
	}

	resp = mustRequest(
		t,
		client,
		http.MethodPost,
		controlPlane.URL+"/api/v3/config/reload",
		bytes.NewBufferString("{}"),
		map[string]string{
			"Content-Type": "application/json",
			"X-CSRF-Token": csrfToken,
		},
	)
	if resp.StatusCode != http.StatusOK {
		body := string(mustReadBody(t, resp))
		t.Fatalf("POST /api/v3/config/reload status = %d body = %s", resp.StatusCode, body)
	}
	_ = mustReadBody(t, resp)

	if requests.count("GET /sessions") != 1 {
		t.Fatalf("GET /sessions count = %d, want 1", requests.count("GET /sessions"))
	}
	if requests.count("POST /config/reload") != 1 {
		t.Fatalf("POST /config/reload count = %d, want 1", requests.count("POST /config/reload"))
	}
}

func TestPublicHealthReportsDegradedWhenDataPlaneHealthFails(t *testing.T) {
	const token = "dp-secret-token"

	dataPlane, requests := newAuthorizedDataPlaneServer(t, token, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/health" {
			http.Error(w, "health probe failed", http.StatusInternalServerError)
			return
		}
		http.NotFound(w, r)
	})

	_, controlPlane := newControlPlaneTestServer(t, dataPlane.URL, token)
	resp := mustRequest(t, http.DefaultClient, http.MethodGet, controlPlane.URL+"/api/v1/health", nil, nil)
	if resp.StatusCode != http.StatusOK {
		body := string(mustReadBody(t, resp))
		t.Fatalf("GET /api/v1/health status = %d body = %s", resp.StatusCode, body)
	}

	payload := mustDecodeJSON[struct {
		ControlPlane string `json:"control_plane"`
	}](t, resp)

	if payload.ControlPlane != "degraded" {
		t.Fatalf("control_plane = %q, want degraded", payload.ControlPlane)
	}
	if requests.count("GET /health") != 1 {
		t.Fatalf("GET /health count = %d, want 1", requests.count("GET /health"))
	}
}
