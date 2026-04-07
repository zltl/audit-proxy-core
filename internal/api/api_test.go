package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/models"
)

// mockDP implements DataPlaneClient for testing.
type mockDP struct {
	health    *models.HealthStatus
	sessions  []models.Session
	servers   []models.Server
	metrics   string
	config    map[string]interface{}
	killErr   error
	reloadErr error
}

func (m *mockDP) GetHealth() (*models.HealthStatus, error) {
	if m.health == nil {
		return &models.HealthStatus{Status: "healthy", Version: "1.0.0", Uptime: "100s"}, nil
	}
	return m.health, nil
}

func (m *mockDP) ListSessions() ([]models.Session, error) {
	return m.sessions, nil
}

func (m *mockDP) KillSession(id string) error {
	return m.killErr
}

func (m *mockDP) GetMetrics() (string, error) {
	return m.metrics, nil
}

func (m *mockDP) ListUpstreams() ([]models.Server, error) {
	return m.servers, nil
}

func (m *mockDP) ReloadConfig() error {
	return m.reloadErr
}

func (m *mockDP) GetConfig() (map[string]interface{}, error) {
	if m.config == nil {
		return map[string]interface{}{"listen_port": 2222}, nil
	}
	return m.config, nil
}

func setupTestAPI(t *testing.T) (*API, *http.ServeMux, *mockDP) {
	t.Helper()
	dir := t.TempDir()

	dp := &mockDP{
		sessions: []models.Session{
			{ID: "s1", Username: "alice", SourceIP: "10.0.0.1", TargetHost: "srv1.local", TargetPort: 22, Status: "active", StartTime: time.Now(), BytesIn: 100, BytesOut: 200},
			{ID: "s2", Username: "bob", SourceIP: "10.0.0.2", TargetHost: "srv2.local", TargetPort: 22, Status: "closed", StartTime: time.Now().Add(-time.Hour), BytesIn: 500, BytesOut: 1000},
			{ID: "s3", Username: "alice", SourceIP: "10.0.0.1", TargetHost: "srv3.local", TargetPort: 22, Status: "active", StartTime: time.Now(), RecordingFile: filepath.Join(dir, "rec-s3.cast")},
		},
		servers: []models.Server{
			{ID: "srv-1", Name: "server1", Host: "10.0.1.1", Port: 22, Status: "online", Healthy: true, Weight: 1},
			{ID: "srv-2", Name: "server2", Host: "10.0.1.2", Port: 22, Status: "offline", Healthy: false, Weight: 1},
		},
		metrics: "ssh_active_sessions 2\nssh_total_bytes 1800\n",
	}

	cfg := &Config{
		AdminUser:     "admin",
		AdminPassHash: "test",
		SessionSecret: "secret",
		AuditLogDir:   filepath.Join(dir, "audit"),
		RecordingDir:  dir,
		DataDir:       dir,
		ConfigFile:    filepath.Join(dir, "config.ini"),
		ConfigVerDir:  filepath.Join(dir, "config_versions"),
	}

	// Create audit log directory with sample events
	os.MkdirAll(cfg.AuditLogDir, 0755)
	auditData := []string{
		`{"id":"ev1","timestamp":"2024-01-15T10:00:00Z","event_type":"login","username":"alice","source_ip":"10.0.0.1","details":"successful login"}`,
		`{"id":"ev2","timestamp":"2024-01-15T11:00:00Z","event_type":"session_start","username":"bob","source_ip":"10.0.0.2","target_host":"srv1","details":"started session"}`,
		`{"id":"ev3","timestamp":"2024-01-15T12:00:00Z","event_type":"config_change","username":"admin","source_ip":"10.0.0.100","details":"updated listen port"}`,
	}
	os.WriteFile(filepath.Join(cfg.AuditLogDir, "audit-2024.jsonl"), []byte(strings.Join(auditData, "\n")+"\n"), 0644)

	// Write initial config file
	os.WriteFile(cfg.ConfigFile, []byte(`{"listen_port": 2222}`), 0644)

	api := New(dp, cfg)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)
	return api, mux, dp
}

func doRequest(mux *http.ServeMux, method, path string, body interface{}) *httptest.ResponseRecorder {
	var bodyReader io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		bodyReader = bytes.NewReader(data)
	}
	req := httptest.NewRequest(method, path, bodyReader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

func parseResponse(t *testing.T, rr *httptest.ResponseRecorder) APIResponse {
	t.Helper()
	var resp APIResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v\nbody: %s", err, rr.Body.String())
	}
	return resp
}

// ---- Tests ----

func TestSystemHealth(t *testing.T) {
	_, mux, _ := setupTestAPI(t)
	rr := doRequest(mux, "GET", "/api/v2/system/health", nil)
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	resp := parseResponse(t, rr)
	if !resp.Success {
		t.Fatal("expected success")
	}
	data := resp.Data.(map[string]interface{})
	if data["status"] != "healthy" {
		t.Errorf("expected healthy, got %v", data["status"])
	}
}

func TestSystemInfo(t *testing.T) {
	_, mux, _ := setupTestAPI(t)
	rr := doRequest(mux, "GET", "/api/v2/system/info", nil)
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	resp := parseResponse(t, rr)
	data := resp.Data.(map[string]interface{})
	if data["version"] != "2.0.0" {
		t.Errorf("expected version 2.0.0, got %v", data["version"])
	}
	if data["go_version"] == nil {
		t.Error("expected go_version")
	}
}

func TestSystemMetrics(t *testing.T) {
	_, mux, _ := setupTestAPI(t)
	rr := doRequest(mux, "GET", "/api/v2/system/metrics", nil)
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "ssh_active_sessions") {
		t.Error("expected metrics content")
	}
}

func TestDashboardStats(t *testing.T) {
	_, mux, _ := setupTestAPI(t)
	rr := doRequest(mux, "GET", "/api/v2/dashboard/stats", nil)
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	resp := parseResponse(t, rr)
	if !resp.Success {
		t.Fatal("expected success")
	}
	data := resp.Data.(map[string]interface{})
	if data["active_sessions"].(float64) != 2 {
		t.Errorf("expected 2 active sessions, got %v", data["active_sessions"])
	}
	if data["total_servers"].(float64) != 2 {
		t.Errorf("expected 2 total servers, got %v", data["total_servers"])
	}
}

func TestDashboardActivity(t *testing.T) {
	_, mux, _ := setupTestAPI(t)
	rr := doRequest(mux, "GET", "/api/v2/dashboard/activity", nil)
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	resp := parseResponse(t, rr)
	if resp.Total != 3 {
		t.Errorf("expected 3 activities, got %d", resp.Total)
	}
}

func TestListSessions(t *testing.T) {
	_, mux, _ := setupTestAPI(t)
	rr := doRequest(mux, "GET", "/api/v2/sessions", nil)
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	resp := parseResponse(t, rr)
	if resp.Total != 3 {
		t.Errorf("expected 3 sessions, got %d", resp.Total)
	}
}

func TestListSessionsFilterByStatus(t *testing.T) {
	_, mux, _ := setupTestAPI(t)
	rr := doRequest(mux, "GET", "/api/v2/sessions?status=active", nil)
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	resp := parseResponse(t, rr)
	if resp.Total != 2 {
		t.Errorf("expected 2 active sessions, got %d", resp.Total)
	}
}

func TestListSessionsFilterByUser(t *testing.T) {
	_, mux, _ := setupTestAPI(t)
	rr := doRequest(mux, "GET", "/api/v2/sessions?user=bob", nil)
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	resp := parseResponse(t, rr)
	if resp.Total != 1 {
		t.Errorf("expected 1 session for bob, got %d", resp.Total)
	}
}

func TestListSessionsPagination(t *testing.T) {
	_, mux, _ := setupTestAPI(t)
	rr := doRequest(mux, "GET", "/api/v2/sessions?page=1&per_page=2", nil)
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	resp := parseResponse(t, rr)
	if resp.Total != 3 {
		t.Errorf("expected total 3, got %d", resp.Total)
	}
	if resp.PerPage != 2 {
		t.Errorf("expected per_page 2, got %d", resp.PerPage)
	}
	items := resp.Data.([]interface{})
	if len(items) != 2 {
		t.Errorf("expected 2 items on page 1, got %d", len(items))
	}
}

func TestGetSession(t *testing.T) {
	_, mux, _ := setupTestAPI(t)
	rr := doRequest(mux, "GET", "/api/v2/sessions/s1", nil)
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	resp := parseResponse(t, rr)
	data := resp.Data.(map[string]interface{})
	if data["id"] != "s1" {
		t.Errorf("expected id s1, got %v", data["id"])
	}
}

func TestGetSessionNotFound(t *testing.T) {
	_, mux, _ := setupTestAPI(t)
	rr := doRequest(mux, "GET", "/api/v2/sessions/nonexistent", nil)
	if rr.Code != 404 {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
}

func TestKillSession(t *testing.T) {
	_, mux, _ := setupTestAPI(t)
	rr := doRequest(mux, "DELETE", "/api/v2/sessions/s1", nil)
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	resp := parseResponse(t, rr)
	if !resp.Success {
		t.Error("expected success")
	}
}

func TestBulkKillSessions(t *testing.T) {
	_, mux, _ := setupTestAPI(t)
	rr := doRequest(mux, "POST", "/api/v2/sessions/bulk-kill", map[string]interface{}{
		"ids": []string{"s1", "s2"},
	})
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	resp := parseResponse(t, rr)
	if !resp.Success {
		t.Error("expected success")
	}
}

func TestBulkKillSessionsEmptyIDs(t *testing.T) {
	_, mux, _ := setupTestAPI(t)
	rr := doRequest(mux, "POST", "/api/v2/sessions/bulk-kill", map[string]interface{}{
		"ids": []string{},
	})
	if rr.Code != 400 {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestGetRecording(t *testing.T) {
	_, mux, _ := setupTestAPI(t)
	rr := doRequest(mux, "GET", "/api/v2/sessions/s3/recording", nil)
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestGetRecordingNoFile(t *testing.T) {
	_, mux, _ := setupTestAPI(t)
	rr := doRequest(mux, "GET", "/api/v2/sessions/s1/recording", nil)
	if rr.Code != 404 {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
}

func TestCreateAndGetUser(t *testing.T) {
	_, mux, _ := setupTestAPI(t)

	// Create user
	rr := doRequest(mux, "POST", "/api/v2/users", map[string]interface{}{
		"username":     "testuser",
		"display_name": "Test User",
		"email":        "test@example.com",
		"password":     "securepassword123",
		"role":         "viewer",
	})
	if rr.Code != 201 {
		t.Fatalf("expected 201, got %d: %s", rr.Code, rr.Body.String())
	}

	// Get user
	rr = doRequest(mux, "GET", "/api/v2/users/testuser", nil)
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	resp := parseResponse(t, rr)
	data := resp.Data.(map[string]interface{})
	if data["username"] != "testuser" {
		t.Errorf("expected testuser, got %v", data["username"])
	}
}

func TestCreateUserDuplicate(t *testing.T) {
	_, mux, _ := setupTestAPI(t)

	body := map[string]interface{}{
		"username": "dup",
		"password": "securepassword123",
	}
	doRequest(mux, "POST", "/api/v2/users", body)
	rr := doRequest(mux, "POST", "/api/v2/users", body)
	if rr.Code != 409 {
		t.Fatalf("expected 409, got %d", rr.Code)
	}
}

func TestCreateUserValidation(t *testing.T) {
	_, mux, _ := setupTestAPI(t)
	rr := doRequest(mux, "POST", "/api/v2/users", map[string]interface{}{
		"username": "",
		"password": "",
	})
	if rr.Code != 400 {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestUpdateUser(t *testing.T) {
	_, mux, _ := setupTestAPI(t)

	doRequest(mux, "POST", "/api/v2/users", map[string]interface{}{
		"username": "updatable",
		"password": "securepassword123",
		"email":    "old@example.com",
	})

	rr := doRequest(mux, "PUT", "/api/v2/users/updatable", map[string]interface{}{
		"email": "new@example.com",
	})
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	resp := parseResponse(t, rr)
	data := resp.Data.(map[string]interface{})
	if data["email"] != "new@example.com" {
		t.Errorf("expected new email, got %v", data["email"])
	}
}

func TestDeleteUser(t *testing.T) {
	_, mux, _ := setupTestAPI(t)

	doRequest(mux, "POST", "/api/v2/users", map[string]interface{}{
		"username": "deleteme",
		"password": "securepassword123",
	})

	rr := doRequest(mux, "DELETE", "/api/v2/users/deleteme", nil)
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	rr = doRequest(mux, "GET", "/api/v2/users/deleteme", nil)
	if rr.Code != 404 {
		t.Fatalf("expected 404 after deletion, got %d", rr.Code)
	}
}

func TestDeleteUserNotFound(t *testing.T) {
	_, mux, _ := setupTestAPI(t)
	rr := doRequest(mux, "DELETE", "/api/v2/users/ghost", nil)
	if rr.Code != 404 {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
}

func TestChangePassword(t *testing.T) {
	_, mux, _ := setupTestAPI(t)

	doRequest(mux, "POST", "/api/v2/users", map[string]interface{}{
		"username": "pwduser",
		"password": "oldpassword123",
	})

	rr := doRequest(mux, "PUT", "/api/v2/users/pwduser/password", map[string]interface{}{
		"new_password": "newpassword456",
	})
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestChangePasswordTooShort(t *testing.T) {
	_, mux, _ := setupTestAPI(t)

	doRequest(mux, "POST", "/api/v2/users", map[string]interface{}{
		"username": "pwduser2",
		"password": "oldpassword123",
	})

	rr := doRequest(mux, "PUT", "/api/v2/users/pwduser2/password", map[string]interface{}{
		"new_password": "short",
	})
	if rr.Code != 400 {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestConfigureMFA(t *testing.T) {
	_, mux, _ := setupTestAPI(t)

	doRequest(mux, "POST", "/api/v2/users", map[string]interface{}{
		"username": "mfauser",
		"password": "securepassword123",
	})

	rr := doRequest(mux, "PUT", "/api/v2/users/mfauser/mfa", map[string]interface{}{
		"enabled": true,
	})
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	resp := parseResponse(t, rr)
	data := resp.Data.(map[string]interface{})
	if data["mfa_enabled"] != true {
		t.Error("expected mfa_enabled true")
	}
	if data["secret"] == nil || data["secret"] == "" {
		t.Error("expected secret")
	}
	if data["otpauth_uri"] == nil {
		t.Error("expected otpauth_uri")
	}
}

func TestMFAQRCode(t *testing.T) {
	_, mux, _ := setupTestAPI(t)

	doRequest(mux, "POST", "/api/v2/users", map[string]interface{}{
		"username": "qruser",
		"password": "securepassword123",
	})
	doRequest(mux, "PUT", "/api/v2/users/qruser/mfa", map[string]interface{}{
		"enabled": true,
	})

	rr := doRequest(mux, "GET", "/api/v2/users/qruser/mfa/qrcode", nil)
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	resp := parseResponse(t, rr)
	data := resp.Data.(map[string]interface{})
	if !strings.HasPrefix(data["otpauth_uri"].(string), "otpauth://totp/SSHProxy:qruser") {
		t.Errorf("unexpected otpauth_uri: %v", data["otpauth_uri"])
	}
}

func TestMFAQRCodeNotEnabled(t *testing.T) {
	_, mux, _ := setupTestAPI(t)

	doRequest(mux, "POST", "/api/v2/users", map[string]interface{}{
		"username": "nomfa",
		"password": "securepassword123",
	})

	rr := doRequest(mux, "GET", "/api/v2/users/nomfa/mfa/qrcode", nil)
	if rr.Code != 400 {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestListServers(t *testing.T) {
	_, mux, _ := setupTestAPI(t)
	rr := doRequest(mux, "GET", "/api/v2/servers", nil)
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	resp := parseResponse(t, rr)
	if resp.Total != 2 {
		t.Errorf("expected 2 servers, got %d", resp.Total)
	}
}

func TestAddAndGetServer(t *testing.T) {
	_, mux, _ := setupTestAPI(t)

	rr := doRequest(mux, "POST", "/api/v2/servers", map[string]interface{}{
		"name": "new-server",
		"host": "10.0.2.1",
		"port": 22,
	})
	if rr.Code != 201 {
		t.Fatalf("expected 201, got %d: %s", rr.Code, rr.Body.String())
	}
	resp := parseResponse(t, rr)
	data := resp.Data.(map[string]interface{})
	serverID := data["id"].(string)

	rr = doRequest(mux, "GET", "/api/v2/servers/"+serverID, nil)
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestAddServerValidation(t *testing.T) {
	_, mux, _ := setupTestAPI(t)
	rr := doRequest(mux, "POST", "/api/v2/servers", map[string]interface{}{
		"name": "bad",
	})
	if rr.Code != 400 {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestDeleteServer(t *testing.T) {
	_, mux, _ := setupTestAPI(t)

	rr := doRequest(mux, "POST", "/api/v2/servers", map[string]interface{}{
		"name": "temp", "host": "10.0.3.1", "port": 22,
	})
	resp := parseResponse(t, rr)
	data := resp.Data.(map[string]interface{})
	id := data["id"].(string)

	rr = doRequest(mux, "DELETE", "/api/v2/servers/"+id, nil)
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestToggleMaintenance(t *testing.T) {
	_, mux, _ := setupTestAPI(t)

	rr := doRequest(mux, "POST", "/api/v2/servers", map[string]interface{}{
		"name": "maint-test", "host": "10.0.4.1", "port": 22,
	})
	resp := parseResponse(t, rr)
	data := resp.Data.(map[string]interface{})
	id := data["id"].(string)

	rr = doRequest(mux, "PUT", "/api/v2/servers/"+id+"/maintenance", map[string]interface{}{
		"maintenance": true,
	})
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	resp = parseResponse(t, rr)
	data = resp.Data.(map[string]interface{})
	if data["status"] != "draining" {
		t.Errorf("expected draining, got %v", data["status"])
	}
}

func TestServersHealth(t *testing.T) {
	_, mux, _ := setupTestAPI(t)
	rr := doRequest(mux, "GET", "/api/v2/servers/health", nil)
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	resp := parseResponse(t, rr)
	data := resp.Data.(map[string]interface{})
	if data["healthy"].(float64) != 1 {
		t.Errorf("expected 1 healthy, got %v", data["healthy"])
	}
}

func TestListAuditEvents(t *testing.T) {
	_, mux, _ := setupTestAPI(t)
	rr := doRequest(mux, "GET", "/api/v2/audit/events", nil)
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	resp := parseResponse(t, rr)
	if resp.Total != 3 {
		t.Errorf("expected 3 events, got %d", resp.Total)
	}
}

func TestListAuditEventsFilterByType(t *testing.T) {
	_, mux, _ := setupTestAPI(t)
	rr := doRequest(mux, "GET", "/api/v2/audit/events?type=login", nil)
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	resp := parseResponse(t, rr)
	if resp.Total != 1 {
		t.Errorf("expected 1 login event, got %d", resp.Total)
	}
}

func TestGetAuditEvent(t *testing.T) {
	_, mux, _ := setupTestAPI(t)
	rr := doRequest(mux, "GET", "/api/v2/audit/events/ev1", nil)
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestGetAuditEventNotFound(t *testing.T) {
	_, mux, _ := setupTestAPI(t)
	rr := doRequest(mux, "GET", "/api/v2/audit/events/evXXX", nil)
	if rr.Code != 404 {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
}

func TestSearchAudit(t *testing.T) {
	_, mux, _ := setupTestAPI(t)
	rr := doRequest(mux, "GET", "/api/v2/audit/search?q=alice", nil)
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	resp := parseResponse(t, rr)
	if resp.Total != 1 {
		t.Errorf("expected 1 result for alice, got %d", resp.Total)
	}
}

func TestSearchAuditMissingQuery(t *testing.T) {
	_, mux, _ := setupTestAPI(t)
	rr := doRequest(mux, "GET", "/api/v2/audit/search", nil)
	if rr.Code != 400 {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestExportAuditCSV(t *testing.T) {
	_, mux, _ := setupTestAPI(t)
	rr := doRequest(mux, "GET", "/api/v2/audit/export", nil)
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "text/csv" {
		t.Errorf("expected text/csv, got %s", ct)
	}
	if !strings.Contains(rr.Body.String(), "id,timestamp,event_type") {
		t.Error("expected CSV header")
	}
}

func TestAuditStats(t *testing.T) {
	_, mux, _ := setupTestAPI(t)
	rr := doRequest(mux, "GET", "/api/v2/audit/stats", nil)
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	resp := parseResponse(t, rr)
	data := resp.Data.(map[string]interface{})
	if data["total"].(float64) != 3 {
		t.Errorf("expected 3 total events, got %v", data["total"])
	}
}

func TestGetConfig(t *testing.T) {
	_, mux, _ := setupTestAPI(t)
	rr := doRequest(mux, "GET", "/api/v2/config", nil)
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestUpdateConfigAndVersioning(t *testing.T) {
	_, mux, _ := setupTestAPI(t)

	rr := doRequest(mux, "PUT", "/api/v2/config", map[string]interface{}{
		"listen_port": 3333,
	})
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Check that a version was saved
	rr = doRequest(mux, "GET", "/api/v2/config/versions", nil)
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	resp := parseResponse(t, rr)
	versions := resp.Data.([]interface{})
	if len(versions) == 0 {
		t.Error("expected at least one config version")
	}
}

func TestReloadConfig(t *testing.T) {
	_, mux, _ := setupTestAPI(t)
	rr := doRequest(mux, "POST", "/api/v2/config/reload", nil)
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestListUsers(t *testing.T) {
	_, mux, _ := setupTestAPI(t)

	doRequest(mux, "POST", "/api/v2/users", map[string]interface{}{
		"username": "u1", "password": "password123",
	})
	doRequest(mux, "POST", "/api/v2/users", map[string]interface{}{
		"username": "u2", "password": "password123",
	})

	rr := doRequest(mux, "GET", "/api/v2/users", nil)
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	resp := parseResponse(t, rr)
	if resp.Total != 2 {
		t.Errorf("expected 2 users, got %d", resp.Total)
	}
}

func TestGetUserNotFound(t *testing.T) {
	_, mux, _ := setupTestAPI(t)
	rr := doRequest(mux, "GET", "/api/v2/users/nobody", nil)
	if rr.Code != 404 {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
}

func TestWriteJSONHelper(t *testing.T) {
	rr := httptest.NewRecorder()
	writeJSON(rr, 200, map[string]string{"key": "value"})
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected application/json, got %s", ct)
	}
}

func TestWriteErrorHelper(t *testing.T) {
	rr := httptest.NewRecorder()
	writeError(rr, 500, "something went wrong")
	if rr.Code != 500 {
		t.Fatalf("expected 500, got %d", rr.Code)
	}
	var resp APIResponse
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Error != "something went wrong" {
		t.Errorf("expected error message, got %v", resp.Error)
	}
}

func TestParsePagination(t *testing.T) {
	req := httptest.NewRequest("GET", "/test?page=3&per_page=25", nil)
	page, perPage := parsePagination(req)
	if page != 3 {
		t.Errorf("expected page 3, got %d", page)
	}
	if perPage != 25 {
		t.Errorf("expected per_page 25, got %d", perPage)
	}
}

func TestParsePaginationDefaults(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	page, perPage := parsePagination(req)
	if page != 1 {
		t.Errorf("expected page 1, got %d", page)
	}
	if perPage != 50 {
		t.Errorf("expected per_page 50, got %d", perPage)
	}
}

func TestReadJSONEmptyBody(t *testing.T) {
	req := httptest.NewRequest("POST", "/test", strings.NewReader(""))
	var dst map[string]interface{}
	err := readJSON(req, &dst)
	if err == nil {
		t.Fatal("expected error for empty body")
	}
}

func TestReadJSONInvalidJSON(t *testing.T) {
	req := httptest.NewRequest("POST", "/test", strings.NewReader("{invalid"))
	var dst map[string]interface{}
	err := readJSON(req, &dst)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestConfigSanitization(t *testing.T) {
	_, mux, dp := setupTestAPI(t)
	dp.config = map[string]interface{}{
		"listen_port": 2222,
		"password":    "secret123",
		"api_token":   "tok-123",
		"nested": map[string]interface{}{
			"private_key": "abc123",
		},
	}
	rr := doRequest(mux, "GET", "/api/v2/config", nil)
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if strings.Contains(body, "secret123") {
		t.Error("config should not contain raw password")
	}
	if strings.Contains(body, "tok-123") {
		t.Error("config should not contain raw token")
	}
	if strings.Contains(body, "abc123") {
		t.Error("config should not contain raw private_key")
	}
}

func TestConfigRollback(t *testing.T) {
	api, mux, _ := setupTestAPI(t)

	// Write initial config
	os.WriteFile(api.config.ConfigFile, []byte(`{"listen_port": 2222}`), 0644)

	// Update config to create a version
	doRequest(mux, "PUT", "/api/v2/config", map[string]interface{}{"listen_port": 3333})

	// List versions
	rr := doRequest(mux, "GET", "/api/v2/config/versions", nil)
	resp := parseResponse(t, rr)
	versions := resp.Data.([]interface{})
	if len(versions) == 0 {
		t.Fatal("expected at least one version")
	}

	ver := versions[0].(map[string]interface{})["version"].(string)

	// Rollback
	rr = doRequest(mux, "POST", "/api/v2/config/rollback", map[string]interface{}{
		"version": ver,
	})
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHashAndCheckPassword(t *testing.T) {
	hash := hashPassword("mypassword")
	if !checkPassword("mypassword", hash) {
		t.Error("password check failed for correct password")
	}
	if checkPassword("wrongpassword", hash) {
		t.Error("password check should fail for wrong password")
	}
}
