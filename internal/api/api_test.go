package api

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/cmdctrl"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/discovery"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/models"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/sshca"
	"golang.org/x/crypto/ssh"
)

// mockDP implements DataPlaneClient for testing.
type mockDP struct {
	health    *models.HealthStatus
	sessions  []models.Session
	servers   []models.Server
	metrics   string
	config    map[string]interface{}
	drain     *models.DrainStatus
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
	if m.killErr == nil {
		filtered := m.sessions[:0]
		for _, session := range m.sessions {
			if session.ID != id {
				filtered = append(filtered, session)
			}
		}
		m.sessions = filtered
	}
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

func (m *mockDP) GetDrainStatus() (*models.DrainStatus, error) {
	if m.drain == nil {
		return &models.DrainStatus{Status: "healthy", Draining: false, ActiveSessions: len(m.sessions)}, nil
	}
	cloned := *m.drain
	return &cloned, nil
}

func (m *mockDP) SetDrainMode(draining bool) (*models.DrainStatus, error) {
	if m.drain == nil {
		m.drain = &models.DrainStatus{}
	}
	m.drain.Draining = draining
	if draining {
		m.drain.Status = "draining"
	} else {
		m.drain.Status = "healthy"
	}
	m.drain.ActiveSessions = len(m.sessions)
	cloned := *m.drain
	return &cloned, nil
}

func setupTestAPI(t *testing.T) (*API, *http.ServeMux, *mockDP) {
	t.Helper()
	dir := t.TempDir()

	dp := &mockDP{
		sessions: []models.Session{
			{ID: "s1", Username: "alice", SourceIP: "10.0.0.1", ClientVersion: "OpenSSH_9.7p1 Ubuntu-7ubuntu4", ClientOS: "Ubuntu/Linux", DeviceFingerprint: "sshfp-4d2d9f6a1f0ef8e0", TargetHost: "srv1.local", TargetPort: 22, Status: "active", StartTime: time.Now(), BytesIn: 100, BytesOut: 200},
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

	api, err := New(dp, cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = api.Close() })
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
	items := resp.Data.([]interface{})
	first := items[0].(map[string]interface{})
	if first["client_version"] != "OpenSSH_9.7p1 Ubuntu-7ubuntu4" {
		t.Fatalf("expected client version in list response, got %v", first["client_version"])
	}
}

func TestListServersIncludesStoredServers(t *testing.T) {
	_, mux, _ := setupTestAPI(t)

	create := doRequest(mux, "POST", "/api/v2/servers", map[string]interface{}{
		"name":  "server3",
		"host":  "10.0.1.3",
		"port":  22,
		"group": "production",
	})
	if create.Code != http.StatusCreated {
		t.Fatalf("expected 201 when creating server, got %d: %s", create.Code, create.Body.String())
	}

	rr := doRequest(mux, "GET", "/api/v2/servers", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	resp := parseResponse(t, rr)
	if resp.Total != 3 {
		t.Fatalf("expected 3 servers after merge, got %d", resp.Total)
	}

	items, ok := resp.Data.([]interface{})
	if !ok {
		t.Fatalf("expected []interface{} payload, got %T", resp.Data)
	}

	found := false
	for _, item := range items {
		server, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		if server["host"] == "10.0.1.3" {
			found = true
			if server["group"] != "production" {
				t.Fatalf("expected merged server group to be preserved, got %v", server["group"])
			}
		}
	}

	if !found {
		t.Fatal("expected newly stored server to appear in merged list response")
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

func TestListSessionsFilterByIP(t *testing.T) {
	_, mux, _ := setupTestAPI(t)
	rr := doRequest(mux, "GET", "/api/v2/sessions?ip=10.0.0.1", nil)
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	resp := parseResponse(t, rr)
	if resp.Total != 2 {
		t.Errorf("expected 2 sessions for IP 10.0.0.1, got %d", resp.Total)
	}
}

func TestListSessionsFilterByTarget(t *testing.T) {
	_, mux, _ := setupTestAPI(t)
	rr := doRequest(mux, "GET", "/api/v2/sessions?target=srv3", nil)
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	resp := parseResponse(t, rr)
	if resp.Total != 1 {
		t.Errorf("expected 1 session for target srv3, got %d", resp.Total)
	}
}

func TestListSessionsFiltersSupportPartialCaseInsensitiveMatch(t *testing.T) {
	_, mux, _ := setupTestAPI(t)
	rr := doRequest(mux, "GET", "/api/v2/sessions?user=ALI&ip=10.0.0&target=SRV3", nil)
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	resp := parseResponse(t, rr)
	if resp.Total != 1 {
		t.Errorf("expected 1 session for partial filters, got %d", resp.Total)
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
	if data["client_os"] != "Ubuntu/Linux" {
		t.Fatalf("expected client_os, got %v", data["client_os"])
	}
	if data["device_fingerprint"] != "sshfp-4d2d9f6a1f0ef8e0" {
		t.Fatalf("expected device_fingerprint, got %v", data["device_fingerprint"])
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

func TestDownloadRecording(t *testing.T) {
	_, mux, dp := setupTestAPI(t)
	if err := os.WriteFile(dp.sessions[2].RecordingFile, []byte("{\"version\":2}\n[0.1,\"o\",\"hello\"]\n"), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	rr := doRequest(mux, "GET", "/api/v2/sessions/s3/recording/download", nil)
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Content-Type"); !strings.Contains(got, "application/x-asciicast") {
		t.Fatalf("unexpected content type: %s", got)
	}
	if !strings.Contains(rr.Body.String(), "\"version\":2") {
		t.Fatalf("expected recording payload, got %q", rr.Body.String())
	}
}

func TestDownloadRecordingRejectsOutsideDir(t *testing.T) {
	_, mux, dp := setupTestAPI(t)
	dp.sessions[2].RecordingFile = filepath.Join(filepath.Dir(dp.sessions[2].RecordingFile), "..", "outside.cast")
	rr := doRequest(mux, "GET", "/api/v2/sessions/s3/recording/download", nil)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rr.Code, rr.Body.String())
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

func TestConfigDiffPreviewSanitizesSecretsAndShowsChanges(t *testing.T) {
	api, mux, _ := setupTestAPI(t)
	if err := os.WriteFile(api.config.ConfigFile, []byte(`{"listen_port":2222,"api_token":"tok-123","nested":{"private_key":"abc123"}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	rr := doRequest(mux, "POST", "/api/v2/config/diff", map[string]interface{}{
		"to_config": map[string]interface{}{
			"listen_port": 3333,
			"api_token":   redactedConfigValue,
			"nested": map[string]interface{}{
				"private_key": redactedConfigValue,
			},
		},
	})
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	resp := parseResponse(t, rr)
	data := resp.Data.(map[string]interface{})
	if changed, ok := data["changed"].(bool); !ok || !changed {
		t.Fatalf("expected changed=true, got %#v", data["changed"])
	}
	diff := data["diff"].(string)
	if !strings.Contains(diff, `-  "listen_port": 2222`) || !strings.Contains(diff, `+  "listen_port": 3333`) {
		t.Fatalf("unexpected diff output: %s", diff)
	}
	if strings.Contains(diff, "tok-123") || strings.Contains(diff, "abc123") {
		t.Fatalf("diff leaked sensitive data: %s", diff)
	}
}

func TestUpdateConfigPreservesRedactedSecrets(t *testing.T) {
	api, mux, _ := setupTestAPI(t)
	if err := os.WriteFile(api.config.ConfigFile, []byte(`{"listen_port":2222,"api_token":"tok-123","nested":{"private_key":"abc123"}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	rr := doRequest(mux, "PUT", "/api/v2/config", map[string]interface{}{
		"listen_port": 3333,
		"api_token":   redactedConfigValue,
		"nested": map[string]interface{}{
			"private_key": redactedConfigValue,
		},
	})
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	raw, err := os.ReadFile(api.config.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	var stored map[string]interface{}
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatal(err)
	}
	if stored["api_token"] != "tok-123" {
		t.Fatalf("expected api_token to be preserved, got %#v", stored["api_token"])
	}
	nested := stored["nested"].(map[string]interface{})
	if nested["private_key"] != "abc123" {
		t.Fatalf("expected private_key to be preserved, got %#v", nested["private_key"])
	}
}

func TestConfigVersionEndpointsSanitizeSnapshotAndDiff(t *testing.T) {
	api, mux, _ := setupTestAPI(t)
	if err := os.WriteFile(api.config.ConfigFile, []byte(`{"listen_port":2222,"api_token":"tok-123"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if rr := doRequest(mux, "PUT", "/api/v2/config", map[string]interface{}{
		"listen_port": 3333,
		"api_token":   redactedConfigValue,
	}); rr.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	listRR := doRequest(mux, "GET", "/api/v2/config/versions", nil)
	listResp := parseResponse(t, listRR)
	versions := listResp.Data.([]interface{})
	if len(versions) == 0 {
		t.Fatal("expected at least one version")
	}
	version := versions[0].(map[string]interface{})["version"].(string)

	getRR := doRequest(mux, "GET", "/api/v2/config/versions/"+version, nil)
	if getRR.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", getRR.Code, getRR.Body.String())
	}
	if strings.Contains(getRR.Body.String(), "tok-123") {
		t.Fatalf("version endpoint leaked secret: %s", getRR.Body.String())
	}
	if !strings.Contains(getRR.Body.String(), redactedConfigValue) {
		t.Fatalf("expected version endpoint to redact secrets: %s", getRR.Body.String())
	}

	diffRR := doRequest(mux, "POST", "/api/v2/config/diff", map[string]interface{}{
		"from_version": version,
		"to_version":   "current",
	})
	if diffRR.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", diffRR.Code, diffRR.Body.String())
	}
	diffResp := parseResponse(t, diffRR)
	diff := diffResp.Data.(map[string]interface{})["diff"].(string)
	if !strings.Contains(diff, `-  "listen_port": 2222`) || !strings.Contains(diff, `+  "listen_port": 3333`) {
		t.Fatalf("unexpected version diff: %s", diff)
	}
	if strings.Contains(diff, "tok-123") {
		t.Fatalf("version diff leaked secret: %s", diff)
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

func TestDiscoveryRegisterCreatesManagedServer(t *testing.T) {
	api, mux, _ := setupTestAPI(t)
	ds := api.initDiscovery()
	ds.inventory.AddFromScan([]discovery.ScanResult{
		{
			Host:       "10.2.0.5",
			Port:       22,
			IsSSH:      true,
			SSHVersion: "OpenSSH_9.0",
			OS:         "linux",
			Status:     "open",
			ScannedAt:  time.Now().UTC(),
		},
	})

	rr := doRequest(mux, "POST", "/api/v2/discovery/register", map[string]interface{}{
		"ids": []string{"10.2.0.5:22"},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	servers, err := api.listManagedServers()
	if err != nil {
		t.Fatalf("list managed servers: %v", err)
	}

	var found *models.Server
	for _, srv := range servers {
		if srv.ID == "discovery-10.2.0.5-22" {
			cp := srv
			found = &cp
			break
		}
	}
	if found == nil {
		t.Fatal("expected discovery-managed server to be created")
	}
	if found.Host != "10.2.0.5" || found.Port != 22 {
		t.Fatalf("unexpected discovery server endpoint: %+v", *found)
	}
	if found.Tags["source"] != "discovery" {
		t.Fatalf("expected discovery source tag, got %+v", found.Tags)
	}
	if found.Tags["discovery_asset_id"] != "10.2.0.5:22" {
		t.Fatalf("expected discovery asset tag, got %+v", found.Tags)
	}
}

func TestDiscoveryAssetOfflineRemovesManagedServer(t *testing.T) {
	api, mux, _ := setupTestAPI(t)
	ds := api.initDiscovery()
	ds.inventory.AddFromScan([]discovery.ScanResult{
		{
			Host:      "10.2.0.6",
			Port:      2222,
			IsSSH:     true,
			Status:    "open",
			ScannedAt: time.Now().UTC(),
		},
	})

	rr := doRequest(mux, "POST", "/api/v2/discovery/register", map[string]interface{}{
		"ids": []string{"10.2.0.6:2222"},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	rr = doRequest(mux, "PUT", "/api/v2/discovery/assets/10.2.0.6:2222", map[string]interface{}{
		"status": "offline",
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	servers, err := api.listManagedServers()
	if err != nil {
		t.Fatalf("list managed servers: %v", err)
	}
	for _, srv := range servers {
		if srv.ID == "discovery-10.2.0.6-2222" {
			t.Fatalf("expected discovery-managed server to be removed, got %+v", srv)
		}
	}
}

func TestCommandEvaluateRewriteAction(t *testing.T) {
	api, mux, _ := setupTestAPI(t)

	engine := cmdctrl.NewPolicyEngine(t.TempDir())
	if err := engine.AddRule(&cmdctrl.CommandRule{
		ID:       "rewrite-audit-flag",
		Name:     "Rewrite command with audit wrapper",
		Pattern:  `^kubectl\s+exec\b`,
		Action:   cmdctrl.ActionRewrite,
		Rewrite:  `audit-wrapper --user {{username}} --target {{target}} -- {{command}}`,
		Severity: "medium",
		Message:  "command rewritten with audit wrapper",
		Enabled:  true,
	}); err != nil {
		t.Fatal(err)
	}
	api.SetCmdCtrl(engine, cmdctrl.NewApprovalManager(5*time.Minute, ""))
	api.RegisterCmdCtrlRoutes(mux)

	rr := doRequest(mux, "POST", "/api/v2/commands/evaluate", map[string]interface{}{
		"command":  "kubectl exec deploy/api -- bash",
		"username": "alice",
		"role":     "operator",
		"target":   "prod-cluster",
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	resp := parseResponse(t, rr)
	data := resp.Data.(map[string]interface{})
	if data["action"] != string(cmdctrl.ActionRewrite) {
		t.Fatalf("expected rewrite action, got %#v", data["action"])
	}
	expected := "audit-wrapper --user alice --target prod-cluster -- kubectl exec deploy/api -- bash"
	if data["rewritten_command"] != expected {
		t.Fatalf("expected rewritten command %q, got %#v", expected, data["rewritten_command"])
	}

	statsRR := doRequest(mux, "GET", "/api/v2/commands/stats", nil)
	if statsRR.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", statsRR.Code, statsRR.Body.String())
	}
	statsResp := parseResponse(t, statsRR)
	stats := statsResp.Data.(map[string]interface{})
	if stats["rewritten"] != float64(1) {
		t.Fatalf("expected rewritten stat to be 1, got %#v", stats["rewritten"])
	}
}

func TestWebhookDeliveriesListAndRetry(t *testing.T) {
	api, mux, _ := setupTestAPI(t)

	var receivedBody string
	var receivedAuth string
	var receivedSignature string
	webhookSink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		receivedAuth = r.Header.Get("Authorization")
		receivedSignature = r.Header.Get("X-SSH-Proxy-Signature")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer webhookSink.Close()

	payload := `{"event":"auth.failure","username":"alice"}`
	dlqPath := filepath.Join(t.TempDir(), "webhook-dlq.jsonl")
	entry, err := json.Marshal(map[string]interface{}{
		"failed_at": time.Now().Unix(),
		"event":     "auth.failure",
		"attempts":  3,
		"payload":   payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dlqPath, append(entry, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(api.config.ConfigFile, []byte(`{
		"webhook": {
			"enabled": true,
			"url": "`+webhookSink.URL+`",
			"auth_header": "Bearer debug-token",
			"hmac_secret": "debug-secret",
			"dead_letter_path": "`+dlqPath+`",
			"timeout_ms": 1000
		}
	}`), 0o600); err != nil {
		t.Fatal(err)
	}

	rr := doRequest(mux, "GET", "/api/v2/webhooks/deliveries", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	resp := parseResponse(t, rr)
	if resp.Total != 1 {
		t.Fatalf("expected 1 delivery, got %d", resp.Total)
	}
	items := resp.Data.([]interface{})
	id := items[0].(map[string]interface{})["id"].(string)

	rr = doRequest(mux, "POST", "/api/v2/webhooks/deliveries/retry", map[string]interface{}{
		"ids": []string{id},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	if receivedBody != payload {
		t.Fatalf("expected payload %q, got %q", payload, receivedBody)
	}
	if receivedAuth != "Bearer debug-token" {
		t.Fatalf("expected auth header to be forwarded, got %q", receivedAuth)
	}
	mac := hmac.New(sha256.New, []byte("debug-secret"))
	mac.Write([]byte(payload))
	expectedSignature := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if receivedSignature != expectedSignature {
		t.Fatalf("expected signature %q, got %q", expectedSignature, receivedSignature)
	}

	rr = doRequest(mux, "GET", "/api/v2/webhooks/deliveries", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	resp = parseResponse(t, rr)
	if resp.Total != 0 {
		t.Fatalf("expected dead letter queue to be empty, got %d entries", resp.Total)
	}
}

func TestWebhookDeliveriesListParsesINIConfig(t *testing.T) {
	api, mux, _ := setupTestAPI(t)

	payload := `{"event":"session.start","username":"alice"}`
	dlqPath := filepath.Join(t.TempDir(), "webhook-dlq.jsonl")
	entry, err := json.Marshal(map[string]interface{}{
		"failed_at": time.Now().Unix(),
		"event":     "session.start",
		"attempts":  2,
		"payload":   payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dlqPath, append(entry, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	iniConfig := "[webhook]\n" +
		"enabled = true\n" +
		"url = http://127.0.0.1:65535/hooks\n" +
		"auth_header = Bearer ini-token\n" +
		"hmac_secret = ini-secret\n" +
		"dead_letter_path = " + dlqPath + "\n" +
		"timeout_ms = 1000\n"
	if err := os.WriteFile(api.config.ConfigFile, []byte(iniConfig), 0o600); err != nil {
		t.Fatal(err)
	}

	rr := doRequest(mux, "GET", "/api/v2/webhooks/deliveries", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	resp := parseResponse(t, rr)
	if resp.Total != 1 {
		t.Fatalf("expected 1 delivery, got %d", resp.Total)
	}
}

func TestSignUserCertEmitsCertificateIssuedWebhook(t *testing.T) {
	api, mux, _ := setupTestAPI(t)
	ca, err := sshca.New(&sshca.CAConfig{})
	if err != nil {
		t.Fatal(err)
	}
	api.SetCA(ca)

	var receivedBody string
	webhookSink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer webhookSink.Close()

	if err := os.WriteFile(api.config.ConfigFile, []byte(`{
		"webhook": {
			"enabled": true,
			"url": "`+webhookSink.URL+`",
			"events": ["certificate.issued"]
		}
	}`), 0o600); err != nil {
		t.Fatal(err)
	}

	userSigner, err := sshca.GenerateED25519Key()
	if err != nil {
		t.Fatal(err)
	}
	publicKey := string(ssh.MarshalAuthorizedKey(userSigner.PublicKey()))

	rr := doRequest(mux, "POST", "/api/v2/ca/sign-user", map[string]interface{}{
		"public_key": publicKey,
		"principals": []string{"alice"},
		"ttl":        "1h",
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(receivedBody, `"event":"certificate.issued"`) {
		t.Fatalf("expected certificate.issued webhook, got %s", receivedBody)
	}
	if !strings.Contains(receivedBody, `"username":"alice"`) {
		t.Fatalf("expected webhook username alice, got %s", receivedBody)
	}
}

func TestExportCRLIncludesRevokedSerials(t *testing.T) {
	api, mux, _ := setupTestAPI(t)
	ca, err := sshca.New(&sshca.CAConfig{})
	if err != nil {
		t.Fatal(err)
	}
	api.SetCA(ca)

	userSigner, err := sshca.GenerateED25519Key()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ca.SignUserCert(userSigner.PublicKey(), "alice", []string{"alice"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := ca.RevokeCert(cert.Serial); err != nil {
		t.Fatal(err)
	}

	rr := doRequest(mux, "GET", "/api/v2/ca/crl", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), strconv.FormatUint(cert.Serial, 10)) {
		t.Fatalf("expected CRL response to contain serial %d, got %s", cert.Serial, rr.Body.String())
	}
}
