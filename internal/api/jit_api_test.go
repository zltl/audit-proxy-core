package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/jit"
)

func setupJITTestAPI(t *testing.T) (*API, *http.ServeMux, *jit.Store) {
	t.Helper()
	dir := t.TempDir()

	dp := &mockDP{}
	cfg := &Config{
		AdminUser:     "admin",
		AdminPassHash: "test",
		SessionSecret: "secret",
		DataDir:       dir,
		AuditLogDir:   dir,
		ConfigFile:    dir + "/config.ini",
		ConfigVerDir:  dir + "/config_versions",
	}

	api, err := New(dp, cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	store := jit.NewStore(dir, &jit.Policy{
		MaxDuration:   24 * time.Hour,
		ApproverRoles: []string{"admin"},
	})
	api.SetJIT(store)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux)
	api.RegisterJITRoutes(mux)

	return api, mux, store
}

func doJITRequest(mux *http.ServeMux, method, path string, body interface{}, user, role string) *httptest.ResponseRecorder {
	var bodyReader io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		bodyReader = bytes.NewReader(data)
	}
	req := httptest.NewRequest(method, path, bodyReader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if user != "" {
		req.Header.Set("X-User", user)
	}
	if role != "" {
		req.Header.Set("X-Role", role)
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

func parseJITResponse(t *testing.T, rr *httptest.ResponseRecorder) APIResponse {
	t.Helper()
	var resp APIResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v\nbody: %s", err, rr.Body.String())
	}
	return resp
}

func extractID(t *testing.T, resp APIResponse) string {
	t.Helper()
	data, ok := resp.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map data, got %T", resp.Data)
	}
	id, ok := data["id"].(string)
	if !ok {
		t.Fatalf("expected string id, got %T", data["id"])
	}
	return id
}

// --- Test: Create Request via API ---

func TestAPICreateJITRequest(t *testing.T) {
	_, mux, _ := setupJITTestAPI(t)

	body := map[string]string{
		"target":   "prod-db-01",
		"role":     "operator",
		"reason":   "Emergency maintenance",
		"duration": "4h",
	}
	rr := doJITRequest(mux, "POST", "/api/v2/jit/requests", body, "alice", "operator")
	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rr.Code, rr.Body.String())
	}
	resp := parseJITResponse(t, rr)
	if !resp.Success {
		t.Fatal("expected success")
	}

	id := extractID(t, resp)
	if id == "" {
		t.Fatal("expected non-empty id")
	}
}

func TestAPICreateJITRequestNoAuth(t *testing.T) {
	_, mux, _ := setupJITTestAPI(t)

	body := map[string]string{
		"target":   "prod-db-01",
		"role":     "operator",
		"reason":   "test",
		"duration": "1h",
	}
	rr := doJITRequest(mux, "POST", "/api/v2/jit/requests", body, "", "")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestAPICreateJITRequestMissingTarget(t *testing.T) {
	_, mux, _ := setupJITTestAPI(t)

	body := map[string]string{
		"role":     "operator",
		"reason":   "test",
		"duration": "1h",
	}
	rr := doJITRequest(mux, "POST", "/api/v2/jit/requests", body, "alice", "operator")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestAPICreateJITRequestInvalidDuration(t *testing.T) {
	_, mux, _ := setupJITTestAPI(t)

	body := map[string]string{
		"target":   "prod-db-01",
		"role":     "operator",
		"reason":   "test",
		"duration": "invalid",
	}
	rr := doJITRequest(mux, "POST", "/api/v2/jit/requests", body, "alice", "operator")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

// --- Test: Approve via API ---

func TestAPIApproveJITRequest(t *testing.T) {
	_, mux, _ := setupJITTestAPI(t)

	// Create request
	body := map[string]string{
		"target": "prod-db-01", "role": "operator",
		"reason": "test", "duration": "1h",
	}
	rr := doJITRequest(mux, "POST", "/api/v2/jit/requests", body, "alice", "operator")
	resp := parseJITResponse(t, rr)
	id := extractID(t, resp)

	// Approve
	rr = doJITRequest(mux, "POST", "/api/v2/jit/requests/"+id+"/approve", nil, "admin-bob", "admin")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	resp = parseJITResponse(t, rr)
	if !resp.Success {
		t.Fatal("expected success")
	}
	data := resp.Data.(map[string]interface{})
	if data["status"] != "approved" {
		t.Fatalf("expected approved, got %v", data["status"])
	}
}

func TestAPIApproveNotAdmin(t *testing.T) {
	_, mux, _ := setupJITTestAPI(t)

	body := map[string]string{
		"target": "prod-db-01", "role": "operator",
		"reason": "test", "duration": "1h",
	}
	rr := doJITRequest(mux, "POST", "/api/v2/jit/requests", body, "alice", "operator")
	resp := parseJITResponse(t, rr)
	id := extractID(t, resp)

	rr = doJITRequest(mux, "POST", "/api/v2/jit/requests/"+id+"/approve", nil, "alice", "operator")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
}

// --- Test: Deny via API ---

func TestAPIDenyJITRequest(t *testing.T) {
	_, mux, _ := setupJITTestAPI(t)

	body := map[string]string{
		"target": "prod-db-01", "role": "operator",
		"reason": "test", "duration": "1h",
	}
	rr := doJITRequest(mux, "POST", "/api/v2/jit/requests", body, "alice", "operator")
	resp := parseJITResponse(t, rr)
	id := extractID(t, resp)

	denyBody := map[string]string{"reason": "not authorized"}
	rr = doJITRequest(mux, "POST", "/api/v2/jit/requests/"+id+"/deny", denyBody, "admin-bob", "admin")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	resp = parseJITResponse(t, rr)
	data := resp.Data.(map[string]interface{})
	if data["status"] != "denied" {
		t.Fatalf("expected denied, got %v", data["status"])
	}
}

// --- Test: List Requests with Filters ---

func TestAPIListJITRequests(t *testing.T) {
	_, mux, _ := setupJITTestAPI(t)

	for _, target := range []string{"db-01", "db-02", "db-03"} {
		body := map[string]string{
			"target": target, "role": "operator",
			"reason": "test", "duration": "1h",
		}
		doJITRequest(mux, "POST", "/api/v2/jit/requests", body, "alice", "operator")
	}

	rr := doJITRequest(mux, "GET", "/api/v2/jit/requests", nil, "alice", "operator")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	resp := parseJITResponse(t, rr)
	if resp.Total != 3 {
		t.Fatalf("expected 3 requests, got %d", resp.Total)
	}
}

func TestAPIListJITRequestsFilterStatus(t *testing.T) {
	_, mux, _ := setupJITTestAPI(t)

	body := map[string]string{
		"target": "db-01", "role": "operator",
		"reason": "test", "duration": "1h",
	}
	rr := doJITRequest(mux, "POST", "/api/v2/jit/requests", body, "alice", "operator")
	resp := parseJITResponse(t, rr)
	id := extractID(t, resp)
	doJITRequest(mux, "POST", "/api/v2/jit/requests/"+id+"/approve", nil, "admin", "admin")

	body2 := map[string]string{
		"target": "db-02", "role": "operator",
		"reason": "test", "duration": "1h",
	}
	doJITRequest(mux, "POST", "/api/v2/jit/requests", body2, "bob", "operator")

	rr = doJITRequest(mux, "GET", "/api/v2/jit/requests?status=approved", nil, "", "")
	resp = parseJITResponse(t, rr)
	if resp.Total != 1 {
		t.Fatalf("expected 1 approved, got %d", resp.Total)
	}
}

// --- Test: Get Request Details ---

func TestAPIGetJITRequest(t *testing.T) {
	_, mux, _ := setupJITTestAPI(t)

	body := map[string]string{
		"target": "prod-db-01", "role": "operator",
		"reason": "test", "duration": "2h",
	}
	rr := doJITRequest(mux, "POST", "/api/v2/jit/requests", body, "alice", "operator")
	resp := parseJITResponse(t, rr)
	id := extractID(t, resp)

	rr = doJITRequest(mux, "GET", "/api/v2/jit/requests/"+id, nil, "", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	resp = parseJITResponse(t, rr)
	data := resp.Data.(map[string]interface{})
	if data["target"] != "prod-db-01" {
		t.Fatalf("expected prod-db-01, got %v", data["target"])
	}
}

func TestAPIGetJITRequestNotFound(t *testing.T) {
	_, mux, _ := setupJITTestAPI(t)
	rr := doJITRequest(mux, "GET", "/api/v2/jit/requests/nonexistent", nil, "", "")
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
}

// --- Test: Access Check Endpoint ---

func TestAPICheckAccess(t *testing.T) {
	_, mux, _ := setupJITTestAPI(t)

	body := map[string]string{
		"target": "prod-db-01", "role": "operator",
		"reason": "test", "duration": "1h",
	}
	rr := doJITRequest(mux, "POST", "/api/v2/jit/requests", body, "alice", "operator")
	resp := parseJITResponse(t, rr)
	id := extractID(t, resp)
	doJITRequest(mux, "POST", "/api/v2/jit/requests/"+id+"/approve", nil, "admin", "admin")

	rr = doJITRequest(mux, "GET", "/api/v2/jit/check?user=alice&target=prod-db-01", nil, "", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	resp = parseJITResponse(t, rr)
	data := resp.Data.(map[string]interface{})
	if data["has_access"] != true {
		t.Fatalf("expected has_access=true, got %v", data["has_access"])
	}
}

func TestAPICheckAccessNoGrant(t *testing.T) {
	_, mux, _ := setupJITTestAPI(t)

	rr := doJITRequest(mux, "GET", "/api/v2/jit/check?user=bob&target=prod-db-01", nil, "", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	resp := parseJITResponse(t, rr)
	data := resp.Data.(map[string]interface{})
	if data["has_access"] != false {
		t.Fatalf("expected has_access=false, got %v", data["has_access"])
	}
}

func TestAPICheckAccessMissingParams(t *testing.T) {
	_, mux, _ := setupJITTestAPI(t)
	rr := doJITRequest(mux, "GET", "/api/v2/jit/check?user=alice", nil, "", "")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

// --- Test: List Grants ---

func TestAPIListGrants(t *testing.T) {
	_, mux, _ := setupJITTestAPI(t)

	body := map[string]string{
		"target": "db-01", "role": "operator",
		"reason": "test", "duration": "1h",
	}
	rr := doJITRequest(mux, "POST", "/api/v2/jit/requests", body, "alice", "operator")
	resp := parseJITResponse(t, rr)
	id := extractID(t, resp)
	doJITRequest(mux, "POST", "/api/v2/jit/requests/"+id+"/approve", nil, "admin", "admin")

	rr = doJITRequest(mux, "GET", "/api/v2/jit/grants", nil, "", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	resp = parseJITResponse(t, rr)
	if resp.Total != 1 {
		t.Fatalf("expected 1 grant, got %d", resp.Total)
	}
}

// --- Test: Policy Endpoints ---

func TestAPIGetPolicy(t *testing.T) {
	_, mux, _ := setupJITTestAPI(t)

	rr := doJITRequest(mux, "GET", "/api/v2/jit/policy", nil, "", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	resp := parseJITResponse(t, rr)
	if !resp.Success {
		t.Fatal("expected success")
	}
}

func TestAPIUpdatePolicy(t *testing.T) {
	_, mux, _ := setupJITTestAPI(t)

	body := map[string]interface{}{
		"max_duration":   "8h",
		"require_reason": true,
		"approver_roles": []string{"admin", "security"},
	}
	rr := doJITRequest(mux, "PUT", "/api/v2/jit/policy", body, "admin-user", "admin")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	resp := parseJITResponse(t, rr)
	if !resp.Success {
		t.Fatal("expected success")
	}
}

func TestAPIUpdatePolicyWithStagesAndAutoRules(t *testing.T) {
	_, mux, _ := setupJITTestAPI(t)

	body := map[string]interface{}{
		"max_duration": "8h",
		"approval_stages": []map[string]interface{}{
			{"name": "security", "approver_roles": []string{"security"}, "required_approvals": 1},
			{"name": "admin", "approver_roles": []string{"admin"}, "required_approvals": 1},
		},
		"auto_approve_rules": []map[string]interface{}{
			{"name": "viewer-staging", "targets": []string{"staging-*"}, "roles": []string{"viewer"}, "max_duration": "30m"},
		},
	}
	rr := doJITRequest(mux, "PUT", "/api/v2/jit/policy", body, "admin-user", "admin")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestAPIMultiStageApprovalWorkflow(t *testing.T) {
	_, mux, store := setupJITTestAPI(t)
	if err := store.SetPolicy(&jit.Policy{
		MaxDuration: 24 * time.Hour,
		ApprovalStages: []jit.ApprovalStage{
			{Name: "security", ApproverRoles: []string{"security"}},
			{Name: "admin", ApproverRoles: []string{"admin"}},
		},
		ApproverRoles: []string{"security", "admin"},
	}); err != nil {
		t.Fatalf("SetPolicy() error = %v", err)
	}

	body := map[string]string{
		"target": "prod-db-01", "role": "operator",
		"reason": "test", "duration": "1h",
	}
	rr := doJITRequest(mux, "POST", "/api/v2/jit/requests", body, "alice", "operator")
	resp := parseJITResponse(t, rr)
	id := extractID(t, resp)

	rr = doJITRequest(mux, "POST", "/api/v2/jit/requests/"+id+"/approve", nil, "sec-amy", "security")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 after stage 1, got %d: %s", rr.Code, rr.Body.String())
	}
	resp = parseJITResponse(t, rr)
	data := resp.Data.(map[string]interface{})
	if data["status"] != "pending" {
		t.Fatalf("expected pending after stage 1, got %v", data["status"])
	}
	if data["current_stage"] != float64(1) {
		t.Fatalf("expected current_stage=1 after stage 1, got %v", data["current_stage"])
	}

	rr = doJITRequest(mux, "POST", "/api/v2/jit/requests/"+id+"/approve", nil, "admin-bob", "admin")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 after final stage, got %d: %s", rr.Code, rr.Body.String())
	}
	resp = parseJITResponse(t, rr)
	data = resp.Data.(map[string]interface{})
	if data["status"] != "approved" {
		t.Fatalf("expected approved after final stage, got %v", data["status"])
	}
}

func TestAPIApproveJITRequestWrongStageRoleForbidden(t *testing.T) {
	_, mux, store := setupJITTestAPI(t)
	if err := store.SetPolicy(&jit.Policy{
		MaxDuration: 24 * time.Hour,
		ApprovalStages: []jit.ApprovalStage{
			{Name: "security", ApproverRoles: []string{"security"}},
		},
		ApproverRoles: []string{"security"},
	}); err != nil {
		t.Fatalf("SetPolicy() error = %v", err)
	}

	body := map[string]string{
		"target": "prod-db-01", "role": "operator",
		"reason": "test", "duration": "1h",
	}
	rr := doJITRequest(mux, "POST", "/api/v2/jit/requests", body, "alice", "operator")
	resp := parseJITResponse(t, rr)
	id := extractID(t, resp)

	rr = doJITRequest(mux, "POST", "/api/v2/jit/requests/"+id+"/approve", nil, "admin-bob", "admin")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestAPICreateBreakGlassRequest(t *testing.T) {
	_, mux, store := setupJITTestAPI(t)
	if err := store.SetPolicy(&jit.Policy{
		MaxDuration:           24 * time.Hour,
		BreakGlassEnabled:     true,
		BreakGlassMaxDuration: time.Hour,
		BreakGlassRoles:       []string{"operator"},
		BreakGlassTargets:     []string{"prod-*"},
		ApproverRoles:         []string{"admin"},
	}); err != nil {
		t.Fatalf("SetPolicy() error = %v", err)
	}

	body := map[string]interface{}{
		"target":      "prod-db-01",
		"role":        "operator",
		"reason":      "incident response",
		"ticket":      "INC-123",
		"break_glass": true,
		"duration":    "30m",
	}
	rr := doJITRequest(mux, "POST", "/api/v2/jit/requests", body, "alice", "operator")
	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rr.Code, rr.Body.String())
	}
	resp := parseJITResponse(t, rr)
	data := resp.Data.(map[string]interface{})
	if data["status"] != "approved" {
		t.Fatalf("expected approved break-glass request, got %v", data["status"])
	}
	if data["break_glass"] != true {
		t.Fatalf("expected break_glass=true, got %v", data["break_glass"])
	}
}

func TestAPIUpdatePolicyWithBreakGlassFields(t *testing.T) {
	_, mux, _ := setupJITTestAPI(t)

	body := map[string]interface{}{
		"break_glass_enabled":      true,
		"break_glass_max_duration": "1h",
		"break_glass_roles":        []string{"operator"},
		"break_glass_targets":      []string{"prod-*"},
	}
	rr := doJITRequest(mux, "PUT", "/api/v2/jit/policy", body, "admin-user", "admin")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestAPIUpdatePolicyNotAdmin(t *testing.T) {
	_, mux, _ := setupJITTestAPI(t)

	body := map[string]interface{}{
		"max_duration": "8h",
	}
	rr := doJITRequest(mux, "PUT", "/api/v2/jit/policy", body, "alice", "operator")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
}

// --- Test: Revoke via API ---

func TestAPIRevokeJITRequest(t *testing.T) {
	_, mux, _ := setupJITTestAPI(t)

	body := map[string]string{
		"target": "prod-db-01", "role": "operator",
		"reason": "test", "duration": "1h",
	}
	rr := doJITRequest(mux, "POST", "/api/v2/jit/requests", body, "alice", "operator")
	resp := parseJITResponse(t, rr)
	id := extractID(t, resp)

	doJITRequest(mux, "POST", "/api/v2/jit/requests/"+id+"/approve", nil, "admin", "admin")

	rr = doJITRequest(mux, "POST", "/api/v2/jit/requests/"+id+"/revoke", nil, "admin", "admin")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	resp = parseJITResponse(t, rr)
	data := resp.Data.(map[string]interface{})
	if data["status"] != "revoked" {
		t.Fatalf("expected revoked, got %v", data["status"])
	}
}

// --- Test: JIT not enabled ---

func TestAPIJITNotEnabled(t *testing.T) {
	dir := t.TempDir()
	dp := &mockDP{}
	cfg := &Config{
		AdminUser:     "admin",
		AdminPassHash: "test",
		SessionSecret: "secret",
		DataDir:       dir,
		AuditLogDir:   dir,
		ConfigFile:    dir + "/config.ini",
		ConfigVerDir:  dir + "/config_versions",
	}
	api, err := New(dp, cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)
	api.RegisterJITRoutes(mux)

	rr := doJITRequest(mux, "GET", "/api/v2/jit/requests", nil, "alice", "admin")
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rr.Code)
	}
}
