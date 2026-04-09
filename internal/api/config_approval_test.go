package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func doRequestWithHeaders(mux *http.ServeMux, method, path string, body interface{}, headers map[string]string) *httptest.ResponseRecorder {
	var bodyReader *bytes.Reader
	if body == nil {
		bodyReader = bytes.NewReader(nil)
	} else {
		data, _ := json.Marshal(body)
		bodyReader = bytes.NewReader(data)
	}

	req := httptest.NewRequest(method, path, bodyReader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

func TestUpdateConfigCreatesPendingApprovalWhenEnabled(t *testing.T) {
	api, mux, _ := setupTestAPI(t)
	api.config.ConfigApprovalEnabled = true

	rr := doRequestWithHeaders(mux, http.MethodPut, "/api/v2/config", map[string]interface{}{
		"listen_port": 3333,
	}, map[string]string{
		"X-User": "alice",
	})
	if rr.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", rr.Code, rr.Body.String())
	}

	resp := parseResponse(t, rr)
	data := resp.Data.(map[string]interface{})
	change := data["change"].(map[string]interface{})
	if change["status"] != string(ConfigChangePending) {
		t.Fatalf("expected pending change, got %#v", change["status"])
	}

	raw, err := os.ReadFile(api.config.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"listen_port": 2222`) {
		t.Fatalf("expected config file to remain unchanged before approval, got %s", raw)
	}
}

func TestConfigChangeListAndGetSanitizeSecretsAndPersist(t *testing.T) {
	api, mux, dp := setupTestAPI(t)
	if err := os.WriteFile(api.config.ConfigFile, []byte(`{"listen_port":2222,"api_token":"tok-123"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	createRR := doRequestWithHeaders(mux, http.MethodPost, "/api/v2/config/changes", map[string]interface{}{
		"listen_port": 3333,
		"api_token":   "tok-456",
	}, map[string]string{
		"X-User": "alice",
	})
	if createRR.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", createRR.Code, createRR.Body.String())
	}

	createResp := parseResponse(t, createRR)
	change := createResp.Data.(map[string]interface{})
	id := change["id"].(string)

	listRR := doRequest(mux, http.MethodGet, "/api/v2/config/changes?status=pending", nil)
	if listRR.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", listRR.Code, listRR.Body.String())
	}
	if strings.Contains(listRR.Body.String(), "tok-456") {
		t.Fatalf("list leaked secret: %s", listRR.Body.String())
	}
	listResp := parseResponse(t, listRR)
	items := listResp.Data.([]interface{})
	if len(items) != 1 {
		t.Fatalf("expected 1 config change, got %d", len(items))
	}
	payload := items[0].(map[string]interface{})["payload"].(map[string]interface{})
	if payload["api_token"] != redactedConfigValue {
		t.Fatalf("expected redacted api_token, got %#v", payload["api_token"])
	}

	getRR := doRequest(mux, http.MethodGet, "/api/v2/config/changes/"+id, nil)
	if getRR.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", getRR.Code, getRR.Body.String())
	}
	if strings.Contains(getRR.Body.String(), "tok-123") || strings.Contains(getRR.Body.String(), "tok-456") {
		t.Fatalf("get leaked secret: %s", getRR.Body.String())
	}
	getResp := parseResponse(t, getRR)
	diff := getResp.Data.(map[string]interface{})["diff"].(string)
	if !strings.Contains(diff, `-  "listen_port": 2222`) || !strings.Contains(diff, `+  "listen_port": 3333`) {
		t.Fatalf("unexpected diff output: %s", diff)
	}

	reloaded, err := New(dp, api.config)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = reloaded.Close() })
	reloadedMux := http.NewServeMux()
	reloaded.RegisterRoutes(reloadedMux)

	reloadedListRR := doRequest(reloadedMux, http.MethodGet, "/api/v2/config/changes", nil)
	if reloadedListRR.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", reloadedListRR.Code, reloadedListRR.Body.String())
	}
	reloadedResp := parseResponse(t, reloadedListRR)
	if reloadedResp.Total != 1 {
		t.Fatalf("expected persisted config change after reload, got %d", reloadedResp.Total)
	}
}

func TestApproveConfigChangeAppliesConfig(t *testing.T) {
	api, mux, _ := setupTestAPI(t)

	createRR := doRequestWithHeaders(mux, http.MethodPost, "/api/v2/config/changes", map[string]interface{}{
		"listen_port": 3333,
	}, map[string]string{
		"X-User": "alice",
	})
	createResp := parseResponse(t, createRR)
	id := createResp.Data.(map[string]interface{})["id"].(string)

	approveRR := doRequestWithHeaders(mux, http.MethodPost, "/api/v2/config/changes/"+id+"/approve", nil, map[string]string{
		"X-User": "admin",
		"X-Role": "admin",
	})
	if approveRR.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", approveRR.Code, approveRR.Body.String())
	}

	approveResp := parseResponse(t, approveRR)
	approvedChange := approveResp.Data.(map[string]interface{})["change"].(map[string]interface{})
	if approvedChange["status"] != string(ConfigChangeApplied) {
		t.Fatalf("expected applied status, got %#v", approveResp.Data)
	}

	raw, err := os.ReadFile(api.config.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"listen_port": 3333`) {
		t.Fatalf("expected config file to be updated after approval, got %s", raw)
	}
}

func TestDenyConfigChangeKeepsCurrentConfig(t *testing.T) {
	api, mux, _ := setupTestAPI(t)

	createRR := doRequestWithHeaders(mux, http.MethodPost, "/api/v2/config/changes", map[string]interface{}{
		"listen_port": 3333,
	}, map[string]string{
		"X-User": "alice",
	})
	createResp := parseResponse(t, createRR)
	id := createResp.Data.(map[string]interface{})["id"].(string)

	denyRR := doRequestWithHeaders(mux, http.MethodPost, "/api/v2/config/changes/"+id+"/deny", map[string]interface{}{
		"reason": "needs review",
	}, map[string]string{
		"X-User": "admin",
		"X-Role": "admin",
	})
	if denyRR.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", denyRR.Code, denyRR.Body.String())
	}

	denyResp := parseResponse(t, denyRR)
	data := denyResp.Data.(map[string]interface{})
	if data["status"] != string(ConfigChangeDenied) {
		t.Fatalf("expected denied status, got %#v", data["status"])
	}
	if data["deny_reason"] != "needs review" {
		t.Fatalf("expected deny reason to persist, got %#v", data["deny_reason"])
	}

	raw, err := os.ReadFile(api.config.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"listen_port": 2222`) {
		t.Fatalf("expected config file to remain unchanged after deny, got %s", raw)
	}
}

func TestApproveConfigChangeRollsBackOnReloadFailure(t *testing.T) {
	api, mux, dp := setupTestAPI(t)

	createRR := doRequestWithHeaders(mux, http.MethodPost, "/api/v2/config/changes", map[string]interface{}{
		"listen_port": 3333,
	}, map[string]string{
		"X-User": "alice",
	})
	createResp := parseResponse(t, createRR)
	id := createResp.Data.(map[string]interface{})["id"].(string)

	dp.reloadErr = errors.New("reload failed")
	approveRR := doRequestWithHeaders(mux, http.MethodPost, "/api/v2/config/changes/"+id+"/approve", nil, map[string]string{
		"X-User": "admin",
		"X-Role": "admin",
	})
	if approveRR.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d: %s", approveRR.Code, approveRR.Body.String())
	}

	change, err := api.configChanges.GetChange(id)
	if err != nil {
		t.Fatal(err)
	}
	if change.Status != ConfigChangeFailed {
		t.Fatalf("expected failed status, got %s", change.Status)
	}
	if !strings.Contains(change.FailureReason, "reload failed") {
		t.Fatalf("expected failure reason to mention reload, got %q", change.FailureReason)
	}

	raw, err := os.ReadFile(api.config.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"listen_port": 2222`) {
		t.Fatalf("expected rollback to restore original config, got %s", raw)
	}
}

func TestExpiredConfigChangeCannotBeApproved(t *testing.T) {
	api, mux, _ := setupTestAPI(t)

	createRR := doRequestWithHeaders(mux, http.MethodPost, "/api/v2/config/changes", map[string]interface{}{
		"listen_port": 3333,
	}, map[string]string{
		"X-User": "alice",
	})
	createResp := parseResponse(t, createRR)
	id := createResp.Data.(map[string]interface{})["id"].(string)

	change, err := api.configChanges.GetChange(id)
	if err != nil {
		t.Fatal(err)
	}
	api.configChanges.now = func() time.Time {
		return change.ExpiresAt.Add(time.Minute)
	}

	approveRR := doRequestWithHeaders(mux, http.MethodPost, "/api/v2/config/changes/"+id+"/approve", nil, map[string]string{
		"X-User": "admin",
		"X-Role": "admin",
	})
	if approveRR.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", approveRR.Code, approveRR.Body.String())
	}

	change, err = api.configChanges.GetChange(id)
	if err != nil {
		t.Fatal(err)
	}
	if change.Status != ConfigChangeExpired {
		t.Fatalf("expected expired status, got %s", change.Status)
	}
}

func TestDirectConfigUpdateRollsBackOnReloadFailure(t *testing.T) {
	api, mux, dp := setupTestAPI(t)
	dp.reloadErr = errors.New("reload failed")

	rr := doRequest(mux, http.MethodPut, "/api/v2/config", map[string]interface{}{
		"listen_port": 3333,
	})
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d: %s", rr.Code, rr.Body.String())
	}

	raw, err := os.ReadFile(api.config.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"listen_port": 2222`) {
		t.Fatalf("expected rollback to preserve original config, got %s", raw)
	}
}
