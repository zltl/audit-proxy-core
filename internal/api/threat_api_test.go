package api

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/threat"
)

func TestThreatRiskEndpointListsDynamicAssessments(t *testing.T) {
	api, mux, _ := setupTestAPI(t)
	api.SetThreat(newThreatDetectorWithGeo(t, `[
		{"cidr":"10.0.0.0/8","country_code":"US","country":"United States","region":"California","city":"San Francisco","latitude":37.7749,"longitude":-122.4194},
		{"cidr":"198.51.100.0/24","country_code":"DE","country":"Germany","region":"Hesse","city":"Frankfurt","latitude":50.1109,"longitude":8.6821}
	]`))
	api.RegisterThreatRoutes(mux)

	baseline := threat.Event{
		Timestamp: time.Now().Add(-10 * time.Minute),
		Type:      "connection",
		Username:  "alice",
		SourceIP:  "10.0.0.10",
		Target:    "srv1.local",
		Details: map[string]interface{}{
			"source_type":        "office",
			"device_fingerprint": "sshfp-known",
		},
	}
	if resp := doRequest(mux, http.MethodPost, "/api/v2/threats/simulate", baseline); resp.Code != http.StatusOK {
		t.Fatalf("baseline simulate status = %d body = %s", resp.Code, resp.Body.String())
	}

	current := threat.Event{
		Timestamp: time.Now(),
		Type:      "connection",
		Username:  "alice",
		SourceIP:  "198.51.100.20",
		Target:    "srv1.local",
		Details: map[string]interface{}{
			"source_type":        "public",
			"device_fingerprint": "sshfp-new",
		},
	}
	resp := doRequest(mux, http.MethodPost, "/api/v2/threats/simulate", current)
	if resp.Code != http.StatusOK {
		t.Fatalf("simulate status = %d body = %s", resp.Code, resp.Body.String())
	}

	var simulateEnvelope APIResponse
	if err := json.Unmarshal(resp.Body.Bytes(), &simulateEnvelope); err != nil {
		t.Fatalf("json.Unmarshal(simulate) error = %v", err)
	}
	simData, ok := simulateEnvelope.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("simulate data type = %T, want map", simulateEnvelope.Data)
	}
	riskAssessment, ok := simData["risk_assessment"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected risk_assessment in simulate response, got %#v", simData["risk_assessment"])
	}
	if score := int(riskAssessment["score"].(float64)); score < 75 {
		t.Fatalf("expected high risk score, got %d", score)
	}

	listResp := doRequest(mux, http.MethodGet, "/api/v2/threats/risk?username=alice&level=critical", nil)
	if listResp.Code != http.StatusOK {
		t.Fatalf("risk list status = %d body = %s", listResp.Code, listResp.Body.String())
	}
	var listEnvelope APIResponse
	if err := json.Unmarshal(listResp.Body.Bytes(), &listEnvelope); err != nil {
		t.Fatalf("json.Unmarshal(risk list) error = %v", err)
	}
	assessments, ok := listEnvelope.Data.([]interface{})
	if !ok || len(assessments) == 0 {
		t.Fatalf("expected risk assessments, got %#v", listEnvelope.Data)
	}
	first := assessments[0].(map[string]interface{})
	if first["username"] != "alice" || first["source_ip"] != "198.51.100.20" {
		t.Fatalf("unexpected first risk assessment %#v", first)
	}
}

func TestThreatIngestWebhookGeneratesGeoAlert(t *testing.T) {
	api, mux, _ := setupTestAPI(t)
	detector := newThreatDetectorWithGeo(t, `[
		{"cidr":"203.0.113.0/24","country_code":"US","country":"United States","region":"California","city":"San Francisco","latitude":37.7749,"longitude":-122.4194},
		{"cidr":"198.51.100.0/24","country_code":"DE","country":"Germany","region":"Hesse","city":"Frankfurt","latitude":50.1109,"longitude":8.6821}
	]`)
	api.SetThreat(detector)
	api.RegisterThreatRoutes(mux)
	writeThreatWebhookConfig(t, api.config.ConfigFile, `[webhook]
enabled = true
hmac_secret = unit-test-secret
events = auth.success,session.start,session.end
`)
	baseTime := time.Now().UTC()

	firstPayload := threatWebhookPayload{
		Event:      "auth.success",
		Timestamp:  baseTime.Add(-10 * time.Minute).Unix(),
		Username:   "geo-user",
		ClientAddr: "203.0.113.10",
	}
	firstResp := doSignedThreatWebhookRequest(t, mux, firstPayload, "unit-test-secret", "")
	if firstResp.Code != http.StatusAccepted {
		t.Fatalf("first threat ingest status = %d body = %s", firstResp.Code, firstResp.Body.String())
	}

	secondPayload := threatWebhookPayload{
		Event:      "auth.success",
		Timestamp:  baseTime.Unix(),
		Username:   "geo-user",
		ClientAddr: "198.51.100.20",
	}
	secondResp := doSignedThreatWebhookRequest(t, mux, secondPayload, "unit-test-secret", "")
	if secondResp.Code != http.StatusAccepted {
		t.Fatalf("second threat ingest status = %d body = %s", secondResp.Code, secondResp.Body.String())
	}

	var envelope APIResponse
	if err := json.Unmarshal(secondResp.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if !envelope.Success {
		t.Fatalf("expected success response, got %+v", envelope)
	}
	data, ok := envelope.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("response data type = %T, want map", envelope.Data)
	}
	if got := int(data["alerts_generated"].(float64)); got < 1 {
		t.Fatalf("alerts_generated = %d, want at least 1", got)
	}
	alerts, ok := data["alerts"].([]interface{})
	if !ok || len(alerts) == 0 {
		t.Fatalf("alerts = %#v, want at least one alert", data["alerts"])
	}
	foundGeoAlert := false
	for _, item := range alerts {
		alert, ok := item.(map[string]interface{})
		if ok && alert["rule_id"] == "impossible_travel" {
			foundGeoAlert = true
			break
		}
	}
	if !foundGeoAlert {
		t.Fatalf("alerts = %#v, want impossible_travel alert", data["alerts"])
	}
}

func TestThreatIngestWebhookEnrichesRiskContext(t *testing.T) {
	api, mux, _ := setupTestAPI(t)
	api.SetThreat(threat.NewDetector(&threat.DetectorConfig{
		Enabled:           true,
		SuppressionWindow: 50 * time.Millisecond,
		MaxAlertsPerRule:  100,
	}))
	api.RegisterThreatRoutes(mux)
	writeThreatWebhookConfig(t, api.config.ConfigFile, `[webhook]
enabled = true
hmac_secret = unit-test-secret
events = session.start

[network_sources]
office_cidrs = 10.0.0.0/8
vpn_cidrs = 100.64.0.0/10
`)

	resp := doSignedThreatWebhookRequest(t, mux, threatWebhookPayload{
		Event:      "session.start",
		Timestamp:  time.Now().Unix(),
		Username:   "alice",
		ClientAddr: "10.0.0.1",
		Detail:     "alice@srv1.local:22",
	}, "unit-test-secret", "")
	if resp.Code != http.StatusAccepted {
		t.Fatalf("threat ingest status = %d body = %s", resp.Code, resp.Body.String())
	}

	var envelope APIResponse
	if err := json.Unmarshal(resp.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	data, ok := envelope.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("response data type = %T, want map", envelope.Data)
	}
	assessment, ok := data["risk_assessment"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected risk_assessment in ingest response, got %#v", data["risk_assessment"])
	}
	if assessment["source_type"] != "office" {
		t.Fatalf("expected office source_type, got %#v", assessment["source_type"])
	}
	if assessment["device_fingerprint"] != "sshfp-4d2d9f6a1f0ef8e0" {
		t.Fatalf("expected device fingerprint enrichment, got %#v", assessment["device_fingerprint"])
	}
}

func TestThreatIngestWebhookRejectsInvalidSignature(t *testing.T) {
	api, mux, _ := setupTestAPI(t)
	api.SetThreat(threat.NewDetector(&threat.DetectorConfig{Enabled: true}))
	api.RegisterThreatRoutes(mux)
	writeThreatWebhookConfig(t, api.config.ConfigFile, `[webhook]
enabled = true
hmac_secret = correct-secret
events = auth.success
`)

	resp := doSignedThreatWebhookRequest(t, mux, threatWebhookPayload{
		Event:      "auth.success",
		Timestamp:  time.Now().Unix(),
		Username:   "alice",
		ClientAddr: "203.0.113.10",
	}, "wrong-secret", "")
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("threat ingest status = %d body = %s", resp.Code, resp.Body.String())
	}
}

func TestThreatIngestWebhookAcceptsUnsupportedEventWithoutDeadLettering(t *testing.T) {
	api, mux, _ := setupTestAPI(t)
	api.SetThreat(threat.NewDetector(&threat.DetectorConfig{Enabled: true}))
	api.RegisterThreatRoutes(mux)
	writeThreatWebhookConfig(t, api.config.ConfigFile, `[webhook]
enabled = true
hmac_secret = unit-test-secret
events = all
`)

	resp := doSignedThreatWebhookRequest(t, mux, threatWebhookPayload{
		Event:      "upstream.healthy",
		Timestamp:  time.Now().Unix(),
		Username:   "",
		ClientAddr: "203.0.113.10",
	}, "unit-test-secret", "")
	if resp.Code != http.StatusAccepted {
		t.Fatalf("threat ingest status = %d body = %s", resp.Code, resp.Body.String())
	}

	var envelope APIResponse
	if err := json.Unmarshal(resp.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	data := envelope.Data.(map[string]interface{})
	if handled, ok := data["handled"].(bool); !ok || handled {
		t.Fatalf("handled = %v, want false", data["handled"])
	}
}

func TestThreatRuleCRUDWithCustomDSL(t *testing.T) {
	api, mux, _ := setupTestAPI(t)
	api.SetThreat(threat.NewDetector(&threat.DetectorConfig{
		Enabled:           true,
		DataDir:           api.config.DataDir,
		SuppressionWindow: 50 * time.Millisecond,
		MaxAlertsPerRule:  100,
	}))
	api.RegisterThreatRoutes(mux)

	createResp := doRequest(mux, http.MethodPost, "/api/v2/threats/rules", map[string]interface{}{
		"name":        "Kubectl Exec Detection",
		"description": "Detect kubectl exec shells",
		"type":        "dsl",
		"severity":    "high",
		"event_types": []string{"command"},
		"expression": map[string]interface{}{
			"operator": "and",
			"children": []map[string]interface{}{
				{"operator": "contains", "field": "details.command", "value": "kubectl"},
				{"operator": "contains", "field": "details.command", "value": "exec"},
			},
		},
	})
	if createResp.Code != http.StatusCreated {
		t.Fatalf("create custom threat rule status = %d body = %s", createResp.Code, createResp.Body.String())
	}

	var createEnvelope APIResponse
	if err := json.Unmarshal(createResp.Body.Bytes(), &createEnvelope); err != nil {
		t.Fatalf("json.Unmarshal(create rule) error = %v", err)
	}
	ruleData, ok := createEnvelope.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("create rule data type = %T, want map", createEnvelope.Data)
	}
	ruleID, _ := ruleData["id"].(string)
	if ruleID == "" {
		t.Fatalf("expected created rule id, got %#v", createEnvelope.Data)
	}

	listResp := doRequest(mux, http.MethodGet, "/api/v2/threats/rules", nil)
	if listResp.Code != http.StatusOK {
		t.Fatalf("list threat rules status = %d body = %s", listResp.Code, listResp.Body.String())
	}
	if !bytes.Contains(listResp.Body.Bytes(), []byte(ruleID)) {
		t.Fatalf("expected list threat rules to contain %q, got %s", ruleID, listResp.Body.String())
	}

	simulateResp := doRequest(mux, http.MethodPost, "/api/v2/threats/simulate", threat.Event{
		Timestamp: time.Now(),
		Type:      "command",
		Username:  "ops",
		SourceIP:  "10.0.0.5",
		Details: map[string]interface{}{
			"command": "kubectl exec deploy/api -- /bin/sh",
		},
	})
	if simulateResp.Code != http.StatusOK {
		t.Fatalf("simulate status = %d body = %s", simulateResp.Code, simulateResp.Body.String())
	}
	if !bytes.Contains(simulateResp.Body.Bytes(), []byte(ruleID)) {
		t.Fatalf("expected simulate response to contain custom rule %q, got %s", ruleID, simulateResp.Body.String())
	}

	deleteResp := doRequest(mux, http.MethodDelete, "/api/v2/threats/rules/"+ruleID, nil)
	if deleteResp.Code != http.StatusOK {
		t.Fatalf("delete custom threat rule status = %d body = %s", deleteResp.Code, deleteResp.Body.String())
	}

	time.Sleep(60 * time.Millisecond)
	simulateResp = doRequest(mux, http.MethodPost, "/api/v2/threats/simulate", threat.Event{
		Timestamp: time.Now(),
		Type:      "command",
		Username:  "ops",
		SourceIP:  "10.0.0.6",
		Details: map[string]interface{}{
			"command": "kubectl exec deploy/api -- /bin/sh",
		},
	})
	if simulateResp.Code != http.StatusOK {
		t.Fatalf("simulate after delete status = %d body = %s", simulateResp.Code, simulateResp.Body.String())
	}
	if bytes.Contains(simulateResp.Body.Bytes(), []byte(ruleID)) {
		t.Fatalf("expected deleted custom rule %q to stop matching, got %s", ruleID, simulateResp.Body.String())
	}
}

func newThreatDetectorWithGeo(t *testing.T, geoJSON string) *threat.Detector {
	t.Helper()
	path := filepath.Join(t.TempDir(), "geoip.json")
	if err := os.WriteFile(path, []byte(geoJSON), 0o600); err != nil {
		t.Fatalf("WriteFile(geoip) error = %v", err)
	}
	resolver, err := threat.LoadStaticGeoResolver(path)
	if err != nil {
		t.Fatalf("LoadStaticGeoResolver() error = %v", err)
	}
	return threat.NewDetector(&threat.DetectorConfig{
		Enabled:           true,
		SuppressionWindow: 50 * time.Millisecond,
		MaxAlertsPerRule:  100,
		BusinessHourStart: 6,
		BusinessHourEnd:   22,
		GeoResolver:       resolver,
	})
}

func writeThreatWebhookConfig(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile(webhook config) error = %v", err)
	}
}

func doSignedThreatWebhookRequest(t *testing.T, mux *http.ServeMux, payload threatWebhookPayload, secret, authHeader string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v2/threats/ingest", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if secret != "" {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		req.Header.Set("X-SSH-Proxy-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}
