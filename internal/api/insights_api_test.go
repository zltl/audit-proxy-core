package api

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeInsightsAuditFixture(t *testing.T, api *API) {
	t.Helper()
	body := strings.Join([]string{
		`{"timestamp":"2026-04-09T09:05:00Z","type":"command","user":"alice","target":"prod-app-1","command":"whoami"}`,
		`{"timestamp":"2026-04-09T09:10:00Z","type":"command","user":"alice","target":"prod-app-1","command":"systemctl restart nginx"}`,
		`{"timestamp":"2026-04-09T23:45:00Z","type":"command","user":"alice","target":"prod-k8s-1","command":"kubectl exec deploy/api -- bash"}`,
		`{"timestamp":"2026-04-09T23:50:00Z","type":"command","user":"alice","target":"prod-k8s-1","command":"rm -rf /tmp/cache"}`,
		`{"timestamp":"2026-04-09T10:00:00Z","type":"command","user":"bob","target":"db-1","command":"psql -c \"select 1\""}`,
		`{"timestamp":"2026-04-09T10:05:00Z","type":"login","user":"bob","target":"db-1","details":"failed login"}`,
	}, "\n") + "\n"
	path := filepath.Join(api.config.AuditLogDir, "insights-commands.jsonl")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", path, err)
	}
}

func TestInsightsCommandIntentsAndSummary(t *testing.T) {
	api, mux, _ := setupTestAPI(t)
	writeInsightsAuditFixture(t, api)

	intentsResp := doRequest(mux, "GET", "/api/v2/insights/command-intents", nil)
	if intentsResp.Code != 200 {
		t.Fatalf("GET /api/v2/insights/command-intents status = %d body = %s", intentsResp.Code, intentsResp.Body.String())
	}
	if !strings.Contains(intentsResp.Body.String(), "kubernetes-admin") {
		t.Fatalf("expected kubernetes-admin intent, got %s", intentsResp.Body.String())
	}
	if !strings.Contains(intentsResp.Body.String(), "destructive-change") {
		t.Fatalf("expected destructive-change intent, got %s", intentsResp.Body.String())
	}

	summaryResp := doRequest(mux, "GET", "/api/v2/insights/audit-summary", nil)
	if summaryResp.Code != 200 {
		t.Fatalf("GET /api/v2/insights/audit-summary status = %d body = %s", summaryResp.Code, summaryResp.Body.String())
	}
	if !strings.Contains(summaryResp.Body.String(), `"high_risk_commands":2`) {
		t.Fatalf("expected high_risk_commands=2, got %s", summaryResp.Body.String())
	}
	if !strings.Contains(summaryResp.Body.String(), "Top users") {
		t.Fatalf("expected summary text, got %s", summaryResp.Body.String())
	}
}

func TestInsightsAnomaliesAndRecommendations(t *testing.T) {
	api, mux, _ := setupTestAPI(t)
	writeInsightsAuditFixture(t, api)

	anomalyResp := doRequest(mux, "GET", "/api/v2/insights/anomalies?user=alice", nil)
	if anomalyResp.Code != 200 {
		t.Fatalf("GET /api/v2/insights/anomalies status = %d body = %s", anomalyResp.Code, anomalyResp.Body.String())
	}
	if !strings.Contains(anomalyResp.Body.String(), "off-pattern-hours") {
		t.Fatalf("expected off-pattern-hours deviation, got %s", anomalyResp.Body.String())
	}
	if !strings.Contains(anomalyResp.Body.String(), "high-risk-command") {
		t.Fatalf("expected high-risk-command deviation, got %s", anomalyResp.Body.String())
	}

	recommendResp := doRequest(mux, "GET", "/api/v2/insights/recommendations", nil)
	if recommendResp.Code != 200 {
		t.Fatalf("GET /api/v2/insights/recommendations status = %d body = %s", recommendResp.Code, recommendResp.Body.String())
	}
	if !strings.Contains(recommendResp.Body.String(), `"suggested_role":"admin"`) {
		t.Fatalf("expected admin recommendation for alice, got %s", recommendResp.Body.String())
	}
	if !strings.Contains(recommendResp.Body.String(), `"suggested_role":"operator"`) {
		t.Fatalf("expected operator recommendation for bob, got %s", recommendResp.Body.String())
	}
}

func TestInsightsPolicyPreview(t *testing.T) {
	_, mux, _ := setupTestAPI(t)

	resp := doRequest(mux, "POST", "/api/v2/insights/policy-preview", map[string]interface{}{
		"text": "允许运维团队在工作时间访问生产服务器",
	})
	if resp.Code != 200 {
		t.Fatalf("POST /api/v2/insights/policy-preview status = %d body = %s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), `"role":"operator"`) {
		t.Fatalf("expected operator role, got %s", resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), `"login_window":"09:00-18:00"`) {
		t.Fatalf("expected login window, got %s", resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), `"prod-*"`) {
		t.Fatalf("expected prod-* resource mapping, got %s", resp.Body.String())
	}
}
