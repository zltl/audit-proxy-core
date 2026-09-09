package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zltl/audit-proxy-core/internal/features"
)

// newGatedTestAPI builds an API with the given experimental feature list.
func newGatedTestAPI(t *testing.T, enabled string) *http.ServeMux {
	t.Helper()
	dir := t.TempDir()
	cfg := &Config{
		AdminUser:            "admin",
		SessionSecret:        "secret",
		AuditLogDir:          filepath.Join(dir, "audit"),
		RecordingDir:         dir,
		DataDir:              dir,
		ConfigFile:           filepath.Join(dir, "config.ini"),
		ConfigVerDir:         filepath.Join(dir, "config_versions"),
		ExperimentalFeatures: enabled,
	}
	if err := os.MkdirAll(cfg.AuditLogDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	api, err := New(&mockDP{}, cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = api.Close() })
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)
	api.RegisterCollabRoutes(mux)
	return mux
}

func TestExperimentalSubsystemsAreGatedByDefault(t *testing.T) {
	mux := newGatedTestAPI(t, "")

	cases := []struct {
		method, path, feature string
	}{
		{http.MethodGet, "/api/v2/gateway/proxies", features.Gateway},
		{http.MethodPost, "/api/v2/gateway/proxies", features.Gateway},
		{http.MethodGet, "/api/v2/collab/sessions", features.Collab},
		{http.MethodGet, "/api/v2/insights/command-intents", features.Insights},
		{http.MethodPost, "/api/v2/insights/policy-preview", features.Insights},
	}
	for _, tc := range cases {
		rr := doRequest(mux, tc.method, tc.path, map[string]interface{}{})
		if rr.Code != http.StatusServiceUnavailable {
			t.Errorf("%s %s = %d, want 503 while %s is disabled", tc.method, tc.path, rr.Code, tc.feature)
			continue
		}
		body := rr.Body.String()
		if !strings.Contains(body, tc.feature) {
			t.Errorf("%s %s: error body should name the feature, got %s", tc.method, tc.path, body)
		}
		if !strings.Contains(body, "experimental_features="+tc.feature) {
			t.Errorf("%s %s: error body should say how to enable it, got %s", tc.method, tc.path, body)
		}
	}
}

func TestExperimentalGateOpensForNamedFeatureOnly(t *testing.T) {
	mux := newGatedTestAPI(t, "insights")

	if rr := doRequest(mux, http.MethodGet, "/api/v2/insights/command-intents", nil); rr.Code == http.StatusServiceUnavailable {
		t.Fatalf("insights should be reachable when enabled: %s", rr.Body.String())
	}
	if rr := doRequest(mux, http.MethodGet, "/api/v2/gateway/proxies", nil); rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("gateway should stay gated when only insights is enabled, got %d", rr.Code)
	}
}

func TestSystemFeaturesEndpointReportsGateState(t *testing.T) {
	mux := newGatedTestAPI(t, "gateway")

	rr := doRequest(mux, http.MethodGet, "/api/v2/system/features", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/v2/system/features = %d: %s", rr.Code, rr.Body.String())
	}
	data := parseResponse(t, rr).Data.(map[string]interface{})
	items, ok := data["experimental"].([]interface{})
	if !ok || len(items) != len(features.All) {
		t.Fatalf("expected %d features, got %v", len(features.All), data["experimental"])
	}

	states := make(map[string]bool, len(items))
	for _, raw := range items {
		item := raw.(map[string]interface{})
		name := item["name"].(string)
		states[name] = item["enabled"].(bool)
		if item["reason"] == "" {
			t.Errorf("feature %q has no stated reason for being gated", name)
		}
	}
	if !states[features.Gateway] {
		t.Error("gateway should report as enabled")
	}
	if states[features.Collab] || states[features.Insights] {
		t.Error("features that were not named should report as disabled")
	}
}

func TestParseAndValidateFeatureNames(t *testing.T) {
	if got := features.Parse("all"); len(got) != len(features.All) {
		t.Fatalf(`Parse("all") = %v, want every gate`, got)
	}
	if got := features.Parse(" Gateway , insights "); len(got) != 2 {
		t.Fatalf("Parse should trim and lowercase, got %v", got)
	}
	if got := features.Parse(""); len(got) != 0 {
		t.Fatalf("Parse(\"\") = %v, want none", got)
	}
	if got := features.Unknown("gateway,teleporter"); len(got) != 1 || got[0] != "teleporter" {
		t.Fatalf("Unknown() = %v, want [teleporter]", got)
	}
	if got := features.Unknown("gateway,collab,insights"); len(got) != 0 {
		t.Fatalf("Unknown() flagged known names: %v", got)
	}
}

func TestGateReturnsBeforeTouchingSubsystemState(t *testing.T) {
	// A gated handler must not run, even when the subsystem it guards was never
	// initialised — otherwise disabling a feature would turn a 503 into a panic.
	mux := newGatedTestAPI(t, "")
	req := httptest.NewRequest(http.MethodGet, "/api/v2/collab/sessions/does-not-exist", nil)
	req.Header.Set("X-Auth-User", "admin")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", rec.Code, rec.Body.String())
	}
}
