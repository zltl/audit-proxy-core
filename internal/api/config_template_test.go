package api

import (
	"net/http"
	"os"
	"strings"
	"testing"
)

func TestListConfigTemplates(t *testing.T) {
	_, mux, _ := setupTestAPI(t)

	rr := doRequest(mux, http.MethodGet, "/api/v2/config/templates", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	resp := parseResponse(t, rr)
	if resp.Total != 3 {
		t.Fatalf("expected 3 templates, got %d", resp.Total)
	}

	items := resp.Data.([]interface{})
	if items[0].(map[string]interface{})["name"] != "development" {
		t.Fatalf("expected sorted templates with development first, got %#v", items[0])
	}
}

func TestGetConfigTemplateReturnsResolvedConfigAndSanitizesSecrets(t *testing.T) {
	api, mux, _ := setupTestAPI(t)
	if err := os.WriteFile(api.config.ConfigFile, []byte(`{"session_timeout":900,"api_token":"tok-123","nested":{"private_key":"abc123"}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	rr := doRequest(mux, http.MethodGet, "/api/v2/config/templates/production", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "tok-123") || strings.Contains(rr.Body.String(), "abc123") {
		t.Fatalf("template response leaked secrets: %s", rr.Body.String())
	}

	resp := parseResponse(t, rr)
	data := resp.Data.(map[string]interface{})
	if data["name"] != "production" {
		t.Fatalf("expected production template, got %#v", data["name"])
	}

	resolved := data["resolved_config"].(map[string]interface{})
	if resolved["session_timeout"].(float64) != 7200 {
		t.Fatalf("expected production template timeout override, got %#v", resolved["session_timeout"])
	}
	if resolved["api_token"] != redactedConfigValue {
		t.Fatalf("expected redacted api_token, got %#v", resolved["api_token"])
	}
	nested := resolved["nested"].(map[string]interface{})
	if nested["private_key"] != redactedConfigValue {
		t.Fatalf("expected redacted nested private_key, got %#v", nested["private_key"])
	}
}

func TestGetConfigTemplateNotFound(t *testing.T) {
	_, mux, _ := setupTestAPI(t)

	rr := doRequest(mux, http.MethodGet, "/api/v2/config/templates/unknown", nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rr.Code, rr.Body.String())
	}
}
