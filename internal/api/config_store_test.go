package api

import (
	"net/http"
	"os"
	"testing"
	"time"
)

func TestGetConfigStoreReturnsBootstrappedSnapshot(t *testing.T) {
	_, mux, _ := setupTestAPI(t)

	rr := doRequest(mux, http.MethodGet, "/api/v2/config/store", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	resp := parseResponse(t, rr)
	data := resp.Data.(map[string]interface{})
	if data["version"] == "" {
		t.Fatalf("expected stored version, got %#v", data["version"])
	}
	if data["source"] != "bootstrap" {
		t.Fatalf("expected bootstrap source, got %#v", data["source"])
	}
	config := data["config"].(map[string]interface{})
	if config["listen_port"] != float64(2222) {
		t.Fatalf("expected listen_port 2222, got %#v", config["listen_port"])
	}
}

func TestGetConfigFallsBackToCentralStoreWhenConfigFileMissing(t *testing.T) {
	api, mux, dp := setupTestAPI(t)
	dp.config = map[string]interface{}{"listen_port": 9999}

	if err := api.configStore.Save([]byte(`{"listen_port":4444}`), "stored-v1", "chg-1", "admin", "node-1", time.Now().UTC()); err != nil {
		t.Fatalf("configStore.Save() error = %v", err)
	}
	if err := os.Remove(api.config.ConfigFile); err != nil {
		t.Fatalf("Remove(config file) error = %v", err)
	}

	rr := doRequest(mux, http.MethodGet, "/api/v2/config", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	resp := parseResponse(t, rr)
	data := resp.Data.(map[string]interface{})
	if data["listen_port"] != float64(4444) {
		t.Fatalf("expected stored listen_port 4444, got %#v", data["listen_port"])
	}
}
