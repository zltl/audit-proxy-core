package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDiscoveryCMDBImportServiceNow(t *testing.T) {
	api, mux, _ := setupTestAPI(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v2/discovery/cmdb/import", bytes.NewBufferString(`{
		"provider": "servicenow",
		"content": {
			"result": [{
				"sys_id": "cmdb-123",
				"name": "bastion-01",
				"ip_address": "10.40.0.10",
				"os": "Ubuntu 22.04",
				"u_ssh_port": "2222"
			}]
		}
	}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	asset, err := api.initDiscovery().inventory.Get("servicenow:cmdb-123")
	if err != nil {
		t.Fatalf("expected imported asset: %v", err)
	}
	if asset.Host != "10.40.0.10" || asset.Port != 2222 || asset.Tags["cmdb_provider"] != "servicenow" {
		t.Fatalf("unexpected asset: %+v", asset)
	}
}

func TestDiscoveryCMDBImportCustomAPI(t *testing.T) {
	api, mux, _ := setupTestAPI(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v2/discovery/cmdb/import", bytes.NewBufferString(`{
		"provider": "custom-api",
		"content": {
			"items": [{
				"id": "asset-01",
				"displayName": "prod-app-01",
				"connection": {"host": "10.41.0.15", "port": 2200},
				"platform": {"os": "Debian 12"},
				"env": "prod"
			}]
		},
		"items_path": "items",
		"id_field": "id",
		"name_field": "displayName",
		"host_field": "connection.host",
		"port_field": "connection.port",
		"os_field": "platform.os",
		"tag_fields": ["env"],
		"auto_register": true
	}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	asset, err := api.initDiscovery().inventory.Get("custom-api:asset-01")
	if err != nil {
		t.Fatalf("expected imported asset: %v", err)
	}
	if !asset.AutoRegister || asset.Host != "10.41.0.15" || asset.Tags["env"] != "prod" {
		t.Fatalf("unexpected asset: %+v", asset)
	}
}

func TestDiscoveryCMDBImportRejectsMissingProvider(t *testing.T) {
	_, mux, _ := setupTestAPI(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v2/discovery/cmdb/import", bytes.NewBufferString(`{"content": []}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "provider is required") {
		t.Fatalf("unexpected response: %s", rr.Body.String())
	}
}
