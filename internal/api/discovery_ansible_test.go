package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDiscoveryAnsibleImportJSON(t *testing.T) {
	api, mux, _ := setupTestAPI(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v2/discovery/ansible/import", bytes.NewBufferString(`{
		"format": "json",
		"content": {
			"_meta": {
				"hostvars": {
					"web-1": {
						"ansible_host": "10.70.0.10",
						"ansible_port": "2222",
						"env": "prod"
					}
				}
			},
			"web": {
				"hosts": ["web-1"]
			}
		}
	}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	asset, err := api.initDiscovery().inventory.Get("ansible:web-1")
	if err != nil {
		t.Fatalf("expected imported asset: %v", err)
	}
	if asset.Host != "10.70.0.10" || asset.Port != 2222 || asset.Tags["env"] != "prod" {
		t.Fatalf("unexpected asset: %+v", asset)
	}
}

func TestDiscoveryAnsibleImportINI(t *testing.T) {
	api, mux, _ := setupTestAPI(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v2/discovery/ansible/import", bytes.NewBufferString(`{
		"content_text": "[web]\nweb-2 ansible_host=10.71.0.10 ansible_port=2200 env=prod\n",
		"auto_register": true
	}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	asset, err := api.initDiscovery().inventory.Get("ansible:web-2")
	if err != nil {
		t.Fatalf("expected imported asset: %v", err)
	}
	if !asset.AutoRegister || asset.Host != "10.71.0.10" || asset.Port != 2200 {
		t.Fatalf("unexpected asset: %+v", asset)
	}
}
