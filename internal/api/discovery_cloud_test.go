package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDiscoveryCloudImportInlineContent(t *testing.T) {
	api, mux, _ := setupTestAPI(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v2/discovery/cloud/import", bytes.NewBufferString(`{
		"provider": "aws",
		"content": {
			"Reservations": [{
				"Instances": [{
					"InstanceId": "i-123",
					"PrivateIpAddress": "10.0.5.10",
					"PlatformDetails": "Linux/UNIX",
					"State": {"Name": "running"},
					"Tags": [{"Key": "Name", "Value": "bastion"}]
				}]
			}]
		},
		"auto_register": true
	}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	asset, err := api.initDiscovery().inventory.Get("aws-ec2:i-123")
	if err != nil {
		t.Fatalf("expected imported asset: %v", err)
	}
	if !asset.AutoRegister || asset.Host != "10.0.5.10" || asset.Tags["cloud_provider"] != "aws-ec2" {
		t.Fatalf("unexpected asset: %+v", asset)
	}
}

func TestDiscoveryCloudImportFromHTTPURI(t *testing.T) {
	api, mux, _ := setupTestAPI(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[
		{
			"vmId": "vm-123",
			"name": "jumpbox",
			"privateIps": "10.0.6.10",
			"resourceGroup": "rg-prod",
			"tags": {"env": "prod"}
		}
	]`))
	}))
	defer server.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/v2/discovery/cloud/import", bytes.NewBufferString(`{
		"provider": "azure",
		"uri": "`+server.URL+`",
		"tag_filters": {"env": "prod"}
	}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	asset, err := api.initDiscovery().inventory.Get("azure-vm:vm-123")
	if err != nil {
		t.Fatalf("expected imported asset: %v", err)
	}
	if asset.Host != "10.0.6.10" || asset.Tags["resource_group"] != "rg-prod" {
		t.Fatalf("unexpected asset: %+v", asset)
	}
}

func TestDiscoveryCloudImportRejectsMissingProvider(t *testing.T) {
	_, mux, _ := setupTestAPI(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v2/discovery/cloud/import", bytes.NewBufferString(`{"content": []}`))
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
