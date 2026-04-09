package openapi

import "testing"

func TestBuildIncludesCoreRoutesAndSecurityMetadata(t *testing.T) {
	doc := Build()

	if doc.OpenAPI != "3.0.3" {
		t.Fatalf("OpenAPI version = %q, want 3.0.3", doc.OpenAPI)
	}
	if len(doc.Paths) < 10 {
		t.Fatalf("expected many documented paths, got %d", len(doc.Paths))
	}

	publicHealth := doc.Paths["/api/v1/health"]
	if publicHealth == nil || publicHealth.Get == nil {
		t.Fatal("missing GET /api/v1/health operation")
	}
	if len(publicHealth.Get.Security) != 0 {
		t.Fatal("public health should not require auth")
	}

	configReload := doc.Paths["/api/v2/config/reload"]
	if configReload == nil || configReload.Post == nil {
		t.Fatal("missing POST /api/v2/config/reload operation")
	}
	if !hasParameter(configReload.Post.Parameters, "X-CSRF-Token", "header") {
		t.Fatal("config reload should document X-CSRF-Token header")
	}
	if len(configReload.Post.Security) == 0 {
		t.Fatal("config reload should require cookie auth")
	}

	configChangeApprove := doc.Paths["/api/v2/config/changes/{id}/approve"]
	if configChangeApprove == nil || configChangeApprove.Post == nil {
		t.Fatal("missing POST /api/v2/config/changes/{id}/approve operation")
	}
	if !hasParameter(configChangeApprove.Post.Parameters, "X-CSRF-Token", "header") {
		t.Fatal("config change approval should document X-CSRF-Token header")
	}

	configSyncStatus := doc.Paths["/api/v2/config/sync-status"]
	if configSyncStatus == nil || configSyncStatus.Get == nil {
		t.Fatal("missing GET /api/v2/config/sync-status operation")
	}

	configTemplates := doc.Paths["/api/v2/config/templates"]
	if configTemplates == nil || configTemplates.Get == nil {
		t.Fatal("missing GET /api/v2/config/templates operation")
	}

	configExport := doc.Paths["/api/v2/config/export"]
	if configExport == nil || configExport.Get == nil {
		t.Fatal("missing GET /api/v2/config/export operation")
	}

	configImport := doc.Paths["/api/v2/config/import"]
	if configImport == nil || configImport.Post == nil {
		t.Fatal("missing POST /api/v2/config/import operation")
	}
	if !hasParameter(configImport.Post.Parameters, "X-CSRF-Token", "header") {
		t.Fatal("config import should document X-CSRF-Token header")
	}

	configTemplate := doc.Paths["/api/v2/config/templates/{name}"]
	if configTemplate == nil || configTemplate.Get == nil {
		t.Fatal("missing GET /api/v2/config/templates/{name} operation")
	}

	terminalRecording := doc.Paths["/api/v2/terminal/recordings/{id}/download"]
	if terminalRecording == nil || terminalRecording.Get == nil {
		t.Fatal("missing GET /api/v2/terminal/recordings/{id}/download operation")
	}
	if _, ok := terminalRecording.Get.Responses["200"].Content["application/x-asciicast"]; !ok {
		t.Fatal("terminal recording download should expose application/x-asciicast content")
	}

	metrics := doc.Paths["/api/v2/system/metrics"]
	if metrics == nil || metrics.Get == nil {
		t.Fatal("missing GET /api/v2/system/metrics operation")
	}
	if _, ok := metrics.Get.Responses["200"].Content["text/plain"]; !ok {
		t.Fatal("system metrics should expose text/plain response content")
	}

	upgradeStatus := doc.Paths["/api/v2/system/upgrade"]
	if upgradeStatus == nil || upgradeStatus.Get == nil || upgradeStatus.Put == nil {
		t.Fatal("missing GET/PUT /api/v2/system/upgrade operations")
	}
	if !hasParameter(upgradeStatus.Put.Parameters, "X-CSRF-Token", "header") {
		t.Fatal("system upgrade drain toggle should document X-CSRF-Token header")
	}

	threatIngest := doc.Paths["/api/v2/threats/ingest"]
	if threatIngest == nil || threatIngest.Post == nil {
		t.Fatal("missing POST /api/v2/threats/ingest operation")
	}
	if len(threatIngest.Post.Security) != 0 {
		t.Fatal("threat ingest should be documented as a public webhook endpoint")
	}
	if hasParameter(threatIngest.Post.Parameters, "X-CSRF-Token", "header") {
		t.Fatal("threat ingest should not require CSRF")
	}

	threatRisk := doc.Paths["/api/v2/threats/risk"]
	if threatRisk == nil || threatRisk.Get == nil {
		t.Fatal("missing GET /api/v2/threats/risk operation")
	}

	sessionSchema := doc.Components.Schemas["Session"]
	if sessionSchema == nil {
		t.Fatal("missing Session schema")
	}
	if sessionSchema.Properties["client_version"] == nil ||
		sessionSchema.Properties["device_fingerprint"] == nil ||
		sessionSchema.Properties["instance_id"] == nil {
		t.Fatal("session schema should expose shared-session metadata")
	}
}

func hasParameter(params []Parameter, name, location string) bool {
	for _, param := range params {
		if param.Name == name && param.In == location {
			return true
		}
	}
	return false
}
