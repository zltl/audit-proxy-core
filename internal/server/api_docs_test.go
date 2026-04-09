package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOpenAPIJSONRequiresAuthentication(t *testing.T) {
	dataPlane := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(dataPlane.Close)

	_, controlPlane := newControlPlaneTestServer(t, dataPlane.URL, "dp-secret-token")
	resp := mustRequest(t, http.DefaultClient, http.MethodGet, controlPlane.URL+"/api/openapi.json", nil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		body := string(mustReadBody(t, resp))
		t.Fatalf("GET /api/openapi.json status = %d body = %s", resp.StatusCode, body)
	}
}

func TestAPIDocsEndpointsExposeSwaggerAndSpec(t *testing.T) {
	dataPlane := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(dataPlane.Close)

	cfg, controlPlane := newControlPlaneTestServer(t, dataPlane.URL, "dp-secret-token")
	client := newAuthenticatedClient(t, controlPlane.URL, cfg.SessionSecret)

	specResp := mustRequest(t, client, http.MethodGet, controlPlane.URL+"/api/openapi.json", nil, nil)
	if specResp.StatusCode != http.StatusOK {
		body := string(mustReadBody(t, specResp))
		t.Fatalf("GET /api/openapi.json status = %d body = %s", specResp.StatusCode, body)
	}
	specBody := string(mustReadBody(t, specResp))
	if !strings.Contains(specBody, `"openapi": "3.0.3"`) {
		t.Fatalf("OpenAPI JSON missing version marker: %s", specBody)
	}
	if !strings.Contains(specBody, `"/api/v2/system/health"`) {
		t.Fatalf("OpenAPI JSON missing system health path: %s", specBody)
	}

	docsResp := mustRequest(t, client, http.MethodGet, controlPlane.URL+"/api/docs", nil, nil)
	if docsResp.StatusCode != http.StatusOK {
		body := string(mustReadBody(t, docsResp))
		t.Fatalf("GET /api/docs status = %d body = %s", docsResp.StatusCode, body)
	}
	docsBody := string(mustReadBody(t, docsResp))
	if !strings.Contains(docsBody, "SwaggerUIBundle") {
		t.Fatalf("Swagger UI page missing bundle bootstrap: %s", docsBody)
	}
	if !strings.Contains(docsBody, "/api/openapi.json") {
		t.Fatalf("Swagger UI page missing spec URL: %s", docsBody)
	}
	if !strings.Contains(docsBody, "X-CSRF-Token") {
		t.Fatalf("Swagger UI page missing CSRF interceptor: %s", docsBody)
	}
}
