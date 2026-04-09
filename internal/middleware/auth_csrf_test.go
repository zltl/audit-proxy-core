package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthAllowsThreatIngestWithoutSession(t *testing.T) {
	handler := Auth("test-secret")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	for _, path := range []string{"/api/v2/threats/ingest", "/api/v3/threats/ingest"} {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusNoContent {
			t.Fatalf("POST %s status = %d body = %s", path, rr.Code, rr.Body.String())
		}
	}
}

func TestCSRFSkipsThreatIngest(t *testing.T) {
	handler := CSRF("test-secret")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	for _, path := range []string{"/api/v2/threats/ingest", "/api/v3/threats/ingest"} {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusNoContent {
			t.Fatalf("POST %s status = %d body = %s", path, rr.Code, rr.Body.String())
		}
	}
}
