package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRateLimitRejectsBurstFromSameClient(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v2/users", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := Chain(mux, RateLimit(1, 1))

	req := httptest.NewRequest(http.MethodGet, "/api/v2/users", nil)
	req.RemoteAddr = "192.0.2.1:1234"

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("first request status = %d, want 200", rr.Code)
	}

	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req.Clone(req.Context()))
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("second request status = %d, want 429", rr.Code)
	}
}

func TestRateLimitBucketsRefillAndSeparateClients(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v2/users", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := Chain(mux, RateLimit(20, 1))

	req1 := httptest.NewRequest(http.MethodGet, "/api/v2/users", nil)
	req1.RemoteAddr = "192.0.2.1:1234"
	req2 := httptest.NewRequest(http.MethodGet, "/api/v2/users", nil)
	req2.RemoteAddr = "198.51.100.2:4321"

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req1)
	if rr.Code != http.StatusOK {
		t.Fatalf("client 1 first request status = %d, want 200", rr.Code)
	}

	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req2)
	if rr.Code != http.StatusOK {
		t.Fatalf("client 2 first request status = %d, want 200", rr.Code)
	}

	time.Sleep(60 * time.Millisecond)

	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req1.Clone(req1.Context()))
	if rr.Code != http.StatusOK {
		t.Fatalf("client 1 refilled request status = %d, want 200", rr.Code)
	}
}
