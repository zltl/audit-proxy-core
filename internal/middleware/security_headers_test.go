package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHSTSAddsHeaderOnHTTPS(t *testing.T) {
	handler := HSTS(true, true, true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "https://proxy.example.com/dashboard", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	got := rr.Header().Get("Strict-Transport-Security")
	want := "max-age=31536000; includeSubDomains; preload"
	if got != want {
		t.Fatalf("Strict-Transport-Security = %q, want %q", got, want)
	}
}

func TestHSTSDoesNotAddHeaderOnHTTP(t *testing.T) {
	handler := HSTS(true, false, false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "http://proxy.example.com/dashboard", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if got := rr.Header().Get("Strict-Transport-Security"); got != "" {
		t.Fatalf("Strict-Transport-Security = %q, want empty", got)
	}
}
