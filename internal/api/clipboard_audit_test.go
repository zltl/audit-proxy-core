package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandleCreateClipboardAudit(t *testing.T) {
	a := &API{
		config: &Config{
			AuditLogDir:              t.TempDir(),
			DLPClipboardAuditEnabled: true,
		},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v2/terminal/clipboard-audit", a.handleCreateClipboardAudit)

	req := httptest.NewRequest(http.MethodPost, "/api/v2/terminal/clipboard-audit", strings.NewReader(`{
		"target":"srv1.local:22",
		"source":"toolbar",
		"text_length":42,
		"sensitive":true,
		"matched_detectors":["api-key","api-key","credit-card"]
	}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-User", "alice")
	req.RemoteAddr = "203.0.113.7:54321"
	rr := httptest.NewRecorder()

	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d body=%s", rr.Code, http.StatusCreated, rr.Body.String())
	}

	events, err := a.loadAuditEvents()
	if err != nil {
		t.Fatalf("loadAuditEvents() error = %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("len(events) = %d, want 1", len(events))
	}
	event := events[0]
	if event.EventType != "terminal.clipboard_paste" {
		t.Fatalf("event_type = %q, want terminal.clipboard_paste", event.EventType)
	}
	if event.Username != "alice" {
		t.Fatalf("username = %q, want alice", event.Username)
	}
	if event.SourceIP != "203.0.113.7" {
		t.Fatalf("source_ip = %q, want 203.0.113.7", event.SourceIP)
	}
	if event.TargetHost != "srv1.local:22" {
		t.Fatalf("target_host = %q, want srv1.local:22", event.TargetHost)
	}
	if !strings.Contains(event.Details, "source=toolbar") || !strings.Contains(event.Details, "detectors=api-key,credit-card") {
		t.Fatalf("details = %q, want normalized source/detectors", event.Details)
	}
}

func TestHandleCreateClipboardAuditRequiresFeature(t *testing.T) {
	a := &API{
		config: &Config{
			AuditLogDir: t.TempDir(),
		},
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v2/terminal/clipboard-audit", strings.NewReader(`{"text_length":4}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-User", "alice")
	rr := httptest.NewRecorder()

	a.handleCreateClipboardAudit(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d body=%s", rr.Code, http.StatusServiceUnavailable, rr.Body.String())
	}
}
