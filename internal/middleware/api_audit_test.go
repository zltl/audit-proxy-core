package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/models"
)

func TestAPIAuditLogsAuthenticatedRequest(t *testing.T) {
	secret := "test-secret"
	auditDir := t.TempDir()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v2/users", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})

	handler := Chain(mux, APIAudit(auditDir, secret), CSRF(secret), Auth(secret))
	req := httptest.NewRequest(http.MethodGet, "/api/v2/users?page=2", nil)
	req.RemoteAddr = "192.0.2.10:12345"
	req.AddCookie(CreateSessionCookie("alice", secret, time.Hour))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	events := readAPIAuditEvents(t, auditDir)
	if len(events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(events))
	}
	if events[0].EventType != "api.request" {
		t.Fatalf("unexpected event type: %#v", events[0].EventType)
	}
	if events[0].Username != "alice" {
		t.Fatalf("expected username alice, got %#v", events[0].Username)
	}
	if events[0].SourceIP != "192.0.2.10" {
		t.Fatalf("expected source IP 192.0.2.10, got %#v", events[0].SourceIP)
	}
	if !strings.Contains(events[0].Details, `"path":"/api/v2/users"`) || !strings.Contains(events[0].Details, `"status":200`) {
		t.Fatalf("unexpected details payload: %s", events[0].Details)
	}
}

func TestAPIAuditLogsCSRFFailuresWithSessionIdentity(t *testing.T) {
	secret := "test-secret"
	auditDir := t.TempDir()

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v2/config/reload", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := Chain(mux, APIAudit(auditDir, secret), CSRF(secret), Auth(secret))
	req := httptest.NewRequest(http.MethodPost, "/api/v2/config/reload", strings.NewReader(`{}`))
	req.RemoteAddr = "198.51.100.8:54321"
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(CreateSessionCookie("admin", secret, time.Hour))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}

	events := readAPIAuditEvents(t, auditDir)
	if len(events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(events))
	}
	if events[0].Username != "admin" {
		t.Fatalf("expected username admin, got %#v", events[0].Username)
	}
	if !strings.Contains(events[0].Details, `"status":403`) || !strings.Contains(events[0].Details, `"path":"/api/v2/config/reload"`) {
		t.Fatalf("unexpected details payload: %s", events[0].Details)
	}
}

func readAPIAuditEvents(t *testing.T, dir string) []models.AuditEvent {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	var events []models.AuditEvent
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".jsonl" {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			var event models.AuditEvent
			if err := json.Unmarshal([]byte(line), &event); err != nil {
				t.Fatalf("invalid audit event %q: %v", line, err)
			}
			events = append(events, event)
		}
	}
	return events
}
