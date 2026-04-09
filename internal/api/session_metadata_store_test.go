package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/models"
)

func decodeSessionList(t *testing.T, data interface{}) []models.Session {
	t.Helper()
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("marshal session list: %v", err)
	}
	var sessions []models.Session
	if err := json.Unmarshal(raw, &sessions); err != nil {
		t.Fatalf("unmarshal session list: %v", err)
	}
	return sessions
}

func decodeSession(t *testing.T, data interface{}) models.Session {
	t.Helper()
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("marshal session: %v", err)
	}
	var session models.Session
	if err := json.Unmarshal(raw, &session); err != nil {
		t.Fatalf("unmarshal session: %v", err)
	}
	return session
}

func findSession(t *testing.T, sessions []models.Session, id string) models.Session {
	t.Helper()
	for _, session := range sessions {
		if session.ID == id {
			return session
		}
	}
	t.Fatalf("session %q not found in %+v", id, sessions)
	return models.Session{}
}

func TestListSessionsPersistsMetadataAcrossRestarts(t *testing.T) {
	api, mux, dp := setupTestAPI(t)
	t.Cleanup(func() { _ = api.Close() })

	rr := doRequest(mux, http.MethodGet, "/api/v2/sessions", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	resp := parseResponse(t, rr)
	initial := decodeSessionList(t, resp.Data)
	if len(initial) != 3 {
		t.Fatalf("expected 3 initial sessions, got %d", len(initial))
	}

	dp.sessions = nil
	rr = doRequest(mux, http.MethodGet, "/api/v2/sessions", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 after live sessions drained, got %d: %s", rr.Code, rr.Body.String())
	}
	resp = parseResponse(t, rr)
	persisted := decodeSessionList(t, resp.Data)
	if len(persisted) != 3 {
		t.Fatalf("expected 3 persisted sessions, got %d", len(persisted))
	}
	if got := findSession(t, persisted, "s1").Status; got != "closed" {
		t.Fatalf("expected s1 to transition to closed, got %q", got)
	}
	if got := findSession(t, persisted, "s3").Status; got != "closed" {
		t.Fatalf("expected s3 to transition to closed, got %q", got)
	}

	api2, err := New(dp, api.config)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = api2.Close() })
	mux2 := http.NewServeMux()
	api2.RegisterRoutes(mux2)

	rr = doRequest(mux2, http.MethodGet, "/api/v2/sessions/s1", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 from restarted API, got %d: %s", rr.Code, rr.Body.String())
	}
	resp = parseResponse(t, rr)
	session := decodeSession(t, resp.Data)
	if session.ID != "s1" || session.Status != "closed" {
		t.Fatalf("unexpected persisted session after restart: %+v", session)
	}
}

func TestKillSessionMarksPersistedRecordTerminated(t *testing.T) {
	api, mux, _ := setupTestAPI(t)
	t.Cleanup(func() { _ = api.Close() })

	rr := doRequest(mux, http.MethodGet, "/api/v2/sessions", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("seed list sessions: got %d: %s", rr.Code, rr.Body.String())
	}

	rr = doRequest(mux, http.MethodDelete, "/api/v2/sessions/s1", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 terminating session, got %d: %s", rr.Code, rr.Body.String())
	}

	rr = doRequest(mux, http.MethodGet, "/api/v2/sessions/s1", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected persisted terminated session, got %d: %s", rr.Code, rr.Body.String())
	}
	resp := parseResponse(t, rr)
	session := decodeSession(t, resp.Data)
	if session.Status != "terminated" {
		t.Fatalf("expected terminated session status, got %+v", session)
	}
}

func TestStartSessionMetadataSyncPersistsSessionsInBackground(t *testing.T) {
	api, _, _ := setupTestAPI(t)
	t.Cleanup(func() { _ = api.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	api.StartSessionMetadataSync(ctx, 20*time.Millisecond)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		sessions, err := api.sessionMetadata.ListSessions()
		if err == nil && len(sessions) == 3 {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("session metadata background sync did not persist sessions")
}
