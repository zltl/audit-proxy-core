package dataplane

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestListSessionsParsesArrayResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sessions" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{
			{"id": "s1", "username": "alice", "source_ip": "10.0.0.1", "target_host": "srv1", "target_port": 22, "status": "active"},
		})
	}))
	defer ts.Close()

	client := New(ts.URL, "")
	sessions, err := client.ListSessions()
	if err != nil {
		t.Fatalf("ListSessions() error = %v", err)
	}
	if len(sessions) != 1 || sessions[0].ID != "s1" {
		t.Fatalf("ListSessions() = %+v, want one session s1", sessions)
	}
}

func TestListSessionsParsesEnvelopeResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sessions" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"sessions": []map[string]interface{}{
				{
					"id":                 "s1",
					"username":           "alice",
					"source_ip":          "10.0.0.1",
					"client_version":     "OpenSSH_9.7p1 Ubuntu-7ubuntu4",
					"client_os":          "Ubuntu/Linux",
					"device_fingerprint": "sshfp-4d2d9f6a1f0ef8e0",
					"target_host":        "srv1",
					"target_port":        22,
					"status":             "active",
				},
			},
			"total": 1,
		})
	}))
	defer ts.Close()

	client := New(ts.URL, "")
	sessions, err := client.ListSessions()
	if err != nil {
		t.Fatalf("ListSessions() error = %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("len(ListSessions()) = %d, want 1", len(sessions))
	}
	if sessions[0].ClientOS != "Ubuntu/Linux" || sessions[0].DeviceFingerprint == "" {
		t.Fatalf("ListSessions() did not preserve device fields: %+v", sessions[0])
	}
}

func TestGetDrainStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/drain" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":          "draining",
			"draining":        true,
			"active_sessions": 3,
		})
	}))
	defer ts.Close()

	client := New(ts.URL, "")
	status, err := client.GetDrainStatus()
	if err != nil {
		t.Fatalf("GetDrainStatus() error = %v", err)
	}
	if !status.Draining || status.ActiveSessions != 3 {
		t.Fatalf("GetDrainStatus() = %+v, want draining with 3 sessions", status)
	}
}

func TestSetDrainMode(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/drain" || r.Method != http.MethodPut {
			http.NotFound(w, r)
			return
		}
		var req map[string]bool
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if !req["draining"] {
			t.Fatalf("expected draining=true request, got %+v", req)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":          "draining",
			"draining":        true,
			"active_sessions": 2,
		})
	}))
	defer ts.Close()

	client := New(ts.URL, "")
	status, err := client.SetDrainMode(true)
	if err != nil {
		t.Fatalf("SetDrainMode(true) error = %v", err)
	}
	if !status.Draining || status.ActiveSessions != 2 {
		t.Fatalf("SetDrainMode(true) = %+v, want draining with 2 sessions", status)
	}
}

func TestGetHealthParsesDrainingStatusOn503(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":   "draining",
			"version":  "1.0.0",
			"uptime_s": 42,
		})
	}))
	defer ts.Close()

	client := New(ts.URL, "")
	status, err := client.GetHealth()
	if err != nil {
		t.Fatalf("GetHealth() error = %v", err)
	}
	if status.Status != "draining" {
		t.Fatalf("GetHealth() status = %q, want draining", status.Status)
	}
}
