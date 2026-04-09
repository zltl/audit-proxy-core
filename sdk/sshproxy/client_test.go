package sshproxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewClientValidatesBaseURL(t *testing.T) {
	_, err := NewClient(Config{BaseURL: "://bad"})
	if err == nil {
		t.Fatal("expected invalid base URL error")
	}
}

func TestListUsers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/users" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer token-123" {
			t.Fatalf("Authorization = %q", got)
		}
		if got := r.Header.Get("User-Agent"); got != defaultUserAgent {
			t.Fatalf("User-Agent = %q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data": []map[string]interface{}{
				{"username": "alice", "role": "admin", "enabled": true},
			},
			"total":    1,
			"page":     1,
			"per_page": 50,
		})
	}))
	defer srv.Close()

	client, err := NewClient(Config{BaseURL: srv.URL, Token: "token-123"})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	page, err := client.ListUsers(context.Background())
	if err != nil {
		t.Fatalf("ListUsers() error = %v", err)
	}
	if page.Total != 1 || len(page.Items) != 1 {
		t.Fatalf("unexpected page: %+v", page)
	}
	if page.Items[0].Username != "alice" {
		t.Fatalf("username = %q", page.Items[0].Username)
	}
}

func TestListSessionsIncludesFilters(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/sessions" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		query := r.URL.Query()
		if query.Get("status") != "active" || query.Get("user") != "alice" || query.Get("page") != "2" || query.Get("per_page") != "10" {
			t.Fatalf("unexpected query: %s", r.URL.RawQuery)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data": []map[string]interface{}{
				{"id": "sess-1", "username": "alice", "status": "active"},
			},
			"total":    11,
			"page":     2,
			"per_page": 10,
		})
	}))
	defer srv.Close()

	client, _ := NewClient(Config{BaseURL: srv.URL})
	page, err := client.ListSessions(context.Background(), SessionsFilter{
		Status:  "active",
		User:    "alice",
		Page:    2,
		PerPage: 10,
	})
	if err != nil {
		t.Fatalf("ListSessions() error = %v", err)
	}
	if page.Page != 2 || page.PerPage != 10 || page.Total != 11 {
		t.Fatalf("unexpected pagination: %+v", page)
	}
}

func TestCreateServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s", r.Method)
		}
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("Decode() error = %v", err)
		}
		if body["host"] != "db.internal" {
			t.Fatalf("host = %#v", body["host"])
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data": map[string]interface{}{
				"id":   "srv-1",
				"name": "db",
				"host": "db.internal",
				"port": 22,
			},
		})
	}))
	defer srv.Close()

	client, _ := NewClient(Config{BaseURL: srv.URL})
	server, err := client.CreateServer(context.Background(), CreateServerRequest{
		Name: "db",
		Host: "db.internal",
		Port: 22,
	})
	if err != nil {
		t.Fatalf("CreateServer() error = %v", err)
	}
	if server.ID != "srv-1" || server.Host != "db.internal" {
		t.Fatalf("unexpected server: %+v", server)
	}
}

func TestSignUserCertificate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/ca/sign-user" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("Decode() error = %v", err)
		}
		if body["public_key"] == "" {
			t.Fatal("missing public_key")
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data": map[string]interface{}{
				"certificate": "ssh-ed25519-cert-v01@openssh.com AAAA...",
				"serial":      7,
				"key_id":      "alice-7",
				"expires_at":  "2026-04-08T12:00:00Z",
			},
		})
	}))
	defer srv.Close()

	client, _ := NewClient(Config{BaseURL: srv.URL})
	cert, err := client.SignUserCertificate(context.Background(), SignUserCertificateRequest{
		PublicKey:  "ssh-ed25519 AAAAalice",
		Principals: []string{"alice"},
		TTL:        "8h",
	})
	if err != nil {
		t.Fatalf("SignUserCertificate() error = %v", err)
	}
	if cert.Serial != 7 || cert.KeyID != "alice-7" {
		t.Fatalf("unexpected cert: %+v", cert)
	}
}

func TestAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"success":false,"error":"bad request"}`))
	}))
	defer srv.Close()

	client, _ := NewClient(Config{BaseURL: srv.URL})
	_, err := client.ListUsers(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "bad request") {
		t.Fatalf("error = %v", err)
	}
}
