package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeAPI spins up a test HTTP server that mimics the SSH Proxy control-plane
// API surface used by the Terraform provider CLI.
func fakeAPI(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/v2/users", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data":    []map[string]string{{"username": "alice"}, {"username": "bob"}},
		})
	})

	mux.HandleFunc("GET /api/v2/servers", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data":    []map[string]string{{"id": "srv-1", "host": "10.0.0.1"}},
		})
	})

	mux.HandleFunc("POST /api/v2/users", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "data": body})
	})

	mux.HandleFunc("PUT /api/v2/users/{username}", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "data": body})
	})

	mux.HandleFunc("DELETE /api/v2/users/{username}", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data":    map[string]string{"message": "deleted"},
		})
	})

	mux.HandleFunc("POST /api/v2/servers", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		body["id"] = "srv-new"
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "data": body})
	})

	mux.HandleFunc("PUT /api/v2/servers/{id}", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "data": body})
	})

	mux.HandleFunc("DELETE /api/v2/servers/{id}", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data":    map[string]string{"message": "deleted"},
		})
	})

	mux.HandleFunc("GET /api/v2/config", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data":    map[string]interface{}{"listen_port": 2222},
		})
	})

	mux.HandleFunc("PUT /api/v2/config", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "data": body})
	})

	return httptest.NewServer(mux)
}

func makeClient(t *testing.T, serverURL string) *apiClient {
	t.Helper()
	return &apiClient{
		baseURL:    serverURL,
		token:      "test-token",
		httpClient: http.DefaultClient,
	}
}

// ---------- Tests ----------

func TestReadUsers(t *testing.T) {
	srv := fakeAPI(t)
	defer srv.Close()
	client := makeClient(t, srv.URL)

	result, err := dispatch("read-users", nil, strings.NewReader(""), client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Contains(result, []byte("alice")) {
		t.Errorf("expected alice in result: %s", string(result))
	}
}

func TestReadServers(t *testing.T) {
	srv := fakeAPI(t)
	defer srv.Close()
	client := makeClient(t, srv.URL)

	result, err := dispatch("read-servers", nil, strings.NewReader(""), client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Contains(result, []byte("srv-1")) {
		t.Errorf("expected srv-1 in result: %s", string(result))
	}
}

func TestCreateUser(t *testing.T) {
	srv := fakeAPI(t)
	defer srv.Close()
	client := makeClient(t, srv.URL)

	input := `{"username":"charlie","password":"secret123","role":"viewer"}`
	result, err := dispatch("create-user", nil, strings.NewReader(input), client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Contains(result, []byte("charlie")) {
		t.Errorf("expected charlie in result: %s", string(result))
	}
}

func TestUpdateUser(t *testing.T) {
	srv := fakeAPI(t)
	defer srv.Close()
	client := makeClient(t, srv.URL)

	input := `{"username":"alice","display_name":"Alice Smith"}`
	result, err := dispatch("update-user", nil, strings.NewReader(input), client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Contains(result, []byte("Alice Smith")) {
		t.Errorf("expected Alice Smith in result: %s", string(result))
	}
}

func TestUpdateUserMissingUsername(t *testing.T) {
	srv := fakeAPI(t)
	defer srv.Close()
	client := makeClient(t, srv.URL)

	input := `{"display_name":"No Username"}`
	_, err := dispatch("update-user", nil, strings.NewReader(input), client)
	if err == nil {
		t.Fatal("expected error for missing username")
	}
	if !strings.Contains(err.Error(), "username is required") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDeleteUser(t *testing.T) {
	srv := fakeAPI(t)
	defer srv.Close()
	client := makeClient(t, srv.URL)

	result, err := dispatch("delete-user", []string{"alice"}, strings.NewReader(""), client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Contains(result, []byte("deleted")) {
		t.Errorf("expected deleted message: %s", string(result))
	}
}

func TestDeleteUserMissingArg(t *testing.T) {
	srv := fakeAPI(t)
	defer srv.Close()
	client := makeClient(t, srv.URL)

	_, err := dispatch("delete-user", nil, strings.NewReader(""), client)
	if err == nil {
		t.Fatal("expected error for missing argument")
	}
}

func TestCreateServer(t *testing.T) {
	srv := fakeAPI(t)
	defer srv.Close()
	client := makeClient(t, srv.URL)

	input := `{"name":"web-server","host":"10.0.1.5","port":22}`
	result, err := dispatch("create-server", nil, strings.NewReader(input), client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Contains(result, []byte("web-server")) {
		t.Errorf("expected web-server in result: %s", string(result))
	}
}

func TestDeleteServer(t *testing.T) {
	srv := fakeAPI(t)
	defer srv.Close()
	client := makeClient(t, srv.URL)

	result, err := dispatch("delete-server", []string{"srv-1"}, strings.NewReader(""), client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Contains(result, []byte("deleted")) {
		t.Errorf("expected deleted message: %s", string(result))
	}
}

func TestReadConfig(t *testing.T) {
	srv := fakeAPI(t)
	defer srv.Close()
	client := makeClient(t, srv.URL)

	result, err := dispatch("read-config", nil, strings.NewReader(""), client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Contains(result, []byte("listen_port")) {
		t.Errorf("expected listen_port in result: %s", string(result))
	}
}

func TestApplyConfig(t *testing.T) {
	srv := fakeAPI(t)
	defer srv.Close()
	client := makeClient(t, srv.URL)

	input := `{"listen_port":3333}`
	result, err := dispatch("apply-config", nil, strings.NewReader(input), client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Contains(result, []byte("3333")) {
		t.Errorf("expected 3333 in result: %s", string(result))
	}
}

func TestUnknownAction(t *testing.T) {
	srv := fakeAPI(t)
	defer srv.Close()
	client := makeClient(t, srv.URL)

	_, err := dispatch("bogus-action", nil, strings.NewReader(""), client)
	if err == nil {
		t.Fatal("expected error for unknown action")
	}
	if !strings.Contains(err.Error(), "unknown action") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunMissingAction(t *testing.T) {
	code, _ := run([]string{"terraform-provider-sshproxy"}, strings.NewReader(""))
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestNewClientMissingServer(t *testing.T) {
	t.Setenv("SSHPROXY_SERVER", "")
	_, err := newClient()
	if err == nil {
		t.Fatal("expected error when SSHPROXY_SERVER is not set")
	}
}

func TestJSONOutputFormat(t *testing.T) {
	srv := fakeAPI(t)
	defer srv.Close()
	client := makeClient(t, srv.URL)

	result, err := dispatch("read-users", nil, strings.NewReader(""), client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Must be valid JSON.
	if !json.Valid(result) {
		t.Errorf("output is not valid JSON: %s", string(result))
	}
}

func TestUpdateServer(t *testing.T) {
	srv := fakeAPI(t)
	defer srv.Close()
	client := makeClient(t, srv.URL)

	input := `{"id":"srv-1","name":"updated-server"}`
	result, err := dispatch("update-server", nil, strings.NewReader(input), client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Contains(result, []byte("updated-server")) {
		t.Errorf("expected updated-server in result: %s", string(result))
	}
}

func TestUpdateServerMissingID(t *testing.T) {
	srv := fakeAPI(t)
	defer srv.Close()
	client := makeClient(t, srv.URL)

	input := `{"name":"no-id-server"}`
	_, err := dispatch("update-server", nil, strings.NewReader(input), client)
	if err == nil {
		t.Fatal("expected error for missing server id")
	}
	if !strings.Contains(err.Error(), "id is required") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDeleteServerMissingArg(t *testing.T) {
	srv := fakeAPI(t)
	defer srv.Close()
	client := makeClient(t, srv.URL)

	_, err := dispatch("delete-server", nil, strings.NewReader(""), client)
	if err == nil {
		t.Fatal("expected error for missing argument")
	}
}

func TestAuthorizationHeader(t *testing.T) {
	var gotAuth string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data":    []string{},
		})
	}))
	defer ts.Close()

	client := &apiClient{
		baseURL:    ts.URL,
		token:      "my-secret-token",
		httpClient: http.DefaultClient,
	}
	_, _ = dispatch("read-users", nil, strings.NewReader(""), client)

	if gotAuth != "Bearer my-secret-token" {
		t.Errorf("expected Bearer token, got %q", gotAuth)
	}
}

func TestAPIErrorResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "forbidden",
		})
	}))
	defer ts.Close()

	client := &apiClient{
		baseURL:    ts.URL,
		token:      "tok",
		httpClient: http.DefaultClient,
	}
	_, err := dispatch("read-users", nil, strings.NewReader(""), client)
	if err == nil {
		t.Fatal("expected error from API")
	}
	if !strings.Contains(err.Error(), "forbidden") {
		t.Errorf("unexpected error: %v", err)
	}
}

// helpers to keep the test output capturing functionality separate
func captureOutput(fn func()) string {
	old := io.Discard
	_ = old
	return ""
}

func ptr(s string) *string { return &s }

func init() {
	// Ensure the formatter function compiles.
	_ = fmt.Sprintf
}
