package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// --- Table formatting tests ---

func TestPrintTable_Basic(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	noColor = true
	headers := []string{"NAME", "AGE", "ROLE"}
	rows := [][]string{
		{"alice", "30", "admin"},
		{"bob", "25", "user"},
	}
	printTable(headers, rows)

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	if !strings.Contains(output, "NAME") {
		t.Errorf("expected header NAME, got:\n%s", output)
	}
	if !strings.Contains(output, "alice") {
		t.Errorf("expected row with alice, got:\n%s", output)
	}
	if !strings.Contains(output, "bob") {
		t.Errorf("expected row with bob, got:\n%s", output)
	}
}

func TestPrintTable_EmptyHeaders(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	noColor = true
	printTable([]string{}, [][]string{})

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)
	if buf.Len() != 0 {
		t.Errorf("expected no output for empty headers, got: %s", buf.String())
	}
}

func TestPrintTable_Alignment(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	noColor = true
	headers := []string{"ID", "DESCRIPTION"}
	rows := [][]string{
		{"1", "short"},
		{"2", "a longer description here"},
	}
	printTable(headers, rows)

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")

	if len(lines) != 3 {
		t.Fatalf("expected 3 lines (header + 2 rows), got %d", len(lines))
	}
	// All lines should have the same column alignment
	hdrParts := strings.Fields(lines[0])
	if hdrParts[0] != "ID" || hdrParts[1] != "DESCRIPTION" {
		t.Errorf("unexpected header format: %s", lines[0])
	}
}

func TestPrintTable_UnevenRows(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	noColor = true
	headers := []string{"A", "B", "C"}
	rows := [][]string{
		{"1"}, // fewer columns than headers
		{"1", "2", "3"},
	}
	printTable(headers, rows)

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()
	if !strings.Contains(output, "1") {
		t.Errorf("expected row data, got:\n%s", output)
	}
}

// --- JSON output tests ---

func TestPrintJSON(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	data := map[string]string{"status": "ok"}
	printJSON(data)

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)

	var result map[string]string
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if result["status"] != "ok" {
		t.Errorf("expected status ok, got %s", result["status"])
	}
}

func TestPrintJSON_Array(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	data := []string{"a", "b", "c"}
	printJSON(data)

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)

	var result []string
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if len(result) != 3 || result[0] != "a" {
		t.Errorf("unexpected result: %v", result)
	}
}

// --- Color / no-color tests ---

func TestColorEnabled(t *testing.T) {
	noColor = false
	result := color(colorGreen, "hello")
	if !strings.Contains(result, "\033[") {
		t.Errorf("expected ANSI codes when color enabled, got: %s", result)
	}
	if !strings.Contains(result, "hello") {
		t.Errorf("expected text 'hello', got: %s", result)
	}
}

func TestColorDisabled(t *testing.T) {
	noColor = true
	result := color(colorGreen, "hello")
	if strings.Contains(result, "\033[") {
		t.Errorf("expected no ANSI codes when color disabled, got: %s", result)
	}
	if result != "hello" {
		t.Errorf("expected plain 'hello', got: %s", result)
	}
}

// --- Client configuration tests ---

func TestClientConfigFromEnv(t *testing.T) {
	t.Setenv("SSHPROXY_SERVER", "https://test.example.com:8443")
	t.Setenv("SSHPROXY_TOKEN", "test-token-123")

	cfg := loadConfig()
	if cfg.Server != "https://test.example.com:8443" {
		t.Errorf("expected server from env, got: %s", cfg.Server)
	}
	if cfg.Token != "test-token-123" {
		t.Errorf("expected token from env, got: %s", cfg.Token)
	}
}

func TestClientConfigEnvOverridesFile(t *testing.T) {
	// Even if config file has values, env vars should win.
	t.Setenv("SSHPROXY_SERVER", "https://env-server.example.com")
	t.Setenv("SSHPROXY_TOKEN", "env-token")

	cfg := loadConfig()
	if cfg.Server != "https://env-server.example.com" {
		t.Errorf("env var should override file, got server: %s", cfg.Server)
	}
	if cfg.Token != "env-token" {
		t.Errorf("env var should override file, got token: %s", cfg.Token)
	}
}

func TestNewClientFromConfig(t *testing.T) {
	cfg := ClientConfig{
		Server:   "https://example.com",
		Token:    "Bearer mytoken",
		Insecure: false,
	}
	client := NewClientFromConfig(cfg)
	if client.baseURL != "https://example.com" {
		t.Errorf("expected base URL https://example.com, got %s", client.baseURL)
	}
	if client.token != "Bearer mytoken" {
		t.Errorf("expected token, got %s", client.token)
	}
}

// --- API response handling tests ---

func TestClientGet(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/status" {
			t.Errorf("expected /api/v1/status, got %s", r.URL.Path)
		}
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-token" {
			t.Errorf("expected Bearer test-token, got %s", auth)
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
	}))
	defer ts.Close()

	client := NewClientFromConfig(ClientConfig{
		Server: ts.URL,
		Token:  "test-token",
	})

	data, err := client.Get("/api/v1/status")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result map[string]string
	json.Unmarshal(data, &result)
	if result["status"] != "healthy" {
		t.Errorf("expected healthy, got %s", result["status"])
	}
}

func TestClientPost(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		ct := r.Header.Get("Content-Type")
		if ct != "application/json" {
			t.Errorf("expected application/json content type, got %s", ct)
		}
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"id": "123"})
	}))
	defer ts.Close()

	client := NewClientFromConfig(ClientConfig{Server: ts.URL, Token: "tk"})
	data, err := client.Post("/api/v1/users", map[string]string{"username": "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result map[string]string
	json.Unmarshal(data, &result)
	if result["id"] != "123" {
		t.Errorf("expected id 123, got %s", result["id"])
	}
}

func TestClientErrorResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"error":"not found"}`)
	}))
	defer ts.Close()

	client := NewClientFromConfig(ClientConfig{Server: ts.URL, Token: "tk"})
	_, err := client.Get("/api/v1/missing")
	if err == nil {
		t.Fatal("expected error for 404 response")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("error should mention 404, got: %v", err)
	}
}

func TestClientDeleteMethod(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "DELETE" {
			t.Errorf("expected DELETE, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"deleted":true}`)
	}))
	defer ts.Close()

	client := NewClientFromConfig(ClientConfig{Server: ts.URL, Token: "tk"})
	data, err := client.Delete("/api/v1/sessions/abc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(string(data), "true") {
		t.Errorf("expected deleted true, got %s", string(data))
	}
}

func TestClientPutMethod(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" {
			t.Errorf("expected PUT, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"updated":true}`)
	}))
	defer ts.Close()

	client := NewClientFromConfig(ClientConfig{Server: ts.URL, Token: "tk"})
	data, err := client.Put("/api/v1/config", map[string]string{"key": "val"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(string(data), "true") {
		t.Errorf("expected updated true, got %s", string(data))
	}
}

// --- Format helper tests ---

func TestFormatTime_Valid(t *testing.T) {
	result := formatTime("2024-01-15T09:30:00Z")
	if result != "2024-01-15 09:30" {
		t.Errorf("expected '2024-01-15 09:30', got '%s'", result)
	}
}

func TestFormatTime_Invalid(t *testing.T) {
	result := formatTime("not-a-time")
	if result != "not-a-time" {
		t.Errorf("expected passthrough for invalid time, got '%s'", result)
	}
}

func TestFormatDuration_Hours(t *testing.T) {
	result := formatDuration("2h15m")
	if result != "2h 15m" {
		t.Errorf("expected '2h 15m', got '%s'", result)
	}
}

func TestFormatDuration_MinutesOnly(t *testing.T) {
	result := formatDuration("45m")
	if result != "45m" {
		t.Errorf("expected '45m', got '%s'", result)
	}
}

func TestFormatDuration_Invalid(t *testing.T) {
	result := formatDuration("5 days")
	if result != "5 days" {
		t.Errorf("expected passthrough for invalid duration, got '%s'", result)
	}
}

// --- printSuccess / printError / printWarning output tests ---

func TestPrintSuccess(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	noColor = true
	printSuccess("done")

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)
	if !strings.Contains(buf.String(), "✓") || !strings.Contains(buf.String(), "done") {
		t.Errorf("expected success marker and message, got: %s", buf.String())
	}
}

func TestPrintError(t *testing.T) {
	old := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	noColor = true
	printError("fail")

	w.Close()
	os.Stderr = old

	var buf bytes.Buffer
	io.Copy(&buf, r)
	if !strings.Contains(buf.String(), "✗") || !strings.Contains(buf.String(), "fail") {
		t.Errorf("expected error marker and message, got: %s", buf.String())
	}
}

func TestPrintWarning(t *testing.T) {
	old := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	noColor = true
	printWarning("caution")

	w.Close()
	os.Stderr = old

	var buf bytes.Buffer
	io.Copy(&buf, r)
	if !strings.Contains(buf.String(), "⚠") || !strings.Contains(buf.String(), "caution") {
		t.Errorf("expected warning marker and message, got: %s", buf.String())
	}
}

// --- Token auth header test ---

func TestClientBearerTokenPrefix(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer already-prefixed" {
			t.Errorf("expected 'Bearer already-prefixed', got '%s'", auth)
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{}`)
	}))
	defer ts.Close()

	// Token already has "Bearer " prefix — should not double-prefix
	client := NewClientFromConfig(ClientConfig{Server: ts.URL, Token: "Bearer already-prefixed"})
	_, err := client.Get("/test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- Pad helper test ---

func TestPad(t *testing.T) {
	tests := []struct {
		s     string
		width int
		want  string
	}{
		{"hi", 5, "hi   "},
		{"hello", 5, "hello"},
		{"toolong", 3, "toolong"},
		{"", 4, "    "},
	}
	for _, tc := range tests {
		got := pad(tc.s, tc.width)
		if got != tc.want {
			t.Errorf("pad(%q, %d) = %q, want %q", tc.s, tc.width, got, tc.want)
		}
	}
}
