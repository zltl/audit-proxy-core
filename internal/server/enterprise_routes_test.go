package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/config"
)

func TestEnterpriseRoutesAreAvailable(t *testing.T) {
	dataPlane := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(dataPlane.Close)

	cfg, controlPlane := newControlPlaneTestServer(t, dataPlane.URL, "dp-secret-token")
	client := newAuthenticatedClient(t, controlPlane.URL, cfg.SessionSecret)

	for _, path := range []string{
		"/api/v2/jit/policy",
		"/api/v2/threats/rules",
		"/api/v2/compliance/frameworks",
		"/api/v3/jit/policy",
		"/api/v3/threats/rules",
		"/api/v3/compliance/frameworks",
	} {
		resp := mustRequest(t, client, http.MethodGet, controlPlane.URL+path, nil, nil)
		if resp.StatusCode != http.StatusOK {
			body := string(mustReadBody(t, resp))
			t.Fatalf("GET %s status = %d body = %s", path, resp.StatusCode, body)
		}
		_ = mustReadBody(t, resp)
	}
}

func TestJITRequestUsesAuthenticatedUser(t *testing.T) {
	dataPlane := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(dataPlane.Close)

	cfg, controlPlane := newControlPlaneTestServer(t, dataPlane.URL, "dp-secret-token")
	client := newAuthenticatedClient(t, controlPlane.URL, cfg.SessionSecret)
	csrfToken := mustFetchCSRFToken(t, client, controlPlane.URL)

	body := bytes.NewBufferString(`{"target":"db.internal","role":"operator","reason":"incident","duration":"30m"}`)
	resp := mustRequest(t, client, http.MethodPost, controlPlane.URL+"/api/v2/jit/requests", body, map[string]string{
		"Content-Type": "application/json",
		"X-CSRF-Token": csrfToken,
	})
	if resp.StatusCode != http.StatusCreated {
		raw := string(mustReadBody(t, resp))
		t.Fatalf("POST /api/v2/jit/requests status = %d body = %s", resp.StatusCode, raw)
	}

	var envelope struct {
		Success bool `json:"success"`
		Data    struct {
			Requester string `json:"requester"`
			Target    string `json:"target"`
			Role      string `json:"role"`
		} `json:"data"`
	}
	if err := json.Unmarshal(mustReadBody(t, resp), &envelope); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if !envelope.Success {
		t.Fatal("expected success response")
	}
	if envelope.Data.Requester != "admin" {
		t.Fatalf("requester = %q, want admin", envelope.Data.Requester)
	}
	if envelope.Data.Target != "db.internal" || envelope.Data.Role != "operator" {
		t.Fatalf("unexpected JIT payload: %+v", envelope.Data)
	}
}

func TestSIEMCanBeConfiguredAndTested(t *testing.T) {
	var (
		gotPath string
		gotAuth string
		gotBody string
	)
	siemSink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotBody = string(body)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(siemSink.Close)

	dataPlane := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(dataPlane.Close)

	cfg, controlPlane := newControlPlaneTestServer(t, dataPlane.URL, "dp-secret-token")
	client := newAuthenticatedClient(t, controlPlane.URL, cfg.SessionSecret)
	csrfToken := mustFetchCSRFToken(t, client, controlPlane.URL)

	configBody := bytes.NewBufferString(`{"type":"splunk","endpoint":"` + siemSink.URL + `","token":"secret-token","source":"ssh-proxy"}`)
	resp := mustRequest(t, client, http.MethodPut, controlPlane.URL+"/api/v2/siem/config", configBody, map[string]string{
		"Content-Type": "application/json",
		"X-CSRF-Token": csrfToken,
	})
	if resp.StatusCode != http.StatusOK {
		raw := string(mustReadBody(t, resp))
		t.Fatalf("PUT /api/v2/siem/config status = %d body = %s", resp.StatusCode, raw)
	}
	_ = mustReadBody(t, resp)

	resp = mustRequest(t, client, http.MethodGet, controlPlane.URL+"/api/v2/siem/config", nil, nil)
	if resp.StatusCode != http.StatusOK {
		raw := string(mustReadBody(t, resp))
		t.Fatalf("GET /api/v2/siem/config status = %d body = %s", resp.StatusCode, raw)
	}
	var cfgEnvelope struct {
		Success bool `json:"success"`
		Data    struct {
			Type     string `json:"type"`
			Endpoint string `json:"endpoint"`
			Token    string `json:"token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(mustReadBody(t, resp), &cfgEnvelope); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if cfgEnvelope.Data.Token != "***" {
		t.Fatalf("expected redacted token, got %q", cfgEnvelope.Data.Token)
	}

	resp = mustRequest(t, client, http.MethodPost, controlPlane.URL+"/api/v2/siem/test", bytes.NewBufferString(`{}`), map[string]string{
		"Content-Type": "application/json",
		"X-CSRF-Token": csrfToken,
	})
	if resp.StatusCode != http.StatusOK {
		raw := string(mustReadBody(t, resp))
		t.Fatalf("POST /api/v2/siem/test status = %d body = %s", resp.StatusCode, raw)
	}
	_ = mustReadBody(t, resp)

	if gotPath != "/services/collector/event" {
		t.Fatalf("SIEM sink path = %q, want /services/collector/event", gotPath)
	}
	if gotAuth != "Splunk secret-token" {
		t.Fatalf("SIEM Authorization = %q", gotAuth)
	}
	if !strings.Contains(gotBody, `"event_type":"siem.test"`) {
		t.Fatalf("SIEM payload missing test event: %s", gotBody)
	}
}

func TestSIEMDatadogCanBeConfiguredAndTested(t *testing.T) {
	var (
		gotAPIKey string
		gotSource string
		gotBody   string
	)
	siemSink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotAPIKey = r.Header.Get("DD-API-KEY")
		gotSource = r.Header.Get("DD-Source")
		gotBody = string(body)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(siemSink.Close)

	dataPlane := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(dataPlane.Close)

	cfg, controlPlane := newControlPlaneTestServer(t, dataPlane.URL, "dp-secret-token")
	client := newAuthenticatedClient(t, controlPlane.URL, cfg.SessionSecret)
	csrfToken := mustFetchCSRFToken(t, client, controlPlane.URL)

	configBody := bytes.NewBufferString(`{"type":"datadog","endpoint":"` + siemSink.URL + `","token":"dd-api-key","source":"ssh-proxy"}`)
	resp := mustRequest(t, client, http.MethodPut, controlPlane.URL+"/api/v2/siem/config", configBody, map[string]string{
		"Content-Type": "application/json",
		"X-CSRF-Token": csrfToken,
	})
	if resp.StatusCode != http.StatusOK {
		raw := string(mustReadBody(t, resp))
		t.Fatalf("PUT /api/v2/siem/config status = %d body = %s", resp.StatusCode, raw)
	}
	_ = mustReadBody(t, resp)

	resp = mustRequest(t, client, http.MethodPost, controlPlane.URL+"/api/v2/siem/test", bytes.NewBufferString(`{}`), map[string]string{
		"Content-Type": "application/json",
		"X-CSRF-Token": csrfToken,
	})
	if resp.StatusCode != http.StatusOK {
		raw := string(mustReadBody(t, resp))
		t.Fatalf("POST /api/v2/siem/test status = %d body = %s", resp.StatusCode, raw)
	}
	_ = mustReadBody(t, resp)

	if gotAPIKey != "dd-api-key" {
		t.Fatalf("Datadog API key header = %q", gotAPIKey)
	}
	if gotSource != "ssh-proxy" {
		t.Fatalf("Datadog source header = %q", gotSource)
	}
	if !strings.Contains(gotBody, `"message":"siem.test"`) {
		t.Fatalf("Datadog payload missing test event: %s", gotBody)
	}
}

func TestClusterRoutesWhenEnabled(t *testing.T) {
	dataPlane := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(dataPlane.Close)

	cfg := &config.Config{
		ListenAddr:      "127.0.0.1:0",
		DataPlaneAddr:   dataPlane.URL,
		DataPlaneToken:  "dp-secret-token",
		SessionSecret:   "integration-test-secret",
		AdminUser:       "admin",
		AuditLogDir:     t.TempDir(),
		RecordingDir:    t.TempDir(),
		DataDir:         t.TempDir(),
		ClusterEnabled:  true,
		ClusterNodeID:   "node-1",
		ClusterNodeName: "control-plane-1",
		ClusterBindAddr: "127.0.0.1:0",
	}

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	controlPlane := httptest.NewServer(srv.srv.Handler)
	t.Cleanup(func() {
		_ = srv.Shutdown(context.Background())
		controlPlane.Close()
	})

	client := newAuthenticatedClient(t, controlPlane.URL, cfg.SessionSecret)

	resp := mustRequest(t, client, http.MethodGet, controlPlane.URL+"/api/v2/cluster/status", nil, nil)
	if resp.StatusCode != http.StatusOK {
		raw := string(mustReadBody(t, resp))
		t.Fatalf("GET /api/v2/cluster/status status = %d body = %s", resp.StatusCode, raw)
	}
	var statusEnvelope struct {
		Success bool `json:"success"`
		Data    struct {
			NodeID    string `json:"node_id"`
			Role      string `json:"role"`
			Leader    string `json:"leader"`
			NodeCount int    `json:"node_count"`
		} `json:"data"`
	}
	if err := json.Unmarshal(mustReadBody(t, resp), &statusEnvelope); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if statusEnvelope.Data.NodeID != "node-1" || statusEnvelope.Data.Role != "leader" {
		t.Fatalf("unexpected cluster status: %+v", statusEnvelope.Data)
	}
	if statusEnvelope.Data.Leader != "node-1" || statusEnvelope.Data.NodeCount != 1 {
		t.Fatalf("unexpected cluster topology: %+v", statusEnvelope.Data)
	}

	resp = mustRequest(t, client, http.MethodGet, controlPlane.URL+"/api/v2/cluster/leader", nil, nil)
	if resp.StatusCode != http.StatusOK {
		raw := string(mustReadBody(t, resp))
		t.Fatalf("GET /api/v2/cluster/leader status = %d body = %s", resp.StatusCode, raw)
	}
}

func TestSIEMSyslogCanBeConfiguredAndTested(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	defer ln.Close()

	syslogData := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		payload, _ := io.ReadAll(conn)
		syslogData <- string(payload)
	}()

	dataPlane := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(dataPlane.Close)

	cfg, controlPlane := newControlPlaneTestServer(t, dataPlane.URL, "dp-secret-token")
	client := newAuthenticatedClient(t, controlPlane.URL, cfg.SessionSecret)
	csrfToken := mustFetchCSRFToken(t, client, controlPlane.URL)

	configBody := bytes.NewBufferString(`{"type":"syslog","endpoint":"` + ln.Addr().String() + `","source":"ssh-proxy"}`)
	resp := mustRequest(t, client, http.MethodPut, controlPlane.URL+"/api/v2/siem/config", configBody, map[string]string{
		"Content-Type": "application/json",
		"X-CSRF-Token": csrfToken,
	})
	if resp.StatusCode != http.StatusOK {
		raw := string(mustReadBody(t, resp))
		t.Fatalf("PUT /api/v2/siem/config status = %d body = %s", resp.StatusCode, raw)
	}
	_ = mustReadBody(t, resp)

	resp = mustRequest(t, client, http.MethodPost, controlPlane.URL+"/api/v2/siem/test", bytes.NewBufferString(`{}`), map[string]string{
		"Content-Type": "application/json",
		"X-CSRF-Token": csrfToken,
	})
	if resp.StatusCode != http.StatusOK {
		raw := string(mustReadBody(t, resp))
		t.Fatalf("POST /api/v2/siem/test status = %d body = %s", resp.StatusCode, raw)
	}
	_ = mustReadBody(t, resp)

	select {
	case payload := <-syslogData:
		if !strings.Contains(payload, "siem.test") {
			t.Fatalf("syslog payload missing event type: %s", payload)
		}
		if !strings.HasPrefix(payload, "<") {
			t.Fatalf("syslog payload missing PRI prefix: %s", payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for syslog payload")
	}
}

func TestSIEMQRadarCanBeConfiguredAndTested(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	defer ln.Close()

	qradarData := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		payload, _ := io.ReadAll(conn)
		qradarData <- string(payload)
	}()

	dataPlane := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(dataPlane.Close)

	cfg, controlPlane := newControlPlaneTestServer(t, dataPlane.URL, "dp-secret-token")
	client := newAuthenticatedClient(t, controlPlane.URL, cfg.SessionSecret)
	csrfToken := mustFetchCSRFToken(t, client, controlPlane.URL)

	configBody := bytes.NewBufferString(`{"type":"qradar","endpoint":"` + ln.Addr().String() + `","source":"ssh-proxy"}`)
	resp := mustRequest(t, client, http.MethodPut, controlPlane.URL+"/api/v2/siem/config", configBody, map[string]string{
		"Content-Type": "application/json",
		"X-CSRF-Token": csrfToken,
	})
	if resp.StatusCode != http.StatusOK {
		raw := string(mustReadBody(t, resp))
		t.Fatalf("PUT /api/v2/siem/config status = %d body = %s", resp.StatusCode, raw)
	}
	_ = mustReadBody(t, resp)

	resp = mustRequest(t, client, http.MethodPost, controlPlane.URL+"/api/v2/siem/test", bytes.NewBufferString(`{}`), map[string]string{
		"Content-Type": "application/json",
		"X-CSRF-Token": csrfToken,
	})
	if resp.StatusCode != http.StatusOK {
		raw := string(mustReadBody(t, resp))
		t.Fatalf("POST /api/v2/siem/test status = %d body = %s", resp.StatusCode, raw)
	}
	_ = mustReadBody(t, resp)

	select {
	case payload := <-qradarData:
		if !strings.Contains(payload, "LEEF:2.0|SSH Proxy|Core|2.0.0|siem.test") {
			t.Fatalf("qradar payload missing LEEF event: %s", payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for qradar payload")
	}
}

func TestSIEMSumoCanBeConfiguredAndTested(t *testing.T) {
	var (
		gotCategory string
		gotBody     string
	)
	siemSink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotCategory = r.Header.Get("X-Sumo-Category")
		gotBody = string(body)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(siemSink.Close)

	dataPlane := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(dataPlane.Close)

	cfg, controlPlane := newControlPlaneTestServer(t, dataPlane.URL, "dp-secret-token")
	client := newAuthenticatedClient(t, controlPlane.URL, cfg.SessionSecret)
	csrfToken := mustFetchCSRFToken(t, client, controlPlane.URL)

	configBody := bytes.NewBufferString(`{"type":"sumo","endpoint":"` + siemSink.URL + `","source":"ssh-proxy"}`)
	resp := mustRequest(t, client, http.MethodPut, controlPlane.URL+"/api/v2/siem/config", configBody, map[string]string{
		"Content-Type": "application/json",
		"X-CSRF-Token": csrfToken,
	})
	if resp.StatusCode != http.StatusOK {
		raw := string(mustReadBody(t, resp))
		t.Fatalf("PUT /api/v2/siem/config status = %d body = %s", resp.StatusCode, raw)
	}
	_ = mustReadBody(t, resp)

	resp = mustRequest(t, client, http.MethodPost, controlPlane.URL+"/api/v2/siem/test", bytes.NewBufferString(`{}`), map[string]string{
		"Content-Type": "application/json",
		"X-CSRF-Token": csrfToken,
	})
	if resp.StatusCode != http.StatusOK {
		raw := string(mustReadBody(t, resp))
		t.Fatalf("POST /api/v2/siem/test status = %d body = %s", resp.StatusCode, raw)
	}
	_ = mustReadBody(t, resp)

	if gotCategory != "ssh-proxy" {
		t.Fatalf("Sumo category header = %q", gotCategory)
	}
	if !strings.Contains(gotBody, `"event_type":"siem.test"`) {
		t.Fatalf("Sumo payload missing test event: %s", gotBody)
	}
}

func TestSIEMLogstashCanBeConfiguredAndTested(t *testing.T) {
	var (
		gotContentType string
		gotBody        string
	)
	siemSink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotContentType = r.Header.Get("Content-Type")
		gotBody = string(body)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(siemSink.Close)

	dataPlane := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(dataPlane.Close)

	cfg, controlPlane := newControlPlaneTestServer(t, dataPlane.URL, "dp-secret-token")
	client := newAuthenticatedClient(t, controlPlane.URL, cfg.SessionSecret)
	csrfToken := mustFetchCSRFToken(t, client, controlPlane.URL)

	configBody := bytes.NewBufferString(`{"type":"logstash","endpoint":"` + siemSink.URL + `","source":"ssh-proxy"}`)
	resp := mustRequest(t, client, http.MethodPut, controlPlane.URL+"/api/v2/siem/config", configBody, map[string]string{
		"Content-Type": "application/json",
		"X-CSRF-Token": csrfToken,
	})
	if resp.StatusCode != http.StatusOK {
		raw := string(mustReadBody(t, resp))
		t.Fatalf("PUT /api/v2/siem/config status = %d body = %s", resp.StatusCode, raw)
	}
	_ = mustReadBody(t, resp)

	resp = mustRequest(t, client, http.MethodPost, controlPlane.URL+"/api/v2/siem/test", bytes.NewBufferString(`{}`), map[string]string{
		"Content-Type": "application/json",
		"X-CSRF-Token": csrfToken,
	})
	if resp.StatusCode != http.StatusOK {
		raw := string(mustReadBody(t, resp))
		t.Fatalf("POST /api/v2/siem/test status = %d body = %s", resp.StatusCode, raw)
	}
	_ = mustReadBody(t, resp)

	if gotContentType != "application/x-ndjson" {
		t.Fatalf("Logstash content-type = %q", gotContentType)
	}
	if !strings.Contains(gotBody, `"event_type":"siem.test"`) || !strings.Contains(gotBody, `"@timestamp"`) {
		t.Fatalf("Logstash payload missing test event: %s", gotBody)
	}
}

func TestSIEMWazuhCanBeConfiguredAndTested(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	defer ln.Close()

	wazuhData := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		payload, _ := io.ReadAll(conn)
		wazuhData <- string(payload)
	}()

	dataPlane := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(dataPlane.Close)

	cfg, controlPlane := newControlPlaneTestServer(t, dataPlane.URL, "dp-secret-token")
	client := newAuthenticatedClient(t, controlPlane.URL, cfg.SessionSecret)
	csrfToken := mustFetchCSRFToken(t, client, controlPlane.URL)

	configBody := bytes.NewBufferString(`{"type":"wazuh","endpoint":"` + ln.Addr().String() + `","source":"ssh-proxy"}`)
	resp := mustRequest(t, client, http.MethodPut, controlPlane.URL+"/api/v2/siem/config", configBody, map[string]string{
		"Content-Type": "application/json",
		"X-CSRF-Token": csrfToken,
	})
	if resp.StatusCode != http.StatusOK {
		raw := string(mustReadBody(t, resp))
		t.Fatalf("PUT /api/v2/siem/config status = %d body = %s", resp.StatusCode, raw)
	}
	_ = mustReadBody(t, resp)

	resp = mustRequest(t, client, http.MethodPost, controlPlane.URL+"/api/v2/siem/test", bytes.NewBufferString(`{}`), map[string]string{
		"Content-Type": "application/json",
		"X-CSRF-Token": csrfToken,
	})
	if resp.StatusCode != http.StatusOK {
		raw := string(mustReadBody(t, resp))
		t.Fatalf("POST /api/v2/siem/test status = %d body = %s", resp.StatusCode, raw)
	}
	_ = mustReadBody(t, resp)

	select {
	case payload := <-wazuhData:
		if !strings.Contains(payload, `"event_type":"siem.test"`) || !strings.Contains(payload, `"@timestamp"`) {
			t.Fatalf("wazuh payload missing JSON test event: %s", payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for wazuh payload")
	}
}

func TestCommandControlEvaluatesDangerousCommands(t *testing.T) {
	dataPlane := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(dataPlane.Close)

	cfg, controlPlane := newControlPlaneTestServer(t, dataPlane.URL, "dp-secret-token")
	client := newAuthenticatedClient(t, controlPlane.URL, cfg.SessionSecret)
	csrfToken := mustFetchCSRFToken(t, client, controlPlane.URL)

	resp := mustRequest(t, client, http.MethodPost, controlPlane.URL+"/api/v2/commands/evaluate",
		bytes.NewBufferString(`{"command":"shutdown -h now","username":"alice","role":"admin","target":"prod-db"}`),
		map[string]string{
			"Content-Type": "application/json",
			"X-CSRF-Token": csrfToken,
		},
	)
	if resp.StatusCode != http.StatusOK {
		raw := string(mustReadBody(t, resp))
		t.Fatalf("POST /api/v2/commands/evaluate status = %d body = %s", resp.StatusCode, raw)
	}

	var envelope struct {
		Success bool `json:"success"`
		Data    struct {
			Action  string `json:"action"`
			Message string `json:"message"`
		} `json:"data"`
	}
	if err := json.Unmarshal(mustReadBody(t, resp), &envelope); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if envelope.Data.Action != "approve" {
		t.Fatalf("decision action = %q, want approve", envelope.Data.Action)
	}
}

func TestCollabSessionUsesAuthenticatedOwner(t *testing.T) {
	dataPlane := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(dataPlane.Close)

	cfg, controlPlane := newControlPlaneTestServer(t, dataPlane.URL, "dp-secret-token")
	client := newAuthenticatedClient(t, controlPlane.URL, cfg.SessionSecret)
	csrfToken := mustFetchCSRFToken(t, client, controlPlane.URL)

	resp := mustRequest(t, client, http.MethodPost, controlPlane.URL+"/api/v2/collab/sessions",
		bytes.NewBufferString(`{"session_id":"sess-123","target":"db.internal","max_viewers":2,"allow_control":true}`),
		map[string]string{
			"Content-Type": "application/json",
			"X-CSRF-Token": csrfToken,
		},
	)
	if resp.StatusCode != http.StatusCreated {
		raw := string(mustReadBody(t, resp))
		t.Fatalf("POST /api/v2/collab/sessions status = %d body = %s", resp.StatusCode, raw)
	}

	var envelope struct {
		Success bool `json:"success"`
		Data    struct {
			ID           string `json:"id"`
			Owner        string `json:"owner"`
			SessionID    string `json:"session_id"`
			AllowControl bool   `json:"allow_control"`
		} `json:"data"`
	}
	if err := json.Unmarshal(mustReadBody(t, resp), &envelope); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if envelope.Data.Owner != "admin" || envelope.Data.SessionID != "sess-123" {
		t.Fatalf("unexpected collab session payload: %+v", envelope.Data)
	}
	if !envelope.Data.AllowControl {
		t.Fatal("expected allow_control to be true")
	}
}
