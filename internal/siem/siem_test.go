package siem

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testEvent(severity string) Event {
	return Event{
		Timestamp: time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC),
		Source:    "ssh-proxy",
		EventType: "auth.login",
		Severity:  severity,
		Data: map[string]interface{}{
			"user": "admin",
			"ip":   "10.0.0.1",
		},
	}
}

func TestNewForwarder_Defaults(t *testing.T) {
	fwd, err := NewForwarder(&SIEMConfig{
		Type:     SIEMWebhook,
		Endpoint: "http://localhost:9999",
	})
	if err != nil {
		t.Fatal(err)
	}
	if fwd.config.BatchSize != 100 {
		t.Errorf("batch size = %d, want 100", fwd.config.BatchSize)
	}
	if fwd.config.FlushInterval != 5*time.Second {
		t.Errorf("flush interval = %v, want 5s", fwd.config.FlushInterval)
	}
	if fwd.config.Source != "ssh-proxy" {
		t.Errorf("source = %q, want ssh-proxy", fwd.config.Source)
	}
}

func TestNewForwarder_MissingEndpoint(t *testing.T) {
	_, err := NewForwarder(&SIEMConfig{Type: SIEMWebhook})
	if err == nil {
		t.Fatal("expected error for missing endpoint")
	}
}

func TestSend_Buffers(t *testing.T) {
	fwd, _ := NewForwarder(&SIEMConfig{
		Type:     SIEMWebhook,
		Endpoint: "http://localhost:9999",
	})

	for i := 0; i < 10; i++ {
		if err := fwd.Send(testEvent("info")); err != nil {
			t.Fatal(err)
		}
	}

	fwd.mu.Lock()
	n := len(fwd.buffer)
	fwd.mu.Unlock()

	if n != 10 {
		t.Errorf("buffer size = %d, want 10", n)
	}
}

func TestSend_AutoFlushAtBatchSize(t *testing.T) {
	var received int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&received, 1)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	fwd, _ := NewForwarder(&SIEMConfig{
		Type:      SIEMWebhook,
		Endpoint:  srv.URL,
		BatchSize: 5,
	})

	for i := 0; i < 5; i++ {
		fwd.Send(testEvent("info"))
	}

	if atomic.LoadInt32(&received) == 0 {
		t.Error("expected flush at batch size")
	}
}

func TestFlush_EmptyBuffer(t *testing.T) {
	fwd, _ := NewForwarder(&SIEMConfig{
		Type:     SIEMWebhook,
		Endpoint: "http://localhost:9999",
	})
	if err := fwd.Flush(); err != nil {
		t.Fatalf("flush empty buffer: %v", err)
	}
}

func TestWebhookFormat(t *testing.T) {
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("content-type = %q", r.Header.Get("Content-Type"))
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("auth = %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	fwd, _ := NewForwarder(&SIEMConfig{
		Type:     SIEMWebhook,
		Endpoint: srv.URL,
		Token:    "test-token",
	})

	fwd.Send(testEvent("warning"))
	fwd.Flush()

	var payload struct {
		Source string  `json:"source"`
		Events []Event `json:"events"`
	}
	json.Unmarshal(body, &payload)
	if len(payload.Events) != 1 {
		t.Errorf("events = %d, want 1", len(payload.Events))
	}
	if payload.Source != "ssh-proxy" {
		t.Errorf("source = %q", payload.Source)
	}
}

func TestSplunkHECFormat(t *testing.T) {
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/services/collector/event") {
			t.Errorf("path = %q", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Splunk hec-token" {
			t.Errorf("auth = %q", r.Header.Get("Authorization"))
		}
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	fwd, _ := NewForwarder(&SIEMConfig{
		Type:     SIEMSplunk,
		Endpoint: srv.URL,
		Token:    "hec-token",
		Index:    "main",
		Source:   "ssh-proxy-test",
	})

	fwd.Send(testEvent("error"))
	fwd.Flush()

	// body should contain "sourcetype":"ssh_proxy" and "index":"main"
	s := string(body)
	if !strings.Contains(s, `"sourcetype":"ssh_proxy"`) {
		t.Errorf("missing sourcetype in splunk payload: %s", s)
	}
	if !strings.Contains(s, `"index":"main"`) {
		t.Errorf("missing index in splunk payload: %s", s)
	}
}

func TestSplunkHECFormatFunction(t *testing.T) {
	events := []Event{testEvent("info")}
	data, err := FormatSplunkHEC(events, "test-index", "test-source")
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	if !strings.Contains(s, `"sourcetype":"ssh_proxy"`) {
		t.Error("missing sourcetype")
	}
	if !strings.Contains(s, `"index":"test-index"`) {
		t.Error("missing index")
	}
}

func TestDatadogFormat(t *testing.T) {
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("DD-API-KEY") != "dd-api-key" {
			t.Errorf("DD-API-KEY = %q", r.Header.Get("DD-API-KEY"))
		}
		if r.Header.Get("DD-Source") != "ssh-proxy-test" {
			t.Errorf("DD-Source = %q", r.Header.Get("DD-Source"))
		}
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	fwd, _ := NewForwarder(&SIEMConfig{
		Type:     SIEMDatadog,
		Endpoint: srv.URL,
		Token:    "dd-api-key",
		Source:   "ssh-proxy-test",
	})

	fwd.Send(testEvent("warning"))
	fwd.Flush()

	var payload []map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("unmarshal datadog body: %v", err)
	}
	if len(payload) != 1 {
		t.Fatalf("datadog logs = %d, want 1", len(payload))
	}
	if payload[0]["message"] != "auth.login" {
		t.Fatalf("datadog message = %v", payload[0]["message"])
	}
	if payload[0]["service"] != "ssh-proxy-test" {
		t.Fatalf("datadog service = %v", payload[0]["service"])
	}
}

func TestDatadogFormatFunction(t *testing.T) {
	data, err := FormatDatadogLogs([]Event{testEvent("error")}, "ssh-proxy-test")
	if err != nil {
		t.Fatal(err)
	}
	var payload []map[string]interface{}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("unmarshal datadog payload: %v", err)
	}
	if payload[0]["status"] != "error" {
		t.Fatalf("datadog status = %v", payload[0]["status"])
	}
}

func TestElasticFormat(t *testing.T) {
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/x-ndjson" {
			t.Errorf("content-type = %q", r.Header.Get("Content-Type"))
		}
		if r.Header.Get("Authorization") != "Bearer elastic-token" {
			t.Errorf("auth = %q", r.Header.Get("Authorization"))
		}
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	fwd, _ := NewForwarder(&SIEMConfig{
		Type:     SIEMElastic,
		Endpoint: srv.URL,
		Token:    "elastic-token",
		Index:    "ssh-logs",
	})

	fwd.Send(testEvent("critical"))
	fwd.Flush()

	// body = action\nevent\n
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	if len(lines) != 2 {
		t.Fatalf("elastic body lines = %d, want 2", len(lines))
	}
	if !strings.Contains(lines[0], `"_index":"ssh-logs"`) {
		t.Errorf("missing index in action line: %s", lines[0])
	}
}

func TestElasticBulkFormatFunction(t *testing.T) {
	events := []Event{testEvent("info"), testEvent("error")}
	data, err := FormatElasticBulk(events, "my-index")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	// 2 events × 2 lines each = 4
	if len(lines) != 4 {
		t.Errorf("lines = %d, want 4", len(lines))
	}
}

func TestSumoFormat(t *testing.T) {
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Sumo-Category") != "ssh-proxy-test" {
			t.Errorf("X-Sumo-Category = %q", r.Header.Get("X-Sumo-Category"))
		}
		if r.Header.Get("X-Sumo-Host") != "ssh-proxy" {
			t.Errorf("X-Sumo-Host = %q", r.Header.Get("X-Sumo-Host"))
		}
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	fwd, _ := NewForwarder(&SIEMConfig{
		Type:     SIEMSumo,
		Endpoint: srv.URL,
		Source:   "ssh-proxy-test",
	})

	fwd.Send(testEvent("info"))
	fwd.Flush()

	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	if len(lines) != 1 {
		t.Fatalf("sumo body lines = %d, want 1", len(lines))
	}
	if !strings.Contains(lines[0], `"event_type":"auth.login"`) {
		t.Fatalf("sumo payload = %q", lines[0])
	}
}

func TestSumoFormatFunction(t *testing.T) {
	data, err := FormatSumoPayload([]Event{testEvent("info"), testEvent("warning")})
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("sumo lines = %d, want 2", len(lines))
	}
}

func TestLogstashFormat(t *testing.T) {
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/x-ndjson" {
			t.Errorf("content-type = %q", r.Header.Get("Content-Type"))
		}
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	fwd, _ := NewForwarder(&SIEMConfig{
		Type:     SIEMLogstash,
		Endpoint: srv.URL,
	})

	fwd.Send(testEvent("info"))
	fwd.Flush()

	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	if len(lines) != 1 {
		t.Fatalf("logstash body lines = %d, want 1", len(lines))
	}
	if !strings.Contains(lines[0], `"event_type":"auth.login"`) || !strings.Contains(lines[0], `"@timestamp"`) {
		t.Fatalf("logstash payload = %q", lines[0])
	}
}

func TestLogstashFormatFunction(t *testing.T) {
	data, err := FormatLogstashPayload([]Event{testEvent("info"), testEvent("warning")})
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("logstash lines = %d, want 2", len(lines))
	}
}

func TestWazuhUsesJSONSyslog(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var received []byte
	done := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		received, _ = io.ReadAll(conn)
		close(done)
	}()

	fwd, _ := NewForwarder(&SIEMConfig{
		Type:     SIEMWazuh,
		Endpoint: ln.Addr().String(),
	})

	fwd.Send(testEvent("warning"))
	if err := fwd.Flush(); err != nil {
		t.Fatalf("wazuh flush: %v", err)
	}

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for wazuh data")
	}

	payload := string(received)
	if !strings.HasPrefix(payload, "<") {
		t.Fatalf("wazuh payload missing PRI prefix: %q", payload)
	}
	if !strings.Contains(payload, `"event_type":"auth.login"`) || !strings.Contains(payload, `"@timestamp"`) {
		t.Fatalf("wazuh payload = %q", payload)
	}
}

func TestSyslogFormat(t *testing.T) {
	msgs := FormatSyslog([]Event{testEvent("critical")}, "myapp")
	if len(msgs) != 1 {
		t.Fatalf("msgs = %d, want 1", len(msgs))
	}
	msg := msgs[0]
	// PRI = facility(4)*8 + severity(2) = 34
	if !strings.HasPrefix(msg, "<34>1 ") {
		t.Errorf("syslog msg prefix = %q, want <34>1 ", msg[:10])
	}
	if !strings.Contains(msg, "myapp") {
		t.Error("syslog msg should contain app name")
	}
	if !strings.Contains(msg, "auth.login") {
		t.Error("syslog msg should contain event type")
	}
}

func TestCEFFormat(t *testing.T) {
	msgs := FormatCEF([]Event{testEvent("info")}, "myapp")
	if len(msgs) != 1 {
		t.Fatalf("msgs = %d, want 1", len(msgs))
	}
	msg := msgs[0]
	if !strings.Contains(msg, "CEF:0|SSH Proxy|Core|2.0.0|auth.login|auth.login|3|") {
		t.Fatalf("CEF payload = %q", msg)
	}
	if !strings.Contains(msg, "user=admin") || !strings.Contains(msg, "ip=10.0.0.1") {
		t.Fatalf("CEF payload missing fields: %q", msg)
	}
}

func TestLEEFFormat(t *testing.T) {
	msgs := FormatLEEF([]Event{testEvent("warning")}, "myapp")
	if len(msgs) != 1 {
		t.Fatalf("msgs = %d, want 1", len(msgs))
	}
	msg := msgs[0]
	if !strings.Contains(msg, "LEEF:2.0|SSH Proxy|Core|2.0.0|auth.login") {
		t.Fatalf("LEEF payload = %q", msg)
	}
	if !strings.Contains(msg, "user=admin") || !strings.Contains(msg, "ip=10.0.0.1") {
		t.Fatalf("LEEF payload missing fields: %q", msg)
	}
}

func TestSyslogSeverityMapping(t *testing.T) {
	tests := []struct {
		sev string
		pri int
	}{
		{"critical", 34}, // 4*8+2
		{"error", 35},    // 4*8+3
		{"warning", 36},  // 4*8+4
		{"info", 38},     // 4*8+6
		{"unknown", 38},  // default = info
	}
	for _, tt := range tests {
		_ = FormatSyslog([]Event{testEvent(tt.sev)}, "app")
		got := severityToSyslog(tt.sev)
		wantPri := 4*8 + got
		if wantPri != tt.pri {
			t.Errorf("severity %q: pri = %d, want %d", tt.sev, wantPri, tt.pri)
		}
	}
}

func TestSyslogTCP(t *testing.T) {
	// Start TCP listener
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var received []byte
	done := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		received, _ = io.ReadAll(conn)
		close(done)
	}()

	fwd, _ := NewForwarder(&SIEMConfig{
		Type:     SIEMSyslog,
		Endpoint: ln.Addr().String(),
	})

	fwd.Send(testEvent("warning"))
	err = fwd.Flush()
	if err != nil {
		t.Fatalf("syslog flush: %v", err)
	}

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for syslog data")
	}

	s := string(received)
	if !strings.Contains(s, "<36>") {
		t.Errorf("syslog data = %q, expected PRI <36>", s)
	}
}

func TestQRadarUsesLEEF(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var received []byte
	done := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		received, _ = io.ReadAll(conn)
		close(done)
	}()

	fwd, _ := NewForwarder(&SIEMConfig{
		Type:     SIEMQRadar,
		Endpoint: ln.Addr().String(),
	})

	fwd.Send(testEvent("warning"))
	err = fwd.Flush()
	if err != nil {
		t.Fatalf("qradar flush: %v", err)
	}

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for qradar data")
	}

	if !strings.Contains(string(received), "LEEF:2.0|SSH Proxy|Core|2.0.0|auth.login") {
		t.Fatalf("qradar payload = %q", string(received))
	}
}

func TestBatchSending(t *testing.T) {
	var count int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var payload struct {
			Events []Event `json:"events"`
		}
		json.Unmarshal(body, &payload)
		atomic.AddInt32(&count, int32(len(payload.Events)))
		w.WriteHeader(200)
	}))
	defer srv.Close()

	fwd, _ := NewForwarder(&SIEMConfig{
		Type:      SIEMWebhook,
		Endpoint:  srv.URL,
		BatchSize: 50,
	})

	for i := 0; i < 25; i++ {
		fwd.Send(testEvent("info"))
	}
	fwd.Flush()

	if atomic.LoadInt32(&count) != 25 {
		t.Errorf("received %d events, want 25", atomic.LoadInt32(&count))
	}
}

func TestStartAndStop(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	fwd, _ := NewForwarder(&SIEMConfig{
		Type:          SIEMWebhook,
		Endpoint:      srv.URL,
		FlushInterval: 50 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- fwd.Start(ctx)
	}()

	time.Sleep(20 * time.Millisecond) // let it start
	fwd.Send(testEvent("info"))

	time.Sleep(100 * time.Millisecond) // let ticker fire
	cancel()

	select {
	case err := <-errCh:
		if err != context.Canceled {
			t.Errorf("Start error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for Stop")
	}
}

func TestStatus(t *testing.T) {
	fwd, _ := NewForwarder(&SIEMConfig{
		Type:     SIEMWebhook,
		Endpoint: "http://localhost:9999",
	})

	fwd.Send(testEvent("info"))
	fwd.Send(testEvent("error"))

	st := fwd.Status()
	if st.BufferSize != 2 {
		t.Errorf("buffer_size = %d, want 2", st.BufferSize)
	}
	if st.Running {
		t.Error("should not be running")
	}
}

func TestFlushUpdatesStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	fwd, _ := NewForwarder(&SIEMConfig{
		Type:     SIEMWebhook,
		Endpoint: srv.URL,
	})

	fwd.Send(testEvent("info"))
	before := fwd.Status()
	fwd.Flush()
	after := fwd.Status()

	if after.BufferSize != 0 {
		t.Errorf("buffer after flush = %d", after.BufferSize)
	}
	if after.EventsSent != 1 {
		t.Errorf("events_sent = %d, want 1", after.EventsSent)
	}
	if after.LastFlush.Before(before.LastFlush) || after.LastFlush.IsZero() {
		t.Error("last_flush should be updated")
	}
}

func TestFlushError(t *testing.T) {
	// Server that returns 500
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()

	fwd, _ := NewForwarder(&SIEMConfig{
		Type:     SIEMWebhook,
		Endpoint: srv.URL,
	})

	fwd.Send(testEvent("info"))
	err := fwd.Flush()
	if err == nil {
		t.Fatal("expected error on 500 response")
	}

	st := fwd.Status()
	if st.LastError == "" {
		t.Error("last_error should be set after failure")
	}
}

func TestEventTimestampDefault(t *testing.T) {
	fwd, _ := NewForwarder(&SIEMConfig{
		Type:     SIEMWebhook,
		Endpoint: "http://localhost:9999",
	})

	ev := Event{
		EventType: "test",
		Severity:  "info",
	}
	fwd.Send(ev)

	fwd.mu.Lock()
	stored := fwd.buffer[0]
	fwd.mu.Unlock()

	if stored.Timestamp.IsZero() {
		t.Error("timestamp should be auto-set")
	}
	if stored.Source != "ssh-proxy" {
		t.Errorf("source = %q, want ssh-proxy", stored.Source)
	}
}
