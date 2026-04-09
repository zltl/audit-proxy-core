package server

import (
	"bufio"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/middleware"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/models"
)

func TestDashboardStreamSendsSnapshot(t *testing.T) {
	dataPlane := newRealtimeTestDataPlane(t, func() []models.Session {
		return []models.Session{
			{
				ID:         "sess-1",
				Username:   "alice",
				SourceIP:   "10.0.0.1",
				TargetHost: "srv-1",
				TargetPort: 22,
				Status:     "active",
				StartTime:  time.Now().Add(-2 * time.Minute).UTC(),
				Duration:   "2m0s",
			},
		}
	}, []models.Server{
		{ID: "srv-1", Name: "server-1", Host: "10.0.1.1", Port: 22, Healthy: true, Sessions: 1, CheckedAt: time.Now().UTC()},
	})
	defer dataPlane.Close()

	cfg, controlPlane := newControlPlaneTestServer(t, dataPlane.URL, "dp-secret-token")

	conn, br := dialAuthenticatedWebSocket(t, controlPlane.URL, "/ws/dashboard", cfg.SessionSecret)
	defer conn.Close()

	msg := readWebSocketJSON(t, &bufferedConn{Conn: conn, br: br})
	if msg.Type != "dashboard.snapshot" {
		t.Fatalf("message type = %q, want dashboard.snapshot", msg.Type)
	}

	payload, ok := msg.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("message data type = %T, want object", msg.Data)
	}
	stats := payload["stats"].(map[string]interface{})
	if stats["active_sessions"].(float64) != 1 {
		t.Fatalf("active_sessions = %v, want 1", stats["active_sessions"])
	}
	sessions := payload["sessions"].([]interface{})
	if len(sessions) != 1 {
		t.Fatalf("sessions len = %d, want 1", len(sessions))
	}
}

func TestSessionLiveStreamTailsRecording(t *testing.T) {
	var sessionStatus atomic.Value
	sessionStatus.Store("active")

	recordingPath := ""
	dataPlane := newRealtimeTestDataPlane(t, func() []models.Session {
		return []models.Session{
			{
				ID:            "sess-live",
				Username:      "alice",
				SourceIP:      "10.0.0.1",
				TargetHost:    "srv-live",
				TargetPort:    22,
				Status:        sessionStatus.Load().(string),
				StartTime:     time.Now().Add(-1 * time.Minute).UTC(),
				Duration:      "1m0s",
				RecordingFile: recordingPath,
			},
		}
	}, []models.Server{{ID: "srv-live", Name: "server-live", Host: "10.0.1.9", Port: 22, Healthy: true}})
	defer dataPlane.Close()

	cfg, controlPlane := newControlPlaneTestServer(t, dataPlane.URL, "dp-secret-token")
	recordingPath = filepath.Join(cfg.RecordingDir, "sess-live.cast")
	initial := strings.Join([]string{
		`{"version":2,"width":80,"height":24}`,
		`[0.1,"o","hello"]`,
		"",
	}, "\n")
	if err := os.WriteFile(recordingPath, []byte(initial), 0o644); err != nil {
		t.Fatal(err)
	}

	conn, br := dialAuthenticatedWebSocket(t, controlPlane.URL, "/ws/sessions/sess-live/live", cfg.SessionSecret)
	defer conn.Close()
	wsConn := &bufferedConn{Conn: conn, br: br}

	msg := readWebSocketJSON(t, wsConn)
	if msg.Type != "session.live.chunk" {
		t.Fatalf("message type = %q, want session.live.chunk", msg.Type)
	}
	if chunk := msg.Data.(map[string]interface{})["chunk"]; chunk != "hello" {
		t.Fatalf("first live chunk = %#v, want hello", chunk)
	}

	appendFile(t, recordingPath, `[0.2,"o"," world"]`+"\n")
	msg = readWebSocketJSON(t, wsConn)
	if msg.Type != "session.live.chunk" {
		t.Fatalf("message type = %q, want session.live.chunk", msg.Type)
	}
	if chunk := msg.Data.(map[string]interface{})["chunk"]; chunk != " world" {
		t.Fatalf("second live chunk = %#v, want \" world\"", chunk)
	}

	sessionStatus.Store("closed")
	msg = readWebSocketJSON(t, wsConn)
	if msg.Type != "session.live.status" {
		t.Fatalf("message type = %q, want session.live.status", msg.Type)
	}
	if state := msg.Data.(map[string]interface{})["state"]; state != "ended" {
		t.Fatalf("live status state = %#v, want ended", state)
	}
}

func TestTerminalRecordingDownloadServesCast(t *testing.T) {
	dataPlane := newRealtimeTestDataPlane(t, func() []models.Session { return nil }, nil)
	defer dataPlane.Close()

	cfg, controlPlane := newControlPlaneTestServer(t, dataPlane.URL, "dp-secret-token")
	client := newAuthenticatedClient(t, controlPlane.URL, cfg.SessionSecret)

	recordingDir := filepath.Join(cfg.RecordingDir, "web-terminal")
	if err := os.MkdirAll(recordingDir, 0o700); err != nil {
		t.Fatal(err)
	}
	recordingID := "term-test-download"
	recordingPath := filepath.Join(recordingDir, recordingID+".cast")
	recordingBody := strings.Join([]string{
		`{"version":2,"width":80,"height":24}`,
		`[0.1,"o","hello from terminal"]`,
		"",
	}, "\n")
	if err := os.WriteFile(recordingPath, []byte(recordingBody), 0o600); err != nil {
		t.Fatal(err)
	}

	resp := mustRequest(t, client, http.MethodGet, controlPlane.URL+"/api/v2/terminal/recordings/"+recordingID+"/download", nil, nil)
	if resp.StatusCode != http.StatusOK {
		body := string(mustReadBody(t, resp))
		t.Fatalf("GET terminal recording status = %d body = %s", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Content-Type"); !strings.Contains(got, "application/x-asciicast") {
		t.Fatalf("content-type = %q, want application/x-asciicast", got)
	}
	if body := string(mustReadBody(t, resp)); body != recordingBody {
		t.Fatalf("downloaded recording = %q, want %q", body, recordingBody)
	}
}

func newRealtimeTestDataPlane(t *testing.T, sessions func() []models.Session, upstreams []models.Server) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(models.HealthStatus{Status: "healthy", Version: "test", Uptime: "1m"})
	})
	mux.HandleFunc("/sessions", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(sessions())
	})
	mux.HandleFunc("/upstreams", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(upstreams)
	})
	mux.HandleFunc("/config", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"listen_port": 2222})
	})
	mux.HandleFunc("/config/reload", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ssh_active_sessions 1\n"))
	})

	return httptest.NewServer(mux)
}

func dialAuthenticatedWebSocket(t *testing.T, rawURL, path, sessionSecret string) (net.Conn, *bufio.Reader) {
	t.Helper()

	addr := strings.TrimPrefix(rawURL, "http://")
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}

	key := base64.StdEncoding.EncodeToString([]byte("dashboard-stream-key"))
	sessionCookie := middleware.CreateSessionCookie("admin", sessionSecret, time.Hour)
	req := "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + addr + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"Cookie: " + sessionCookie.Name + "=" + sessionCookie.Value + "\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("websocket upgrade status = %d body = %s", resp.StatusCode, string(body))
	}
	return conn, br
}

type bufferedConn struct {
	net.Conn
	br *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) {
	return c.br.Read(b)
}

func readWebSocketJSON(t *testing.T, conn net.Conn) websocketMessage {
	t.Helper()

	opcode, payload, err := readServerFrame(conn)
	if err != nil {
		t.Fatal(err)
	}
	if opcode != 1 {
		t.Fatalf("opcode = %d, want 1", opcode)
	}

	var msg websocketMessage
	if err := json.Unmarshal(payload, &msg); err != nil {
		t.Fatalf("json.Unmarshal(%q) error = %v", string(payload), err)
	}
	return msg
}

func readServerFrame(conn net.Conn) (int, []byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, nil, err
	}

	opcode := int(header[0] & 0x0F)
	length := uint64(header[1] & 0x7F)
	switch length {
	case 126:
		ext := make([]byte, 2)
		if _, err := io.ReadFull(conn, ext); err != nil {
			return 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(ext))
	case 127:
		ext := make([]byte, 8)
		if _, err := io.ReadFull(conn, ext); err != nil {
			return 0, nil, err
		}
		length = binary.BigEndian.Uint64(ext)
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return 0, nil, err
	}
	return opcode, payload, nil
}

func appendFile(t *testing.T, path, content string) {
	t.Helper()

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
}
