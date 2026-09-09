package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAsciiDemoPageAndCastDownload(t *testing.T) {
	dataPlane := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(dataPlane.Close)

	cfg, controlPlane := newControlPlaneTestServer(t, dataPlane.URL, "dp-secret-token")
	client := newAuthenticatedClient(t, controlPlane.URL, cfg.SessionSecret)

	page := mustRequest(t, client, http.MethodGet, controlPlane.URL+"/demo/ascii-stream", nil, nil)
	if page.StatusCode != http.StatusOK {
		t.Fatalf("GET /demo/ascii-stream status = %d body = %s", page.StatusCode, mustReadBody(t, page))
	}
	_ = mustReadBody(t, page)

	body := mustReadEmbeddedTemplate(t, "templates/pages/demo_ascii.html")
	for _, needle := range []string{
		"/ws/demo/ascii-stream",
		"/api/v2/demo/ascii-stream.cast",
		"asciinema-player.min.js",
		"session.live.chunk",
	} {
		if !strings.Contains(body, needle) {
			t.Fatalf("demo page missing %q", needle)
		}
	}

	cast := mustRequest(t, client, http.MethodGet, controlPlane.URL+"/api/v2/demo/ascii-stream.cast", nil, nil)
	if cast.StatusCode != http.StatusOK {
		t.Fatalf("GET cast status = %d body = %s", cast.StatusCode, mustReadBody(t, cast))
	}
	if got := cast.Header.Get("Content-Type"); !strings.Contains(got, "application/x-asciicast") {
		t.Fatalf("content-type = %q", got)
	}
	castBody := string(mustReadBody(t, cast))
	if !strings.Contains(castBody, `"version":2`) {
		t.Fatalf("cast missing version header: %s", castBody[:min(80, len(castBody))])
	}
}

func TestAsciiDemoStreamDripsChunksThenEnds(t *testing.T) {
	dataPlane := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(dataPlane.Close)

	cfg, controlPlane := newControlPlaneTestServer(t, dataPlane.URL, "dp-secret-token")
	conn, br := dialAuthenticatedWebSocket(t, controlPlane.URL, "/ws/demo/ascii-stream?speed=1000", cfg.SessionSecret)
	defer conn.Close()
	wsConn := &bufferedConn{Conn: conn, br: br}

	deadline := time.Now().Add(15 * time.Second)
	sawChunk := false
	for time.Now().Before(deadline) {
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		msg := readWebSocketJSON(t, wsConn)
		switch msg.Type {
		case "session.live.chunk":
			sawChunk = true
			chunk, _ := msg.Data.(map[string]interface{})["chunk"].(string)
			if chunk == "" {
				t.Fatal("empty live chunk")
			}
		case "session.live.status":
			if !sawChunk {
				t.Fatal("ended before any chunk")
			}
			state, _ := msg.Data.(map[string]interface{})["state"].(string)
			if state != "ended" {
				t.Fatalf("state = %q, want ended", state)
			}
			return
		case "error":
			t.Fatalf("demo stream error: %s", msg.Error)
		default:
			t.Fatalf("unexpected message type %q", msg.Type)
		}
	}
	t.Fatal("timed out waiting for demo stream to end")
}
