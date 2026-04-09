package ws

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTerminalHandlerBridgesTextBinaryAndControls(t *testing.T) {
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer proxyLn.Close()

	proxyReads := make(chan []byte, 4)
	proxyErrs := make(chan error, 1)
	go func() {
		conn, err := proxyLn.Accept()
		if err != nil {
			proxyErrs <- err
			return
		}
		defer conn.Close()

		if _, err := conn.Write([]byte("proxy hello\r\n")); err != nil {
			proxyErrs <- err
			return
		}

		first := make([]byte, 3)
		if _, err := io.ReadFull(conn, first); err != nil {
			proxyErrs <- err
			return
		}
		proxyReads <- append([]byte(nil), first...)

		conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		shouldNotArrive := make([]byte, 16)
		if n, err := conn.Read(shouldNotArrive); n > 0 {
			proxyReads <- append([]byte(nil), shouldNotArrive[:n]...)
			return
		} else if err != nil {
			if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
				proxyErrs <- err
				return
			}
		}

		conn.SetReadDeadline(time.Now().Add(time.Second))
		second := make([]byte, 3)
		if _, err := io.ReadFull(conn, second); err != nil {
			proxyErrs <- err
			return
		}
		proxyReads <- append([]byte(nil), second...)
	}()

	recordingDir := t.TempDir()
	mux := http.NewServeMux()
	handler := &TerminalHandler{
		ProxyAddr:         proxyLn.Addr().String(),
		RecordingDir:      recordingDir,
		RecordingBasePath: "/api/v2/terminal/recordings",
	}
	mux.Handle("/ws/terminal", handler)
	server := httptest.NewServer(mux)
	defer server.Close()

	client, br := dialTerminalWS(t, server.URL+"/ws/terminal?host=test-host")
	defer client.Close()
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("receive initial control: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("expected 101 handshake response, got %d", resp.StatusCode)
	}

	client = &bufferedConn{Conn: client, br: br}

	mt, payload, err := clientReadFrame(client)
	if err != nil {
		t.Fatalf("read initial control frame: %v", err)
	}
	if mt != OpText {
		t.Fatalf("expected text control message, got opcode %d", mt)
	}
	var initial terminalMsg
	if err := json.Unmarshal(payload, &initial); err != nil {
		t.Fatalf("json.Unmarshal initial control: %v", err)
	}
	if initial.Action != "connected" || !strings.Contains(initial.Data, "test-host") {
		t.Fatalf("unexpected initial control message: %#v", initial)
	}
	if initial.RecordingID == "" {
		t.Fatal("expected connected message to include recording_id")
	}
	if initial.DownloadURL != "/api/v2/terminal/recordings/"+initial.RecordingID+"/download" {
		t.Fatalf("download_url = %q", initial.DownloadURL)
	}

	mt, fromProxy, err := clientReadFrame(client)
	if err != nil {
		t.Fatalf("receive proxied payload: %v", err)
	}
	if mt != OpBinary {
		t.Fatalf("expected binary proxied payload, got opcode %d", mt)
	}
	if string(fromProxy) != "proxy hello\r\n" {
		t.Fatalf("expected proxied output, got %q", string(fromProxy))
	}

	clientWriteMaskedFrame(client, OpText, []byte(`{"type":"control","action":"resize","cols":120,"rows":40}`))
	select {
	case got := <-proxyReads:
		t.Fatalf("resize control should not be proxied, got %q", string(got))
	case <-time.After(300 * time.Millisecond):
	}

	clientWriteMaskedFrame(client, OpText, []byte("ls\r"))
	select {
	case got := <-proxyReads:
		if string(got) != "ls\r" {
			t.Fatalf("expected text input to reach proxy, got %q", string(got))
		}
	case err := <-proxyErrs:
		t.Fatalf("proxy error after text input: %v", err)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for proxied text input")
	}

	binaryPayload := []byte{0x18, 0x42, 0x00}
	clientWriteMaskedFrame(client, OpBinary, binaryPayload)
	select {
	case got := <-proxyReads:
		if !bytes.Equal(got, binaryPayload) {
			t.Fatalf("expected binary input to reach proxy, got %v", got)
		}
	case err := <-proxyErrs:
		t.Fatalf("proxy error after binary input: %v", err)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for proxied binary input")
	}

	select {
	case err := <-proxyErrs:
		t.Fatalf("unexpected proxy error: %v", err)
	default:
	}

	recordingPath, err := handler.RecordingFilePath(initial.RecordingID)
	if err != nil {
		t.Fatalf("RecordingFilePath: %v", err)
	}
	recordingBytes, err := os.ReadFile(recordingPath)
	if err != nil {
		t.Fatalf("os.ReadFile(%q): %v", recordingPath, err)
	}
	recording := string(recordingBytes)
	if !strings.Contains(recording, `"title":"Web Terminal — test-host"`) {
		t.Fatalf("recording missing header: %s", recording)
	}
	if !strings.Contains(recording, `proxy hello\r\n`) {
		t.Fatalf("recording missing proxied output: %s", recording)
	}
	if !strings.HasPrefix(recordingPath, filepath.Join(recordingDir, "web-terminal")+string(filepath.Separator)) {
		t.Fatalf("recording path %q outside recording dir", recordingPath)
	}
}

func dialTerminalWS(t *testing.T, rawURL string) (net.Conn, *bufio.Reader) {
	t.Helper()

	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	conn, err := net.Dial("tcp", parsed.Host)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	path := parsed.RequestURI()
	if path == "" {
		path = "/"
	}
	key := base64.StdEncoding.EncodeToString([]byte("terminal-test-key-123"))
	req := "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + parsed.Host + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write handshake: %v", err)
	}

	return conn, bufio.NewReader(conn)
}
