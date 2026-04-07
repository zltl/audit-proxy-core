package ws

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// --- WebSocket handshake tests ---

func TestUpgradeSuccess(t *testing.T) {
	done := make(chan *Conn, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := Upgrade(w, r)
		if err != nil {
			t.Errorf("Upgrade failed: %v", err)
			return
		}
		done <- c
	}))
	defer ts.Close()

	conn, br := dialWS(t, ts.URL)
	defer conn.Close()

	// Verify 101 response.
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 101 {
		t.Fatalf("expected 101 got %d", resp.StatusCode)
	}

	wsConn := <-done
	defer wsConn.Close()
}

func TestUpgradeRejectNonWebSocket(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := Upgrade(w, r)
		if err == nil {
			t.Error("expected error for non-websocket request")
		}
	}))
	defer ts.Close()

	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 got %d", resp.StatusCode)
	}
}

// --- Frame read/write tests ---

func TestTextFrameRoundTrip(t *testing.T) {
	serverConn, clientConn := wsConnPair(t)
	defer serverConn.Close()
	defer clientConn.Close()

	msg := []byte("hello websocket")
	go func() {
		if err := serverConn.WriteText(msg); err != nil {
			t.Errorf("write: %v", err)
		}
	}()

	op, data, err := clientReadFrame(clientConn)
	if err != nil {
		t.Fatal(err)
	}
	if op != OpText {
		t.Fatalf("expected OpText got %d", op)
	}
	if string(data) != string(msg) {
		t.Fatalf("expected %q got %q", msg, data)
	}
}

func TestBinaryFrameRoundTrip(t *testing.T) {
	serverConn, clientConn := wsConnPair(t)
	defer serverConn.Close()
	defer clientConn.Close()

	msg := []byte{0x00, 0xFF, 0x42, 0x13}
	go func() {
		serverConn.WriteBinary(msg)
	}()

	op, data, err := clientReadFrame(clientConn)
	if err != nil {
		t.Fatal(err)
	}
	if op != OpBinary {
		t.Fatalf("expected OpBinary got %d", op)
	}
	if len(data) != len(msg) {
		t.Fatalf("expected %d bytes got %d", len(msg), len(data))
	}
}

func TestPingPong(t *testing.T) {
	serverConn, clientConn := wsConnPair(t)
	defer serverConn.Close()
	defer clientConn.Close()

	// Client sends ping.
	clientWriteMaskedFrame(clientConn, OpPing, []byte("ping"))

	// Server should auto-respond pong via ReadMessage loop.
	go func() {
		serverConn.ReadMessage() // triggers pong
	}()

	// Read the pong from client side.
	time.Sleep(50 * time.Millisecond)
	op, data, err := clientReadFrame(clientConn)
	if err != nil {
		t.Fatal(err)
	}
	if op != OpPong {
		t.Fatalf("expected OpPong got %d", op)
	}
	if string(data) != "ping" {
		t.Fatalf("expected ping payload, got %q", data)
	}
}

func TestCloseHandshake(t *testing.T) {
	serverConn, clientConn := wsConnPair(t)
	defer clientConn.Close()

	// Send close from client.
	code := make([]byte, 2)
	binary.BigEndian.PutUint16(code, 1000)
	clientWriteMaskedFrame(clientConn, OpClose, code)

	// Server ReadMessage should return EOF.
	_, _, err := serverConn.ReadMessage()
	if err != io.EOF {
		t.Fatalf("expected EOF got %v", err)
	}
}

func TestLargeFrame(t *testing.T) {
	serverConn, clientConn := wsConnPair(t)
	defer serverConn.Close()
	defer clientConn.Close()

	// 1000 byte message.
	msg := make([]byte, 1000)
	for i := range msg {
		msg[i] = byte(i % 256)
	}

	go func() {
		serverConn.WriteText(msg)
	}()

	_, data, err := clientReadFrame(clientConn)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 1000 {
		t.Fatalf("expected 1000 bytes got %d", len(data))
	}
}

func TestMaskedClientFrame(t *testing.T) {
	serverConn, clientConn := wsConnPair(t)
	defer serverConn.Close()
	defer clientConn.Close()

	// Send masked text frame from client.
	clientWriteMaskedFrame(clientConn, OpText, []byte("masked hello"))

	done := make(chan struct{})
	go func() {
		op, data, err := serverConn.ReadMessage()
		if err != nil {
			t.Errorf("read: %v", err)
		}
		if op != OpText || string(data) != "masked hello" {
			t.Errorf("expected masked hello, got op=%d data=%q", op, data)
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for read")
	}
}

func TestDoubleClose(t *testing.T) {
	serverConn, clientConn := wsConnPair(t)
	defer clientConn.Close()

	if err := serverConn.Close(); err != nil {
		t.Fatal(err)
	}
	// Second close should not panic.
	if err := serverConn.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestWriteAfterClose(t *testing.T) {
	serverConn, clientConn := wsConnPair(t)
	defer clientConn.Close()

	serverConn.Close()
	err := serverConn.WriteText([]byte("after close"))
	if err == nil {
		t.Fatal("expected error writing to closed conn")
	}
}

// --- helpers ---

// dialWS performs a raw TCP connection and sends a WebSocket upgrade request.
func dialWS(t *testing.T, rawURL string) (net.Conn, *bufio.Reader) {
	t.Helper()
	addr := strings.TrimPrefix(rawURL, "http://")
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}

	key := base64.StdEncoding.EncodeToString([]byte("test-key-12345678"))
	req := "GET / HTTP/1.1\r\n" +
		"Host: " + addr + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	conn.Write([]byte(req))

	return conn, bufio.NewReader(conn)
}

// wsConnPair creates a connected server *Conn and raw client net.Conn pair.
func wsConnPair(t *testing.T) (*Conn, net.Conn) {
	t.Helper()
	srvCh := make(chan *Conn, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := Upgrade(w, r)
		if err != nil {
			t.Errorf("upgrade: %v", err)
			return
		}
		srvCh <- c
	}))
	t.Cleanup(ts.Close)

	conn, br := dialWS(t, ts.URL)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 101 {
		t.Fatalf("expected 101 got %d", resp.StatusCode)
	}

	// Replace conn reader with the buffered reader (it may have buffered data).
	wrappedConn := &bufferedConn{Conn: conn, br: br}

	return <-srvCh, wrappedConn
}

// bufferedConn wraps a net.Conn with a buffered reader.
type bufferedConn struct {
	net.Conn
	br *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) {
	return c.br.Read(b)
}

// clientReadFrame reads a single unmasked frame from the server (raw parsing).
func clientReadFrame(conn net.Conn) (int, []byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, nil, err
	}
	opcode := int(header[0] & 0x0F)
	length := uint64(header[1] & 0x7F)

	switch length {
	case 126:
		ext := make([]byte, 2)
		io.ReadFull(conn, ext)
		length = uint64(binary.BigEndian.Uint16(ext))
	case 127:
		ext := make([]byte, 8)
		io.ReadFull(conn, ext)
		length = binary.BigEndian.Uint64(ext)
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return 0, nil, err
	}
	return opcode, payload, nil
}

// clientWriteMaskedFrame writes a masked frame from the client side.
func clientWriteMaskedFrame(conn net.Conn, opcode int, payload []byte) {
	var buf []byte
	buf = append(buf, 0x80|byte(opcode))

	mask := [4]byte{0x12, 0x34, 0x56, 0x78}
	length := len(payload)

	switch {
	case length <= 125:
		buf = append(buf, 0x80|byte(length)) // MASK bit set
	case length <= 65535:
		buf = append(buf, 0x80|126)
		ext := make([]byte, 2)
		binary.BigEndian.PutUint16(ext, uint16(length))
		buf = append(buf, ext...)
	}

	buf = append(buf, mask[:]...)

	masked := make([]byte, length)
	for i := range payload {
		masked[i] = payload[i] ^ mask[i%4]
	}
	buf = append(buf, masked...)

	conn.Write(buf)
}

// acceptKeyFor computes the expected Sec-WebSocket-Accept value.
func acceptKeyFor(key string) string {
	h := sha1.New()
	h.Write([]byte(key + websocketGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func TestAcceptKey(t *testing.T) {
	// Verify SHA-1 accept key computation per RFC 6455 §4.2.2.
	key := "dGhlIHNhbXBsZSBub25jZQ=="
	expected := "/dvkGt6SdDYiHhDka48TyWxocvo="
	got := acceptKeyFor(key)
	if got != expected {
		t.Fatalf("expected %q got %q", expected, got)
	}
}
