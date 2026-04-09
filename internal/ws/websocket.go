// Package ws provides a minimal RFC 6455 WebSocket implementation using
// only the Go standard library.  It supports text and binary frames,
// close handshake, ping/pong, and frame masking (client→server).
package ws

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	// WebSocket frame opcodes.
	OpText   = 1
	OpBinary = 2
	OpClose  = 8
	OpPing   = 9
	OpPong   = 10

	websocketGUID = "258EAFA5-E914-47DA-95CA-5ABB0D7EE3B2"
	maxFrameSize  = 64 * 1024 // 64 KB per frame
)

// Conn wraps a hijacked TCP connection and provides WebSocket read/write.
type Conn struct {
	conn   net.Conn
	br     *bufio.Reader
	mu     sync.Mutex // serialises writes
	closed bool
}

// Upgrade performs the HTTP→WebSocket handshake and returns a *Conn.
func Upgrade(w http.ResponseWriter, r *http.Request) (*Conn, error) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") ||
		!strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
		http.Error(w, "not a websocket request", http.StatusBadRequest)
		return nil, errors.New("ws: not a websocket upgrade request")
	}

	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		http.Error(w, "missing Sec-WebSocket-Key", http.StatusBadRequest)
		return nil, errors.New("ws: missing Sec-WebSocket-Key")
	}

	// Compute accept key per RFC 6455 §4.2.2.
	h := sha1.New()
	h.Write([]byte(key + websocketGUID))
	accept := base64.StdEncoding.EncodeToString(h.Sum(nil))

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return nil, errors.New("ws: response writer does not support hijack")
	}

	conn, bufrw, err := hj.Hijack()
	if err != nil {
		return nil, fmt.Errorf("ws: hijack: %w", err)
	}

	// Write the 101 Switching Protocols response.
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
	if _, err := bufrw.WriteString(resp); err != nil {
		conn.Close()
		return nil, fmt.Errorf("ws: write handshake: %w", err)
	}
	if err := bufrw.Flush(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("ws: flush handshake: %w", err)
	}

	return &Conn{conn: conn, br: bufrw.Reader}, nil
}

// ReadMessage reads the next text or binary frame.
func (c *Conn) ReadMessage() (opcode int, payload []byte, err error) {
	for {
		op, data, readErr := c.readFrame()
		if readErr != nil {
			return 0, nil, readErr
		}
		switch op {
		case OpClose:
			c.writeClose(1000, "")
			return OpClose, data, io.EOF
		case OpPing:
			c.writeFrame(OpPong, data)
			continue
		case OpPong:
			continue
		case OpText, OpBinary:
			return op, data, nil
		default:
			return op, data, nil
		}
	}
}

// WriteText sends a text frame.
func (c *Conn) WriteText(data []byte) error {
	return c.writeFrame(OpText, data)
}

// WriteBinary sends a binary frame.
func (c *Conn) WriteBinary(data []byte) error {
	return c.writeFrame(OpBinary, data)
}

// Close sends a close frame and closes the underlying connection.
func (c *Conn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	// Best-effort close frame (already holding mutex, use internal writer).
	payload := make([]byte, 2+len("normal closure"))
	binary.BigEndian.PutUint16(payload, 1000)
	copy(payload[2:], "normal closure")
	c.writeFrameLocked(OpClose, payload)
	return c.conn.Close()
}

// SetDeadline sets the read/write deadline on the underlying connection.
func (c *Conn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// readFrame reads a single WebSocket frame (handles masking).
func (c *Conn) readFrame() (opcode int, payload []byte, err error) {
	// Read first 2 bytes: FIN|RSV|opcode, MASK|payload-len.
	header := make([]byte, 2)
	if _, err := io.ReadFull(c.br, header); err != nil {
		return 0, nil, err
	}

	opcode = int(header[0] & 0x0F)
	masked := (header[1] & 0x80) != 0
	length := uint64(header[1] & 0x7F)

	switch length {
	case 126:
		ext := make([]byte, 2)
		if _, err := io.ReadFull(c.br, ext); err != nil {
			return 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(ext))
	case 127:
		ext := make([]byte, 8)
		if _, err := io.ReadFull(c.br, ext); err != nil {
			return 0, nil, err
		}
		length = binary.BigEndian.Uint64(ext)
	}

	if length > maxFrameSize {
		return 0, nil, fmt.Errorf("ws: frame too large (%d bytes)", length)
	}

	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(c.br, mask[:]); err != nil {
			return 0, nil, err
		}
	}

	payload = make([]byte, length)
	if _, err := io.ReadFull(c.br, payload); err != nil {
		return 0, nil, err
	}

	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}

	return opcode, payload, nil
}

// writeFrame writes a single unmasked WebSocket frame (server→client).
func (c *Conn) writeFrame(opcode int, payload []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return errors.New("ws: connection closed")
	}
	return c.writeFrameLocked(opcode, payload)
}

// writeFrameLocked writes a frame assuming the mutex is already held.
func (c *Conn) writeFrameLocked(opcode int, payload []byte) error {
	var buf []byte
	fin := byte(0x80)
	op, err := frameOpcode(opcode)
	if err != nil {
		return err
	}
	buf = append(buf, fin|op)

	length := len(payload)
	switch {
	case length <= 125:
		buf = append(buf, byte(length))
	case length <= 65535:
		buf = append(buf, 126)
		ext := make([]byte, 2)
		binary.BigEndian.PutUint16(ext, uint16(length))
		buf = append(buf, ext...)
	default:
		buf = append(buf, 127)
		ext := make([]byte, 8)
		binary.BigEndian.PutUint64(ext, uint64(length))
		buf = append(buf, ext...)
	}

	buf = append(buf, payload...)
	_, err = c.conn.Write(buf)
	return err
}

// writeClose sends a close frame with the given code and reason.
func (c *Conn) writeClose(code uint16, reason string) {
	payload := make([]byte, 2+len(reason))
	binary.BigEndian.PutUint16(payload, code)
	copy(payload[2:], reason)
	c.writeFrame(OpClose, payload)
}

func frameOpcode(opcode int) (byte, error) {
	switch opcode {
	case OpText, OpBinary, OpClose, OpPing, OpPong:
		return byte(opcode), nil
	default:
		return 0, fmt.Errorf("ws: invalid opcode %d", opcode)
	}
}
