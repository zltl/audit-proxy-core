package server

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/ws"
)

const (
	dashboardStreamInterval = 5 * time.Second
	sessionStreamInterval   = 5 * time.Second
	sessionLivePollInterval = time.Second
	sessionLiveTailBytes    = 64 * 1024
)

type websocketMessage struct {
	Type  string      `json:"type"`
	Data  interface{} `json:"data,omitempty"`
	Error string      `json:"error,omitempty"`
}

func (s *Server) handleDashboardStream() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.streamSnapshots(w, r, dashboardStreamInterval, func() (interface{}, error) {
			return s.apiHandler.BuildDashboardSnapshot()
		}, func(payload interface{}) websocketMessage {
			return websocketMessage{Type: "dashboard.snapshot", Data: payload}
		})
	})
}

func (s *Server) handleSessionsStream() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		status := strings.TrimSpace(r.URL.Query().Get("status"))
		user := strings.TrimSpace(r.URL.Query().Get("user"))
		ip := strings.TrimSpace(r.URL.Query().Get("ip"))
		target := strings.TrimSpace(r.URL.Query().Get("target"))

		s.streamSnapshots(w, r, sessionStreamInterval, func() (interface{}, error) {
			sessions, err := s.apiHandler.ListFilteredSessions(status, user, ip, target)
			if err != nil {
				return nil, err
			}
			return map[string]interface{}{
				"sessions": sessions,
				"total":    len(sessions),
				"filters": map[string]string{
					"status": status,
					"user":   user,
					"ip":     ip,
					"target": target,
				},
			}, nil
		}, func(payload interface{}) websocketMessage {
			return websocketMessage{Type: "sessions.snapshot", Data: payload}
		})
	})
}

func (s *Server) handleSessionLiveStream() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := ws.Upgrade(w, r)
		if err != nil {
			log.Printf("session live: websocket upgrade failed: %v", err)
			return
		}
		defer conn.Close()

		if s.apiHandler == nil {
			_ = writeWebsocketMessage(conn, websocketMessage{Type: "error", Error: "api handler not initialized"})
			return
		}

		sessionID := r.PathValue("id")
		recordingPath, _, message := s.apiHandler.ResolveRecordingPath(sessionID)
		if message != "" {
			_ = writeWebsocketMessage(conn, websocketMessage{Type: "error", Error: message})
			return
		}

		done := consumeWebSocketControlFrames(conn)

		offset, remainder, chunks, err := readRecordingTail(recordingPath, sessionLiveTailBytes)
		if err != nil {
			_ = writeWebsocketMessage(conn, websocketMessage{Type: "error", Error: "failed to read live recording: " + err.Error()})
			return
		}
		for _, chunk := range chunks {
			if err := writeWebsocketMessage(conn, websocketMessage{
				Type: "session.live.chunk",
				Data: map[string]string{
					"session_id": sessionID,
					"chunk":      chunk,
				},
			}); err != nil {
				return
			}
		}

		if !s.sessionIsActive(sessionID) {
			_ = writeWebsocketMessage(conn, websocketMessage{
				Type: "session.live.status",
				Data: map[string]string{
					"session_id": sessionID,
					"state":      "ended",
				},
			})
			return
		}

		ticker := time.NewTicker(sessionLivePollInterval)
		defer ticker.Stop()

		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				offset, remainder, chunks, err = readRecordingUpdates(recordingPath, offset, remainder)
				if err != nil {
					_ = writeWebsocketMessage(conn, websocketMessage{Type: "error", Error: "failed to tail live recording: " + err.Error()})
					return
				}
				for _, chunk := range chunks {
					if err := writeWebsocketMessage(conn, websocketMessage{
						Type: "session.live.chunk",
						Data: map[string]string{
							"session_id": sessionID,
							"chunk":      chunk,
						},
					}); err != nil {
						return
					}
				}
				if !s.sessionIsActive(sessionID) && len(chunks) == 0 {
					_ = writeWebsocketMessage(conn, websocketMessage{
						Type: "session.live.status",
						Data: map[string]string{
							"session_id": sessionID,
							"state":      "ended",
						},
					})
					return
				}
			}
		}
	})
}

func (s *Server) streamSnapshots(w http.ResponseWriter, r *http.Request, interval time.Duration, build func() (interface{}, error), wrap func(interface{}) websocketMessage) {
	conn, err := ws.Upgrade(w, r)
	if err != nil {
		log.Printf("websocket stream: upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	if s.apiHandler == nil {
		_ = writeWebsocketMessage(conn, websocketMessage{Type: "error", Error: "api handler not initialized"})
		return
	}

	done := consumeWebSocketControlFrames(conn)
	if err := s.writeSnapshot(conn, build, wrap); err != nil {
		return
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			if err := s.writeSnapshot(conn, build, wrap); err != nil {
				return
			}
		}
	}
}

func (s *Server) writeSnapshot(conn *ws.Conn, build func() (interface{}, error), wrap func(interface{}) websocketMessage) error {
	payload, err := build()
	if err != nil {
		_ = writeWebsocketMessage(conn, websocketMessage{Type: "error", Error: err.Error()})
		return err
	}
	return writeWebsocketMessage(conn, wrap(payload))
}

func (s *Server) sessionIsActive(id string) bool {
	sessions, err := s.apiHandler.ListFilteredSessions("", "", "", "")
	if err != nil {
		return true
	}
	for _, session := range sessions {
		if session.ID == id {
			return session.Status == "active"
		}
	}
	return false
}

func consumeWebSocketControlFrames(conn *ws.Conn) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()
	return done
}

func writeWebsocketMessage(conn *ws.Conn, message websocketMessage) error {
	payload, err := json.Marshal(message)
	if err != nil {
		return err
	}
	return conn.WriteText(payload)
}

func readRecordingTail(path string, maxBytes int64) (int64, string, []string, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, "", nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return 0, "", nil, err
	}

	offset := info.Size() - maxBytes
	if offset < 0 {
		offset = 0
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return 0, "", nil, err
	}

	raw, err := io.ReadAll(f)
	if err != nil {
		return 0, "", nil, err
	}
	if offset > 0 {
		if idx := bytes.IndexByte(raw, '\n'); idx >= 0 {
			offset += int64(idx + 1)
			raw = raw[idx+1:]
		} else {
			return info.Size(), "", nil, nil
		}
	}

	chunks, remainder := extractAsciicastChunks(raw, "")
	return info.Size(), remainder, chunks, nil
}

func readRecordingUpdates(path string, offset int64, remainder string) (int64, string, []string, error) {
	f, err := os.Open(path)
	if err != nil {
		return offset, remainder, nil, err
	}
	defer f.Close()

	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return offset, remainder, nil, err
	}
	raw, err := io.ReadAll(f)
	if err != nil {
		return offset, remainder, nil, err
	}

	chunks, nextRemainder := extractAsciicastChunks(raw, remainder)
	return offset + int64(len(raw)), nextRemainder, chunks, nil
}

func extractAsciicastChunks(raw []byte, remainder string) ([]string, string) {
	text := remainder + string(raw)
	if text == "" {
		return nil, ""
	}

	lines := strings.Split(text, "\n")
	nextRemainder := ""
	if !strings.HasSuffix(text, "\n") {
		nextRemainder = lines[len(lines)-1]
		lines = lines[:len(lines)-1]
	}

	chunks := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "{") {
			continue
		}
		chunk, ok := parseAsciicastOutput(line)
		if ok && chunk != "" {
			chunks = append(chunks, chunk)
		}
	}
	return chunks, nextRemainder
}

func parseAsciicastOutput(line string) (string, bool) {
	var frame []json.RawMessage
	if err := json.Unmarshal([]byte(line), &frame); err != nil || len(frame) != 3 {
		return "", false
	}

	var stream string
	if err := json.Unmarshal(frame[1], &stream); err != nil {
		return "", false
	}
	if stream != "o" && stream != "stdout" {
		return "", false
	}

	var data string
	if err := json.Unmarshal(frame[2], &data); err != nil {
		return "", false
	}
	return data, true
}
