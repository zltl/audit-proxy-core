package server

import (
	"bytes"
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/zltl/audit-proxy-core/internal/asciidemo"
	"github.com/zltl/audit-proxy-core/internal/ws"
)

var errDemoInterrupted = errors.New("demo stream interrupted")

func (s *Server) handleAsciiDemoCastDownload(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/x-asciicast")
	w.Header().Set("Content-Disposition", `attachment; filename="ascii-stream-demo.cast"`)
	w.Header().Set("Cache-Control", "public, max-age=60")
	_, _ = w.Write(asciidemo.DemoCast)
}

func (s *Server) handleAsciiDemoStream() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := ws.Upgrade(w, r)
		if err != nil {
			log.Printf("ascii demo live: websocket upgrade failed: %v", err)
			return
		}
		defer conn.Close()

		speed := 1.0
		if raw := r.URL.Query().Get("speed"); raw != "" {
			parsed, parseErr := strconv.ParseFloat(raw, 64)
			if parseErr != nil || parsed <= 0 {
				_ = writeWebsocketMessage(conn, websocketMessage{Type: "error", Error: "speed must be a positive number"})
				return
			}
			speed = parsed
		}

		frames, err := asciidemo.ParseOutputFrames(bytes.NewReader(asciidemo.DemoCast))
		if err != nil {
			_ = writeWebsocketMessage(conn, websocketMessage{Type: "error", Error: "failed to parse demo cast: " + err.Error()})
			return
		}

		done := consumeWebSocketControlFrames(conn)
		interrupted := false

		err = asciidemo.DripFrames(frames, asciidemo.DripOptions{
			Speed: speed,
			Sleep: func(d time.Duration) {
				timer := time.NewTimer(d)
				defer timer.Stop()
				select {
				case <-done:
					interrupted = true
				case <-r.Context().Done():
					interrupted = true
				case <-timer.C:
				}
			},
			OnChunk: func(chunk string) error {
				if interrupted {
					return errDemoInterrupted
				}
				select {
				case <-done:
					return errDemoInterrupted
				case <-r.Context().Done():
					return errDemoInterrupted
				default:
				}
				return writeWebsocketMessage(conn, websocketMessage{
					Type: "session.live.chunk",
					Data: map[string]string{
						"session_id": "ascii-stream-demo",
						"chunk":      chunk,
					},
				})
			},
		})
		if err != nil && !errors.Is(err, errDemoInterrupted) {
			_ = writeWebsocketMessage(conn, websocketMessage{Type: "error", Error: err.Error()})
			return
		}
		if interrupted || errors.Is(err, errDemoInterrupted) {
			return
		}
		_ = writeWebsocketMessage(conn, websocketMessage{
			Type: "session.live.status",
			Data: map[string]string{
				"session_id": "ascii-stream-demo",
				"state":      "ended",
			},
		})
	})
}
