// Package ws provides WebSocket handlers including a terminal proxy that
// bridges browser xterm.js sessions to SSH connections through the data plane.
package ws

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/zltl/audit-proxy-core/internal/dlp"
	"github.com/zltl/audit-proxy-core/internal/terminal"
)

// TerminalHandler handles WebSocket connections for the web terminal feature.
type TerminalHandler struct {
	// Bridge runs in-process SSH sessions through the policy decision point.
	// When set, the handler uses unified policy, recordings, and session registry.
	Bridge *terminal.Bridge
	// ProxyAddr is the legacy raw TCP fallback when Bridge is nil.
	ProxyAddr string
	RecordingDir            string
	RecordingBasePath       string
	TransferPolicy          dlp.FileTransferPolicy
	TransferApprovalEnabled bool
	ClipboardAuditEnabled   bool
}

// terminalMsg is the JSON message format between browser and server.
type terminalMsg struct {
	Type                    string                 `json:"type"`
	Action                  string                 `json:"action,omitempty"`
	Data                    string                 `json:"data,omitempty"`
	Cols                    int                    `json:"cols,omitempty"`
	Rows                    int                    `json:"rows,omitempty"`
	RequestID               string                 `json:"request_id,omitempty"`
	Direction               string                 `json:"direction,omitempty"`
	Name                    string                 `json:"name,omitempty"`
	Path                    string                 `json:"path,omitempty"`
	Size                    int64                  `json:"size,omitempty"`
	Allowed                 bool                   `json:"allowed,omitempty"`
	Reason                  string                 `json:"reason,omitempty"`
	SensitivePatterns       []dlp.SensitivePattern `json:"sensitive_patterns,omitempty"`
	SensitiveMaxScanBytes   int64                  `json:"sensitive_max_scan_bytes,omitempty"`
	TransferApprovalEnabled bool                   `json:"transfer_approval_enabled,omitempty"`
	ClipboardAuditEnabled   bool                   `json:"clipboard_audit_enabled,omitempty"`
	RecordingID             string                 `json:"recording_id,omitempty"`
	DownloadURL             string                 `json:"download_url,omitempty"`
	SessionID               string                 `json:"session_id,omitempty"`
}

// ServeHTTP upgrades to WebSocket and bridges to an SSH session.
func (h *TerminalHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.Bridge != nil {
		h.servePolicyTerminal(w, r)
		return
	}
	h.serveLegacyTCPBridge(w, r)
}

func (h *TerminalHandler) servePolicyTerminal(w http.ResponseWriter, r *http.Request) {
	wsConn, err := Upgrade(w, r)
	if err != nil {
		log.Printf("terminal: websocket upgrade failed: %v", err)
		return
	}
	defer wsConn.Close()

	host := strings.TrimSpace(r.URL.Query().Get("host"))
	if host == "" {
		_ = writeTerminalControl(wsConn, terminalMsg{Type: "control", Action: "error", Data: "missing host parameter"})
		return
	}

	username := strings.TrimSpace(r.Header.Get("X-User"))
	if username == "" {
		_ = writeTerminalControl(wsConn, terminalMsg{Type: "control", Action: "error", Data: "not authenticated"})
		return
	}
	role := strings.TrimSpace(r.Header.Get("X-Auth-Role"))
	roles := []string{}
	if role != "" {
		roles = []string{role}
	}

	cols, rows := 80, 24
	if c := r.URL.Query().Get("cols"); c != "" {
		fmt.Sscanf(c, "%d", &cols)
	}
	if rv := r.URL.Query().Get("rows"); rv != "" {
		fmt.Sscanf(rv, "%d", &rows)
	}

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	session, err := h.Bridge.Connect(ctx, terminal.ConnectRequest{
		Username:      username,
		Roles:         roles,
		Target:        host,
		UpstreamLogin: strings.TrimSpace(r.URL.Query().Get("login")),
		SourceIP:      clientIP(r),
		Cols:          cols,
		Rows:          rows,
	})
	if err != nil {
		_ = writeTerminalControl(wsConn, terminalMsg{Type: "control", Action: "error", Data: err.Error()})
		return
	}
	defer session.Close("web terminal disconnected")

	connectedMsg := terminalMsg{
		Type:        "control",
		Action:      "connected",
		Data:        fmt.Sprintf("Connected to %s as %s\r\n", host, session.UpstreamLogin),
		SessionID:   session.ID,
		RecordingID: session.ID,
	}
	if patterns := h.TransferPolicy.SensitivePatterns(); len(patterns) > 0 {
		connectedMsg.SensitivePatterns = patterns
		connectedMsg.SensitiveMaxScanBytes = h.TransferPolicy.SensitiveMaxScanBytes()
	}
	if h.TransferApprovalEnabled {
		connectedMsg.TransferApprovalEnabled = true
	}
	if h.ClipboardAuditEnabled {
		connectedMsg.ClipboardAuditEnabled = true
	}
	_ = writeTerminalControl(wsConn, connectedMsg)

	var wg sync.WaitGroup
	done := make(chan struct{})
	var doneOnce sync.Once
	signalDone := func() { doneOnce.Do(func() { close(done) }) }

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer signalDone()
		for {
			opcode, payload, err := wsConn.ReadMessage()
			if err != nil {
				return
			}
			if opcode == OpText {
				var msg terminalMsg
				if err := json.Unmarshal(payload, &msg); err == nil && msg.Type == "control" {
					switch msg.Action {
					case "resize":
						_ = session.Resize(msg.Cols, msg.Rows)
					case "ping":
						_ = writeTerminalControl(wsConn, terminalMsg{Type: "control", Action: "pong"})
					case "transfer_check":
						decision := h.evaluateTransferPolicy(msg)
						_ = writeTerminalControl(wsConn, terminalMsg{
							Type: "control", Action: "transfer_decision",
							RequestID: msg.RequestID, Allowed: decision.Allowed, Reason: decision.Reason,
						})
					}
					continue
				}
			}
			if err := session.WriteInput(payload); err != nil {
				return
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer signalDone()
		buf := make([]byte, 4096)
		for {
			n, err := session.ReadOutput(buf)
			if n > 0 {
				if werr := wsConn.WriteBinary(append([]byte(nil), buf[:n]...)); werr != nil {
					return
				}
			}
			if err != nil {
				if err != io.EOF {
					log.Printf("terminal: read output: %v", err)
				}
				return
			}
		}
	}()

	<-done
	wg.Wait()
}

func clientIP(r *http.Request) string {
	if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
		if ip, _, ok := strings.Cut(xff, ","); ok {
			return strings.TrimSpace(ip)
		}
		return xff
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (h *TerminalHandler) evaluateTransferPolicy(msg terminalMsg) dlp.FileTransferDecision {
	return h.TransferPolicy.Evaluate(dlp.FileTransferMeta{
		Direction: msg.Direction,
		Name:      msg.Name,
		Path:      msg.Path,
		Size:      msg.Size,
	})
}

func writeTerminalControl(conn *Conn, msg terminalMsg) error {
	payload, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return conn.WriteText(payload)
}
