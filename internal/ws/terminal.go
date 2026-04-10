// Package ws provides WebSocket handlers including a terminal proxy that
// bridges browser xterm.js sessions to SSH connections through the data plane.
package ws

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/dlp"
)

// TerminalHandler handles WebSocket connections for the web terminal feature.
// It connects the browser (xterm.js) to a target SSH server by opening a raw
// TCP connection to the data plane's SSH proxy port.
type TerminalHandler struct {
	// ProxyAddr is the data plane SSH proxy address (e.g., "127.0.0.1:2222").
	ProxyAddr string
	// RecordingDir stores web terminal asciicast recordings when audit sync is enabled.
	RecordingDir string
	// RecordingBasePath is the HTTP base path used to download terminal recordings.
	RecordingBasePath string
	// TransferPolicy evaluates browser terminal upload/download candidates before transfer.
	TransferPolicy dlp.FileTransferPolicy
	// TransferApprovalEnabled exposes whether sensitive transfer approvals can be requested.
	TransferApprovalEnabled bool
	// ClipboardAuditEnabled exposes whether browser terminal pastes should be audited.
	ClipboardAuditEnabled bool
}

// terminalMsg is the JSON message format between browser and server.
type terminalMsg struct {
	Type                    string                 `json:"type"`             // "control"
	Action                  string                 `json:"action,omitempty"` // "connected", "error", "resize", "ping", "pong"
	Data                    string                 `json:"data,omitempty"`   // optional control payload
	Cols                    int                    `json:"cols,omitempty"`   // terminal columns (for resize)
	Rows                    int                    `json:"rows,omitempty"`   // terminal rows (for resize)
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
}

type terminalRecording struct {
	id          string
	path        string
	downloadURL string
	startedAt   time.Time
	file        *os.File
	mu          sync.Mutex
}

// ServeHTTP upgrades to WebSocket and bridges to the SSH proxy.
func (h *TerminalHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	wsConn, err := Upgrade(w, r)
	if err != nil {
		log.Printf("terminal: websocket upgrade failed: %v", err)
		return
	}
	defer wsConn.Close()

	host := r.URL.Query().Get("host")
	if host == "" {
		_ = writeTerminalControl(wsConn, terminalMsg{Type: "control", Action: "error", Data: "missing host parameter"})
		return
	}

	// Connect to the SSH proxy data plane.
	proxyAddr := h.ProxyAddr
	if proxyAddr == "" {
		proxyAddr = "127.0.0.1:2222"
	}

	tcpConn, err := net.DialTimeout("tcp", proxyAddr, 10*time.Second)
	if err != nil {
		_ = writeTerminalControl(wsConn, terminalMsg{
			Type:   "control",
			Action: "error",
			Data:   "failed to connect to SSH proxy: " + err.Error(),
		})
		log.Printf("terminal: connect to proxy %s: %v", proxyAddr, err)
		return
	}
	defer tcpConn.Close()

	recording, err := h.startRecording(host)
	if err != nil {
		_ = writeTerminalControl(wsConn, terminalMsg{
			Type:   "control",
			Action: "error",
			Data:   "failed to start audit recording: " + err.Error(),
		})
		log.Printf("terminal: start recording for %s: %v", host, err)
		return
	}
	if recording != nil {
		defer recording.Close()
	}

	// Send connection metadata (target host) as initial message.
	connectedMsg := terminalMsg{
		Type:        "control",
		Action:      "connected",
		Data:        "Connected to " + host + " via SSH Proxy\r\n",
		RecordingID: recordingID(recording),
		DownloadURL: recordingDownloadURL(recording),
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
	signalDone := func() {
		doneOnce.Do(func() {
			close(done)
		})
	}

	// WebSocket → TCP (browser input to SSH).
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer signalDone()
		for {
			opcode, payload, err := wsConn.ReadMessage()
			if err != nil {
				if err != io.EOF {
					log.Printf("terminal: ws read: %v", err)
				}
				tcpConn.Close()
				return
			}

			if opcode == OpText {
				var msg terminalMsg
				if err := json.Unmarshal(payload, &msg); err == nil && msg.Type == "control" {
					switch msg.Action {
					case "resize":
						log.Printf("terminal: resize %dx%d", msg.Cols, msg.Rows)
					case "ping":
						_ = writeTerminalControl(wsConn, terminalMsg{Type: "control", Action: "pong"})
					case "transfer_check":
						decision := h.evaluateTransferPolicy(msg)
						if !decision.Allowed {
							log.Printf("terminal: blocked %s transfer host=%s name=%q path=%q reason=%q", msg.Direction, host, msg.Name, msg.Path, decision.Reason)
						}
						_ = writeTerminalControl(wsConn, terminalMsg{
							Type:      "control",
							Action:    "transfer_decision",
							RequestID: msg.RequestID,
							Allowed:   decision.Allowed,
							Reason:    decision.Reason,
						})
					}
					continue
				}
			}

			if _, err := tcpConn.Write(payload); err != nil {
				log.Printf("terminal: tcp write: %v", err)
				return
			}
		}
	}()

	// TCP → WebSocket (SSH output to browser).
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer signalDone()
		buf := make([]byte, 4096)
		for {
			n, err := tcpConn.Read(buf)
			if err != nil {
				if err != io.EOF {
					log.Printf("terminal: tcp read: %v", err)
				}
				return
			}
			payload := append([]byte(nil), buf[:n]...)
			if err := wsConn.WriteBinary(payload); err != nil {
				log.Printf("terminal: ws write: %v", err)
				return
			}
			if recording != nil {
				if err := recording.AppendOutput(payload); err != nil {
					log.Printf("terminal: append audit recording: %v", err)
				}
			}
		}
	}()

	<-done
	wg.Wait()
}

func (h *TerminalHandler) evaluateTransferPolicy(msg terminalMsg) dlp.FileTransferDecision {
	return h.TransferPolicy.Evaluate(dlp.FileTransferMeta{
		Direction: msg.Direction,
		Name:      msg.Name,
		Path:      msg.Path,
		Size:      msg.Size,
	})
}

func (h *TerminalHandler) startRecording(host string) (*terminalRecording, error) {
	if strings.TrimSpace(h.RecordingDir) == "" {
		return nil, nil
	}

	root := h.recordingRootDir()
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}

	recordingID := fmt.Sprintf("term-%d", time.Now().UTC().UnixNano())
	recordingPath, err := h.RecordingFilePath(recordingID)
	if err != nil {
		return nil, err
	}

	file, err := os.OpenFile(recordingPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}

	startedAt := time.Now().UTC()
	header := map[string]interface{}{
		"version":   2,
		"width":     80,
		"height":    24,
		"timestamp": startedAt.Unix(),
		"title":     "Web Terminal — " + host,
	}
	headerBytes, err := json.Marshal(header)
	if err != nil {
		file.Close()
		_ = os.Remove(recordingPath)
		return nil, err
	}
	if _, err := file.Write(append(headerBytes, '\n')); err != nil {
		file.Close()
		_ = os.Remove(recordingPath)
		return nil, err
	}

	return &terminalRecording{
		id:          recordingID,
		path:        recordingPath,
		downloadURL: h.recordingDownloadURL(recordingID),
		startedAt:   startedAt,
		file:        file,
	}, nil
}

func (h *TerminalHandler) recordingRootDir() string {
	return filepath.Join(h.RecordingDir, "web-terminal")
}

func (h *TerminalHandler) recordingDownloadURL(id string) string {
	basePath := strings.TrimSpace(h.RecordingBasePath)
	if basePath == "" {
		basePath = "/api/v2/terminal/recordings"
	}
	return strings.TrimRight(basePath, "/") + "/" + url.PathEscape(id) + "/download"
}

// RecordingFilePath returns the validated on-disk path for a web terminal recording.
func (h *TerminalHandler) RecordingFilePath(id string) (string, error) {
	if strings.TrimSpace(h.RecordingDir) == "" {
		return "", os.ErrNotExist
	}
	root := h.recordingRootDir()
	recordingPath := filepath.Join(root, id+".cast")

	rel, err := filepath.Rel(root, recordingPath)
	if err != nil {
		return "", err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("invalid recording id")
	}
	return recordingPath, nil
}

func recordingID(recording *terminalRecording) string {
	if recording == nil {
		return ""
	}
	return recording.id
}

func recordingDownloadURL(recording *terminalRecording) string {
	if recording == nil {
		return ""
	}
	return recording.downloadURL
}

func (r *terminalRecording) AppendOutput(payload []byte) error {
	if r == nil || len(payload) == 0 {
		return nil
	}
	event := []interface{}{
		time.Since(r.startedAt).Seconds(),
		"o",
		string(payload),
	}
	line, err := json.Marshal(event)
	if err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, err := r.file.Write(append(line, '\n')); err != nil {
		return err
	}
	return nil
}

func (r *terminalRecording) Close() error {
	if r == nil || r.file == nil {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	err := r.file.Close()
	r.file = nil
	return err
}

func writeTerminalControl(conn *Conn, msg terminalMsg) error {
	payload, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return conn.WriteText(payload)
}
