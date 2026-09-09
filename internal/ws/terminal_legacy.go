package ws

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// serveLegacyTCPBridge is the pre-policy raw TCP bridge kept for tests.
func (h *TerminalHandler) serveLegacyTCPBridge(w http.ResponseWriter, r *http.Request) {
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

	proxyAddr := h.ProxyAddr
	if proxyAddr == "" {
		proxyAddr = "127.0.0.1:2222"
	}

	tcpConn, err := net.DialTimeout("tcp", proxyAddr, 10*time.Second)
	if err != nil {
		_ = writeTerminalControl(wsConn, terminalMsg{
			Type: "control", Action: "error",
			Data: "failed to connect to SSH proxy: " + err.Error(),
		})
		return
	}
	defer tcpConn.Close()

	recording, err := h.startLegacyRecording(host)
	if err != nil {
		_ = writeTerminalControl(wsConn, terminalMsg{
			Type: "control", Action: "error",
			Data: "failed to start audit recording: " + err.Error(),
		})
		return
	}
	if recording != nil {
		defer recording.Close()
	}

	connectedMsg := terminalMsg{
		Type: "control", Action: "connected",
		Data:        "Connected to " + host + " via Audit Proxy\r\n",
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
	signalDone := func() { doneOnce.Do(func() { close(done) }) }

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer signalDone()
		for {
			opcode, payload, err := wsConn.ReadMessage()
			if err != nil {
				tcpConn.Close()
				return
			}
			if opcode == OpText {
				var msg terminalMsg
				if err := json.Unmarshal(payload, &msg); err == nil && msg.Type == "control" {
					switch msg.Action {
					case "resize":
						log.Printf("terminal: resize %dx%d (legacy bridge ignores)", msg.Cols, msg.Rows)
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
			if _, err := tcpConn.Write(payload); err != nil {
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
			n, err := tcpConn.Read(buf)
			if err != nil {
				return
			}
			payload := append([]byte(nil), buf[:n]...)
			if err := wsConn.WriteBinary(payload); err != nil {
				return
			}
			if recording != nil {
				_ = recording.AppendOutput(payload)
			}
		}
	}()

	<-done
	wg.Wait()
}

type terminalRecording struct {
	id          string
	path        string
	downloadURL string
	startedAt   time.Time
	file        *os.File
	mu          sync.Mutex
}

func (h *TerminalHandler) startLegacyRecording(host string) (*terminalRecording, error) {
	if strings.TrimSpace(h.RecordingDir) == "" {
		return nil, nil
	}
	root := filepath.Join(h.RecordingDir, "web-terminal")
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
		"version": 2, "width": 80, "height": 24,
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
		id: recordingID, path: recordingPath,
		downloadURL: h.recordingDownloadURL(recordingID),
		startedAt: startedAt, file: file,
	}, nil
}

func (h *TerminalHandler) recordingDownloadURL(id string) string {
	basePath := strings.TrimSpace(h.RecordingBasePath)
	if basePath == "" {
		basePath = "/api/v2/terminal/recordings"
	}
	return strings.TrimRight(basePath, "/") + "/" + url.PathEscape(id) + "/download"
}

func (h *TerminalHandler) RecordingFilePath(id string) (string, error) {
	if strings.TrimSpace(h.RecordingDir) == "" {
		return "", os.ErrNotExist
	}
	root := filepath.Join(h.RecordingDir, "web-terminal")
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
	event := []interface{}{time.Since(r.startedAt).Seconds(), "o", string(payload)}
	line, err := json.Marshal(event)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	_, err = r.file.Write(append(line, '\n'))
	return err
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
