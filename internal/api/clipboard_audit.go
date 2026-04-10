package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/models"
)

const terminalClipboardAuditFile = "terminal_clipboard.jsonl"

func (a *API) requireClipboardAudit(w http.ResponseWriter) bool {
	if a == nil || a.config == nil || !a.config.DLPClipboardAuditEnabled {
		writeError(w, http.StatusServiceUnavailable, "clipboard audit is not enabled")
		return false
	}
	if strings.TrimSpace(a.config.AuditLogDir) == "" {
		writeError(w, http.StatusServiceUnavailable, "audit log directory not configured")
		return false
	}
	return true
}

func (a *API) handleCreateClipboardAudit(w http.ResponseWriter, r *http.Request) {
	if !a.requireClipboardAudit(w) {
		return
	}
	username := strings.TrimSpace(r.Header.Get("X-User"))
	if username == "" {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var body struct {
		Target           string   `json:"target"`
		Source           string   `json:"source"`
		TextLength       int      `json:"text_length"`
		Sensitive        bool     `json:"sensitive"`
		MatchedDetectors []string `json:"matched_detectors"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.TextLength <= 0 {
		writeError(w, http.StatusBadRequest, "text_length must be > 0")
		return
	}

	detectors := normalizeClipboardDetectors(body.MatchedDetectors)
	if len(detectors) > 0 {
		body.Sensitive = true
	}

	event := models.AuditEvent{
		ID:         newAuditEventID("clipboard"),
		Timestamp:  time.Now().UTC(),
		EventType:  "terminal.clipboard_paste",
		Username:   username,
		SourceIP:   clientAddr(r.RemoteAddr),
		TargetHost: strings.TrimSpace(body.Target),
		Details:    clipboardAuditDetails(body.Source, body.TextLength, body.Sensitive, detectors),
	}
	if err := a.appendControlPlaneAuditEvent(event); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, APIResponse{
		Success: true,
		Data:    event,
	})
}

func normalizeClipboardDetectors(raw []string) []string {
	if len(raw) == 0 {
		return []string{}
	}
	seen := make(map[string]struct{}, len(raw))
	detectors := make([]string, 0, len(raw))
	for _, item := range raw {
		value := strings.ToLower(strings.TrimSpace(item))
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		detectors = append(detectors, value)
	}
	sort.Strings(detectors)
	return detectors
}

func clipboardAuditDetails(source string, textLength int, sensitive bool, detectors []string) string {
	source = strings.TrimSpace(source)
	if source == "" {
		source = "paste"
	}
	parts := []string{
		"terminal clipboard paste",
		"source=" + source,
		fmt.Sprintf("length=%d", textLength),
	}
	if sensitive {
		parts = append(parts, "sensitive=true")
	} else {
		parts = append(parts, "sensitive=false")
	}
	if len(detectors) > 0 {
		parts = append(parts, "detectors="+strings.Join(detectors, ","))
	}
	return strings.Join(parts, " ")
}

func (a *API) appendControlPlaneAuditEvent(event models.AuditEvent) error {
	if a == nil || a.config == nil || strings.TrimSpace(a.config.AuditLogDir) == "" {
		return fmt.Errorf("audit log directory not configured")
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal audit event: %w", err)
	}

	dir := strings.TrimSpace(a.config.AuditLogDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create audit directory: %w", err)
	}
	path := filepath.Join(dir, terminalClipboardAuditFile)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer file.Close()

	if _, err := file.Write(append(payload, '\n')); err != nil {
		return fmt.Errorf("write audit log: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync audit log: %w", err)
	}
	return nil
}

func newAuditEventID(prefix string) string {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return fmt.Sprintf("%s-%d", prefix, time.Now().UTC().UnixNano())
	}
	return prefix + "-" + hex.EncodeToString(buf[:])
}
