package api

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

type webhookDebugConfig struct {
	Enabled        bool
	URL            string
	AuthHeader     string
	HMACSecret     string
	DeadLetterPath string
	TimeoutMS      int
	Events         []string
}

type webhookDelivery struct {
	ID          string      `json:"id"`
	FailedAt    int64       `json:"failed_at"`
	Event       string      `json:"event"`
	Attempts    int         `json:"attempts"`
	Payload     string      `json:"payload"`
	PayloadJSON interface{} `json:"payload_json,omitempty"`
	rawLine     string
}

// RegisterWebhookDebugRoutes exposes webhook dead-letter inspection and retry APIs.
func (a *API) RegisterWebhookDebugRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v2/webhooks/deliveries", a.handleListWebhookDeliveries)
	mux.HandleFunc("POST /api/v2/webhooks/deliveries/retry", a.handleRetryWebhookDeliveries)
}

func (a *API) loadWebhookDebugConfig() (*webhookDebugConfig, error) {
	if a.config == nil || a.config.ConfigFile == "" {
		return nil, fmt.Errorf("config file is not configured")
	}

	data, err := os.ReadFile(a.config.ConfigFile)
	if err != nil {
		return nil, fmt.Errorf("read webhook config: %w", err)
	}

	if cfg, err := parseWebhookDebugJSON(data); err == nil {
		return cfg, nil
	}
	return parseWebhookDebugINI(data)
}

func parseWebhookDebugJSON(data []byte) (*webhookDebugConfig, error) {
	var root map[string]interface{}
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	section, ok := root["webhook"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("webhook section not found")
	}
	return &webhookDebugConfig{
		Enabled:        boolFromValue(section["enabled"]),
		URL:            stringFromValue(section["url"]),
		AuthHeader:     stringFromValue(section["auth_header"]),
		HMACSecret:     stringFromValue(section["hmac_secret"]),
		DeadLetterPath: stringFromValue(section["dead_letter_path"]),
		TimeoutMS:      intFromValue(section["timeout_ms"]),
		Events:         eventListFromValue(section["events"]),
	}, nil
}

func parseWebhookDebugINI(data []byte) (*webhookDebugConfig, error) {
	cfg := &webhookDebugConfig{}
	inWebhookSection := false
	seenWebhookSection := false

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section := strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			inWebhookSection = section == "webhook"
			if inWebhookSection {
				seenWebhookSection = true
			}
			continue
		}
		if !inWebhookSection {
			continue
		}

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		switch key {
		case "enabled":
			cfg.Enabled = value == "1" || strings.EqualFold(value, "true") || strings.EqualFold(value, "yes")
		case "url":
			cfg.URL = value
		case "auth_header":
			cfg.AuthHeader = value
		case "hmac_secret":
			cfg.HMACSecret = value
		case "dead_letter_path":
			cfg.DeadLetterPath = value
		case "timeout_ms":
			cfg.TimeoutMS, _ = strconv.Atoi(value)
		case "events":
			cfg.Events = parseWebhookEventList(value)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan webhook config: %w", err)
	}
	if !seenWebhookSection {
		return nil, fmt.Errorf("webhook section not found")
	}
	return cfg, nil
}

func eventListFromValue(v interface{}) []string {
	switch value := v.(type) {
	case string:
		return parseWebhookEventList(value)
	case []interface{}:
		events := make([]string, 0, len(value))
		for _, item := range value {
			if event, ok := item.(string); ok {
				events = append(events, strings.ToLower(strings.TrimSpace(event)))
			}
		}
		return events
	default:
		return nil
	}
}

func parseWebhookEventList(value string) []string {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	events := make([]string, 0, len(parts))
	for _, part := range parts {
		event := strings.ToLower(strings.TrimSpace(part))
		if event != "" {
			events = append(events, event)
		}
	}
	return events
}

func stringFromValue(v interface{}) string {
	switch value := v.(type) {
	case string:
		return value
	default:
		return ""
	}
}

func boolFromValue(v interface{}) bool {
	switch value := v.(type) {
	case bool:
		return value
	case string:
		return value == "1" || strings.EqualFold(value, "true") || strings.EqualFold(value, "yes")
	default:
		return false
	}
}

func intFromValue(v interface{}) int {
	switch value := v.(type) {
	case int:
		return value
	case int64:
		return int(value)
	case float64:
		return int(value)
	case string:
		n, _ := strconv.Atoi(value)
		return n
	default:
		return 0
	}
}

func (cfg *webhookDebugConfig) allowsEvent(event string) bool {
	if cfg == nil || len(cfg.Events) == 0 {
		return true
	}
	for _, candidate := range cfg.Events {
		if candidate == "*" || candidate == "all" || candidate == strings.ToLower(event) {
			return true
		}
	}
	return false
}

func readWebhookDeliveries(path string) ([]webhookDelivery, error) {
	if path == "" {
		return nil, fmt.Errorf("webhook dead letter path is not configured")
	}
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []webhookDelivery{}, nil
		}
		return nil, fmt.Errorf("open webhook dead letter file: %w", err)
	}
	defer file.Close()

	var deliveries []webhookDelivery
	scanner := bufio.NewScanner(file)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" {
			continue
		}

		var delivery webhookDelivery
		if err := json.Unmarshal([]byte(raw), &delivery); err != nil {
			return nil, fmt.Errorf("parse webhook dead letter line %d: %w", lineNo, err)
		}
		sum := sha256.Sum256([]byte(raw))
		delivery.ID = hex.EncodeToString(sum[:])
		delivery.rawLine = raw
		if delivery.Payload != "" {
			var parsed interface{}
			if err := json.Unmarshal([]byte(delivery.Payload), &parsed); err == nil {
				delivery.PayloadJSON = parsed
			}
		}
		deliveries = append(deliveries, delivery)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan webhook dead letter file: %w", err)
	}

	sort.SliceStable(deliveries, func(i, j int) bool {
		return deliveries[i].FailedAt > deliveries[j].FailedAt
	})
	return deliveries, nil
}

func writeWebhookDeliveries(path string, deliveries []webhookDelivery) error {
	var buf strings.Builder
	for _, delivery := range deliveries {
		buf.WriteString(delivery.rawLine)
		buf.WriteByte('\n')
	}
	return os.WriteFile(path, []byte(buf.String()), 0o600)
}

func appendWebhookDelivery(path, event, payload string, attempts int) error {
	if path == "" {
		return nil
	}
	entry, err := json.Marshal(map[string]interface{}{
		"failed_at": time.Now().Unix(),
		"event":     event,
		"attempts":  attempts,
		"payload":   payload,
	})
	if err != nil {
		return fmt.Errorf("marshal webhook dead letter entry: %w", err)
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open webhook dead letter file: %w", err)
	}
	defer file.Close()

	if _, err := file.Write(append(entry, '\n')); err != nil {
		return fmt.Errorf("append webhook dead letter entry: %w", err)
	}
	return nil
}

func buildWebhookPayload(event, username, clientAddr, detail string) (string, error) {
	payload, err := json.Marshal(map[string]interface{}{
		"event":       defaultString(event, "unknown"),
		"timestamp":   time.Now().Unix(),
		"username":    username,
		"client_addr": clientAddr,
		"detail":      detail,
	})
	if err != nil {
		return "", fmt.Errorf("marshal webhook payload: %w", err)
	}
	return string(payload), nil
}

func defaultString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func sendWebhookDelivery(ctx context.Context, cfg *webhookDebugConfig, payload string) error {
	if cfg == nil || cfg.URL == "" {
		return fmt.Errorf("webhook URL is not configured")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.URL, strings.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create webhook retry request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if cfg.AuthHeader != "" {
		req.Header.Set("Authorization", cfg.AuthHeader)
	}
	if cfg.HMACSecret != "" {
		mac := hmac.New(sha256.New, []byte(cfg.HMACSecret))
		mac.Write([]byte(payload))
		req.Header.Set("X-SSH-Proxy-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}

	timeout := cfg.TimeoutMS
	if timeout <= 0 {
		timeout = 5000
	}
	client := &http.Client{Timeout: time.Duration(timeout) * time.Millisecond}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("send webhook retry request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook retry returned %d", resp.StatusCode)
	}
	return nil
}

func (a *API) emitWebhookEvent(event, username, clientAddr, detail string) {
	cfg, err := a.loadWebhookDebugConfig()
	if err != nil || cfg == nil || !cfg.Enabled || cfg.URL == "" || !cfg.allowsEvent(event) {
		return
	}

	payload, err := buildWebhookPayload(event, username, clientAddr, detail)
	if err != nil {
		log.Printf("webhook emit %s: build payload: %v", event, err)
		return
	}

	timeout := cfg.TimeoutMS
	if timeout <= 0 {
		timeout = 5000
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Millisecond)
	defer cancel()

	if err := sendWebhookDelivery(ctx, cfg, payload); err != nil {
		log.Printf("webhook emit %s: %v", event, err)
		if dlqErr := appendWebhookDelivery(cfg.DeadLetterPath, event, payload, 1); dlqErr != nil {
			log.Printf("webhook emit %s: append DLQ: %v", event, dlqErr)
		}
	}
}

func (a *API) handleListWebhookDeliveries(w http.ResponseWriter, r *http.Request) {
	cfg, err := a.loadWebhookDebugConfig()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "failed to load webhook configuration: "+err.Error())
		return
	}
	deliveries, err := readWebhookDeliveries(cfg.DeadLetterPath)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}

	page, perPage := parsePagination(r)
	total := len(deliveries)
	start, end := paginate(total, page, perPage)
	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    deliveries[start:end],
		Total:   total,
		Page:    page,
		PerPage: perPage,
	})
}

func (a *API) handleRetryWebhookDeliveries(w http.ResponseWriter, r *http.Request) {
	cfg, err := a.loadWebhookDebugConfig()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "failed to load webhook configuration: "+err.Error())
		return
	}
	if !cfg.Enabled {
		writeError(w, http.StatusBadRequest, "webhook delivery is not enabled")
		return
	}

	var req struct {
		IDs []string `json:"ids"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	deliveries, err := readWebhookDeliveries(cfg.DeadLetterPath)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}

	selected := make(map[string]struct{}, len(req.IDs))
	for _, id := range req.IDs {
		selected[id] = struct{}{}
	}

	var remaining []webhookDelivery
	type retryFailure struct {
		ID    string `json:"id"`
		Event string `json:"event"`
		Error string `json:"error"`
	}
	var failures []retryFailure
	retried := 0
	for _, delivery := range deliveries {
		if len(selected) > 0 {
			if _, ok := selected[delivery.ID]; !ok {
				remaining = append(remaining, delivery)
				continue
			}
		}

		ctx, cancel := context.WithTimeout(r.Context(), time.Duration(max(cfg.TimeoutMS, 5000))*time.Millisecond)
		err := sendWebhookDelivery(ctx, cfg, delivery.Payload)
		cancel()
		if err != nil {
			remaining = append(remaining, delivery)
			failures = append(failures, retryFailure{
				ID:    delivery.ID,
				Event: delivery.Event,
				Error: err.Error(),
			})
			continue
		}
		retried++
	}

	if err := writeWebhookDeliveries(cfg.DeadLetterPath, remaining); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update webhook dead letter queue: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"retried": retried,
			"failed":  failures,
			"total":   len(deliveries),
		},
	})
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
