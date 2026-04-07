package jit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Notifier sends webhook notifications for JIT events.
type Notifier struct {
	webhookURL string
	httpClient *http.Client
}

// JITEvent describes a JIT lifecycle event sent to webhooks.
type JITEvent struct {
	Type      string         `json:"type"`
	Request   *AccessRequest `json:"request"`
	Actor     string         `json:"actor"`
	Timestamp time.Time      `json:"timestamp"`
}

// NewNotifier creates a new webhook notifier.
func NewNotifier(webhookURL string) *Notifier {
	return &Notifier{
		webhookURL: webhookURL,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// Notify sends a JIT event to the configured webhook URL.
func (n *Notifier) Notify(ctx context.Context, event *JITEvent) error {
	if n.webhookURL == "" {
		return nil
	}

	event.Timestamp = time.Now().UTC()

	body, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := n.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("webhook request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}
	return nil
}
