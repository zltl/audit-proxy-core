package jit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/smtp"
	"strings"
	"time"
)

// NotifierConfig configures email and chat webhook targets for JIT events.
type NotifierConfig struct {
	WebhookURL         string
	SlackWebhookURL    string
	DingTalkWebhookURL string
	WeComWebhookURL    string
	SMTPAddr           string
	SMTPUsername       string
	SMTPPassword       string
	EmailFrom          string
	EmailTo            string
	HTTPTimeout        time.Duration
}

// Notifier sends webhook and email notifications for JIT events.
type Notifier struct {
	webhookURL         string
	slackWebhookURL    string
	dingTalkWebhookURL string
	weComWebhookURL    string
	smtpAddr           string
	smtpUsername       string
	smtpPassword       string
	emailFrom          string
	emailTo            []string
	httpClient         *http.Client
	sendMail           func(addr string, a smtp.Auth, from string, to []string, msg []byte) error
}

// JITEvent describes a JIT lifecycle event sent to webhooks.
type JITEvent struct {
	Type      string         `json:"type"`
	Request   *AccessRequest `json:"request"`
	Actor     string         `json:"actor"`
	Timestamp time.Time      `json:"timestamp"`
}

// NewNotifier creates a new notifier. It returns nil when no notification target is configured.
func NewNotifier(cfg NotifierConfig) (*Notifier, error) {
	timeout := cfg.HTTPTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	emailTo := splitRecipients(cfg.EmailTo)
	if len(emailTo) == 0 &&
		cfg.WebhookURL == "" &&
		cfg.SlackWebhookURL == "" &&
		cfg.DingTalkWebhookURL == "" &&
		cfg.WeComWebhookURL == "" {
		return nil, nil
	}
	return &Notifier{
		webhookURL:         strings.TrimSpace(cfg.WebhookURL),
		slackWebhookURL:    strings.TrimSpace(cfg.SlackWebhookURL),
		dingTalkWebhookURL: strings.TrimSpace(cfg.DingTalkWebhookURL),
		weComWebhookURL:    strings.TrimSpace(cfg.WeComWebhookURL),
		smtpAddr:           strings.TrimSpace(cfg.SMTPAddr),
		smtpUsername:       strings.TrimSpace(cfg.SMTPUsername),
		smtpPassword:       cfg.SMTPPassword,
		emailFrom:          strings.TrimSpace(cfg.EmailFrom),
		emailTo:            emailTo,
		httpClient:         &http.Client{Timeout: timeout},
		sendMail:           smtp.SendMail,
	}, nil
}

// Notify sends a JIT event to every configured sink.
func (n *Notifier) Notify(ctx context.Context, event *JITEvent) error {
	if n == nil {
		return nil
	}

	event.Timestamp = time.Now().UTC()
	var errs []error

	if n.webhookURL != "" {
		if err := n.postJSON(ctx, n.webhookURL, event); err != nil {
			errs = append(errs, fmt.Errorf("generic webhook: %w", err))
		}
	}
	if n.slackWebhookURL != "" {
		if err := n.postJSON(ctx, n.slackWebhookURL, map[string]string{"text": renderNotificationText(event)}); err != nil {
			errs = append(errs, fmt.Errorf("slack webhook: %w", err))
		}
	}
	if n.dingTalkWebhookURL != "" {
		payload := map[string]interface{}{
			"msgtype": "text",
			"text": map[string]string{
				"content": renderNotificationText(event),
			},
		}
		if err := n.postJSON(ctx, n.dingTalkWebhookURL, payload); err != nil {
			errs = append(errs, fmt.Errorf("dingtalk webhook: %w", err))
		}
	}
	if n.weComWebhookURL != "" {
		payload := map[string]interface{}{
			"msgtype": "text",
			"text": map[string]string{
				"content": renderNotificationText(event),
			},
		}
		if err := n.postJSON(ctx, n.weComWebhookURL, payload); err != nil {
			errs = append(errs, fmt.Errorf("wecom webhook: %w", err))
		}
	}
	if len(n.emailTo) > 0 {
		if err := n.sendEmail(event); err != nil {
			errs = append(errs, fmt.Errorf("email notification: %w", err))
		}
	}
	return errors.Join(errs...)
}

func splitRecipients(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	recipients := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		recipients = append(recipients, trimmed)
	}
	return recipients
}

func (n *Notifier) postJSON(ctx context.Context, endpoint string, payload interface{}) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := n.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("received status %d", resp.StatusCode)
	}
	return nil
}

func (n *Notifier) sendEmail(event *JITEvent) error {
	if n.smtpAddr == "" || n.emailFrom == "" || len(n.emailTo) == 0 {
		return nil
	}
	host := n.smtpAddr
	if idx := strings.LastIndex(host, ":"); idx > 0 {
		host = host[:idx]
	}

	var auth smtp.Auth
	if n.smtpUsername != "" || n.smtpPassword != "" {
		auth = smtp.PlainAuth("", n.smtpUsername, n.smtpPassword, host)
	}

	msg := buildEmailMessage(n.emailFrom, n.emailTo, renderNotificationSubject(event), renderNotificationText(event))
	if err := n.sendMail(n.smtpAddr, auth, n.emailFrom, n.emailTo, []byte(msg)); err != nil {
		return fmt.Errorf("send smtp mail: %w", err)
	}
	return nil
}

func buildEmailMessage(from string, to []string, subject, body string) string {
	headers := []string{
		"From: " + from,
		"To: " + strings.Join(to, ", "),
		"Subject: " + subject,
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
		"",
		body,
	}
	return strings.Join(headers, "\r\n")
}

func renderNotificationSubject(event *JITEvent) string {
	target := ""
	if event != nil && event.Request != nil {
		target = event.Request.Target
	}
	switch event.Type {
	case "request_created":
		return fmt.Sprintf("[SSH Proxy] JIT approval requested for %s", defaultString(target, "target"))
	case "request_approved":
		return fmt.Sprintf("[SSH Proxy] JIT request approved for %s", defaultString(target, "target"))
	case "request_denied":
		return fmt.Sprintf("[SSH Proxy] JIT request denied for %s", defaultString(target, "target"))
	case "request_revoked":
		return fmt.Sprintf("[SSH Proxy] JIT request revoked for %s", defaultString(target, "target"))
	case "request_break_glass":
		return fmt.Sprintf("[SSH Proxy] Break-glass access activated for %s", defaultString(target, "target"))
	default:
		return fmt.Sprintf("[SSH Proxy] JIT event for %s", defaultString(target, "target"))
	}
}

func renderNotificationText(event *JITEvent) string {
	if event == nil || event.Request == nil {
		return "JIT event received."
	}
	req := event.Request
	lines := []string{
		renderNotificationSubject(event),
		"",
		"Request ID: " + req.ID,
		"Requester: " + req.Requester,
		"Target: " + req.Target,
		"Role: " + req.Role,
		"Status: " + string(req.Status),
		"Duration: " + req.Duration.String(),
	}
	if req.Reason != "" {
		lines = append(lines, "Reason: "+req.Reason)
	}
	if req.Ticket != "" {
		lines = append(lines, "Ticket: "+req.Ticket)
	}
	if req.BreakGlass {
		lines = append(lines, "Break Glass: true")
	}
	if event.Actor != "" {
		lines = append(lines, "Actor: "+event.Actor)
	}
	if !req.ExpiresAt.IsZero() {
		lines = append(lines, "Expires At: "+req.ExpiresAt.UTC().Format(time.RFC3339))
	}
	if req.DenyReason != "" {
		lines = append(lines, "Deny Reason: "+req.DenyReason)
	}
	lines = append(lines, "Timestamp: "+event.Timestamp.UTC().Format(time.RFC3339))
	return strings.Join(lines, "\n")
}

func defaultString(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}
