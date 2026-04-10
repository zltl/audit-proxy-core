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
	"text/template"
	"time"
)

var pagerDutyEnqueueURL = "https://events.pagerduty.com/v2/enqueue"

// NotifierConfig configures email and chat webhook targets for JIT events.
type NotifierConfig struct {
	WebhookURL             string
	SlackWebhookURL        string
	DingTalkWebhookURL     string
	WeComWebhookURL        string
	TeamsWebhookURL        string
	PagerDutyRoutingKey    string
	OpsgenieAPIURL         string
	OpsgenieAPIKey         string
	SubjectTemplate        string
	BodyTemplate           string
	MessageSubjectTemplate string
	MessageBodyTemplate    string
	SMTPAddr               string
	SMTPUsername           string
	SMTPPassword           string
	EmailFrom              string
	EmailTo                string
	HTTPTimeout            time.Duration
}

// Notifier sends webhook and email notifications for JIT events.
type Notifier struct {
	webhookURL             string
	slackWebhookURL        string
	dingTalkWebhookURL     string
	weComWebhookURL        string
	teamsWebhookURL        string
	pagerDutyRoutingKey    string
	opsgenieAPIURL         string
	opsgenieAPIKey         string
	subjectTemplate        *template.Template
	bodyTemplate           *template.Template
	messageSubjectTemplate *template.Template
	messageBodyTemplate    *template.Template
	smtpAddr               string
	smtpUsername           string
	smtpPassword           string
	emailFrom              string
	emailTo                []string
	httpClient             *http.Client
	sendMail               func(addr string, a smtp.Auth, from string, to []string, msg []byte) error
}

// JITEvent describes a JIT lifecycle event sent to webhooks.
type JITEvent struct {
	Type      string         `json:"type"`
	Request   *AccessRequest `json:"request"`
	Actor     string         `json:"actor"`
	Timestamp time.Time      `json:"timestamp"`
}

type messageEvent struct {
	Type      string    `json:"type"`
	Subject   string    `json:"subject"`
	Body      string    `json:"body"`
	Timestamp time.Time `json:"timestamp"`
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
		cfg.WeComWebhookURL == "" &&
		cfg.TeamsWebhookURL == "" &&
		cfg.PagerDutyRoutingKey == "" &&
		cfg.OpsgenieAPIKey == "" {
		return nil, nil
	}
	opsgenieURL := strings.TrimSpace(cfg.OpsgenieAPIURL)
	if opsgenieURL == "" {
		opsgenieURL = "https://api.opsgenie.com/v2/alerts"
	}
	subjectTemplate, err := compileNotificationTemplate("jit-subject", cfg.SubjectTemplate)
	if err != nil {
		return nil, err
	}
	bodyTemplate, err := compileNotificationTemplate("jit-body", cfg.BodyTemplate)
	if err != nil {
		return nil, err
	}
	messageSubjectTemplate, err := compileNotificationTemplate("message-subject", cfg.MessageSubjectTemplate)
	if err != nil {
		return nil, err
	}
	messageBodyTemplate, err := compileNotificationTemplate("message-body", cfg.MessageBodyTemplate)
	if err != nil {
		return nil, err
	}
	return &Notifier{
		webhookURL:             strings.TrimSpace(cfg.WebhookURL),
		slackWebhookURL:        strings.TrimSpace(cfg.SlackWebhookURL),
		dingTalkWebhookURL:     strings.TrimSpace(cfg.DingTalkWebhookURL),
		weComWebhookURL:        strings.TrimSpace(cfg.WeComWebhookURL),
		teamsWebhookURL:        strings.TrimSpace(cfg.TeamsWebhookURL),
		pagerDutyRoutingKey:    strings.TrimSpace(cfg.PagerDutyRoutingKey),
		opsgenieAPIURL:         opsgenieURL,
		opsgenieAPIKey:         strings.TrimSpace(cfg.OpsgenieAPIKey),
		subjectTemplate:        subjectTemplate,
		bodyTemplate:           bodyTemplate,
		messageSubjectTemplate: messageSubjectTemplate,
		messageBodyTemplate:    messageBodyTemplate,
		smtpAddr:               strings.TrimSpace(cfg.SMTPAddr),
		smtpUsername:           strings.TrimSpace(cfg.SMTPUsername),
		smtpPassword:           cfg.SMTPPassword,
		emailFrom:              strings.TrimSpace(cfg.EmailFrom),
		emailTo:                emailTo,
		httpClient:             &http.Client{Timeout: timeout},
		sendMail:               smtp.SendMail,
	}, nil
}

// Notify sends a JIT event to every configured sink.
func (n *Notifier) Notify(ctx context.Context, event *JITEvent) error {
	if n == nil {
		return nil
	}

	event.Timestamp = time.Now().UTC()
	subject := n.renderEventSubject(event)
	body := n.renderEventBody(event)
	var errs []error

	if n.webhookURL != "" {
		if err := n.postJSON(ctx, n.webhookURL, event); err != nil {
			errs = append(errs, fmt.Errorf("generic webhook: %w", err))
		}
	}
	if n.slackWebhookURL != "" {
		if err := n.postJSON(ctx, n.slackWebhookURL, map[string]string{"text": body}); err != nil {
			errs = append(errs, fmt.Errorf("slack webhook: %w", err))
		}
	}
	if n.dingTalkWebhookURL != "" {
		payload := map[string]interface{}{
			"msgtype": "text",
			"text": map[string]string{
				"content": body,
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
				"content": body,
			},
		}
		if err := n.postJSON(ctx, n.weComWebhookURL, payload); err != nil {
			errs = append(errs, fmt.Errorf("wecom webhook: %w", err))
		}
	}
	if n.teamsWebhookURL != "" {
		if err := n.postJSON(ctx, n.teamsWebhookURL, renderTeamsWebhookPayload(subject, body)); err != nil {
			errs = append(errs, fmt.Errorf("teams webhook: %w", err))
		}
	}
	if n.pagerDutyRoutingKey != "" {
		if err := n.postJSON(ctx, pagerDutyEnqueueURL, renderPagerDutyPayload(n.pagerDutyRoutingKey, subject, body, pagerDutySeverityForEvent(event))); err != nil {
			errs = append(errs, fmt.Errorf("pagerduty: %w", err))
		}
	}
	if n.opsgenieAPIKey != "" {
		headers := map[string]string{"Authorization": "GenieKey " + n.opsgenieAPIKey}
		if err := n.postJSONWithHeaders(ctx, n.opsgenieAPIURL, renderOpsgeniePayload(subject, body, opsgeniePriorityForEvent(event)), headers); err != nil {
			errs = append(errs, fmt.Errorf("opsgenie: %w", err))
		}
	}
	if len(n.emailTo) > 0 {
		if err := n.sendEmail(event); err != nil {
			errs = append(errs, fmt.Errorf("email notification: %w", err))
		}
	}
	return errors.Join(errs...)
}

// NotifyMessage sends a generic message to every configured sink using the same
// delivery backends as JIT notifications.
func (n *Notifier) NotifyMessage(ctx context.Context, subject, body string) error {
	if n == nil {
		return nil
	}

	message := &messageEvent{
		Type:      "message",
		Subject:   strings.TrimSpace(subject),
		Body:      strings.TrimSpace(body),
		Timestamp: time.Now().UTC(),
	}
	if message.Subject == "" {
		message.Subject = "[SSH Proxy] Notification"
	}
	if message.Body == "" {
		message.Body = message.Subject
	}
	message.Subject = n.renderMessageSubject(message)
	message.Body = n.renderMessageBody(message)

	var errs []error
	if n.webhookURL != "" {
		if err := n.postJSON(ctx, n.webhookURL, message); err != nil {
			errs = append(errs, fmt.Errorf("generic webhook: %w", err))
		}
	}
	if n.slackWebhookURL != "" {
		if err := n.postJSON(ctx, n.slackWebhookURL, map[string]string{"text": message.Body}); err != nil {
			errs = append(errs, fmt.Errorf("slack webhook: %w", err))
		}
	}
	if n.dingTalkWebhookURL != "" {
		payload := map[string]interface{}{
			"msgtype": "text",
			"text": map[string]string{
				"content": message.Body,
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
				"content": message.Body,
			},
		}
		if err := n.postJSON(ctx, n.weComWebhookURL, payload); err != nil {
			errs = append(errs, fmt.Errorf("wecom webhook: %w", err))
		}
	}
	if n.teamsWebhookURL != "" {
		if err := n.postJSON(ctx, n.teamsWebhookURL, renderTeamsWebhookPayload(message.Subject, message.Body)); err != nil {
			errs = append(errs, fmt.Errorf("teams webhook: %w", err))
		}
	}
	if n.pagerDutyRoutingKey != "" {
		if err := n.postJSON(ctx, pagerDutyEnqueueURL, renderPagerDutyPayload(n.pagerDutyRoutingKey, message.Subject, message.Body, pagerDutySeverityForMessage(message.Subject))); err != nil {
			errs = append(errs, fmt.Errorf("pagerduty: %w", err))
		}
	}
	if n.opsgenieAPIKey != "" {
		headers := map[string]string{"Authorization": "GenieKey " + n.opsgenieAPIKey}
		if err := n.postJSONWithHeaders(ctx, n.opsgenieAPIURL, renderOpsgeniePayload(message.Subject, message.Body, opsgeniePriorityForMessage(message.Subject)), headers); err != nil {
			errs = append(errs, fmt.Errorf("opsgenie: %w", err))
		}
	}
	if len(n.emailTo) > 0 {
		if err := n.sendGenericEmail(message.Subject, message.Body); err != nil {
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

func compileNotificationTemplate(name, raw string) (*template.Template, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	tpl, err := template.New(name).Option("missingkey=zero").Funcs(template.FuncMap{
		"default": func(value, fallback string) string {
			if strings.TrimSpace(value) != "" {
				return value
			}
			return fallback
		},
		"join": strings.Join,
		"rfc3339": func(ts time.Time) string {
			if ts.IsZero() {
				return ""
			}
			return ts.UTC().Format(time.RFC3339)
		},
	}).Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse notification template %s: %w", name, err)
	}
	return tpl, nil
}

func renderCompiledTemplate(tpl *template.Template, data interface{}) (string, error) {
	if tpl == nil {
		return "", nil
	}
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return strings.TrimSpace(buf.String()), nil
}

func (n *Notifier) renderEventSubject(event *JITEvent) string {
	fallback := renderNotificationSubject(event)
	rendered, err := renderCompiledTemplate(n.subjectTemplate, map[string]interface{}{
		"Event":   event,
		"Request": eventRequest(event),
	})
	if err != nil || rendered == "" {
		return fallback
	}
	return rendered
}

func (n *Notifier) renderEventBody(event *JITEvent) string {
	fallback := renderNotificationText(event)
	rendered, err := renderCompiledTemplate(n.bodyTemplate, map[string]interface{}{
		"Event":   event,
		"Request": eventRequest(event),
	})
	if err != nil || rendered == "" {
		return fallback
	}
	return rendered
}

func (n *Notifier) renderMessageSubject(message *messageEvent) string {
	if message == nil {
		return "[SSH Proxy] Notification"
	}
	rendered, err := renderCompiledTemplate(n.messageSubjectTemplate, map[string]interface{}{
		"Message": message,
	})
	if err != nil || rendered == "" {
		return message.Subject
	}
	return rendered
}

func (n *Notifier) renderMessageBody(message *messageEvent) string {
	if message == nil {
		return ""
	}
	rendered, err := renderCompiledTemplate(n.messageBodyTemplate, map[string]interface{}{
		"Message": message,
	})
	if err != nil || rendered == "" {
		return message.Body
	}
	return rendered
}

func eventRequest(event *JITEvent) *AccessRequest {
	if event == nil {
		return nil
	}
	return event.Request
}

func (n *Notifier) postJSON(ctx context.Context, endpoint string, payload interface{}) error {
	return n.postJSONWithHeaders(ctx, endpoint, payload, nil)
}

func (n *Notifier) postJSONWithHeaders(ctx context.Context, endpoint string, payload interface{}, headers map[string]string) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		if strings.TrimSpace(key) == "" || strings.TrimSpace(value) == "" {
			continue
		}
		req.Header.Set(key, value)
	}

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

	msg := buildEmailMessage(n.emailFrom, n.emailTo, n.renderEventSubject(event), n.renderEventBody(event))
	if err := n.sendMail(n.smtpAddr, auth, n.emailFrom, n.emailTo, []byte(msg)); err != nil {
		return fmt.Errorf("send smtp mail: %w", err)
	}
	return nil
}

func (n *Notifier) sendGenericEmail(subject, body string) error {
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

	msg := buildEmailMessage(n.emailFrom, n.emailTo, subject, body)
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

func renderTeamsWebhookPayload(title, body string) map[string]interface{} {
	body = strings.ReplaceAll(strings.TrimSpace(body), "\n", "<br>")
	return map[string]interface{}{
		"@type":      "MessageCard",
		"@context":   "https://schema.org/extensions",
		"summary":    strings.TrimSpace(title),
		"themeColor": "0076D7",
		"title":      strings.TrimSpace(title),
		"text":       body,
	}
}

func renderPagerDutyPayload(routingKey, summary, body, severity string) map[string]interface{} {
	return map[string]interface{}{
		"routing_key":  strings.TrimSpace(routingKey),
		"event_action": "trigger",
		"payload": map[string]interface{}{
			"summary":  strings.TrimSpace(summary),
			"source":   "ssh-proxy-core",
			"severity": severity,
			"custom_details": map[string]string{
				"body": strings.TrimSpace(body),
			},
		},
	}
}

func renderOpsgeniePayload(subject, body, priority string) map[string]interface{} {
	return map[string]interface{}{
		"message":     strings.TrimSpace(subject),
		"description": strings.TrimSpace(body),
		"priority":    priority,
		"details": map[string]string{
			"source": "ssh-proxy-core",
		},
	}
}

func pagerDutySeverityForEvent(event *JITEvent) string {
	if event == nil {
		return "warning"
	}
	switch event.Type {
	case "request_break_glass":
		return "critical"
	case "request_denied", "request_revoked":
		return "warning"
	default:
		return "info"
	}
}

func pagerDutySeverityForMessage(subject string) string {
	if strings.Contains(strings.ToLower(subject), "break-glass") {
		return "critical"
	}
	return "warning"
}

func opsgeniePriorityForEvent(event *JITEvent) string {
	if event == nil {
		return "P3"
	}
	switch event.Type {
	case "request_break_glass":
		return "P1"
	case "request_denied", "request_revoked":
		return "P2"
	default:
		return "P4"
	}
}

func opsgeniePriorityForMessage(subject string) string {
	if strings.Contains(strings.ToLower(subject), "break-glass") {
		return "P1"
	}
	return "P3"
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
