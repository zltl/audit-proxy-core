package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/jit"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/threat"
)

func TestThreatResponseAppliesActions(t *testing.T) {
	api, _, dp := setupTestAPI(t)

	var notificationBody string
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		notificationBody = string(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer webhook.Close()

	notifier, err := jit.NewNotifier(jit.NotifierConfig{
		SlackWebhookURL: webhook.URL,
	})
	if err != nil {
		t.Fatalf("NewNotifier() error = %v", err)
	}

	api.handleThreatAlert(context.Background(), &threat.Alert{
		ID:          "alert-1",
		RuleID:      "brute_force",
		RuleName:    "Brute Force Attack",
		Severity:    threat.SeverityHigh,
		Username:    "alice",
		SourceIP:    "10.0.0.1",
		Description: "Too many authentication failures",
		Evidence:    []string{"11 auth_failure events in 5m"},
		CreatedAt:   time.Now().UTC(),
	}, ThreatResponseConfig{
		Enabled:       true,
		BlockSourceIP: true,
		KillSessions:  true,
		Notify:        true,
		MinSeverity:   threat.SeverityHigh,
	}, notifier)

	if len(dp.sessions) != 1 || dp.sessions[0].ID != "s2" {
		t.Fatalf("sessions after response = %#v, want only s2 remaining", dp.sessions)
	}

	rawConfig, err := os.ReadFile(api.config.ConfigFile)
	if err != nil {
		t.Fatalf("ReadFile(config) error = %v", err)
	}
	var configDoc map[string]interface{}
	if err := json.Unmarshal(rawConfig, &configDoc); err != nil {
		t.Fatalf("Unmarshal(config) error = %v\n%s", err, string(rawConfig))
	}
	mode, ok := configDoc["ip_acl_mode"].(string)
	if !ok {
		t.Fatalf("ip_acl_mode missing from config: %#v", configDoc)
	}
	if got := strings.TrimSpace(mode); got != "blacklist" {
		t.Fatalf("ip_acl_mode = %q, want blacklist", got)
	}
	rules, ok := configDoc["ip_acl_rules"].(string)
	if !ok {
		t.Fatalf("ip_acl_rules missing from config: %#v", configDoc)
	}
	if !strings.Contains(rules, "10.0.0.1/32:deny") {
		t.Fatalf("ip_acl_rules = %q, want source deny rule", rules)
	}
	if !strings.Contains(notificationBody, "Brute Force Attack") {
		t.Fatalf("notification body = %s", notificationBody)
	}
	if !strings.Contains(notificationBody, "blocked source IP 10.0.0.1") {
		t.Fatalf("notification body missing block action: %s", notificationBody)
	}
	if !strings.Contains(notificationBody, "terminated sessions s1, s3") {
		t.Fatalf("notification body missing kill action: %s", notificationBody)
	}
}

func TestThreatResponseRespectsMinimumSeverity(t *testing.T) {
	api, _, dp := setupTestAPI(t)

	calls := 0
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))
	defer webhook.Close()

	notifier, err := jit.NewNotifier(jit.NotifierConfig{
		SlackWebhookURL: webhook.URL,
	})
	if err != nil {
		t.Fatalf("NewNotifier() error = %v", err)
	}

	api.handleThreatAlert(context.Background(), &threat.Alert{
		ID:        "alert-2",
		RuleID:    "custom-medium",
		RuleName:  "Medium severity test",
		Severity:  threat.SeverityMedium,
		Username:  "alice",
		SourceIP:  "10.0.0.1",
		CreatedAt: time.Now().UTC(),
	}, ThreatResponseConfig{
		Enabled:       true,
		BlockSourceIP: true,
		KillSessions:  true,
		Notify:        true,
		MinSeverity:   threat.SeverityHigh,
	}, notifier)

	if len(dp.sessions) != 3 {
		t.Fatalf("sessions after below-threshold response = %#v, want unchanged", dp.sessions)
	}
	rawConfig, err := os.ReadFile(api.config.ConfigFile)
	if err != nil {
		t.Fatalf("ReadFile(config) error = %v", err)
	}
	if strings.Contains(string(rawConfig), "ip_acl_rules") {
		t.Fatalf("config unexpectedly changed: %s", string(rawConfig))
	}
	if calls != 0 {
		t.Fatalf("notification calls = %d, want 0", calls)
	}
}
