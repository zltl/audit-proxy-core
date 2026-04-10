package api

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"strings"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/jit"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/models"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/threat"
)

// ThreatResponseConfig controls how automatic response reacts to fresh threat alerts.
type ThreatResponseConfig struct {
	Enabled       bool
	BlockSourceIP bool
	KillSessions  bool
	Notify        bool
	MinSeverity   threat.Severity
}

func normalizeThreatResponseConfig(cfg ThreatResponseConfig) ThreatResponseConfig {
	if cfg.MinSeverity == "" {
		cfg.MinSeverity = threat.SeverityHigh
	}
	if cfg.Enabled && !cfg.BlockSourceIP && !cfg.KillSessions && !cfg.Notify {
		cfg.BlockSourceIP = true
		cfg.KillSessions = true
		cfg.Notify = true
	}
	return cfg
}

// StartThreatResponseLoop consumes newly raised threat alerts and executes the
// configured response actions.
func (a *API) StartThreatResponseLoop(ctx context.Context, detector *threat.Detector, cfg ThreatResponseConfig, notifier *jit.Notifier) {
	if a == nil || detector == nil || ctx == nil {
		return
	}
	cfg = normalizeThreatResponseConfig(cfg)
	if !cfg.Enabled || (!cfg.BlockSourceIP && !cfg.KillSessions && !cfg.Notify) {
		return
	}

	alerts := detector.AlertChannel()
	a.threatResponseOnce.Do(func() {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case alert, ok := <-alerts:
					if !ok {
						return
					}
					a.handleThreatAlert(ctx, alert, cfg, notifier)
				}
			}
		}()
	})
}

func (a *API) handleThreatAlert(parent context.Context, alert *threat.Alert, cfg ThreatResponseConfig, notifier *jit.Notifier) {
	if a == nil || alert == nil {
		return
	}
	cfg = normalizeThreatResponseConfig(cfg)
	if !cfg.Enabled || !threatSeverityAtLeast(alert.Severity, cfg.MinSeverity) {
		return
	}

	actions := make([]string, 0, 3)
	failures := make([]string, 0, 3)

	if cfg.BlockSourceIP {
		added, err := a.blockThreatSourceIP(alert)
		if added {
			actions = append(actions, "blocked source IP "+normalizeThreatSourceIP(alert.SourceIP))
		}
		if err != nil {
			failures = append(failures, "block source IP: "+err.Error())
		}
	}

	if cfg.KillSessions {
		killed, err := a.killThreatSessions(alert)
		if err != nil {
			failures = append(failures, "terminate sessions: "+err.Error())
		}
		if len(killed) > 0 {
			actions = append(actions, "terminated sessions "+strings.Join(killed, ", "))
		}
	}

	if len(actions) > 0 {
		log.Printf("api: threat response alert=%s actions=%s", alert.ID, strings.Join(actions, "; "))
	}
	if len(failures) > 0 {
		log.Printf("api: threat response alert=%s errors=%s", alert.ID, strings.Join(failures, "; "))
	}

	if cfg.Notify && notifier != nil {
		ctx, cancel := context.WithTimeout(parent, 10*time.Second)
		defer cancel()
		subject, body := renderThreatResponseNotification(alert, actions, failures)
		if err := notifier.NotifyMessage(ctx, subject, body); err != nil {
			log.Printf("api: threat response notify alert=%s: %v", alert.ID, err)
		}
	}
}

func (a *API) blockThreatSourceIP(alert *threat.Alert) (bool, error) {
	if a == nil || alert == nil {
		return false, nil
	}
	if a.cluster != nil && !a.cluster.IsLeader() {
		return false, fmt.Errorf("configuration changes must be submitted to the cluster leader")
	}

	sourceIP := normalizeThreatSourceIP(alert.SourceIP)
	if sourceIP == "" {
		return false, nil
	}
	denyRule, err := exactDenyRuleForIP(sourceIP)
	if err != nil {
		return false, err
	}

	current, ok := a.loadCurrentConfigDocument().(map[string]interface{})
	if !ok || current == nil {
		return false, fmt.Errorf("failed to load current config")
	}
	rules := configStringList(current["ip_acl_rules"])
	for _, rule := range rules {
		if strings.EqualFold(strings.TrimSpace(rule), denyRule) {
			return false, nil
		}
	}

	current["ip_acl_rules"] = strings.Join(append([]string{denyRule}, rules...), ", ")
	if value := current["ip_acl_mode"]; value == nil || strings.TrimSpace(fmt.Sprint(value)) == "" || fmt.Sprint(value) == "<nil>" {
		current["ip_acl_mode"] = "blacklist"
	}
	current = a.prepareConfigDocument(current)
	if err := a.applyConfigDocument(current); err != nil {
		return false, err
	}
	if err := a.publishCurrentConfigClusterWide("", "threat-response"); err != nil {
		return true, err
	}
	return true, nil
}

func (a *API) killThreatSessions(alert *threat.Alert) ([]string, error) {
	if a == nil || alert == nil {
		return nil, nil
	}
	sessions, err := a.dp.ListSessions()
	if err != nil {
		return nil, err
	}
	sessions = append([]models.Session(nil), sessions...)

	killed := make([]string, 0)
	errs := make([]error, 0)
	for _, session := range sessions {
		if !sessionMatchesThreatAlert(session, alert) {
			continue
		}
		if err := a.dp.KillSession(session.ID); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", session.ID, err))
			continue
		}
		killed = append(killed, session.ID)
	}
	return killed, errors.Join(errs...)
}

func sessionMatchesThreatAlert(session models.Session, alert *threat.Alert) bool {
	if alert == nil || !strings.EqualFold(session.Status, "active") {
		return false
	}

	hasScope := false
	if username := strings.TrimSpace(alert.Username); username != "" {
		hasScope = true
		if session.Username != username {
			return false
		}
	}
	if sourceIP := normalizeThreatSourceIP(alert.SourceIP); sourceIP != "" {
		hasScope = true
		if normalizeThreatSourceIP(session.SourceIP) != sourceIP {
			return false
		}
	}
	if target := strings.TrimSpace(alert.Target); target != "" {
		hasScope = true
		if session.TargetHost != target {
			return false
		}
	}
	return hasScope
}

func exactDenyRuleForIP(raw string) (string, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("invalid source_ip %q", raw)
	}
	bits := 32
	if addr.Is6() {
		bits = 128
	}
	return netip.PrefixFrom(addr, bits).String() + ":deny", nil
}

func threatSeverityAtLeast(actual, minimum threat.Severity) bool {
	return threatSeverityRank(actual) >= threatSeverityRank(minimum)
}

func threatSeverityRank(value threat.Severity) int {
	switch strings.ToLower(strings.TrimSpace(string(value))) {
	case string(threat.SeverityLow):
		return 1
	case string(threat.SeverityMedium):
		return 2
	case string(threat.SeverityHigh):
		return 3
	case string(threat.SeverityCritical):
		return 4
	default:
		return 0
	}
}

func renderThreatResponseNotification(alert *threat.Alert, actions, failures []string) (string, string) {
	if alert == nil {
		return "[SSH Proxy] Threat response", "Threat response executed."
	}
	ruleName := strings.TrimSpace(alert.RuleName)
	if ruleName == "" {
		ruleName = strings.TrimSpace(alert.RuleID)
	}
	if ruleName == "" {
		ruleName = "threat alert"
	}

	subject := fmt.Sprintf("[SSH Proxy] Threat response for %s", ruleName)
	lines := []string{
		subject,
		"",
		"Alert ID: " + defaultThreatField(alert.ID, "n/a"),
		"Rule: " + ruleName,
		"Severity: " + defaultThreatField(string(alert.Severity), "unknown"),
	}
	if alert.Username != "" {
		lines = append(lines, "Username: "+alert.Username)
	}
	if alert.SourceIP != "" {
		lines = append(lines, "Source IP: "+normalizeThreatSourceIP(alert.SourceIP))
	}
	if alert.Target != "" {
		lines = append(lines, "Target: "+alert.Target)
	}
	if alert.Description != "" {
		lines = append(lines, "Description: "+alert.Description)
	}
	if len(alert.Evidence) > 0 {
		lines = append(lines, "Evidence: "+strings.Join(alert.Evidence, "; "))
	}
	if !alert.CreatedAt.IsZero() {
		lines = append(lines, "Created At: "+alert.CreatedAt.UTC().Format(time.RFC3339))
	}
	if len(actions) > 0 {
		lines = append(lines, "", "Actions:")
		for _, action := range actions {
			lines = append(lines, "- "+action)
		}
	}
	if len(failures) > 0 {
		lines = append(lines, "", "Errors:")
		for _, failure := range failures {
			lines = append(lines, "- "+failure)
		}
	}
	if len(actions) == 0 && len(failures) == 0 {
		lines = append(lines, "", "No automatic action was required.")
	}
	return subject, strings.Join(lines, "\n")
}

func defaultThreatField(value, fallback string) string {
	if strings.TrimSpace(value) != "" {
		return value
	}
	return fallback
}
