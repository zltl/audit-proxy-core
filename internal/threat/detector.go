package threat

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Severity classifies the impact level of a threat alert.
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// AlertStatus tracks the lifecycle state of an alert.
type AlertStatus string

const (
	AlertActive        AlertStatus = "active"
	AlertAcknowledged  AlertStatus = "acknowledged"
	AlertResolved      AlertStatus = "resolved"
	AlertFalsePositive AlertStatus = "false_positive"
)

// Alert represents a single threat detection alert.
type Alert struct {
	ID          string      `json:"id"`
	RuleID      string      `json:"rule_id"`
	RuleName    string      `json:"rule_name"`
	Severity    Severity    `json:"severity"`
	Status      AlertStatus `json:"status"`
	Username    string      `json:"username,omitempty"`
	SourceIP    string      `json:"source_ip,omitempty"`
	Target      string      `json:"target,omitempty"`
	Description string      `json:"description"`
	Evidence    []string    `json:"evidence"`
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
	AckedBy     string      `json:"acked_by,omitempty"`
}

// AlertFilter defines criteria for querying alerts.
type AlertFilter struct {
	Severity Severity    `json:"severity,omitempty"`
	Status   AlertStatus `json:"status,omitempty"`
	Username string      `json:"username,omitempty"`
	SourceIP string      `json:"source_ip,omitempty"`
	RuleID   string      `json:"rule_id,omitempty"`
}

// DetectorConfig controls the behavior of the threat detection engine.
type DetectorConfig struct {
	Enabled          bool
	AlertRetention   time.Duration
	MaxAlertsPerRule int
	WebhookURL       string
	DataDir          string
	// SuppressionWindow is how long to suppress duplicate alerts for the same
	// rule + grouping key. Default: 10 minutes.
	SuppressionWindow time.Duration
	// BusinessHourStart and BusinessHourEnd define "normal" hours in UTC (0-23).
	BusinessHourStart int
	BusinessHourEnd   int
}

func (c *DetectorConfig) defaults() {
	if c.AlertRetention == 0 {
		c.AlertRetention = 30 * 24 * time.Hour
	}
	if c.MaxAlertsPerRule == 0 {
		c.MaxAlertsPerRule = 100
	}
	if c.SuppressionWindow == 0 {
		c.SuppressionWindow = 10 * time.Minute
	}
	if c.BusinessHourStart == 0 && c.BusinessHourEnd == 0 {
		c.BusinessHourStart = 6
		c.BusinessHourEnd = 22
	}
}

// Detector is the behavioural threat detection engine.
type Detector struct {
	rules       []*Rule
	alerts      map[string]*Alert
	mu          sync.RWMutex
	trackers    map[string]*behaviorTracker
	config      *DetectorConfig
	alertCh     chan *Alert
	stopCh      chan struct{}
	suppression map[string]time.Time // ruleID:groupKey → last alert time
}

// NewDetector creates a new threat detection engine.
func NewDetector(cfg *DetectorConfig) *Detector {
	if cfg == nil {
		cfg = &DetectorConfig{Enabled: true}
	}
	cfg.defaults()
	d := &Detector{
		rules:       DefaultRules(),
		alerts:      make(map[string]*Alert),
		trackers:    make(map[string]*behaviorTracker),
		config:      cfg,
		alertCh:     make(chan *Alert, 256),
		stopCh:      make(chan struct{}),
		suppression: make(map[string]time.Time),
	}
	if cfg.DataDir != "" {
		d.loadAlerts()
	}
	return d
}

// Start begins background maintenance (alert cleanup).
func (d *Detector) Start(ctx context.Context) error {
	go d.maintenanceLoop(ctx)
	return nil
}

// Stop shuts down the detector and persists state.
func (d *Detector) Stop() error {
	close(d.stopCh)
	if d.config.DataDir != "" {
		return d.persistAlerts()
	}
	return nil
}

// AlertChannel returns a read-only channel that receives new alerts.
func (d *Detector) AlertChannel() <-chan *Alert {
	return d.alertCh
}

// ProcessEvent evaluates an event against all enabled rules and returns any alerts generated.
func (d *Detector) ProcessEvent(event *Event) []*Alert {
	if !d.config.Enabled {
		return nil
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	// Record event in per-group trackers.
	d.recordEvent(event)

	var alerts []*Alert
	for _, rule := range d.rules {
		if !rule.Enabled {
			continue
		}
		if !rule.matchesEventType(event.Type) {
			continue
		}
		if alert := d.evaluate(rule, event); alert != nil {
			alerts = append(alerts, alert)
		}
	}
	return alerts
}

// GetAlerts returns alerts matching the given filter.
func (d *Detector) GetAlerts(filter AlertFilter) []*Alert {
	d.mu.RLock()
	defer d.mu.RUnlock()
	var result []*Alert
	for _, a := range d.alerts {
		if filter.Severity != "" && a.Severity != filter.Severity {
			continue
		}
		if filter.Status != "" && a.Status != filter.Status {
			continue
		}
		if filter.Username != "" && a.Username != filter.Username {
			continue
		}
		if filter.SourceIP != "" && a.SourceIP != filter.SourceIP {
			continue
		}
		if filter.RuleID != "" && a.RuleID != filter.RuleID {
			continue
		}
		result = append(result, a)
	}
	return result
}

// GetAlert returns a single alert by ID.
func (d *Detector) GetAlert(id string) (*Alert, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	a, ok := d.alerts[id]
	if !ok {
		return nil, fmt.Errorf("alert not found: %s", id)
	}
	return a, nil
}

// AcknowledgeAlert marks an alert as acknowledged.
func (d *Detector) AcknowledgeAlert(id, user string) error {
	return d.updateAlertStatus(id, AlertAcknowledged, user)
}

// ResolveAlert marks an alert as resolved.
func (d *Detector) ResolveAlert(id, user string) error {
	return d.updateAlertStatus(id, AlertResolved, user)
}

// MarkFalsePositive marks an alert as a false positive.
func (d *Detector) MarkFalsePositive(id, user string) error {
	return d.updateAlertStatus(id, AlertFalsePositive, user)
}

// Rules returns the current set of rules (read-only view).
func (d *Detector) Rules() []*Rule {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]*Rule, len(d.rules))
	copy(out, d.rules)
	return out
}

// UpdateRule modifies a rule by ID. Only Enabled, Conditions.Threshold,
// Conditions.Window, and Conditions.Pattern may be changed.
func (d *Detector) UpdateRule(id string, enabled *bool, threshold *int, window *time.Duration, pattern *string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, r := range d.rules {
		if r.ID == id {
			if enabled != nil {
				r.Enabled = *enabled
			}
			if threshold != nil {
				r.Conditions.Threshold = *threshold
			}
			if window != nil {
				r.Conditions.Window = *window
			}
			if pattern != nil {
				r.Conditions.Pattern = *pattern
				r.compilePattern()
			}
			return nil
		}
	}
	return fmt.Errorf("rule not found: %s", id)
}

// Stats returns aggregate threat statistics.
func (d *Detector) Stats() map[string]interface{} {
	d.mu.RLock()
	defer d.mu.RUnlock()
	bySeverity := map[Severity]int{
		SeverityLow: 0, SeverityMedium: 0,
		SeverityHigh: 0, SeverityCritical: 0,
	}
	byStatus := map[AlertStatus]int{
		AlertActive: 0, AlertAcknowledged: 0,
		AlertResolved: 0, AlertFalsePositive: 0,
	}
	byRule := make(map[string]int)
	for _, a := range d.alerts {
		bySeverity[a.Severity]++
		byStatus[a.Status]++
		byRule[a.RuleID]++
	}
	// Top rules by alert count.
	type ruleCount struct {
		RuleID string `json:"rule_id"`
		Count  int    `json:"count"`
	}
	var topRules []ruleCount
	for rid, c := range byRule {
		topRules = append(topRules, ruleCount{RuleID: rid, Count: c})
	}
	// Simple sort.
	for i := 0; i < len(topRules); i++ {
		for j := i + 1; j < len(topRules); j++ {
			if topRules[j].Count > topRules[i].Count {
				topRules[i], topRules[j] = topRules[j], topRules[i]
			}
		}
	}
	if len(topRules) > 10 {
		topRules = topRules[:10]
	}
	return map[string]interface{}{
		"total_alerts": len(d.alerts),
		"by_severity":  bySeverity,
		"by_status":    byStatus,
		"top_rules":    topRules,
		"rules_count":  len(d.rules),
	}
}

// --- internal helpers ---

func (d *Detector) recordEvent(event *Event) {
	// Determine tracker keys based on groupBy usage across rules.
	keys := make(map[string]struct{})
	if event.SourceIP != "" {
		keys["ip:"+event.SourceIP] = struct{}{}
	}
	if event.Username != "" {
		keys["user:"+event.Username] = struct{}{}
	}

	te := trackedEvent{
		Timestamp: event.Timestamp,
		Type:      event.Type,
		SourceIP:  event.SourceIP,
		Target:    event.Target,
		Username:  event.Username,
		Details:   event.Details,
	}

	d.mu.Lock()
	for key := range keys {
		bt, ok := d.trackers[key]
		if !ok {
			bt = newBehaviorTracker(10000)
			d.trackers[key] = bt
		}
		bt.Add(te)
	}
	d.mu.Unlock()
}

func (d *Detector) trackerFor(groupBy, event_username, event_ip string) *behaviorTracker {
	var key string
	switch groupBy {
	case "source_ip":
		key = "ip:" + event_ip
	default:
		key = "user:" + event_username
	}
	d.mu.RLock()
	bt := d.trackers[key]
	d.mu.RUnlock()
	return bt
}

func (d *Detector) evaluate(rule *Rule, event *Event) *Alert {
	switch rule.Type {
	case RuleThreshold:
		return d.evalThreshold(rule, event)
	case RulePattern:
		return d.evalPattern(rule, event)
	case RuleAnomaly:
		return d.evalAnomaly(rule, event)
	case RuleSequence:
		return d.evalSequence(rule, event)
	}
	return nil
}

func (d *Detector) evalThreshold(rule *Rule, event *Event) *Alert {
	bt := d.trackerFor(rule.Conditions.GroupBy, event.Username, event.SourceIP)
	if bt == nil {
		return nil
	}

	switch rule.ID {
	case "credential_stuffing":
		// Count unique usernames with auth_failure from this IP.
		uniqueUsers := bt.UniqueValuesInWindow("username", rule.Conditions.Window)
		// Only count users that had auth_failure events.
		failUsers := 0
		events := bt.EventsInWindow(rule.Conditions.Window)
		seen := make(map[string]struct{})
		for _, e := range events {
			if e.Type == "auth_failure" {
				if _, ok := seen[e.Username]; !ok {
					seen[e.Username] = struct{}{}
					failUsers++
				}
			}
		}
		_ = uniqueUsers
		if failUsers <= rule.Conditions.Threshold {
			return nil
		}
		return d.createAlert(rule, event, fmt.Sprintf(
			"%d unique users failed auth from IP %s in %v",
			failUsers, event.SourceIP, rule.Conditions.Window))

	case "data_exfiltration":
		// Check bytes_transferred in event details.
		if event.Details == nil {
			return nil
		}
		bytes, ok := toFloat64(event.Details["bytes_transferred"])
		if !ok {
			return nil
		}
		if int(bytes) <= rule.Conditions.Threshold {
			return nil
		}
		return d.createAlert(rule, event, fmt.Sprintf(
			"Data transfer of %.0f bytes exceeds threshold of %d bytes",
			bytes, rule.Conditions.Threshold))

	default:
		// Generic threshold: count events of matching type in window.
		count := bt.CountInWindow(event.Type, rule.Conditions.Window)
		if count <= rule.Conditions.Threshold {
			return nil
		}
		return d.createAlert(rule, event, fmt.Sprintf(
			"%d events of type %q in %v (threshold: %d)",
			count, event.Type, rule.Conditions.Window, rule.Conditions.Threshold))
	}
}

func (d *Detector) evalPattern(rule *Rule, event *Event) *Alert {
	switch rule.ID {
	case "off_hours_access":
		hour := event.Timestamp.UTC().Hour()
		if hour >= d.config.BusinessHourStart && hour < d.config.BusinessHourEnd {
			return nil
		}
		return d.createAlert(rule, event, fmt.Sprintf(
			"Access at %s UTC (outside business hours %02d:00-%02d:00)",
			event.Timestamp.UTC().Format("15:04"), d.config.BusinessHourStart, d.config.BusinessHourEnd))

	default:
		if rule.compiled == nil {
			return nil
		}
		val := d.fieldValue(rule.Conditions.Field, event)
		if val == "" {
			return nil
		}
		if !rule.compiled.MatchString(val) {
			return nil
		}
		return d.createAlert(rule, event, fmt.Sprintf(
			"Pattern %q matched in field %q: %s",
			rule.Conditions.Pattern, rule.Conditions.Field, val))
	}
}

func (d *Detector) evalAnomaly(rule *Rule, event *Event) *Alert {
	switch rule.ID {
	case "impossible_travel":
		bt := d.trackerFor(rule.Conditions.GroupBy, event.Username, event.SourceIP)
		if bt == nil {
			return nil
		}
		ips := bt.UniqueValuesInWindow("source_ip", rule.Conditions.Window)
		if len(ips) < 2 {
			return nil
		}
		// Heuristic: compare /16 prefixes of IPs. Different prefixes ≈ different locations.
		prefixes := make(map[string]struct{})
		for _, ip := range ips {
			prefixes[ipPrefix(ip)] = struct{}{}
		}
		if len(prefixes) < 2 {
			return nil
		}
		return d.createAlert(rule, event, fmt.Sprintf(
			"User %q connected from %d distinct IP ranges in %v: %s",
			event.Username, len(prefixes), rule.Conditions.Window, strings.Join(ips, ", ")))

	case "session_anomaly":
		if event.Details == nil {
			return nil
		}
		dur, ok := toFloat64(event.Details["duration"])
		if !ok {
			return nil
		}
		if int(dur) <= rule.Conditions.Threshold {
			return nil
		}
		return d.createAlert(rule, event, fmt.Sprintf(
			"Session duration %.0fs exceeds threshold %ds", dur, rule.Conditions.Threshold))

	default:
		return nil
	}
}

func (d *Detector) evalSequence(rule *Rule, event *Event) *Alert {
	switch rule.ID {
	case "lateral_movement":
		bt := d.trackerFor(rule.Conditions.GroupBy, event.Username, event.SourceIP)
		if bt == nil {
			return nil
		}
		targets := bt.UniqueValuesInWindow("target", rule.Conditions.Window)
		if len(targets) < rule.Conditions.Threshold {
			return nil
		}
		return d.createAlert(rule, event, fmt.Sprintf(
			"User %q connected to %d hosts in %v: %s",
			event.Username, len(targets), rule.Conditions.Window, strings.Join(targets, ", ")))

	case "account_compromise":
		bt := d.trackerFor(rule.Conditions.GroupBy, event.Username, event.SourceIP)
		if bt == nil {
			return nil
		}
		if !bt.HasSequenceInWindow(rule.Conditions.Sequence, rule.Conditions.Window) {
			return nil
		}
		return d.createAlert(rule, event, fmt.Sprintf(
			"Account compromise pattern detected for user %q: auth_failure → auth_success → command",
			event.Username))

	default:
		return nil
	}
}

func (d *Detector) fieldValue(field string, event *Event) string {
	switch field {
	case "command":
		if event.Details != nil {
			if cmd, ok := event.Details["command"].(string); ok {
				return cmd
			}
		}
	case "username":
		return event.Username
	case "source_ip":
		return event.SourceIP
	case "target":
		return event.Target
	}
	return ""
}

func (d *Detector) createAlert(rule *Rule, event *Event, evidence string) *Alert {
	// Deduplication: suppress if we recently fired the same rule for the same group key.
	groupKey := d.groupKey(rule, event)
	suppKey := rule.ID + ":" + groupKey

	d.mu.Lock()
	defer d.mu.Unlock()

	if last, ok := d.suppression[suppKey]; ok {
		if time.Since(last) < d.config.SuppressionWindow {
			return nil
		}
	}

	// Check max alerts per rule.
	ruleAlertCount := 0
	for _, a := range d.alerts {
		if a.RuleID == rule.ID && a.Status == AlertActive {
			ruleAlertCount++
		}
	}
	if ruleAlertCount >= d.config.MaxAlertsPerRule {
		return nil
	}

	now := time.Now()
	alert := &Alert{
		ID:          generateID(),
		RuleID:      rule.ID,
		RuleName:    rule.Name,
		Severity:    rule.Severity,
		Status:      AlertActive,
		Username:    event.Username,
		SourceIP:    event.SourceIP,
		Target:      event.Target,
		Description: rule.Description,
		Evidence:    []string{evidence},
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	d.alerts[alert.ID] = alert
	d.suppression[suppKey] = now

	// Non-blocking send to the alert channel.
	select {
	case d.alertCh <- alert:
	default:
	}

	return alert
}

func (d *Detector) groupKey(rule *Rule, event *Event) string {
	switch rule.Conditions.GroupBy {
	case "source_ip":
		return event.SourceIP
	case "username":
		return event.Username
	default:
		return event.Username + ":" + event.SourceIP
	}
}

func (d *Detector) updateAlertStatus(id string, status AlertStatus, user string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	a, ok := d.alerts[id]
	if !ok {
		return fmt.Errorf("alert not found: %s", id)
	}
	a.Status = status
	a.UpdatedAt = time.Now()
	if user != "" {
		a.AckedBy = user
	}
	return nil
}

func (d *Detector) maintenanceLoop(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-d.stopCh:
			return
		case <-ticker.C:
			d.cleanup()
		}
	}
}

func (d *Detector) cleanup() {
	d.mu.Lock()
	defer d.mu.Unlock()
	cutoff := time.Now().Add(-d.config.AlertRetention)
	for id, a := range d.alerts {
		if a.CreatedAt.Before(cutoff) {
			delete(d.alerts, id)
		}
	}
	// Clean suppression entries.
	for key, t := range d.suppression {
		if time.Since(t) > d.config.SuppressionWindow*2 {
			delete(d.suppression, key)
		}
	}
	// Clean trackers.
	for _, bt := range d.trackers {
		bt.Cleanup(1 * time.Hour)
	}
}

func (d *Detector) persistAlerts() error {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.config.DataDir == "" {
		return nil
	}
	if err := os.MkdirAll(d.config.DataDir, 0o750); err != nil {
		return err
	}
	data, err := json.Marshal(d.alerts)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(d.config.DataDir, "threat_alerts.json"), data, 0o640)
}

func (d *Detector) loadAlerts() {
	path := filepath.Join(d.config.DataDir, "threat_alerts.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var alerts map[string]*Alert
	if err := json.Unmarshal(data, &alerts); err != nil {
		return
	}
	d.alerts = alerts
}

// --- utility functions ---

func generateID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fallback: use timestamp.
		return fmt.Sprintf("alert-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func ipPrefix(ip string) string {
	// Return the /16 prefix for IPv4 (first two octets).
	parts := strings.Split(ip, ".")
	if len(parts) >= 2 {
		return parts[0] + "." + parts[1]
	}
	// For IPv6 or other formats, use the first half.
	if idx := strings.LastIndex(ip, ":"); idx > 0 {
		return ip[:idx]
	}
	return ip
}

func toFloat64(v interface{}) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case int32:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	}
	return 0, false
}
