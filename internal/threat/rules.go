package threat

import (
	"regexp"
	"time"
)

// RuleType classifies how a detection rule evaluates events.
type RuleType string

const (
	RuleThreshold RuleType = "threshold" // count exceeds threshold in window
	RuleAnomaly   RuleType = "anomaly"   // deviation from baseline
	RulePattern   RuleType = "pattern"   // regex/keyword match
	RuleSequence  RuleType = "sequence"  // ordered sequence of events
)

// Rule describes a single detection rule.
type Rule struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Type        RuleType       `json:"type"`
	Severity    Severity       `json:"severity"`
	Enabled     bool           `json:"enabled"`
	Conditions  RuleConditions `json:"conditions"`
	compiled    *regexp.Regexp // pre-compiled pattern
}

// RuleConditions holds the parameters that control when a rule fires.
type RuleConditions struct {
	EventTypes []string      `json:"event_types,omitempty"`
	Threshold  int           `json:"threshold,omitempty"`
	Window     time.Duration `json:"window,omitempty"`
	Pattern    string        `json:"pattern,omitempty"`
	Field      string        `json:"field,omitempty"`
	Sequence   []string      `json:"sequence,omitempty"`
	GroupBy    string        `json:"group_by,omitempty"`
}

// Event is the input to the threat detection engine.
type Event struct {
	Timestamp time.Time              `json:"timestamp"`
	Type      string                 `json:"type"`
	Username  string                 `json:"username"`
	SourceIP  string                 `json:"source_ip"`
	Target    string                 `json:"target"`
	Details   map[string]interface{} `json:"details"`
}

// compilePattern pre-compiles the regex pattern for pattern-type rules.
func (r *Rule) compilePattern() {
	if r.Conditions.Pattern != "" {
		if re, err := regexp.Compile(r.Conditions.Pattern); err == nil {
			r.compiled = re
		}
	}
}

// matchesEventType returns true if the event type matches any of the rule's event type filters.
// An empty filter list matches everything.
func (r *Rule) matchesEventType(eventType string) bool {
	if len(r.Conditions.EventTypes) == 0 {
		return true
	}
	for _, et := range r.Conditions.EventTypes {
		if et == eventType {
			return true
		}
	}
	return false
}

// DefaultRules returns the built-in detection rules.
func DefaultRules() []*Rule {
	rules := []*Rule{
		{
			ID:          "brute_force",
			Name:        "Brute Force Attack",
			Description: "More than 10 authentication failures from the same IP within 5 minutes",
			Type:        RuleThreshold,
			Severity:    SeverityHigh,
			Enabled:     true,
			Conditions: RuleConditions{
				EventTypes: []string{"auth_failure"},
				Threshold:  10,
				Window:     5 * time.Minute,
				GroupBy:    "source_ip",
			},
		},
		{
			ID:          "credential_stuffing",
			Name:        "Credential Stuffing",
			Description: "More than 5 authentication failures for different users from the same IP within 10 minutes",
			Type:        RuleThreshold,
			Severity:    SeverityHigh,
			Enabled:     true,
			Conditions: RuleConditions{
				EventTypes: []string{"auth_failure"},
				Threshold:  5,
				Window:     10 * time.Minute,
				GroupBy:    "source_ip",
				Field:      "username",
			},
		},
		{
			ID:          "impossible_travel",
			Name:        "Impossible Travel",
			Description: "Same user connects from geographically distant IPs in a short time",
			Type:        RuleAnomaly,
			Severity:    SeverityMedium,
			Enabled:     true,
			Conditions: RuleConditions{
				EventTypes: []string{"auth_success", "connection"},
				Window:     30 * time.Minute,
				GroupBy:    "username",
			},
		},
		{
			ID:          "off_hours_access",
			Name:        "Off-Hours Access",
			Description: "Access outside business hours (before 06:00 or after 22:00 UTC)",
			Type:        RulePattern,
			Severity:    SeverityLow,
			Enabled:     true,
			Conditions: RuleConditions{
				EventTypes: []string{"auth_success", "connection"},
				Pattern:    "off_hours",
				Field:      "timestamp",
			},
		},
		{
			ID:          "suspicious_command",
			Name:        "Suspicious Command",
			Description: "Command matching dangerous patterns (rm -rf, chmod 777, wget/curl to external, etc.)",
			Type:        RulePattern,
			Severity:    SeverityHigh,
			Enabled:     true,
			Conditions: RuleConditions{
				EventTypes: []string{"command"},
				Pattern:    `(?i)(rm\s+(-[a-z]*f[a-z]*\s+)?/|chmod\s+777|mkfs\.|dd\s+if=|wget\s+|curl\s+.*\|.*sh|>\s*/dev/sd|nc\s+-[a-z]*l|ncat\s|/etc/shadow|/etc/passwd)`,
				Field:      "command",
			},
		},
		{
			ID:          "privilege_escalation",
			Name:        "Privilege Escalation",
			Description: "Use of sudo, su, or passwd commands",
			Type:        RulePattern,
			Severity:    SeverityMedium,
			Enabled:     true,
			Conditions: RuleConditions{
				EventTypes: []string{"command"},
				Pattern:    `(?i)^(sudo\s|su\s|su$|passwd)`,
				Field:      "command",
			},
		},
		{
			ID:          "data_exfiltration",
			Name:        "Data Exfiltration",
			Description: "Large data transfer (>100MB) in a single session",
			Type:        RuleThreshold,
			Severity:    SeverityMedium,
			Enabled:     true,
			Conditions: RuleConditions{
				EventTypes: []string{"data_transfer"},
				Threshold:  100 * 1024 * 1024, // 100 MB in bytes
				Field:      "bytes_transferred",
				GroupBy:    "username",
			},
		},
		{
			ID:          "lateral_movement",
			Name:        "Lateral Movement",
			Description: "SSH connections to multiple hosts in a short time",
			Type:        RuleSequence,
			Severity:    SeverityMedium,
			Enabled:     true,
			Conditions: RuleConditions{
				EventTypes: []string{"connection"},
				Threshold:  3, // 3 or more distinct targets
				Window:     15 * time.Minute,
				GroupBy:    "username",
				Field:      "target",
			},
		},
		{
			ID:          "account_compromise",
			Name:        "Account Compromise",
			Description: "Auth failure followed by successful auth then suspicious command",
			Type:        RuleSequence,
			Severity:    SeverityCritical,
			Enabled:     true,
			Conditions: RuleConditions{
				Sequence: []string{"auth_failure", "auth_success", "command"},
				Window:   30 * time.Minute,
				GroupBy:  "username",
			},
		},
		{
			ID:          "session_anomaly",
			Name:        "Session Anomaly",
			Description: "Unusually long session or access at an unusual time",
			Type:        RuleAnomaly,
			Severity:    SeverityLow,
			Enabled:     true,
			Conditions: RuleConditions{
				EventTypes: []string{"session_end"},
				Field:      "duration",
				Threshold:  28800, // 8 hours in seconds
				GroupBy:    "username",
			},
		},
	}
	for _, r := range rules {
		r.compilePattern()
	}
	return rules
}
