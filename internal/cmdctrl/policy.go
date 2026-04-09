package cmdctrl

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
)

// ActionType defines what happens when a command matches a rule.
type ActionType string

const (
	ActionAllow   ActionType = "allow"
	ActionDeny    ActionType = "deny"
	ActionAudit   ActionType = "audit"   // allow but flag for review
	ActionApprove ActionType = "approve" // require real-time approval
	ActionRewrite ActionType = "rewrite" // allow with command substitution
)

// CommandRule defines a pattern-based command control rule.
type CommandRule struct {
	ID       string     `json:"id"`
	Name     string     `json:"name"`
	Pattern  string     `json:"pattern"`
	Action   ActionType `json:"action"`
	Rewrite  string     `json:"rewrite,omitempty"`
	Severity string     `json:"severity"`
	Message  string     `json:"message"`
	Roles    []string   `json:"roles"`
	Targets  []string   `json:"targets"`
	Enabled  bool       `json:"enabled"`
	compiled *regexp.Regexp
}

// Decision is the result of evaluating a command against the policy engine.
type Decision struct {
	Action           ActionType   `json:"action"`
	Rule             *CommandRule `json:"rule,omitempty"`
	Message          string       `json:"message"`
	RewrittenCommand string       `json:"rewritten_command,omitempty"`
}

// PolicyEngine evaluates commands against an ordered list of rules.
type PolicyEngine struct {
	rules   []*CommandRule
	mu      sync.RWMutex
	dataDir string
}

// NewPolicyEngine creates a new PolicyEngine backed by the given data directory.
func NewPolicyEngine(dataDir string) *PolicyEngine {
	return &PolicyEngine{
		rules:   make([]*CommandRule, 0),
		dataDir: dataDir,
	}
}

func (pe *PolicyEngine) rulesPath() string {
	return pe.dataDir + "/cmdctrl_rules.json"
}

// LoadRules loads rules from the JSON file on disk.
func (pe *PolicyEngine) LoadRules() error {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	data, err := os.ReadFile(pe.rulesPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read rules file: %w", err)
	}

	var rules []*CommandRule
	if err := json.Unmarshal(data, &rules); err != nil {
		return fmt.Errorf("failed to parse rules file: %w", err)
	}

	for _, r := range rules {
		compiled, err := regexp.Compile(r.Pattern)
		if err != nil {
			return fmt.Errorf("invalid regex in rule %s: %w", r.ID, err)
		}
		r.compiled = compiled
	}

	pe.rules = rules
	return nil
}

// SaveRules persists the current rules to disk as JSON.
func (pe *PolicyEngine) SaveRules() error {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	data, err := json.MarshalIndent(pe.rules, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal rules: %w", err)
	}

	if err := os.MkdirAll(pe.dataDir, 0o755); err != nil {
		return fmt.Errorf("failed to create data directory: %w", err)
	}

	return os.WriteFile(pe.rulesPath(), data, 0o644)
}

// Evaluate checks a command against all enabled rules. First match wins.
// If no rule matches, the command is allowed.
func (pe *PolicyEngine) Evaluate(cmd, username, role, target string) *Decision {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	for _, r := range pe.rules {
		if !r.Enabled {
			continue
		}
		if !matchesRoles(r.Roles, role) {
			continue
		}
		if !matchesTargets(r.Targets, target) {
			continue
		}
		if r.compiled != nil && r.compiled.MatchString(cmd) {
			decision := &Decision{
				Action:  r.Action,
				Rule:    r,
				Message: r.Message,
			}
			if r.Action == ActionRewrite {
				decision.RewrittenCommand = rewriteCommand(r.Rewrite, cmd, username, role, target)
			}
			return decision
		}
	}

	return &Decision{
		Action:  ActionAllow,
		Message: "no matching rule, command allowed",
	}
}

// AddRule appends a new rule after validating and compiling it.
func (pe *PolicyEngine) AddRule(rule *CommandRule) error {
	if rule.ID == "" {
		return fmt.Errorf("rule ID is required")
	}
	if rule.Pattern == "" {
		return fmt.Errorf("rule pattern is required")
	}
	if rule.Action == ActionRewrite && rule.Rewrite == "" {
		return fmt.Errorf("rewrite action requires rewrite template")
	}

	compiled, err := regexp.Compile(rule.Pattern)
	if err != nil {
		return fmt.Errorf("invalid regex pattern: %w", err)
	}

	pe.mu.Lock()
	defer pe.mu.Unlock()

	for _, existing := range pe.rules {
		if existing.ID == rule.ID {
			return fmt.Errorf("rule with ID %s already exists", rule.ID)
		}
	}

	rule.compiled = compiled
	pe.rules = append(pe.rules, rule)
	return nil
}

// UpdateRule replaces an existing rule by ID.
func (pe *PolicyEngine) UpdateRule(id string, rule *CommandRule) error {
	if rule.Pattern == "" {
		return fmt.Errorf("rule pattern is required")
	}
	if rule.Action == ActionRewrite && rule.Rewrite == "" {
		return fmt.Errorf("rewrite action requires rewrite template")
	}

	compiled, err := regexp.Compile(rule.Pattern)
	if err != nil {
		return fmt.Errorf("invalid regex pattern: %w", err)
	}

	pe.mu.Lock()
	defer pe.mu.Unlock()

	for i, existing := range pe.rules {
		if existing.ID == id {
			rule.ID = id
			rule.compiled = compiled
			pe.rules[i] = rule
			return nil
		}
	}

	return fmt.Errorf("rule %s not found", id)
}

// DeleteRule removes a rule by ID.
func (pe *PolicyEngine) DeleteRule(id string) error {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	for i, r := range pe.rules {
		if r.ID == id {
			pe.rules = append(pe.rules[:i], pe.rules[i+1:]...)
			return nil
		}
	}

	return fmt.Errorf("rule %s not found", id)
}

// GetRule returns a single rule by ID.
func (pe *PolicyEngine) GetRule(id string) (*CommandRule, error) {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	for _, r := range pe.rules {
		if r.ID == id {
			return r, nil
		}
	}

	return nil, fmt.Errorf("rule %s not found", id)
}

// ListRules returns a copy of all rules.
func (pe *PolicyEngine) ListRules() []*CommandRule {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	out := make([]*CommandRule, len(pe.rules))
	copy(out, pe.rules)
	return out
}

// matchesRoles returns true if the rule applies to the given role.
// An empty roles list means the rule applies to all roles.
func matchesRoles(ruleRoles []string, role string) bool {
	if len(ruleRoles) == 0 {
		return true
	}
	for _, r := range ruleRoles {
		if r == role {
			return true
		}
	}
	return false
}

// matchesTargets returns true if the rule applies to the given target.
// An empty targets list means the rule applies to all targets.
func matchesTargets(ruleTargets []string, target string) bool {
	if len(ruleTargets) == 0 {
		return true
	}
	for _, t := range ruleTargets {
		if t == target {
			return true
		}
	}
	return false
}

func rewriteCommand(template, cmd, username, role, target string) string {
	if template == "" {
		return cmd
	}
	replacer := strings.NewReplacer(
		"{{command}}", cmd,
		"{{username}}", username,
		"{{role}}", role,
		"{{target}}", target,
	)
	return replacer.Replace(template)
}
