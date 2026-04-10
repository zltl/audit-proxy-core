package threat

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type RuleUpdate struct {
	Enabled     *bool
	Threshold   *int
	Window      *time.Duration
	Pattern     *string
	Name        *string
	Description *string
	Severity    *Severity
	Expression  *RuleDSLExpr
}

type persistedRuleStore struct {
	CustomRules []*Rule                 `json:"custom_rules,omitempty"`
	Overrides   map[string]ruleOverride `json:"overrides,omitempty"`
}

type ruleOverride struct {
	Enabled     *bool     `json:"enabled,omitempty"`
	Threshold   *int      `json:"threshold,omitempty"`
	Window      string    `json:"window,omitempty"`
	Pattern     *string   `json:"pattern,omitempty"`
	Name        *string   `json:"name,omitempty"`
	Description *string   `json:"description,omitempty"`
	Severity    *Severity `json:"severity,omitempty"`
}

func cloneRule(rule *Rule) *Rule {
	if rule == nil {
		return nil
	}
	cloned := *rule
	cloned.Conditions.EventTypes = append([]string(nil), rule.Conditions.EventTypes...)
	cloned.Conditions.Sequence = append([]string(nil), rule.Conditions.Sequence...)
	cloned.Conditions.Expression = cloneRuleDSLExpr(rule.Conditions.Expression)
	cloned.compilePattern()
	return &cloned
}

func cloneRuleDSLExpr(expr *RuleDSLExpr) *RuleDSLExpr {
	if expr == nil {
		return nil
	}
	cloned := *expr
	if len(expr.Values) > 0 {
		cloned.Values = append([]interface{}(nil), expr.Values...)
	}
	if len(expr.Children) > 0 {
		cloned.Children = make([]*RuleDSLExpr, 0, len(expr.Children))
		for _, child := range expr.Children {
			cloned.Children = append(cloned.Children, cloneRuleDSLExpr(child))
		}
	}
	cloned.compile()
	return &cloned
}

func (d *Detector) UpdateRule(id string, enabled *bool, threshold *int, window *time.Duration, pattern *string) error {
	return d.UpdateRuleConfig(id, RuleUpdate{
		Enabled:   enabled,
		Threshold: threshold,
		Window:    window,
		Pattern:   pattern,
	})
}

func (d *Detector) UpdateRuleConfig(id string, update RuleUpdate) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, rule := range d.rules {
		if rule.ID != id {
			continue
		}
		if err := applyRuleUpdate(rule, update); err != nil {
			return err
		}
		if rule.Builtin {
			override := d.ruleOverrides[id]
			override.apply(update)
			d.ruleOverrides[id] = override
		}
		if d.config.DataDir != "" {
			return d.persistRulesLocked()
		}
		return nil
	}
	return fmt.Errorf("rule not found: %s", id)
}

func (d *Detector) CreateRule(rule *Rule) (*Rule, error) {
	if rule == nil {
		return nil, fmt.Errorf("rule is required")
	}
	cloned := cloneRule(rule)
	cloned.Builtin = false
	cloned.ID = normalizeRuleID(cloned.ID)
	if cloned.ID == "" {
		cloned.ID = "custom-" + generateID()[:12]
	}
	if strings.TrimSpace(cloned.Name) == "" {
		return nil, fmt.Errorf("rule name is required")
	}
	if cloned.Severity == "" {
		cloned.Severity = SeverityMedium
	}
	if cloned.Type == "" {
		switch {
		case cloned.Conditions.Expression != nil:
			cloned.Type = RuleDSL
		case strings.TrimSpace(cloned.Conditions.Pattern) != "":
			cloned.Type = RulePattern
		case cloned.Conditions.Threshold > 0:
			cloned.Type = RuleThreshold
		default:
			return nil, fmt.Errorf("rule type is required")
		}
	}
	if err := validateCustomRule(cloned); err != nil {
		return nil, err
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	for _, existing := range d.rules {
		if existing.ID == cloned.ID {
			return nil, fmt.Errorf("rule already exists: %s", cloned.ID)
		}
	}
	d.rules = append(d.rules, cloned)
	if d.config.DataDir != "" {
		if err := d.persistRulesLocked(); err != nil {
			return nil, err
		}
	}
	return cloneRule(cloned), nil
}

func (d *Detector) DeleteRule(id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	for i, rule := range d.rules {
		if rule.ID != id {
			continue
		}
		if rule.Builtin {
			return fmt.Errorf("cannot delete built-in rule: %s", id)
		}
		d.rules = append(d.rules[:i], d.rules[i+1:]...)
		if d.config.DataDir != "" {
			return d.persistRulesLocked()
		}
		return nil
	}
	return fmt.Errorf("rule not found: %s", id)
}

func validateCustomRule(rule *Rule) error {
	switch rule.Type {
	case RulePattern:
		if strings.TrimSpace(rule.Conditions.Pattern) == "" {
			return fmt.Errorf("pattern rule requires conditions.pattern")
		}
		if strings.TrimSpace(rule.Conditions.Field) == "" {
			return fmt.Errorf("pattern rule requires conditions.field")
		}
	case RuleThreshold:
		if rule.Conditions.Threshold <= 0 {
			return fmt.Errorf("threshold rule requires conditions.threshold > 0")
		}
		if rule.Conditions.Window <= 0 {
			return fmt.Errorf("threshold rule requires conditions.window > 0")
		}
	case RuleDSL:
		if rule.Conditions.Expression == nil {
			return fmt.Errorf("dsl rule requires conditions.expression")
		}
		if err := validateRuleExpression(rule.Conditions.Expression); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported custom rule type: %s", rule.Type)
	}
	rule.compilePattern()
	if rule.Type == RulePattern && rule.compiled == nil {
		return fmt.Errorf("invalid rule pattern")
	}
	return nil
}

func validateRuleExpression(expr *RuleDSLExpr) error {
	if expr == nil {
		return fmt.Errorf("expression is required")
	}
	op := strings.ToLower(strings.TrimSpace(expr.Operator))
	switch op {
	case "and", "or":
		if len(expr.Children) < 2 {
			return fmt.Errorf("%s expression requires at least two children", op)
		}
		for _, child := range expr.Children {
			if err := validateRuleExpression(child); err != nil {
				return err
			}
		}
	case "not":
		if len(expr.Children) != 1 {
			return fmt.Errorf("not expression requires exactly one child")
		}
		return validateRuleExpression(expr.Children[0])
	case "exists":
		if strings.TrimSpace(expr.Field) == "" {
			return fmt.Errorf("exists expression requires field")
		}
	case "eq", "neq", "contains", "prefix", "suffix", "regex", "gt", "gte", "lt", "lte":
		if strings.TrimSpace(expr.Field) == "" {
			return fmt.Errorf("%s expression requires field", op)
		}
		if expr.Value == nil {
			return fmt.Errorf("%s expression requires value", op)
		}
		if op == "regex" {
			pattern, ok := expr.Value.(string)
			if !ok || strings.TrimSpace(pattern) == "" {
				return fmt.Errorf("regex expression requires string value")
			}
			if _, err := regexp.Compile(pattern); err != nil {
				return fmt.Errorf("invalid regex expression: %w", err)
			}
		}
	case "in":
		if strings.TrimSpace(expr.Field) == "" {
			return fmt.Errorf("in expression requires field")
		}
		if len(expr.Values) == 0 {
			return fmt.Errorf("in expression requires values")
		}
	default:
		return fmt.Errorf("unsupported expression operator: %s", expr.Operator)
	}
	return nil
}

func applyRuleUpdate(rule *Rule, update RuleUpdate) error {
	if rule == nil {
		return fmt.Errorf("rule is required")
	}
	if update.Enabled != nil {
		rule.Enabled = *update.Enabled
	}
	if update.Threshold != nil {
		rule.Conditions.Threshold = *update.Threshold
	}
	if update.Window != nil {
		rule.Conditions.Window = *update.Window
	}
	if update.Pattern != nil {
		rule.Conditions.Pattern = *update.Pattern
		rule.compilePattern()
		if strings.TrimSpace(rule.Conditions.Pattern) != "" && rule.compiled == nil {
			return fmt.Errorf("invalid rule pattern")
		}
	}
	if update.Name != nil {
		rule.Name = strings.TrimSpace(*update.Name)
	}
	if update.Description != nil {
		rule.Description = strings.TrimSpace(*update.Description)
	}
	if update.Severity != nil {
		rule.Severity = *update.Severity
	}
	if update.Expression != nil {
		if rule.Builtin {
			return fmt.Errorf("built-in rules cannot replace their evaluation logic")
		}
		rule.Type = RuleDSL
		rule.Conditions.Expression = cloneRuleDSLExpr(update.Expression)
		if err := validateCustomRule(rule); err != nil {
			return err
		}
	}
	return nil
}

func (o *ruleOverride) apply(update RuleUpdate) {
	if update.Enabled != nil {
		value := *update.Enabled
		o.Enabled = &value
	}
	if update.Threshold != nil {
		value := *update.Threshold
		o.Threshold = &value
	}
	if update.Window != nil {
		o.Window = update.Window.String()
	}
	if update.Pattern != nil {
		value := *update.Pattern
		o.Pattern = &value
	}
	if update.Name != nil {
		value := strings.TrimSpace(*update.Name)
		o.Name = &value
	}
	if update.Description != nil {
		value := strings.TrimSpace(*update.Description)
		o.Description = &value
	}
	if update.Severity != nil {
		value := *update.Severity
		o.Severity = &value
	}
}

func (d *Detector) persistRules() error {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.persistRulesLocked()
}

func (d *Detector) persistRulesLocked() error {
	if d.config.DataDir == "" {
		return nil
	}
	if err := os.MkdirAll(d.config.DataDir, 0o750); err != nil {
		return err
	}
	customRules := make([]*Rule, 0)
	for _, rule := range d.rules {
		if !rule.Builtin {
			customRules = append(customRules, cloneRule(rule))
		}
	}
	payload := persistedRuleStore{
		CustomRules: customRules,
		Overrides:   d.ruleOverrides,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(d.config.DataDir, "threat_rules.json"), raw, 0o640)
}

func (d *Detector) loadRules() {
	d.rules = DefaultRules()
	d.ruleOverrides = make(map[string]ruleOverride)
	if d.config.DataDir == "" {
		return
	}
	path := filepath.Join(d.config.DataDir, "threat_rules.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var payload persistedRuleStore
	if err := json.Unmarshal(raw, &payload); err != nil {
		return
	}
	if payload.Overrides != nil {
		d.ruleOverrides = payload.Overrides
	}
	for _, rule := range d.rules {
		override, ok := d.ruleOverrides[rule.ID]
		if !ok {
			continue
		}
		_ = applyRuleOverride(rule, override)
	}
	for _, rule := range payload.CustomRules {
		if rule == nil {
			continue
		}
		cloned := cloneRule(rule)
		cloned.Builtin = false
		if err := validateCustomRule(cloned); err == nil {
			d.rules = append(d.rules, cloned)
		}
	}
}

func applyRuleOverride(rule *Rule, override ruleOverride) error {
	var window *time.Duration
	if strings.TrimSpace(override.Window) != "" {
		parsed, err := time.ParseDuration(strings.TrimSpace(override.Window))
		if err != nil {
			return err
		}
		window = &parsed
	}
	return applyRuleUpdate(rule, RuleUpdate{
		Enabled:     override.Enabled,
		Threshold:   override.Threshold,
		Window:      window,
		Pattern:     override.Pattern,
		Name:        override.Name,
		Description: override.Description,
		Severity:    override.Severity,
	})
}

func normalizeRuleID(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return ""
	}
	var b strings.Builder
	lastDash := false
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		case r == '-', r == '_', r == ' ', r == ':':
			if !lastDash && b.Len() > 0 {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}

func (d *Detector) evalDSL(rule *Rule, event *Event) *Alert {
	if rule == nil || event == nil || rule.Conditions.Expression == nil {
		return nil
	}
	matched, evidence := d.evalRuleExpression(rule.Conditions.Expression, event)
	if !matched {
		return nil
	}
	if strings.TrimSpace(evidence) == "" {
		evidence = fmt.Sprintf("custom DSL rule %q matched", rule.Name)
	}
	return d.createAlert(rule, event, evidence)
}

func (d *Detector) evalRuleExpression(expr *RuleDSLExpr, event *Event) (bool, string) {
	if expr == nil {
		return false, ""
	}
	op := strings.ToLower(strings.TrimSpace(expr.Operator))
	switch op {
	case "and":
		parts := make([]string, 0, len(expr.Children))
		for _, child := range expr.Children {
			matched, evidence := d.evalRuleExpression(child, event)
			if !matched {
				return false, ""
			}
			if strings.TrimSpace(evidence) != "" {
				parts = append(parts, evidence)
			}
		}
		return true, strings.Join(parts, "; ")
	case "or":
		for _, child := range expr.Children {
			matched, evidence := d.evalRuleExpression(child, event)
			if matched {
				return true, evidence
			}
		}
		return false, ""
	case "not":
		if len(expr.Children) != 1 {
			return false, ""
		}
		matched, evidence := d.evalRuleExpression(expr.Children[0], event)
		if matched {
			return false, ""
		}
		if strings.TrimSpace(evidence) == "" {
			return true, "negated condition matched"
		}
		return true, "not(" + evidence + ")"
	case "exists":
		value, ok := d.ruleFieldValue(expr.Field, event)
		if !ok {
			return false, ""
		}
		if s := strings.TrimSpace(ruleStringValue(value)); s == "" && !ruleBooleanValue(value) {
			if _, numeric := toFloat64(value); !numeric {
				return false, ""
			}
		}
		return true, fmt.Sprintf("%s exists", expr.Field)
	case "eq":
		actual, ok := d.ruleFieldValue(expr.Field, event)
		return compareRuleExpression(expr.Field, "=", expr.Value, actual, ok, ruleEquals)
	case "neq":
		actual, ok := d.ruleFieldValue(expr.Field, event)
		return compareRuleExpression(expr.Field, "!=", expr.Value, actual, ok, func(actual, expected interface{}) bool {
			return !ruleEquals(actual, expected)
		})
	case "contains":
		actual, ok := d.ruleFieldValue(expr.Field, event)
		return compareRuleExpression(expr.Field, "contains", expr.Value, actual, ok, func(actual, expected interface{}) bool {
			return strings.Contains(ruleStringValue(actual), ruleStringValue(expected))
		})
	case "prefix":
		actual, ok := d.ruleFieldValue(expr.Field, event)
		return compareRuleExpression(expr.Field, "prefix", expr.Value, actual, ok, func(actual, expected interface{}) bool {
			return strings.HasPrefix(ruleStringValue(actual), ruleStringValue(expected))
		})
	case "suffix":
		actual, ok := d.ruleFieldValue(expr.Field, event)
		return compareRuleExpression(expr.Field, "suffix", expr.Value, actual, ok, func(actual, expected interface{}) bool {
			return strings.HasSuffix(ruleStringValue(actual), ruleStringValue(expected))
		})
	case "regex":
		actual, ok := d.ruleFieldValue(expr.Field, event)
		return compareRuleExpression(expr.Field, "regex", expr.Value, actual, ok, func(actual, expected interface{}) bool {
			if expr.compiled == nil {
				return false
			}
			return expr.compiled.MatchString(ruleStringValue(actual))
		})
	case "in":
		actual, ok := d.ruleFieldValue(expr.Field, event)
		if !ok {
			return false, ""
		}
		for _, candidate := range expr.Values {
			if ruleEquals(actual, candidate) {
				return true, fmt.Sprintf("%s in %v", expr.Field, expr.Values)
			}
		}
		return false, ""
	case "gt":
		actual, ok := d.ruleFieldValue(expr.Field, event)
		return compareRuleExpression(expr.Field, ">", expr.Value, actual, ok, func(actual, expected interface{}) bool {
			return ruleCompare(actual, expected) > 0
		})
	case "gte":
		actual, ok := d.ruleFieldValue(expr.Field, event)
		return compareRuleExpression(expr.Field, ">=", expr.Value, actual, ok, func(actual, expected interface{}) bool {
			return ruleCompare(actual, expected) >= 0
		})
	case "lt":
		actual, ok := d.ruleFieldValue(expr.Field, event)
		return compareRuleExpression(expr.Field, "<", expr.Value, actual, ok, func(actual, expected interface{}) bool {
			return ruleCompare(actual, expected) < 0
		})
	case "lte":
		actual, ok := d.ruleFieldValue(expr.Field, event)
		return compareRuleExpression(expr.Field, "<=", expr.Value, actual, ok, func(actual, expected interface{}) bool {
			return ruleCompare(actual, expected) <= 0
		})
	default:
		return false, ""
	}
}

func compareRuleExpression(field, operator string, expected interface{}, actual interface{}, ok bool, matcher func(actual, expected interface{}) bool) (bool, string) {
	if !ok {
		return false, ""
	}
	if !matcher(actual, expected) {
		return false, ""
	}
	return true, fmt.Sprintf("%s %s %v", field, operator, expected)
}

func ruleEquals(actual, expected interface{}) bool {
	if left, ok := toFloat64(actual); ok {
		if right, ok := toFloat64(expected); ok {
			return left == right
		}
	}
	if leftTime, ok := ruleTimeValue(actual); ok {
		if rightTime, ok := ruleTimeValue(expected); ok {
			return leftTime.Equal(rightTime)
		}
	}
	if left, ok := actual.(bool); ok {
		if right, ok := expected.(bool); ok {
			return left == right
		}
	}
	return ruleStringValue(actual) == ruleStringValue(expected)
}

func ruleCompare(actual, expected interface{}) int {
	if leftTime, ok := ruleTimeValue(actual); ok {
		if rightTime, ok := ruleTimeValue(expected); ok {
			switch {
			case leftTime.Before(rightTime):
				return -1
			case leftTime.After(rightTime):
				return 1
			default:
				return 0
			}
		}
	}
	left, leftOK := toFloat64(actual)
	right, rightOK := toFloat64(expected)
	if leftOK && rightOK {
		switch {
		case left < right:
			return -1
		case left > right:
			return 1
		default:
			return 0
		}
	}
	leftStr := ruleStringValue(actual)
	rightStr := ruleStringValue(expected)
	switch {
	case leftStr < rightStr:
		return -1
	case leftStr > rightStr:
		return 1
	default:
		return 0
	}
}

func (d *Detector) ruleFieldValue(field string, event *Event) (interface{}, bool) {
	field = strings.TrimSpace(field)
	if field == "" || event == nil {
		return nil, false
	}
	switch field {
	case "timestamp":
		return event.Timestamp.UTC(), !event.Timestamp.IsZero()
	case "type":
		return event.Type, event.Type != ""
	case "username":
		return event.Username, event.Username != ""
	case "source_ip":
		return event.SourceIP, event.SourceIP != ""
	case "target":
		return event.Target, event.Target != ""
	}
	if strings.HasPrefix(field, "details.") {
		return ruleDetailsValue(event.Details, strings.Split(strings.TrimPrefix(field, "details."), "."))
	}
	return nil, false
}

func ruleDetailsValue(current interface{}, parts []string) (interface{}, bool) {
	if len(parts) == 0 {
		return current, true
	}
	if current == nil {
		return nil, false
	}
	switch typed := current.(type) {
	case map[string]interface{}:
		next, ok := typed[parts[0]]
		if !ok {
			return nil, false
		}
		return ruleDetailsValue(next, parts[1:])
	default:
		return nil, false
	}
}

func ruleStringValue(value interface{}) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return typed
	case time.Time:
		return typed.UTC().Format(time.RFC3339)
	default:
		return fmt.Sprintf("%v", typed)
	}
}

func ruleTimeValue(value interface{}) (time.Time, bool) {
	switch typed := value.(type) {
	case time.Time:
		if typed.IsZero() {
			return time.Time{}, false
		}
		return typed.UTC(), true
	case string:
		parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(typed))
		if err != nil {
			return time.Time{}, false
		}
		return parsed.UTC(), true
	default:
		return time.Time{}, false
	}
}

func ruleBooleanValue(value interface{}) bool {
	if typed, ok := value.(bool); ok {
		return typed
	}
	return false
}
