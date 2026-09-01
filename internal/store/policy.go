package store

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// AccessRequest is what the data plane asks about before opening a session.
type AccessRequest struct {
	Username      string
	Roles         []string
	Groups        []string
	SourceIP      string
	Target        Target
	UpstreamLogin string
	At            time.Time
}

// AccessDecision is the answer, including the constraints the session must run
// under. Callers must honour every field, not just Allowed: a session that is
// permitted but unrecorded, or permitted without its idle timeout, is not the
// session the policy described.
type AccessDecision struct {
	Allowed bool
	// Reason is safe to show the user; it explains a refusal without disclosing
	// which rules exist.
	Reason string
	// RuleID identifies the rule that decided, for the audit trail.
	RuleID           string
	RuleName         string
	Features         FeatureSet
	UpstreamLogins   []string
	MaxSessionTTL    time.Duration
	IdleTimeout      time.Duration
	MaxConcurrent    int
	RecordPolicy     RecordPolicy
	CommandPolicyID  string
	ApprovalRequired bool
}

// Evaluate decides whether a request may proceed.
//
// Rules are considered in the order ListAccessRules returns them and the first
// match wins. A request that matches nothing is refused: an access proxy must
// fail closed, or a policy authoring mistake silently becomes open access.
func (s *Store) Evaluate(req AccessRequest) (AccessDecision, error) {
	rules, err := s.ListEnabledAccessRules()
	if err != nil {
		return AccessDecision{}, err
	}
	return EvaluateRules(rules, req), nil
}

// EvaluateRules is Evaluate against an already-loaded rule set, which is what
// the decision point uses so a cached snapshot can serve connections without a
// query per attempt.
func EvaluateRules(rules []AccessRule, req AccessRequest) AccessDecision {
	at := req.At
	if at.IsZero() {
		at = time.Now()
	}

	for _, rule := range rules {
		if !ruleMatches(rule, req, at) {
			continue
		}
		if rule.Effect == EffectDeny {
			return AccessDecision{
				Allowed:  false,
				Reason:   "access denied by policy",
				RuleID:   rule.ID,
				RuleName: rule.Name,
			}
		}
		if !loginPermitted(rule, req.UpstreamLogin) {
			// A rule that matches the subject and target but not the requested
			// account is a refusal, not a reason to look at later rules: the
			// operator already said what this subject may do here.
			return AccessDecision{
				Allowed:  false,
				Reason:   "upstream account " + req.UpstreamLogin + " is not permitted for this target",
				RuleID:   rule.ID,
				RuleName: rule.Name,
			}
		}
		features := rule.Features
		if features == FeatureNone {
			// A rule that grants access without naming features grants the
			// interactive basics rather than nothing, which is what an author
			// writing a minimal allow rule means.
			features = FeatureShell | FeatureExec | FeaturePTY | FeatureEnv
		}
		features = features.Without(rule.DeniedFeatures)

		return AccessDecision{
			Allowed:          true,
			Reason:           "allowed by policy",
			RuleID:           rule.ID,
			RuleName:         rule.Name,
			Features:         features,
			UpstreamLogins:   rule.UpstreamLogins,
			MaxSessionTTL:    rule.MaxSessionTTL,
			IdleTimeout:      rule.IdleTimeout,
			MaxConcurrent:    rule.MaxConcurrent,
			RecordPolicy:     rule.RecordPolicy,
			CommandPolicyID:  rule.CommandPolicyID,
			ApprovalRequired: rule.ApprovalRequired,
		}
	}

	return AccessDecision{Allowed: false, Reason: "no access rule permits this connection"}
}

func ruleMatches(rule AccessRule, req AccessRequest, at time.Time) bool {
	if !subjectMatches(rule, req) {
		return false
	}
	if !TargetMatches(req.Target, rule.TargetSelector) {
		return false
	}
	if !sourceMatches(rule.SourceCIDRs, req.SourceIP) {
		return false
	}
	if !windowsMatch(rule.TimeWindows, at) {
		return false
	}
	return true
}

func subjectMatches(rule AccessRule, req AccessRequest) bool {
	subject := strings.TrimSpace(rule.Subject)
	switch rule.SubjectKind {
	case SubjectAny:
		return true
	case SubjectUser:
		return subject == "*" || strings.EqualFold(subject, req.Username)
	case SubjectRole:
		if subject == "*" {
			return len(req.Roles) > 0
		}
		return containsFold(req.Roles, subject)
	case SubjectGroup:
		if subject == "*" {
			return len(req.Groups) > 0
		}
		return containsFold(req.Groups, subject)
	default:
		return false
	}
}

func containsFold(values []string, want string) bool {
	for _, v := range values {
		if strings.EqualFold(strings.TrimSpace(v), want) {
			return true
		}
	}
	return false
}

// sourceMatches reports whether the client address falls inside any listed
// network. An empty list places no restriction; a non-empty list that cannot be
// evaluated (no address, unparseable address) does not match, so a rule scoped
// to an office network is never satisfied by an unknown origin.
func sourceMatches(cidrs []string, sourceIP string) bool {
	if len(cidrs) == 0 {
		return true
	}
	ip := net.ParseIP(hostOnly(sourceIP))
	if ip == nil {
		return false
	}
	for _, raw := range cidrs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if _, network, err := net.ParseCIDR(raw); err == nil {
			if network.Contains(ip) {
				return true
			}
			continue
		}
		if candidate := net.ParseIP(raw); candidate != nil && candidate.Equal(ip) {
			return true
		}
	}
	return false
}

func hostOnly(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

// windowsMatch reports whether the instant falls inside any configured window.
// An empty list places no restriction.
func windowsMatch(windows []TimeWindow, at time.Time) bool {
	if len(windows) == 0 {
		return true
	}
	for _, w := range windows {
		if windowContains(w, at) {
			return true
		}
	}
	return false
}

func windowContains(w TimeWindow, at time.Time) bool {
	local := at
	if strings.TrimSpace(w.Location) != "" {
		loc, err := time.LoadLocation(w.Location)
		if err != nil {
			// An unresolvable timezone makes the window meaningless; refusing to
			// match is the conservative reading.
			return false
		}
		local = at.In(loc)
	}

	if len(w.Days) > 0 {
		weekday := int(local.Weekday())
		if weekday == 0 {
			weekday = 7 // ISO: Sunday is 7.
		}
		found := false
		for _, d := range w.Days {
			if d == weekday {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	start, okStart := parseClock(w.Start)
	end, okEnd := parseClock(w.End)
	if !okStart || !okEnd {
		return false
	}
	minutes := local.Hour()*60 + local.Minute()
	if start <= end {
		return minutes >= start && minutes < end
	}
	// A window whose end precedes its start wraps past midnight.
	return minutes >= start || minutes < end
}

func parseClock(raw string) (int, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, false
	}
	hourStr, minuteStr, ok := strings.Cut(raw, ":")
	if !ok {
		return 0, false
	}
	hour, err := strconv.Atoi(strings.TrimSpace(hourStr))
	if err != nil || hour < 0 || hour > 23 {
		return 0, false
	}
	minute, err := strconv.Atoi(strings.TrimSpace(minuteStr))
	if err != nil || minute < 0 || minute > 59 {
		return 0, false
	}
	return hour*60 + minute, true
}

func loginPermitted(rule AccessRule, login string) bool {
	login = strings.TrimSpace(login)
	if login == "" || len(rule.UpstreamLogins) == 0 {
		return true
	}
	for _, allowed := range rule.UpstreamLogins {
		allowed = strings.TrimSpace(allowed)
		if allowed == "*" || strings.EqualFold(allowed, login) {
			return true
		}
	}
	return false
}

// --------------------------------------------------------------------------
// Source-network gate
// --------------------------------------------------------------------------

// CheckSourceIP applies the IP rules to a client address before authentication.
//
// The default when no rule matches is to allow, because these rules express
// blocks and carve-outs rather than the whole access policy; a connection that
// gets past this gate still has to satisfy an access rule to reach anything.
func (s *Store) CheckSourceIP(sourceIP string) (allowed bool, ruleID string, err error) {
	rules, err := s.ListIPRules()
	if err != nil {
		return false, "", err
	}
	allowed, ruleID = CheckSourceIPRules(rules, sourceIP, s.clock())
	return allowed, ruleID, nil
}

// CheckSourceIPRules evaluates a preloaded rule set.
func CheckSourceIPRules(rules []IPRule, sourceIP string, now time.Time) (bool, string) {
	ip := net.ParseIP(hostOnly(sourceIP))
	if ip == nil {
		return true, ""
	}
	for _, rule := range rules {
		if !rule.ExpiresAt.IsZero() && now.After(rule.ExpiresAt) {
			continue
		}
		if !cidrContains(rule.CIDR, ip) {
			continue
		}
		return rule.Action == IPAllow, rule.ID
	}
	return true, ""
}

func cidrContains(raw string, ip net.IP) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}
	if _, network, err := net.ParseCIDR(raw); err == nil {
		return network.Contains(ip)
	}
	candidate := net.ParseIP(raw)
	return candidate != nil && candidate.Equal(ip)
}

// --------------------------------------------------------------------------
// Concurrency limits
// --------------------------------------------------------------------------

// CheckConcurrency reports whether another session would exceed the decision's
// limit. It counts rows in the shared table so the limit holds across every
// proxy node rather than per process.
func (s *Store) CheckConcurrency(username, targetID string, decision AccessDecision) error {
	if decision.MaxConcurrent <= 0 {
		return nil
	}
	count, err := s.CountActiveSessions(username, "")
	if err != nil {
		return err
	}
	if count >= decision.MaxConcurrent {
		return fmt.Errorf("session limit reached: %d of %d concurrent sessions already open",
			count, decision.MaxConcurrent)
	}
	return nil
}
