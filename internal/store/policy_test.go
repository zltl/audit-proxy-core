package store

import (
	"strings"
	"testing"
	"time"
)

func prodTarget() Target {
	return Target{
		ID:    "tgt-1",
		Name:  "prod-web-1",
		Host:  "10.0.1.10",
		Port:  22,
		Group: "web",
		Tags:  map[string]string{"env": "prod"},
	}
}

func TestEvaluateFailsClosedWithNoRules(t *testing.T) {
	decision := EvaluateRules(nil, AccessRequest{Username: "alice", Target: prodTarget()})
	if decision.Allowed {
		t.Fatal("an empty policy must refuse; failing open would make a policy mistake invisible")
	}
	if decision.Reason == "" {
		t.Fatal("a refusal should explain itself")
	}
}

func TestEvaluateFirstMatchWins(t *testing.T) {
	rules := []AccessRule{
		{ID: "deny-prod", Priority: 10, Effect: EffectDeny, SubjectKind: SubjectUser,
			Subject: "alice", TargetSelector: "tag:env=prod", Enabled: true},
		{ID: "allow-all", Priority: 20, Effect: EffectAllow, SubjectKind: SubjectUser,
			Subject: "*", TargetSelector: "*", Features: FeatureAll, Enabled: true},
	}

	denied := EvaluateRules(rules, AccessRequest{Username: "alice", Target: prodTarget()})
	if denied.Allowed {
		t.Fatal("the higher-priority deny should win")
	}
	if denied.RuleID != "deny-prod" {
		t.Fatalf("decision attributed to %q, want deny-prod", denied.RuleID)
	}

	allowed := EvaluateRules(rules, AccessRequest{Username: "bob", Target: prodTarget()})
	if !allowed.Allowed || allowed.RuleID != "allow-all" {
		t.Fatalf("bob should fall through to the allow rule: %+v", allowed)
	}
}

func TestEvaluateSubjectKinds(t *testing.T) {
	target := prodTarget()
	base := AccessRule{Priority: 10, Effect: EffectAllow, TargetSelector: "*",
		Features: FeatureShell, Enabled: true}

	byRole := base
	byRole.ID = "by-role"
	byRole.SubjectKind = SubjectRole
	byRole.Subject = "sre"

	if d := EvaluateRules([]AccessRule{byRole}, AccessRequest{
		Username: "alice", Roles: []string{"SRE"}, Target: target,
	}); !d.Allowed {
		t.Error("role matching should be case-insensitive")
	}
	if d := EvaluateRules([]AccessRule{byRole}, AccessRequest{
		Username: "alice", Roles: []string{"dev"}, Target: target,
	}); d.Allowed {
		t.Error("a user without the role should not match")
	}

	byGroup := base
	byGroup.ID = "by-group"
	byGroup.SubjectKind = SubjectGroup
	byGroup.Subject = "platform"
	if d := EvaluateRules([]AccessRule{byGroup}, AccessRequest{
		Username: "alice", Groups: []string{"platform"}, Target: target,
	}); !d.Allowed {
		t.Error("group matching failed")
	}

	anyone := base
	anyone.ID = "anyone"
	anyone.SubjectKind = SubjectAny
	if d := EvaluateRules([]AccessRule{anyone}, AccessRequest{Username: "zoe", Target: target}); !d.Allowed {
		t.Error("SubjectAny should match every principal")
	}
}

func TestEvaluateSourceCIDRRestriction(t *testing.T) {
	rule := AccessRule{
		ID: "office-only", Priority: 10, Effect: EffectAllow, SubjectKind: SubjectAny,
		TargetSelector: "*", Features: FeatureShell, Enabled: true,
		SourceCIDRs: []string{"10.0.0.0/8", "192.168.1.5"},
	}
	rules := []AccessRule{rule}

	for _, ip := range []string{"10.1.2.3", "10.1.2.3:54321", "192.168.1.5"} {
		if d := EvaluateRules(rules, AccessRequest{Username: "a", SourceIP: ip, Target: prodTarget()}); !d.Allowed {
			t.Errorf("source %q should be inside the allowed networks", ip)
		}
	}
	for _, ip := range []string{"172.16.0.1", "192.168.1.6", "", "not-an-ip"} {
		if d := EvaluateRules(rules, AccessRequest{Username: "a", SourceIP: ip, Target: prodTarget()}); d.Allowed {
			t.Errorf("source %q should not satisfy a network-scoped rule", ip)
		}
	}
}

func TestEvaluateTimeWindows(t *testing.T) {
	rule := AccessRule{
		ID: "business-hours", Priority: 10, Effect: EffectAllow, SubjectKind: SubjectAny,
		TargetSelector: "*", Features: FeatureShell, Enabled: true,
		TimeWindows: []TimeWindow{{Days: []int{1, 2, 3, 4, 5}, Start: "09:00", End: "18:00", Location: "UTC"}},
	}
	rules := []AccessRule{rule}

	// 2026-03-02 is a Monday.
	inside := time.Date(2026, 3, 2, 10, 30, 0, 0, time.UTC)
	if d := EvaluateRules(rules, AccessRequest{Username: "a", Target: prodTarget(), At: inside}); !d.Allowed {
		t.Error("Monday 10:30 UTC should be inside business hours")
	}
	evening := time.Date(2026, 3, 2, 20, 0, 0, 0, time.UTC)
	if d := EvaluateRules(rules, AccessRequest{Username: "a", Target: prodTarget(), At: evening}); d.Allowed {
		t.Error("Monday 20:00 UTC should be outside business hours")
	}
	weekend := time.Date(2026, 3, 7, 10, 30, 0, 0, time.UTC)
	if d := EvaluateRules(rules, AccessRequest{Username: "a", Target: prodTarget(), At: weekend}); d.Allowed {
		t.Error("Saturday should be outside a weekday window")
	}
}

func TestEvaluateOvernightWindowWraps(t *testing.T) {
	rules := []AccessRule{{
		ID: "night-shift", Priority: 10, Effect: EffectAllow, SubjectKind: SubjectAny,
		TargetSelector: "*", Features: FeatureShell, Enabled: true,
		TimeWindows: []TimeWindow{{Start: "22:00", End: "06:00", Location: "UTC"}},
	}}

	for _, hour := range []int{22, 23, 0, 5} {
		at := time.Date(2026, 3, 2, hour, 30, 0, 0, time.UTC)
		if d := EvaluateRules(rules, AccessRequest{Username: "a", Target: prodTarget(), At: at}); !d.Allowed {
			t.Errorf("%02d:30 should fall inside a 22:00-06:00 window", hour)
		}
	}
	for _, hour := range []int{6, 12, 21} {
		at := time.Date(2026, 3, 2, hour, 30, 0, 0, time.UTC)
		if d := EvaluateRules(rules, AccessRequest{Username: "a", Target: prodTarget(), At: at}); d.Allowed {
			t.Errorf("%02d:30 should fall outside a 22:00-06:00 window", hour)
		}
	}
}

func TestEvaluateRejectsUnresolvableTimezone(t *testing.T) {
	rules := []AccessRule{{
		ID: "bad-tz", Priority: 10, Effect: EffectAllow, SubjectKind: SubjectAny,
		TargetSelector: "*", Features: FeatureShell, Enabled: true,
		TimeWindows: []TimeWindow{{Start: "00:00", End: "23:59", Location: "Mars/Olympus"}},
	}}
	if d := EvaluateRules(rules, AccessRequest{Username: "a", Target: prodTarget()}); d.Allowed {
		t.Fatal("a window with an unresolvable timezone must not match")
	}
}

func TestEvaluateFeatureMaskSubtractsDenials(t *testing.T) {
	rules := []AccessRule{{
		ID: "limited", Priority: 10, Effect: EffectAllow, SubjectKind: SubjectAny,
		TargetSelector: "*", Enabled: true,
		Features:       FeatureAll,
		DeniedFeatures: FeatureLocalForward | FeatureRemoteForward | FeatureDynamicForward | FeatureAgentForward,
	}}

	d := EvaluateRules(rules, AccessRequest{Username: "a", Target: prodTarget()})
	if !d.Allowed {
		t.Fatal("expected the rule to allow")
	}
	if d.Features.HasAny(FeatureLocalForward | FeatureRemoteForward | FeatureDynamicForward) {
		t.Errorf("denied forwarding still present: %s", d.Features)
	}
	if d.Features.Has(FeatureAgentForward) {
		t.Error("agent forwarding should have been removed")
	}
	if !d.Features.Has(FeatureShell) || !d.Features.Has(FeatureSFTP) {
		t.Errorf("features that were not denied should remain: %s", d.Features)
	}
}

func TestEvaluateDefaultFeaturesWhenUnspecified(t *testing.T) {
	rules := []AccessRule{{
		ID: "bare-allow", Priority: 10, Effect: EffectAllow, SubjectKind: SubjectAny,
		TargetSelector: "*", Enabled: true,
	}}
	d := EvaluateRules(rules, AccessRequest{Username: "a", Target: prodTarget()})
	if !d.Allowed {
		t.Fatal("expected allow")
	}
	if !d.Features.Has(FeatureShell) || !d.Features.Has(FeatureExec) {
		t.Errorf("a bare allow should grant interactive basics, got %s", d.Features)
	}
	if d.Features.Has(FeatureLocalForward) || d.Features.Has(FeatureSFTP) {
		t.Errorf("a bare allow must not silently grant forwarding or transfer, got %s", d.Features)
	}
}

func TestEvaluateUpstreamLoginRestriction(t *testing.T) {
	rules := []AccessRule{{
		ID: "deploy-only", Priority: 10, Effect: EffectAllow, SubjectKind: SubjectAny,
		TargetSelector: "*", Features: FeatureShell, Enabled: true,
		UpstreamLogins: []string{"deploy", "appuser"},
	}}

	if d := EvaluateRules(rules, AccessRequest{Username: "a", Target: prodTarget(), UpstreamLogin: "deploy"}); !d.Allowed {
		t.Error("a permitted upstream account should be allowed")
	}
	d := EvaluateRules(rules, AccessRequest{Username: "a", Target: prodTarget(), UpstreamLogin: "root"})
	if d.Allowed {
		t.Fatal("root is not in the permitted account list")
	}
	if !strings.Contains(d.Reason, "root") {
		t.Errorf("the refusal should name the account, got %q", d.Reason)
	}
}

func TestEvaluateCarriesSessionConstraints(t *testing.T) {
	rules := []AccessRule{{
		ID: "constrained", Name: "Constrained", Priority: 10, Effect: EffectAllow,
		SubjectKind: SubjectAny, TargetSelector: "*", Features: FeatureShell, Enabled: true,
		MaxSessionTTL: 2 * time.Hour, IdleTimeout: 15 * time.Minute, MaxConcurrent: 3,
		RecordPolicy: RecordCommands, CommandPolicyID: "cmdpol-1", ApprovalRequired: true,
	}}

	d := EvaluateRules(rules, AccessRequest{Username: "a", Target: prodTarget()})
	if d.MaxSessionTTL != 2*time.Hour || d.IdleTimeout != 15*time.Minute || d.MaxConcurrent != 3 {
		t.Fatalf("session limits not carried: %+v", d)
	}
	if d.RecordPolicy != RecordCommands || d.CommandPolicyID != "cmdpol-1" || !d.ApprovalRequired {
		t.Fatalf("policy attributes not carried: %+v", d)
	}
	if d.RuleName != "Constrained" {
		t.Errorf("decision should identify the deciding rule for the audit trail: %+v", d)
	}
}

func TestListAccessRulesOrdersDenyFirstAtEqualPriority(t *testing.T) {
	s := newTestStore(t)

	if _, err := s.PutAccessRule(AccessRule{
		ID: "allow-same", Priority: 50, Effect: EffectAllow, SubjectKind: SubjectAny,
		TargetSelector: "*", Enabled: true,
	}); err != nil {
		t.Fatalf("PutAccessRule allow: %v", err)
	}
	if _, err := s.PutAccessRule(AccessRule{
		ID: "deny-same", Priority: 50, Effect: EffectDeny, SubjectKind: SubjectAny,
		TargetSelector: "tag:env=prod", Enabled: true,
	}); err != nil {
		t.Fatalf("PutAccessRule deny: %v", err)
	}

	rules, err := s.ListAccessRules()
	if err != nil {
		t.Fatalf("ListAccessRules: %v", err)
	}
	if len(rules) != 2 || rules[0].ID != "deny-same" {
		t.Fatalf("deny should sort first at equal priority, got %+v", rules)
	}

	d := EvaluateRules(rules, AccessRequest{Username: "a", Target: prodTarget()})
	if d.Allowed {
		t.Fatal("the deny carve-out should win over a same-priority blanket allow")
	}
}

func TestAccessRuleRoundTrip(t *testing.T) {
	s := newTestStore(t)

	original := AccessRule{
		Name: "SRE prod", Priority: 20, Effect: EffectAllow, SubjectKind: SubjectRole,
		Subject: "sre", TargetSelector: "tag:env=prod",
		UpstreamLogins: []string{"deploy", "root"},
		Features:       FeatureShell | FeatureSFTP,
		DeniedFeatures: FeatureAgentForward,
		SourceCIDRs:    []string{"10.0.0.0/8"},
		TimeWindows:    []TimeWindow{{Days: []int{1, 2}, Start: "09:00", End: "17:00", Location: "UTC"}},
		MaxSessionTTL:  4 * time.Hour, IdleTimeout: 10 * time.Minute, MaxConcurrent: 2,
		RecordPolicy: RecordFull, CommandPolicyID: "cp-1", ApprovalRequired: true, Enabled: true,
	}
	saved, err := s.PutAccessRule(original)
	if err != nil {
		t.Fatalf("PutAccessRule: %v", err)
	}

	loaded, err := s.GetAccessRule(saved.ID)
	if err != nil {
		t.Fatalf("GetAccessRule: %v", err)
	}
	if loaded.Features != original.Features || loaded.DeniedFeatures != original.DeniedFeatures {
		t.Errorf("feature masks did not round-trip: %s / %s", loaded.Features, loaded.DeniedFeatures)
	}
	if len(loaded.UpstreamLogins) != 2 || loaded.UpstreamLogins[0] != "deploy" {
		t.Errorf("upstream logins did not round-trip: %v", loaded.UpstreamLogins)
	}
	if len(loaded.TimeWindows) != 1 || loaded.TimeWindows[0].Start != "09:00" ||
		loaded.TimeWindows[0].Location != "UTC" || len(loaded.TimeWindows[0].Days) != 2 {
		t.Errorf("time windows did not round-trip: %+v", loaded.TimeWindows)
	}
	if loaded.MaxSessionTTL != 4*time.Hour || loaded.IdleTimeout != 10*time.Minute {
		t.Errorf("durations did not round-trip: %v / %v", loaded.MaxSessionTTL, loaded.IdleTimeout)
	}
	if !loaded.ApprovalRequired || loaded.RecordPolicy != RecordFull {
		t.Errorf("policy flags did not round-trip: %+v", loaded)
	}
}

func TestCheckSourceIPRules(t *testing.T) {
	now := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	rules := []IPRule{
		{ID: "allow-office", CIDR: "10.0.0.0/8", Action: IPAllow, Priority: 10},
		{ID: "deny-all-private", CIDR: "0.0.0.0/0", Action: IPDeny, Priority: 20},
		{ID: "expired-ban", CIDR: "203.0.113.0/24", Action: IPDeny, Priority: 5,
			ExpiresAt: now.Add(-time.Hour)},
	}

	if allowed, id := CheckSourceIPRules(rules, "10.1.1.1", now); !allowed || id != "allow-office" {
		t.Errorf("office address = (%v, %q), want (true, allow-office)", allowed, id)
	}
	if allowed, id := CheckSourceIPRules(rules, "8.8.8.8", now); allowed || id != "deny-all-private" {
		t.Errorf("outside address = (%v, %q), want (false, deny-all-private)", allowed, id)
	}
	// The expired ban must be skipped, so the catch-all deny applies instead.
	if allowed, id := CheckSourceIPRules(rules, "203.0.113.5", now); allowed || id != "deny-all-private" {
		t.Errorf("expired ban was not skipped: (%v, %q)", allowed, id)
	}
	// No rules at all is not a block: these express carve-outs, not the policy.
	if allowed, _ := CheckSourceIPRules(nil, "8.8.8.8", now); !allowed {
		t.Error("an empty IP rule set should not block")
	}
}

func TestPurgeExpiredIPRules(t *testing.T) {
	s := newTestStore(t)
	now := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	s.SetClock(func() time.Time { return now })

	if _, err := s.PutIPRule(IPRule{CIDR: "203.0.113.0/24", Action: IPDeny, ExpiresAt: now.Add(-time.Hour)}); err != nil {
		t.Fatalf("PutIPRule expired: %v", err)
	}
	if _, err := s.PutIPRule(IPRule{CIDR: "198.51.100.0/24", Action: IPDeny, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatalf("PutIPRule live: %v", err)
	}
	if _, err := s.PutIPRule(IPRule{CIDR: "192.0.2.0/24", Action: IPDeny}); err != nil {
		t.Fatalf("PutIPRule permanent: %v", err)
	}

	purged, err := s.PurgeExpiredIPRules()
	if err != nil {
		t.Fatalf("PurgeExpiredIPRules: %v", err)
	}
	if purged != 1 {
		t.Fatalf("purged %d rules, want 1", purged)
	}
	remaining, err := s.ListIPRules()
	if err != nil {
		t.Fatalf("ListIPRules: %v", err)
	}
	if len(remaining) != 2 {
		t.Fatalf("expected the live and permanent rules to remain, got %d", len(remaining))
	}
}
