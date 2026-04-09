package jit

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/smtp"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newTestStore(t *testing.T, policy *Policy) *Store {
	t.Helper()
	dir := t.TempDir()
	s := NewStore(dir, policy)
	return s
}

func makeRequest(requester, target, role, reason string, dur time.Duration) *AccessRequest {
	return &AccessRequest{
		Requester: requester,
		Target:    target,
		Role:      role,
		Reason:    reason,
		Duration:  dur,
	}
}

// --- Test: Create Request ---

func TestCreateRequest(t *testing.T) {
	s := newTestStore(t, nil)
	req := makeRequest("alice", "prod-db-01", "operator", "maintenance", time.Hour)
	if err := s.CreateRequest(req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.ID == "" {
		t.Fatal("expected non-empty ID")
	}
	if req.Status != StatusPending {
		t.Fatalf("expected pending, got %s", req.Status)
	}
	if req.CreatedAt.IsZero() {
		t.Fatal("expected non-zero CreatedAt")
	}
}

func TestCreateRequestMissingRequester(t *testing.T) {
	s := newTestStore(t, nil)
	req := makeRequest("", "prod-db-01", "operator", "reason", time.Hour)
	if err := s.CreateRequest(req); err == nil {
		t.Fatal("expected error for missing requester")
	}
}

func TestCreateRequestMissingTarget(t *testing.T) {
	s := newTestStore(t, nil)
	req := makeRequest("alice", "", "operator", "reason", time.Hour)
	if err := s.CreateRequest(req); err == nil {
		t.Fatal("expected error for missing target")
	}
}

func TestCreateRequestMissingRole(t *testing.T) {
	s := newTestStore(t, nil)
	req := makeRequest("alice", "prod-db-01", "", "reason", time.Hour)
	if err := s.CreateRequest(req); err == nil {
		t.Fatal("expected error for missing role")
	}
}

func TestCreateRequestZeroDuration(t *testing.T) {
	s := newTestStore(t, nil)
	req := makeRequest("alice", "prod-db-01", "operator", "reason", 0)
	if err := s.CreateRequest(req); err == nil {
		t.Fatal("expected error for zero duration")
	}
}

// --- Test: Approve/Deny Flow ---

func TestApproveRequest(t *testing.T) {
	s := newTestStore(t, nil)
	req := makeRequest("alice", "prod-db-01", "operator", "reason", time.Hour)
	s.CreateRequest(req)

	if err := s.ApproveRequest(req.ID, "admin-bob"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Status != StatusApproved {
		t.Fatalf("expected approved, got %s", req.Status)
	}
	if req.Approver != "admin-bob" {
		t.Fatalf("expected admin-bob, got %s", req.Approver)
	}
	if req.ApprovedAt.IsZero() {
		t.Fatal("expected non-zero ApprovedAt")
	}
	if req.ExpiresAt.IsZero() {
		t.Fatal("expected non-zero ExpiresAt")
	}
}

func TestApproveNotFound(t *testing.T) {
	s := newTestStore(t, nil)
	if err := s.ApproveRequest("nonexistent", "admin"); err == nil {
		t.Fatal("expected error for missing request")
	}
}

func TestApproveAlreadyApproved(t *testing.T) {
	s := newTestStore(t, nil)
	req := makeRequest("alice", "prod-db-01", "operator", "reason", time.Hour)
	s.CreateRequest(req)
	s.ApproveRequest(req.ID, "admin")

	if err := s.ApproveRequest(req.ID, "admin2"); err == nil {
		t.Fatal("expected error for non-pending request")
	}
}

func TestDenyRequest(t *testing.T) {
	s := newTestStore(t, nil)
	req := makeRequest("alice", "prod-db-01", "operator", "reason", time.Hour)
	s.CreateRequest(req)

	if err := s.DenyRequest(req.ID, "admin-carol", "not needed"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Status != StatusDenied {
		t.Fatalf("expected denied, got %s", req.Status)
	}
	if req.DenyReason != "not needed" {
		t.Fatalf("expected 'not needed', got %s", req.DenyReason)
	}
}

func TestDenyAlreadyDenied(t *testing.T) {
	s := newTestStore(t, nil)
	req := makeRequest("alice", "prod-db-01", "operator", "reason", time.Hour)
	s.CreateRequest(req)
	s.DenyRequest(req.ID, "admin", "no")

	if err := s.DenyRequest(req.ID, "admin2", "also no"); err == nil {
		t.Fatal("expected error for non-pending request")
	}
}

// --- Test: Revoke ---

func TestRevokeRequest(t *testing.T) {
	s := newTestStore(t, nil)
	req := makeRequest("alice", "prod-db-01", "operator", "reason", time.Hour)
	s.CreateRequest(req)
	s.ApproveRequest(req.ID, "admin")

	if err := s.RevokeRequest(req.ID, "admin"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Status != StatusRevoked {
		t.Fatalf("expected revoked, got %s", req.Status)
	}

	// Grant should be removed
	_, ok := s.CheckAccess("alice", "prod-db-01")
	if ok {
		t.Fatal("expected no access after revoke")
	}
}

func TestRevokePendingFails(t *testing.T) {
	s := newTestStore(t, nil)
	req := makeRequest("alice", "prod-db-01", "operator", "reason", time.Hour)
	s.CreateRequest(req)

	if err := s.RevokeRequest(req.ID, "admin"); err == nil {
		t.Fatal("expected error revoking non-approved request")
	}
}

// --- Test: Access Check ---

func TestCheckAccessGranted(t *testing.T) {
	s := newTestStore(t, nil)
	req := makeRequest("alice", "prod-db-01", "operator", "reason", time.Hour)
	s.CreateRequest(req)
	s.ApproveRequest(req.ID, "admin")

	grant, ok := s.CheckAccess("alice", "prod-db-01")
	if !ok {
		t.Fatal("expected access to be granted")
	}
	if grant.Username != "alice" {
		t.Fatalf("expected alice, got %s", grant.Username)
	}
	if grant.Role != "operator" {
		t.Fatalf("expected operator, got %s", grant.Role)
	}
}

func TestCheckAccessDenied(t *testing.T) {
	s := newTestStore(t, nil)
	_, ok := s.CheckAccess("alice", "prod-db-01")
	if ok {
		t.Fatal("expected no access for non-existent user")
	}
}

func TestCheckAccessExpired(t *testing.T) {
	s := newTestStore(t, nil)
	req := makeRequest("alice", "prod-db-01", "operator", "reason", 10*time.Millisecond)
	s.CreateRequest(req)
	s.ApproveRequest(req.ID, "admin")

	time.Sleep(20 * time.Millisecond)

	_, ok := s.CheckAccess("alice", "prod-db-01")
	if ok {
		t.Fatal("expected no access after expiry")
	}
}

// --- Test: Expiry and Cleanup ---

func TestCleanExpired(t *testing.T) {
	s := newTestStore(t, nil)
	req := makeRequest("alice", "prod-db-01", "operator", "reason", 10*time.Millisecond)
	s.CreateRequest(req)
	s.ApproveRequest(req.ID, "admin")

	time.Sleep(20 * time.Millisecond)

	count := s.CleanExpired()
	if count != 1 {
		t.Fatalf("expected 1 expired, got %d", count)
	}

	got, err := s.GetRequest(req.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusExpired {
		t.Fatalf("expected expired, got %s", got.Status)
	}
}

func TestCleanExpiredNoneExpired(t *testing.T) {
	s := newTestStore(t, nil)
	req := makeRequest("alice", "prod-db-01", "operator", "reason", time.Hour)
	s.CreateRequest(req)
	s.ApproveRequest(req.ID, "admin")

	count := s.CleanExpired()
	if count != 0 {
		t.Fatalf("expected 0 expired, got %d", count)
	}
}

func TestStartCleanupLoop(t *testing.T) {
	s := newTestStore(t, nil)
	req := makeRequest("alice", "prod-db-01", "operator", "reason", 10*time.Millisecond)
	s.CreateRequest(req)
	s.ApproveRequest(req.ID, "admin")

	ctx, cancel := context.WithCancel(context.Background())
	go s.StartCleanupLoop(ctx, 15*time.Millisecond)

	time.Sleep(50 * time.Millisecond)
	cancel()

	got, _ := s.GetRequest(req.ID)
	if got.Status != StatusExpired {
		t.Fatalf("expected expired status from cleanup loop, got %s", got.Status)
	}
}

// --- Test: Policy Enforcement ---

func TestPolicyMaxDuration(t *testing.T) {
	s := newTestStore(t, &Policy{
		MaxDuration:   30 * time.Minute,
		ApproverRoles: []string{"admin"},
	})
	req := makeRequest("alice", "prod-db-01", "operator", "reason", time.Hour)
	if err := s.CreateRequest(req); err == nil {
		t.Fatal("expected error for exceeding max duration")
	}
}

func TestPolicyMaxDurationAllowed(t *testing.T) {
	s := newTestStore(t, &Policy{
		MaxDuration:   2 * time.Hour,
		ApproverRoles: []string{"admin"},
	})
	req := makeRequest("alice", "prod-db-01", "operator", "reason", time.Hour)
	if err := s.CreateRequest(req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPolicyRequireReason(t *testing.T) {
	s := newTestStore(t, &Policy{
		MaxDuration:   24 * time.Hour,
		RequireReason: true,
		ApproverRoles: []string{"admin"},
	})
	req := makeRequest("alice", "prod-db-01", "operator", "", time.Hour)
	if err := s.CreateRequest(req); err == nil {
		t.Fatal("expected error for missing reason")
	}
}

func TestPolicyRequireReasonProvided(t *testing.T) {
	s := newTestStore(t, &Policy{
		MaxDuration:   24 * time.Hour,
		RequireReason: true,
		ApproverRoles: []string{"admin"},
	})
	req := makeRequest("alice", "prod-db-01", "operator", "JIRA-123", time.Hour)
	if err := s.CreateRequest(req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPolicyAutoApprove(t *testing.T) {
	s := newTestStore(t, &Policy{
		MaxDuration:    24 * time.Hour,
		AutoApprove:    true,
		AutoApproveFor: []string{"viewer"},
		ApproverRoles:  []string{"admin"},
	})

	req := makeRequest("alice", "prod-db-01", "viewer", "quick check", time.Hour)
	if err := s.CreateRequest(req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Status != StatusApproved {
		t.Fatalf("expected auto-approved, got %s", req.Status)
	}
	if req.Approver != "system" {
		t.Fatalf("expected system approver, got %s", req.Approver)
	}

	grant, ok := s.CheckAccess("alice", "prod-db-01")
	if !ok {
		t.Fatal("expected access after auto-approve")
	}
	if grant.Role != "viewer" {
		t.Fatalf("expected viewer role, got %s", grant.Role)
	}
}

func TestPolicyAutoApproveNoMatch(t *testing.T) {
	s := newTestStore(t, &Policy{
		MaxDuration:    24 * time.Hour,
		AutoApprove:    true,
		AutoApproveFor: []string{"viewer"},
		ApproverRoles:  []string{"admin"},
	})

	req := makeRequest("alice", "prod-db-01", "operator", "need access", time.Hour)
	if err := s.CreateRequest(req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Status != StatusPending {
		t.Fatalf("expected pending for non-auto-approve role, got %s", req.Status)
	}
}

func TestPolicyAutoApproveRule(t *testing.T) {
	s := newTestStore(t, &Policy{
		MaxDuration: 24 * time.Hour,
		AutoApproveRules: []AutoApproveRule{{
			Name:        "viewer-staging",
			Targets:     []string{"staging-*"},
			Roles:       []string{"viewer"},
			MaxDuration: 30 * time.Minute,
		}},
		ApproverRoles: []string{"admin"},
	})

	req := makeRequest("alice", "staging-db-01", "viewer", "quick check", 15*time.Minute)
	if err := s.CreateRequest(req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Status != StatusApproved {
		t.Fatalf("expected auto-approved, got %s", req.Status)
	}
	if req.Approver != "system" {
		t.Fatalf("expected system approver, got %s", req.Approver)
	}
}

func TestMultiStageApprovalWorkflow(t *testing.T) {
	s := newTestStore(t, &Policy{
		MaxDuration: 24 * time.Hour,
		ApprovalStages: []ApprovalStage{
			{Name: "security-review", ApproverRoles: []string{"security"}},
			{Name: "admin-review", ApproverRoles: []string{"admin"}},
		},
		ApproverRoles: []string{"security", "admin"},
	})

	req := makeRequest("alice", "prod-db-01", "operator", "maintenance", time.Hour)
	if err := s.CreateRequest(req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(req.CurrentApproverRoles) != 1 || req.CurrentApproverRoles[0] != "security" {
		t.Fatalf("initial current approver roles = %#v", req.CurrentApproverRoles)
	}

	if err := s.ApproveRequestWithRole(req.ID, "sec-amy", "security"); err != nil {
		t.Fatalf("stage 1 approval error: %v", err)
	}
	if req.Status != StatusPending {
		t.Fatalf("expected request to remain pending after stage 1, got %s", req.Status)
	}
	if req.CurrentStage != 1 {
		t.Fatalf("expected current stage 1, got %d", req.CurrentStage)
	}
	if len(req.CurrentApproverRoles) != 1 || req.CurrentApproverRoles[0] != "admin" {
		t.Fatalf("next approver roles = %#v", req.CurrentApproverRoles)
	}

	if err := s.ApproveRequestWithRole(req.ID, "admin-bob", "admin"); err != nil {
		t.Fatalf("stage 2 approval error: %v", err)
	}
	if req.Status != StatusApproved {
		t.Fatalf("expected approved after final stage, got %s", req.Status)
	}
	if len(req.ApprovalHistory) != 2 {
		t.Fatalf("expected 2 approval history entries, got %d", len(req.ApprovalHistory))
	}
}

func TestMultiStageApprovalRejectsWrongRole(t *testing.T) {
	s := newTestStore(t, &Policy{
		MaxDuration: 24 * time.Hour,
		ApprovalStages: []ApprovalStage{
			{Name: "security-review", ApproverRoles: []string{"security"}},
		},
		ApproverRoles: []string{"security"},
	})

	req := makeRequest("alice", "prod-db-01", "operator", "maintenance", time.Hour)
	if err := s.CreateRequest(req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err := s.ApproveRequestWithRole(req.ID, "admin-bob", "admin")
	if !errors.Is(err, ErrApproverRoleNotAllowed) {
		t.Fatalf("ApproveRequestWithRole(wrong role) = %v, want ErrApproverRoleNotAllowed", err)
	}
}

func TestBreakGlassRequestActivatesImmediateGrant(t *testing.T) {
	s := newTestStore(t, &Policy{
		MaxDuration:           24 * time.Hour,
		BreakGlassEnabled:     true,
		BreakGlassMaxDuration: time.Hour,
		BreakGlassRoles:       []string{"operator"},
		BreakGlassTargets:     []string{"prod-*"},
		ApproverRoles:         []string{"admin"},
	})

	req := makeRequest("alice", "prod-db-01", "operator", "incident response", 30*time.Minute)
	req.BreakGlass = true
	req.Ticket = "INC-123"
	if err := s.CreateRequest(req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Status != StatusApproved {
		t.Fatalf("expected break-glass request to be approved, got %s", req.Status)
	}
	if !req.ReviewRequired {
		t.Fatal("expected break-glass request to require review")
	}
	if req.Approver != "break-glass" {
		t.Fatalf("expected break-glass approver, got %s", req.Approver)
	}
	if req.BreakGlassActivatedAt.IsZero() {
		t.Fatal("expected break_glass_activated_at to be set")
	}
}

func TestBreakGlassRequiresPolicyAndTicket(t *testing.T) {
	s := newTestStore(t, &Policy{
		MaxDuration:   24 * time.Hour,
		ApproverRoles: []string{"admin"},
	})

	req := makeRequest("alice", "prod-db-01", "operator", "incident response", 30*time.Minute)
	req.BreakGlass = true
	req.Ticket = "INC-123"
	if err := s.CreateRequest(req); err == nil {
		t.Fatal("expected break-glass disabled error")
	}

	s = newTestStore(t, &Policy{
		MaxDuration:           24 * time.Hour,
		BreakGlassEnabled:     true,
		BreakGlassMaxDuration: time.Hour,
		ApproverRoles:         []string{"admin"},
	})
	req = makeRequest("alice", "prod-db-01", "operator", "incident response", 30*time.Minute)
	req.BreakGlass = true
	if err := s.CreateRequest(req); err == nil {
		t.Fatal("expected missing ticket error")
	}
}

// --- Test: Concurrent Access ---

func TestConcurrentRequests(t *testing.T) {
	s := newTestStore(t, nil)
	var wg sync.WaitGroup
	var errCount atomic.Int32

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			req := makeRequest("user", "server", "operator", "reason", time.Hour)
			if err := s.CreateRequest(req); err != nil {
				errCount.Add(1)
			}
		}(i)
	}
	wg.Wait()

	if errCount.Load() > 0 {
		t.Fatalf("had %d concurrent errors", errCount.Load())
	}

	reqs := s.ListRequests(RequestFilter{})
	if len(reqs) != 50 {
		t.Fatalf("expected 50 requests, got %d", len(reqs))
	}
}

func TestConcurrentApproveAndCheck(t *testing.T) {
	s := newTestStore(t, nil)
	req := makeRequest("alice", "prod-db", "operator", "reason", time.Hour)
	s.CreateRequest(req)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		s.ApproveRequest(req.ID, "admin")
	}()
	go func() {
		defer wg.Done()
		// This should not panic
		s.CheckAccess("alice", "prod-db")
	}()
	wg.Wait()
}

// --- Test: Persistence ---

func TestPersistenceRoundTrip(t *testing.T) {
	dir := t.TempDir()
	policy := &Policy{
		MaxDuration:   4 * time.Hour,
		RequireReason: true,
		ApproverRoles: []string{"admin"},
	}

	s1 := NewStore(dir, policy)
	req := makeRequest("alice", "prod-db-01", "operator", "JIRA-123", time.Hour)
	s1.CreateRequest(req)
	s1.ApproveRequest(req.ID, "admin-bob")

	// Load a new store from the same directory
	s2 := NewStore(dir, nil)

	got, err := s2.GetRequest(req.ID)
	if err != nil {
		t.Fatalf("request not found after reload: %v", err)
	}
	if got.Status != StatusApproved {
		t.Fatalf("expected approved after reload, got %s", got.Status)
	}
	if got.Approver != "admin-bob" {
		t.Fatalf("expected admin-bob, got %s", got.Approver)
	}

	grant, ok := s2.CheckAccess("alice", "prod-db-01")
	if !ok {
		t.Fatal("expected grant after reload")
	}
	if grant.Role != "operator" {
		t.Fatalf("expected operator, got %s", grant.Role)
	}
}

func TestPersistencePolicy(t *testing.T) {
	dir := t.TempDir()
	policy := &Policy{
		MaxDuration:   8 * time.Hour,
		RequireReason: true,
		ApproverRoles: []string{"admin", "security"},
	}

	s1 := NewStore(dir, policy)
	// Create and save a request to trigger save
	req := makeRequest("bob", "staging", "viewer", "testing", time.Hour)
	s1.CreateRequest(req)

	s2 := NewStore(dir, nil)
	p := s2.GetPolicy()
	if p.MaxDuration != 8*time.Hour {
		t.Fatalf("expected 8h max duration, got %s", p.MaxDuration)
	}
	if !p.RequireReason {
		t.Fatal("expected RequireReason=true")
	}
}

func TestPersistenceFileCreated(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir, nil)
	req := makeRequest("alice", "server", "operator", "reason", time.Hour)
	s.CreateRequest(req)

	path := filepath.Join(dir, "jit_data.json")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatal("expected persistence file to exist")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var pd persistedData
	if err := json.Unmarshal(data, &pd); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(pd.Requests) != 1 {
		t.Fatalf("expected 1 request in file, got %d", len(pd.Requests))
	}
}

// --- Test: List with Filters ---

func TestListRequestsByStatus(t *testing.T) {
	s := newTestStore(t, nil)

	r1 := makeRequest("alice", "db-01", "operator", "reason", time.Hour)
	r2 := makeRequest("bob", "db-02", "viewer", "reason", time.Hour)
	r3 := makeRequest("carol", "db-03", "admin", "reason", time.Hour)
	s.CreateRequest(r1)
	s.CreateRequest(r2)
	s.CreateRequest(r3)
	s.ApproveRequest(r1.ID, "admin")
	s.DenyRequest(r2.ID, "admin", "nope")

	pending := s.ListRequests(RequestFilter{Status: StatusPending})
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending, got %d", len(pending))
	}
	approved := s.ListRequests(RequestFilter{Status: StatusApproved})
	if len(approved) != 1 {
		t.Fatalf("expected 1 approved, got %d", len(approved))
	}
	denied := s.ListRequests(RequestFilter{Status: StatusDenied})
	if len(denied) != 1 {
		t.Fatalf("expected 1 denied, got %d", len(denied))
	}
}

func TestListRequestsByRequester(t *testing.T) {
	s := newTestStore(t, nil)

	r1 := makeRequest("alice", "db-01", "operator", "reason", time.Hour)
	r2 := makeRequest("alice", "db-02", "viewer", "reason", time.Hour)
	r3 := makeRequest("bob", "db-01", "operator", "reason", time.Hour)
	s.CreateRequest(r1)
	s.CreateRequest(r2)
	s.CreateRequest(r3)

	result := s.ListRequests(RequestFilter{Requester: "alice"})
	if len(result) != 2 {
		t.Fatalf("expected 2 requests for alice, got %d", len(result))
	}
}

func TestListRequestsByTarget(t *testing.T) {
	s := newTestStore(t, nil)

	r1 := makeRequest("alice", "db-01", "operator", "reason", time.Hour)
	r2 := makeRequest("bob", "db-01", "viewer", "reason", time.Hour)
	r3 := makeRequest("carol", "db-02", "operator", "reason", time.Hour)
	s.CreateRequest(r1)
	s.CreateRequest(r2)
	s.CreateRequest(r3)

	result := s.ListRequests(RequestFilter{Target: "db-01"})
	if len(result) != 2 {
		t.Fatalf("expected 2 requests for db-01, got %d", len(result))
	}
}

func TestListRequestsByDateRange(t *testing.T) {
	s := newTestStore(t, nil)

	// Inject a controllable clock
	now := time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }

	r1 := makeRequest("alice", "db-01", "operator", "reason", time.Hour)
	s.CreateRequest(r1)

	now = now.Add(2 * time.Hour)
	s.now = func() time.Time { return now }
	r2 := makeRequest("bob", "db-02", "viewer", "reason", time.Hour)
	s.CreateRequest(r2)

	// Filter: only requests after the first one
	midTime := time.Date(2024, 6, 15, 13, 0, 0, 0, time.UTC)
	result := s.ListRequests(RequestFilter{Since: midTime})
	if len(result) != 1 {
		t.Fatalf("expected 1 request after midTime, got %d", len(result))
	}
	if result[0].Requester != "bob" {
		t.Fatalf("expected bob, got %s", result[0].Requester)
	}

	// Filter: only requests before midTime
	result2 := s.ListRequests(RequestFilter{Until: midTime})
	if len(result2) != 1 {
		t.Fatalf("expected 1 request before midTime, got %d", len(result2))
	}
	if result2[0].Requester != "alice" {
		t.Fatalf("expected alice, got %s", result2[0].Requester)
	}
}

func TestListRequestsCombinedFilter(t *testing.T) {
	s := newTestStore(t, nil)

	r1 := makeRequest("alice", "db-01", "operator", "reason", time.Hour)
	r2 := makeRequest("alice", "db-02", "viewer", "reason", time.Hour)
	r3 := makeRequest("bob", "db-01", "operator", "reason", time.Hour)
	s.CreateRequest(r1)
	s.CreateRequest(r2)
	s.CreateRequest(r3)
	s.ApproveRequest(r1.ID, "admin")

	result := s.ListRequests(RequestFilter{Requester: "alice", Status: StatusApproved})
	if len(result) != 1 {
		t.Fatalf("expected 1 approved alice request, got %d", len(result))
	}
}

// --- Test: GetRequest ---

func TestGetRequestNotFound(t *testing.T) {
	s := newTestStore(t, nil)
	_, err := s.GetRequest("nonexistent")
	if err == nil {
		t.Fatal("expected error for missing request")
	}
}

func TestGetRequestExists(t *testing.T) {
	s := newTestStore(t, nil)
	req := makeRequest("alice", "server", "operator", "reason", time.Hour)
	s.CreateRequest(req)

	got, err := s.GetRequest(req.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Requester != "alice" {
		t.Fatalf("expected alice, got %s", got.Requester)
	}
}

// --- Test: ListGrants ---

func TestListGrants(t *testing.T) {
	s := newTestStore(t, nil)

	r1 := makeRequest("alice", "db-01", "operator", "reason", time.Hour)
	r2 := makeRequest("bob", "db-02", "viewer", "reason", time.Hour)
	s.CreateRequest(r1)
	s.CreateRequest(r2)
	s.ApproveRequest(r1.ID, "admin")
	s.ApproveRequest(r2.ID, "admin")

	grants := s.ListGrants()
	if len(grants) != 2 {
		t.Fatalf("expected 2 grants, got %d", len(grants))
	}
}

func TestListGrantsExcludesExpired(t *testing.T) {
	s := newTestStore(t, nil)

	r1 := makeRequest("alice", "db-01", "operator", "reason", 10*time.Millisecond)
	r2 := makeRequest("bob", "db-02", "viewer", "reason", time.Hour)
	s.CreateRequest(r1)
	s.CreateRequest(r2)
	s.ApproveRequest(r1.ID, "admin")
	s.ApproveRequest(r2.ID, "admin")

	time.Sleep(20 * time.Millisecond)

	grants := s.ListGrants()
	if len(grants) != 1 {
		t.Fatalf("expected 1 active grant, got %d", len(grants))
	}
}

// --- Test: SetPolicy / GetPolicy ---

func TestSetGetPolicy(t *testing.T) {
	s := newTestStore(t, nil)

	newPolicy := &Policy{
		MaxDuration:   2 * time.Hour,
		RequireReason: true,
		ApproverRoles: []string{"admin", "security"},
	}
	if err := s.SetPolicy(newPolicy); err != nil {
		t.Fatal(err)
	}

	p := s.GetPolicy()
	if p.MaxDuration != 2*time.Hour {
		t.Fatalf("expected 2h, got %s", p.MaxDuration)
	}
	if !p.RequireReason {
		t.Fatal("expected RequireReason=true")
	}
	if len(p.ApproverRoles) != 2 {
		t.Fatalf("expected 2 approver roles, got %d", len(p.ApproverRoles))
	}
}

// --- Test: Notifier ---

func TestNotifierWebhook(t *testing.T) {
	var received atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := newTestStore(t, &Policy{
		MaxDuration:     24 * time.Hour,
		NotifyOnRequest: true,
		NotifyOnApprove: true,
		ApproverRoles:   []string{"admin"},
	})
	n, err := NewNotifier(NotifierConfig{WebhookURL: srv.URL})
	if err != nil {
		t.Fatalf("NewNotifier() error = %v", err)
	}
	s.SetNotifier(n)

	req := makeRequest("alice", "prod-db", "operator", "reason", time.Hour)
	s.CreateRequest(req)

	// Allow async notification
	time.Sleep(100 * time.Millisecond)

	if received.Load() < 1 {
		t.Fatal("expected at least 1 webhook call")
	}
}

func TestNotifierChannelPayloads(t *testing.T) {
	type capturedRequest struct {
		body string
	}
	var (
		slackReq    capturedRequest
		dingTalkReq capturedRequest
		weComReq    capturedRequest
	)
	newServer := func(target *capturedRequest) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			target.body = string(body)
			w.WriteHeader(http.StatusOK)
		}))
	}

	slackSrv := newServer(&slackReq)
	defer slackSrv.Close()
	dingTalkSrv := newServer(&dingTalkReq)
	defer dingTalkSrv.Close()
	weComSrv := newServer(&weComReq)
	defer weComSrv.Close()

	n, err := NewNotifier(NotifierConfig{
		SlackWebhookURL:    slackSrv.URL,
		DingTalkWebhookURL: dingTalkSrv.URL,
		WeComWebhookURL:    weComSrv.URL,
	})
	if err != nil {
		t.Fatalf("NewNotifier() error = %v", err)
	}

	event := &JITEvent{
		Type: "request_created",
		Request: &AccessRequest{
			ID:        "req-1",
			Requester: "alice",
			Target:    "prod-db",
			Role:      "operator",
			Status:    StatusPending,
			Duration:  time.Hour,
			Reason:    "maintenance",
		},
		Actor: "alice",
	}
	if err := n.Notify(context.Background(), event); err != nil {
		t.Fatalf("Notify() error = %v", err)
	}

	if !strings.Contains(slackReq.body, `"text"`) || !strings.Contains(slackReq.body, `alice`) {
		t.Fatalf("slack payload = %s", slackReq.body)
	}
	if !strings.Contains(dingTalkReq.body, `"msgtype":"text"`) || !strings.Contains(dingTalkReq.body, `prod-db`) {
		t.Fatalf("dingtalk payload = %s", dingTalkReq.body)
	}
	if !strings.Contains(weComReq.body, `"msgtype":"text"`) || !strings.Contains(weComReq.body, `maintenance`) {
		t.Fatalf("wecom payload = %s", weComReq.body)
	}
}

func TestNotifierEmailUsesConfiguredEnvelope(t *testing.T) {
	n, err := NewNotifier(NotifierConfig{
		SMTPAddr:  "mail.example.com:587",
		EmailFrom: "proxy@example.com",
		EmailTo:   "ops@example.com,security@example.com",
	})
	if err != nil {
		t.Fatalf("NewNotifier() error = %v", err)
	}

	var (
		gotAddr string
		gotFrom string
		gotTo   []string
		gotMsg  string
	)
	n.sendMail = func(addr string, _ smtp.Auth, from string, to []string, msg []byte) error {
		gotAddr = addr
		gotFrom = from
		gotTo = append([]string(nil), to...)
		gotMsg = string(msg)
		return nil
	}

	event := &JITEvent{
		Type: "request_approved",
		Request: &AccessRequest{
			ID:         "req-1",
			Requester:  "alice",
			Target:     "prod-db",
			Role:       "operator",
			Status:     StatusApproved,
			Duration:   time.Hour,
			ApprovedAt: time.Now().UTC(),
			ExpiresAt:  time.Now().UTC().Add(time.Hour),
		},
		Actor: "admin",
	}
	if err := n.Notify(context.Background(), event); err != nil {
		t.Fatalf("Notify() error = %v", err)
	}

	if gotAddr != "mail.example.com:587" {
		t.Fatalf("smtp addr = %q", gotAddr)
	}
	if gotFrom != "proxy@example.com" {
		t.Fatalf("from = %q", gotFrom)
	}
	if len(gotTo) != 2 || gotTo[0] != "ops@example.com" || gotTo[1] != "security@example.com" {
		t.Fatalf("to = %#v", gotTo)
	}
	if !strings.Contains(gotMsg, "Subject: [SSH Proxy] JIT request approved for prod-db") {
		t.Fatalf("email subject/message = %s", gotMsg)
	}
	if !strings.Contains(gotMsg, "Actor: admin") {
		t.Fatalf("email body missing actor: %s", gotMsg)
	}
}

// --- Test: ID generation ---

func TestGenerateID(t *testing.T) {
	id, err := generateID()
	if err != nil {
		t.Fatal(err)
	}
	if len(id) != 16 { // 8 bytes hex-encoded = 16 chars
		t.Fatalf("expected 16-char hex ID, got %d chars: %s", len(id), id)
	}
}

func TestUniqueIDs(t *testing.T) {
	s := newTestStore(t, nil)
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		req := makeRequest("alice", "server", "operator", "reason", time.Hour)
		s.CreateRequest(req)
		if ids[req.ID] {
			t.Fatalf("duplicate ID: %s", req.ID)
		}
		ids[req.ID] = true
	}
}
