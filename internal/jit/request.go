package jit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// RequestStatus represents the lifecycle state of a JIT access request.
type RequestStatus string

const (
	StatusPending  RequestStatus = "pending"
	StatusApproved RequestStatus = "approved"
	StatusDenied   RequestStatus = "denied"
	StatusExpired  RequestStatus = "expired"
	StatusRevoked  RequestStatus = "revoked"
)

// ErrApproverRoleNotAllowed is returned when the caller's role cannot approve the current stage.
var ErrApproverRoleNotAllowed = errors.New("approver role not allowed for current stage")

// ApprovalStage defines one stage in a multi-step approval workflow.
type ApprovalStage struct {
	Name              string   `json:"name,omitempty"`
	ApproverRoles     []string `json:"approver_roles"`
	RequiredApprovals int      `json:"required_approvals,omitempty"`
}

// ApprovalDecision records a stage-level approval or denial.
type ApprovalDecision struct {
	Stage        int       `json:"stage"`
	StageName    string    `json:"stage_name,omitempty"`
	Approver     string    `json:"approver"`
	ApproverRole string    `json:"approver_role,omitempty"`
	Decision     string    `json:"decision"`
	Reason       string    `json:"reason,omitempty"`
	Timestamp    time.Time `json:"timestamp"`
}

// AutoApproveRule matches requests that should skip manual approval.
type AutoApproveRule struct {
	Name        string        `json:"name,omitempty"`
	Requesters  []string      `json:"requesters,omitempty"`
	Targets     []string      `json:"targets,omitempty"`
	Roles       []string      `json:"roles,omitempty"`
	MaxDuration time.Duration `json:"max_duration,omitempty"`
}

// AccessRequest represents a JIT access request from a user.
type AccessRequest struct {
	ID                    string             `json:"id"`
	Requester             string             `json:"requester"`
	Target                string             `json:"target"`
	Role                  string             `json:"role"`
	Reason                string             `json:"reason"`
	Ticket                string             `json:"ticket,omitempty"`
	BreakGlass            bool               `json:"break_glass,omitempty"`
	Duration              time.Duration      `json:"duration"`
	Status                RequestStatus      `json:"status"`
	Approver              string             `json:"approver,omitempty"`
	ApprovalStages        []ApprovalStage    `json:"approval_stages,omitempty"`
	CurrentStage          int                `json:"current_stage,omitempty"`
	CurrentApproverRoles  []string           `json:"current_approver_roles,omitempty"`
	ApprovalHistory       []ApprovalDecision `json:"approval_history,omitempty"`
	ReviewRequired        bool               `json:"review_required,omitempty"`
	BreakGlassActivatedAt time.Time          `json:"break_glass_activated_at,omitempty"`
	CreatedAt             time.Time          `json:"created_at"`
	ApprovedAt            time.Time          `json:"approved_at,omitempty"`
	ExpiresAt             time.Time          `json:"expires_at,omitempty"`
	DeniedAt              time.Time          `json:"denied_at,omitempty"`
	DenyReason            string             `json:"deny_reason,omitempty"`
}

// Policy controls JIT access behaviour.
type Policy struct {
	MaxDuration           time.Duration     `json:"max_duration"`
	AutoApprove           bool              `json:"auto_approve"`
	AutoApproveFor        []string          `json:"auto_approve_for"`
	AutoApproveRules      []AutoApproveRule `json:"auto_approve_rules,omitempty"`
	RequireReason         bool              `json:"require_reason"`
	ApproverRoles         []string          `json:"approver_roles"`
	ApprovalStages        []ApprovalStage   `json:"approval_stages,omitempty"`
	BreakGlassEnabled     bool              `json:"break_glass_enabled,omitempty"`
	BreakGlassMaxDuration time.Duration     `json:"break_glass_max_duration,omitempty"`
	BreakGlassRoles       []string          `json:"break_glass_roles,omitempty"`
	BreakGlassTargets     []string          `json:"break_glass_targets,omitempty"`
	NotifyOnRequest       bool              `json:"notify_on_request"`
	NotifyOnApprove       bool              `json:"notify_on_approve"`
}

// AccessGrant represents an active access grant derived from an approved request.
type AccessGrant struct {
	RequestID string    `json:"request_id"`
	Username  string    `json:"username"`
	Target    string    `json:"target"`
	Role      string    `json:"role"`
	GrantedAt time.Time `json:"granted_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// RequestFilter specifies criteria for listing requests.
type RequestFilter struct {
	Status    RequestStatus
	Requester string
	Target    string
	Since     time.Time
	Until     time.Time
}

// persistedData is the JSON structure written to disk.
type persistedData struct {
	Requests []*AccessRequest `json:"requests"`
	Grants   []*AccessGrant   `json:"grants"`
	Policy   *Policy          `json:"policy"`
}

// Store manages JIT access requests and grants.
type Store struct {
	mu       sync.RWMutex
	requests map[string]*AccessRequest
	grants   map[string]*AccessGrant // keyed by "username\x00target"
	policy   *Policy
	dataDir  string
	notifier *Notifier
	now      func() time.Time // injectable clock for testing
}

// NewStore creates a new JIT store, loading any persisted state from dataDir.
func NewStore(dataDir string, policy *Policy) *Store {
	if policy == nil {
		policy = &Policy{
			MaxDuration:   24 * time.Hour,
			ApproverRoles: []string{"admin"},
		}
	}
	s := &Store{
		requests: make(map[string]*AccessRequest),
		grants:   make(map[string]*AccessGrant),
		policy:   policy,
		dataDir:  dataDir,
		now:      time.Now,
	}
	s.load()
	return s
}

// SetNotifier attaches a notifier for JIT events.
func (s *Store) SetNotifier(n *Notifier) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.notifier = n
}

// GetPolicy returns a copy of the current policy.
func (s *Store) GetPolicy() Policy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return clonePolicy(s.policy)
}

// SetPolicy replaces the current policy and persists it.
func (s *Store) SetPolicy(p *Policy) error {
	if err := validatePolicy(p); err != nil {
		return err
	}
	s.mu.Lock()
	s.policy = normalizePolicy(p)
	s.mu.Unlock()
	return s.save()
}

func clonePolicy(p *Policy) Policy {
	if p == nil {
		return Policy{}
	}
	clone := *p
	clone.AutoApproveFor = cloneStringSlice(p.AutoApproveFor)
	clone.ApproverRoles = cloneStringSlice(p.ApproverRoles)
	clone.ApprovalStages = cloneApprovalStages(p.ApprovalStages)
	clone.AutoApproveRules = cloneAutoApproveRules(p.AutoApproveRules)
	clone.BreakGlassRoles = cloneStringSlice(p.BreakGlassRoles)
	clone.BreakGlassTargets = cloneStringSlice(p.BreakGlassTargets)
	return clone
}

func cloneStringSlice(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	clone := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		clone = append(clone, value)
	}
	return clone
}

func cloneApprovalStages(stages []ApprovalStage) []ApprovalStage {
	if len(stages) == 0 {
		return nil
	}
	clone := make([]ApprovalStage, 0, len(stages))
	for _, stage := range stages {
		copied := stage
		copied.ApproverRoles = cloneStringSlice(stage.ApproverRoles)
		clone = append(clone, copied)
	}
	return clone
}

func cloneAutoApproveRules(rules []AutoApproveRule) []AutoApproveRule {
	if len(rules) == 0 {
		return nil
	}
	clone := make([]AutoApproveRule, 0, len(rules))
	for _, rule := range rules {
		copied := rule
		copied.Requesters = cloneStringSlice(rule.Requesters)
		copied.Targets = cloneStringSlice(rule.Targets)
		copied.Roles = cloneStringSlice(rule.Roles)
		clone = append(clone, copied)
	}
	return clone
}

func validatePolicy(p *Policy) error {
	if p == nil {
		return errors.New("policy is required")
	}
	for i, stage := range p.ApprovalStages {
		if len(stage.ApproverRoles) == 0 {
			return fmt.Errorf("approval stage %d must define approver_roles", i+1)
		}
		if stage.RequiredApprovals < 0 {
			return fmt.Errorf("approval stage %d required_approvals must be >= 0", i+1)
		}
	}
	for i, rule := range p.AutoApproveRules {
		if rule.MaxDuration < 0 {
			return fmt.Errorf("auto approve rule %d max_duration must be >= 0", i+1)
		}
	}
	if p.BreakGlassMaxDuration < 0 {
		return errors.New("break_glass_max_duration must be >= 0")
	}
	return nil
}

func normalizePolicy(p *Policy) *Policy {
	clone := clonePolicy(p)
	clone.ApproverRoles = normalizeStringSlice(clone.ApproverRoles)
	clone.AutoApproveFor = normalizeStringSlice(clone.AutoApproveFor)
	clone.ApprovalStages = normalizeApprovalStages(clone.ApprovalStages, clone.ApproverRoles)
	clone.AutoApproveRules = normalizeAutoApproveRules(clone.AutoApproveRules)
	clone.BreakGlassRoles = normalizeStringSlice(clone.BreakGlassRoles)
	clone.BreakGlassTargets = normalizeStringSlice(clone.BreakGlassTargets)
	if len(clone.ApproverRoles) == 0 && len(clone.ApprovalStages) > 0 {
		roleSet := map[string]struct{}{}
		for _, stage := range clone.ApprovalStages {
			for _, role := range stage.ApproverRoles {
				if _, ok := roleSet[role]; ok {
					continue
				}
				roleSet[role] = struct{}{}
				clone.ApproverRoles = append(clone.ApproverRoles, role)
			}
		}
	}
	if len(clone.ApproverRoles) == 0 {
		clone.ApproverRoles = []string{"admin"}
	}
	return &clone
}

func normalizeStringSlice(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	result := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func normalizeApprovalStages(stages []ApprovalStage, fallbackRoles []string) []ApprovalStage {
	if len(stages) == 0 {
		roles := normalizeStringSlice(fallbackRoles)
		if len(roles) == 0 {
			roles = []string{"admin"}
		}
		return []ApprovalStage{{
			Name:              "approval",
			ApproverRoles:     roles,
			RequiredApprovals: 1,
		}}
	}
	result := make([]ApprovalStage, 0, len(stages))
	for i, stage := range stages {
		roles := normalizeStringSlice(stage.ApproverRoles)
		if len(roles) == 0 {
			continue
		}
		required := stage.RequiredApprovals
		if required <= 0 {
			required = 1
		}
		name := strings.TrimSpace(stage.Name)
		if name == "" {
			name = fmt.Sprintf("stage-%d", i+1)
		}
		result = append(result, ApprovalStage{
			Name:              name,
			ApproverRoles:     roles,
			RequiredApprovals: required,
		})
	}
	if len(result) == 0 {
		return normalizeApprovalStages(nil, fallbackRoles)
	}
	return result
}

func normalizeAutoApproveRules(rules []AutoApproveRule) []AutoApproveRule {
	if len(rules) == 0 {
		return nil
	}
	result := make([]AutoApproveRule, 0, len(rules))
	for _, rule := range rules {
		result = append(result, AutoApproveRule{
			Name:        strings.TrimSpace(rule.Name),
			Requesters:  normalizeStringSlice(rule.Requesters),
			Targets:     normalizeStringSlice(rule.Targets),
			Roles:       normalizeStringSlice(rule.Roles),
			MaxDuration: rule.MaxDuration,
		})
	}
	return result
}

func grantKey(username, target string) string {
	return username + "\x00" + target
}

func generateID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate ID: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// CreateRequest validates and stores a new access request.
func (s *Store) CreateRequest(req *AccessRequest) error {
	if req.Requester == "" {
		return errors.New("requester is required")
	}
	if req.Target == "" {
		return errors.New("target is required")
	}
	if req.Role == "" {
		return errors.New("role is required")
	}
	if req.Duration <= 0 {
		return errors.New("duration must be positive")
	}

	s.mu.RLock()
	policy := normalizePolicy(s.policy)
	s.mu.RUnlock()

	if policy.RequireReason && req.Reason == "" {
		return errors.New("reason is required by policy")
	}
	if policy.MaxDuration > 0 && req.Duration > policy.MaxDuration {
		return fmt.Errorf("requested duration %s exceeds maximum %s", req.Duration, policy.MaxDuration)
	}
	if req.BreakGlass {
		if err := validateBreakGlassRequest(policy, req); err != nil {
			return err
		}
	}

	id, err := generateID()
	if err != nil {
		return err
	}
	req.ID = id
	req.Status = StatusPending
	req.CreatedAt = s.now().UTC()
	req.ApprovalStages = cloneApprovalStages(policy.ApprovalStages)
	req.CurrentStage = 0
	if len(req.ApprovalStages) > 0 {
		req.CurrentApproverRoles = cloneStringSlice(req.ApprovalStages[0].ApproverRoles)
	}

	s.mu.Lock()
	s.requests[req.ID] = req

	// Check auto-approve
	autoApprove := shouldAutoApprove(policy, req)
	s.mu.Unlock()

	if req.BreakGlass {
		if err := s.activateBreakGlass(req.ID); err != nil {
			return fmt.Errorf("break-glass activation failed: %w", err)
		}
	} else if autoApprove {
		if err := s.ApproveRequestWithRole(req.ID, "system", "system"); err != nil {
			return fmt.Errorf("auto-approve failed: %w", err)
		}
	} else {
		s.notifyAsync("request_created", req, req.Requester)
		if err := s.save(); err != nil {
			return fmt.Errorf("failed to persist request: %w", err)
		}
	}

	return nil
}

// ApproveRequest approves a pending request and creates an access grant.
func (s *Store) ApproveRequest(id, approver string) error {
	return s.ApproveRequestWithRole(id, approver, "")
}

// ApproveRequestWithRole approves the current stage for a pending request.
func (s *Store) ApproveRequestWithRole(id, approver, approverRole string) error {
	s.mu.Lock()
	req, ok := s.requests[id]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("request %s not found", id)
	}
	if req.Status != StatusPending {
		s.mu.Unlock()
		return fmt.Errorf("request %s is not pending (status: %s)", id, req.Status)
	}

	policy := normalizePolicy(s.policy)
	if len(req.ApprovalStages) == 0 {
		req.ApprovalStages = cloneApprovalStages(policy.ApprovalStages)
	}
	stage, err := currentApprovalStage(req)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	if approverRole != "" && approverRole != "system" && !roleAllowed(stage.ApproverRoles, approverRole) {
		s.mu.Unlock()
		return fmt.Errorf("%w: %s", ErrApproverRoleNotAllowed, approverRole)
	}
	if hasDecision(req, req.CurrentStage, approver, "approved") {
		s.mu.Unlock()
		return fmt.Errorf("approver %s already approved stage %d", approver, req.CurrentStage+1)
	}

	now := s.now().UTC()
	req.Approver = approver
	req.ApprovalHistory = append(req.ApprovalHistory, ApprovalDecision{
		Stage:        req.CurrentStage,
		StageName:    stage.Name,
		Approver:     approver,
		ApproverRole: approverRole,
		Decision:     "approved",
		Timestamp:    now,
	})

	eventType := ""
	if approvalsForStage(req, req.CurrentStage) >= stage.RequiredApprovals {
		if req.CurrentStage+1 < len(req.ApprovalStages) {
			req.CurrentStage++
			req.CurrentApproverRoles = cloneStringSlice(req.ApprovalStages[req.CurrentStage].ApproverRoles)
			eventType = "request_stage_advanced"
		} else {
			req.Status = StatusApproved
			req.ApprovedAt = now
			req.ExpiresAt = now.Add(req.Duration)
			req.CurrentApproverRoles = nil

			grant := &AccessGrant{
				RequestID: req.ID,
				Username:  req.Requester,
				Target:    req.Target,
				Role:      req.Role,
				GrantedAt: now,
				ExpiresAt: req.ExpiresAt,
			}
			s.grants[grantKey(req.Requester, req.Target)] = grant
			eventType = "request_approved"
		}
	}
	s.mu.Unlock()

	if eventType != "" {
		s.notifyAsync(eventType, req, approver)
	}

	if err := s.save(); err != nil {
		return fmt.Errorf("failed to persist approval: %w", err)
	}
	return nil
}

// DenyRequest denies a pending request.
func (s *Store) DenyRequest(id, approver, reason string) error {
	return s.DenyRequestWithRole(id, approver, "", reason)
}

// DenyRequestWithRole denies the current stage for a pending request.
func (s *Store) DenyRequestWithRole(id, approver, approverRole, reason string) error {
	s.mu.Lock()
	req, ok := s.requests[id]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("request %s not found", id)
	}
	if req.Status != StatusPending {
		s.mu.Unlock()
		return fmt.Errorf("request %s is not pending (status: %s)", id, req.Status)
	}

	policy := normalizePolicy(s.policy)
	if len(req.ApprovalStages) == 0 {
		req.ApprovalStages = cloneApprovalStages(policy.ApprovalStages)
	}
	stage, err := currentApprovalStage(req)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	if approverRole != "" && approverRole != "system" && !roleAllowed(stage.ApproverRoles, approverRole) {
		s.mu.Unlock()
		return fmt.Errorf("%w: %s", ErrApproverRoleNotAllowed, approverRole)
	}

	req.Status = StatusDenied
	req.Approver = approver
	req.DeniedAt = s.now().UTC()
	req.DenyReason = reason
	req.CurrentApproverRoles = nil
	req.ApprovalHistory = append(req.ApprovalHistory, ApprovalDecision{
		Stage:        req.CurrentStage,
		StageName:    stage.Name,
		Approver:     approver,
		ApproverRole: approverRole,
		Decision:     "denied",
		Reason:       reason,
		Timestamp:    req.DeniedAt,
	})
	s.mu.Unlock()

	s.notifyAsync("request_denied", req, approver)

	if err := s.save(); err != nil {
		return fmt.Errorf("failed to persist denial: %w", err)
	}
	return nil
}

func shouldAutoApprove(policy *Policy, req *AccessRequest) bool {
	for _, rule := range policy.AutoApproveRules {
		if matchesAutoApproveRule(rule, req) {
			return true
		}
	}
	if policy.AutoApprove {
		for _, role := range policy.AutoApproveFor {
			if role == req.Role {
				return true
			}
		}
	}
	return false
}

func validateBreakGlassRequest(policy *Policy, req *AccessRequest) error {
	if !policy.BreakGlassEnabled {
		return errors.New("break-glass access is not enabled")
	}
	if strings.TrimSpace(req.Reason) == "" {
		return errors.New("reason is required for break-glass access")
	}
	if strings.TrimSpace(req.Ticket) == "" {
		return errors.New("ticket is required for break-glass access")
	}
	if policy.BreakGlassMaxDuration > 0 && req.Duration > policy.BreakGlassMaxDuration {
		return fmt.Errorf("break-glass duration %s exceeds maximum %s", req.Duration, policy.BreakGlassMaxDuration)
	}
	if len(policy.BreakGlassRoles) > 0 && !matchesAnyPattern(policy.BreakGlassRoles, req.Role) {
		return fmt.Errorf("role %s is not eligible for break-glass access", req.Role)
	}
	if len(policy.BreakGlassTargets) > 0 && !matchesAnyPattern(policy.BreakGlassTargets, req.Target) {
		return fmt.Errorf("target %s is not eligible for break-glass access", req.Target)
	}
	return nil
}

func (s *Store) activateBreakGlass(id string) error {
	s.mu.Lock()
	req, ok := s.requests[id]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("request %s not found", id)
	}
	if !req.BreakGlass {
		s.mu.Unlock()
		return fmt.Errorf("request %s is not a break-glass request", id)
	}
	if req.Status != StatusPending {
		s.mu.Unlock()
		return fmt.Errorf("request %s is not pending (status: %s)", id, req.Status)
	}

	now := s.now().UTC()
	req.Status = StatusApproved
	req.Approver = "break-glass"
	req.ApprovedAt = now
	req.ExpiresAt = now.Add(req.Duration)
	req.ReviewRequired = true
	req.BreakGlassActivatedAt = now
	req.CurrentApproverRoles = nil
	req.ApprovalHistory = append(req.ApprovalHistory, ApprovalDecision{
		Stage:     0,
		StageName: "break-glass",
		Approver:  "break-glass",
		Decision:  "break_glass",
		Reason:    req.Ticket,
		Timestamp: now,
	})
	grant := &AccessGrant{
		RequestID: req.ID,
		Username:  req.Requester,
		Target:    req.Target,
		Role:      req.Role,
		GrantedAt: now,
		ExpiresAt: req.ExpiresAt,
	}
	s.grants[grantKey(req.Requester, req.Target)] = grant
	s.mu.Unlock()

	s.notifyAsync("request_break_glass", req, req.Requester)

	if err := s.save(); err != nil {
		return fmt.Errorf("failed to persist break-glass approval: %w", err)
	}
	return nil
}

func matchesAutoApproveRule(rule AutoApproveRule, req *AccessRequest) bool {
	if len(rule.Requesters) > 0 && !matchesAnyPattern(rule.Requesters, req.Requester) {
		return false
	}
	if len(rule.Targets) > 0 && !matchesAnyPattern(rule.Targets, req.Target) {
		return false
	}
	if len(rule.Roles) > 0 && !matchesAnyPattern(rule.Roles, req.Role) {
		return false
	}
	if rule.MaxDuration > 0 && req.Duration > rule.MaxDuration {
		return false
	}
	return true
}

func matchesAnyPattern(patterns []string, value string) bool {
	for _, patternValue := range patterns {
		if patternValue == value {
			return true
		}
		matched, err := path.Match(patternValue, value)
		if err == nil && matched {
			return true
		}
	}
	return false
}

func currentApprovalStage(req *AccessRequest) (ApprovalStage, error) {
	if len(req.ApprovalStages) == 0 {
		return ApprovalStage{}, errors.New("request approval workflow is not configured")
	}
	if req.CurrentStage < 0 || req.CurrentStage >= len(req.ApprovalStages) {
		return ApprovalStage{}, fmt.Errorf("request current stage %d is invalid", req.CurrentStage)
	}
	if len(req.CurrentApproverRoles) == 0 {
		req.CurrentApproverRoles = cloneStringSlice(req.ApprovalStages[req.CurrentStage].ApproverRoles)
	}
	return req.ApprovalStages[req.CurrentStage], nil
}

func roleAllowed(roles []string, role string) bool {
	for _, candidate := range roles {
		if candidate == role {
			return true
		}
	}
	return false
}

func hasDecision(req *AccessRequest, stage int, approver, decision string) bool {
	for _, item := range req.ApprovalHistory {
		if item.Stage == stage && item.Approver == approver && item.Decision == decision {
			return true
		}
	}
	return false
}

func approvalsForStage(req *AccessRequest, stage int) int {
	count := 0
	for _, item := range req.ApprovalHistory {
		if item.Stage == stage && item.Decision == "approved" {
			count++
		}
	}
	return count
}

// RevokeRequest revokes an approved request and removes its grant.
func (s *Store) RevokeRequest(id, revoker string) error {
	s.mu.Lock()
	req, ok := s.requests[id]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("request %s not found", id)
	}
	if req.Status != StatusApproved {
		s.mu.Unlock()
		return fmt.Errorf("request %s is not approved (status: %s)", id, req.Status)
	}

	req.Status = StatusRevoked
	delete(s.grants, grantKey(req.Requester, req.Target))
	s.mu.Unlock()

	s.notifyAsync("request_revoked", req, revoker)

	if err := s.save(); err != nil {
		return fmt.Errorf("failed to persist revocation: %w", err)
	}
	return nil
}

// GetRequest returns a request by ID.
func (s *Store) GetRequest(id string) (*AccessRequest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	req, ok := s.requests[id]
	if !ok {
		return nil, fmt.Errorf("request %s not found", id)
	}
	return req, nil
}

// ListRequests returns requests matching the given filter.
func (s *Store) ListRequests(filter RequestFilter) []*AccessRequest {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*AccessRequest
	for _, req := range s.requests {
		if filter.Status != "" && req.Status != filter.Status {
			continue
		}
		if filter.Requester != "" && req.Requester != filter.Requester {
			continue
		}
		if filter.Target != "" && req.Target != filter.Target {
			continue
		}
		if !filter.Since.IsZero() && req.CreatedAt.Before(filter.Since) {
			continue
		}
		if !filter.Until.IsZero() && req.CreatedAt.After(filter.Until) {
			continue
		}
		result = append(result, req)
	}
	return result
}

// ListGrants returns all currently active (non-expired) grants.
func (s *Store) ListGrants() []*AccessGrant {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := s.now().UTC()
	var result []*AccessGrant
	for _, g := range s.grants {
		if now.Before(g.ExpiresAt) {
			result = append(result, g)
		}
	}
	return result
}

// CheckAccess checks whether a user currently has an active grant for a target.
func (s *Store) CheckAccess(username, target string) (*AccessGrant, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	grant, ok := s.grants[grantKey(username, target)]
	if !ok {
		return nil, false
	}
	if s.now().UTC().After(grant.ExpiresAt) {
		return nil, false
	}
	return grant, true
}

// CleanExpired removes expired grants and marks their requests as expired.
// Returns the number of grants removed.
func (s *Store) CleanExpired() int {
	s.mu.Lock()

	now := s.now().UTC()
	count := 0
	var expiredReqs []*AccessRequest

	for key, grant := range s.grants {
		if now.After(grant.ExpiresAt) {
			delete(s.grants, key)
			count++
			if req, ok := s.requests[grant.RequestID]; ok {
				req.Status = StatusExpired
				expiredReqs = append(expiredReqs, req)
			}
		}
	}
	s.mu.Unlock()

	for _, req := range expiredReqs {
		s.notifyAsync("grant_expired", req, "system")
	}

	if count > 0 {
		s.save()
	}
	return count
}

// StartCleanupLoop runs periodic cleanup of expired grants.
func (s *Store) StartCleanupLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.CleanExpired()
		}
	}
}

func (s *Store) notifyAsync(eventType string, req *AccessRequest, actor string) {
	s.mu.RLock()
	n := s.notifier
	policy := s.policy
	s.mu.RUnlock()

	if n == nil {
		return
	}

	shouldNotify := false
	switch eventType {
	case "request_created", "request_stage_advanced":
		shouldNotify = policy.NotifyOnRequest
	case "request_approved":
		shouldNotify = policy.NotifyOnApprove
	case "request_break_glass":
		shouldNotify = true
	default:
		shouldNotify = true
	}

	if shouldNotify {
		go func() {
			if err := n.Notify(context.Background(), &JITEvent{
				Type:    eventType,
				Request: req,
				Actor:   actor,
			}); err != nil {
				log.Printf("jit: notify %s: %v", eventType, err)
			}
		}()
	}
}

// persistence

func (s *Store) filePath() string {
	return filepath.Join(s.dataDir, "jit_data.json")
}

func (s *Store) save() error {
	if s.dataDir == "" {
		return nil
	}

	s.mu.RLock()
	data := persistedData{
		Policy: s.policy,
	}
	for _, r := range s.requests {
		data.Requests = append(data.Requests, r)
	}
	for _, g := range s.grants {
		data.Grants = append(data.Grants, g)
	}
	s.mu.RUnlock()

	raw, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	if err := os.MkdirAll(s.dataDir, 0755); err != nil {
		return err
	}
	return os.WriteFile(s.filePath(), raw, 0600)
}

func (s *Store) load() {
	if s.dataDir == "" {
		return
	}
	raw, err := os.ReadFile(s.filePath())
	if err != nil {
		return
	}
	var data persistedData
	if err := json.Unmarshal(raw, &data); err != nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if data.Policy != nil {
		s.policy = data.Policy
	}
	for _, r := range data.Requests {
		s.requests[r.ID] = r
	}
	for _, g := range data.Grants {
		s.grants[grantKey(g.Username, g.Target)] = g
	}
}
