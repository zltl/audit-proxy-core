package jit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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

// AccessRequest represents a JIT access request from a user.
type AccessRequest struct {
	ID         string        `json:"id"`
	Requester  string        `json:"requester"`
	Target     string        `json:"target"`
	Role       string        `json:"role"`
	Reason     string        `json:"reason"`
	Duration   time.Duration `json:"duration"`
	Status     RequestStatus `json:"status"`
	Approver   string        `json:"approver,omitempty"`
	CreatedAt  time.Time     `json:"created_at"`
	ApprovedAt time.Time     `json:"approved_at,omitempty"`
	ExpiresAt  time.Time     `json:"expires_at,omitempty"`
	DeniedAt   time.Time     `json:"denied_at,omitempty"`
	DenyReason string        `json:"deny_reason,omitempty"`
}

// Policy controls JIT access behaviour.
type Policy struct {
	MaxDuration     time.Duration `json:"max_duration"`
	AutoApprove     bool          `json:"auto_approve"`
	AutoApproveFor  []string      `json:"auto_approve_for"`
	RequireReason   bool          `json:"require_reason"`
	ApproverRoles   []string      `json:"approver_roles"`
	NotifyOnRequest bool          `json:"notify_on_request"`
	NotifyOnApprove bool          `json:"notify_on_approve"`
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
	return *s.policy
}

// SetPolicy replaces the current policy and persists it.
func (s *Store) SetPolicy(p *Policy) error {
	s.mu.Lock()
	s.policy = p
	s.mu.Unlock()
	return s.save()
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
	policy := s.policy
	s.mu.RUnlock()

	if policy.RequireReason && req.Reason == "" {
		return errors.New("reason is required by policy")
	}
	if policy.MaxDuration > 0 && req.Duration > policy.MaxDuration {
		return fmt.Errorf("requested duration %s exceeds maximum %s", req.Duration, policy.MaxDuration)
	}

	id, err := generateID()
	if err != nil {
		return err
	}
	req.ID = id
	req.Status = StatusPending
	req.CreatedAt = s.now().UTC()

	s.mu.Lock()
	s.requests[req.ID] = req

	// Check auto-approve
	autoApprove := false
	if policy.AutoApprove {
		for _, role := range policy.AutoApproveFor {
			if role == req.Role {
				autoApprove = true
				break
			}
		}
	}
	s.mu.Unlock()

	if autoApprove {
		if err := s.ApproveRequest(req.ID, "system"); err != nil {
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

	now := s.now().UTC()
	req.Status = StatusApproved
	req.Approver = approver
	req.ApprovedAt = now
	req.ExpiresAt = now.Add(req.Duration)

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

	s.notifyAsync("request_approved", req, approver)

	if err := s.save(); err != nil {
		return fmt.Errorf("failed to persist approval: %w", err)
	}
	return nil
}

// DenyRequest denies a pending request.
func (s *Store) DenyRequest(id, approver, reason string) error {
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

	req.Status = StatusDenied
	req.Approver = approver
	req.DeniedAt = s.now().UTC()
	req.DenyReason = reason
	s.mu.Unlock()

	s.notifyAsync("request_denied", req, approver)

	if err := s.save(); err != nil {
		return fmt.Errorf("failed to persist denial: %w", err)
	}
	return nil
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
	case "request_created":
		shouldNotify = policy.NotifyOnRequest
	case "request_approved":
		shouldNotify = policy.NotifyOnApprove
	default:
		shouldNotify = true
	}

	if shouldNotify {
		go n.Notify(context.Background(), &JITEvent{
			Type:    eventType,
			Request: req,
			Actor:   actor,
		})
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
