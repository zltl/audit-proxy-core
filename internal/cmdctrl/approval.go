package cmdctrl

import (
	"fmt"
	"sync"
	"time"
)

// ApprovalRequest tracks a command that requires real-time approval.
type ApprovalRequest struct {
	ID        string    `json:"id"`
	SessionID string    `json:"session_id"`
	Username  string    `json:"username"`
	Command   string    `json:"command"`
	Target    string    `json:"target"`
	RuleID    string    `json:"rule_id"`
	Status    string    `json:"status"` // pending, approved, denied, expired
	Approver  string    `json:"approver,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	DecidedAt time.Time `json:"decided_at,omitempty"`
}

// ApprovalManager handles real-time command approval workflows.
type ApprovalManager struct {
	requests   map[string]*ApprovalRequest
	mu         sync.RWMutex
	timeout    time.Duration
	webhookURL string
	// channels maps request IDs to notification channels that unblock waiters.
	channels map[string]chan struct{}
}

// NewApprovalManager creates an ApprovalManager with the given timeout and optional webhook URL.
func NewApprovalManager(timeout time.Duration, webhookURL string) *ApprovalManager {
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	return &ApprovalManager{
		requests:   make(map[string]*ApprovalRequest),
		timeout:    timeout,
		webhookURL: webhookURL,
		channels:   make(map[string]chan struct{}),
	}
}

// RequestApproval submits a new approval request.
func (am *ApprovalManager) RequestApproval(req *ApprovalRequest) error {
	if req.ID == "" {
		return fmt.Errorf("approval request ID is required")
	}

	am.mu.Lock()
	defer am.mu.Unlock()

	if _, exists := am.requests[req.ID]; exists {
		return fmt.Errorf("approval request %s already exists", req.ID)
	}

	req.Status = "pending"
	req.CreatedAt = time.Now()
	req.ExpiresAt = req.CreatedAt.Add(am.timeout)
	am.requests[req.ID] = req
	am.channels[req.ID] = make(chan struct{})

	return nil
}

// Approve marks a pending request as approved.
func (am *ApprovalManager) Approve(id, approver string) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	req, ok := am.requests[id]
	if !ok {
		return fmt.Errorf("approval request %s not found", id)
	}
	if req.Status != "pending" {
		return fmt.Errorf("approval request %s is not pending (status: %s)", id, req.Status)
	}
	if time.Now().After(req.ExpiresAt) {
		req.Status = "expired"
		am.notifyLocked(id)
		return fmt.Errorf("approval request %s has expired", id)
	}

	req.Status = "approved"
	req.Approver = approver
	req.DecidedAt = time.Now()
	am.notifyLocked(id)
	return nil
}

// Deny marks a pending request as denied.
func (am *ApprovalManager) Deny(id, approver string) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	req, ok := am.requests[id]
	if !ok {
		return fmt.Errorf("approval request %s not found", id)
	}
	if req.Status != "pending" {
		return fmt.Errorf("approval request %s is not pending (status: %s)", id, req.Status)
	}

	req.Status = "denied"
	req.Approver = approver
	req.DecidedAt = time.Now()
	am.notifyLocked(id)
	return nil
}

// notifyLocked closes the channel for a request to unblock any waiter.
// Must be called with am.mu held.
func (am *ApprovalManager) notifyLocked(id string) {
	if ch, ok := am.channels[id]; ok {
		select {
		case <-ch:
			// already closed
		default:
			close(ch)
		}
	}
}

// WaitForDecision blocks until the request is decided or the timeout elapses.
func (am *ApprovalManager) WaitForDecision(id string, timeout time.Duration) (*ApprovalRequest, error) {
	am.mu.RLock()
	req, ok := am.requests[id]
	if !ok {
		am.mu.RUnlock()
		return nil, fmt.Errorf("approval request %s not found", id)
	}
	ch, chOk := am.channels[id]
	am.mu.RUnlock()

	if !chOk {
		return nil, fmt.Errorf("no channel for approval request %s", id)
	}

	// If already decided, return immediately.
	if req.Status != "pending" {
		return req, nil
	}

	if timeout <= 0 {
		timeout = am.timeout
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-ch:
		am.mu.RLock()
		result := am.requests[id]
		am.mu.RUnlock()
		return result, nil
	case <-timer.C:
		am.mu.Lock()
		r := am.requests[id]
		if r.Status == "pending" {
			r.Status = "expired"
			am.notifyLocked(id)
		}
		am.mu.Unlock()
		return r, fmt.Errorf("approval request %s timed out", id)
	}
}

// GetPending returns all pending approval requests.
func (am *ApprovalManager) GetPending() []*ApprovalRequest {
	am.mu.RLock()
	defer am.mu.RUnlock()

	var pending []*ApprovalRequest
	now := time.Now()
	for _, req := range am.requests {
		if req.Status == "pending" && now.Before(req.ExpiresAt) {
			pending = append(pending, req)
		}
	}
	return pending
}

// CleanExpired marks expired pending requests and removes old decided requests.
// Returns the number of requests cleaned.
func (am *ApprovalManager) CleanExpired() int {
	am.mu.Lock()
	defer am.mu.Unlock()

	count := 0
	now := time.Now()
	for id, req := range am.requests {
		if req.Status == "pending" && now.After(req.ExpiresAt) {
			req.Status = "expired"
			am.notifyLocked(id)
			count++
		}
	}
	return count
}
