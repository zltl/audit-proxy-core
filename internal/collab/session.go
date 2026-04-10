package collab

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// ParticipantRole defines the level of access a participant has.
type ParticipantRole string

const (
	RoleOwner    ParticipantRole = "owner"
	RoleOperator ParticipantRole = "operator"
	RoleViewer   ParticipantRole = "viewer"
)

// Participant represents a user in a shared session.
type Participant struct {
	ID         string          `json:"id"`
	Username   string          `json:"username"`
	Role       ParticipantRole `json:"role"`
	JoinedAt   time.Time       `json:"joined_at"`
	LastActive time.Time       `json:"last_active"`
}

// SessionAction identifies a privileged collaboration action that may require
// four-eyes approval before it is executed.
type SessionAction string

const (
	SessionActionGrantControl  SessionAction = "grant_control"
	SessionActionRevokeControl SessionAction = "revoke_control"
	SessionActionEndSession    SessionAction = "end_session"
)

// SessionActionApproval tracks a privileged action waiting for a second
// participant to approve it while both are present.
type SessionActionApproval struct {
	ID             string        `json:"id"`
	SessionID      string        `json:"session_id"`
	Action         SessionAction `json:"action"`
	RequestedBy    string        `json:"requested_by"`
	TargetUsername string        `json:"target_username,omitempty"`
	Status         string        `json:"status"`
	RequestedAt    time.Time     `json:"requested_at"`
	ExpiresAt      time.Time     `json:"expires_at"`
	Approver       string        `json:"approver,omitempty"`
	DecidedAt      time.Time     `json:"decided_at,omitempty"`
}

// SessionOptions captures optional collaboration session behavior.
type SessionOptions struct {
	MaxViewers       int
	AllowControl     bool
	FourEyesRequired bool
}

// SharedSession represents a collaborative terminal session.
type SharedSession struct {
	ID               string         `json:"id"`
	SessionID        string         `json:"session_id"`
	Owner            string         `json:"owner"`
	Target           string         `json:"target"`
	CreatedAt        time.Time      `json:"created_at"`
	Participants     []*Participant `json:"participants"`
	MaxViewers       int            `json:"max_viewers"`
	AllowControl     bool           `json:"allow_control"`
	FourEyesRequired bool           `json:"four_eyes_required"`
	Status           string         `json:"status"`
	mu               sync.RWMutex
	broadcast        chan []byte
	subscribers      map[string]chan []byte
	approvals        []*SessionActionApproval
}

// Manager manages all shared sessions.
type Manager struct {
	sessions        map[string]*SharedSession
	approvalTimeout time.Duration
	mu              sync.RWMutex
}

func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// NewManager creates a new collaboration Manager.
func NewManager() *Manager {
	return &Manager{
		sessions:        make(map[string]*SharedSession),
		approvalTimeout: 5 * time.Minute,
	}
}

// CreateSession creates a new shared session.
func (m *Manager) CreateSession(sessionID, owner, target string, maxViewers int, allowControl bool) (*SharedSession, error) {
	return m.CreateSessionWithOptions(sessionID, owner, target, SessionOptions{
		MaxViewers:   maxViewers,
		AllowControl: allowControl,
	})
}

// CreateSessionWithOptions creates a new shared session with optional
// collaboration policy settings.
func (m *Manager) CreateSessionWithOptions(sessionID, owner, target string, opts SessionOptions) (*SharedSession, error) {
	if sessionID == "" {
		return nil, errors.New("session_id is required")
	}
	if owner == "" {
		return nil, errors.New("owner is required")
	}

	now := time.Now()
	ownerParticipant := &Participant{
		ID:         generateID(),
		Username:   owner,
		Role:       RoleOwner,
		JoinedAt:   now,
		LastActive: now,
	}

	s := &SharedSession{
		ID:               generateID(),
		SessionID:        sessionID,
		Owner:            owner,
		Target:           target,
		CreatedAt:        now,
		Participants:     []*Participant{ownerParticipant},
		MaxViewers:       opts.MaxViewers,
		AllowControl:     opts.AllowControl,
		FourEyesRequired: opts.FourEyesRequired,
		Status:           "active",
		broadcast:        make(chan []byte, 256),
		subscribers:      make(map[string]chan []byte),
	}

	ownerCh := make(chan []byte, 256)
	s.subscribers[owner] = ownerCh

	m.mu.Lock()
	m.sessions[s.ID] = s
	m.mu.Unlock()

	return s, nil
}

// GetSession returns a shared session by ID.
func (m *Manager) GetSession(id string) (*SharedSession, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	s, ok := m.sessions[id]
	if !ok {
		return nil, errors.New("session not found")
	}
	return s, nil
}

// ListSessions returns all shared sessions.
func (m *Manager) ListSessions() []*SharedSession {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*SharedSession, 0, len(m.sessions))
	for _, s := range m.sessions {
		result = append(result, s)
	}
	return result
}

// JoinSession adds a user to an existing shared session.
func (m *Manager) JoinSession(sessionID, username string, role ParticipantRole) error {
	s, err := m.GetSession(sessionID)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.Status != "active" {
		return errors.New("session is not active")
	}

	// Check if user already joined
	for _, p := range s.Participants {
		if p.Username == username {
			return errors.New("user already in session")
		}
	}

	// Check max viewers for viewer role
	if role == RoleViewer && s.MaxViewers > 0 {
		viewerCount := 0
		for _, p := range s.Participants {
			if p.Role == RoleViewer {
				viewerCount++
			}
		}
		if viewerCount >= s.MaxViewers {
			return errors.New("maximum viewers reached")
		}
	}

	// Disallow joining as owner
	if role == RoleOwner {
		return errors.New("cannot join as owner")
	}

	now := time.Now()
	p := &Participant{
		ID:         generateID(),
		Username:   username,
		Role:       role,
		JoinedAt:   now,
		LastActive: now,
	}
	s.Participants = append(s.Participants, p)

	ch := make(chan []byte, 256)
	s.subscribers[username] = ch

	return nil
}

// LeaveSession removes a user from a shared session.
func (m *Manager) LeaveSession(sessionID, username string) error {
	s, err := m.GetSession(sessionID)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	found := false
	filtered := make([]*Participant, 0, len(s.Participants))
	for _, p := range s.Participants {
		if p.Username == username {
			found = true
			continue
		}
		filtered = append(filtered, p)
	}

	if !found {
		return errors.New("user not in session")
	}

	s.Participants = filtered

	if ch, ok := s.subscribers[username]; ok {
		delete(s.subscribers, username)
		select {
		case <-ch:
			// already closed
		default:
			close(ch)
		}
	}

	return nil
}

// EndSession ends a shared session and cleans up all subscriber channels.
func (m *Manager) EndSession(id string) error {
	s, err := m.GetSession(id)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.FourEyesRequired {
		return errors.New("four-eyes approval required before ending the session")
	}

	s.endSessionLocked()
	return nil
}

// Broadcast sends data to all participants of a session.
func (m *Manager) Broadcast(sessionID string, data []byte) error {
	s, err := m.GetSession(sessionID)
	if err != nil {
		return err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.Status != "active" {
		return errors.New("session is not active")
	}

	msg := make([]byte, len(data))
	copy(msg, data)

	for _, ch := range s.subscribers {
		select {
		case ch <- msg:
		default:
			// channel full, drop message to avoid blocking
		}
	}

	return nil
}

// Subscribe returns a read-only channel for receiving session data.
func (m *Manager) Subscribe(sessionID, username string) (<-chan []byte, error) {
	s, err := m.GetSession(sessionID)
	if err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	ch, ok := s.subscribers[username]
	if !ok {
		return nil, errors.New("user not in session")
	}

	return ch, nil
}

// RequestControl allows a viewer to request typing control (promoted to operator).
func (m *Manager) RequestControl(sessionID, username string) error {
	s, err := m.GetSession(sessionID)
	if err != nil {
		return err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.AllowControl {
		return errors.New("control sharing is not allowed for this session")
	}

	found := false
	for _, p := range s.Participants {
		if p.Username == username {
			if p.Role == RoleOwner || p.Role == RoleOperator {
				return errors.New("user already has control")
			}
			found = true
			break
		}
	}

	if !found {
		return errors.New("user not in session")
	}

	return nil
}

// GrantControl grants typing control to a participant (owner only).
func (m *Manager) GrantControl(sessionID, ownerUsername, targetUsername string) error {
	s, err := m.GetSession(sessionID)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.FourEyesRequired {
		return errors.New("four-eyes approval required before granting control")
	}

	return s.grantControlLocked(ownerUsername, targetUsername)
}

// RevokeControl revokes typing control from a participant (owner only).
func (m *Manager) RevokeControl(sessionID, ownerUsername, targetUsername string) error {
	s, err := m.GetSession(sessionID)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.FourEyesRequired {
		return errors.New("four-eyes approval required before revoking control")
	}

	return s.revokeControlLocked(ownerUsername, targetUsername)
}

// ListActionApprovals returns all recorded action approvals for a shared
// session, including approved, denied, and expired requests.
func (m *Manager) ListActionApprovals(sessionID string) ([]*SessionActionApproval, error) {
	s, err := m.GetSession(sessionID)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.cleanupExpiredApprovalsLocked(time.Now())

	approvals := make([]*SessionActionApproval, 0, len(s.approvals))
	for _, approval := range s.approvals {
		approvals = append(approvals, cloneSessionActionApproval(approval))
	}
	return approvals, nil
}

// RequestActionApproval creates or reuses a pending four-eyes approval for a
// privileged collaboration action.
func (m *Manager) RequestActionApproval(sessionID, requester string, action SessionAction, targetUsername string) (*SessionActionApproval, error) {
	s, err := m.GetSession(sessionID)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.FourEyesRequired {
		return nil, errors.New("four-eyes approval is not enabled for this session")
	}

	now := time.Now()
	s.cleanupExpiredApprovalsLocked(now)

	if !s.hasParticipantLocked(requester) {
		return nil, errors.New("requester must be present in the session")
	}
	if !s.hasOtherParticipantLocked(requester) {
		return nil, errors.New("four-eyes requires another participant to be present")
	}
	if err := s.validateActionRequestLocked(action, requester, targetUsername); err != nil {
		return nil, err
	}
	if existing := s.findMatchingPendingApprovalLocked(action, requester, targetUsername); existing != nil {
		return cloneSessionActionApproval(existing), nil
	}

	approval := &SessionActionApproval{
		ID:             generateID(),
		SessionID:      s.ID,
		Action:         action,
		RequestedBy:    requester,
		TargetUsername: targetUsername,
		Status:         "pending",
		RequestedAt:    now,
		ExpiresAt:      now.Add(m.approvalTimeout),
	}
	s.approvals = append(s.approvals, approval)
	return cloneSessionActionApproval(approval), nil
}

// ApproveAction approves a pending four-eyes action and executes it.
func (m *Manager) ApproveAction(sessionID, approvalID, approver string) (*SessionActionApproval, error) {
	s, err := m.GetSession(sessionID)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	s.cleanupExpiredApprovalsLocked(now)

	approval := s.findApprovalLocked(approvalID)
	if approval == nil {
		return nil, errors.New("approval not found")
	}
	if approval.Status != "pending" {
		return nil, errors.New("approval is not pending")
	}
	if approval.RequestedBy == approver {
		return nil, errors.New("requester cannot decide their own four-eyes action")
	}
	if !s.hasParticipantLocked(approver) {
		return nil, errors.New("approver must be present in the session")
	}
	if !s.hasParticipantLocked(approval.RequestedBy) {
		return nil, errors.New("requester must remain present in the session")
	}
	if !s.hasOtherParticipantLocked(approval.RequestedBy) {
		return nil, errors.New("four-eyes requires another participant to be present")
	}
	if err := s.validateActionRequestLocked(approval.Action, approval.RequestedBy, approval.TargetUsername); err != nil {
		return nil, err
	}

	approval.Status = "approved"
	approval.Approver = approver
	approval.DecidedAt = now
	if err := s.executeApprovedActionLocked(approval); err != nil {
		approval.Status = "pending"
		approval.Approver = ""
		approval.DecidedAt = time.Time{}
		return nil, err
	}
	return cloneSessionActionApproval(approval), nil
}

// DenyAction rejects a pending four-eyes action without executing it.
func (m *Manager) DenyAction(sessionID, approvalID, approver string) (*SessionActionApproval, error) {
	s, err := m.GetSession(sessionID)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	s.cleanupExpiredApprovalsLocked(now)

	approval := s.findApprovalLocked(approvalID)
	if approval == nil {
		return nil, errors.New("approval not found")
	}
	if approval.Status != "pending" {
		return nil, errors.New("approval is not pending")
	}
	if approval.RequestedBy == approver {
		return nil, errors.New("requester cannot decide their own four-eyes action")
	}
	if !s.hasParticipantLocked(approver) {
		return nil, errors.New("approver must be present in the session")
	}
	if !s.hasParticipantLocked(approval.RequestedBy) {
		return nil, errors.New("requester must remain present in the session")
	}

	approval.Status = "denied"
	approval.Approver = approver
	approval.DecidedAt = now
	return cloneSessionActionApproval(approval), nil
}

func cloneSessionActionApproval(approval *SessionActionApproval) *SessionActionApproval {
	if approval == nil {
		return nil
	}
	cloned := *approval
	return &cloned
}

func (s *SharedSession) hasParticipantLocked(username string) bool {
	for _, p := range s.Participants {
		if p.Username == username {
			return true
		}
	}
	return false
}

func (s *SharedSession) hasOtherParticipantLocked(username string) bool {
	for _, p := range s.Participants {
		if p.Username != username {
			return true
		}
	}
	return false
}

func (s *SharedSession) validateGrantControlLocked(ownerUsername, targetUsername string) error {
	if s.Status != "active" {
		return errors.New("session is not active")
	}
	if s.Owner != ownerUsername {
		return errors.New("only the session owner can grant control")
	}
	if !s.AllowControl {
		return errors.New("control sharing is not allowed for this session")
	}
	for _, p := range s.Participants {
		if p.Username == targetUsername {
			if p.Role == RoleOwner {
				return errors.New("owner already has control")
			}
			return nil
		}
	}
	return errors.New("target user not in session")
}

func (s *SharedSession) grantControlLocked(ownerUsername, targetUsername string) error {
	if err := s.validateGrantControlLocked(ownerUsername, targetUsername); err != nil {
		return err
	}
	for _, p := range s.Participants {
		if p.Username == targetUsername {
			p.Role = RoleOperator
			return nil
		}
	}
	return errors.New("target user not in session")
}

func (s *SharedSession) validateRevokeControlLocked(ownerUsername, targetUsername string) error {
	if s.Status != "active" {
		return errors.New("session is not active")
	}
	if s.Owner != ownerUsername {
		return errors.New("only the session owner can revoke control")
	}
	for _, p := range s.Participants {
		if p.Username == targetUsername {
			if p.Role == RoleOwner {
				return errors.New("cannot revoke control from owner")
			}
			return nil
		}
	}
	return errors.New("target user not in session")
}

func (s *SharedSession) revokeControlLocked(ownerUsername, targetUsername string) error {
	if err := s.validateRevokeControlLocked(ownerUsername, targetUsername); err != nil {
		return err
	}
	for _, p := range s.Participants {
		if p.Username == targetUsername {
			p.Role = RoleViewer
			return nil
		}
	}
	return errors.New("target user not in session")
}

func (s *SharedSession) validateEndSessionLocked(ownerUsername string) error {
	if s.Status != "active" {
		return errors.New("session is not active")
	}
	if s.Owner != ownerUsername {
		return errors.New("only the session owner can end the session")
	}
	return nil
}

func (s *SharedSession) endSessionLocked() {
	now := time.Now()
	s.Status = "ended"
	for _, approval := range s.approvals {
		if approval.Status == "pending" {
			approval.Status = "expired"
			approval.DecidedAt = now
		}
	}
	for username, ch := range s.subscribers {
		delete(s.subscribers, username)
		select {
		case <-ch:
			// already closed
		default:
			close(ch)
		}
	}
}

func (s *SharedSession) validateActionRequestLocked(action SessionAction, requester, targetUsername string) error {
	switch action {
	case SessionActionGrantControl:
		return s.validateGrantControlLocked(requester, targetUsername)
	case SessionActionRevokeControl:
		return s.validateRevokeControlLocked(requester, targetUsername)
	case SessionActionEndSession:
		return s.validateEndSessionLocked(requester)
	default:
		return errors.New("unsupported four-eyes action")
	}
}

func (s *SharedSession) executeApprovedActionLocked(approval *SessionActionApproval) error {
	switch approval.Action {
	case SessionActionGrantControl:
		return s.grantControlLocked(approval.RequestedBy, approval.TargetUsername)
	case SessionActionRevokeControl:
		return s.revokeControlLocked(approval.RequestedBy, approval.TargetUsername)
	case SessionActionEndSession:
		if err := s.validateEndSessionLocked(approval.RequestedBy); err != nil {
			return err
		}
		s.endSessionLocked()
		return nil
	default:
		return errors.New("unsupported four-eyes action")
	}
}

func (s *SharedSession) findApprovalLocked(approvalID string) *SessionActionApproval {
	for _, approval := range s.approvals {
		if approval.ID == approvalID {
			return approval
		}
	}
	return nil
}

func (s *SharedSession) findMatchingPendingApprovalLocked(action SessionAction, requester, targetUsername string) *SessionActionApproval {
	for _, approval := range s.approvals {
		if approval.Status != "pending" {
			continue
		}
		if approval.Action == action && approval.RequestedBy == requester && approval.TargetUsername == targetUsername {
			return approval
		}
	}
	return nil
}

func (s *SharedSession) cleanupExpiredApprovalsLocked(now time.Time) {
	for _, approval := range s.approvals {
		if approval.Status == "pending" && now.After(approval.ExpiresAt) {
			approval.Status = "expired"
			approval.DecidedAt = now
		}
	}
}
