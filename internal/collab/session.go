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

// SharedSession represents a collaborative terminal session.
type SharedSession struct {
	ID           string         `json:"id"`
	SessionID    string         `json:"session_id"`
	Owner        string         `json:"owner"`
	Target       string         `json:"target"`
	CreatedAt    time.Time      `json:"created_at"`
	Participants []*Participant `json:"participants"`
	MaxViewers   int            `json:"max_viewers"`
	AllowControl bool           `json:"allow_control"`
	Status       string         `json:"status"`
	mu           sync.RWMutex
	broadcast    chan []byte
	subscribers  map[string]chan []byte
}

// Manager manages all shared sessions.
type Manager struct {
	sessions map[string]*SharedSession
	mu       sync.RWMutex
}

func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// NewManager creates a new collaboration Manager.
func NewManager() *Manager {
	return &Manager{
		sessions: make(map[string]*SharedSession),
	}
}

// CreateSession creates a new shared session.
func (m *Manager) CreateSession(sessionID, owner, target string, maxViewers int, allowControl bool) (*SharedSession, error) {
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
		ID:           generateID(),
		SessionID:    sessionID,
		Owner:        owner,
		Target:       target,
		CreatedAt:    now,
		Participants: []*Participant{ownerParticipant},
		MaxViewers:   maxViewers,
		AllowControl: allowControl,
		Status:       "active",
		broadcast:    make(chan []byte, 256),
		subscribers:  make(map[string]chan []byte),
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
	s.Status = "ended"
	for username, ch := range s.subscribers {
		delete(s.subscribers, username)
		select {
		case <-ch:
			// already closed
		default:
			close(ch)
		}
	}
	s.mu.Unlock()

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
			p.Role = RoleOperator
			return nil
		}
	}

	return errors.New("target user not in session")
}

// RevokeControl revokes typing control from a participant (owner only).
func (m *Manager) RevokeControl(sessionID, ownerUsername, targetUsername string) error {
	s, err := m.GetSession(sessionID)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.Owner != ownerUsername {
		return errors.New("only the session owner can revoke control")
	}

	for _, p := range s.Participants {
		if p.Username == targetUsername {
			if p.Role == RoleOwner {
				return errors.New("cannot revoke control from owner")
			}
			p.Role = RoleViewer
			return nil
		}
	}

	return errors.New("target user not in session")
}
