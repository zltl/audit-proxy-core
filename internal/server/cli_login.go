package server

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const cliLoginChallengeTTL = 10 * time.Minute

type cliLoginChallenge struct {
	ID            string
	PollToken     string
	Username      string
	SessionCookie string
	CreatedAt     time.Time
}

type cliLoginManager struct {
	mu         sync.Mutex
	challenges map[string]*cliLoginChallenge
}

func newCLILoginManager() *cliLoginManager {
	return &cliLoginManager{
		challenges: make(map[string]*cliLoginChallenge),
	}
}

func (m *cliLoginManager) create() (*cliLoginChallenge, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.cleanupLocked(time.Now())

	id, err := randomHex(16)
	if err != nil {
		return nil, err
	}
	pollToken, err := randomHex(32)
	if err != nil {
		return nil, err
	}

	challenge := &cliLoginChallenge{
		ID:        id,
		PollToken: pollToken,
		CreatedAt: time.Now(),
	}
	m.challenges[id] = challenge
	return cloneCLILoginChallenge(challenge), nil
}

func (m *cliLoginManager) exists(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.cleanupLocked(time.Now())
	_, ok := m.challenges[id]
	return ok
}

func (m *cliLoginManager) complete(id, username, sessionCookie string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.cleanupLocked(time.Now())
	challenge, ok := m.challenges[id]
	if !ok {
		return false
	}
	challenge.Username = username
	challenge.SessionCookie = sessionCookie
	return true
}

func (m *cliLoginManager) lookup(id, pollToken string) (*cliLoginChallenge, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.cleanupLocked(time.Now())
	challenge, ok := m.challenges[id]
	if !ok || challenge.PollToken != pollToken {
		return nil, false
	}
	return cloneCLILoginChallenge(challenge), true
}

func (m *cliLoginManager) cleanupLocked(now time.Time) {
	for id, challenge := range m.challenges {
		if now.Sub(challenge.CreatedAt) > cliLoginChallengeTTL {
			delete(m.challenges, id)
		}
	}
}

func cloneCLILoginChallenge(challenge *cliLoginChallenge) *cliLoginChallenge {
	if challenge == nil {
		return nil
	}
	copy := *challenge
	return &copy
}

func (s *Server) registerCLILoginRoutes() {
	s.mux.HandleFunc("POST /api/v2/cli/login/start", s.handleCLILoginStart)
	s.mux.HandleFunc("GET /api/v2/cli/login/status/{id}", s.handleCLILoginStatus)
}

func (s *Server) handleCLILoginStart(w http.ResponseWriter, r *http.Request) {
	if s.oidcProvider == nil {
		respondJSON(w, http.StatusNotFound, map[string]interface{}{
			"success": false,
			"error":   "OIDC is not configured",
		})
		return
	}
	if s.cliLogin == nil {
		respondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"error":   "CLI login is unavailable",
		})
		return
	}

	challenge, err := s.cliLogin.create()
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"error":   "failed to create CLI login challenge",
		})
		return
	}

	authURL := requestBaseURL(r) + "/auth/oidc/login?cli_challenge=" + url.QueryEscape(challenge.ID)
	respondJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"challenge_id": challenge.ID,
			"poll_token":   challenge.PollToken,
			"auth_url":     authURL,
			"expires_in":   int(cliLoginChallengeTTL.Seconds()),
		},
	})
}

func (s *Server) handleCLILoginStatus(w http.ResponseWriter, r *http.Request) {
	if s.cliLogin == nil {
		respondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"error":   "CLI login is unavailable",
		})
		return
	}

	id := r.PathValue("id")
	pollToken := strings.TrimSpace(r.URL.Query().Get("poll_token"))
	if id == "" || pollToken == "" {
		respondJSON(w, http.StatusBadRequest, map[string]interface{}{
			"success": false,
			"error":   "challenge id and poll_token are required",
		})
		return
	}

	challenge, ok := s.cliLogin.lookup(id, pollToken)
	if !ok {
		respondJSON(w, http.StatusNotFound, map[string]interface{}{
			"success": false,
			"error":   "login challenge not found",
		})
		return
	}

	status := http.StatusAccepted
	data := map[string]interface{}{
		"status": "pending",
	}
	if challenge.SessionCookie != "" {
		status = http.StatusOK
		data["status"] = "authenticated"
		data["username"] = challenge.Username
		data["session_cookie"] = challenge.SessionCookie
	}

	respondJSON(w, status, map[string]interface{}{
		"success": true,
		"data":    data,
	})
}

func requestBaseURL(r *http.Request) string {
	scheme := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto"))
	if scheme == "" {
		if r.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}

	host := strings.TrimSpace(r.Header.Get("X-Forwarded-Host"))
	if host == "" {
		host = r.Host
	}
	return fmt.Sprintf("%s://%s", scheme, host)
}
