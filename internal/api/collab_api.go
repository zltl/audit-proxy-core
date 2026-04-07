package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/collab"
)

// SetCollab attaches a collaboration Manager to the API.
// Call this after RegisterRoutes if collaboration is enabled.
func (a *API) SetCollab(mgr *collab.Manager) {
	a.collab = mgr
}

// RegisterCollabRoutes registers all collaboration routes on the given mux.
func (a *API) RegisterCollabRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v2/collab/sessions", a.handleCreateCollabSession)
	mux.HandleFunc("GET /api/v2/collab/sessions", a.handleListCollabSessions)
	mux.HandleFunc("GET /api/v2/collab/sessions/{id}", a.handleGetCollabSession)
	mux.HandleFunc("POST /api/v2/collab/sessions/{id}/join", a.handleJoinCollabSession)
	mux.HandleFunc("POST /api/v2/collab/sessions/{id}/leave", a.handleLeaveCollabSession)
	mux.HandleFunc("POST /api/v2/collab/sessions/{id}/end", a.handleEndCollabSession)
	mux.HandleFunc("POST /api/v2/collab/sessions/{id}/request-control", a.handleRequestControl)
	mux.HandleFunc("POST /api/v2/collab/sessions/{id}/grant-control", a.handleGrantControl)
	mux.HandleFunc("POST /api/v2/collab/sessions/{id}/revoke-control", a.handleRevokeControl)
	mux.HandleFunc("GET /api/v2/collab/sessions/{id}/chat", a.handleGetChat)
	mux.HandleFunc("POST /api/v2/collab/sessions/{id}/chat", a.handleSendChat)
	mux.HandleFunc("GET /api/v2/collab/sessions/{id}/recording", a.handleGetCollabRecording)
}

func (a *API) requireCollab(w http.ResponseWriter) bool {
	if a.collab == nil {
		writeError(w, http.StatusServiceUnavailable, "collaboration is not enabled")
		return false
	}
	return true
}

func (a *API) handleCreateCollabSession(w http.ResponseWriter, r *http.Request) {
	if !a.requireCollab(w) {
		return
	}

	var req struct {
		SessionID    string `json:"session_id"`
		Target       string `json:"target"`
		MaxViewers   int    `json:"max_viewers"`
		AllowControl bool   `json:"allow_control"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	owner := r.Header.Get("X-User")
	if owner == "" {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if req.SessionID == "" {
		writeError(w, http.StatusBadRequest, "session_id is required")
		return
	}

	session, err := a.collab.CreateSession(req.SessionID, owner, req.Target, req.MaxViewers, req.AllowControl)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, APIResponse{
		Success: true,
		Data:    session,
	})
}

func (a *API) handleListCollabSessions(w http.ResponseWriter, r *http.Request) {
	if !a.requireCollab(w) {
		return
	}

	sessions := a.collab.ListSessions()
	if sessions == nil {
		sessions = []*collab.SharedSession{}
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    sessions,
		Total:   len(sessions),
	})
}

func (a *API) handleGetCollabSession(w http.ResponseWriter, r *http.Request) {
	if !a.requireCollab(w) {
		return
	}

	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing session id")
		return
	}

	session, err := a.collab.GetSession(id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    session,
	})
}

func (a *API) handleJoinCollabSession(w http.ResponseWriter, r *http.Request) {
	if !a.requireCollab(w) {
		return
	}

	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing session id")
		return
	}

	var req struct {
		Role string `json:"role"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	username := r.Header.Get("X-User")
	if username == "" {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	role := collab.ParticipantRole(req.Role)
	if role == "" {
		role = collab.RoleViewer
	}

	if err := a.collab.JoinSession(id, username, role); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    map[string]string{"status": "joined"},
	})
}

func (a *API) handleLeaveCollabSession(w http.ResponseWriter, r *http.Request) {
	if !a.requireCollab(w) {
		return
	}

	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing session id")
		return
	}

	username := r.Header.Get("X-User")
	if username == "" {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if err := a.collab.LeaveSession(id, username); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    map[string]string{"status": "left"},
	})
}

func (a *API) handleEndCollabSession(w http.ResponseWriter, r *http.Request) {
	if !a.requireCollab(w) {
		return
	}

	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing session id")
		return
	}

	owner := r.Header.Get("X-User")
	if owner == "" {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	session, err := a.collab.GetSession(id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	if session.Owner != owner {
		writeError(w, http.StatusForbidden, "only the session owner can end the session")
		return
	}

	if err := a.collab.EndSession(id); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    map[string]string{"status": "ended"},
	})
}

func (a *API) handleRequestControl(w http.ResponseWriter, r *http.Request) {
	if !a.requireCollab(w) {
		return
	}

	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing session id")
		return
	}

	username := r.Header.Get("X-User")
	if username == "" {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if err := a.collab.RequestControl(id, username); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    map[string]string{"status": "requested"},
	})
}

func (a *API) handleGrantControl(w http.ResponseWriter, r *http.Request) {
	if !a.requireCollab(w) {
		return
	}

	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing session id")
		return
	}

	owner := r.Header.Get("X-User")
	if owner == "" {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req struct {
		Username string `json:"username"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if req.Username == "" {
		writeError(w, http.StatusBadRequest, "username is required")
		return
	}

	if err := a.collab.GrantControl(id, owner, req.Username); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    map[string]string{"status": "granted"},
	})
}

func (a *API) handleRevokeControl(w http.ResponseWriter, r *http.Request) {
	if !a.requireCollab(w) {
		return
	}

	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing session id")
		return
	}

	owner := r.Header.Get("X-User")
	if owner == "" {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req struct {
		Username string `json:"username"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if req.Username == "" {
		writeError(w, http.StatusBadRequest, "username is required")
		return
	}

	if err := a.collab.RevokeControl(id, owner, req.Username); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    map[string]string{"status": "revoked"},
	})
}

func (a *API) handleGetChat(w http.ResponseWriter, r *http.Request) {
	if !a.requireCollab(w) {
		return
	}

	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing session id")
		return
	}

	chatRoom := a.getOrCreateChatRoom(id, false)
	if chatRoom == nil {
		writeJSON(w, http.StatusOK, APIResponse{
			Success: true,
			Data:    []collab.ChatMessage{},
		})
		return
	}

	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if l, err := strconv.Atoi(v); err == nil && l > 0 {
			limit = l
		}
	}

	messages := chatRoom.GetHistory(limit)
	if messages == nil {
		messages = []collab.ChatMessage{}
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    messages,
		Total:   len(messages),
	})
}

func (a *API) handleSendChat(w http.ResponseWriter, r *http.Request) {
	if !a.requireCollab(w) {
		return
	}

	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing session id")
		return
	}

	// Verify session exists
	if _, err := a.collab.GetSession(id); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	username := r.Header.Get("X-User")
	if username == "" {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req struct {
		Message string `json:"message"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if req.Message == "" {
		writeError(w, http.StatusBadRequest, "message is required")
		return
	}

	// Lazy-init chat room (thread-safe)
	chatRoom := a.getOrCreateChatRoom(id, true)

	msg := chatRoom.SendMessage(username, req.Message)

	writeJSON(w, http.StatusCreated, APIResponse{
		Success: true,
		Data:    msg,
	})
}

func (a *API) handleGetCollabRecording(w http.ResponseWriter, r *http.Request) {
	if !a.requireCollab(w) {
		return
	}

	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing session id")
		return
	}

	a.collabMu.RLock()
	rec := a.collabRecordings[id]
	a.collabMu.RUnlock()
	if rec == nil {
		writeJSON(w, http.StatusOK, APIResponse{
			Success: true,
			Data:    []collab.RecordingEvent{},
		})
		return
	}

	events := rec.Events()
	if events == nil {
		events = []collab.RecordingEvent{}
	}

	// Return as NDJSON if Accept header requests it, otherwise JSON array
	if r.Header.Get("Accept") == "application/x-ndjson" {
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.WriteHeader(http.StatusOK)
		enc := json.NewEncoder(w)
		for _, e := range events {
			enc.Encode(e)
		}
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    events,
		Total:   len(events),
	})
}

// getOrCreateChatRoom returns a chat room for the given session ID.
// If create is true and no room exists, one is created.
func (a *API) getOrCreateChatRoom(sessionID string, create bool) *collab.ChatRoom {
	if !create {
		a.collabMu.RLock()
		defer a.collabMu.RUnlock()
		if a.collabChats == nil {
			return nil
		}
		return a.collabChats[sessionID]
	}
	a.collabMu.Lock()
	defer a.collabMu.Unlock()
	if a.collabChats == nil {
		a.collabChats = make(map[string]*collab.ChatRoom)
	}
	room := a.collabChats[sessionID]
	if room == nil {
		room = collab.NewChatRoom(sessionID, 1000)
		a.collabChats[sessionID] = room
	}
	return room
}
