package api

import (
	"net/http"
	"strings"
)

// handleListSessions lists sessions with optional pagination and filtering.
func (a *API) handleListSessions(w http.ResponseWriter, r *http.Request) {
	sessions, err := a.dp.ListSessions()
	if err != nil {
		writeError(w, http.StatusBadGateway, "failed to fetch sessions: "+err.Error())
		return
	}

	// Apply filters
	q := r.URL.Query()
	statusFilter := q.Get("status")
	userFilter := q.Get("user")
	ipFilter := q.Get("ip")

	filtered := sessions[:0:0]
	for _, s := range sessions {
		if statusFilter != "" && s.Status != statusFilter {
			continue
		}
		if userFilter != "" && s.Username != userFilter {
			continue
		}
		if ipFilter != "" && s.SourceIP != ipFilter {
			continue
		}
		filtered = append(filtered, s)
	}

	page, perPage := parsePagination(r)
	total := len(filtered)
	start, end := paginate(total, page, perPage)

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    filtered[start:end],
		Total:   total,
		Page:    page,
		PerPage: perPage,
	})
}

// handleGetSession returns details for a single session.
func (a *API) handleGetSession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing session id")
		return
	}

	sessions, err := a.dp.ListSessions()
	if err != nil {
		writeError(w, http.StatusBadGateway, "failed to fetch sessions: "+err.Error())
		return
	}

	for _, s := range sessions {
		if s.ID == id {
			writeJSON(w, http.StatusOK, APIResponse{
				Success: true,
				Data:    s,
			})
			return
		}
	}

	writeError(w, http.StatusNotFound, "session not found")
}

// handleKillSession terminates a single session.
func (a *API) handleKillSession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing session id")
		return
	}

	if err := a.dp.KillSession(id); err != nil {
		writeError(w, http.StatusBadGateway, "failed to kill session: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    map[string]string{"message": "session " + id + " terminated"},
	})
}

// handleBulkKillSessions kills multiple sessions by IDs.
func (a *API) handleBulkKillSessions(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IDs []string `json:"ids"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if len(req.IDs) == 0 {
		writeError(w, http.StatusBadRequest, "no session IDs provided")
		return
	}

	results := make(map[string]string, len(req.IDs))
	for _, id := range req.IDs {
		if err := a.dp.KillSession(id); err != nil {
			results[id] = "error: " + err.Error()
		} else {
			results[id] = "terminated"
		}
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    results,
	})
}

// handleGetRecording returns the recording file path for a session.
func (a *API) handleGetRecording(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing session id")
		return
	}

	sessions, err := a.dp.ListSessions()
	if err != nil {
		writeError(w, http.StatusBadGateway, "failed to fetch sessions: "+err.Error())
		return
	}

	for _, s := range sessions {
		if s.ID == id {
			if s.RecordingFile == "" {
				writeError(w, http.StatusNotFound, "no recording available for this session")
				return
			}
			// Sanitize: only allow files within the recording directory
			if a.config.RecordingDir != "" && !strings.HasPrefix(s.RecordingFile, a.config.RecordingDir) {
				writeError(w, http.StatusForbidden, "recording path outside allowed directory")
				return
			}
			writeJSON(w, http.StatusOK, APIResponse{
				Success: true,
				Data: map[string]string{
					"session_id":     s.ID,
					"recording_file": s.RecordingFile,
				},
			})
			return
		}
	}

	writeError(w, http.StatusNotFound, "session not found")
}
