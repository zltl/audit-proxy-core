package api

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/models"
)

// handleListSessions lists sessions with optional pagination and filtering.
func (a *API) handleListSessions(w http.ResponseWriter, r *http.Request) {
	// Apply filters
	q := r.URL.Query()
	statusFilter := q.Get("status")
	userFilter := q.Get("user")
	ipFilter := q.Get("ip")
	targetFilter := q.Get("target")

	filtered, err := a.ListFilteredSessions(statusFilter, userFilter, ipFilter, targetFilter)
	if err != nil {
		writeError(w, http.StatusBadGateway, "failed to fetch sessions: "+err.Error())
		return
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

	session, err := a.getSessionByID(id)
	if err != nil {
		switch {
		case errors.Is(err, errSessionNotFound):
			writeError(w, http.StatusNotFound, "session not found")
		default:
			writeError(w, http.StatusBadGateway, "failed to fetch sessions: "+err.Error())
		}
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    session,
	})
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
	if a.sessionMetadata != nil {
		_ = a.sessionMetadata.MarkTerminated(id, time.Now().UTC())
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
			if a.sessionMetadata != nil {
				_ = a.sessionMetadata.MarkTerminated(id, time.Now().UTC())
			}
			results[id] = "terminated"
		}
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    results,
	})
}

func (a *API) recordingPathForSession(id string) (string, error) {
	session, err := a.getSessionByID(id)
	if err != nil {
		return "", fmt.Errorf("get session: %w", err)
	}
	if session.RecordingFile == "" {
		if liveSession, liveErr := a.getLiveSessionByID(id); liveErr == nil && liveSession.RecordingFile != "" {
			session = liveSession
		}
	}
	if session.RecordingFile == "" {
		session.RecordingFile = a.discoverSessionRecordingPath(id)
	}
	if session.RecordingFile == "" {
		return "", errNoRecording
	}
	if err := ensureWithinDir(a.config.RecordingDir, session.RecordingFile); err != nil {
		return "", err
	}
	return session.RecordingFile, nil
}

var (
	errSessionNotFound = errors.New("session not found")
	errNoRecording     = errors.New("no recording available for this session")
	errRecordingPath   = errors.New("recording path outside allowed directory")
)

func (a *API) getSessionByID(id string) (*models.Session, error) {
	if strings.TrimSpace(id) == "" {
		return nil, errSessionNotFound
	}
	if a.sessionMetadata != nil {
		var syncErr error
		if !a.sessionSyncBg.Load() {
			syncErr = a.syncSessionMetadata()
		}
		session, storeErr := a.sessionMetadata.GetSession(id)
		switch {
		case storeErr == nil:
			return session, nil
		case storeErr != nil && !errors.Is(storeErr, errSessionMetadataNotFound):
			return nil, storeErr
		case syncErr != nil:
			return nil, syncErr
		default:
			return nil, errSessionNotFound
		}
	}

	return a.getLiveSessionByID(id)
}

func (a *API) getLiveSessionByID(id string) (*models.Session, error) {
	sessions, err := a.dp.ListSessions()
	if err != nil {
		return nil, err
	}
	for _, session := range sessions {
		if session.ID == id {
			cloned := session
			return &cloned, nil
		}
	}
	return nil, errSessionNotFound
}

func ensureWithinDir(root, candidate string) error {
	if root == "" {
		return nil
	}

	absRoot, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	absCandidate, err := filepath.Abs(candidate)
	if err != nil {
		return err
	}

	rel, err := filepath.Rel(absRoot, absCandidate)
	if err != nil {
		return err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return errRecordingPath
	}
	return nil
}

func (a *API) resolveRecordingPath(id string) (string, int, string) {
	if id == "" {
		return "", http.StatusBadRequest, "missing session id"
	}

	recordingPath, err := a.recordingPathForSession(id)
	if err == nil {
		return recordingPath, http.StatusOK, ""
	}

	switch {
	case errors.Is(err, errSessionNotFound):
		return "", http.StatusNotFound, errSessionNotFound.Error()
	case errors.Is(err, errNoRecording):
		return "", http.StatusNotFound, errNoRecording.Error()
	case errors.Is(err, errRecordingPath):
		return "", http.StatusForbidden, errRecordingPath.Error()
	default:
		return "", http.StatusBadGateway, "failed to fetch sessions: " + err.Error()
	}
}

// handleGetRecording returns the recording file path for a session.
func (a *API) handleGetRecording(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	recordingPath, status, message := a.resolveRecordingPath(id)
	if message != "" {
		writeError(w, status, message)
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data: map[string]string{
			"session_id":     id,
			"recording_file": recordingPath,
		},
	})
}

// handleDownloadRecording streams the asciicast recording for a session.
func (a *API) handleDownloadRecording(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	recordingPath, status, message := a.resolveRecordingPath(id)
	if message != "" {
		if status == http.StatusNotFound {
			served, err := a.tryServeArchivedRecording(w, r, id, "")
			if served {
				return
			}
			if err != nil {
				writeError(w, http.StatusBadGateway, "failed to download archived recording: "+err.Error())
				return
			}
		}
		writeError(w, status, message)
		return
	}

	file, err := os.Open(recordingPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			served, archiveErr := a.tryServeArchivedRecording(w, r, id, recordingPath)
			if served {
				return
			}
			if archiveErr == nil {
				writeError(w, http.StatusNotFound, "recording file not found")
				return
			}
			writeError(w, http.StatusBadGateway, "failed to download archived recording: "+archiveErr.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to open recording: "+err.Error())
		return
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to stat recording: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/x-asciicast")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filepath.Base(recordingPath)))
	http.ServeContent(w, r, filepath.Base(recordingPath), info.ModTime(), file)
}

func (a *API) tryServeArchivedRecording(w http.ResponseWriter, r *http.Request, id, nameHint string) (bool, error) {
	if a == nil || a.recordingStore == nil {
		return false, nil
	}

	reader, name, err := a.recordingStore.openSessionRecording(r.Context(), id)
	if err != nil {
		if objectStorageNotFound(err) {
			return false, nil
		}
		return false, err
	}
	defer reader.Close()

	if strings.TrimSpace(nameHint) != "" {
		name = filepath.Base(nameHint)
	}
	if strings.TrimSpace(name) == "" {
		name = id + ".cast"
	}

	w.Header().Set("Content-Type", "application/x-asciicast")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
	_, _ = io.Copy(w, reader)
	return true, nil
}
