package api

import (
	"net/http"
)

// handleDashboardStats returns aggregate statistics for the dashboard.
func (a *API) handleDashboardStats(w http.ResponseWriter, r *http.Request) {
	snapshot, err := a.BuildDashboardSnapshot()
	if err != nil {
		writeError(w, http.StatusBadGateway, "failed to build dashboard snapshot: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    snapshot.Stats,
	})
}

// handleDashboardActivity returns a recent activity feed.
func (a *API) handleDashboardActivity(w http.ResponseWriter, r *http.Request) {
	sessions, err := a.dp.ListSessions()
	if err != nil {
		writeError(w, http.StatusBadGateway, "failed to fetch sessions: "+err.Error())
		return
	}

	activities := make([]map[string]interface{}, 0)
	limit := 20
	if len(sessions) < limit {
		limit = len(sessions)
	}
	for i := 0; i < limit; i++ {
		s := sessions[i]
		activities = append(activities, map[string]interface{}{
			"type":      "session",
			"action":    s.Status,
			"user":      s.Username,
			"source_ip": s.SourceIP,
			"target":    s.TargetHost,
			"time":      s.StartTime,
			"detail":    "Session " + s.ID + " " + s.Status,
		})
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    activities,
		Total:   len(activities),
	})
}
