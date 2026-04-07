package api

import (
	"net/http"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/models"
)

// handleDashboardStats returns aggregate statistics for the dashboard.
func (a *API) handleDashboardStats(w http.ResponseWriter, r *http.Request) {
	health, err := a.dp.GetHealth()
	if err != nil {
		writeError(w, http.StatusBadGateway, "failed to fetch data plane health: "+err.Error())
		return
	}

	sessions, err := a.dp.ListSessions()
	if err != nil {
		writeError(w, http.StatusBadGateway, "failed to fetch sessions: "+err.Error())
		return
	}

	servers, err := a.dp.ListUpstreams()
	if err != nil {
		writeError(w, http.StatusBadGateway, "failed to fetch servers: "+err.Error())
		return
	}

	active := 0
	for _, s := range sessions {
		if s.Status == "active" {
			active++
		}
	}

	healthy := 0
	for _, srv := range servers {
		if srv.Healthy {
			healthy++
		}
	}

	a.users.mu.RLock()
	totalUsers := len(a.users.users)
	a.users.mu.RUnlock()

	stats := models.DashboardStats{
		ActiveSessions: active,
		TotalUsers:     totalUsers,
		TotalServers:   len(servers),
		HealthyServers: healthy,
	}

	// Populate recent events from the last few sessions
	recentEvents := make([]models.AuditEvent, 0)
	limit := 10
	if len(sessions) < limit {
		limit = len(sessions)
	}
	for i := 0; i < limit; i++ {
		s := sessions[i]
		recentEvents = append(recentEvents, models.AuditEvent{
			ID:        s.ID,
			Timestamp: s.StartTime,
			EventType: "session_start",
			Username:  s.Username,
			SourceIP:  s.SourceIP,
			Details:   "Session to " + s.TargetHost,
			SessionID: s.ID,
		})
	}
	stats.RecentEvents = recentEvents

	_ = health // health data available for future enrichment

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    stats,
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
