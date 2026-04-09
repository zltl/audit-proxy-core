package api

import (
	"slices"
	"strconv"
	"strings"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/models"
)

// BuildDashboardSnapshot returns the composite payload used by the realtime dashboard.
func (a *API) BuildDashboardSnapshot() (*models.DashboardSnapshot, error) {
	health, err := a.dp.GetHealth()
	if err != nil {
		return nil, err
	}

	sessions, err := a.ListFilteredSessions("", "", "", "")
	if err != nil {
		return nil, err
	}

	servers, err := a.listManagedServers()
	if err != nil {
		return nil, err
	}

	auditEvents, err := a.loadAuditEvents()
	if err != nil {
		auditEvents = nil
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

	totalUsers, err := a.users.count()
	if err != nil {
		return nil, err
	}

	recentEvents := latestAuditEvents(auditEvents, 10)
	if len(recentEvents) == 0 {
		recentEvents = synthesizeSessionEvents(sessions, 10)
	}

	stats := models.DashboardStats{
		ActiveSessions:  active,
		TotalUsers:      totalUsers,
		TotalServers:    len(servers),
		HealthyServers:  healthy,
		AuthSuccessRate: authSuccessRate(auditEvents),
		RecentEvents:    recentEvents,
	}

	_ = health // reserved for future enrichment without changing the snapshot contract.

	return &models.DashboardSnapshot{
		Stats:    stats,
		Sessions: latestSessions(sessions, 10),
		Events:   latestAuditEvents(auditEvents, 8),
		Servers:  servers,
	}, nil
}

// ListFilteredSessions returns sessions after applying the same filters as the REST API.
func (a *API) ListFilteredSessions(status, user, ip, target string) ([]models.Session, error) {
	if a.sessionMetadata != nil {
		var syncErr error
		if !a.sessionSyncBg.Load() {
			syncErr = a.syncSessionMetadata()
		}
		stored, storeErr := a.sessionMetadata.ListSessions()
		switch {
		case storeErr == nil && (syncErr == nil || len(stored) > 0):
			return filterSessions(stored, status, user, ip, target), nil
		case storeErr != nil:
			return nil, storeErr
		case syncErr != nil:
			return nil, syncErr
		}
	}

	sessions, err := a.dp.ListSessions()
	if err != nil {
		return nil, err
	}
	return filterSessions(sessions, status, user, ip, target), nil
}

// ResolveRecordingPath exposes the validated recording resolver for realtime handlers.
func (a *API) ResolveRecordingPath(id string) (string, int, string) {
	return a.resolveRecordingPath(id)
}

func filterSessions(sessions []models.Session, status, user, ip, target string) []models.Session {
	user = strings.ToLower(strings.TrimSpace(user))
	ip = strings.ToLower(strings.TrimSpace(ip))
	target = strings.ToLower(strings.TrimSpace(target))

	filtered := sessions[:0:0]
	for _, s := range sessions {
		if status != "" && s.Status != status {
			continue
		}
		if user != "" && !strings.Contains(strings.ToLower(s.Username), user) {
			continue
		}
		if ip != "" && !strings.Contains(strings.ToLower(s.SourceIP), ip) {
			continue
		}

		targetValue := strings.ToLower(s.TargetHost)
		if s.TargetPort != 0 {
			targetValue += ":" + strconv.Itoa(s.TargetPort)
		}
		if target != "" && !strings.Contains(targetValue, target) {
			continue
		}
		filtered = append(filtered, s)
	}
	return filtered
}

func latestSessions(sessions []models.Session, limit int) []models.Session {
	if len(sessions) == 0 {
		return []models.Session{}
	}
	items := slices.Clone(sessions)
	if len(items) > limit {
		items = items[:limit]
	}
	return items
}

func latestAuditEvents(events []models.AuditEvent, limit int) []models.AuditEvent {
	if len(events) == 0 {
		return []models.AuditEvent{}
	}
	items := slices.Clone(events)
	if len(items) > limit {
		items = items[:limit]
	}
	return items
}

func synthesizeSessionEvents(sessions []models.Session, limit int) []models.AuditEvent {
	items := latestSessions(sessions, limit)
	events := make([]models.AuditEvent, 0, len(items))
	for _, s := range items {
		events = append(events, models.AuditEvent{
			ID:        s.ID,
			Timestamp: s.StartTime,
			EventType: "session_start",
			Username:  s.Username,
			SourceIP:  s.SourceIP,
			Details:   "Session to " + s.TargetHost,
			SessionID: s.ID,
		})
	}
	return events
}

func authSuccessRate(events []models.AuditEvent) float64 {
	var success, failure int
	for _, ev := range events {
		switch strings.ToLower(ev.EventType) {
		case "auth.success", "login", "auth.login":
			success++
		case "auth.failure", "login_failed", "auth.denied":
			failure++
		}
	}
	if success+failure == 0 {
		return 0
	}
	return float64(success) * 100 / float64(success+failure)
}
