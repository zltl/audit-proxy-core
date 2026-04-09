package api

import (
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/models"
)

type complianceDataProvider struct {
	api *API
}

// ComplianceDataProvider exposes subject data inventory for GDPR and custom SQL report rendering.
func (a *API) ComplianceDataProvider() complianceDataProvider {
	return complianceDataProvider{api: a}
}

func (p complianceDataProvider) GetUser(username string) (models.User, bool, error) {
	if p.api == nil || p.api.users == nil {
		return models.User{}, false, nil
	}
	return p.api.users.get(username)
}

func (p complianceDataProvider) ListSessions(username string, start, end time.Time) ([]models.Session, error) {
	if p.api == nil {
		return []models.Session{}, nil
	}
	var (
		sessions []models.Session
		err      error
	)
	if p.api.sessionMetadata != nil {
		sessions, err = p.api.sessionMetadata.ListSessions()
	}
	if err != nil {
		return nil, err
	}
	if len(sessions) == 0 && p.api.dp != nil {
		sessions, err = p.api.dp.ListSessions()
		if err != nil {
			return nil, err
		}
	}
	filtered := make([]models.Session, 0, len(sessions))
	for _, session := range sessions {
		if session.Username != username {
			continue
		}
		if !start.IsZero() && session.StartTime.Before(start) {
			continue
		}
		if !end.IsZero() && session.StartTime.After(end) {
			continue
		}
		filtered = append(filtered, session)
	}
	return filtered, nil
}

func (p complianceDataProvider) ListAuditEvents(username string, start, end time.Time) ([]models.AuditEvent, error) {
	if p.api == nil {
		return []models.AuditEvent{}, nil
	}
	events, err := p.api.loadAuditEvents()
	if err != nil {
		return nil, err
	}
	filtered := make([]models.AuditEvent, 0, len(events))
	for _, event := range events {
		if event.Username != username {
			continue
		}
		if !start.IsZero() && event.Timestamp.Before(start) {
			continue
		}
		if !end.IsZero() && event.Timestamp.After(end) {
			continue
		}
		filtered = append(filtered, event)
	}
	return filtered, nil
}

func (p complianceDataProvider) SnapshotUsers() ([]models.User, error) {
	if p.api == nil || p.api.users == nil {
		return []models.User{}, nil
	}
	return p.api.users.list()
}

func (p complianceDataProvider) SnapshotSessions() ([]models.Session, error) {
	if p.api == nil {
		return []models.Session{}, nil
	}
	var (
		sessions []models.Session
		err      error
	)
	if p.api.sessionMetadata != nil {
		sessions, err = p.api.sessionMetadata.ListSessions()
	}
	if err != nil {
		return nil, err
	}
	if len(sessions) == 0 && p.api.dp != nil {
		sessions, err = p.api.dp.ListSessions()
		if err != nil {
			return nil, err
		}
	}
	if sessions == nil {
		return []models.Session{}, nil
	}
	return sessions, nil
}

func (p complianceDataProvider) SnapshotAuditEvents() ([]models.AuditEvent, error) {
	if p.api == nil {
		return []models.AuditEvent{}, nil
	}
	return p.api.loadAuditEvents()
}

func (p complianceDataProvider) SnapshotServers() ([]models.Server, error) {
	if p.api == nil || p.api.servers == nil {
		return []models.Server{}, nil
	}
	return p.api.servers.list(), nil
}
