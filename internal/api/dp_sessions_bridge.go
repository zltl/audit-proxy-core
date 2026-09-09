package api

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/zltl/audit-proxy-core/internal/models"
	"github.com/zltl/audit-proxy-core/internal/store"
)

// RecordingDecryptionKey returns the key used to open protected recordings.
func (a *API) RecordingDecryptionKey() []byte {
	if a == nil || a.config == nil {
		return nil
	}
	raw := strings.TrimSpace(a.config.RecordingEncryptionKey)
	if raw == "" {
		return nil
	}
	if strings.HasPrefix(raw, "file:") {
		return nil
	}
	key, err := hex.DecodeString(raw)
	if err != nil || len(key) != 32 {
		return nil
	}
	return key
}

// listDataPlaneSessions returns sessions from the shared dp_sessions table.
func (a *API) listDataPlaneSessions(status, user, ip, target string) ([]models.Session, error) {
	if a == nil || a.dpStore == nil {
		return nil, nil
	}
	filter := store.SessionFilter{Limit: 500}
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "active":
		filter.Status = store.SessionActive
	case "closed":
		filter.Status = store.SessionClosed
	case "terminated", "killed":
		filter.Status = store.SessionTerminated
	}
	if user != "" {
		filter.Username = user
	}
	if ip != "" {
		filter.SourceIP = ip
	}
	rows, err := a.dpStore.ListSessions(filter)
	if err != nil {
		return nil, err
	}
	out := make([]models.Session, 0, len(rows))
	for _, row := range rows {
		sess := storeSessionToModel(row)
		if target != "" {
			value := strings.ToLower(sess.TargetHost)
			if sess.TargetPort != 0 {
				value += fmt.Sprintf(":%d", sess.TargetPort)
			}
			if !strings.Contains(value, strings.ToLower(target)) {
				continue
			}
		}
		if sess.RecordingFile == "" {
			sess.RecordingFile = a.discoverSessionRecordingPath(sess.ID)
		}
		out = append(out, sess)
	}
	return out, nil
}

func (a *API) getDataPlaneSession(id string) (*models.Session, error) {
	if a == nil || a.dpStore == nil {
		return nil, errSessionNotFound
	}
	row, err := a.dpStore.GetSession(id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, errSessionNotFound
		}
		return nil, err
	}
	sess := storeSessionToModel(row)
	if sess.RecordingFile == "" {
		sess.RecordingFile = a.discoverSessionRecordingPath(sess.ID)
	}
	return &sess, nil
}

func storeSessionToModel(row store.Session) models.Session {
	status := string(row.Status)
	switch row.Status {
	case store.SessionActive:
		status = "active"
	case store.SessionTerminated:
		status = "killed"
	case store.SessionClosed:
		if row.RevokeRequested {
			status = "killed"
		} else {
			status = "closed"
		}
	}
	duration := ""
	if !row.StartedAt.IsZero() {
		end := row.ClosedAt
		if end.IsZero() {
			end = time.Now().UTC()
		}
		duration = end.Sub(row.StartedAt).Round(time.Second).String()
	}
	recording := strings.TrimSpace(row.RecordingRef)
	return models.Session{
		ID:            row.ID,
		Username:      row.Username,
		SourceIP:      row.SourceIP,
		ClientVersion: row.ClientVersion,
		InstanceID:    row.NodeID,
		TargetHost:    row.TargetHost,
		TargetPort:    row.TargetPort,
		StartTime:     row.StartedAt,
		Duration:      duration,
		BytesIn:       row.BytesIn,
		BytesOut:      row.BytesOut,
		Status:        status,
		RecordingFile: recording,
	}
}

// terminateSession prefers the shared store revocation path used by the Go
// data plane and web terminal, falling back to the legacy C admin API.
func (a *API) terminateSession(id, reason string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return errSessionNotFound
	}
	if a.dpStore != nil {
		if err := a.dpStore.RequestRevocation(id, reason); err != nil {
			if !errors.Is(err, store.ErrNotFound) {
				return err
			}
		} else {
			if a.sessionMetadata != nil {
				_ = a.sessionMetadata.MarkTerminated(id, time.Now().UTC())
			}
			return nil
		}
	}
	if err := a.dp.KillSession(id); err != nil {
		return err
	}
	if a.sessionMetadata != nil {
		_ = a.sessionMetadata.MarkTerminated(id, time.Now().UTC())
	}
	return nil
}
