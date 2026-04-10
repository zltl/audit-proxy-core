package api

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/models"
	_ "modernc.org/sqlite"
)

const defaultSessionMetadataSyncInterval = 5 * time.Second

var errSessionMetadataNotFound = errors.New("session metadata not found")

type sessionMetadataStore struct {
	path string
	db   *sql.DB
}

type sessionMetadataRow struct {
	ID                string
	Username          string
	SourceIP          string
	ClientVersion     string
	ClientOS          string
	DeviceFingerprint string
	InstanceID        string
	TargetHost        string
	TargetPort        int
	StartUnix         int64
	BytesIn           int64
	BytesOut          int64
	Status            string
	RecordingFile     string
	LastSeenUnix      int64
	ClosedAtUnix      sql.NullInt64
	UpdatedUnix       int64
}

type sessionMetadataBackupRow struct {
	ID                string `json:"id"`
	Username          string `json:"username"`
	SourceIP          string `json:"source_ip"`
	ClientVersion     string `json:"client_version,omitempty"`
	ClientOS          string `json:"client_os,omitempty"`
	DeviceFingerprint string `json:"device_fingerprint,omitempty"`
	InstanceID        string `json:"instance_id,omitempty"`
	TargetHost        string `json:"target_host"`
	TargetPort        int    `json:"target_port"`
	StartUnix         int64  `json:"start_unix"`
	BytesIn           int64  `json:"bytes_in"`
	BytesOut          int64  `json:"bytes_out"`
	Status            string `json:"status"`
	RecordingFile     string `json:"recording_file,omitempty"`
	LastSeenUnix      int64  `json:"last_seen_unix"`
	ClosedAtUnix      *int64 `json:"closed_at_unix,omitempty"`
	UpdatedUnix       int64  `json:"updated_unix"`
}

func newSessionMetadataStore(path string) *sessionMetadataStore {
	if strings.TrimSpace(path) == "" {
		path = "sessions.db"
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		log.Printf("api: disable session metadata database: mkdir %s: %v", filepath.Dir(path), err)
		return nil
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		log.Printf("api: disable session metadata database %s: %v", path, err)
		return nil
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	store := &sessionMetadataStore{path: path, db: db}
	if err := store.init(); err != nil {
		log.Printf("api: disable session metadata database %s: %v", path, err)
		_ = db.Close()
		return nil
	}
	return store
}

func (s *sessionMetadataStore) init() error {
	if s == nil || s.db == nil {
		return nil
	}
	for _, pragma := range []string{
		`PRAGMA journal_mode = WAL;`,
		`PRAGMA busy_timeout = 5000;`,
	} {
		if _, err := s.db.Exec(pragma); err != nil {
			return err
		}
	}
	return runSQLSchemaMigrations(s.db, sqlDialectSQLite, "session_metadata", []sqlSchemaMigration{
		{
			Version: 1,
			Statements: []string{
				`CREATE TABLE IF NOT EXISTS session_metadata (
					id TEXT PRIMARY KEY,
					username TEXT NOT NULL,
					source_ip TEXT NOT NULL DEFAULT '',
					client_version TEXT NOT NULL DEFAULT '',
					client_os TEXT NOT NULL DEFAULT '',
					device_fingerprint TEXT NOT NULL DEFAULT '',
					instance_id TEXT NOT NULL DEFAULT '',
					target_host TEXT NOT NULL DEFAULT '',
					target_port INTEGER NOT NULL DEFAULT 0,
					start_time INTEGER NOT NULL,
					bytes_in INTEGER NOT NULL DEFAULT 0,
					bytes_out INTEGER NOT NULL DEFAULT 0,
					status TEXT NOT NULL DEFAULT 'active',
					recording_file TEXT NOT NULL DEFAULT '',
					last_seen_at INTEGER NOT NULL,
					closed_at INTEGER,
					updated_at INTEGER NOT NULL
				);`,
				`CREATE INDEX IF NOT EXISTS idx_session_metadata_status_time
					ON session_metadata(status, start_time DESC);`,
				`CREATE INDEX IF NOT EXISTS idx_session_metadata_user_time
					ON session_metadata(username, start_time DESC);`,
			},
		},
	})
}

func (s *sessionMetadataStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *sessionMetadataStore) SchemaVersion() (int, error) {
	if s == nil || s.db == nil {
		return 0, nil
	}
	return sqlSchemaVersion(s.db, sqlDialectSQLite, "session_metadata")
}

func (s *sessionMetadataStore) ListBackupRows() ([]sessionMetadataBackupRow, error) {
	if s == nil || s.db == nil {
		return []sessionMetadataBackupRow{}, nil
	}
	rows, err := s.db.Query(`
		SELECT id, username, source_ip, client_version, client_os, device_fingerprint,
		       instance_id, target_host, target_port, start_time, bytes_in, bytes_out,
		       status, recording_file, last_seen_at, closed_at, updated_at
		FROM session_metadata
		ORDER BY start_time DESC, updated_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make([]sessionMetadataBackupRow, 0)
	for rows.Next() {
		var row sessionMetadataRow
		if err := rows.Scan(
			&row.ID,
			&row.Username,
			&row.SourceIP,
			&row.ClientVersion,
			&row.ClientOS,
			&row.DeviceFingerprint,
			&row.InstanceID,
			&row.TargetHost,
			&row.TargetPort,
			&row.StartUnix,
			&row.BytesIn,
			&row.BytesOut,
			&row.Status,
			&row.RecordingFile,
			&row.LastSeenUnix,
			&row.ClosedAtUnix,
			&row.UpdatedUnix,
		); err != nil {
			return nil, err
		}
		result = append(result, row.toBackup())
	}
	return result, rows.Err()
}

func (s *sessionMetadataStore) ReplaceBackupRows(rows []sessionMetadataBackupRow) error {
	if s == nil || s.db == nil {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	if _, err = tx.Exec(`DELETE FROM session_metadata`); err != nil {
		return err
	}
	stmt, err := tx.Prepare(`
		INSERT INTO session_metadata (
			id, username, source_ip, client_version, client_os, device_fingerprint,
			instance_id, target_host, target_port, start_time, bytes_in, bytes_out,
			status, recording_file, last_seen_at, closed_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, item := range rows {
		closedAt := interface{}(nil)
		if item.ClosedAtUnix != nil {
			closedAt = *item.ClosedAtUnix
		}
		if _, err = stmt.Exec(
			item.ID,
			item.Username,
			item.SourceIP,
			item.ClientVersion,
			item.ClientOS,
			item.DeviceFingerprint,
			item.InstanceID,
			item.TargetHost,
			item.TargetPort,
			item.StartUnix,
			item.BytesIn,
			item.BytesOut,
			item.Status,
			item.RecordingFile,
			item.LastSeenUnix,
			closedAt,
			item.UpdatedUnix,
		); err != nil {
			return err
		}
	}
	err = tx.Commit()
	return err
}

func (s *sessionMetadataStore) UpsertSnapshot(sessions []models.Session, seenAt time.Time) error {
	if s == nil || s.db == nil {
		return nil
	}

	seenAt = seenAt.UTC()
	seenUnix := seenAt.Unix()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	stmt, err := tx.Prepare(`
		INSERT INTO session_metadata (
			id, username, source_ip, client_version, client_os, device_fingerprint,
			instance_id, target_host, target_port, start_time, bytes_in, bytes_out,
			status, recording_file, last_seen_at, closed_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			username = excluded.username,
			source_ip = excluded.source_ip,
			client_version = excluded.client_version,
			client_os = excluded.client_os,
			device_fingerprint = excluded.device_fingerprint,
			instance_id = excluded.instance_id,
			target_host = excluded.target_host,
			target_port = excluded.target_port,
			start_time = excluded.start_time,
			bytes_in = excluded.bytes_in,
			bytes_out = excluded.bytes_out,
			status = excluded.status,
			recording_file = excluded.recording_file,
			last_seen_at = excluded.last_seen_at,
			closed_at = excluded.closed_at,
			updated_at = excluded.updated_at
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	seenIDs := make([]string, 0, len(sessions))
	for _, session := range sessions {
		id := strings.TrimSpace(session.ID)
		if id == "" {
			continue
		}
		seenIDs = append(seenIDs, id)

		startUnix := session.StartTime.UTC().Unix()
		if startUnix <= 0 {
			startUnix = seenUnix
		}
		status := normalizeSessionStatus(session.Status)
		var closedAt interface{}
		if status != "active" && status != "closing" {
			closedAt = seenUnix
		}

		if _, err = stmt.Exec(
			id,
			session.Username,
			session.SourceIP,
			session.ClientVersion,
			session.ClientOS,
			session.DeviceFingerprint,
			session.InstanceID,
			session.TargetHost,
			session.TargetPort,
			startUnix,
			session.BytesIn,
			session.BytesOut,
			status,
			session.RecordingFile,
			seenUnix,
			closedAt,
			seenUnix,
		); err != nil {
			return err
		}
	}

	markMissingArgs := []interface{}{seenUnix, seenUnix, seenUnix}
	markMissingQuery := `
		UPDATE session_metadata
		SET status = 'closed',
			closed_at = COALESCE(closed_at, ?),
			last_seen_at = ?,
			updated_at = ?
		WHERE status IN ('active', 'closing')
	`
	if len(seenIDs) > 0 {
		markMissingQuery += " AND id NOT IN (" + sqlPlaceholders(len(seenIDs)) + ")"
		for _, id := range seenIDs {
			markMissingArgs = append(markMissingArgs, id)
		}
	}
	if _, err = tx.Exec(markMissingQuery, markMissingArgs...); err != nil {
		return err
	}

	err = tx.Commit()
	return err
}

func (s *sessionMetadataStore) ListSessions() ([]models.Session, error) {
	return s.querySessions(`
		SELECT id, username, source_ip, client_version, client_os, device_fingerprint,
		       instance_id, target_host, target_port, start_time, bytes_in, bytes_out,
		       status, recording_file, last_seen_at, closed_at, updated_at
		FROM session_metadata
		ORDER BY start_time DESC, updated_at DESC
	`)
}

func (s *sessionMetadataStore) GetSession(id string) (*models.Session, error) {
	sessions, err := s.querySessions(`
		SELECT id, username, source_ip, client_version, client_os, device_fingerprint,
		       instance_id, target_host, target_port, start_time, bytes_in, bytes_out,
		       status, recording_file, last_seen_at, closed_at, updated_at
		FROM session_metadata
		WHERE id = ?
		LIMIT 1
	`, id)
	if err != nil {
		return nil, err
	}
	if len(sessions) == 0 {
		return nil, errSessionMetadataNotFound
	}
	return &sessions[0], nil
}

func (s *sessionMetadataStore) MarkTerminated(id string, when time.Time) error {
	if s == nil || s.db == nil || strings.TrimSpace(id) == "" {
		return nil
	}
	when = when.UTC()
	result, err := s.db.Exec(`
		UPDATE session_metadata
		SET status = 'terminated',
			closed_at = COALESCE(closed_at, ?),
			last_seen_at = ?,
			updated_at = ?
		WHERE id = ?
	`, when.Unix(), when.Unix(), when.Unix(), id)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return errSessionMetadataNotFound
	}
	return nil
}

func (s *sessionMetadataStore) querySessions(query string, args ...interface{}) ([]models.Session, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []models.Session
	for rows.Next() {
		var row sessionMetadataRow
		if err := rows.Scan(
			&row.ID,
			&row.Username,
			&row.SourceIP,
			&row.ClientVersion,
			&row.ClientOS,
			&row.DeviceFingerprint,
			&row.InstanceID,
			&row.TargetHost,
			&row.TargetPort,
			&row.StartUnix,
			&row.BytesIn,
			&row.BytesOut,
			&row.Status,
			&row.RecordingFile,
			&row.LastSeenUnix,
			&row.ClosedAtUnix,
			&row.UpdatedUnix,
		); err != nil {
			return nil, err
		}
		sessions = append(sessions, row.toModel())
	}
	return sessions, rows.Err()
}

func (r sessionMetadataRow) toModel() models.Session {
	start := unixUTC(r.StartUnix)
	end := time.Now().UTC()
	if r.ClosedAtUnix.Valid {
		end = unixUTC(r.ClosedAtUnix.Int64)
	}
	return models.Session{
		ID:                r.ID,
		Username:          r.Username,
		SourceIP:          r.SourceIP,
		ClientVersion:     r.ClientVersion,
		ClientOS:          r.ClientOS,
		DeviceFingerprint: r.DeviceFingerprint,
		InstanceID:        r.InstanceID,
		TargetHost:        r.TargetHost,
		TargetPort:        r.TargetPort,
		StartTime:         start,
		Duration:          sessionDurationString(start, end),
		BytesIn:           r.BytesIn,
		BytesOut:          r.BytesOut,
		Status:            normalizeSessionStatus(r.Status),
		RecordingFile:     r.RecordingFile,
	}
}

func (r sessionMetadataRow) toBackup() sessionMetadataBackupRow {
	item := sessionMetadataBackupRow{
		ID:                r.ID,
		Username:          r.Username,
		SourceIP:          r.SourceIP,
		ClientVersion:     r.ClientVersion,
		ClientOS:          r.ClientOS,
		DeviceFingerprint: r.DeviceFingerprint,
		InstanceID:        r.InstanceID,
		TargetHost:        r.TargetHost,
		TargetPort:        r.TargetPort,
		StartUnix:         r.StartUnix,
		BytesIn:           r.BytesIn,
		BytesOut:          r.BytesOut,
		Status:            r.Status,
		RecordingFile:     r.RecordingFile,
		LastSeenUnix:      r.LastSeenUnix,
		UpdatedUnix:       r.UpdatedUnix,
	}
	if r.ClosedAtUnix.Valid {
		value := r.ClosedAtUnix.Int64
		item.ClosedAtUnix = &value
	}
	return item
}

func unixUTC(value int64) time.Time {
	if value <= 0 {
		return time.Time{}
	}
	return time.Unix(value, 0).UTC()
}

func sessionDurationString(start, end time.Time) string {
	if start.IsZero() {
		return "0s"
	}
	if end.IsZero() || end.Before(start) {
		end = start
	}
	elapsed := end.Sub(start)
	days := int(elapsed / (24 * time.Hour))
	elapsed -= time.Duration(days) * 24 * time.Hour
	hours := int(elapsed / time.Hour)
	elapsed -= time.Duration(hours) * time.Hour
	minutes := int(elapsed / time.Minute)
	elapsed -= time.Duration(minutes) * time.Minute
	seconds := int(elapsed / time.Second)

	switch {
	case days > 0:
		return fmt.Sprintf("%dd%dh%dm%ds", days, hours, minutes, seconds)
	case hours > 0:
		return fmt.Sprintf("%dh%dm%ds", hours, minutes, seconds)
	case minutes > 0:
		return fmt.Sprintf("%dm%ds", minutes, seconds)
	default:
		return fmt.Sprintf("%ds", seconds)
	}
}

func normalizeSessionStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "", "active":
		return "active"
	case "closing":
		return "closing"
	case "terminated":
		return "terminated"
	default:
		return "closed"
	}
}

func sqlPlaceholders(count int) string {
	if count <= 0 {
		return ""
	}
	parts := make([]string, count)
	for i := range parts {
		parts[i] = "?"
	}
	return strings.Join(parts, ", ")
}

func (a *API) syncSessionMetadata() error {
	if a == nil || a.sessionMetadata == nil || a.dp == nil {
		return nil
	}
	a.sessionSyncMu.Lock()
	defer a.sessionSyncMu.Unlock()

	sessions, err := a.dp.ListSessions()
	if err != nil {
		return err
	}
	a.enrichSessionRecordingPaths(sessions)
	return a.sessionMetadata.UpsertSnapshot(sessions, time.Now().UTC())
}

// StartSessionMetadataSync persists live session metadata to the local session database.
func (a *API) StartSessionMetadataSync(ctx context.Context, interval time.Duration) {
	if a == nil || a.sessionMetadata == nil || ctx == nil {
		return
	}
	if interval <= 0 {
		interval = defaultSessionMetadataSyncInterval
	}
	a.sessionSyncOnce.Do(func() {
		a.sessionSyncBg.Store(true)
		_ = a.syncSessionMetadata()

		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					_ = a.syncSessionMetadata()
				}
			}
		}()
	})
}

// Close releases API resources with explicit shutdown hooks.
func (a *API) Close() error {
	if a == nil {
		return nil
	}
	var closeErr error
	if a.sessionMetadata != nil {
		closeErr = a.sessionMetadata.Close()
	}
	if a.storageDB != nil {
		if err := a.storageDB.Close(); closeErr == nil {
			closeErr = err
		}
	}
	if a.auditStore != nil {
		if err := a.auditStore.Close(); closeErr == nil {
			closeErr = err
		}
	}
	if a.auditQueue != nil {
		if err := a.auditQueue.Close(); closeErr == nil {
			closeErr = err
		}
	}
	if a.gateway != nil {
		if err := a.gateway.Close(); closeErr == nil {
			closeErr = err
		}
	}
	return closeErr
}
