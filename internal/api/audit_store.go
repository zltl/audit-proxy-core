package api

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/models"
)

const defaultAuditSyncInterval = 5 * time.Second

type auditSQLStore struct {
	cluster *sqlDBCluster
	dialect sqlDialect
}

type auditBackupEvent struct {
	Event      models.AuditEvent `json:"event"`
	RawEvent   string            `json:"raw_event,omitempty"`
	SourceFile string            `json:"source_file,omitempty"`
}

func newAuditSQLStoreFromCluster(backend string, cluster *sqlDBCluster) (*auditSQLStore, error) {
	if !auditStoreUsesSQL(backend) {
		return nil, nil
	}
	if cluster == nil {
		return nil, fmt.Errorf("audit database cluster is required")
	}
	store := &auditSQLStore{cluster: cluster, dialect: cluster.dialect}
	if err := store.init(); err != nil {
		return nil, err
	}
	return store, nil
}

func newAuditSQLStore(backend, dsn string) (*auditSQLStore, error) {
	return newAuditSQLStoreWithOptions(backend, dsn, nil, sqlPoolSettings{})
}

func newAuditSQLStoreWithOptions(backend, dsn string, readDSNs []string, settings sqlPoolSettings) (*auditSQLStore, error) {
	return newAuditSQLStoreWithDriverOptions(backend, "pgx", dsn, readDSNs, settings)
}

func newAuditSQLStoreWithDriver(backend, driver, dsn string) (*auditSQLStore, error) {
	return newAuditSQLStoreWithDriverOptions(backend, driver, dsn, nil, sqlPoolSettings{})
}

func newAuditSQLStoreWithDriverOptions(backend, driver, dsn string, readDSNs []string, settings sqlPoolSettings) (*auditSQLStore, error) {
	if !auditStoreUsesSQL(backend) {
		return nil, nil
	}
	dialect, err := sqlDialectForDriver(strings.TrimSpace(strings.ToLower(driver)))
	if err != nil {
		return nil, err
	}
	cluster, err := newSQLDBCluster(driver, dsn, readDSNs, settings)
	if err != nil {
		return nil, err
	}
	store, err := newAuditSQLStoreFromCluster(backend, cluster)
	if err != nil {
		_ = cluster.Close()
		return nil, err
	}
	store.dialect = dialect
	return store, nil
}

func (s *auditSQLStore) init() error {
	if s == nil || s.cluster == nil || s.cluster.writer == nil {
		return nil
	}
	return runSQLSchemaMigrations(s.cluster.writer, s.dialect, "audit_store", []sqlSchemaMigration{
		{
			Version: 1,
			Statements: []string{
				`CREATE TABLE IF NOT EXISTS audit_events (
					id TEXT PRIMARY KEY,
					event_unix BIGINT NOT NULL,
					event_type TEXT NOT NULL DEFAULT '',
					username TEXT NOT NULL DEFAULT '',
					source_ip TEXT NOT NULL DEFAULT '',
					target_host TEXT NOT NULL DEFAULT '',
					details TEXT NOT NULL DEFAULT '',
					session_id TEXT NOT NULL DEFAULT '',
					raw_event TEXT NOT NULL DEFAULT '',
					source_file TEXT NOT NULL DEFAULT ''
				);`,
				`CREATE INDEX IF NOT EXISTS idx_audit_events_unix ON audit_events(event_unix DESC);`,
				`CREATE INDEX IF NOT EXISTS idx_audit_events_type ON audit_events(event_type);`,
				`CREATE INDEX IF NOT EXISTS idx_audit_events_user ON audit_events(username);`,
				`CREATE INDEX IF NOT EXISTS idx_audit_events_session ON audit_events(session_id);`,
				`CREATE TABLE IF NOT EXISTS audit_file_offsets (
					path TEXT PRIMARY KEY,
					offset_bytes BIGINT NOT NULL DEFAULT 0,
					updated_at BIGINT NOT NULL DEFAULT 0
				);`,
			},
		},
	})
}

func (s *auditSQLStore) Close() error {
	if s == nil || s.cluster == nil {
		return nil
	}
	return s.cluster.Close()
}

func (s *auditSQLStore) SchemaVersion() (int, error) {
	if s == nil || s.cluster == nil || s.cluster.writer == nil {
		return 0, nil
	}
	return sqlSchemaVersion(s.cluster.writer, s.dialect, "audit_store")
}

func (s *auditSQLStore) EventCount() (int, error) {
	if s == nil || s.cluster == nil || s.cluster.writer == nil {
		return 0, nil
	}
	var count int
	if err := s.cluster.writeQueryRow(`SELECT COUNT(*) FROM audit_events`).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func (s *auditSQLStore) ReplaceEvents(events []auditBackupEvent) error {
	if s == nil || s.cluster == nil || s.cluster.writer == nil {
		return nil
	}
	tx, err := s.cluster.beginWrite()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	if _, err = tx.Exec(`DELETE FROM audit_events`); err != nil {
		return err
	}
	if _, err = tx.Exec(`DELETE FROM audit_file_offsets`); err != nil {
		return err
	}
	insert := fmt.Sprintf(`
		INSERT INTO audit_events (
			id, event_unix, event_type, username, source_ip, target_host, details, session_id, raw_event, source_file
		) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
	`, bindForDialect(s.dialect, 1), bindForDialect(s.dialect, 2), bindForDialect(s.dialect, 3), bindForDialect(s.dialect, 4), bindForDialect(s.dialect, 5), bindForDialect(s.dialect, 6), bindForDialect(s.dialect, 7), bindForDialect(s.dialect, 8), bindForDialect(s.dialect, 9), bindForDialect(s.dialect, 10))
	for _, item := range events {
		rawEvent := item.RawEvent
		if strings.TrimSpace(rawEvent) == "" {
			raw, marshalErr := json.Marshal(item.Event)
			if marshalErr != nil {
				return marshalErr
			}
			rawEvent = string(raw)
		}
		if _, err = tx.Exec(
			insert,
			item.Event.ID,
			unixTimestamp(item.Event.Timestamp),
			item.Event.EventType,
			item.Event.Username,
			item.Event.SourceIP,
			item.Event.TargetHost,
			item.Event.Details,
			item.Event.SessionID,
			rawEvent,
			item.SourceFile,
		); err != nil {
			return err
		}
	}
	err = tx.Commit()
	return err
}

func (s *auditSQLStore) bind(index int) string {
	if s != nil && s.dialect == sqlDialectPostgres {
		return fmt.Sprintf("$%d", index)
	}
	return "?"
}

func (s *auditSQLStore) ListEvents() ([]models.AuditEvent, error) {
	if s == nil || s.cluster == nil || s.cluster.writer == nil {
		return []models.AuditEvent{}, nil
	}
	rows, err := s.cluster.readQuery(`
		SELECT id, event_unix, event_type, username, source_ip, target_host, details, session_id
		FROM audit_events
		ORDER BY event_unix DESC, id DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	events := make([]models.AuditEvent, 0)
	for rows.Next() {
		var event models.AuditEvent
		var eventUnix int64
		if err := rows.Scan(
			&event.ID,
			&eventUnix,
			&event.EventType,
			&event.Username,
			&event.SourceIP,
			&event.TargetHost,
			&event.Details,
			&event.SessionID,
		); err != nil {
			return nil, err
		}
		event.Timestamp = unixTimeOrZero(eventUnix)
		events = append(events, event)
	}
	return events, rows.Err()
}

func (s *auditSQLStore) ListBackupEvents() ([]auditBackupEvent, error) {
	if s == nil || s.cluster == nil || s.cluster.writer == nil {
		return []auditBackupEvent{}, nil
	}
	rows, err := s.cluster.readQuery(`
		SELECT id, event_unix, event_type, username, source_ip, target_host, details, session_id, raw_event, source_file
		FROM audit_events
		ORDER BY event_unix DESC, id DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	events := make([]auditBackupEvent, 0)
	for rows.Next() {
		var item auditBackupEvent
		var eventUnix int64
		if err := rows.Scan(
			&item.Event.ID,
			&eventUnix,
			&item.Event.EventType,
			&item.Event.Username,
			&item.Event.SourceIP,
			&item.Event.TargetHost,
			&item.Event.Details,
			&item.Event.SessionID,
			&item.RawEvent,
			&item.SourceFile,
		); err != nil {
			return nil, err
		}
		item.Event.Timestamp = unixTimeOrZero(eventUnix)
		events = append(events, item)
	}
	return events, rows.Err()
}

func (s *auditSQLStore) SyncDir(dir string) error {
	if s == nil || s.cluster == nil || s.cluster.writer == nil {
		return nil
	}
	if strings.TrimSpace(dir) == "" {
		return fmt.Errorf("audit log directory not configured")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read audit directory: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".jsonl") && !strings.HasSuffix(name, ".log") {
			continue
		}

		path := filepath.Join(dir, name)
		info, err := entry.Info()
		if err != nil {
			return err
		}
		offset, err := s.fileOffset(path)
		if err != nil {
			return err
		}
		if info.Size() < offset {
			offset = 0
		}
		nextOffset, err := s.syncFile(path, offset)
		if err != nil {
			return err
		}
		if err := s.saveFileOffset(path, nextOffset); err != nil {
			return err
		}
	}
	return nil
}

func (s *auditSQLStore) syncFile(path string, offset int64) (int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return offset, err
	}
	defer file.Close()

	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return offset, err
	}

	reader := bufio.NewReader(file)
	currentOffset := offset
	for {
		lineOffset := currentOffset
		line, readErr := reader.ReadBytes('\n')
		currentOffset += int64(len(line))
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) > 0 {
			event, err := parseAuditLogLine(path, lineOffset, trimmed)
			if err == nil && event != nil {
				if err := s.upsertEvent(*event, string(trimmed), path); err != nil {
					return offset, err
				}
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				break
			}
			return offset, readErr
		}
	}
	return currentOffset, nil
}

func (s *auditSQLStore) upsertEvent(event models.AuditEvent, raw, sourceFile string) error {
	query := fmt.Sprintf(`
		INSERT INTO audit_events (
			id, event_unix, event_type, username, source_ip, target_host, details, session_id, raw_event, source_file
		) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
		ON CONFLICT(id) DO UPDATE SET
			event_unix = excluded.event_unix,
			event_type = excluded.event_type,
			username = excluded.username,
			source_ip = excluded.source_ip,
			target_host = excluded.target_host,
			details = excluded.details,
			session_id = excluded.session_id,
			raw_event = excluded.raw_event,
			source_file = excluded.source_file
	`, s.bind(1), s.bind(2), s.bind(3), s.bind(4), s.bind(5), s.bind(6), s.bind(7), s.bind(8), s.bind(9), s.bind(10))
	_, err := s.cluster.writeExec(
		query,
		event.ID,
		unixTimestamp(event.Timestamp),
		event.EventType,
		event.Username,
		event.SourceIP,
		event.TargetHost,
		event.Details,
		event.SessionID,
		raw,
		sourceFile,
	)
	return err
}

func (s *auditSQLStore) fileOffset(path string) (int64, error) {
	query := fmt.Sprintf(`SELECT offset_bytes FROM audit_file_offsets WHERE path = %s LIMIT 1`, s.bind(1))
	var offset int64
	err := s.cluster.writeQueryRow(query, path).Scan(&offset)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return offset, err
}

func (s *auditSQLStore) saveFileOffset(path string, offset int64) error {
	query := fmt.Sprintf(`
		INSERT INTO audit_file_offsets(path, offset_bytes, updated_at)
		VALUES (%s, %s, %s)
		ON CONFLICT(path) DO UPDATE SET
			offset_bytes = excluded.offset_bytes,
			updated_at = excluded.updated_at
	`, s.bind(1), s.bind(2), s.bind(3))
	_, err := s.cluster.writeExec(query, path, offset, time.Now().UTC().Unix())
	return err
}

func parseAuditLogLine(sourcePath string, offset int64, line []byte) (*models.AuditEvent, error) {
	var direct models.AuditEvent
	if err := json.Unmarshal(line, &direct); err == nil &&
		(direct.ID != "" || direct.EventType != "" || direct.Username != "" ||
			direct.SourceIP != "" || direct.TargetHost != "" || direct.Details != "" || direct.SessionID != "") {
		if direct.ID == "" {
			direct.ID = syntheticAuditEventID(sourcePath, offset, line)
		}
		return &direct, nil
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(line, &raw); err != nil {
		return nil, err
	}

	timestamp, err := parseAuditTimestamp(raw["timestamp"])
	if err != nil {
		return nil, err
	}
	eventType := firstNonEmptyString(raw["event_type"], raw["type"], raw["event"])
	if eventType == "" {
		return nil, fmt.Errorf("missing event type")
	}
	username := firstNonEmptyString(raw["username"], raw["user"])
	sourceIP := firstNonEmptyString(raw["source_ip"], raw["client"])
	targetHost := firstNonEmptyString(raw["target_host"], raw["target"], raw["upstream"])
	sessionID := stringifyAuditValue(raw["session_id"])
	if sessionID == "" {
		sessionID = stringifyAuditValue(raw["session"])
	}
	details := stringifyAuditValue(raw["details"])
	if details == "" {
		details = stringifyAuditValue(raw["command"])
	}
	id := firstNonEmptyString(raw["id"])
	if id == "" {
		id = syntheticAuditEventID(sourcePath, offset, line)
	}

	return &models.AuditEvent{
		ID:         id,
		Timestamp:  timestamp,
		EventType:  normalizeAuditEventType(eventType),
		Username:   username,
		SourceIP:   sourceIP,
		TargetHost: targetHost,
		Details:    details,
		SessionID:  sessionID,
	}, nil
}

func parseAuditTimestamp(value interface{}) (time.Time, error) {
	switch typed := value.(type) {
	case string:
		if strings.TrimSpace(typed) == "" {
			return time.Time{}, fmt.Errorf("empty timestamp")
		}
		if parsed, err := time.Parse(time.RFC3339, typed); err == nil {
			return parsed.UTC(), nil
		}
		if unix, err := strconv.ParseInt(typed, 10, 64); err == nil {
			return time.Unix(unix, 0).UTC(), nil
		}
	case float64:
		return time.Unix(int64(typed), 0).UTC(), nil
	case json.Number:
		unix, err := typed.Int64()
		if err != nil {
			return time.Time{}, err
		}
		return time.Unix(unix, 0).UTC(), nil
	}
	return time.Time{}, fmt.Errorf("unsupported timestamp")
}

func stringifyAuditValue(value interface{}) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return typed
	case float64:
		return strconv.FormatInt(int64(typed), 10)
	case json.Number:
		return typed.String()
	default:
		raw, err := json.Marshal(typed)
		if err != nil {
			return fmt.Sprintf("%v", typed)
		}
		return string(raw)
	}
}

func firstNonEmptyString(values ...interface{}) string {
	for _, value := range values {
		if str := strings.TrimSpace(stringifyAuditValue(value)); str != "" {
			return str
		}
	}
	return ""
}

func normalizeAuditEventType(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	value = strings.ReplaceAll(value, " ", "_")
	return value
}

func syntheticAuditEventID(sourcePath string, offset int64, line []byte) string {
	sum := sha256.Sum256(append([]byte(fmt.Sprintf("%s:%d:", sourcePath, offset)), line...))
	return "audit-" + hex.EncodeToString(sum[:12])
}

func (a *API) syncAuditStore() error {
	if a == nil || a.auditStore == nil {
		return nil
	}
	a.auditSyncMu.Lock()
	defer a.auditSyncMu.Unlock()
	return a.auditStore.SyncDir(a.config.AuditLogDir)
}

// StartAuditSync mirrors append-only audit log files into the configured SQL audit store.
func (a *API) StartAuditSync(ctx context.Context, interval time.Duration) {
	if a == nil || a.auditStore == nil || ctx == nil {
		return
	}
	if interval <= 0 {
		interval = defaultAuditSyncInterval
	}

	a.auditSyncOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()

			if err := a.syncAuditStore(); err == nil {
				a.auditSyncBg.Store(true)
			}

			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if err := a.syncAuditStore(); err == nil {
						a.auditSyncBg.Store(true)
					}
				}
			}
		}()
	})
}
