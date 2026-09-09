package api

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/zltl/audit-proxy-core/internal/models"
)

// auditClickHouseStore indexes audit events in ClickHouse.
//
// ClickHouse is the right home for this data once a deployment has enough of
// it: audit events are append-only, queried by time range and a handful of
// low-cardinality dimensions, and retained for months or years. That is what a
// column store is for, and it is where a relational store starts to struggle.
type auditClickHouseStore struct {
	db *sql.DB
	// retentionDays drives the table's TTL. Expiry belongs in the schema rather
	// than in a deletion job, so retention holds even if nothing is running it.
	retentionDays int
	// batchSize bounds how many rows are sent in one insert. ClickHouse is
	// built for large batches and degrades badly on row-at-a-time writes.
	batchSize int
}

const (
	defaultClickHouseBatchSize = 1000
	// defaultClickHouseRetentionDays is deliberately long: audit data usually
	// has a compliance-driven lifetime, and deleting it early is worse than
	// keeping it.
	defaultClickHouseRetentionDays = 365
)

// auditStoreUsesClickHouse reports whether the backend name selects ClickHouse.
func auditStoreUsesClickHouse(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "clickhouse":
		return true
	default:
		return false
	}
}

// newAuditClickHouseStore connects and applies the schema.
func newAuditClickHouseStore(cfg *Config) (*auditClickHouseStore, error) {
	if cfg == nil {
		return nil, fmt.Errorf("clickhouse audit store: configuration is required")
	}
	dsn := strings.TrimSpace(cfg.AuditStoreDatabaseURL)
	if dsn == "" {
		dsn = strings.TrimSpace(cfg.AuditStoreEndpoint)
	}
	if dsn == "" {
		return nil, fmt.Errorf("clickhouse audit store: audit_store_database_url is required")
	}

	options, err := clickHouseOptions(dsn, cfg)
	if err != nil {
		return nil, err
	}
	db := clickhouse.OpenDB(options)
	// ClickHouse connections are cheap to hold and expensive to churn; a small
	// bounded pool avoids both extremes.
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(time.Hour)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("clickhouse audit store: connect: %w", err)
	}

	store := &auditClickHouseStore{
		db:            db,
		retentionDays: defaultClickHouseRetentionDays,
		batchSize:     defaultClickHouseBatchSize,
	}
	if cfg.AuditRetentionDays > 0 {
		store.retentionDays = cfg.AuditRetentionDays
	}
	if err := store.init(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

// clickHouseOptions builds connection options from a DSN plus the shared
// credential fields, so a deployment can keep the password out of the DSN.
func clickHouseOptions(dsn string, cfg *Config) (*clickhouse.Options, error) {
	options, err := clickhouse.ParseDSN(dsn)
	if err != nil {
		// A bare host:port is a reasonable thing to configure; upgrade it to a
		// DSN rather than rejecting it.
		if !strings.Contains(dsn, "://") {
			options, err = clickhouse.ParseDSN("clickhouse://" + dsn)
		}
		if err != nil {
			return nil, fmt.Errorf("clickhouse audit store: parse address: %w", err)
		}
	}
	if options.Auth.Database == "" {
		options.Auth.Database = "default"
	}
	if user := strings.TrimSpace(cfg.AuditStoreUsername); user != "" {
		options.Auth.Username = user
	}
	if password := cfg.AuditStorePassword; password != "" {
		options.Auth.Password = password
	}
	if cfg.AuditStoreInsecureTLS {
		if options.TLS == nil {
			options.TLS = &tls.Config{}
		}
		options.TLS.InsecureSkipVerify = true
	}
	options.DialTimeout = 10 * time.Second
	options.Compression = &clickhouse.Compression{Method: clickhouse.CompressionLZ4}
	return options, nil
}

func (s *auditClickHouseStore) init(ctx context.Context) error {
	// ReplacingMergeTree keyed by the deterministic event id makes ingestion
	// idempotent. That matters because the insert and the offset update cannot
	// be one atomic operation: a crash between them replays some lines, and
	// without deduplication those would become duplicate audit records.
	statements := []string{
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS audit_events (
			id String,
			event_time DateTime64(3, 'UTC'),
			event_date Date MATERIALIZED toDate(event_time),
			event_type LowCardinality(String),
			username LowCardinality(String),
			source_ip String,
			target_host String,
			session_id String,
			details String,
			raw_event String,
			source_file String,
			ingested_at DateTime DEFAULT now()
		) ENGINE = ReplacingMergeTree(ingested_at)
		PARTITION BY toYYYYMM(event_date)
		ORDER BY (event_date, event_type, username, id)
		TTL event_date + INTERVAL %d DAY`, s.retentionDays),

		// Offsets live in ClickHouse rather than in a local file so that a node
		// replacement does not re-ingest the whole directory.
		`CREATE TABLE IF NOT EXISTS audit_file_offsets (
			path String,
			offset_bytes Int64,
			updated_at DateTime
		) ENGINE = ReplacingMergeTree(updated_at)
		ORDER BY path`,
	}
	for _, stmt := range statements {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("clickhouse audit store: apply schema: %w", err)
		}
	}
	return nil
}

// Close releases the connection pool.
func (s *auditClickHouseStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// ListEvents returns recent events, newest first.
//
// FINAL collapses the duplicate rows a ReplacingMergeTree may still hold before
// a merge, so a replayed line is not reported twice.
func (s *auditClickHouseStore) ListEvents() ([]models.AuditEvent, error) {
	if s == nil || s.db == nil {
		return []models.AuditEvent{}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, event_time, event_type, username, source_ip, target_host, details, session_id
		FROM audit_events FINAL
		ORDER BY event_time DESC, id DESC
		LIMIT 10000
	`)
	if err != nil {
		return nil, fmt.Errorf("clickhouse audit store: query events: %w", err)
	}
	defer func() { _ = rows.Close() }()

	events := make([]models.AuditEvent, 0)
	for rows.Next() {
		var (
			event     models.AuditEvent
			timestamp time.Time
		)
		if err := rows.Scan(&event.ID, &timestamp, &event.EventType, &event.Username,
			&event.SourceIP, &event.TargetHost, &event.Details, &event.SessionID); err != nil {
			return nil, fmt.Errorf("clickhouse audit store: scan event: %w", err)
		}
		event.Timestamp = timestamp.UTC()
		events = append(events, event)
	}
	return events, rows.Err()
}

// SyncDir ingests everything written since the last run.
func (s *auditClickHouseStore) SyncDir(dir string) error {
	if s == nil || s.db == nil {
		return nil
	}
	if strings.TrimSpace(dir) == "" {
		return fmt.Errorf("clickhouse audit store: audit log directory is not configured")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("clickhouse audit store: read audit directory: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	offsets, err := s.loadOffsets()
	if err != nil {
		return err
	}

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
		offset := offsets[path]
		if offset > info.Size() {
			// The file shrank, which means it was rotated or truncated in place.
			// Continuing from the old offset would skip the new contents.
			offset = 0
		}
		if offset == info.Size() {
			continue
		}
		newOffset, err := s.syncFile(path, offset)
		if err != nil {
			return err
		}
		if newOffset != offset {
			if err := s.saveOffset(path, newOffset); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *auditClickHouseStore) syncFile(path string, offset int64) (int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return offset, err
	}
	defer func() { _ = file.Close() }()

	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return offset, err
	}

	reader := bufio.NewReader(file)
	currentOffset := offset
	batch := make([]auditBackupEvent, 0, s.batchSize)
	// committedOffset trails the read position by whatever is still unflushed,
	// so a failure mid-directory resumes from data that was actually stored.
	committedOffset := offset

	flush := func(upTo int64) error {
		if len(batch) == 0 {
			return nil
		}
		if err := s.insertBatch(batch); err != nil {
			return err
		}
		batch = batch[:0]
		committedOffset = upTo
		return nil
	}

	for {
		lineOffset := currentOffset
		line, readErr := reader.ReadBytes('\n')
		currentOffset += int64(len(line))

		if trimmed := bytes.TrimSpace(line); len(trimmed) > 0 {
			event, parseErr := parseAuditLogLine(path, lineOffset, trimmed)
			if parseErr == nil && event != nil {
				batch = append(batch, auditBackupEvent{
					Event:      *event,
					RawEvent:   string(trimmed),
					SourceFile: path,
				})
				if len(batch) >= s.batchSize {
					if err := flush(currentOffset); err != nil {
						return committedOffset, err
					}
				}
			}
		}

		if readErr != nil {
			if readErr == io.EOF {
				// A trailing partial line has no newline yet; leaving the offset
				// before it means the complete line is read on the next pass.
				if len(line) > 0 && !bytes.HasSuffix(line, []byte("\n")) {
					currentOffset = lineOffset
				}
				if err := flush(currentOffset); err != nil {
					return committedOffset, err
				}
				return committedOffset, nil
			}
			if err := flush(currentOffset); err != nil {
				return committedOffset, err
			}
			return committedOffset, readErr
		}
	}
}

// insertBatch writes a batch of events.
func (s *auditClickHouseStore) insertBatch(events []auditBackupEvent) error {
	if len(events) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("clickhouse audit store: begin batch: %w", err)
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO audit_events
		(id, event_time, event_type, username, source_ip, target_host, session_id, details, raw_event, source_file)`)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("clickhouse audit store: prepare batch: %w", err)
	}
	for _, item := range events {
		timestamp := item.Event.Timestamp
		if timestamp.IsZero() {
			timestamp = time.Now().UTC()
		}
		if _, err := stmt.ExecContext(ctx,
			item.Event.ID,
			timestamp.UTC(),
			item.Event.EventType,
			item.Event.Username,
			item.Event.SourceIP,
			item.Event.TargetHost,
			item.Event.SessionID,
			item.Event.Details,
			item.RawEvent,
			item.SourceFile,
		); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("clickhouse audit store: append to batch: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("clickhouse audit store: send batch: %w", err)
	}
	return nil
}

func (s *auditClickHouseStore) loadOffsets() (map[string]int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	rows, err := s.db.QueryContext(ctx, `SELECT path, offset_bytes FROM audit_file_offsets FINAL`)
	if err != nil {
		return nil, fmt.Errorf("clickhouse audit store: load offsets: %w", err)
	}
	defer func() { _ = rows.Close() }()

	offsets := make(map[string]int64)
	for rows.Next() {
		var (
			path   string
			offset int64
		)
		if err := rows.Scan(&path, &offset); err != nil {
			return nil, fmt.Errorf("clickhouse audit store: scan offset: %w", err)
		}
		offsets[path] = offset
	}
	return offsets, rows.Err()
}

func (s *auditClickHouseStore) saveOffset(path string, offset int64) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO audit_file_offsets (path, offset_bytes, updated_at) VALUES (?, ?, ?)`,
		path, offset, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("clickhouse audit store: save offset: %w", err)
	}
	return nil
}

// redactClickHouseDSN removes credentials so a DSN can appear in a log line.
func redactClickHouseDSN(dsn string) string {
	parsed, err := url.Parse(dsn)
	if err != nil || parsed.User == nil {
		return dsn
	}
	parsed.User = url.User(parsed.User.Username())
	return parsed.String()
}
