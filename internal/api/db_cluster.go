package api

import (
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type sqlPoolSettings struct {
	MaxOpenConns         int
	MaxIdleConns         int
	ConnMaxLifetime      time.Duration
	ConnMaxIdleTime      time.Duration
	ReadAfterWriteWindow time.Duration
}

func defaultSQLPoolSettings(dialect sqlDialect) sqlPoolSettings {
	if dialect == sqlDialectPostgres {
		return sqlPoolSettings{
			MaxOpenConns:         10,
			MaxIdleConns:         5,
			ConnMaxLifetime:      30 * time.Minute,
			ConnMaxIdleTime:      5 * time.Minute,
			ReadAfterWriteWindow: 2 * time.Second,
		}
	}
	return sqlPoolSettings{
		MaxOpenConns:    1,
		MaxIdleConns:    1,
		ConnMaxLifetime: 0,
		ConnMaxIdleTime: 0,
	}
}

func normalizeSQLPoolSettings(dialect sqlDialect, settings sqlPoolSettings) sqlPoolSettings {
	defaults := defaultSQLPoolSettings(dialect)
	if settings.MaxOpenConns <= 0 {
		settings.MaxOpenConns = defaults.MaxOpenConns
	}
	if settings.MaxIdleConns < 0 {
		settings.MaxIdleConns = defaults.MaxIdleConns
	}
	if settings.MaxIdleConns == 0 {
		settings.MaxIdleConns = defaults.MaxIdleConns
	}
	if settings.MaxIdleConns > settings.MaxOpenConns {
		settings.MaxIdleConns = settings.MaxOpenConns
	}
	if settings.ConnMaxLifetime < 0 {
		settings.ConnMaxLifetime = defaults.ConnMaxLifetime
	}
	if settings.ConnMaxIdleTime < 0 {
		settings.ConnMaxIdleTime = defaults.ConnMaxIdleTime
	}
	if dialect == sqlDialectPostgres && settings.ConnMaxLifetime == 0 {
		settings.ConnMaxLifetime = defaults.ConnMaxLifetime
	}
	if dialect == sqlDialectPostgres && settings.ConnMaxIdleTime == 0 {
		settings.ConnMaxIdleTime = defaults.ConnMaxIdleTime
	}
	if settings.ReadAfterWriteWindow < 0 {
		settings.ReadAfterWriteWindow = defaults.ReadAfterWriteWindow
	}
	return settings
}

func configureSQLPoolWithSettings(db *sql.DB, dialect sqlDialect, settings sqlPoolSettings) {
	if db == nil {
		return
	}
	settings = normalizeSQLPoolSettings(dialect, settings)
	db.SetMaxOpenConns(settings.MaxOpenConns)
	db.SetMaxIdleConns(settings.MaxIdleConns)
	db.SetConnMaxLifetime(settings.ConnMaxLifetime)
	db.SetConnMaxIdleTime(settings.ConnMaxIdleTime)
}

type sqlDBCluster struct {
	dialect              sqlDialect
	writer               *sql.DB
	readers              []*sql.DB
	readAfterWriteWindow time.Duration
	preferWriterUntil    atomic.Int64
	nextReader           atomic.Uint64
	closeOnce            sync.Once
}

func newSQLDBCluster(driver, writerDSN string, readerDSNs []string, settings sqlPoolSettings) (*sqlDBCluster, error) {
	driver = strings.TrimSpace(strings.ToLower(driver))
	writerDSN = strings.TrimSpace(writerDSN)
	if writerDSN == "" {
		return nil, fmt.Errorf("database url is required")
	}

	dialect, err := sqlDialectForDriver(driver)
	if err != nil {
		return nil, err
	}
	settings = normalizeSQLPoolSettings(dialect, settings)

	writer, err := openSQLPool(driver, writerDSN, dialect, settings)
	if err != nil {
		return nil, err
	}
	cluster := &sqlDBCluster{
		dialect:              dialect,
		writer:               writer,
		readAfterWriteWindow: settings.ReadAfterWriteWindow,
	}
	for _, dsn := range cleanedDatabaseURLs(readerDSNs) {
		reader, err := openSQLPool(driver, dsn, dialect, settings)
		if err != nil {
			_ = cluster.Close()
			return nil, err
		}
		cluster.readers = append(cluster.readers, reader)
	}
	return cluster, nil
}

func openSQLPool(driver, dsn string, dialect sqlDialect, settings sqlPoolSettings) (*sql.DB, error) {
	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, err
	}
	configureSQLPoolWithSettings(db, dialect, settings)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

func (c *sqlDBCluster) Close() error {
	if c == nil {
		return nil
	}
	var closeErr error
	c.closeOnce.Do(func() {
		closed := map[*sql.DB]struct{}{}
		for _, db := range append([]*sql.DB{c.writer}, c.readers...) {
			if db == nil {
				continue
			}
			if _, ok := closed[db]; ok {
				continue
			}
			closed[db] = struct{}{}
			if err := db.Close(); err != nil && closeErr == nil {
				closeErr = err
			}
		}
	})
	return closeErr
}

func (c *sqlDBCluster) writeExec(query string, args ...interface{}) (sql.Result, error) {
	if c == nil || c.writer == nil {
		return nil, fmt.Errorf("database unavailable")
	}
	result, err := c.writer.Exec(query, args...)
	if err == nil {
		c.markWriteObserved()
	}
	return result, err
}

func (c *sqlDBCluster) readQuery(query string, args ...interface{}) (*sql.Rows, error) {
	db := c.readDB()
	if db == nil {
		return nil, fmt.Errorf("database unavailable")
	}
	return db.Query(query, args...)
}

func (c *sqlDBCluster) readQueryRow(query string, args ...interface{}) *sql.Row {
	db := c.readDB()
	if db == nil {
		return nil
	}
	return db.QueryRow(query, args...)
}

func (c *sqlDBCluster) writeQueryRow(query string, args ...interface{}) *sql.Row {
	if c == nil || c.writer == nil {
		return nil
	}
	return c.writer.QueryRow(query, args...)
}

func (c *sqlDBCluster) writeQuery(query string, args ...interface{}) (*sql.Rows, error) {
	if c == nil || c.writer == nil {
		return nil, fmt.Errorf("database unavailable")
	}
	return c.writer.Query(query, args...)
}

func (c *sqlDBCluster) beginWrite() (*sql.Tx, error) {
	if c == nil || c.writer == nil {
		return nil, fmt.Errorf("database unavailable")
	}
	c.markWriteObserved()
	return c.writer.Begin()
}

func (c *sqlDBCluster) markWriteObserved() {
	if c == nil || c.readAfterWriteWindow <= 0 {
		return
	}
	c.preferWriterUntil.Store(time.Now().Add(c.readAfterWriteWindow).UnixNano())
}

func (c *sqlDBCluster) readDB() *sql.DB {
	if c == nil {
		return nil
	}
	if c.writer == nil {
		return nil
	}
	if len(c.readers) == 0 {
		return c.writer
	}
	if time.Now().UnixNano() < c.preferWriterUntil.Load() {
		return c.writer
	}
	index := c.nextReader.Add(1) - 1
	return c.readers[index%uint64(len(c.readers))]
}

func cleanedDatabaseURLs(raw []string) []string {
	values := make([]string, 0, len(raw))
	seen := map[string]struct{}{}
	for _, item := range raw {
		for _, token := range strings.FieldsFunc(item, func(r rune) bool {
			return r == ',' || r == '\n' || r == '\r'
		}) {
			value := strings.TrimSpace(token)
			if value == "" {
				continue
			}
			if _, ok := seen[value]; ok {
				continue
			}
			seen[value] = struct{}{}
			values = append(values, value)
		}
	}
	return values
}
