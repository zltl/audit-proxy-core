// Package dbx holds the SQL plumbing shared by the control plane and the data
// plane: dialect handling, placeholder generation, and a versioned migration
// runner keyed by component so independent subsystems can evolve their schema
// without coordinating version numbers.
package dbx

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // Postgres driver, registered as "pgx"
	_ "modernc.org/sqlite"             // cgo-free SQLite driver
)

// Dialect identifies the SQL flavour in use. Only the differences that actually
// matter to this codebase are modelled: placeholder syntax and a few DDL types.
type Dialect int

const (
	SQLite Dialect = iota
	Postgres
)

func (d Dialect) String() string {
	switch d {
	case Postgres:
		return "postgres"
	default:
		return "sqlite"
	}
}

// DialectForDriver maps a database/sql driver name to a Dialect.
func DialectForDriver(driver string) (Dialect, error) {
	switch strings.TrimSpace(strings.ToLower(driver)) {
	case "pgx", "postgres", "postgresql":
		return Postgres, nil
	case "sqlite", "sqlite3":
		return SQLite, nil
	default:
		return SQLite, fmt.Errorf("dbx: unsupported sql driver %q", driver)
	}
}

// Bind returns the placeholder for the index-th parameter (1-based).
func Bind(d Dialect, index int) string {
	if d == Postgres {
		return fmt.Sprintf("$%d", index)
	}
	return "?"
}

// Binds returns a comma-separated placeholder list for n parameters, which is
// what INSERT statements need and what is easy to get wrong by hand.
func Binds(d Dialect, n int) string {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = Bind(d, i+1)
	}
	return strings.Join(parts, ", ")
}

// BoolType is the column type for booleans.
func (d Dialect) BoolType() string {
	if d == Postgres {
		return "BOOLEAN"
	}
	return "BOOLEAN"
}

// Open connects with sane pool defaults and verifies the connection.
func Open(driver, dsn string) (*sql.DB, Dialect, error) {
	dialect, err := DialectForDriver(driver)
	if err != nil {
		return nil, dialect, err
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, dialect, fmt.Errorf("dbx: open %s: %w", driver, err)
	}
	if dialect == SQLite {
		// A single writer avoids "database is locked" under concurrent writes,
		// and WAL keeps readers from blocking behind it.
		db.SetMaxOpenConns(1)
		if _, err := db.Exec(`PRAGMA journal_mode = WAL;`); err != nil {
			_ = db.Close()
			return nil, dialect, fmt.Errorf("dbx: enable WAL: %w", err)
		}
		if _, err := db.Exec(`PRAGMA busy_timeout = 5000;`); err != nil {
			_ = db.Close()
			return nil, dialect, fmt.Errorf("dbx: set busy_timeout: %w", err)
		}
		if _, err := db.Exec(`PRAGMA foreign_keys = ON;`); err != nil {
			_ = db.Close()
			return nil, dialect, fmt.Errorf("dbx: enable foreign_keys: %w", err)
		}
	} else {
		db.SetMaxOpenConns(20)
		db.SetMaxIdleConns(5)
		db.SetConnMaxLifetime(30 * time.Minute)
		db.SetConnMaxIdleTime(5 * time.Minute)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, dialect, fmt.Errorf("dbx: ping: %w", err)
	}
	return db, dialect, nil
}

// Migration is one forward-only schema step for a component.
type Migration struct {
	Version    int
	Statements []string
}

// migrationsTable is shared with the control plane's own migration runner; both
// use CREATE TABLE IF NOT EXISTS and key rows by component name.
const migrationsTable = "cp_schema_migrations"

// Migrate applies every migration newer than the component's recorded version,
// each in its own transaction so a failure leaves the schema at the last
// version that fully applied rather than half-way through one.
func Migrate(db *sql.DB, d Dialect, component string, migrations []Migration) error {
	if db == nil {
		return nil
	}
	if err := ensureMigrationsTable(db); err != nil {
		return err
	}
	current, err := SchemaVersion(db, d, component)
	if err != nil {
		return err
	}
	for _, migration := range migrations {
		if migration.Version <= current {
			continue
		}
		if err := applyMigration(db, d, component, migration); err != nil {
			return fmt.Errorf("dbx: %s migration %d: %w", component, migration.Version, err)
		}
		current = migration.Version
	}
	return nil
}

func applyMigration(db *sql.DB, d Dialect, component string, migration Migration) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	for _, stmt := range migration.Statements {
		if strings.TrimSpace(stmt) == "" {
			continue
		}
		if _, err := tx.Exec(stmt); err != nil {
			return fmt.Errorf("statement %q: %w", firstLine(stmt), err)
		}
	}
	upsert := fmt.Sprintf(`
		INSERT INTO %s(component, version, updated_at)
		VALUES (%s, %s, %s)
		ON CONFLICT(component) DO UPDATE SET
			version = excluded.version,
			updated_at = excluded.updated_at
	`, migrationsTable, Bind(d, 1), Bind(d, 2), Bind(d, 3))
	if _, err := tx.Exec(upsert, component, migration.Version, time.Now().UTC().Unix()); err != nil {
		return err
	}
	return tx.Commit()
}

func ensureMigrationsTable(db *sql.DB) error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS ` + migrationsTable + ` (
		component TEXT PRIMARY KEY,
		version INTEGER NOT NULL,
		updated_at BIGINT NOT NULL
	);`)
	return err
}

// SchemaVersion returns the recorded version for a component, or 0 if it has
// never been migrated.
func SchemaVersion(db *sql.DB, d Dialect, component string) (int, error) {
	if db == nil {
		return 0, nil
	}
	if err := ensureMigrationsTable(db); err != nil {
		return 0, err
	}
	query := fmt.Sprintf(`SELECT version FROM %s WHERE component = %s LIMIT 1`, migrationsTable, Bind(d, 1))
	var version int
	err := db.QueryRow(query, component).Scan(&version)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return version, err
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i] + " …"
	}
	return s
}

// Unix converts a time to the integer representation used throughout the
// schema, mapping the zero time to 0 rather than a negative epoch offset.
func Unix(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UTC().Unix()
}

// FromUnix is the inverse of Unix.
func FromUnix(sec int64) time.Time {
	if sec <= 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0).UTC()
}
