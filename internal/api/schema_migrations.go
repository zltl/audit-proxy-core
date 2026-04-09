package api

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

type sqlSchemaMigration struct {
	Version    int
	Statements []string
}

func runSQLSchemaMigrations(db *sql.DB, dialect sqlDialect, component string, migrations []sqlSchemaMigration) error {
	if db == nil {
		return nil
	}
	if err := ensureSQLSchemaMigrationsTable(db); err != nil {
		return err
	}
	currentVersion, err := sqlSchemaVersion(db, dialect, component)
	if err != nil {
		return err
	}
	for _, migration := range migrations {
		if migration.Version <= currentVersion {
			continue
		}
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		for _, stmt := range migration.Statements {
			if _, err := tx.Exec(stmt); err != nil {
				_ = tx.Rollback()
				return err
			}
		}
		upsert := fmt.Sprintf(`
			INSERT INTO cp_schema_migrations(component, version, updated_at)
			VALUES (%s, %s, %s)
			ON CONFLICT(component) DO UPDATE SET
				version = excluded.version,
				updated_at = excluded.updated_at
		`, bindForDialect(dialect, 1), bindForDialect(dialect, 2), bindForDialect(dialect, 3))
		if _, err := tx.Exec(upsert, component, migration.Version, time.Now().UTC().Unix()); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		currentVersion = migration.Version
	}
	return nil
}

func ensureSQLSchemaMigrationsTable(db *sql.DB) error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS cp_schema_migrations (
		component TEXT PRIMARY KEY,
		version INTEGER NOT NULL,
		updated_at BIGINT NOT NULL
	);`)
	return err
}

func sqlSchemaVersion(db *sql.DB, dialect sqlDialect, component string) (int, error) {
	if db == nil {
		return 0, nil
	}
	query := fmt.Sprintf(`
		SELECT version
		FROM cp_schema_migrations
		WHERE component = %s
		LIMIT 1
	`, bindForDialect(dialect, 1))
	var version int
	err := db.QueryRow(query, component).Scan(&version)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return version, err
}

func bindForDialect(dialect sqlDialect, index int) string {
	if dialect == sqlDialectPostgres {
		return fmt.Sprintf("$%d", index)
	}
	return "?"
}
