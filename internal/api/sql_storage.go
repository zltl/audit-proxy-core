package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/models"
	_ "modernc.org/sqlite"
)

var errConfigVersionNotFound = errors.New("config version not found")

type configVersionSnapshot struct {
	Version   string          `json:"version"`
	CreatedAt time.Time       `json:"created_at"`
	Snapshot  json.RawMessage `json:"snapshot"`
}

type sqlDialect int

const (
	sqlDialectSQLite sqlDialect = iota
	sqlDialectPostgres
)

type sqlStorage struct {
	cluster *sqlDBCluster
	dialect sqlDialect
}

func newSQLStorageFromCluster(cluster *sqlDBCluster) (*sqlStorage, error) {
	if cluster == nil {
		return nil, fmt.Errorf("database cluster is required")
	}
	store := &sqlStorage{cluster: cluster, dialect: cluster.dialect}
	if err := store.init(); err != nil {
		return nil, err
	}
	return store, nil
}

func newPostgresStorage(dsn string) (*sqlStorage, error) {
	return newPostgresStorageWithOptions(dsn, nil, sqlPoolSettings{})
}

func newPostgresStorageWithOptions(dsn string, readDSNs []string, settings sqlPoolSettings) (*sqlStorage, error) {
	return newSQLStorageWithOptions("pgx", dsn, readDSNs, settings)
}

func newSQLStorage(driver, dsn string) (*sqlStorage, error) {
	return newSQLStorageWithOptions(driver, dsn, nil, sqlPoolSettings{})
}

func newSQLStorageWithOptions(driver, dsn string, readDSNs []string, settings sqlPoolSettings) (*sqlStorage, error) {
	dialect, err := sqlDialectForDriver(strings.TrimSpace(strings.ToLower(driver)))
	if err != nil {
		return nil, err
	}
	cluster, err := newSQLDBCluster(driver, dsn, readDSNs, settings)
	if err != nil {
		return nil, err
	}

	store, err := newSQLStorageFromCluster(cluster)
	if err != nil {
		_ = cluster.Close()
		return nil, err
	}
	store.dialect = dialect
	return store, nil
}

func sqlDialectForDriver(driver string) (sqlDialect, error) {
	switch driver {
	case "pgx", "postgres":
		return sqlDialectPostgres, nil
	case "sqlite":
		return sqlDialectSQLite, nil
	default:
		return sqlDialectSQLite, fmt.Errorf("unsupported sql driver %q", driver)
	}
}

func configureSQLPool(db *sql.DB, dialect sqlDialect) {
	configureSQLPoolWithSettings(db, dialect, sqlPoolSettings{})
}

func (s *sqlStorage) init() error {
	if s == nil || s.cluster == nil || s.cluster.writer == nil {
		return nil
	}
	if s.dialect == sqlDialectSQLite {
		if _, err := s.cluster.writer.Exec(`PRAGMA busy_timeout = 5000;`); err != nil {
			return err
		}
	}
	return runSQLSchemaMigrations(s.cluster.writer, s.dialect, "sql_storage", []sqlSchemaMigration{
		{
			Version: 1,
			Statements: []string{
				`CREATE TABLE IF NOT EXISTS cp_config_current (
					store_key TEXT PRIMARY KEY,
					version TEXT NOT NULL,
					change_id TEXT NOT NULL DEFAULT '',
					requester TEXT NOT NULL DEFAULT '',
					source TEXT NOT NULL DEFAULT '',
					updated_at INTEGER NOT NULL,
					snapshot TEXT NOT NULL
				);`,
				`CREATE TABLE IF NOT EXISTS cp_config_versions (
					version TEXT PRIMARY KEY,
					created_at INTEGER NOT NULL,
					snapshot TEXT NOT NULL
				);`,
				`CREATE INDEX IF NOT EXISTS idx_cp_config_versions_created_at
					ON cp_config_versions(created_at DESC);`,
				`CREATE TABLE IF NOT EXISTS cp_users (
					username TEXT PRIMARY KEY,
					display_name TEXT NOT NULL DEFAULT '',
					email TEXT NOT NULL DEFAULT '',
					role TEXT NOT NULL DEFAULT '',
					pass_hash TEXT NOT NULL DEFAULT '',
					mfa_secret TEXT NOT NULL DEFAULT '',
					mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
					enabled BOOLEAN NOT NULL DEFAULT TRUE,
					allowed_ips TEXT NOT NULL DEFAULT '[]',
					created_at INTEGER NOT NULL DEFAULT 0,
					updated_at INTEGER NOT NULL DEFAULT 0,
					last_login INTEGER NOT NULL DEFAULT 0
				);`,
				`CREATE INDEX IF NOT EXISTS idx_cp_users_role ON cp_users(role);`,
				`CREATE INDEX IF NOT EXISTS idx_cp_users_enabled ON cp_users(enabled);`,
			},
		},
	})
}

func (s *sqlStorage) Close() error {
	if s == nil || s.cluster == nil {
		return nil
	}
	return s.cluster.Close()
}

func (s *sqlStorage) SchemaVersion() (int, error) {
	if s == nil || s.cluster == nil || s.cluster.writer == nil {
		return 0, nil
	}
	return sqlSchemaVersion(s.cluster.writer, s.dialect, "sql_storage")
}

func (s *sqlStorage) bind(index int) string {
	if s != nil && s.dialect == sqlDialectPostgres {
		return fmt.Sprintf("$%d", index)
	}
	return "?"
}

func (s *sqlStorage) LoadCurrentConfig() (*ConfigStoreEntry, error) {
	if s == nil || s.cluster == nil || s.cluster.writer == nil {
		return nil, nil
	}
	query := fmt.Sprintf(`
		SELECT version, change_id, requester, source, updated_at, snapshot
		FROM cp_config_current
		WHERE store_key = %s
		LIMIT 1
	`, s.bind(1))

	var entry ConfigStoreEntry
	var updatedAtUnix int64
	var snapshot string
	err := s.cluster.readQueryRow(query, "current").Scan(
		&entry.Version,
		&entry.ChangeID,
		&entry.Requester,
		&entry.Source,
		&updatedAtUnix,
		&snapshot,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	entry.UpdatedAt = unixTimeOrZero(updatedAtUnix)
	entry.Snapshot = json.RawMessage([]byte(snapshot))
	return cloneConfigStoreEntry(&entry), nil
}

func (s *sqlStorage) ReplaceCurrentConfig(entry *ConfigStoreEntry) error {
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
	if _, err = tx.Exec(`DELETE FROM cp_config_current WHERE store_key = `+bindForDialect(s.dialect, 1), "current"); err != nil {
		return err
	}
	if entry != nil && len(entry.Snapshot) > 0 {
		query := fmt.Sprintf(`
			INSERT INTO cp_config_current (
				store_key, version, change_id, requester, source, updated_at, snapshot
			) VALUES (%s, %s, %s, %s, %s, %s, %s)
		`, bindForDialect(s.dialect, 1), bindForDialect(s.dialect, 2), bindForDialect(s.dialect, 3), bindForDialect(s.dialect, 4), bindForDialect(s.dialect, 5), bindForDialect(s.dialect, 6), bindForDialect(s.dialect, 7))
		if _, err = tx.Exec(
			query,
			"current",
			entry.Version,
			entry.ChangeID,
			entry.Requester,
			entry.Source,
			unixTimestamp(entry.UpdatedAt),
			string(entry.Snapshot),
		); err != nil {
			return err
		}
	}
	err = tx.Commit()
	return err
}

func (s *sqlStorage) SaveCurrentConfig(entry *ConfigStoreEntry) error {
	if s == nil || s.cluster == nil || s.cluster.writer == nil || entry == nil || len(entry.Snapshot) == 0 {
		return nil
	}
	query := fmt.Sprintf(`
		INSERT INTO cp_config_current (
			store_key, version, change_id, requester, source, updated_at, snapshot
		) VALUES (%s, %s, %s, %s, %s, %s, %s)
		ON CONFLICT(store_key) DO UPDATE SET
			version = excluded.version,
			change_id = excluded.change_id,
			requester = excluded.requester,
			source = excluded.source,
			updated_at = excluded.updated_at,
			snapshot = excluded.snapshot
	`, s.bind(1), s.bind(2), s.bind(3), s.bind(4), s.bind(5), s.bind(6), s.bind(7))

	_, err := s.cluster.writeExec(
		query,
		"current",
		entry.Version,
		entry.ChangeID,
		entry.Requester,
		entry.Source,
		unixTimestamp(entry.UpdatedAt),
		string(entry.Snapshot),
	)
	return err
}

func (s *sqlStorage) HasConfigVersions() (bool, error) {
	if s == nil || s.cluster == nil || s.cluster.writer == nil {
		return false, nil
	}
	var count int
	if err := s.cluster.readQueryRow(`SELECT COUNT(*) FROM cp_config_versions`).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

func (s *sqlStorage) SaveConfigVersion(version string, snapshot []byte, createdAt time.Time) error {
	if s == nil || s.cluster == nil || s.cluster.writer == nil || strings.TrimSpace(version) == "" || len(snapshot) == 0 {
		return nil
	}
	query := fmt.Sprintf(`
		INSERT INTO cp_config_versions(version, created_at, snapshot)
		VALUES (%s, %s, %s)
		ON CONFLICT(version) DO NOTHING
	`, s.bind(1), s.bind(2), s.bind(3))
	_, err := s.cluster.writeExec(query, version, unixTimestamp(createdAt), string(snapshot))
	return err
}

func (s *sqlStorage) LoadConfigVersion(version string) ([]byte, error) {
	if s == nil || s.cluster == nil || s.cluster.writer == nil {
		return nil, errConfigVersionNotFound
	}
	query := fmt.Sprintf(`
		SELECT snapshot
		FROM cp_config_versions
		WHERE version = %s
		LIMIT 1
	`, s.bind(1))

	var snapshot string
	err := s.cluster.readQueryRow(query, version).Scan(&snapshot)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errConfigVersionNotFound
	}
	if err != nil {
		return nil, err
	}
	return []byte(snapshot), nil
}

func (s *sqlStorage) ListConfigVersions() ([]map[string]interface{}, error) {
	if s == nil || s.cluster == nil || s.cluster.writer == nil {
		return []map[string]interface{}{}, nil
	}
	rows, err := s.cluster.readQuery(`
		SELECT version, created_at, LENGTH(snapshot)
		FROM cp_config_versions
		ORDER BY version DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	versions := make([]map[string]interface{}, 0)
	for rows.Next() {
		var version string
		var createdAtUnix int64
		var size int64
		if err := rows.Scan(&version, &createdAtUnix, &size); err != nil {
			return nil, err
		}
		versions = append(versions, map[string]interface{}{
			"version":   version,
			"size":      size,
			"timestamp": unixTimeOrZero(createdAtUnix),
		})
	}
	return versions, rows.Err()
}

func (s *sqlStorage) ListConfigVersionSnapshots() ([]configVersionSnapshot, error) {
	if s == nil || s.cluster == nil || s.cluster.writer == nil {
		return []configVersionSnapshot{}, nil
	}
	rows, err := s.cluster.readQuery(`
		SELECT version, created_at, snapshot
		FROM cp_config_versions
		ORDER BY version ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	versions := make([]configVersionSnapshot, 0)
	for rows.Next() {
		var item configVersionSnapshot
		var createdAtUnix int64
		var snapshot string
		if err := rows.Scan(&item.Version, &createdAtUnix, &snapshot); err != nil {
			return nil, err
		}
		item.CreatedAt = unixTimeOrZero(createdAtUnix)
		item.Snapshot = json.RawMessage([]byte(snapshot))
		versions = append(versions, item)
	}
	return versions, rows.Err()
}

func (s *sqlStorage) ReplaceConfigVersions(items []configVersionSnapshot) error {
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
	if _, err = tx.Exec(`DELETE FROM cp_config_versions`); err != nil {
		return err
	}
	insert := fmt.Sprintf(`
		INSERT INTO cp_config_versions(version, created_at, snapshot)
		VALUES (%s, %s, %s)
	`, bindForDialect(s.dialect, 1), bindForDialect(s.dialect, 2), bindForDialect(s.dialect, 3))
	for _, item := range items {
		if strings.TrimSpace(item.Version) == "" || len(item.Snapshot) == 0 {
			continue
		}
		if _, err = tx.Exec(insert, item.Version, unixTimestamp(item.CreatedAt), string(item.Snapshot)); err != nil {
			return err
		}
	}
	err = tx.Commit()
	return err
}

func (s *sqlStorage) CountUsers() (int, error) {
	if s == nil || s.cluster == nil || s.cluster.writer == nil {
		return 0, nil
	}
	var count int
	if err := s.cluster.readQueryRow(`SELECT COUNT(*) FROM cp_users`).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func (s *sqlStorage) ListUsers() ([]models.User, error) {
	if s == nil || s.cluster == nil || s.cluster.writer == nil {
		return []models.User{}, nil
	}
	rows, err := s.cluster.readQuery(`
		SELECT username, display_name, email, role, pass_hash, mfa_secret, mfa_enabled,
		       enabled, allowed_ips, created_at, updated_at, last_login
		FROM cp_users
		ORDER BY username ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	users := make([]models.User, 0)
	for rows.Next() {
		user, err := scanStoredUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, rows.Err()
}

func (s *sqlStorage) GetUser(username string) (models.User, bool, error) {
	if s == nil || s.cluster == nil || s.cluster.writer == nil {
		return models.User{}, false, nil
	}
	query := fmt.Sprintf(`
		SELECT username, display_name, email, role, pass_hash, mfa_secret, mfa_enabled,
		       enabled, allowed_ips, created_at, updated_at, last_login
		FROM cp_users
		WHERE username = %s
		LIMIT 1
	`, s.bind(1))
	row := s.cluster.readQueryRow(query, username)
	user, err := scanStoredUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return models.User{}, false, nil
	}
	if err != nil {
		return models.User{}, false, err
	}
	return user, true, nil
}

func (s *sqlStorage) CreateUser(user models.User) error {
	if s == nil || s.cluster == nil || s.cluster.writer == nil {
		return nil
	}
	allowedIPs, err := encodeUserAllowedIPs(user.AllowedIPs)
	if err != nil {
		return err
	}
	query := fmt.Sprintf(`
		INSERT INTO cp_users (
			username, display_name, email, role, pass_hash, mfa_secret,
			mfa_enabled, enabled, allowed_ips, created_at, updated_at, last_login
		) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
		ON CONFLICT(username) DO NOTHING
	`, s.bind(1), s.bind(2), s.bind(3), s.bind(4), s.bind(5), s.bind(6), s.bind(7), s.bind(8), s.bind(9), s.bind(10), s.bind(11), s.bind(12))
	result, err := s.cluster.writeExec(
		query,
		user.Username,
		user.DisplayName,
		user.Email,
		user.Role,
		user.PassHash,
		user.MFASecret,
		user.MFAEnabled,
		user.Enabled,
		allowedIPs,
		unixTimestamp(user.CreatedAt),
		unixTimestamp(user.UpdatedAt),
		unixTimestamp(user.LastLogin),
	)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return errUserExists
	}
	return nil
}

func (s *sqlStorage) UpdateUser(user models.User) error {
	if s == nil || s.cluster == nil || s.cluster.writer == nil {
		return nil
	}
	allowedIPs, err := encodeUserAllowedIPs(user.AllowedIPs)
	if err != nil {
		return err
	}
	query := fmt.Sprintf(`
		UPDATE cp_users SET
			display_name = %s,
			email = %s,
			role = %s,
			pass_hash = %s,
			mfa_secret = %s,
			mfa_enabled = %s,
			enabled = %s,
			allowed_ips = %s,
			created_at = %s,
			updated_at = %s,
			last_login = %s
		WHERE username = %s
	`, s.bind(1), s.bind(2), s.bind(3), s.bind(4), s.bind(5), s.bind(6), s.bind(7), s.bind(8), s.bind(9), s.bind(10), s.bind(11), s.bind(12))
	result, err := s.cluster.writeExec(
		query,
		user.DisplayName,
		user.Email,
		user.Role,
		user.PassHash,
		user.MFASecret,
		user.MFAEnabled,
		user.Enabled,
		allowedIPs,
		unixTimestamp(user.CreatedAt),
		unixTimestamp(user.UpdatedAt),
		unixTimestamp(user.LastLogin),
		user.Username,
	)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return errUserNotFound
	}
	return nil
}

func (s *sqlStorage) DeleteUser(username string) error {
	if s == nil || s.cluster == nil || s.cluster.writer == nil {
		return nil
	}
	query := fmt.Sprintf(`DELETE FROM cp_users WHERE username = %s`, s.bind(1))
	result, err := s.cluster.writeExec(query, username)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return errUserNotFound
	}
	return nil
}

func (s *sqlStorage) ReplaceUsers(users []models.User) error {
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
	if _, err = tx.Exec(`DELETE FROM cp_users`); err != nil {
		return err
	}
	insert := fmt.Sprintf(`
		INSERT INTO cp_users (
			username, display_name, email, role, pass_hash, mfa_secret,
			mfa_enabled, enabled, allowed_ips, created_at, updated_at, last_login
		) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
	`, bindForDialect(s.dialect, 1), bindForDialect(s.dialect, 2), bindForDialect(s.dialect, 3), bindForDialect(s.dialect, 4), bindForDialect(s.dialect, 5), bindForDialect(s.dialect, 6), bindForDialect(s.dialect, 7), bindForDialect(s.dialect, 8), bindForDialect(s.dialect, 9), bindForDialect(s.dialect, 10), bindForDialect(s.dialect, 11), bindForDialect(s.dialect, 12))
	for _, user := range users {
		allowedIPs, err := encodeUserAllowedIPs(user.AllowedIPs)
		if err != nil {
			return err
		}
		if _, err = tx.Exec(
			insert,
			user.Username,
			user.DisplayName,
			user.Email,
			user.Role,
			user.PassHash,
			user.MFASecret,
			user.MFAEnabled,
			user.Enabled,
			allowedIPs,
			unixTimestamp(user.CreatedAt),
			unixTimestamp(user.UpdatedAt),
			unixTimestamp(user.LastLogin),
		); err != nil {
			return err
		}
	}
	err = tx.Commit()
	return err
}

type userScanner interface {
	Scan(dest ...interface{}) error
}

func scanStoredUser(scanner userScanner) (models.User, error) {
	var user models.User
	var allowedIPs string
	var createdAtUnix int64
	var updatedAtUnix int64
	var lastLoginUnix int64
	err := scanner.Scan(
		&user.Username,
		&user.DisplayName,
		&user.Email,
		&user.Role,
		&user.PassHash,
		&user.MFASecret,
		&user.MFAEnabled,
		&user.Enabled,
		&allowedIPs,
		&createdAtUnix,
		&updatedAtUnix,
		&lastLoginUnix,
	)
	if err != nil {
		return models.User{}, err
	}
	user.AllowedIPs, err = decodeUserAllowedIPs(allowedIPs)
	if err != nil {
		return models.User{}, err
	}
	user.CreatedAt = unixTimeOrZero(createdAtUnix)
	user.UpdatedAt = unixTimeOrZero(updatedAtUnix)
	user.LastLogin = unixTimeOrZero(lastLoginUnix)
	return user, nil
}

func encodeUserAllowedIPs(values []string) (string, error) {
	if len(values) == 0 {
		return "[]", nil
	}
	raw, err := json.Marshal(values)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func decodeUserAllowedIPs(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var values []string
	if err := json.Unmarshal([]byte(raw), &values); err != nil {
		return nil, err
	}
	return values, nil
}

func unixTimestamp(ts time.Time) int64 {
	if ts.IsZero() {
		return 0
	}
	return ts.UTC().Unix()
}

func unixTimeOrZero(ts int64) time.Time {
	if ts <= 0 {
		return time.Time{}
	}
	return time.Unix(ts, 0).UTC()
}
