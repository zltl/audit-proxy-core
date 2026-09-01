package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

const userColumns = `id, username, display_name, email, status, source, password_hash,
	password_changed_at, password_change_required, mfa_type, mfa_secret_ref, mfa_pending,
	created_at, updated_at, last_login_at`

// CreateUser inserts a new identity. PasswordHash must already be hashed.
func (s *Store) CreateUser(u User) (User, error) {
	u.Username = strings.TrimSpace(u.Username)
	if u.Username == "" {
		return User{}, fmt.Errorf("store: username is required")
	}
	if u.ID == "" {
		u.ID = NewID("usr")
	}
	if u.Status == "" {
		u.Status = UserActive
	}
	if u.Source == "" {
		u.Source = SourceLocal
	}
	if u.MFAType == "" {
		u.MFAType = MFANone
	}
	now := s.clock()
	if u.CreatedAt.IsZero() {
		u.CreatedAt = now
	}
	u.UpdatedAt = now

	query := fmt.Sprintf(`INSERT INTO dp_users (%s) VALUES (%s)
		ON CONFLICT(username) DO NOTHING`, userColumns, s.binds(15))
	result, err := s.db.Exec(query,
		u.ID, u.Username, u.DisplayName, u.Email, string(u.Status), string(u.Source),
		u.PasswordHash, s.unix(u.PasswordChangedAt), u.PasswordChangeRequired,
		string(u.MFAType), u.MFASecretRef, u.MFAPending,
		s.unix(u.CreatedAt), s.unix(u.UpdatedAt), s.unix(u.LastLoginAt),
	)
	if err != nil {
		return User{}, err
	}
	affected, err := rowsAffected(result)
	if err != nil {
		return User{}, err
	}
	if affected == 0 {
		return User{}, fmt.Errorf("%w: user %q", ErrConflict, u.Username)
	}
	return u, nil
}

// GetUser looks an identity up by username.
func (s *Store) GetUser(username string) (User, error) {
	query := fmt.Sprintf(`SELECT %s FROM dp_users WHERE username = %s LIMIT 1`, userColumns, s.bind(1))
	return s.scanUserRow(s.db.QueryRow(query, strings.TrimSpace(username)))
}

// GetUserByID looks an identity up by its stable identifier.
func (s *Store) GetUserByID(id string) (User, error) {
	query := fmt.Sprintf(`SELECT %s FROM dp_users WHERE id = %s LIMIT 1`, userColumns, s.bind(1))
	return s.scanUserRow(s.db.QueryRow(query, id))
}

// ListUsers returns every identity, ordered by username.
func (s *Store) ListUsers() ([]User, error) {
	rows, err := s.db.Query(fmt.Sprintf(`SELECT %s FROM dp_users ORDER BY username ASC`, userColumns))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	users := make([]User, 0)
	for rows.Next() {
		u, err := s.scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// UpdateUser applies mutate to the stored record and writes it back.
//
// Read-modify-write is done inside a transaction so that two concurrent updates
// cannot silently drop one another's changes, which matters here because these
// rows carry credentials and enrolment state.
func (s *Store) UpdateUser(username string, mutate func(*User) error) (User, error) {
	username = strings.TrimSpace(username)
	tx, err := s.db.Begin()
	if err != nil {
		return User{}, err
	}
	defer func() { _ = tx.Rollback() }()

	selectQuery := fmt.Sprintf(`SELECT %s FROM dp_users WHERE username = %s LIMIT 1`, userColumns, s.bind(1))
	u, err := s.scanUserRow(tx.QueryRow(selectQuery, username))
	if err != nil {
		return User{}, err
	}
	if err := mutate(&u); err != nil {
		return User{}, err
	}
	u.UpdatedAt = s.clock()

	updateQuery := fmt.Sprintf(`UPDATE dp_users SET
		display_name = %s, email = %s, status = %s, source = %s, password_hash = %s,
		password_changed_at = %s, password_change_required = %s, mfa_type = %s,
		mfa_secret_ref = %s, mfa_pending = %s, updated_at = %s, last_login_at = %s
		WHERE id = %s`,
		s.bind(1), s.bind(2), s.bind(3), s.bind(4), s.bind(5), s.bind(6), s.bind(7),
		s.bind(8), s.bind(9), s.bind(10), s.bind(11), s.bind(12), s.bind(13))
	if _, err := tx.Exec(updateQuery,
		u.DisplayName, u.Email, string(u.Status), string(u.Source), u.PasswordHash,
		s.unix(u.PasswordChangedAt), u.PasswordChangeRequired, string(u.MFAType),
		u.MFASecretRef, u.MFAPending, s.unix(u.UpdatedAt), s.unix(u.LastLoginAt), u.ID,
	); err != nil {
		return User{}, err
	}
	if err := tx.Commit(); err != nil {
		return User{}, err
	}
	return u, nil
}

// DeleteUser removes an identity and the public keys bound to it.
func (s *Store) DeleteUser(username string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var id string
	err = tx.QueryRow(fmt.Sprintf(`SELECT id FROM dp_users WHERE username = %s`, s.bind(1)),
		strings.TrimSpace(username)).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: user %q", ErrNotFound, username)
	}
	if err != nil {
		return err
	}
	if _, err := tx.Exec(fmt.Sprintf(`DELETE FROM dp_user_public_keys WHERE user_id = %s`, s.bind(1)), id); err != nil {
		return err
	}
	if _, err := tx.Exec(fmt.Sprintf(`DELETE FROM dp_role_bindings WHERE subject_kind = %s AND subject = %s`,
		s.bind(1), s.bind(2)), string(SubjectUser), username); err != nil {
		return err
	}
	if _, err := tx.Exec(fmt.Sprintf(`DELETE FROM dp_users WHERE id = %s`, s.bind(1)), id); err != nil {
		return err
	}
	return tx.Commit()
}

// RecordLogin stamps a successful authentication.
func (s *Store) RecordLogin(username string, at time.Time) error {
	query := fmt.Sprintf(`UPDATE dp_users SET last_login_at = %s WHERE username = %s`, s.bind(1), s.bind(2))
	return requireAffected(s.db.Exec(query, s.unix(at), strings.TrimSpace(username)))
}

type rowScanner interface {
	Scan(dest ...interface{}) error
}

func (s *Store) scanUserRow(row rowScanner) (User, error) {
	u, err := s.scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

func (s *Store) scanUser(row rowScanner) (User, error) {
	var (
		u                 User
		status, source    string
		mfaType           string
		passwordChangedAt int64
		createdAt         int64
		updatedAt         int64
		lastLoginAt       int64
	)
	if err := row.Scan(
		&u.ID, &u.Username, &u.DisplayName, &u.Email, &status, &source, &u.PasswordHash,
		&passwordChangedAt, &u.PasswordChangeRequired, &mfaType, &u.MFASecretRef, &u.MFAPending,
		&createdAt, &updatedAt, &lastLoginAt,
	); err != nil {
		return User{}, err
	}
	u.Status = UserStatus(status)
	u.Source = IdentitySource(source)
	u.MFAType = MFAType(mfaType)
	u.PasswordChangedAt = fromUnix(passwordChangedAt)
	u.CreatedAt = fromUnix(createdAt)
	u.UpdatedAt = fromUnix(updatedAt)
	u.LastLoginAt = fromUnix(lastLoginAt)
	return u, nil
}

// --------------------------------------------------------------------------
// Public keys
// --------------------------------------------------------------------------

const publicKeyColumns = `id, user_id, fingerprint, algorithm, public_key, comment,
	expires_at, created_at, last_used_at`

// AddPublicKey authorises an SSH public key for a user.
func (s *Store) AddPublicKey(k PublicKey) (PublicKey, error) {
	if strings.TrimSpace(k.UserID) == "" {
		return PublicKey{}, fmt.Errorf("store: user_id is required")
	}
	if strings.TrimSpace(k.Fingerprint) == "" {
		return PublicKey{}, fmt.Errorf("store: fingerprint is required")
	}
	if k.ID == "" {
		k.ID = NewID("key")
	}
	if k.CreatedAt.IsZero() {
		k.CreatedAt = s.clock()
	}
	query := fmt.Sprintf(`INSERT INTO dp_user_public_keys (%s) VALUES (%s)
		ON CONFLICT(fingerprint) DO NOTHING`, publicKeyColumns, s.binds(9))
	result, err := s.db.Exec(query, k.ID, k.UserID, k.Fingerprint, k.Algorithm, k.PublicKey,
		k.Comment, s.unix(k.ExpiresAt), s.unix(k.CreatedAt), s.unix(k.LastUsedAt))
	if err != nil {
		return PublicKey{}, err
	}
	affected, err := rowsAffected(result)
	if err != nil {
		return PublicKey{}, err
	}
	if affected == 0 {
		return PublicKey{}, fmt.Errorf("%w: public key %s", ErrConflict, k.Fingerprint)
	}
	return k, nil
}

// ListPublicKeys returns the keys authorised for a user.
func (s *Store) ListPublicKeys(userID string) ([]PublicKey, error) {
	query := fmt.Sprintf(`SELECT %s FROM dp_user_public_keys WHERE user_id = %s ORDER BY created_at ASC`,
		publicKeyColumns, s.bind(1))
	rows, err := s.db.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	keys := make([]PublicKey, 0)
	for rows.Next() {
		k, err := scanPublicKey(rows)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

// FindPublicKey resolves a key by fingerprint along with its owner. This is the
// hot path for publickey authentication, so it is a single indexed lookup
// rather than a scan over each user's key list.
func (s *Store) FindPublicKey(fingerprint string) (PublicKey, User, error) {
	query := fmt.Sprintf(`SELECT k.id, k.user_id, k.fingerprint, k.algorithm, k.public_key,
		k.comment, k.expires_at, k.created_at, k.last_used_at,
		%s
		FROM dp_user_public_keys k
		JOIN dp_users u ON u.id = k.user_id
		WHERE k.fingerprint = %s LIMIT 1`,
		prefixColumns("u.", userColumns), s.bind(1))

	row := s.db.QueryRow(query, strings.TrimSpace(fingerprint))

	var (
		k                 PublicKey
		expiresAt         int64
		keyCreatedAt      int64
		lastUsedAt        int64
		u                 User
		status, source    string
		mfaType           string
		passwordChangedAt int64
		userCreatedAt     int64
		userUpdatedAt     int64
		userLastLoginAt   int64
	)
	err := row.Scan(
		&k.ID, &k.UserID, &k.Fingerprint, &k.Algorithm, &k.PublicKey, &k.Comment,
		&expiresAt, &keyCreatedAt, &lastUsedAt,
		&u.ID, &u.Username, &u.DisplayName, &u.Email, &status, &source, &u.PasswordHash,
		&passwordChangedAt, &u.PasswordChangeRequired, &mfaType, &u.MFASecretRef, &u.MFAPending,
		&userCreatedAt, &userUpdatedAt, &userLastLoginAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return PublicKey{}, User{}, ErrNotFound
	}
	if err != nil {
		return PublicKey{}, User{}, err
	}
	k.ExpiresAt = fromUnix(expiresAt)
	k.CreatedAt = fromUnix(keyCreatedAt)
	k.LastUsedAt = fromUnix(lastUsedAt)
	u.Status = UserStatus(status)
	u.Source = IdentitySource(source)
	u.MFAType = MFAType(mfaType)
	u.PasswordChangedAt = fromUnix(passwordChangedAt)
	u.CreatedAt = fromUnix(userCreatedAt)
	u.UpdatedAt = fromUnix(userUpdatedAt)
	u.LastLoginAt = fromUnix(userLastLoginAt)
	return k, u, nil
}

// TouchPublicKey records that a key was used to authenticate.
func (s *Store) TouchPublicKey(fingerprint string, at time.Time) error {
	query := fmt.Sprintf(`UPDATE dp_user_public_keys SET last_used_at = %s WHERE fingerprint = %s`,
		s.bind(1), s.bind(2))
	_, err := s.db.Exec(query, s.unix(at), fingerprint)
	return err
}

// DeletePublicKey revokes an authorised key.
func (s *Store) DeletePublicKey(fingerprint string) error {
	query := fmt.Sprintf(`DELETE FROM dp_user_public_keys WHERE fingerprint = %s`, s.bind(1))
	return requireAffected(s.db.Exec(query, fingerprint))
}

func scanPublicKey(row rowScanner) (PublicKey, error) {
	var (
		k                                PublicKey
		expiresAt, createdAt, lastUsedAt int64
	)
	if err := row.Scan(&k.ID, &k.UserID, &k.Fingerprint, &k.Algorithm, &k.PublicKey,
		&k.Comment, &expiresAt, &createdAt, &lastUsedAt); err != nil {
		return PublicKey{}, err
	}
	k.ExpiresAt = fromUnix(expiresAt)
	k.CreatedAt = fromUnix(createdAt)
	k.LastUsedAt = fromUnix(lastUsedAt)
	return k, nil
}

// prefixColumns qualifies a comma-separated column list with a table alias.
func prefixColumns(prefix, columns string) string {
	parts := strings.Split(columns, ",")
	for i, part := range parts {
		parts[i] = prefix + strings.TrimSpace(part)
	}
	return strings.Join(parts, ", ")
}
