package store

import (
	"database/sql"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"
)

const targetColumns = `id, name, host, port, group_name, tags, os, enabled, maintenance,
	weight, created_at, updated_at`

// CreateTarget registers an upstream host.
func (s *Store) CreateTarget(t Target) (Target, error) {
	t.Name = strings.TrimSpace(t.Name)
	t.Host = strings.TrimSpace(t.Host)
	if t.Name == "" {
		return Target{}, fmt.Errorf("store: target name is required")
	}
	if t.Host == "" {
		return Target{}, fmt.Errorf("store: target host is required")
	}
	if t.ID == "" {
		t.ID = NewID("tgt")
	}
	if t.Port == 0 {
		t.Port = 22
	}
	if t.Weight == 0 {
		t.Weight = 1
	}
	now := s.clock()
	if t.CreatedAt.IsZero() {
		t.CreatedAt = now
	}
	t.UpdatedAt = now

	query := fmt.Sprintf(`INSERT INTO dp_targets (%s) VALUES (%s)
		ON CONFLICT(name) DO NOTHING`, targetColumns, s.binds(12))
	result, err := s.db.Exec(query, t.ID, t.Name, t.Host, t.Port, t.Group,
		encodeStringMap(t.Tags), t.OS, t.Enabled, t.Maintenance, t.Weight,
		s.unix(t.CreatedAt), s.unix(t.UpdatedAt))
	if err != nil {
		return Target{}, err
	}
	affected, err := rowsAffected(result)
	if err != nil {
		return Target{}, err
	}
	if affected == 0 {
		return Target{}, fmt.Errorf("%w: target %q", ErrConflict, t.Name)
	}
	return t, nil
}

// GetTarget resolves a target by name.
func (s *Store) GetTarget(name string) (Target, error) {
	query := fmt.Sprintf(`SELECT %s FROM dp_targets WHERE name = %s LIMIT 1`, targetColumns, s.bind(1))
	t, err := scanTarget(s.db.QueryRow(query, strings.TrimSpace(name)))
	if errors.Is(err, sql.ErrNoRows) {
		return Target{}, ErrNotFound
	}
	return t, err
}

// GetTargetByID resolves a target by identifier.
func (s *Store) GetTargetByID(id string) (Target, error) {
	query := fmt.Sprintf(`SELECT %s FROM dp_targets WHERE id = %s LIMIT 1`, targetColumns, s.bind(1))
	t, err := scanTarget(s.db.QueryRow(query, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Target{}, ErrNotFound
	}
	return t, err
}

// FindTargetByAddress resolves a target by host and port, which is how a client
// that asked for a raw address rather than a registered name is routed.
func (s *Store) FindTargetByAddress(host string, port int) (Target, error) {
	if port == 0 {
		port = 22
	}
	query := fmt.Sprintf(`SELECT %s FROM dp_targets WHERE host = %s AND port = %s LIMIT 1`,
		targetColumns, s.bind(1), s.bind(2))
	t, err := scanTarget(s.db.QueryRow(query, strings.TrimSpace(host), port))
	if errors.Is(err, sql.ErrNoRows) {
		return Target{}, ErrNotFound
	}
	return t, err
}

// ListTargets returns every registered target, ordered by name.
func (s *Store) ListTargets() ([]Target, error) {
	rows, err := s.db.Query(fmt.Sprintf(`SELECT %s FROM dp_targets ORDER BY name ASC`, targetColumns))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	targets := make([]Target, 0)
	for rows.Next() {
		t, err := scanTarget(rows)
		if err != nil {
			return nil, err
		}
		targets = append(targets, t)
	}
	return targets, rows.Err()
}

// UpdateTarget applies mutate to a stored target.
func (s *Store) UpdateTarget(name string, mutate func(*Target) error) (Target, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return Target{}, err
	}
	defer func() { _ = tx.Rollback() }()

	query := fmt.Sprintf(`SELECT %s FROM dp_targets WHERE name = %s LIMIT 1`, targetColumns, s.bind(1))
	t, err := scanTarget(tx.QueryRow(query, strings.TrimSpace(name)))
	if errors.Is(err, sql.ErrNoRows) {
		return Target{}, ErrNotFound
	}
	if err != nil {
		return Target{}, err
	}
	if err := mutate(&t); err != nil {
		return Target{}, err
	}
	t.UpdatedAt = s.clock()

	update := fmt.Sprintf(`UPDATE dp_targets SET host = %s, port = %s, group_name = %s,
		tags = %s, os = %s, enabled = %s, maintenance = %s, weight = %s, updated_at = %s
		WHERE id = %s`,
		s.bind(1), s.bind(2), s.bind(3), s.bind(4), s.bind(5), s.bind(6), s.bind(7), s.bind(8), s.bind(9), s.bind(10))
	if _, err := tx.Exec(update, t.Host, t.Port, t.Group, encodeStringMap(t.Tags), t.OS,
		t.Enabled, t.Maintenance, t.Weight, s.unix(t.UpdatedAt), t.ID); err != nil {
		return Target{}, err
	}
	if err := tx.Commit(); err != nil {
		return Target{}, err
	}
	return t, nil
}

// DeleteTarget removes a target along with its host keys and credentials.
func (s *Store) DeleteTarget(name string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var id string
	err = tx.QueryRow(fmt.Sprintf(`SELECT id FROM dp_targets WHERE name = %s`, s.bind(1)),
		strings.TrimSpace(name)).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: target %q", ErrNotFound, name)
	}
	if err != nil {
		return err
	}
	for _, stmt := range []string{
		`DELETE FROM dp_target_host_keys WHERE target_id = ` + s.bind(1),
		`DELETE FROM dp_target_credentials WHERE target_id = ` + s.bind(1),
		`DELETE FROM dp_targets WHERE id = ` + s.bind(1),
	} {
		if _, err := tx.Exec(stmt, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// MatchTargets returns the targets a selector resolves to. A selector is one of
// an exact name, a host[:port] address, a "group:<name>" or "tag:<k>=<v>"
// qualifier, or a glob over names and hosts. "*" matches everything.
func (s *Store) MatchTargets(selector string) ([]Target, error) {
	all, err := s.ListTargets()
	if err != nil {
		return nil, err
	}
	selector = normalizeSelector(selector)
	if selector == "" || selector == "*" {
		return all, nil
	}
	matched := make([]Target, 0)
	for _, t := range all {
		if TargetMatches(t, selector) {
			matched = append(matched, t)
		}
	}
	return matched, nil
}

// TargetMatches reports whether a selector designates the given target.
func TargetMatches(t Target, selector string) bool {
	selector = normalizeSelector(selector)
	switch {
	case selector == "" || selector == "*":
		return true

	case strings.HasPrefix(selector, "group:"):
		return strings.EqualFold(t.Group, strings.TrimPrefix(selector, "group:"))

	case strings.HasPrefix(selector, "tag:"):
		key, value, ok := strings.Cut(strings.TrimPrefix(selector, "tag:"), "=")
		if !ok {
			_, present := t.Tags[key]
			return present
		}
		return strings.EqualFold(t.Tags[key], value)

	case strings.HasPrefix(selector, "name:"):
		return globMatch(strings.TrimPrefix(selector, "name:"), strings.ToLower(t.Name))

	case strings.HasPrefix(selector, "host:"):
		return globMatch(strings.TrimPrefix(selector, "host:"), strings.ToLower(t.Host))
	}

	// A bare selector is matched against the name, the host, and host:port so
	// that a rule written either way behaves as its author expects.
	if globMatch(selector, strings.ToLower(t.Name)) {
		return true
	}
	if globMatch(selector, strings.ToLower(t.Host)) {
		return true
	}
	return globMatch(selector, strings.ToLower(t.Address()))
}

// globMatch does shell-style matching, treating a malformed pattern as a
// literal so that a bad rule cannot accidentally match everything.
func globMatch(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	ok, err := path.Match(pattern, value)
	if err != nil {
		return pattern == value
	}
	return ok
}

func scanTarget(row rowScanner) (Target, error) {
	var (
		t                    Target
		tags                 string
		createdAt, updatedAt int64
	)
	if err := row.Scan(&t.ID, &t.Name, &t.Host, &t.Port, &t.Group, &tags, &t.OS,
		&t.Enabled, &t.Maintenance, &t.Weight, &createdAt, &updatedAt); err != nil {
		return Target{}, err
	}
	t.Tags = decodeStringMap(tags)
	t.CreatedAt = fromUnix(createdAt)
	t.UpdatedAt = fromUnix(updatedAt)
	return t, nil
}

// --------------------------------------------------------------------------
// Host keys
// --------------------------------------------------------------------------

const hostKeyColumns = `id, target_id, algorithm, public_key, fingerprint, status, source,
	first_seen_at, trusted_at, comment`

// PutHostKey records or updates a pinned upstream host key.
func (s *Store) PutHostKey(k HostKey) (HostKey, error) {
	if strings.TrimSpace(k.TargetID) == "" || strings.TrimSpace(k.Fingerprint) == "" {
		return HostKey{}, fmt.Errorf("store: target_id and fingerprint are required")
	}
	if k.ID == "" {
		k.ID = NewID("hk")
	}
	if k.Status == "" {
		k.Status = HostKeyTrusted
	}
	if k.Source == "" {
		k.Source = HostKeyManual
	}
	now := s.clock()
	if k.FirstSeenAt.IsZero() {
		k.FirstSeenAt = now
	}
	if k.Status == HostKeyTrusted && k.TrustedAt.IsZero() {
		k.TrustedAt = now
	}

	query := fmt.Sprintf(`INSERT INTO dp_target_host_keys (%s) VALUES (%s)
		ON CONFLICT(target_id, fingerprint) DO UPDATE SET
			algorithm = excluded.algorithm,
			public_key = excluded.public_key,
			status = excluded.status,
			source = excluded.source,
			trusted_at = excluded.trusted_at,
			comment = excluded.comment`, hostKeyColumns, s.binds(10))
	if _, err := s.db.Exec(query, k.ID, k.TargetID, k.Algorithm, k.PublicKey, k.Fingerprint,
		string(k.Status), string(k.Source), s.unix(k.FirstSeenAt), s.unix(k.TrustedAt),
		k.Comment); err != nil {
		return HostKey{}, err
	}
	return k, nil
}

// ListHostKeys returns every recorded key for a target, in any trust state.
func (s *Store) ListHostKeys(targetID string) ([]HostKey, error) {
	query := fmt.Sprintf(`SELECT %s FROM dp_target_host_keys WHERE target_id = %s
		ORDER BY first_seen_at ASC`, hostKeyColumns, s.bind(1))
	rows, err := s.db.Query(query, targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	keys := make([]HostKey, 0)
	for rows.Next() {
		k, err := scanHostKey(rows)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

// ListPendingHostKeys returns keys learned on first contact that an operator has
// not yet ruled on.
func (s *Store) ListPendingHostKeys() ([]HostKey, error) {
	query := fmt.Sprintf(`SELECT %s FROM dp_target_host_keys WHERE status = %s
		ORDER BY first_seen_at ASC`, hostKeyColumns, s.bind(1))
	rows, err := s.db.Query(query, string(HostKeyPending))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	keys := make([]HostKey, 0)
	for rows.Next() {
		k, err := scanHostKey(rows)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

// SetHostKeyStatus promotes, demotes, or revokes a recorded host key.
func (s *Store) SetHostKeyStatus(targetID, fingerprint string, status HostKeyStatus) error {
	trustedAt := int64(0)
	if status == HostKeyTrusted {
		trustedAt = s.unix(s.clock())
	}
	query := fmt.Sprintf(`UPDATE dp_target_host_keys SET status = %s, trusted_at = %s
		WHERE target_id = %s AND fingerprint = %s`, s.bind(1), s.bind(2), s.bind(3), s.bind(4))
	return requireAffected(s.db.Exec(query, string(status), trustedAt, targetID, fingerprint))
}

// DeleteHostKey forgets a recorded host key.
func (s *Store) DeleteHostKey(targetID, fingerprint string) error {
	query := fmt.Sprintf(`DELETE FROM dp_target_host_keys WHERE target_id = %s AND fingerprint = %s`,
		s.bind(1), s.bind(2))
	return requireAffected(s.db.Exec(query, targetID, fingerprint))
}

func scanHostKey(row rowScanner) (HostKey, error) {
	var (
		k                      HostKey
		status, source         string
		firstSeenAt, trustedAt int64
	)
	if err := row.Scan(&k.ID, &k.TargetID, &k.Algorithm, &k.PublicKey, &k.Fingerprint,
		&status, &source, &firstSeenAt, &trustedAt, &k.Comment); err != nil {
		return HostKey{}, err
	}
	k.Status = HostKeyStatus(status)
	k.Source = HostKeySource(source)
	k.FirstSeenAt = fromUnix(firstSeenAt)
	k.TrustedAt = fromUnix(trustedAt)
	return k, nil
}

// --------------------------------------------------------------------------
// Host certificate authorities
// --------------------------------------------------------------------------

// PutHostCA records a CA whose host certificates are accepted for matching
// hostnames, which lets a fleet rotate host keys without repinning each one.
func (s *Store) PutHostCA(ca HostCA) (HostCA, error) {
	if strings.TrimSpace(ca.Fingerprint) == "" || strings.TrimSpace(ca.PublicKey) == "" {
		return HostCA{}, fmt.Errorf("store: host CA public_key and fingerprint are required")
	}
	if ca.ID == "" {
		ca.ID = NewID("hca")
	}
	if ca.CreatedAt.IsZero() {
		ca.CreatedAt = s.clock()
	}
	query := fmt.Sprintf(`INSERT INTO dp_host_ca_keys
		(id, name, public_key, fingerprint, host_patterns, created_at) VALUES (%s)
		ON CONFLICT(fingerprint) DO UPDATE SET
			name = excluded.name,
			public_key = excluded.public_key,
			host_patterns = excluded.host_patterns`, s.binds(6))
	if _, err := s.db.Exec(query, ca.ID, ca.Name, ca.PublicKey, ca.Fingerprint,
		encodeStringSlice(ca.HostPatterns), s.unix(ca.CreatedAt)); err != nil {
		return HostCA{}, err
	}
	return ca, nil
}

// ListHostCAs returns every trusted host certificate authority.
func (s *Store) ListHostCAs() ([]HostCA, error) {
	rows, err := s.db.Query(`SELECT id, name, public_key, fingerprint, host_patterns, created_at
		FROM dp_host_ca_keys ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	cas := make([]HostCA, 0)
	for rows.Next() {
		var (
			ca        HostCA
			patterns  string
			createdAt int64
		)
		if err := rows.Scan(&ca.ID, &ca.Name, &ca.PublicKey, &ca.Fingerprint, &patterns, &createdAt); err != nil {
			return nil, err
		}
		ca.HostPatterns = decodeStringSlice(patterns)
		ca.CreatedAt = fromUnix(createdAt)
		cas = append(cas, ca)
	}
	return cas, rows.Err()
}

// DeleteHostCA stops trusting a host certificate authority.
func (s *Store) DeleteHostCA(fingerprint string) error {
	query := fmt.Sprintf(`DELETE FROM dp_host_ca_keys WHERE fingerprint = %s`, s.bind(1))
	return requireAffected(s.db.Exec(query, fingerprint))
}

// --------------------------------------------------------------------------
// Upstream credentials
// --------------------------------------------------------------------------

const credentialColumns = `id, target_id, target_selector, login, kind, secret_ref,
	rotate_after_seconds, last_rotated_at, created_at, updated_at`

// PutCredential records how to authenticate to a target as a given account.
func (s *Store) PutCredential(c Credential) (Credential, error) {
	c.Login = strings.TrimSpace(c.Login)
	if c.Login == "" {
		return Credential{}, fmt.Errorf("store: credential login is required")
	}
	if c.Kind == "" {
		return Credential{}, fmt.Errorf("store: credential kind is required")
	}
	if c.TargetID == "" && strings.TrimSpace(c.TargetSelector) == "" {
		return Credential{}, fmt.Errorf("store: credential needs a target_id or target_selector")
	}
	if c.ID == "" {
		c.ID = NewID("cred")
	}
	now := s.clock()
	if c.CreatedAt.IsZero() {
		c.CreatedAt = now
	}
	c.UpdatedAt = now

	query := fmt.Sprintf(`INSERT INTO dp_target_credentials (%s) VALUES (%s)
		ON CONFLICT(id) DO UPDATE SET
			target_id = excluded.target_id,
			target_selector = excluded.target_selector,
			login = excluded.login,
			kind = excluded.kind,
			secret_ref = excluded.secret_ref,
			rotate_after_seconds = excluded.rotate_after_seconds,
			last_rotated_at = excluded.last_rotated_at,
			updated_at = excluded.updated_at`, credentialColumns, s.binds(10))
	if _, err := s.db.Exec(query, c.ID, c.TargetID, c.TargetSelector, c.Login, string(c.Kind),
		c.SecretRef, int64(c.RotateAfter/time.Second), s.unix(c.LastRotatedAt),
		s.unix(c.CreatedAt), s.unix(c.UpdatedAt)); err != nil {
		return Credential{}, err
	}
	return c, nil
}

// ListCredentials returns every stored upstream credential.
func (s *Store) ListCredentials() ([]Credential, error) {
	rows, err := s.db.Query(fmt.Sprintf(`SELECT %s FROM dp_target_credentials ORDER BY created_at ASC`,
		credentialColumns))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	creds := make([]Credential, 0)
	for rows.Next() {
		c, err := scanCredential(rows)
		if err != nil {
			return nil, err
		}
		creds = append(creds, c)
	}
	return creds, rows.Err()
}

// CredentialsForTarget returns the credentials that apply to a target, both
// those bound to it directly and those matched through a selector. Direct
// bindings come first so a target-specific credential wins over a fleet-wide one.
func (s *Store) CredentialsForTarget(t Target) ([]Credential, error) {
	all, err := s.ListCredentials()
	if err != nil {
		return nil, err
	}
	var direct, bySelector []Credential
	for _, c := range all {
		switch {
		case c.TargetID != "" && c.TargetID == t.ID:
			direct = append(direct, c)
		case c.TargetID == "" && TargetMatches(t, c.TargetSelector):
			bySelector = append(bySelector, c)
		}
	}
	return append(direct, bySelector...), nil
}

// DeleteCredential removes a stored credential binding.
func (s *Store) DeleteCredential(id string) error {
	query := fmt.Sprintf(`DELETE FROM dp_target_credentials WHERE id = %s`, s.bind(1))
	return requireAffected(s.db.Exec(query, id))
}

func scanCredential(row rowScanner) (Credential, error) {
	var (
		c                                          Credential
		kind                                       string
		rotateAfter, lastRotated, created, updated int64
	)
	if err := row.Scan(&c.ID, &c.TargetID, &c.TargetSelector, &c.Login, &kind, &c.SecretRef,
		&rotateAfter, &lastRotated, &created, &updated); err != nil {
		return Credential{}, err
	}
	c.Kind = CredentialKind(kind)
	c.RotateAfter = time.Duration(rotateAfter) * time.Second
	c.LastRotatedAt = fromUnix(lastRotated)
	c.CreatedAt = fromUnix(created)
	c.UpdatedAt = fromUnix(updated)
	return c, nil
}
