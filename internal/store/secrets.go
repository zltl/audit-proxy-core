package store

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/secrets"
)

// ErrNoSealer is returned when secret material is requested from a Store that
// was opened without a key provider.
var ErrNoSealer = errors.New("store: no secret sealer configured")

// SetSealer attaches the envelope-encryption sealer used for credential
// material. Without one, the secret APIs refuse rather than storing plaintext.
func (s *Store) SetSealer(sealer *secrets.Sealer) {
	s.sealer = sealer
}

// HasSealer reports whether secret storage is available.
func (s *Store) HasSealer() bool { return s != nil && s.sealer != nil }

// secretContext binds a stored secret to its purpose so a ciphertext cannot be
// moved between rows of different kinds and still decrypt.
func secretContext(kind, id string) string {
	return "dp_secret:" + kind + ":" + id
}

// PutSecret encrypts plaintext and stores it, returning the reference to record
// on the owning row. The plaintext is never written anywhere.
func (s *Store) PutSecret(kind string, plaintext []byte) (string, error) {
	if !s.HasSealer() {
		return "", ErrNoSealer
	}
	kind = strings.TrimSpace(kind)
	if kind == "" {
		return "", fmt.Errorf("store: secret kind is required")
	}
	id := NewID("sec")
	sealed, err := s.sealer.Seal(secretContext(kind, id), plaintext)
	if err != nil {
		return "", err
	}
	now := s.clock()
	query := fmt.Sprintf(`INSERT INTO dp_secrets
		(id, kind, key_id, nonce, ciphertext, aad, version, created_at, rotated_at)
		VALUES (%s)`, s.binds(9))
	if _, err := s.db.Exec(query, id, kind, sealed.KeyID,
		base64.StdEncoding.EncodeToString(sealed.Nonce),
		base64.StdEncoding.EncodeToString(sealed.Ciphertext),
		sealed.Context, 1, s.unix(now), s.unix(now)); err != nil {
		return "", err
	}
	return id, nil
}

// PutSecretString is PutSecret for text material.
func (s *Store) PutSecretString(kind, plaintext string) (string, error) {
	return s.PutSecret(kind, []byte(plaintext))
}

// GetSecret decrypts a stored secret. Callers should hold the plaintext for as
// short a time as possible and never persist or log it.
func (s *Store) GetSecret(id string) ([]byte, error) {
	if !s.HasSealer() {
		return nil, ErrNoSealer
	}
	sealed, _, err := s.loadSealed(id)
	if err != nil {
		return nil, err
	}
	return s.sealer.Open(sealed)
}

// GetSecretString is GetSecret for text material.
func (s *Store) GetSecretString(id string) (string, error) {
	plaintext, err := s.GetSecret(id)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// UpdateSecret replaces the material behind an existing reference, so rotating a
// credential does not require rewriting the row that points at it.
func (s *Store) UpdateSecret(id string, plaintext []byte) error {
	if !s.HasSealer() {
		return ErrNoSealer
	}
	_, kind, err := s.loadSealed(id)
	if err != nil {
		return err
	}
	sealed, err := s.sealer.Seal(secretContext(kind, id), plaintext)
	if err != nil {
		return err
	}
	query := fmt.Sprintf(`UPDATE dp_secrets SET key_id = %s, nonce = %s, ciphertext = %s,
		aad = %s, version = version + 1, rotated_at = %s WHERE id = %s`,
		s.bind(1), s.bind(2), s.bind(3), s.bind(4), s.bind(5), s.bind(6))
	return requireAffected(s.db.Exec(query, sealed.KeyID,
		base64.StdEncoding.EncodeToString(sealed.Nonce),
		base64.StdEncoding.EncodeToString(sealed.Ciphertext),
		sealed.Context, s.unix(s.clock()), id))
}

// DeleteSecret removes stored material.
func (s *Store) DeleteSecret(id string) error {
	query := fmt.Sprintf(`DELETE FROM dp_secrets WHERE id = %s`, s.bind(1))
	return requireAffected(s.db.Exec(query, id))
}

// RotateSecrets re-seals every value that is still under a retired key.
//
// It reports how many rows it moved and returns the first failure it hit rather
// than continuing blindly, because a decryption failure during rotation usually
// means a key was dropped from the provider and continuing would obscure that.
func (s *Store) RotateSecrets() (rotated int, err error) {
	if !s.HasSealer() {
		return 0, ErrNoSealer
	}
	rows, err := s.db.Query(`SELECT id FROM dp_secrets ORDER BY created_at ASC`)
	if err != nil {
		return 0, err
	}
	ids := make([]string, 0)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return rotated, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return rotated, err
	}
	_ = rows.Close()

	for _, id := range ids {
		sealed, _, err := s.loadSealed(id)
		if err != nil {
			return rotated, err
		}
		if !s.sealer.NeedsRotation(sealed) {
			continue
		}
		resealed, err := s.sealer.Reseal(sealed)
		if err != nil {
			return rotated, fmt.Errorf("store: reseal %s: %w", id, err)
		}
		query := fmt.Sprintf(`UPDATE dp_secrets SET key_id = %s, nonce = %s, ciphertext = %s,
			rotated_at = %s WHERE id = %s`, s.bind(1), s.bind(2), s.bind(3), s.bind(4), s.bind(5))
		if _, err := s.db.Exec(query, resealed.KeyID,
			base64.StdEncoding.EncodeToString(resealed.Nonce),
			base64.StdEncoding.EncodeToString(resealed.Ciphertext),
			s.unix(s.clock()), id); err != nil {
			return rotated, err
		}
		rotated++
	}
	return rotated, nil
}

// CountSecretsUnderKey reports how many values are still sealed under a given
// key, which is what tells an operator when a retired key can finally be dropped.
func (s *Store) CountSecretsUnderKey(keyID string) (int, error) {
	query := fmt.Sprintf(`SELECT COUNT(*) FROM dp_secrets WHERE key_id = %s`, s.bind(1))
	var count int
	if err := s.db.QueryRow(query, keyID).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func (s *Store) loadSealed(id string) (secrets.SealedValue, string, error) {
	query := fmt.Sprintf(`SELECT kind, key_id, nonce, ciphertext, aad FROM dp_secrets
		WHERE id = %s LIMIT 1`, s.bind(1))
	var kind, keyID, nonceB64, cipherB64, aad string
	err := s.db.QueryRow(query, id).Scan(&kind, &keyID, &nonceB64, &cipherB64, &aad)
	if errors.Is(err, sql.ErrNoRows) {
		return secrets.SealedValue{}, "", fmt.Errorf("%w: secret %q", ErrNotFound, id)
	}
	if err != nil {
		return secrets.SealedValue{}, "", err
	}
	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		return secrets.SealedValue{}, "", fmt.Errorf("store: decode secret nonce: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(cipherB64)
	if err != nil {
		return secrets.SealedValue{}, "", fmt.Errorf("store: decode secret ciphertext: %w", err)
	}
	return secrets.SealedValue{
		KeyID:      keyID,
		Context:    aad,
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}, kind, nil
}
