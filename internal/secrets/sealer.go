package secrets

import (
	"crypto/rand"
	"fmt"
	"io"
)

// SealedValue is the persisted form of an encrypted secret.
type SealedValue struct {
	// KeyID names the key-encryption key that sealed this value, so rotation
	// can leave existing rows readable.
	KeyID string
	// Context binds the value to its purpose; decryption fails if it differs.
	Context    string
	Nonce      []byte
	Ciphertext []byte
}

// Sealer encrypts and decrypts secret material under a Provider's keys.
type Sealer struct {
	provider Provider
}

// NewSealer returns a Sealer backed by the given key provider.
func NewSealer(provider Provider) (*Sealer, error) {
	if provider == nil {
		return nil, ErrNoKey
	}
	if provider.ActiveKeyID() == "" {
		return nil, ErrNoKey
	}
	return &Sealer{provider: provider}, nil
}

// ActiveKeyID reports which key new values are sealed under.
func (s *Sealer) ActiveKeyID() string {
	if s == nil || s.provider == nil {
		return ""
	}
	return s.provider.ActiveKeyID()
}

// Seal encrypts plaintext under the active key.
//
// The context is authenticated but not encrypted: it travels as additional data
// so that a ciphertext moved to a row with a different purpose fails to open
// rather than silently decrypting into the wrong place.
func (s *Sealer) Seal(context string, plaintext []byte) (SealedValue, error) {
	if s == nil || s.provider == nil {
		return SealedValue{}, ErrNoKey
	}
	keyID := s.provider.ActiveKeyID()
	kek, err := s.provider.Key(keyID)
	if err != nil {
		return SealedValue{}, err
	}
	dek, err := deriveDEK(kek, context)
	if err != nil {
		return SealedValue{}, err
	}
	aead, err := newGCM(dek)
	if err != nil {
		return SealedValue{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return SealedValue{}, fmt.Errorf("secrets: generate nonce: %w", err)
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, []byte(context))
	return SealedValue{
		KeyID:      keyID,
		Context:    context,
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}, nil
}

// SealString is Seal for text secrets.
func (s *Sealer) SealString(context, plaintext string) (SealedValue, error) {
	return s.Seal(context, []byte(plaintext))
}

// Open decrypts a sealed value. A value sealed under a retired key still opens
// as long as that key remains in the provider.
func (s *Sealer) Open(value SealedValue) ([]byte, error) {
	if s == nil || s.provider == nil {
		return nil, ErrNoKey
	}
	kek, err := s.provider.Key(value.KeyID)
	if err != nil {
		return nil, err
	}
	dek, err := deriveDEK(kek, value.Context)
	if err != nil {
		return nil, err
	}
	aead, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	if len(value.Nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("%w: nonce is %d bytes, expected %d",
			ErrDecrypt, len(value.Nonce), aead.NonceSize())
	}
	plaintext, err := aead.Open(nil, value.Nonce, value.Ciphertext, []byte(value.Context))
	if err != nil {
		// The underlying error only ever says "message authentication failed";
		// wrapping it keeps callers from having to string-match.
		return nil, ErrDecrypt
	}
	return plaintext, nil
}

// OpenString is Open for text secrets.
func (s *Sealer) OpenString(value SealedValue) (string, error) {
	plaintext, err := s.Open(value)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// NeedsRotation reports whether a value was sealed under a key that is no longer
// the active one, which is how a rotation sweep finds work to do.
func (s *Sealer) NeedsRotation(value SealedValue) bool {
	if s == nil || s.provider == nil {
		return false
	}
	return value.KeyID != s.provider.ActiveKeyID()
}

// Reseal decrypts under the key that sealed a value and re-encrypts it under the
// active key, leaving the plaintext unchanged.
func (s *Sealer) Reseal(value SealedValue) (SealedValue, error) {
	plaintext, err := s.Open(value)
	if err != nil {
		return SealedValue{}, err
	}
	defer zero(plaintext)
	return s.Seal(value.Context, plaintext)
}

// zero overwrites a plaintext buffer once it is no longer needed. It does not
// make secrets unrecoverable from memory in general, but it shortens the window
// in which a heap dump would contain them.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
