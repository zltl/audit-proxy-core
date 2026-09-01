// Package secrets provides envelope encryption for credential material.
//
// Values are sealed with AES-256-GCM under a data-encryption key that is itself
// derived from a key-encryption key held by a Provider. Only the ciphertext,
// nonce, and the identifier of the key that sealed it are ever persisted, so a
// database dump on its own does not disclose any upstream password or private
// key. Rotation works by sealing under a new key identifier while old keys stay
// available for decryption.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"golang.org/x/crypto/hkdf"
)

// Errors callers are expected to distinguish.
var (
	ErrNoKey        = errors.New("secrets: no key-encryption key configured")
	ErrUnknownKeyID = errors.New("secrets: unknown key id")
	ErrDecrypt      = errors.New("secrets: decryption failed")
)

// Provider supplies key-encryption keys by identifier. Implementations may hold
// keys locally or fetch them from a KMS; the sealing code does not care which.
type Provider interface {
	// ActiveKeyID names the key new values should be sealed under.
	ActiveKeyID() string
	// Key returns the 32-byte key-encryption key for an identifier.
	Key(keyID string) ([]byte, error)
	// KeyIDs lists every identifier that can still be decrypted.
	KeyIDs() []string
}

// StaticProvider holds keys in memory. It is the default for deployments that
// manage key material through configuration or a mounted file rather than a KMS.
type StaticProvider struct {
	mu     sync.RWMutex
	keys   map[string][]byte
	active string
}

// NewStaticProvider builds a provider from a key set. The active identifier must
// be present in keys.
func NewStaticProvider(keys map[string][]byte, active string) (*StaticProvider, error) {
	if len(keys) == 0 {
		return nil, ErrNoKey
	}
	copied := make(map[string][]byte, len(keys))
	for id, key := range keys {
		if len(key) != 32 {
			return nil, fmt.Errorf("secrets: key %q must be 32 bytes, got %d", id, len(key))
		}
		buf := make([]byte, len(key))
		copy(buf, key)
		copied[id] = buf
	}
	if active == "" {
		return nil, fmt.Errorf("secrets: an active key id is required")
	}
	if _, ok := copied[active]; !ok {
		return nil, fmt.Errorf("secrets: active key %q is not in the key set", active)
	}
	return &StaticProvider{keys: copied, active: active}, nil
}

// NewStaticProviderFromHex builds a single-key provider from a hex-encoded key.
// The identifier is derived from the key so that rotating the material also
// changes the identifier recorded alongside each sealed value.
func NewStaticProviderFromHex(hexKey string) (*StaticProvider, error) {
	hexKey = strings.TrimSpace(hexKey)
	if hexKey == "" {
		return nil, ErrNoKey
	}
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("secrets: decode key: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("secrets: key must be 32 bytes (64 hex characters), got %d", len(key))
	}
	id := KeyIDFor(key)
	return NewStaticProvider(map[string][]byte{id: key}, id)
}

// LoadStaticProvider resolves key material from a literal hex string or a
// "file:" reference, so that a deployment can mount the key instead of putting
// it in a configuration value that ends up in backups and diffs.
func LoadStaticProvider(spec string) (*StaticProvider, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, ErrNoKey
	}
	if path, ok := strings.CutPrefix(spec, "file:"); ok {
		raw, err := os.ReadFile(strings.TrimSpace(path))
		if err != nil {
			return nil, fmt.Errorf("secrets: read key file: %w", err)
		}
		return NewStaticProviderFromHex(strings.TrimSpace(string(raw)))
	}
	return NewStaticProviderFromHex(spec)
}

// AddKey registers an additional key, typically an old one being kept for
// decryption after a rotation.
func (p *StaticProvider) AddKey(id string, key []byte) error {
	if len(key) != 32 {
		return fmt.Errorf("secrets: key %q must be 32 bytes, got %d", id, len(key))
	}
	buf := make([]byte, len(key))
	copy(buf, key)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.keys[id] = buf
	return nil
}

// SetActive changes which key seals new values.
func (p *StaticProvider) SetActive(id string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.keys[id]; !ok {
		return fmt.Errorf("%w: %s", ErrUnknownKeyID, id)
	}
	p.active = id
	return nil
}

// ActiveKeyID implements Provider.
func (p *StaticProvider) ActiveKeyID() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.active
}

// Key implements Provider.
func (p *StaticProvider) Key(keyID string) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	key, ok := p.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownKeyID, keyID)
	}
	return key, nil
}

// KeyIDs implements Provider.
func (p *StaticProvider) KeyIDs() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	ids := make([]string, 0, len(p.keys))
	for id := range p.keys {
		ids = append(ids, id)
	}
	return ids
}

// KeyIDFor derives a short, stable identifier from key material. Using a digest
// rather than a counter means two nodes configured with the same key agree on
// its identifier without coordinating.
func KeyIDFor(key []byte) string {
	sum := sha256.Sum256(append([]byte("ssh-proxy-kek-id\x00"), key...))
	return "k" + hex.EncodeToString(sum[:6])
}

// GenerateKey returns a fresh 256-bit key.
func GenerateKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("secrets: generate key: %w", err)
	}
	return key, nil
}

// deriveDEK produces a per-context data-encryption key from the KEK.
//
// Deriving per context rather than encrypting everything under the KEK directly
// means one context's nonces can never collide with another's, and it binds the
// ciphertext to its purpose: a sealed upstream password cannot be moved to a
// row of a different kind and still open.
func deriveDEK(kek []byte, context string) ([]byte, error) {
	reader := hkdf.New(sha256.New, kek, nil, []byte("ssh-proxy-dek\x00"+context))
	dek := make([]byte, 32)
	if _, err := reader.Read(dek); err != nil {
		return nil, fmt.Errorf("secrets: derive data key: %w", err)
	}
	return dek, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("secrets: new cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secrets: new gcm: %w", err)
	}
	return aead, nil
}
