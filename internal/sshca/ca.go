package sshca

import (
	"crypto/rand"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

// serialCounter provides a globally unique, monotonically increasing serial.
var serialCounter uint64

// nextSerial returns a unique serial by combining a timestamp with an atomic counter.
func nextSerial() uint64 {
	ts := uint64(time.Now().UnixNano() / 1000)
	seq := atomic.AddUint64(&serialCounter, 1)
	return ts ^ (seq << 48)
}

// CA is the SSH Certificate Authority.
type CA struct {
	hostKey    ssh.Signer
	userKey    ssh.Signer
	hostKeyPub ssh.PublicKey
	userKeyPub ssh.PublicKey
	config     *CAConfig
	mu         sync.RWMutex

	// issued tracks certificates for the list/revoke API.
	issued  []IssuedCert
	revoked map[uint64]bool
}

// CAConfig holds configuration for the Certificate Authority.
type CAConfig struct {
	HostKeyPath       string
	UserKeyPath       string
	UserCertTTL       time.Duration
	HostCertTTL       time.Duration
	MaxCertTTL        time.Duration
	AllowedPrincipals []string
	CriticalOptions   map[string]string
	Extensions        map[string]string
}

// IssuedCert records metadata about an issued certificate.
type IssuedCert struct {
	Serial     uint64    `json:"serial"`
	KeyID      string    `json:"key_id"`
	Type       string    `json:"type"` // "user" or "host"
	Principals []string  `json:"principals"`
	ValidAfter time.Time `json:"valid_after"`
	ValidBefore time.Time `json:"valid_before"`
	IssuedAt   time.Time `json:"issued_at"`
	Revoked    bool      `json:"revoked"`
}

// defaultExtensions are the standard OpenSSH extensions for user certificates.
var defaultExtensions = map[string]string{
	"permit-pty":              "",
	"permit-user-rc":          "",
	"permit-port-forwarding":  "",
	"permit-agent-forwarding": "",
}

func applyDefaults(cfg *CAConfig) {
	if cfg.UserCertTTL == 0 {
		cfg.UserCertTTL = 8 * time.Hour
	}
	if cfg.HostCertTTL == 0 {
		cfg.HostCertTTL = 720 * time.Hour
	}
	if cfg.MaxCertTTL == 0 {
		cfg.MaxCertTTL = 720 * time.Hour
	}
	if cfg.Extensions == nil {
		cfg.Extensions = defaultExtensions
	}
}

// New creates a new CA, loading keys from disk or generating new ones.
func New(cfg *CAConfig) (*CA, error) {
	applyDefaults(cfg)

	hostKey, err := loadOrGenerate(cfg.HostKeyPath)
	if err != nil {
		return nil, fmt.Errorf("host CA key: %w", err)
	}

	userKey, err := loadOrGenerate(cfg.UserKeyPath)
	if err != nil {
		return nil, fmt.Errorf("user CA key: %w", err)
	}

	return &CA{
		hostKey:    hostKey,
		userKey:    userKey,
		hostKeyPub: hostKey.PublicKey(),
		userKeyPub: userKey.PublicKey(),
		config:     cfg,
		issued:     make([]IssuedCert, 0),
		revoked:    make(map[uint64]bool),
	}, nil
}

// loadOrGenerate loads a key from path, or generates and saves a new ED25519 key.
func loadOrGenerate(path string) (ssh.Signer, error) {
	if path == "" {
		return GenerateED25519Key()
	}

	if _, err := os.Stat(path); err == nil {
		return LoadPrivateKey(path)
	}

	signer, err := GenerateED25519Key()
	if err != nil {
		return nil, err
	}
	if err := SavePrivateKey(path, signer); err != nil {
		return nil, fmt.Errorf("save generated key to %s: %w", path, err)
	}
	return signer, nil
}

// SignUserCert signs a user certificate for the given public key.
func (ca *CA) SignUserCert(pubKey ssh.PublicKey, username string, principals []string, ttl time.Duration, opts ...CertOption) (*ssh.Certificate, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	if ttl <= 0 {
		ttl = ca.config.UserCertTTL
	}
	if ttl > ca.config.MaxCertTTL {
		return nil, fmt.Errorf("requested TTL %v exceeds maximum %v", ttl, ca.config.MaxCertTTL)
	}

	if len(principals) == 0 {
		return nil, fmt.Errorf("at least one principal is required")
	}

	if len(ca.config.AllowedPrincipals) > 0 {
		allowed := make(map[string]bool, len(ca.config.AllowedPrincipals))
		for _, p := range ca.config.AllowedPrincipals {
			allowed[p] = true
		}
		for _, p := range principals {
			if !allowed[p] {
				return nil, fmt.Errorf("principal %q is not in the allowed list", p)
			}
		}
	}

	now := time.Now()
	serial := nextSerial()

	cert := &ssh.Certificate{
		CertType:        ssh.UserCert,
		Key:             pubKey,
		KeyId:           fmt.Sprintf("user-%s-%d", username, serial),
		Serial:          serial,
		ValidPrincipals: principals,
		ValidAfter:      uint64(now.Add(-5 * time.Minute).Unix()),
		ValidBefore:     uint64(now.Add(ttl).Unix()),
		Permissions: ssh.Permissions{
			Extensions: copyMap(ca.config.Extensions),
		},
	}

	// Apply configured critical options.
	if len(ca.config.CriticalOptions) > 0 {
		cert.Permissions.CriticalOptions = copyMap(ca.config.CriticalOptions)
	}

	// Apply functional options.
	for _, opt := range opts {
		opt(cert)
	}

	if err := cert.SignCert(rand.Reader, ca.userKey); err != nil {
		return nil, fmt.Errorf("sign certificate: %w", err)
	}

	ca.issued = append(ca.issued, IssuedCert{
		Serial:      serial,
		KeyID:       cert.KeyId,
		Type:        "user",
		Principals:  principals,
		ValidAfter:  now.Add(-5 * time.Minute),
		ValidBefore: now.Add(ttl),
		IssuedAt:    now,
	})

	return cert, nil
}

// SignHostCert signs a host certificate for the given public key.
func (ca *CA) SignHostCert(pubKey ssh.PublicKey, hostname string, ttl time.Duration) (*ssh.Certificate, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	if ttl <= 0 {
		ttl = ca.config.HostCertTTL
	}
	if ttl > ca.config.MaxCertTTL {
		return nil, fmt.Errorf("requested TTL %v exceeds maximum %v", ttl, ca.config.MaxCertTTL)
	}

	if hostname == "" {
		return nil, fmt.Errorf("hostname is required")
	}

	now := time.Now()
	serial := nextSerial()

	cert := &ssh.Certificate{
		CertType:        ssh.HostCert,
		Key:             pubKey,
		KeyId:           fmt.Sprintf("host-%s-%d", hostname, serial),
		Serial:          serial,
		ValidPrincipals: []string{hostname},
		ValidAfter:      uint64(now.Add(-5 * time.Minute).Unix()),
		ValidBefore:     uint64(now.Add(ttl).Unix()),
	}

	if err := cert.SignCert(rand.Reader, ca.hostKey); err != nil {
		return nil, fmt.Errorf("sign certificate: %w", err)
	}

	ca.issued = append(ca.issued, IssuedCert{
		Serial:      serial,
		KeyID:       cert.KeyId,
		Type:        "host",
		Principals:  []string{hostname},
		ValidAfter:  now.Add(-5 * time.Minute),
		ValidBefore: now.Add(ttl),
		IssuedAt:    now,
	})

	return cert, nil
}

// HostPublicKey returns the host CA public key in authorized_keys format.
func (ca *CA) HostPublicKey() string {
	return string(ssh.MarshalAuthorizedKey(ca.hostKeyPub))
}

// UserPublicKey returns the user CA public key in authorized_keys format.
func (ca *CA) UserPublicKey() string {
	return string(ssh.MarshalAuthorizedKey(ca.userKeyPub))
}

// ListIssuedCerts returns a copy of all issued certificates.
func (ca *CA) ListIssuedCerts() []IssuedCert {
	ca.mu.RLock()
	defer ca.mu.RUnlock()

	out := make([]IssuedCert, len(ca.issued))
	copy(out, ca.issued)
	for i := range out {
		if ca.revoked[out[i].Serial] {
			out[i].Revoked = true
		}
	}
	return out
}

// RevokeCert marks a certificate as revoked by its serial number.
func (ca *CA) RevokeCert(serial uint64) error {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	found := false
	for _, ic := range ca.issued {
		if ic.Serial == serial {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("certificate with serial %d not found", serial)
	}

	ca.revoked[serial] = true
	return nil
}

// IsRevoked checks whether a certificate serial has been revoked.
func (ca *CA) IsRevoked(serial uint64) bool {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	return ca.revoked[serial]
}

func copyMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
