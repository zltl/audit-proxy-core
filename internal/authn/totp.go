package authn

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
	"net/url"
	"strings"
	"time"
)

// TOTPConfig describes an RFC 6238 time-based one-time password scheme.
type TOTPConfig struct {
	Algorithm string        // SHA1 (default), SHA256, SHA512
	Digits    int           // default 6
	Period    time.Duration // default 30s
	Skew      int           // number of periods tolerated either side, default 1
}

func (c TOTPConfig) withDefaults() TOTPConfig {
	if c.Algorithm == "" {
		c.Algorithm = "SHA1"
	}
	if c.Digits == 0 {
		c.Digits = 6
	}
	if c.Period == 0 {
		c.Period = 30 * time.Second
	}
	if c.Skew == 0 {
		c.Skew = 1
	}
	return c
}

// DefaultTOTPConfig matches what Google Authenticator and compatible apps use.
func DefaultTOTPConfig() TOTPConfig { return TOTPConfig{}.withDefaults() }

var totpEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateTOTPSecret returns a fresh 160-bit base32 secret.
func GenerateTOTPSecret() (string, error) {
	secret := make([]byte, 20)
	if _, err := rand.Read(secret); err != nil {
		return "", fmt.Errorf("authn: read totp secret: %w", err)
	}
	return totpEncoding.EncodeToString(secret), nil
}

// TOTPCode computes the one-time password for a specific instant.
func TOTPCode(secret string, at time.Time, cfg TOTPConfig) (string, error) {
	cfg = cfg.withDefaults()
	key, err := decodeTOTPSecret(secret)
	if err != nil {
		return "", err
	}
	counter := uint64(at.UTC().Unix()) / uint64(cfg.Period.Seconds())
	return hotp(key, counter, cfg)
}

// ValidateTOTP reports whether code is a currently valid one-time password for
// secret. It accepts codes from cfg.Skew periods before and after now to absorb
// clock drift, and compares in constant time.
func ValidateTOTP(secret, code string, cfg TOTPConfig) bool {
	return ValidateTOTPAt(secret, code, time.Now(), cfg)
}

// ValidateTOTPAt is ValidateTOTP with an explicit reference time.
func ValidateTOTPAt(secret, code string, now time.Time, cfg TOTPConfig) bool {
	cfg = cfg.withDefaults()
	code = strings.TrimSpace(code)
	if len(code) != cfg.Digits {
		return false
	}
	key, err := decodeTOTPSecret(secret)
	if err != nil {
		return false
	}
	step := uint64(cfg.Period.Seconds())
	if step == 0 {
		return false
	}
	counter := uint64(now.UTC().Unix()) / step
	// Accumulate rather than returning early so the work is independent of which
	// window matched.
	matched := 0
	for delta := -cfg.Skew; delta <= cfg.Skew; delta++ {
		c := int64(counter) + int64(delta)
		if c < 0 {
			continue
		}
		candidate, err := hotp(key, uint64(c), cfg)
		if err != nil {
			return false
		}
		matched |= subtle.ConstantTimeCompare([]byte(candidate), []byte(code))
	}
	return matched == 1
}

// TOTPProvisioningURI builds the otpauth:// URI consumed by authenticator apps.
func TOTPProvisioningURI(issuer, account, secret string, cfg TOTPConfig) string {
	cfg = cfg.withDefaults()
	label := account
	if issuer != "" {
		label = issuer + ":" + account
	}
	q := url.Values{}
	q.Set("secret", secret)
	if issuer != "" {
		q.Set("issuer", issuer)
	}
	q.Set("algorithm", strings.ToUpper(cfg.Algorithm))
	q.Set("digits", fmt.Sprintf("%d", cfg.Digits))
	q.Set("period", fmt.Sprintf("%d", int(cfg.Period.Seconds())))
	return (&url.URL{
		Scheme:   "otpauth",
		Host:     "totp",
		Path:     "/" + label,
		RawQuery: q.Encode(),
	}).String()
}

func decodeTOTPSecret(secret string) ([]byte, error) {
	normalized := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	normalized = strings.TrimRight(normalized, "=")
	if normalized == "" {
		return nil, fmt.Errorf("authn: empty totp secret")
	}
	key, err := totpEncoding.DecodeString(normalized)
	if err != nil {
		return nil, fmt.Errorf("authn: decode totp secret: %w", err)
	}
	return key, nil
}

func hotp(key []byte, counter uint64, cfg TOTPConfig) (string, error) {
	var newHash func() hash.Hash
	switch strings.ToUpper(cfg.Algorithm) {
	case "SHA1":
		newHash = sha1.New
	case "SHA256":
		newHash = sha256.New
	case "SHA512":
		newHash = sha512.New
	default:
		return "", fmt.Errorf("authn: unsupported totp algorithm %q", cfg.Algorithm)
	}
	if cfg.Digits < 6 || cfg.Digits > 9 {
		return "", fmt.Errorf("authn: unsupported totp digit count %d", cfg.Digits)
	}

	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(newHash, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	truncated := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	mod := uint32(math.Pow10(cfg.Digits))
	return fmt.Sprintf("%0*d", cfg.Digits, truncated%mod), nil
}
