// Package authn provides the shared authentication primitives used by both the
// control plane and the SSH data plane: password hashing/verification and TOTP.
//
// Password hashes are stored in PHC string format so that the algorithm and its
// parameters travel with the hash and can be upgraded without a flag day.
package authn

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// ErrInvalidHash is returned when a stored hash cannot be parsed.
var ErrInvalidHash = errors.New("authn: invalid password hash")

// Argon2Params holds the cost parameters for argon2id hashing.
type Argon2Params struct {
	Memory      uint32 // KiB
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// DefaultArgon2Params targets roughly 64 MiB and ~50ms on a modern core, which
// is the OWASP baseline for interactive logins.
func DefaultArgon2Params() Argon2Params {
	parallelism := uint8(runtime.NumCPU())
	if parallelism < 1 {
		parallelism = 1
	}
	if parallelism > 4 {
		parallelism = 4
	}
	return Argon2Params{
		Memory:      64 * 1024,
		Iterations:  3,
		Parallelism: parallelism,
		SaltLength:  16,
		KeyLength:   32,
	}
}

// HashPassword derives an argon2id hash and returns it in PHC string format:
//
//	$argon2id$v=19$m=65536,t=3,p=4$<b64 salt>$<b64 key>
func HashPassword(password string) (string, error) {
	return HashPasswordWithParams(password, DefaultArgon2Params())
}

// HashPasswordWithParams is HashPassword with explicit cost parameters.
func HashPasswordWithParams(password string, p Argon2Params) (string, error) {
	if p.SaltLength == 0 || p.KeyLength == 0 || p.Iterations == 0 || p.Memory == 0 || p.Parallelism == 0 {
		return "", fmt.Errorf("authn: invalid argon2 parameters")
	}
	salt := make([]byte, p.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("authn: read salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Iterations, p.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// VerifyPassword reports whether password matches encoded. It understands
// argon2id PHC strings, bcrypt hashes, and the legacy HMAC-SHA1 digests written
// by earlier releases so that existing deployments keep working across upgrade.
func VerifyPassword(password, encoded string) bool {
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return false
	}
	switch {
	case strings.HasPrefix(encoded, "$argon2id$"):
		return verifyArgon2id(password, encoded)
	case strings.HasPrefix(encoded, "$2a$"), strings.HasPrefix(encoded, "$2b$"), strings.HasPrefix(encoded, "$2y$"):
		return bcrypt.CompareHashAndPassword([]byte(encoded), []byte(password)) == nil
	case isSHACryptHash(encoded):
		// crypt(3) hashes carried over from the file-based configuration.
		return verifySHACrypt(password, encoded)
	default:
		return verifyLegacyHMACSHA1(password, encoded)
	}
}

// NeedsRehash reports whether a stored hash uses an algorithm or cost weaker
// than the current default and should be upgraded on the next successful login.
func NeedsRehash(encoded string) bool {
	encoded = strings.TrimSpace(encoded)
	if !strings.HasPrefix(encoded, "$argon2id$") {
		return true
	}
	p, _, _, err := decodeArgon2id(encoded)
	if err != nil {
		return true
	}
	want := DefaultArgon2Params()
	return p.Memory < want.Memory || p.Iterations < want.Iterations || p.KeyLength < want.KeyLength
}

func verifyArgon2id(password, encoded string) bool {
	p, salt, want, err := decodeArgon2id(encoded)
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

func decodeArgon2id(encoded string) (Argon2Params, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	// ["", "argon2id", "v=19", "m=...,t=...,p=...", salt, key]
	if len(parts) != 6 || parts[1] != "argon2id" {
		return Argon2Params{}, nil, nil, ErrInvalidHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return Argon2Params{}, nil, nil, ErrInvalidHash
	}
	if version != argon2.Version {
		return Argon2Params{}, nil, nil, fmt.Errorf("%w: unsupported argon2 version %d", ErrInvalidHash, version)
	}
	var p Argon2Params
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Iterations, &p.Parallelism); err != nil {
		return Argon2Params{}, nil, nil, ErrInvalidHash
	}
	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil {
		return Argon2Params{}, nil, nil, ErrInvalidHash
	}
	key, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil {
		return Argon2Params{}, nil, nil, ErrInvalidHash
	}
	p.SaltLength = uint32(len(salt))
	p.KeyLength = uint32(len(key))
	return p, salt, key, nil
}

// legacyHMACSalt is the fixed salt used by the pre-argon2 password scheme. It is
// only ever used to recognise and then upgrade old hashes; never to create one.
const legacyHMACSalt = "ssh-proxy-salt"

func verifyLegacyHMACSHA1(password, encoded string) bool {
	want, err := hex.DecodeString(strings.ToLower(encoded))
	if err != nil || len(want) != sha1.Size {
		return false
	}
	mac := hmac.New(sha1.New, []byte(legacyHMACSalt))
	mac.Write([]byte(password))
	return hmac.Equal(mac.Sum(nil), want)
}

// ParseArgon2Params reads "m=65536,t=3,p=4" style tuning strings from config.
func ParseArgon2Params(raw string) (Argon2Params, error) {
	p := DefaultArgon2Params()
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return p, nil
	}
	for _, field := range strings.Split(raw, ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(field), "=")
		if !ok {
			return p, fmt.Errorf("authn: malformed argon2 parameter %q", field)
		}
		n, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
		if err != nil {
			return p, fmt.Errorf("authn: argon2 parameter %q: %w", key, err)
		}
		switch strings.TrimSpace(key) {
		case "m":
			p.Memory = uint32(n)
		case "t":
			p.Iterations = uint32(n)
		case "p":
			if n == 0 || n > 255 {
				return p, fmt.Errorf("authn: argon2 parallelism out of range: %d", n)
			}
			p.Parallelism = uint8(n)
		default:
			return p, fmt.Errorf("authn: unknown argon2 parameter %q", key)
		}
	}
	return p, nil
}
