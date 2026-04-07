// Package oidc implements OIDC/OAuth2 authentication for the SSH Proxy
// control plane using only the Go standard library.
package oidc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// GenerateCodeVerifier creates a cryptographically random PKCE code verifier
// (RFC 7636) between 43 and 128 characters using base64url-safe characters.
func GenerateCodeVerifier() (string, error) {
	// 32 random bytes → 43 base64url characters (no padding).
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64URLEncode(b), nil
}

// CodeChallenge computes the S256 PKCE code challenge for a given verifier.
// challenge = BASE64URL(SHA256(verifier))
func CodeChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64URLEncode(h[:])
}

// base64URLEncode encodes bytes to unpadded base64url (RFC 4648 §5).
func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// base64URLDecode decodes an unpadded base64url string.
func base64URLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}
