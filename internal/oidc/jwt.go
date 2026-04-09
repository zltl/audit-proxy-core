package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// JSONWebKey represents a single key from a JWKS document.
type JSONWebKey struct {
	Kid string      `json:"kid"` // Key ID
	Kty string      `json:"kty"` // Key type (RSA, EC)
	Alg string      `json:"alg"` // Algorithm (RS256, ES256)
	Use string      `json:"use"` // Key use (sig)
	N   string      `json:"n"`   // RSA modulus (base64url)
	E   string      `json:"e"`   // RSA exponent (base64url)
	Crv string      `json:"crv"` // EC curve name (P-256)
	X   string      `json:"x"`   // EC X coordinate (base64url)
	Y   string      `json:"y"`   // EC Y coordinate (base64url)
	key interface{} // parsed crypto key (cached)
}

// PublicKey returns the parsed public key (either *rsa.PublicKey or
// *ecdsa.PublicKey). The result is cached after the first successful parse.
func (k *JSONWebKey) PublicKey() (interface{}, error) {
	if k.key != nil {
		return k.key, nil
	}
	var err error
	switch strings.ToUpper(k.Kty) {
	case "RSA":
		k.key, err = k.parseRSA()
	case "EC":
		k.key, err = k.parseEC()
	default:
		return nil, fmt.Errorf("oidc: unsupported key type %q", k.Kty)
	}
	return k.key, err
}

func (k *JSONWebKey) parseRSA() (*rsa.PublicKey, error) {
	nb, err := base64URLDecode(k.N)
	if err != nil {
		return nil, fmt.Errorf("oidc: decode RSA N: %w", err)
	}
	eb, err := base64URLDecode(k.E)
	if err != nil {
		return nil, fmt.Errorf("oidc: decode RSA E: %w", err)
	}
	n := new(big.Int).SetBytes(nb)
	e := new(big.Int).SetBytes(eb)
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

func (k *JSONWebKey) parseEC() (*ecdsa.PublicKey, error) {
	xb, err := base64URLDecode(k.X)
	if err != nil {
		return nil, fmt.Errorf("oidc: decode EC X: %w", err)
	}
	yb, err := base64URLDecode(k.Y)
	if err != nil {
		return nil, fmt.Errorf("oidc: decode EC Y: %w", err)
	}
	curve := elliptic.P256()
	if k.Crv != "" && k.Crv != "P-256" {
		return nil, fmt.Errorf("oidc: unsupported curve %q", k.Crv)
	}
	x := new(big.Int).SetBytes(xb)
	y := new(big.Int).SetBytes(yb)
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

// IDToken represents the decoded and validated claims of an OIDC ID Token.
type IDToken struct {
	Issuer   string
	Subject  string
	Audience []string
	Expiry   time.Time
	IssuedAt time.Time
	Nonce    string
	Email    string
	Name     string
	Groups   []string
	Claims   map[string]interface{} // all raw claims
}

// ParseJWT splits a compact JWS into its three decoded parts.
func ParseJWT(raw string) (header, payload map[string]interface{}, signature []byte, err error) {
	parts := strings.SplitN(raw, ".", 3)
	if len(parts) != 3 {
		return nil, nil, nil, errors.New("oidc: JWT must have 3 parts")
	}

	hdr, err := base64URLDecode(parts[0])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("oidc: decode JWT header: %w", err)
	}
	if err := json.Unmarshal(hdr, &header); err != nil {
		return nil, nil, nil, fmt.Errorf("oidc: unmarshal JWT header: %w", err)
	}

	pay, err := base64URLDecode(parts[1])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("oidc: decode JWT payload: %w", err)
	}
	if err := json.Unmarshal(pay, &payload); err != nil {
		return nil, nil, nil, fmt.Errorf("oidc: unmarshal JWT payload: %w", err)
	}

	signature, err = base64URLDecode(parts[2])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("oidc: decode JWT signature: %w", err)
	}

	return header, payload, signature, nil
}

// VerifySignature verifies the JWS signature of a compact JWT against the
// provided JWKS keys. Supports RS256 and ES256 algorithms.
func VerifySignature(token string, keys []JSONWebKey) error {
	header, _, _, err := ParseJWT(token)
	if err != nil {
		return err
	}

	alg, _ := header["alg"].(string)
	kid, _ := header["kid"].(string)

	// Find the matching key.
	var matchedKeys []JSONWebKey
	for _, k := range keys {
		if kid != "" && k.Kid == kid {
			matchedKeys = append(matchedKeys, k)
			break
		}
		// If no kid in the header, try all keys of the right type.
		if kid == "" {
			matchedKeys = append(matchedKeys, k)
		}
	}
	if len(matchedKeys) == 0 {
		return fmt.Errorf("oidc: no matching key found for kid=%q", kid)
	}

	// Split the signed content from the signature.
	lastDot := strings.LastIndex(token, ".")
	signedContent := token[:lastDot]
	sigBytes, err := base64URLDecode(token[lastDot+1:])
	if err != nil {
		return fmt.Errorf("oidc: decode signature: %w", err)
	}

	hash := sha256.Sum256([]byte(signedContent))

	for _, k := range matchedKeys {
		pub, keyErr := k.PublicKey()
		if keyErr != nil {
			continue
		}
		switch strings.ToUpper(alg) {
		case "RS256":
			rsaKey, ok := pub.(*rsa.PublicKey)
			if !ok {
				continue
			}
			if err := rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, hash[:], sigBytes); err == nil {
				return nil
			}
		case "ES256":
			ecKey, ok := pub.(*ecdsa.PublicKey)
			if !ok {
				continue
			}
			if verifyES256(ecKey, hash[:], sigBytes) {
				return nil
			}
		default:
			return fmt.Errorf("oidc: unsupported algorithm %q", alg)
		}
	}

	return errors.New("oidc: signature verification failed")
}

// verifyES256 verifies an ECDSA P-256 signature. The signature is the
// concatenation of r and s as fixed-size big-endian integers (32 bytes each).
func verifyES256(pub *ecdsa.PublicKey, hash, sig []byte) bool {
	if len(sig) != 64 {
		return false
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	return ecdsa.Verify(pub, hash, r, s)
}

// DecodeIDToken parses and extracts standard OIDC claims from a raw JWT
// without verifying the signature (call VerifySignature separately).
func DecodeIDToken(raw string) (*IDToken, error) {
	_, payload, _, err := ParseJWT(raw)
	if err != nil {
		return nil, err
	}

	tok := &IDToken{Claims: payload}
	tok.Issuer, _ = payload["iss"].(string)
	tok.Subject, _ = payload["sub"].(string)
	tok.Nonce, _ = payload["nonce"].(string)
	tok.Email, _ = payload["email"].(string)
	tok.Name, _ = payload["name"].(string)

	// Audience can be a string or an array.
	switch aud := payload["aud"].(type) {
	case string:
		tok.Audience = []string{aud}
	case []interface{}:
		for _, a := range aud {
			if s, ok := a.(string); ok {
				tok.Audience = append(tok.Audience, s)
			}
		}
	}

	// Timestamps (JSON numbers are float64).
	if exp, ok := payload["exp"].(float64); ok {
		tok.Expiry = time.Unix(int64(exp), 0)
	}
	if iat, ok := payload["iat"].(float64); ok {
		tok.IssuedAt = time.Unix(int64(iat), 0)
	}

	// Groups: try the standard "groups" claim, then fall back to
	// "roles" and "realm_access.roles" (Keycloak style).
	tok.Groups = extractStringSlice(payload, "groups")
	if len(tok.Groups) == 0 {
		tok.Groups = extractStringSlice(payload, "roles")
	}
	if len(tok.Groups) == 0 {
		if ra, ok := payload["realm_access"].(map[string]interface{}); ok {
			tok.Groups = extractStringSlice(ra, "roles")
		}
	}

	return tok, nil
}

// extractStringSlice pulls a []string from a claim that might be
// []interface{} (JSON arrays), a single string, or nil.
func extractStringSlice(m map[string]interface{}, key string) []string {
	val, ok := m[key]
	if !ok {
		return nil
	}
	switch v := val.(type) {
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		return []string{v}
	default:
		return nil
	}
}

// ValidateClaims checks standard ID token claims (issuer, audience, expiry).
func ValidateClaims(tok *IDToken, issuer, clientID string) error {
	if tok.Issuer != issuer {
		return fmt.Errorf("oidc: issuer mismatch: got %q, want %q", tok.Issuer, issuer)
	}

	audOK := false
	for _, a := range tok.Audience {
		if a == clientID {
			audOK = true
			break
		}
	}
	if !audOK {
		return fmt.Errorf("oidc: audience %q not found in token audiences %v", clientID, tok.Audience)
	}

	if time.Now().After(tok.Expiry) {
		return fmt.Errorf("oidc: token expired at %v", tok.Expiry)
	}

	return nil
}
