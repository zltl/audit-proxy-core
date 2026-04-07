package oidc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// buildJWT constructs a compact JWS from header+payload maps and signs it.
func buildJWT(t *testing.T, header, payload map[string]interface{}, signFn func(data []byte) []byte) string {
	t.Helper()
	hdr := encodeJSON(t, header)
	pay := encodeJSON(t, payload)
	unsigned := hdr + "." + pay
	sig := base64.RawURLEncoding.EncodeToString(signFn([]byte(unsigned)))
	return unsigned + "." + sig
}

func encodeJSON(t *testing.T, v interface{}) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// generateRSAKey creates a test RSA key pair and the corresponding JSONWebKey.
func generateRSAKey(t *testing.T) (*rsa.PrivateKey, JSONWebKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwk := JSONWebKey{
		Kid: "rsa-test-kid",
		Kty: "RSA",
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(priv.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.E)).Bytes()),
	}
	return priv, jwk
}

// generateECKey creates a test ECDSA P-256 key pair and the corresponding JSONWebKey.
func generateECKey(t *testing.T) (*ecdsa.PrivateKey, JSONWebKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk := JSONWebKey{
		Kid: "ec-test-kid",
		Kty: "EC",
		Alg: "ES256",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(priv.X.Bytes()),
		Y:   base64.RawURLEncoding.EncodeToString(priv.Y.Bytes()),
	}
	return priv, jwk
}

// signRS256 returns a signing function for RS256.
func signRS256(priv *rsa.PrivateKey) func([]byte) []byte {
	return func(data []byte) []byte {
		h := sha256.Sum256(data)
		sig, err := rsa.SignPKCS1v15(rand.Reader, priv, 0, h[:])
		if err != nil {
			panic(err)
		}
		return sig
	}
}

// signES256 returns a signing function for ES256.
func signES256(priv *ecdsa.PrivateKey) func([]byte) []byte {
	return func(data []byte) []byte {
		h := sha256.Sum256(data)
		r, s, err := ecdsa.Sign(rand.Reader, priv, h[:])
		if err != nil {
			panic(err)
		}
		// Fixed-size (32 bytes each for P-256).
		rb := r.Bytes()
		sb := s.Bytes()
		sig := make([]byte, 64)
		copy(sig[32-len(rb):32], rb)
		copy(sig[64-len(sb):64], sb)
		return sig
	}
}

func testClaims(exp time.Time) map[string]interface{} {
	return map[string]interface{}{
		"iss":    "https://idp.example.com",
		"sub":    "user-123",
		"aud":    "my-client-id",
		"exp":    float64(exp.Unix()),
		"iat":    float64(time.Now().Unix()),
		"email":  "alice@example.com",
		"name":   "Alice",
		"groups": []interface{}{"admins", "devs"},
	}
}

// ---------------------------------------------------------------------------
// PKCE Tests
// ---------------------------------------------------------------------------

func TestGenerateCodeVerifier(t *testing.T) {
	v, err := GenerateCodeVerifier()
	if err != nil {
		t.Fatal(err)
	}
	if len(v) < 43 || len(v) > 128 {
		t.Fatalf("verifier length %d not in [43,128]", len(v))
	}
}

func TestGenerateCodeVerifierUniqueness(t *testing.T) {
	v1, _ := GenerateCodeVerifier()
	v2, _ := GenerateCodeVerifier()
	if v1 == v2 {
		t.Fatal("two verifiers should not be equal")
	}
}

func TestCodeChallenge(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	// RFC 7636 Appendix B reference value.
	expected := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	got := CodeChallenge(verifier)
	if got != expected {
		t.Fatalf("CodeChallenge(%q) = %q, want %q", verifier, got, expected)
	}
}

func TestCodeChallengeRoundTrip(t *testing.T) {
	v, _ := GenerateCodeVerifier()
	c := CodeChallenge(v)
	if c == "" {
		t.Fatal("challenge should not be empty")
	}
	// The challenge must be base64url without padding.
	if strings.ContainsRune(c, '=') || strings.ContainsRune(c, '+') || strings.ContainsRune(c, '/') {
		t.Fatalf("challenge contains non-base64url characters: %q", c)
	}
}

// ---------------------------------------------------------------------------
// JWT Parsing Tests
// ---------------------------------------------------------------------------

func TestParseJWT_Valid(t *testing.T) {
	rsaPriv, _ := generateRSAKey(t)
	token := buildJWT(t,
		map[string]interface{}{"alg": "RS256", "typ": "JWT"},
		testClaims(time.Now().Add(time.Hour)),
		signRS256(rsaPriv),
	)

	hdr, pay, sig, err := ParseJWT(token)
	if err != nil {
		t.Fatal(err)
	}
	if hdr["alg"] != "RS256" {
		t.Fatalf("alg = %v, want RS256", hdr["alg"])
	}
	if pay["sub"] != "user-123" {
		t.Fatalf("sub = %v, want user-123", pay["sub"])
	}
	if len(sig) == 0 {
		t.Fatal("signature should not be empty")
	}
}

func TestParseJWT_BadFormat(t *testing.T) {
	_, _, _, err := ParseJWT("not.a.valid.jwt")
	if err == nil {
		t.Fatal("expected error for malformed JWT")
	}
}

func TestParseJWT_TwoParts(t *testing.T) {
	_, _, _, err := ParseJWT("header.payload")
	if err == nil {
		t.Fatal("expected error for 2-part JWT")
	}
}

func TestParseJWT_BadBase64(t *testing.T) {
	_, _, _, err := ParseJWT("!!!.!!!.!!!")
	if err == nil {
		t.Fatal("expected error for bad base64")
	}
}

// ---------------------------------------------------------------------------
// JWT Verification Tests — RS256
// ---------------------------------------------------------------------------

func TestVerifySignature_RS256(t *testing.T) {
	priv, jwk := generateRSAKey(t)
	token := buildJWT(t,
		map[string]interface{}{"alg": "RS256", "typ": "JWT", "kid": jwk.Kid},
		testClaims(time.Now().Add(time.Hour)),
		signRS256(priv),
	)
	if err := VerifySignature(token, []JSONWebKey{jwk}); err != nil {
		t.Fatalf("RS256 verify failed: %v", err)
	}
}

func TestVerifySignature_RS256_BadSignature(t *testing.T) {
	priv, jwk := generateRSAKey(t)
	token := buildJWT(t,
		map[string]interface{}{"alg": "RS256", "typ": "JWT", "kid": jwk.Kid},
		testClaims(time.Now().Add(time.Hour)),
		signRS256(priv),
	)
	// Tamper with the signature.
	parts := strings.SplitN(token, ".", 3)
	parts[2] = base64.RawURLEncoding.EncodeToString([]byte("badsig"))
	tampered := strings.Join(parts, ".")

	if err := VerifySignature(tampered, []JSONWebKey{jwk}); err == nil {
		t.Fatal("expected verification failure for tampered token")
	}
}

func TestVerifySignature_RS256_WrongKey(t *testing.T) {
	priv, _ := generateRSAKey(t)
	_, wrongJWK := generateRSAKey(t)
	wrongJWK.Kid = "rsa-test-kid" // match kid

	token := buildJWT(t,
		map[string]interface{}{"alg": "RS256", "typ": "JWT", "kid": "rsa-test-kid"},
		testClaims(time.Now().Add(time.Hour)),
		signRS256(priv),
	)
	if err := VerifySignature(token, []JSONWebKey{wrongJWK}); err == nil {
		t.Fatal("expected verification failure with wrong key")
	}
}

// ---------------------------------------------------------------------------
// JWT Verification Tests — ES256
// ---------------------------------------------------------------------------

func TestVerifySignature_ES256(t *testing.T) {
	priv, jwk := generateECKey(t)
	token := buildJWT(t,
		map[string]interface{}{"alg": "ES256", "typ": "JWT", "kid": jwk.Kid},
		testClaims(time.Now().Add(time.Hour)),
		signES256(priv),
	)
	if err := VerifySignature(token, []JSONWebKey{jwk}); err != nil {
		t.Fatalf("ES256 verify failed: %v", err)
	}
}

func TestVerifySignature_ES256_BadSignature(t *testing.T) {
	priv, jwk := generateECKey(t)
	token := buildJWT(t,
		map[string]interface{}{"alg": "ES256", "typ": "JWT", "kid": jwk.Kid},
		testClaims(time.Now().Add(time.Hour)),
		signES256(priv),
	)
	parts := strings.SplitN(token, ".", 3)
	parts[2] = base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	tampered := strings.Join(parts, ".")

	if err := VerifySignature(tampered, []JSONWebKey{jwk}); err == nil {
		t.Fatal("expected verification failure for tampered ES256 token")
	}
}

func TestVerifySignature_NoMatchingKey(t *testing.T) {
	priv, _ := generateRSAKey(t)
	token := buildJWT(t,
		map[string]interface{}{"alg": "RS256", "typ": "JWT", "kid": "nonexistent"},
		testClaims(time.Now().Add(time.Hour)),
		signRS256(priv),
	)
	if err := VerifySignature(token, []JSONWebKey{}); err == nil {
		t.Fatal("expected error for no matching key")
	}
}

func TestVerifySignature_UnsupportedAlgorithm(t *testing.T) {
	priv, jwk := generateRSAKey(t)
	token := buildJWT(t,
		map[string]interface{}{"alg": "PS256", "typ": "JWT", "kid": jwk.Kid},
		testClaims(time.Now().Add(time.Hour)),
		signRS256(priv),
	)
	if err := VerifySignature(token, []JSONWebKey{jwk}); err == nil {
		t.Fatal("expected error for unsupported alg")
	}
}

// ---------------------------------------------------------------------------
// DecodeIDToken Tests
// ---------------------------------------------------------------------------

func TestDecodeIDToken(t *testing.T) {
	priv, _ := generateRSAKey(t)
	claims := testClaims(time.Now().Add(time.Hour))
	token := buildJWT(t,
		map[string]interface{}{"alg": "RS256", "typ": "JWT"},
		claims,
		signRS256(priv),
	)

	tok, err := DecodeIDToken(token)
	if err != nil {
		t.Fatal(err)
	}
	if tok.Issuer != "https://idp.example.com" {
		t.Fatalf("issuer = %q", tok.Issuer)
	}
	if tok.Subject != "user-123" {
		t.Fatalf("sub = %q", tok.Subject)
	}
	if tok.Email != "alice@example.com" {
		t.Fatalf("email = %q", tok.Email)
	}
	if tok.Name != "Alice" {
		t.Fatalf("name = %q", tok.Name)
	}
	if len(tok.Audience) != 1 || tok.Audience[0] != "my-client-id" {
		t.Fatalf("aud = %v", tok.Audience)
	}
	if len(tok.Groups) != 2 {
		t.Fatalf("groups = %v", tok.Groups)
	}
}

func TestDecodeIDToken_ArrayAudience(t *testing.T) {
	priv, _ := generateRSAKey(t)
	claims := testClaims(time.Now().Add(time.Hour))
	claims["aud"] = []interface{}{"client-a", "client-b"}
	token := buildJWT(t,
		map[string]interface{}{"alg": "RS256", "typ": "JWT"},
		claims,
		signRS256(priv),
	)
	tok, err := DecodeIDToken(token)
	if err != nil {
		t.Fatal(err)
	}
	if len(tok.Audience) != 2 {
		t.Fatalf("expected 2 audiences, got %v", tok.Audience)
	}
}

func TestDecodeIDToken_KeycloakRoles(t *testing.T) {
	priv, _ := generateRSAKey(t)
	claims := map[string]interface{}{
		"iss": "https://kc.example.com",
		"sub": "kc-user",
		"aud": "my-client",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
		"iat": float64(time.Now().Unix()),
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"admin", "user"},
		},
	}
	token := buildJWT(t,
		map[string]interface{}{"alg": "RS256", "typ": "JWT"},
		claims,
		signRS256(priv),
	)
	tok, err := DecodeIDToken(token)
	if err != nil {
		t.Fatal(err)
	}
	if len(tok.Groups) != 2 || tok.Groups[0] != "admin" {
		t.Fatalf("expected Keycloak roles, got %v", tok.Groups)
	}
}

// ---------------------------------------------------------------------------
// ValidateClaims Tests
// ---------------------------------------------------------------------------

func TestValidateClaims_Valid(t *testing.T) {
	tok := &IDToken{
		Issuer:   "https://idp.example.com",
		Audience: []string{"my-client-id"},
		Expiry:   time.Now().Add(time.Hour),
	}
	if err := ValidateClaims(tok, "https://idp.example.com", "my-client-id"); err != nil {
		t.Fatal(err)
	}
}

func TestValidateClaims_ExpiredToken(t *testing.T) {
	tok := &IDToken{
		Issuer:   "https://idp.example.com",
		Audience: []string{"my-client-id"},
		Expiry:   time.Now().Add(-time.Hour), // expired
	}
	err := ValidateClaims(tok, "https://idp.example.com", "my-client-id")
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expiry error, got %v", err)
	}
}

func TestValidateClaims_WrongIssuer(t *testing.T) {
	tok := &IDToken{
		Issuer:   "https://evil.example.com",
		Audience: []string{"my-client-id"},
		Expiry:   time.Now().Add(time.Hour),
	}
	err := ValidateClaims(tok, "https://idp.example.com", "my-client-id")
	if err == nil || !strings.Contains(err.Error(), "issuer") {
		t.Fatalf("expected issuer error, got %v", err)
	}
}

func TestValidateClaims_WrongAudience(t *testing.T) {
	tok := &IDToken{
		Issuer:   "https://idp.example.com",
		Audience: []string{"other-client"},
		Expiry:   time.Now().Add(time.Hour),
	}
	err := ValidateClaims(tok, "https://idp.example.com", "my-client-id")
	if err == nil || !strings.Contains(err.Error(), "audience") {
		t.Fatalf("expected audience error, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// RoleMapping Tests
// ---------------------------------------------------------------------------

func TestRoleMapping_BasicMatch(t *testing.T) {
	rm := &RoleMapping{
		Claim:    "groups",
		Mappings: map[string]string{"admins": "admin", "devs": "operator"},
		Default:  "viewer",
	}
	role := rm.MapRoles(map[string]interface{}{
		"groups": []interface{}{"admins"},
	})
	if role != "admin" {
		t.Fatalf("role = %q, want admin", role)
	}
}

func TestRoleMapping_HighestPriority(t *testing.T) {
	rm := &RoleMapping{
		Claim:    "groups",
		Mappings: map[string]string{"admins": "admin", "devs": "operator"},
		Default:  "viewer",
	}
	role := rm.MapRoles(map[string]interface{}{
		"groups": []interface{}{"devs", "admins"},
	})
	if role != "admin" {
		t.Fatalf("role = %q, want admin (highest priority)", role)
	}
}

func TestRoleMapping_DefaultRole(t *testing.T) {
	rm := &RoleMapping{
		Claim:    "groups",
		Mappings: map[string]string{"admins": "admin"},
		Default:  "viewer",
	}
	role := rm.MapRoles(map[string]interface{}{
		"groups": []interface{}{"users"},
	})
	if role != "viewer" {
		t.Fatalf("role = %q, want viewer (default)", role)
	}
}

func TestRoleMapping_NoGroups(t *testing.T) {
	rm := &RoleMapping{
		Claim:    "groups",
		Mappings: map[string]string{"admins": "admin"},
		Default:  "viewer",
	}
	role := rm.MapRoles(map[string]interface{}{})
	if role != "viewer" {
		t.Fatalf("role = %q, want viewer", role)
	}
}

func TestRoleMapping_KeycloakRealmAccess(t *testing.T) {
	rm := &RoleMapping{
		Claim:    "roles",
		Mappings: map[string]string{"admin": "admin"},
		Default:  "viewer",
	}
	role := rm.MapRoles(map[string]interface{}{
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"admin", "user"},
		},
	})
	if role != "admin" {
		t.Fatalf("role = %q, want admin (Keycloak)", role)
	}
}

func TestRoleMapping_CustomClaim(t *testing.T) {
	rm := &RoleMapping{
		Claim:    "custom_roles",
		Mappings: map[string]string{"super": "admin"},
		Default:  "viewer",
	}
	role := rm.MapRoles(map[string]interface{}{
		"custom_roles": []interface{}{"super"},
	})
	if role != "admin" {
		t.Fatalf("role = %q, want admin", role)
	}
}

// ---------------------------------------------------------------------------
// OIDC Discovery Tests (using httptest)
// ---------------------------------------------------------------------------

func setupTestOIDCServer(t *testing.T) (*httptest.Server, *rsa.PrivateKey, JSONWebKey) {
	t.Helper()
	priv, jwk := generateRSAKey(t)

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		// We'll fill in the issuer URL after we know the server address.
		// Use a placeholder that we'll replace.
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"issuer": "%s",
			"authorization_endpoint": "%s/authorize",
			"token_endpoint": "%s/token",
			"userinfo_endpoint": "%s/userinfo",
			"jwks_uri": "%s/jwks",
			"end_session_endpoint": "%s/logout"
		}`, r.Header.Get("X-Issuer"), r.Header.Get("X-Issuer"),
			r.Header.Get("X-Issuer"), r.Header.Get("X-Issuer"),
			r.Header.Get("X-Issuer"), r.Header.Get("X-Issuer"))
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		jwks := map[string]interface{}{"keys": []JSONWebKey{jwk}}
		json.NewEncoder(w).Encode(jwks)
	})

	srv := httptest.NewServer(mux)
	return srv, priv, jwk
}

// setupSelfRefOIDCServer creates a test OIDC server whose discovery document
// correctly references its own URL (no X-Issuer header trick needed).
func setupSelfRefOIDCServer(t *testing.T) (*httptest.Server, *rsa.PrivateKey, JSONWebKey) {
	t.Helper()
	priv, jwk := generateRSAKey(t)

	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"issuer": "%s",
			"authorization_endpoint": "%s/authorize",
			"token_endpoint": "%s/token",
			"userinfo_endpoint": "%s/userinfo",
			"jwks_uri": "%s/jwks",
			"end_session_endpoint": "%s/logout"
		}`, srv.URL, srv.URL, srv.URL, srv.URL, srv.URL, srv.URL)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		jwks := map[string]interface{}{"keys": []JSONWebKey{jwk}}
		json.NewEncoder(w).Encode(jwks)
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"sub":    "user-42",
			"name":   "Bob Test",
			"email":  "bob@example.com",
			"groups": []string{"staff"},
		})
	})

	srv = httptest.NewServer(mux)
	return srv, priv, jwk
}

func TestDiscovery(t *testing.T) {
	srv, _, _ := setupSelfRefOIDCServer(t)
	defer srv.Close()

	cfg := &OIDCConfig{
		Issuer:   srv.URL,
		ClientID: "test-client",
	}
	p, err := NewProvider(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	if p.AuthorizationEndpoint != srv.URL+"/authorize" {
		t.Fatalf("auth endpoint = %q", p.AuthorizationEndpoint)
	}
	if p.TokenEndpoint != srv.URL+"/token" {
		t.Fatalf("token endpoint = %q", p.TokenEndpoint)
	}
	if len(p.Keys()) == 0 {
		t.Fatal("no JWKS keys loaded")
	}
}

func TestDiscovery_BadURL(t *testing.T) {
	cfg := &OIDCConfig{
		Issuer:   "http://127.0.0.1:1", // nothing listening
		ClientID: "test",
	}
	_, err := NewProvider(cfg)
	if err == nil {
		t.Fatal("expected error for unreachable issuer")
	}
}

func TestDiscovery_EmptyIssuer(t *testing.T) {
	_, err := NewProvider(&OIDCConfig{})
	if err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("expected empty issuer error, got %v", err)
	}
}

func TestAuthURL(t *testing.T) {
	srv, _, _ := setupSelfRefOIDCServer(t)
	defer srv.Close()

	p, _ := NewProvider(&OIDCConfig{
		Issuer:      srv.URL,
		ClientID:    "cid",
		RedirectURL: "https://app/callback",
		Scopes:      []string{"openid", "email"},
	})
	defer p.Close()

	verifier, _ := GenerateCodeVerifier()
	challenge := CodeChallenge(verifier)
	u := p.AuthURL("state123", challenge)

	if !strings.Contains(u, "client_id=cid") {
		t.Fatalf("missing client_id in %q", u)
	}
	if !strings.Contains(u, "state=state123") {
		t.Fatalf("missing state in %q", u)
	}
	if !strings.Contains(u, "code_challenge_method=S256") {
		t.Fatalf("missing PKCE method in %q", u)
	}
	if !strings.Contains(u, "code_challenge=") {
		t.Fatalf("missing code_challenge in %q", u)
	}
}

func TestUserinfo(t *testing.T) {
	srv, _, _ := setupSelfRefOIDCServer(t)
	defer srv.Close()

	p, err := NewProvider(&OIDCConfig{
		Issuer:   srv.URL,
		ClientID: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	info, err := p.Userinfo(t.Context(), "fake-token")
	if err != nil {
		t.Fatal(err)
	}
	if info.Email != "bob@example.com" {
		t.Fatalf("email = %q", info.Email)
	}
	if info.Name != "Bob Test" {
		t.Fatalf("name = %q", info.Name)
	}
}

// ---------------------------------------------------------------------------
// Base64url decoding edge cases
// ---------------------------------------------------------------------------

func TestBase64URLDecode_NoPadding(t *testing.T) {
	// "Hello" in base64url without padding is "SGVsbG8"
	b, err := base64URLDecode("SGVsbG8")
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "Hello" {
		t.Fatalf("got %q", string(b))
	}
}

func TestBase64URLEncode_NoPadding(t *testing.T) {
	encoded := base64URLEncode([]byte("Hello"))
	if strings.Contains(encoded, "=") {
		t.Fatalf("encoded should not contain padding: %q", encoded)
	}
}

// ---------------------------------------------------------------------------
// JSONWebKey parsing
// ---------------------------------------------------------------------------

func TestJSONWebKey_ParseRSA(t *testing.T) {
	_, jwk := generateRSAKey(t)
	pub, err := jwk.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pub.(*rsa.PublicKey); !ok {
		t.Fatalf("expected *rsa.PublicKey, got %T", pub)
	}
}

func TestJSONWebKey_ParseEC(t *testing.T) {
	_, jwk := generateECKey(t)
	pub, err := jwk.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pub.(*ecdsa.PublicKey); !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", pub)
	}
}

func TestJSONWebKey_UnsupportedType(t *testing.T) {
	jwk := JSONWebKey{Kty: "OKP"}
	_, err := jwk.PublicKey()
	if err == nil {
		t.Fatal("expected error for unsupported key type")
	}
}

// ---------------------------------------------------------------------------
// extractStringSlice Tests
// ---------------------------------------------------------------------------

func TestExtractStringSlice_Array(t *testing.T) {
	m := map[string]interface{}{
		"groups": []interface{}{"a", "b"},
	}
	got := extractStringSlice(m, "groups")
	if len(got) != 2 || got[0] != "a" {
		t.Fatalf("got %v", got)
	}
}

func TestExtractStringSlice_SingleString(t *testing.T) {
	m := map[string]interface{}{
		"groups": "admin",
	}
	got := extractStringSlice(m, "groups")
	if len(got) != 1 || got[0] != "admin" {
		t.Fatalf("got %v", got)
	}
}

func TestExtractStringSlice_Missing(t *testing.T) {
	got := extractStringSlice(map[string]interface{}{}, "groups")
	if got != nil {
		t.Fatalf("expected nil, got %v", got)
	}
}

// ---------------------------------------------------------------------------
// Thread safety of JWKS keys
// ---------------------------------------------------------------------------

func TestProvider_SetKeysThreadSafe(t *testing.T) {
	srv, _, _ := setupSelfRefOIDCServer(t)
	defer srv.Close()

	p, err := NewProvider(&OIDCConfig{Issuer: srv.URL, ClientID: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			p.SetKeys([]JSONWebKey{{Kid: fmt.Sprintf("k%d", i)}})
		}
		close(done)
	}()

	for i := 0; i < 100; i++ {
		_ = p.Keys()
	}
	<-done
}
