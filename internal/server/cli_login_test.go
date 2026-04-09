package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/config"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/oidc"
)

func TestCLILoginFlowBridgesSessionAndCertificate(t *testing.T) {
	dataPlane := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(dataPlane.Close)

	idp := newOIDCTestProvider(t)
	t.Cleanup(idp.Close)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}

	baseURL := "http://" + ln.Addr().String()
	cfg := &config.Config{
		ListenAddr:       ln.Addr().String(),
		DataPlaneAddr:    dataPlane.URL,
		DataPlaneToken:   "dp-secret-token",
		SessionSecret:    "cli-login-secret",
		AuditLogDir:      t.TempDir(),
		RecordingDir:     t.TempDir(),
		DataDir:          t.TempDir(),
		OIDCEnabled:      true,
		OIDCIssuer:       idp.URL,
		OIDCClientID:     "sshproxy-cli",
		OIDCClientSecret: "",
		OIDCRedirectURL:  baseURL + "/auth/callback",
	}

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() {
		_ = srv.Shutdown(context.Background())
		_ = ln.Close()
	})

	go func() {
		_ = srv.srv.Serve(ln)
	}()

	startResp := mustRequest(t, http.DefaultClient, http.MethodPost, baseURL+"/api/v2/cli/login/start", bytes.NewBufferString(`{}`), map[string]string{
		"Content-Type": "application/json",
	})
	if startResp.StatusCode != http.StatusCreated {
		raw := string(mustReadBody(t, startResp))
		t.Fatalf("POST /api/v2/cli/login/start status = %d body = %s", startResp.StatusCode, raw)
	}

	var startEnvelope struct {
		Success bool `json:"success"`
		Data    struct {
			ChallengeID string `json:"challenge_id"`
			PollToken   string `json:"poll_token"`
			AuthURL     string `json:"auth_url"`
		} `json:"data"`
	}
	if err := json.Unmarshal(mustReadBody(t, startResp), &startEnvelope); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if !startEnvelope.Success || startEnvelope.Data.ChallengeID == "" || startEnvelope.Data.PollToken == "" {
		t.Fatalf("unexpected CLI login start response: %+v", startEnvelope)
	}

	browserJar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New() error = %v", err)
	}
	browserClient := &http.Client{Jar: browserJar}
	browserResp := mustRequest(t, browserClient, http.MethodGet, startEnvelope.Data.AuthURL, nil, nil)
	if browserResp.StatusCode != http.StatusOK {
		raw := string(mustReadBody(t, browserResp))
		t.Fatalf("browser auth flow status = %d body = %s", browserResp.StatusCode, raw)
	}
	if !strings.Contains(string(mustReadBody(t, browserResp)), "Authentication successful") {
		t.Fatal("expected CLI login success page")
	}

	statusURL := fmt.Sprintf("%s/api/v2/cli/login/status/%s?poll_token=%s",
		baseURL,
		url.PathEscape(startEnvelope.Data.ChallengeID),
		url.QueryEscape(startEnvelope.Data.PollToken),
	)
	statusResp := mustRequest(t, http.DefaultClient, http.MethodGet, statusURL, nil, nil)
	if statusResp.StatusCode != http.StatusOK {
		raw := string(mustReadBody(t, statusResp))
		t.Fatalf("GET cli login status status = %d body = %s", statusResp.StatusCode, raw)
	}

	var statusEnvelope struct {
		Success bool `json:"success"`
		Data    struct {
			Status        string `json:"status"`
			Username      string `json:"username"`
			SessionCookie string `json:"session_cookie"`
		} `json:"data"`
	}
	if err := json.Unmarshal(mustReadBody(t, statusResp), &statusEnvelope); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if statusEnvelope.Data.Status != "authenticated" {
		t.Fatalf("status = %q, want authenticated", statusEnvelope.Data.Status)
	}
	if statusEnvelope.Data.Username != "cli@example.com" {
		t.Fatalf("username = %q, want cli@example.com", statusEnvelope.Data.Username)
	}
	if statusEnvelope.Data.SessionCookie == "" {
		t.Fatal("expected session cookie in CLI login status response")
	}

	authJar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New() error = %v", err)
	}
	baseParsed, err := url.Parse(baseURL)
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}
	authJar.SetCookies(baseParsed, []*http.Cookie{{
		Name:  "session",
		Value: statusEnvelope.Data.SessionCookie,
		Path:  "/",
	}})
	authClient := &http.Client{Jar: authJar}

	authResp := mustRequest(t, authClient, http.MethodGet, baseURL+"/api/v1/auth/me", nil, nil)
	if authResp.StatusCode != http.StatusOK {
		raw := string(mustReadBody(t, authResp))
		t.Fatalf("GET /api/v1/auth/me status = %d body = %s", authResp.StatusCode, raw)
	}
	csrfToken := authResp.Header.Get("X-CSRF-Token")
	if csrfToken == "" {
		t.Fatal("expected X-CSRF-Token header")
	}

	publicKey := generateAuthorizedKey(t)
	signBody := bytes.NewBufferString(fmt.Sprintf(`{"public_key":%q,"principals":["cli@example.com"],"ttl":"1h"}`, publicKey))
	signResp := mustRequest(t, authClient, http.MethodPost, baseURL+"/api/v2/ca/sign-user", signBody, map[string]string{
		"Content-Type": "application/json",
		"X-CSRF-Token": csrfToken,
	})
	if signResp.StatusCode != http.StatusOK {
		raw := string(mustReadBody(t, signResp))
		t.Fatalf("POST /api/v2/ca/sign-user status = %d body = %s", signResp.StatusCode, raw)
	}

	var signEnvelope struct {
		Success bool `json:"success"`
		Data    struct {
			Certificate string `json:"certificate"`
			KeyID       string `json:"key_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(mustReadBody(t, signResp), &signEnvelope); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if !signEnvelope.Success || !strings.Contains(signEnvelope.Data.Certificate, "-cert-v01@openssh.com") {
		t.Fatalf("unexpected certificate response: %+v", signEnvelope)
	}
	if !strings.Contains(signEnvelope.Data.KeyID, "cli@example.com") {
		t.Fatalf("unexpected key id: %q", signEnvelope.Data.KeyID)
	}
}

func newOIDCTestProvider(t *testing.T) *httptest.Server {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	jwk := oidc.JSONWebKey{
		Kid: "test-key",
		Kty: "RSA",
		Alg: "RS256",
		Use: "sig",
		N:   base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(bigEndianBytes(privateKey.PublicKey.E)),
	}

	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q,"userinfo_endpoint":%q,"jwks_uri":%q}`,
			srv.URL,
			srv.URL+"/authorize",
			srv.URL+"/token",
			srv.URL+"/userinfo",
			srv.URL+"/jwks",
		)
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		redirectURI := r.URL.Query().Get("redirect_uri")
		state := r.URL.Query().Get("state")
		if redirectURI == "" || state == "" {
			http.Error(w, "missing redirect_uri or state", http.StatusBadRequest)
			return
		}
		if r.URL.Query().Get("code_challenge") == "" {
			http.Error(w, "missing code_challenge", http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, redirectURI+"?code=test-code&state="+url.QueryEscape(state), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if r.Form.Get("code") != "test-code" {
			http.Error(w, "invalid code", http.StatusBadRequest)
			return
		}
		if r.Form.Get("code_verifier") == "" {
			http.Error(w, "missing code_verifier", http.StatusBadRequest)
			return
		}

		idToken := signedOIDCTestJWT(t, privateKey, map[string]interface{}{
			"iss":   srv.URL,
			"aud":   "sshproxy-cli",
			"sub":   "user-123",
			"email": "cli@example.com",
			"exp":   time.Now().Add(time.Hour).Unix(),
			"iat":   time.Now().Unix(),
		})

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"id_token":     idToken,
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"keys": []oidc.JSONWebKey{jwk},
		})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"sub":   "user-123",
			"email": "cli@example.com",
			"name":  "CLI User",
		})
	})

	srv = httptest.NewServer(mux)
	return srv
}

func signedOIDCTestJWT(t *testing.T, key *rsa.PrivateKey, claims map[string]interface{}) string {
	t.Helper()

	headerJSON, err := json.Marshal(map[string]interface{}{
		"alg": "RS256",
		"typ": "JWT",
		"kid": "test-key",
	})
	if err != nil {
		t.Fatalf("json.Marshal(header) error = %v", err)
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("json.Marshal(payload) error = %v", err)
	}

	encodedHeader := base64.RawURLEncoding.EncodeToString(headerJSON)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signed := encodedHeader + "." + encodedPayload
	sum := sha256.Sum256([]byte(signed))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("rsa.SignPKCS1v15() error = %v", err)
	}
	return signed + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func bigEndianBytes(n int) []byte {
	if n == 0 {
		return []byte{0}
	}
	var out []byte
	for n > 0 {
		out = append([]byte{byte(n & 0xff)}, out...)
		n >>= 8
	}
	return out
}

func generateAuthorizedKey(t *testing.T) string {
	t.Helper()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey() error = %v", err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
}
