package server

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/middleware"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/oidc"
)

// oidcStateCookieName is the cookie that stores the PKCE verifier and nonce
// during the OIDC authorization flow.
const oidcStateCookieName = "oidc_state"

// oidcStateTTL limits how long a login flow can take.
const oidcStateTTL = 10 * time.Minute

// oidcState is stored (HMAC-signed) in a cookie while the user is at the IdP.
type oidcState struct {
	State    string `json:"s"`
	Verifier string `json:"v"`
}

// registerOIDCRoutes adds OIDC-specific HTTP routes to the mux.
func (s *Server) registerOIDCRoutes() {
	s.mux.HandleFunc("GET /auth/oidc/login", s.handleOIDCLogin)
	s.mux.HandleFunc("GET /auth/callback", s.handleOIDCCallback)
	s.mux.HandleFunc("GET /auth/oidc/logout", s.handleOIDCLogout)
}

// handleOIDCLogin redirects the user to the OIDC provider's authorization
// endpoint with a PKCE challenge and a signed state cookie.
func (s *Server) handleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	if s.oidcProvider == nil {
		http.Error(w, "OIDC is not configured", http.StatusNotFound)
		return
	}

	verifier, err := oidc.GenerateCodeVerifier()
	if err != nil {
		log.Printf("oidc: generate verifier: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	state, err := randomHex(16)
	if err != nil {
		log.Printf("oidc: generate state: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Store state+verifier in a signed cookie.
	stObj := oidcState{State: state, Verifier: verifier}
	stJSON, _ := json.Marshal(stObj)
	signed := signOIDCState(string(stJSON), s.config.SessionSecret)

	http.SetCookie(w, &http.Cookie{
		Name:     oidcStateCookieName,
		Value:    signed,
		Path:     "/",
		MaxAge:   int(oidcStateTTL.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	})

	challenge := oidc.CodeChallenge(verifier)
	authURL := s.oidcProvider.AuthURL(state, challenge)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleOIDCCallback is the OAuth2 redirect URI. It validates the state,
// exchanges the authorization code for tokens, verifies the ID token,
// extracts user info, creates a session, and redirects to /dashboard.
func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if s.oidcProvider == nil {
		http.Error(w, "OIDC is not configured", http.StatusNotFound)
		return
	}

	// Check for error from the IdP.
	if errCode := r.URL.Query().Get("error"); errCode != "" {
		desc := r.URL.Query().Get("error_description")
		log.Printf("oidc: IdP error: %s — %s", errCode, desc)
		s.renderOIDCError(w, r, fmt.Sprintf("Authentication failed: %s", desc))
		return
	}

	code := r.URL.Query().Get("code")
	stateParam := r.URL.Query().Get("state")
	if code == "" || stateParam == "" {
		s.renderOIDCError(w, r, "Missing authorization code or state parameter")
		return
	}

	// Recover and validate the state cookie.
	stObj, err := s.recoverOIDCState(r)
	if err != nil {
		log.Printf("oidc: state validation: %v", err)
		s.renderOIDCError(w, r, "Invalid or expired login session. Please try again.")
		return
	}

	if stObj.State != stateParam {
		s.renderOIDCError(w, r, "State mismatch. Please try logging in again.")
		return
	}

	// Clear the state cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     oidcStateCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

	// Exchange code for tokens.
	tokResp, err := s.oidcProvider.Exchange(r.Context(), code, stObj.Verifier)
	if err != nil {
		log.Printf("oidc: token exchange: %v", err)
		s.renderOIDCError(w, r, "Failed to exchange authorization code. Please try again.")
		return
	}

	if tokResp.IDToken == "" {
		s.renderOIDCError(w, r, "No ID token received from provider.")
		return
	}

	// Verify the ID token.
	idToken, err := s.oidcProvider.VerifyIDToken(r.Context(), tokResp.IDToken)
	if err != nil {
		log.Printf("oidc: verify ID token: %v", err)
		s.renderOIDCError(w, r, "ID token verification failed.")
		return
	}

	// Determine the username — prefer email, fall back to subject.
	username := idToken.Email
	if username == "" {
		username = idToken.Subject
	}

	// Map roles.
	role := "viewer" // safe default
	if s.oidcRoleMapper != nil {
		role = s.oidcRoleMapper.MapRoles(idToken.Claims)
	}

	log.Printf("oidc: user %q (%s) authenticated with role %q", username, idToken.Subject, role)

	// Create a session cookie (reuse existing HMAC-signed cookie mechanism).
	cookie := middleware.CreateSessionCookie(username, s.config.SessionSecret, sessionTTL)
	http.SetCookie(w, cookie)

	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

// handleOIDCLogout clears the session and optionally redirects to the IdP's
// end_session_endpoint.
func (s *Server) handleOIDCLogout(w http.ResponseWriter, r *http.Request) {
	// Clear session cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

	user := r.Header.Get("X-Auth-User")
	log.Printf("oidc: user %q logged out", user)

	// If the provider has an end_session_endpoint, redirect there.
	if s.oidcProvider != nil && s.oidcProvider.EndSessionEndpoint != "" {
		params := url.Values{
			"client_id":                {s.config.OIDCClientID},
			"post_logout_redirect_uri": {s.config.OIDCRedirectURL},
		}
		logoutURL := s.oidcProvider.EndSessionEndpoint + "?" + params.Encode()
		http.Redirect(w, r, logoutURL, http.StatusFound)
		return
	}

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// renderOIDCError displays a user-friendly error page for OIDC failures.
func (s *Server) renderOIDCError(w http.ResponseWriter, r *http.Request, message string) {
	w.WriteHeader(http.StatusUnauthorized)
	s.render(w, r, "pages/login.html", map[string]interface{}{
		"Title": "Login",
		"Error": message,
	})
}

// signOIDCState produces "payload|hmac_hex".
func signOIDCState(payload, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))
	return payload + "|" + sig
}

// verifyOIDCState checks the HMAC and returns the payload.
func verifyOIDCState(raw, secret string) (string, error) {
	// Find the last "|" — the signature delimiter.
	idx := lastIndex(raw, '|')
	if idx < 0 {
		return "", fmt.Errorf("malformed state cookie")
	}
	payload := raw[:idx]
	sig := raw[idx+1:]

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	expected := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return "", fmt.Errorf("state cookie HMAC mismatch")
	}
	return payload, nil
}

// recoverOIDCState reads and validates the OIDC state cookie.
func (s *Server) recoverOIDCState(r *http.Request) (*oidcState, error) {
	c, err := r.Cookie(oidcStateCookieName)
	if err != nil {
		return nil, fmt.Errorf("missing oidc_state cookie")
	}

	payload, err := verifyOIDCState(c.Value, s.config.SessionSecret)
	if err != nil {
		return nil, err
	}

	var st oidcState
	if err := json.Unmarshal([]byte(payload), &st); err != nil {
		return nil, fmt.Errorf("unmarshal state: %w", err)
	}
	return &st, nil
}

// lastIndex returns the index of the last occurrence of b in s, or -1.
func lastIndex(s string, b byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// randomHex generates a hex string of n random bytes.
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
