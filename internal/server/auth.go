package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/authn"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/middleware"

	"golang.org/x/crypto/bcrypt"
)

// sessionTTL is the lifetime of a session cookie.
const sessionTTL = 24 * time.Hour

// mfaPendingTTL bounds how long a password-verified login may wait for its
// second factor before the user has to start over.
const mfaPendingTTL = 5 * time.Minute

// mfaPendingCookie carries the first-factor result between the two login POSTs
// so the password never has to be resubmitted or held server-side.
const mfaPendingCookie = "mfa_pending"

var errMFARequired = errors.New("mfa required")

// authenticatedPrincipal is the outcome of a successful credential check.
type authenticatedPrincipal struct {
	Username    string
	Role        string
	MFARequired bool
	MFASecret   string
}

// handleLoginPage renders the login form.
func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "pages/login.html", s.loginPageData(nil))
}

// handleLoginSubmit validates credentials and sets a session cookie.
//
// When the account has MFA enabled the first POST only verifies the password
// and returns the form again asking for a code; the second POST carries the
// signed pending cookie plus the code.
func (s *Server) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	if code := strings.TrimSpace(r.FormValue("totp_code")); code != "" {
		s.completeMFALogin(w, r, code)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	principal, err := s.authenticate(username, password)
	if err != nil {
		log.Printf("auth: failed login attempt for user %q from %s", username, r.RemoteAddr)
		s.renderLoginError(w, r, "Invalid username or password")
		return
	}

	if principal.MFARequired {
		http.SetCookie(w, s.newMFAPendingCookie(r, principal))
		s.render(w, r, "pages/login.html", s.loginPageData(map[string]interface{}{
			"MFARequired": true,
			"Username":    principal.Username,
		}))
		return
	}

	s.grantSession(w, r, principal)
}

// completeMFALogin validates the second factor against the pending cookie.
func (s *Server) completeMFALogin(w http.ResponseWriter, r *http.Request, code string) {
	cookie, err := r.Cookie(mfaPendingCookie)
	if err != nil {
		s.renderLoginError(w, r, "Your login attempt expired. Please sign in again.")
		return
	}
	username, role, ok := s.parseMFAPending(cookie.Value)
	if !ok {
		s.clearMFAPending(w)
		s.renderLoginError(w, r, "Your login attempt expired. Please sign in again.")
		return
	}

	secret, enabled := s.lookupMFASecret(username)
	if !enabled || !authn.ValidateTOTP(secret, code, authn.DefaultTOTPConfig()) {
		log.Printf("auth: failed MFA for user %q from %s", username, r.RemoteAddr)
		s.render(w, r, "pages/login.html", s.loginPageData(map[string]interface{}{
			"MFARequired": true,
			"Username":    username,
			"Error":       "Invalid authentication code",
		}))
		return
	}

	s.clearMFAPending(w)
	s.grantSession(w, r, authenticatedPrincipal{Username: username, Role: role})
}

func (s *Server) grantSession(w http.ResponseWriter, r *http.Request, principal authenticatedPrincipal) {
	role := principal.Role
	if role == "" {
		role = middleware.RoleViewer
	}
	cookie := middleware.CreateSessionCookieWithRole(principal.Username, role, s.config.SessionSecret, sessionTTL)
	cookie.Secure = r.TLS != nil
	http.SetCookie(w, cookie)

	log.Printf("auth: user %q logged in from %s with role %s", principal.Username, r.RemoteAddr, role)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) renderLoginError(w http.ResponseWriter, r *http.Request, message string) {
	s.render(w, r, "pages/login.html", s.loginPageData(map[string]interface{}{
		"Error": message,
	}))
}

// handleLogout clears the session cookie and redirects to the login page.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
	log.Printf("auth: user %q logged out", r.Header.Get("X-Auth-User"))
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// handleAuthMe returns the current authenticated user's information as JSON.
func (s *Server) handleAuthMe(w http.ResponseWriter, r *http.Request) {
	username := r.Header.Get("X-Auth-User")
	if username == "" {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"username": username,
		"role":     defaultString(r.Header.Get("X-Auth-Role"), middleware.RoleViewer),
	})
}

func (s *Server) loginPageData(extra map[string]interface{}) map[string]interface{} {
	data := map[string]interface{}{
		"Title":       "Login",
		"Year":        time.Now().Year(),
		"OIDCEnabled": s.oidcProvider != nil,
		"SAMLEnabled": s.samlProvider != nil,
	}
	for key, value := range extra {
		data[key] = value
	}
	return data
}

func defaultString(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}

// authenticate checks the supplied credentials against the user store first and
// the bootstrap admin account second, and resolves the principal's real role.
//
// Looking the role up rather than assuming one is what makes the role-based
// authorization policy meaningful: previously every local login was minted as
// an admin regardless of the account's configured role.
func (s *Server) authenticate(username, password string) (authenticatedPrincipal, error) {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return authenticatedPrincipal{}, errors.New("missing credentials")
	}

	if s.apiHandler != nil {
		if user, ok, err := s.apiHandler.LookupUser(username); err == nil && ok {
			if !user.Enabled {
				return authenticatedPrincipal{}, errors.New("account disabled")
			}
			if user.PassHash == "" || !authn.VerifyPassword(password, user.PassHash) {
				return authenticatedPrincipal{}, errors.New("invalid credentials")
			}
			s.upgradePasswordHash(username, password, user.PassHash)
			return authenticatedPrincipal{
				Username:    user.Username,
				Role:        user.Role,
				MFARequired: user.MFAEnabled && user.MFASecret != "",
				MFASecret:   user.MFASecret,
			}, nil
		} else if err != nil {
			log.Printf("auth: user store lookup for %q failed: %v", username, err)
		}
	}

	if !s.validateBootstrapAdmin(username, password) {
		return authenticatedPrincipal{}, errors.New("invalid credentials")
	}
	return authenticatedPrincipal{Username: username, Role: middleware.RoleAdmin}, nil
}

// upgradePasswordHash transparently re-hashes credentials that are still stored
// under a superseded scheme, so old hashes drain away as users log in.
func (s *Server) upgradePasswordHash(username, password, current string) {
	if !authn.NeedsRehash(current) || s.apiHandler == nil {
		return
	}
	if err := s.apiHandler.UpgradeUserPasswordHash(username, password); err != nil {
		log.Printf("auth: password hash upgrade for %q failed: %v", username, err)
	}
}

func (s *Server) lookupMFASecret(username string) (string, bool) {
	if s.apiHandler == nil {
		return "", false
	}
	user, ok, err := s.apiHandler.LookupUser(username)
	if err != nil || !ok {
		return "", false
	}
	return user.MFASecret, user.MFAEnabled && user.MFASecret != ""
}

// validateBootstrapAdmin checks the single admin account defined in the
// control-plane config file. It exists so a fresh install can log in before any
// user rows exist.
func (s *Server) validateBootstrapAdmin(username, password string) bool {
	if username != s.config.AdminUser {
		return false
	}
	// If no hash is configured, reject all logins to avoid an insecure default.
	if s.config.AdminPassHash == "" {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(s.config.AdminPassHash), []byte(password)) == nil
}

// --------------------------------------------------------------------------
// Pending-MFA cookie
// --------------------------------------------------------------------------

func (s *Server) newMFAPendingCookie(r *http.Request, principal authenticatedPrincipal) *http.Cookie {
	expiry := strconv.FormatInt(time.Now().Add(mfaPendingTTL).Unix(), 10)
	value := principal.Username + "|" + principal.Role + "|" + expiry
	value += "|" + signMFAPending(principal.Username, principal.Role, expiry, s.config.SessionSecret)
	return &http.Cookie{
		Name:     mfaPendingCookie,
		Value:    value,
		Path:     "/login",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(mfaPendingTTL.Seconds()),
	}
}

func (s *Server) clearMFAPending(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     mfaPendingCookie,
		Value:    "",
		Path:     "/login",
		MaxAge:   -1,
		HttpOnly: true,
	})
}

func (s *Server) parseMFAPending(raw string) (username, role string, ok bool) {
	parts := strings.Split(raw, "|")
	if len(parts) != 4 {
		return "", "", false
	}
	username, role, expiryStr, sig := parts[0], parts[1], parts[2], parts[3]
	expiry, err := strconv.ParseInt(expiryStr, 10, 64)
	if err != nil || time.Now().Unix() > expiry {
		return "", "", false
	}
	expected := signMFAPending(username, role, expiryStr, s.config.SessionSecret)
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return "", "", false
	}
	return username, role, true
}

// signMFAPending is domain-separated from the session cookie MAC so a pending
// token can never be replayed as a full session cookie.
func signMFAPending(username, role, expiry, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("mfa-pending|" + username + "|" + role + "|" + expiry))
	return hex.EncodeToString(mac.Sum(nil))
}
