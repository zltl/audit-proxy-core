package server

import (
	"log"
	"net/http"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/middleware"

	"golang.org/x/crypto/bcrypt"
)

// sessionTTL is the lifetime of a session cookie.
const sessionTTL = 24 * time.Hour

// handleLoginPage renders the login form.
func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "pages/login.html", map[string]interface{}{
		"Title": "Login",
	})
}

// handleLoginSubmit validates credentials and sets a session cookie.
func (s *Server) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	if !s.validateCredentials(username, password) {
		log.Printf("auth: failed login attempt for user %q from %s", username, r.RemoteAddr)
		s.render(w, r, "pages/login.html", map[string]interface{}{
			"Title": "Login",
			"Error": "Invalid username or password",
		})
		return
	}

	cookie := middleware.CreateSessionCookie(username, s.config.SessionSecret, sessionTTL)
	http.SetCookie(w, cookie)

	log.Printf("auth: user %q logged in from %s", username, r.RemoteAddr)
	http.Redirect(w, r, "/", http.StatusSeeOther)
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
		"role":     "admin",
	})
}

// validateCredentials checks the supplied username/password against the
// configured admin account.  Returns true when the credentials are valid.
func (s *Server) validateCredentials(username, password string) bool {
	if username != s.config.AdminUser {
		return false
	}

	// If no hash is configured, reject all logins to avoid an insecure
	// default.
	if s.config.AdminPassHash == "" {
		return false
	}

	err := bcrypt.CompareHashAndPassword([]byte(s.config.AdminPassHash), []byte(password))
	return err == nil
}
