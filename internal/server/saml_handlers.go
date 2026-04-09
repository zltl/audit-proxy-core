package server

import (
	"log"
	"net/http"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/middleware"
)

func (s *Server) registerSAMLRoutes() {
	s.mux.HandleFunc("GET /auth/saml/login", s.handleSAMLLogin)
	s.mux.HandleFunc("GET /auth/saml/metadata", s.handleSAMLMetadata)
	s.mux.HandleFunc("GET /auth/saml/acs", s.handleSAMLACS)
	s.mux.HandleFunc("POST /auth/saml/acs", s.handleSAMLACS)
}

func (s *Server) handleSAMLLogin(w http.ResponseWriter, r *http.Request) {
	if s.samlProvider == nil {
		http.Error(w, "SAML is not configured", http.StatusNotFound)
		return
	}
	if err := s.samlProvider.StartAuthFlow(w, r, defaultString(r.URL.Query().Get("return_to"), r.URL.Query().Get("redirect"))); err != nil {
		log.Printf("saml: start auth flow: %v", err)
		s.render(w, r, "pages/login.html", s.loginPageData(map[string]interface{}{
			"Error": "Failed to start SAML authentication. Please try again.",
		}))
	}
}

func (s *Server) handleSAMLMetadata(w http.ResponseWriter, r *http.Request) {
	if s.samlProvider == nil {
		http.Error(w, "SAML is not configured", http.StatusNotFound)
		return
	}
	s.samlProvider.ServeMetadata(w, r)
}

func (s *Server) handleSAMLACS(w http.ResponseWriter, r *http.Request) {
	if s.samlProvider == nil {
		http.Error(w, "SAML is not configured", http.StatusNotFound)
		return
	}

	identity, redirectURI, err := s.samlProvider.Authenticate(w, r)
	if err != nil {
		log.Printf("saml: authenticate: %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		s.render(w, r, "pages/login.html", s.loginPageData(map[string]interface{}{
			"Error": "SAML authentication failed. Please try again.",
		}))
		return
	}

	cookie := middleware.CreateSessionCookieWithRole(identity.Username, identity.Role, s.config.SessionSecret, sessionTTL)
	cookie.Secure = r.TLS != nil
	http.SetCookie(w, cookie)
	log.Printf("saml: user %q authenticated with role %q", identity.Username, identity.Role)
	http.Redirect(w, r, redirectURI, http.StatusFound)
}
