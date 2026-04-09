// Package middleware provides composable HTTP middleware for the control-plane.
// Every middleware follows the standard func(http.Handler) http.Handler pattern
// so they can be chained in any order.
package middleware

import (
	"bufio"
	"compress/gzip"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Chain applies a sequence of middleware to a handler, in the order given.
// The first middleware in the slice is the outermost wrapper.
func Chain(h http.Handler, mws ...func(http.Handler) http.Handler) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}

// --------------------------------------------------------------------------
// Logger
// --------------------------------------------------------------------------

// statusWriter wraps http.ResponseWriter to capture the status code.
type statusWriter struct {
	http.ResponseWriter
	code int
}

func (w *statusWriter) WriteHeader(code int) {
	w.code = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.code == 0 {
		w.code = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

// Unwrap allows http.ResponseController to reach the underlying writer.
func (w *statusWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("hijack not supported")
	}
	return hj.Hijack()
}

// Logger logs every request: method, path, status code, and duration.
func Logger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		log.Printf("%-7s %-30s %d %s", r.Method, r.URL.Path, sw.code, time.Since(start).Round(time.Microsecond))
	})
}

// --------------------------------------------------------------------------
// Recovery
// --------------------------------------------------------------------------

// Recovery catches panics in downstream handlers, logs a stack trace, and
// returns a 500 response.
func Recovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("PANIC: %v\n%s", err, debug.Stack())
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// HSTS adds a Strict-Transport-Security header on HTTPS responses when enabled.
func HSTS(enabled, includeSubdomains, preload bool) func(http.Handler) http.Handler {
	value := "max-age=31536000"
	if includeSubdomains {
		value += "; includeSubDomains"
	}
	if preload {
		value += "; preload"
	}

	return func(next http.Handler) http.Handler {
		if !enabled {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS != nil {
				w.Header().Set("Strict-Transport-Security", value)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// --------------------------------------------------------------------------
// Auth
// --------------------------------------------------------------------------

// publicPrefixes are paths that do not require authentication.
var publicPrefixes = []string{
	"/login",
	"/static/",
	"/api/v1/health",
	"/auth/oidc/login",
	"/auth/callback",
	"/auth/saml/",
	"/api/v2/cli/login/",
	"/api/v3/cli/login/",
	"/api/v2/threats/ingest",
	"/api/v3/threats/ingest",
}

// SessionPrincipal is the authenticated user extracted from the session cookie.
type SessionPrincipal struct {
	Username string
	Role     string
}

// Auth validates the HMAC-signed session cookie.  Unauthenticated requests
// are redirected to /login (HTML) or receive a 401 (API).
func Auth(secret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip auth for public paths.
			for _, p := range publicPrefixes {
				if r.URL.Path == p || strings.HasPrefix(r.URL.Path, p) {
					next.ServeHTTP(w, r)
					return
				}
			}

			principal, ok := ValidateSessionClaims(r, secret)
			if !ok {
				if strings.HasPrefix(r.URL.Path, "/api/") {
					http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				} else {
					http.Redirect(w, r, "/login", http.StatusSeeOther)
				}
				return
			}

			// Propagate username via both legacy and current headers so API
			// handlers can read a consistent authenticated principal.
			r.Header.Set("X-Auth-User", principal.Username)
			r.Header.Set("X-User", principal.Username)
			if principal.Role != "" {
				r.Header.Set("X-Auth-Role", principal.Role)
				r.Header.Set("X-Role", principal.Role)
				r.Header.Set("X-User-Role", principal.Role)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ValidateSession checks the session cookie and returns the username if valid.
func ValidateSession(r *http.Request, secret string) (string, bool) {
	principal, ok := ValidateSessionClaims(r, secret)
	return principal.Username, ok
}

// ValidateSessionClaims checks the session cookie and returns the username/role if valid.
func ValidateSessionClaims(r *http.Request, secret string) (SessionPrincipal, bool) {
	c, err := r.Cookie("session")
	if err != nil {
		return SessionPrincipal{}, false
	}
	parts := strings.Split(c.Value, "|")
	switch len(parts) {
	case 3:
		username, expiryStr, sig := parts[0], parts[1], parts[2]
		expiry, err := strconv.ParseInt(expiryStr, 10, 64)
		if err != nil || time.Now().Unix() > expiry {
			return SessionPrincipal{}, false
		}
		expected := signLegacySession(username, expiryStr, secret)
		if !hmac.Equal([]byte(sig), []byte(expected)) {
			return SessionPrincipal{}, false
		}
		return SessionPrincipal{Username: username}, true
	case 4:
		username, role, expiryStr, sig := parts[0], parts[1], parts[2], parts[3]
		expiry, err := strconv.ParseInt(expiryStr, 10, 64)
		if err != nil || time.Now().Unix() > expiry {
			return SessionPrincipal{}, false
		}
		expected := signSession(username, role, expiryStr, secret)
		if !hmac.Equal([]byte(sig), []byte(expected)) {
			return SessionPrincipal{}, false
		}
		return SessionPrincipal{Username: username, Role: role}, true
	default:
		return SessionPrincipal{}, false
	}
}

// CreateSessionCookie builds an HMAC-signed session cookie value.
// Format: username|expiry_unix|hmac_hex
func CreateSessionCookie(username, secret string, ttl time.Duration) *http.Cookie {
	expiry := strconv.FormatInt(time.Now().Add(ttl).Unix(), 10)
	sig := signLegacySession(username, expiry, secret)
	return &http.Cookie{
		Name:     "session",
		Value:    username + "|" + expiry + "|" + sig,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(ttl.Seconds()),
	}
}

// CreateSessionCookieWithRole builds an HMAC-signed session cookie that also carries the mapped role.
// Format: username|role|expiry_unix|hmac_hex
func CreateSessionCookieWithRole(username, role, secret string, ttl time.Duration) *http.Cookie {
	expiry := strconv.FormatInt(time.Now().Add(ttl).Unix(), 10)
	sig := signSession(username, role, expiry, secret)
	return &http.Cookie{
		Name:     "session",
		Value:    username + "|" + role + "|" + expiry + "|" + sig,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(ttl.Seconds()),
	}
}

// signSession computes the HMAC-SHA256 hex digest of "username|role|expiry".
func signSession(username, role, expiry, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(username + "|" + role + "|" + expiry))
	return hex.EncodeToString(mac.Sum(nil))
}

func signLegacySession(username, expiry, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(username + "|" + expiry))
	return hex.EncodeToString(mac.Sum(nil))
}

// --------------------------------------------------------------------------
// CSRF
// --------------------------------------------------------------------------

// csrfTokenLen is the byte-length of raw CSRF tokens (hex-encoded = 2×).
const csrfTokenLen = 32

// CSRF validates a CSRF token on state-changing methods (POST, PUT, DELETE).
// The token is expected in a hidden form field named "csrf_token" or in the
// X-CSRF-Token HTTP header.  Tokens are bound to the session via HMAC.
func CSRF(secret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Always ensure a CSRF token cookie exists so templates can
			// read it.
			tok := ensureCSRFToken(w, r, secret)

			// Safe methods are exempted.
			if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
				// Expose token in response header for JS fetch callers.
				w.Header().Set("X-CSRF-Token", tok)
				next.ServeHTTP(w, r)
				return
			}

			// Skip CSRF for public API endpoints.
			if strings.HasPrefix(r.URL.Path, "/api/v1/health") ||
				strings.HasPrefix(r.URL.Path, "/api/v2/cli/login/") ||
				strings.HasPrefix(r.URL.Path, "/api/v3/cli/login/") ||
				r.URL.Path == "/api/v2/threats/ingest" ||
				r.URL.Path == "/api/v3/threats/ingest" ||
				r.URL.Path == "/auth/saml/acs" {
				next.ServeHTTP(w, r)
				return
			}

			// Validate token from form or header.
			submitted := r.FormValue("csrf_token")
			if submitted == "" {
				submitted = r.Header.Get("X-CSRF-Token")
			}
			if !validCSRFToken(submitted, secret) {
				http.Error(w, "invalid CSRF token", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// ensureCSRFToken reads or creates the csrf_token cookie.
func ensureCSRFToken(w http.ResponseWriter, r *http.Request, secret string) string {
	if c, err := r.Cookie("csrf_token"); err == nil && validCSRFToken(c.Value, secret) {
		return c.Value
	}
	tok := generateCSRFToken(secret)
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    tok,
		Path:     "/",
		HttpOnly: false, // JS needs to read it
		SameSite: http.SameSiteStrictMode,
	})
	return tok
}

// generateCSRFToken produces a random token signed with the secret.
// Format: random_hex|hmac_hex
func generateCSRFToken(secret string) string {
	b := make([]byte, csrfTokenLen)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("csrf: rand read: %v", err))
	}
	raw := hex.EncodeToString(b)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(raw))
	sig := hex.EncodeToString(mac.Sum(nil))
	return raw + "|" + sig
}

// validCSRFToken verifies the HMAC signature of a csrf token.
func validCSRFToken(token, secret string) bool {
	parts := strings.SplitN(token, "|", 2)
	if len(parts) != 2 {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(parts[0]))
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(parts[1]), []byte(expected))
}

// --------------------------------------------------------------------------
// Compression
// --------------------------------------------------------------------------

// compressibleTypes are MIME prefixes eligible for gzip compression.
var compressibleTypes = []string{
	"text/",
	"application/json",
	"application/javascript",
	"application/xml",
	"image/svg+xml",
}

// gzipWriter wraps an http.ResponseWriter and lazily decides whether to gzip.
type gzipWriter struct {
	http.ResponseWriter
	gw          *gzip.Writer
	pool        *sync.Pool
	wroteHeader bool
	useGzip     bool
}

func (g *gzipWriter) WriteHeader(code int) {
	if !g.wroteHeader {
		g.wroteHeader = true
		ct := g.ResponseWriter.Header().Get("Content-Type")
		g.useGzip = isCompressible(ct)
		if g.useGzip {
			g.ResponseWriter.Header().Set("Content-Encoding", "gzip")
			g.ResponseWriter.Header().Del("Content-Length")
		}
	}
	g.ResponseWriter.WriteHeader(code)
}

func (g *gzipWriter) Write(b []byte) (int, error) {
	if !g.wroteHeader {
		// Trigger default 200 + content-type sniffing.
		if g.ResponseWriter.Header().Get("Content-Type") == "" {
			g.ResponseWriter.Header().Set("Content-Type", http.DetectContentType(b))
		}
		g.WriteHeader(http.StatusOK)
	}
	if g.useGzip {
		return g.gw.Write(b)
	}
	return g.ResponseWriter.Write(b)
}

// Unwrap allows http.ResponseController to reach the underlying writer.
func (g *gzipWriter) Unwrap() http.ResponseWriter {
	return g.ResponseWriter
}

func (g *gzipWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := g.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("hijack not supported")
	}
	return hj.Hijack()
}

func (g *gzipWriter) close() {
	if g.useGzip && g.gw != nil {
		g.gw.Close()
		g.pool.Put(g.gw)
	}
}

func isCompressible(ct string) bool {
	for _, prefix := range compressibleTypes {
		if strings.HasPrefix(ct, prefix) {
			return true
		}
	}
	return false
}

// Compression applies gzip encoding for text-like responses when the client
// advertises Accept-Encoding: gzip.
func Compression(next http.Handler) http.Handler {
	pool := &sync.Pool{
		New: func() interface{} {
			gz, _ := gzip.NewWriterLevel(io.Discard, gzip.DefaultCompression)
			return gz
		},
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			next.ServeHTTP(w, r)
			return
		}

		gz := pool.Get().(*gzip.Writer)
		gz.Reset(w)

		gw := &gzipWriter{
			ResponseWriter: w,
			gw:             gz,
			pool:           pool,
		}
		defer gw.close()

		next.ServeHTTP(gw, r)
	})
}
