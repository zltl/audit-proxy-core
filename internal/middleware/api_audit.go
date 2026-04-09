package middleware

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/models"
)

// APIAudit appends one audit event per API request so the audit center can show
// who called which management endpoint and whether it succeeded.
func APIAudit(auditDir, sessionSecret string) func(http.Handler) http.Handler {
	if auditDir == "" {
		return func(next http.Handler) http.Handler { return next }
	}

	logger := &apiAuditLogger{
		dir:    auditDir,
		secret: sessionSecret,
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !shouldAuditAPIRequest(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			start := time.Now()
			sw := &statusWriter{ResponseWriter: w}
			next.ServeHTTP(sw, r)
			if sw.code == 0 {
				sw.code = http.StatusOK
			}

			if err := logger.append(r, sw.code, time.Since(start)); err != nil {
				log.Printf("api audit: %v", err)
			}
		})
	}
}

type apiAuditLogger struct {
	dir     string
	secret  string
	mu      sync.Mutex
	counter atomic.Uint64
}

func shouldAuditAPIRequest(path string) bool {
	if path == "/api/v1/health" {
		return false
	}
	return strings.HasPrefix(path, "/api/")
}

func (l *apiAuditLogger) append(r *http.Request, status int, duration time.Duration) error {
	if err := os.MkdirAll(l.dir, 0o700); err != nil {
		return err
	}

	details, err := json.Marshal(map[string]interface{}{
		"method":      r.Method,
		"path":        r.URL.Path,
		"query":       r.URL.RawQuery,
		"status":      status,
		"duration_ms": duration.Milliseconds(),
	})
	if err != nil {
		return err
	}

	eventBytes, err := json.Marshal(models.AuditEvent{
		ID:        fmt.Sprintf("api-%d-%d", time.Now().UTC().UnixNano(), l.counter.Add(1)),
		Timestamp: time.Now().UTC(),
		EventType: "api.request",
		Username:  l.usernameFor(r),
		SourceIP:  clientIP(r),
		Details:   string(details),
	})
	if err != nil {
		return err
	}

	filePath := filepath.Join(l.dir, "audit-"+time.Now().UTC().Format("20060102")+".jsonl")

	l.mu.Lock()
	defer l.mu.Unlock()

	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.Write(append(eventBytes, '\n')); err != nil {
		return err
	}
	return nil
}

func (l *apiAuditLogger) usernameFor(r *http.Request) string {
	if username := strings.TrimSpace(r.Header.Get("X-Auth-User")); username != "" {
		return username
	}
	if username, ok := ValidateSession(r, l.secret); ok {
		return username
	}
	return "anonymous"
}

func clientIP(r *http.Request) string {
	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); forwarded != "" {
		parts := strings.Split(forwarded, ",")
		if len(parts) > 0 && strings.TrimSpace(parts[0]) != "" {
			return strings.TrimSpace(parts[0])
		}
	}
	if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); realIP != "" {
		return realIP
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}
