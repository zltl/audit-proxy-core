package middleware

import (
	"net/http"
	"sync"
	"time"
)

type clientTokens struct {
	tokens     float64
	lastRefill time.Time
	lastSeen   time.Time
}

// RateLimit applies a per-client token bucket to management API requests.
func RateLimit(ratePerSecond float64, burst int) func(http.Handler) http.Handler {
	if ratePerSecond <= 0 || burst <= 0 {
		return func(next http.Handler) http.Handler { return next }
	}

	limiter := &clientRateLimiter{
		ratePerSecond: ratePerSecond,
		burst:         float64(burst),
		clients:       make(map[string]*clientTokens),
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !shouldRateLimitRequest(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}
			if limiter.allow(clientIP(r), time.Now()) {
				next.ServeHTTP(w, r)
				return
			}

			w.Header().Set("Retry-After", "1")
			http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
		})
	}
}

type clientRateLimiter struct {
	mu            sync.Mutex
	ratePerSecond float64
	burst         float64
	clients       map[string]*clientTokens
	lastSweep     time.Time
}

func shouldRateLimitRequest(path string) bool {
	if path == "/api/v1/health" {
		return false
	}
	return shouldAuditAPIRequest(path)
}

func (l *clientRateLimiter) allow(client string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.sweep(now)

	bucket := l.clients[client]
	if bucket == nil {
		l.clients[client] = &clientTokens{
			tokens:     l.burst - 1,
			lastRefill: now,
			lastSeen:   now,
		}
		return true
	}

	elapsed := now.Sub(bucket.lastRefill).Seconds()
	if elapsed > 0 {
		bucket.tokens += elapsed * l.ratePerSecond
		if bucket.tokens > l.burst {
			bucket.tokens = l.burst
		}
		bucket.lastRefill = now
	}
	bucket.lastSeen = now

	if bucket.tokens < 1 {
		return false
	}
	bucket.tokens--
	return true
}

func (l *clientRateLimiter) sweep(now time.Time) {
	if !l.lastSweep.IsZero() && now.Sub(l.lastSweep) < time.Minute {
		return
	}
	l.lastSweep = now

	for client, bucket := range l.clients {
		if now.Sub(bucket.lastSeen) > 10*time.Minute {
			delete(l.clients, client)
		}
	}
}
