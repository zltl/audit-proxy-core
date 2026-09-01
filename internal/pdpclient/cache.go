package pdpclient

import (
	"sync"
	"time"
)

// decisionCache holds authorization answers for a short window.
//
// It exists so a burst of connections from one user to one target does not turn
// into a burst of identical queries. The window is deliberately small: a cached
// allow is a decision that is no longer being re-checked, so the time it stays
// valid is the time a revocation can lag.
type decisionCache struct {
	ttl time.Duration

	mu      sync.RWMutex
	entries map[string]cacheEntry
	now     func() time.Time
}

type cacheEntry struct {
	value     interface{}
	expiresAt time.Time
}

func newDecisionCache(ttl time.Duration) *decisionCache {
	return &decisionCache{
		ttl:     ttl,
		entries: make(map[string]cacheEntry),
		now:     time.Now,
	}
}

// Get returns a cached value that has not expired.
func (c *decisionCache) Get(key string) (interface{}, bool) {
	if c == nil || c.ttl <= 0 {
		return nil, false
	}
	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok || c.now().After(entry.expiresAt) {
		return nil, false
	}
	return entry.value, true
}

// Put stores a value for the cache's TTL.
func (c *decisionCache) Put(key string, value interface{}) {
	if c == nil || c.ttl <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = cacheEntry{value: value, expiresAt: c.now().Add(c.ttl)}
	// Expired entries are dropped opportunistically rather than by a sweeper,
	// since the map only grows while decisions are actively being made.
	if len(c.entries) > 1024 {
		now := c.now()
		for k, e := range c.entries {
			if now.After(e.expiresAt) {
				delete(c.entries, k)
			}
		}
	}
}

// Invalidate drops every entry mentioning a subject. It is called when a
// revocation arrives, so a cached allow cannot outlive the grant behind it.
func (c *decisionCache) Invalidate(prefix string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for key := range c.entries {
		if len(prefix) == 0 || hasPrefix(key, prefix) {
			delete(c.entries, key)
		}
	}
}

// Clear empties the cache.
func (c *decisionCache) Clear() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]cacheEntry)
}

// Len reports how many entries are held, including expired ones not yet swept.
func (c *decisionCache) Len() int {
	if c == nil {
		return 0
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
