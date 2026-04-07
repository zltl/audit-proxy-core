package threat

import (
	"sync"
	"time"
)

type behaviorTracker struct {
	events    []trackedEvent
	mu        sync.Mutex
	maxEvents int
}

type trackedEvent struct {
	Timestamp time.Time
	Type      string
	SourceIP  string
	Target    string
	Username  string
	Details   map[string]interface{}
}

func newBehaviorTracker(maxEvents int) *behaviorTracker {
	return &behaviorTracker{
		events:    make([]trackedEvent, 0, 128),
		maxEvents: maxEvents,
	}
}

// Add appends an event and evicts the oldest if capacity is exceeded.
func (bt *behaviorTracker) Add(event trackedEvent) {
	bt.mu.Lock()
	defer bt.mu.Unlock()
	bt.events = append(bt.events, event)
	if len(bt.events) > bt.maxEvents {
		// Drop the oldest quarter to amortize copies.
		drop := bt.maxEvents / 4
		if drop < 1 {
			drop = 1
		}
		copy(bt.events, bt.events[drop:])
		bt.events = bt.events[:len(bt.events)-drop]
	}
}

// CountInWindow returns how many events of the given type occurred within the window.
func (bt *behaviorTracker) CountInWindow(eventType string, window time.Duration) int {
	bt.mu.Lock()
	defer bt.mu.Unlock()
	cutoff := time.Now().Add(-window)
	count := 0
	for i := len(bt.events) - 1; i >= 0; i-- {
		e := bt.events[i]
		if e.Timestamp.Before(cutoff) {
			break
		}
		if e.Type == eventType {
			count++
		}
	}
	return count
}

// EventsInWindow returns all events within the given duration.
func (bt *behaviorTracker) EventsInWindow(window time.Duration) []trackedEvent {
	bt.mu.Lock()
	defer bt.mu.Unlock()
	cutoff := time.Now().Add(-window)
	var result []trackedEvent
	for i := len(bt.events) - 1; i >= 0; i-- {
		if bt.events[i].Timestamp.Before(cutoff) {
			break
		}
		result = append(result, bt.events[i])
	}
	return result
}

// UniqueValuesInWindow returns distinct values for a field within the window.
// Supported fields: source_ip, target, username, type.
func (bt *behaviorTracker) UniqueValuesInWindow(field string, window time.Duration) []string {
	bt.mu.Lock()
	defer bt.mu.Unlock()
	cutoff := time.Now().Add(-window)
	seen := make(map[string]struct{})
	var result []string
	for i := len(bt.events) - 1; i >= 0; i-- {
		e := bt.events[i]
		if e.Timestamp.Before(cutoff) {
			break
		}
		var val string
		switch field {
		case "source_ip":
			val = e.SourceIP
		case "target":
			val = e.Target
		case "username":
			val = e.Username
		case "type":
			val = e.Type
		default:
			continue
		}
		if val == "" {
			continue
		}
		if _, ok := seen[val]; !ok {
			seen[val] = struct{}{}
			result = append(result, val)
		}
	}
	return result
}

// Cleanup removes events older than maxAge.
func (bt *behaviorTracker) Cleanup(maxAge time.Duration) {
	bt.mu.Lock()
	defer bt.mu.Unlock()
	cutoff := time.Now().Add(-maxAge)
	idx := 0
	for idx < len(bt.events) && bt.events[idx].Timestamp.Before(cutoff) {
		idx++
	}
	if idx > 0 {
		copy(bt.events, bt.events[idx:])
		bt.events = bt.events[:len(bt.events)-idx]
	}
}

// HasSequenceInWindow checks if the given event types occurred in order within the window.
func (bt *behaviorTracker) HasSequenceInWindow(sequence []string, window time.Duration) bool {
	bt.mu.Lock()
	defer bt.mu.Unlock()
	if len(sequence) == 0 {
		return false
	}
	cutoff := time.Now().Add(-window)
	seqIdx := 0
	for _, e := range bt.events {
		if e.Timestamp.Before(cutoff) {
			continue
		}
		if e.Type == sequence[seqIdx] {
			seqIdx++
			if seqIdx == len(sequence) {
				return true
			}
		}
	}
	return false
}
