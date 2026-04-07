package cluster

import (
	"fmt"
	"sync"
	"time"
)

// StateEntry is a single key-value entry in the distributed state store.
type StateEntry struct {
	Key       string    `json:"key"`
	Value     []byte    `json:"value"`
	Version   uint64    `json:"version"`
	UpdatedBy string    `json:"updated_by"`
	UpdatedAt time.Time `json:"updated_at"`
}

// StateSync provides a distributed key-value store that is replicated across
// the cluster. Writes are forwarded to the leader which propagates them to
// all followers.
type StateSync struct {
	manager *Manager
	mu      sync.RWMutex
	data    map[string]StateEntry
}

func newStateSync(mgr *Manager) *StateSync {
	return &StateSync{
		manager: mgr,
		data:    make(map[string]StateEntry),
	}
}

// Get returns the value for key and whether it exists.
func (ss *StateSync) Get(key string) ([]byte, bool) {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	entry, ok := ss.data[key]
	if !ok {
		return nil, false
	}
	return entry.Value, true
}

// Set stores a value. If this node is the leader the value is applied locally
// and will be propagated to followers on the next sync cycle. If this node
// is a follower the write is forwarded to the leader.
func (ss *StateSync) Set(key string, value []byte) error {
	ss.manager.mu.RLock()
	isLeader := ss.manager.self.Role == RoleLeader
	leaderAddr := ""
	if !isLeader {
		if n, ok := ss.manager.nodes[ss.manager.leader]; ok {
			leaderAddr = n.Address
		}
	}
	nodeID := ss.manager.self.ID
	ss.manager.mu.RUnlock()

	if isLeader {
		ss.applySet(key, value, nodeID)
		return nil
	}

	if leaderAddr == "" {
		return fmt.Errorf("no leader available")
	}

	// Forward to leader via sync.
	req := &SyncRequest{
		Entries: map[string]StateEntry{
			key: {
				Key:       key,
				Value:     value,
				Version:   ss.nextVersion(key),
				UpdatedBy: nodeID,
				UpdatedAt: time.Now().UTC(),
			},
		},
	}
	reply, err := ss.manager.sendSync(leaderAddr, req)
	if err != nil {
		return fmt.Errorf("forward to leader: %w", err)
	}

	// Merge leader's reply.
	ss.mu.Lock()
	for k, v := range reply.Entries {
		if existing, ok := ss.data[k]; !ok || v.Version > existing.Version {
			ss.data[k] = v
		}
	}
	ss.mu.Unlock()
	return nil
}

// Delete removes a key from the state store.
func (ss *StateSync) Delete(key string) error {
	ss.manager.mu.RLock()
	isLeader := ss.manager.self.Role == RoleLeader
	ss.manager.mu.RUnlock()

	if !isLeader {
		return fmt.Errorf("delete must be performed on the leader")
	}

	ss.mu.Lock()
	delete(ss.data, key)
	ss.mu.Unlock()
	return nil
}

// Snapshot returns a copy of all state entries.
func (ss *StateSync) Snapshot() map[string]StateEntry {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	snap := make(map[string]StateEntry, len(ss.data))
	for k, v := range ss.data {
		snap[k] = v
	}
	return snap
}

// applySet applies a Set locally.
func (ss *StateSync) applySet(key string, value []byte, nodeID string) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ver := uint64(1)
	if e, ok := ss.data[key]; ok {
		ver = e.Version + 1
	}
	ss.data[key] = StateEntry{
		Key:       key,
		Value:     value,
		Version:   ver,
		UpdatedBy: nodeID,
		UpdatedAt: time.Now().UTC(),
	}
}

func (ss *StateSync) nextVersion(key string) uint64 {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	if e, ok := ss.data[key]; ok {
		return e.Version + 1
	}
	return 1
}
