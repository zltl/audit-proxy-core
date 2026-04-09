package cluster

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	configSyncDesiredKey      = "system/config/latest"
	configSyncStatusKeyPrefix = "system/config/status/"
	configSyncStatusIdle      = "idle"
	configSyncStatusPending   = "pending"
	configSyncStatusApplied   = "applied"
	configSyncStatusFailed    = "failed"
)

// ConfigSyncPayload is the desired config snapshot replicated cluster-wide.
type ConfigSyncPayload struct {
	Version   string          `json:"version"`
	ChangeID  string          `json:"change_id,omitempty"`
	Requester string          `json:"requester,omitempty"`
	Snapshot  json.RawMessage `json:"snapshot"`
	UpdatedAt time.Time       `json:"updated_at"`
}

// ConfigSyncNodeStatus is a per-node config sync result.
type ConfigSyncNodeStatus struct {
	NodeID    string    `json:"node_id"`
	NodeName  string    `json:"node_name,omitempty"`
	Role      string    `json:"role,omitempty"`
	Version   string    `json:"version,omitempty"`
	Status    string    `json:"status"`
	AppliedAt time.Time `json:"applied_at,omitempty"`
	Error     string    `json:"error,omitempty"`
}

// ConfigSyncStatus is the aggregated cluster config sync view.
type ConfigSyncStatus struct {
	Version   string                 `json:"version,omitempty"`
	ChangeID  string                 `json:"change_id,omitempty"`
	Requester string                 `json:"requester,omitempty"`
	UpdatedAt time.Time              `json:"updated_at,omitempty"`
	Nodes     []ConfigSyncNodeStatus `json:"nodes"`
}

// ConfigSyncManager coordinates desired config replication using the existing
// distributed state store.
type ConfigSyncManager struct {
	manager        *Manager
	mu             sync.Mutex
	applier        func([]byte) error
	appliedVersion string
	applying       bool
	lastAttempt    time.Time
}

func newConfigSyncManager(m *Manager) *ConfigSyncManager {
	return &ConfigSyncManager{manager: m}
}

// SetApplier attaches the local config apply callback used on followers.
func (c *ConfigSyncManager) SetApplier(applier func([]byte) error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.applier = applier
}

// Publish stores the desired config snapshot in distributed state and records
// the leader's local apply status.
func (c *ConfigSyncManager) Publish(snapshot []byte, version, changeID, requester string) error {
	if version == "" {
		return fmt.Errorf("config sync version is required")
	}
	desired := ConfigSyncPayload{
		Version:   version,
		ChangeID:  changeID,
		Requester: requester,
		Snapshot:  append(json.RawMessage(nil), snapshot...),
		UpdatedAt: time.Now().UTC(),
	}
	raw, err := json.Marshal(desired)
	if err != nil {
		return fmt.Errorf("marshal desired config: %w", err)
	}
	if err := c.manager.state.Set(configSyncDesiredKey, raw); err != nil {
		return fmt.Errorf("store desired config: %w", err)
	}

	c.mu.Lock()
	c.appliedVersion = version
	c.mu.Unlock()

	if err := c.recordLocalStatus(version, configSyncStatusApplied, "", time.Now().UTC()); err != nil {
		return fmt.Errorf("record leader config status: %w", err)
	}

	c.manager.syncStateNow()
	return nil
}

// Reconcile applies the desired config snapshot on followers when they lag
// behind the cluster's target version.
func (c *ConfigSyncManager) Reconcile() {
	c.manager.mu.RLock()
	isLeader := c.manager.self.Role == RoleLeader
	c.manager.mu.RUnlock()
	if isLeader {
		return
	}

	desired, err := c.desiredPayload()
	if err != nil || desired == nil || len(desired.Snapshot) == 0 {
		return
	}

	c.mu.Lock()
	applier := c.applier
	if applier == nil || c.applying {
		c.mu.Unlock()
		return
	}
	if c.appliedVersion == desired.Version {
		c.mu.Unlock()
		return
	}
	if !c.lastAttempt.IsZero() && time.Since(c.lastAttempt) < time.Second {
		c.mu.Unlock()
		return
	}
	c.applying = true
	c.lastAttempt = time.Now()
	version := desired.Version
	snapshot := append([]byte(nil), desired.Snapshot...)
	c.mu.Unlock()

	go c.apply(version, snapshot, applier)
}

// Status returns the current cluster-wide view of config sync progress.
func (c *ConfigSyncManager) Status() *ConfigSyncStatus {
	status := &ConfigSyncStatus{
		Nodes: []ConfigSyncNodeStatus{},
	}

	desired, _ := c.desiredPayload()
	if desired != nil {
		status.Version = desired.Version
		status.ChangeID = desired.ChangeID
		status.Requester = desired.Requester
		status.UpdatedAt = desired.UpdatedAt
	}

	state := c.manager.state.Snapshot()
	nodeStatuses := make(map[string]ConfigSyncNodeStatus)
	for key, entry := range state {
		if !strings.HasPrefix(key, configSyncStatusKeyPrefix) {
			continue
		}
		var nodeStatus ConfigSyncNodeStatus
		if err := json.Unmarshal(entry.Value, &nodeStatus); err != nil {
			continue
		}
		nodeStatuses[nodeStatus.NodeID] = nodeStatus
	}

	for _, node := range c.manager.Nodes() {
		current := ConfigSyncNodeStatus{
			NodeID:   node.ID,
			NodeName: node.Name,
			Role:     string(node.Role),
			Status:   configSyncStatusIdle,
		}
		if desired != nil {
			current.Version = desired.Version
			current.Status = configSyncStatusPending
		}
		if stored, ok := nodeStatuses[node.ID]; ok && (desired == nil || stored.Version == desired.Version) {
			current.Version = stored.Version
			current.Status = stored.Status
			current.AppliedAt = stored.AppliedAt
			current.Error = stored.Error
		}
		status.Nodes = append(status.Nodes, current)
	}

	sort.Slice(status.Nodes, func(i, j int) bool {
		return status.Nodes[i].NodeID < status.Nodes[j].NodeID
	})
	return status
}

func (c *ConfigSyncManager) apply(version string, snapshot []byte, applier func([]byte) error) {
	appliedAt := time.Now().UTC()
	err := applier(snapshot)
	status := configSyncStatusApplied
	errText := ""

	c.mu.Lock()
	if err == nil {
		c.appliedVersion = version
	} else {
		status = configSyncStatusFailed
		errText = err.Error()
	}
	c.applying = false
	c.mu.Unlock()

	_ = c.recordLocalStatus(version, status, errText, appliedAt)
}

func (c *ConfigSyncManager) desiredPayload() (*ConfigSyncPayload, error) {
	raw, ok := c.manager.state.Get(configSyncDesiredKey)
	if !ok {
		return nil, nil
	}

	var desired ConfigSyncPayload
	if err := json.Unmarshal(raw, &desired); err != nil {
		return nil, fmt.Errorf("decode desired config: %w", err)
	}
	return &desired, nil
}

func (c *ConfigSyncManager) recordLocalStatus(version, status, errText string, appliedAt time.Time) error {
	self := c.manager.Self()
	entry := ConfigSyncNodeStatus{
		NodeID:    self.ID,
		Version:   version,
		Status:    status,
		AppliedAt: appliedAt,
		Error:     errText,
	}
	raw, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal config status: %w", err)
	}
	return c.manager.state.Set(configSyncStatusKey(self.ID), raw)
}

func configSyncStatusKey(nodeID string) string {
	return configSyncStatusKeyPrefix + nodeID
}
