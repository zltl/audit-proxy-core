package cluster

import "time"

// NodeRole represents the current role of a node in the cluster.
type NodeRole string

const (
	RoleLeader    NodeRole = "leader"
	RoleFollower  NodeRole = "follower"
	RoleCandidate NodeRole = "candidate"
)

// NodeStatus represents the health status of a cluster node.
type NodeStatus string

const (
	StatusHealthy  NodeStatus = "healthy"
	StatusDegraded NodeStatus = "degraded"
	StatusOffline  NodeStatus = "offline"
)

// Node represents a single member of the cluster.
type Node struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Address  string            `json:"address"`  // cluster communication host:port
	APIAddr  string            `json:"api_addr"` // control plane API address
	Role     NodeRole          `json:"role"`
	Status   NodeStatus        `json:"status"`
	JoinedAt time.Time         `json:"joined_at"`
	LastSeen time.Time         `json:"last_seen"`
	Version  string            `json:"version"`
	Metadata map[string]string `json:"metadata,omitempty"`
	Sessions int               `json:"sessions"` // active session count
	Load     float64           `json:"load"`      // CPU load
}

// ClusterConfig holds the configuration for the cluster manager.
type ClusterConfig struct {
	NodeID            string
	NodeName          string
	BindAddr          string        // cluster communication address (host:port)
	APIAddr           string        // this node's public API address
	Seeds             []string      // seed node addresses for joining
	HeartbeatInterval time.Duration // default: 5s
	ElectionTimeout   time.Duration // default: 15s
	SyncInterval      time.Duration // default: 10s
}

// defaults fills in zero-valued fields with sensible defaults.
func (c *ClusterConfig) defaults() {
	if c.HeartbeatInterval == 0 {
		c.HeartbeatInterval = 5 * time.Second
	}
	if c.ElectionTimeout == 0 {
		c.ElectionTimeout = 15 * time.Second
	}
	if c.SyncInterval == 0 {
		c.SyncInterval = 10 * time.Second
	}
}
