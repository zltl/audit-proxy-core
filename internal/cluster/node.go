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
	Load     float64           `json:"load"`     // CPU load
}

// ClusterConfig holds the configuration for the cluster manager.
type ClusterConfig struct {
	NodeID            string
	NodeName          string
	BindAddr          string        // cluster communication address (host:port)
	APIAddr           string        // this node's public API address
	Region            string        // logical deployment region (for example us-east-1)
	Zone              string        // availability zone / fault domain (for example us-east-1a)
	Seeds             []string      // seed addresses or discovery URIs (dns://, k8s://, consul://)
	HeartbeatInterval time.Duration // default: 5s
	ElectionTimeout   time.Duration // default: 15s
	SyncInterval      time.Duration // default: 10s
	TLSCert           string        // PEM certificate used for both server and client auth
	TLSKey            string        // PEM private key paired with TLSCert
	TLSCA             string        // PEM CA bundle used to verify and require peer certificates
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

func (c *ClusterConfig) mtlsEnabled() bool {
	return c.TLSCert != "" || c.TLSKey != "" || c.TLSCA != ""
}
