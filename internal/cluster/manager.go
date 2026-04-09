package cluster

import (
	"context"
	crand "crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"sync"
	"time"
)

// ClusterEvent describes a significant event in the cluster lifecycle.
type ClusterEvent struct {
	Type    string            `json:"type"` // node_joined, node_left, leader_elected, leader_lost
	NodeID  string            `json:"node_id"`
	Details map[string]string `json:"details,omitempty"`
}

// Manager coordinates cluster membership, leader election, and state sync.
type Manager struct {
	config     *ClusterConfig
	self       *Node
	nodes      map[string]*Node
	mu         sync.RWMutex
	leader     string // current leader node ID
	term       uint64
	votedFor   string
	listener   net.Listener
	httpServer *http.Server
	httpClient *http.Client
	state      *StateSync
	configSync *ConfigSyncManager
	eventCh    chan ClusterEvent
	stopCh     chan struct{}

	lastHeartbeat time.Time
}

const (
	metadataRegionKey        = "region"
	metadataZoneKey          = "zone"
	metadataFailureDomainKey = "failure_domain"
)

func cloneMetadata(metadata map[string]string) map[string]string {
	if len(metadata) == 0 {
		return nil
	}
	cloned := make(map[string]string, len(metadata))
	for key, value := range metadata {
		cloned[key] = value
	}
	return cloned
}

func cloneNode(node *Node) *Node {
	if node == nil {
		return nil
	}
	cloned := *node
	cloned.Metadata = cloneMetadata(node.Metadata)
	return &cloned
}

func newNodeMetadata(region, zone string) map[string]string {
	metadata := make(map[string]string)
	if region != "" {
		metadata[metadataRegionKey] = region
	}
	if zone != "" {
		metadata[metadataZoneKey] = zone
	}
	if region != "" && zone != "" {
		metadata[metadataFailureDomainKey] = region + "/" + zone
	}
	if len(metadata) == 0 {
		return nil
	}
	return metadata
}

// NewManager creates a new cluster manager. Call Start to begin cluster
// communication and leader election.
func NewManager(cfg *ClusterConfig) (*Manager, error) {
	if cfg.NodeID == "" {
		return nil, fmt.Errorf("cluster: NodeID is required")
	}
	if cfg.BindAddr == "" {
		return nil, fmt.Errorf("cluster: BindAddr is required")
	}
	if err := validateTLSConfig(cfg); err != nil {
		return nil, err
	}
	cfg.defaults()

	clientTLSConfig, err := buildClientTLSConfig(cfg)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{}
	if clientTLSConfig != nil {
		transport.TLSClientConfig = clientTLSConfig
	}

	now := time.Now().UTC()
	self := &Node{
		ID:       cfg.NodeID,
		Name:     cfg.NodeName,
		Address:  cfg.BindAddr,
		APIAddr:  cfg.APIAddr,
		Role:     RoleFollower,
		Status:   StatusHealthy,
		JoinedAt: now,
		LastSeen: now,
		Version:  "2.0.0",
		Metadata: newNodeMetadata(cfg.Region, cfg.Zone),
	}

	m := &Manager{
		config: cfg,
		self:   self,
		nodes:  map[string]*Node{cfg.NodeID: self},
		httpClient: &http.Client{
			Timeout:   2 * time.Second,
			Transport: transport,
		},
		eventCh: make(chan ClusterEvent, 64),
		stopCh:  make(chan struct{}),
	}
	m.state = newStateSync(m)
	m.configSync = newConfigSyncManager(m)
	return m, nil
}

// Start begins listening for cluster RPCs and runs leader election and
// heartbeat background loops. The provided context is used to signal
// graceful shutdown.
func (m *Manager) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", m.config.BindAddr)
	if err != nil {
		return fmt.Errorf("cluster listen: %w", err)
	}
	m.listener = ln

	// Update BindAddr to the actual address (useful when port is 0).
	m.mu.Lock()
	m.config.BindAddr = ln.Addr().String()
	m.self.Address = ln.Addr().String()
	m.lastHeartbeat = time.Now()
	m.mu.Unlock()

	serverTLSConfig, err := buildServerTLSConfig(m.config)
	if err != nil {
		return err
	}
	m.httpServer = &http.Server{
		Handler:   m.clusterMux(),
		TLSConfig: serverTLSConfig,
	}

	if serverTLSConfig != nil {
		go m.httpServer.ServeTLS(ln, "", "")
	} else {
		go m.httpServer.Serve(ln)
	}

	// If there are no seeds, this node starts as the leader.
	if len(m.config.Seeds) == 0 {
		m.mu.Lock()
		m.self.Role = RoleLeader
		m.leader = m.self.ID
		m.term = 1
		m.mu.Unlock()
		m.emitEvent("leader_elected", m.self.ID, nil)
	} else {
		// Try to join.
		_ = m.Join(m.config.Seeds)
	}

	go m.electionLoop(ctx)
	go m.heartbeatLoop(ctx)
	go m.syncLoop(ctx)
	go m.discoveryLoop(ctx)

	return nil
}

// Stop shuts down the cluster manager: leaves the cluster, stops listeners,
// and drains background goroutines.
func (m *Manager) Stop() error {
	select {
	case <-m.stopCh:
		return nil // already stopped
	default:
	}
	close(m.stopCh)

	_ = m.Leave()

	if m.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		m.httpServer.Shutdown(ctx)
	}
	return nil
}

// Join attempts to join an existing cluster by contacting seed nodes.
func (m *Manager) Join(seeds []string) error {
	m.mu.RLock()
	self := *m.self
	m.mu.RUnlock()

	resolveCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	resolvedSeeds, err := resolveSeedReferences(resolveCtx, seeds)
	if err != nil {
		return err
	}

	req := &JoinRequest{Node: &self}
	for _, seed := range resolvedSeeds {
		if seed == m.self.Address {
			continue
		}
		reply, err := m.sendJoinRequest(seed, req)
		if err != nil {
			continue
		}
		m.mu.Lock()
		if reply.Leader != "" {
			m.leader = reply.Leader
		}
		for _, n := range reply.Nodes {
			if n.ID == m.self.ID {
				continue
			}
			m.nodes[n.ID] = n
		}
		m.self.Role = RoleFollower
		m.lastHeartbeat = time.Now()
		m.mu.Unlock()
		return nil
	}
	return fmt.Errorf("cluster: could not join any seed")
}

// Leave gracefully removes this node from the cluster.
func (m *Manager) Leave() error {
	m.mu.RLock()
	peers := m.peerAddressesLocked()
	m.mu.RUnlock()

	req := &LeaveRequest{NodeID: m.self.ID}
	for _, addr := range peers {
		_ = m.sendLeaveNotification(addr, req)
	}
	return nil
}

// IsLeader reports whether this node is the current cluster leader.
func (m *Manager) IsLeader() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.self.Role == RoleLeader
}

// Leader returns the current leader node, or nil if unknown.
func (m *Manager) Leader() *Node {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if n, ok := m.nodes[m.leader]; ok {
		return cloneNode(n)
	}
	return nil
}

// Nodes returns a snapshot of all known cluster members.
func (m *Manager) Nodes() []*Node {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.nodeListLocked()
}

// NodeCount returns the number of known nodes.
func (m *Manager) NodeCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.nodes)
}

// Events returns a read-only channel of cluster events.
func (m *Manager) Events() <-chan ClusterEvent {
	return m.eventCh
}

// State returns the distributed state store.
func (m *Manager) State() *StateSync {
	return m.state
}

// SetConfigSyncApplier attaches a callback used by followers to apply synced
// configuration snapshots locally.
func (m *Manager) SetConfigSyncApplier(applier func([]byte) error) {
	if m.configSync != nil {
		m.configSync.SetApplier(applier)
	}
}

// PublishConfigSnapshot publishes the desired cluster config snapshot and marks
// the leader's local status as applied.
func (m *Manager) PublishConfigSnapshot(snapshot []byte, version, changeID, requester string) error {
	if m.configSync == nil {
		return nil
	}
	return m.configSync.Publish(snapshot, version, changeID, requester)
}

// GetConfigSyncStatus returns the current cluster-wide config sync view.
func (m *Manager) GetConfigSyncStatus() *ConfigSyncStatus {
	if m.configSync == nil {
		return &ConfigSyncStatus{Nodes: []ConfigSyncNodeStatus{}}
	}
	return m.configSync.Status()
}

// GetDesiredConfigPayload returns the current desired cluster config snapshot, if any.
func (m *Manager) GetDesiredConfigPayload() (*ConfigSyncPayload, error) {
	if m.configSync == nil {
		return nil, nil
	}
	payload, err := m.configSync.desiredPayload()
	if err != nil || payload == nil {
		return payload, err
	}
	cloned := *payload
	cloned.Snapshot = append(json.RawMessage(nil), payload.Snapshot...)
	return &cloned, nil
}

// Self returns a copy of this node's descriptor.
func (m *Manager) Self() Node {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return *cloneNode(m.self)
}

// Term returns the current election term.
func (m *Manager) Term() uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.term
}

// --- background loops ---

func (m *Manager) electionLoop(ctx context.Context) {
	for {
		// Jitter the election timeout to reduce split votes.
		jitter, err := cryptoJitter(m.config.ElectionTimeout / 2)
		if err != nil {
			jitter = 0
		}
		timeout := m.config.ElectionTimeout + jitter

		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case <-time.After(timeout):
		}

		m.mu.RLock()
		isLeader := m.self.Role == RoleLeader
		elapsed := time.Since(m.lastHeartbeat)
		m.mu.RUnlock()

		if isLeader {
			continue
		}

		if elapsed < m.config.ElectionTimeout {
			continue
		}

		m.startElection()
	}
}

func cryptoJitter(max time.Duration) (time.Duration, error) {
	if max <= 0 {
		return 0, nil
	}

	n, err := crand.Int(crand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0, err
	}
	return time.Duration(n.Int64()), nil
}

func (m *Manager) startElection() {
	m.mu.Lock()
	m.term++
	m.self.Role = RoleCandidate
	m.votedFor = m.self.ID
	currentTerm := m.term
	peers := m.peerNodesLocked()
	m.lastHeartbeat = time.Now()
	m.mu.Unlock()

	votes := 1 // vote for self
	responded := 1

	req := &VoteRequest{
		Term:        currentTerm,
		CandidateID: m.self.ID,
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, p := range peers {
		wg.Add(1)
		go func(id, addr string) {
			defer wg.Done()
			reply, err := m.sendVoteRequest(addr, req)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				// Mark unreachable node as offline.
				m.mu.Lock()
				if n, ok := m.nodes[id]; ok {
					n.Status = StatusOffline
				}
				m.mu.Unlock()
				return
			}
			responded++
			if reply.Term > currentTerm {
				m.mu.Lock()
				if reply.Term > m.term {
					m.term = reply.Term
					m.self.Role = RoleFollower
					m.votedFor = ""
				}
				m.mu.Unlock()
				return
			}
			if reply.Granted {
				votes++
			}
		}(p.id, p.addr)
	}
	wg.Wait()

	m.mu.Lock()
	defer m.mu.Unlock()

	// Only claim victory if we are still a candidate in the same term.
	if m.term != currentTerm || m.self.Role != RoleCandidate {
		return
	}

	// Remove nodes that are offline — they are no longer part of
	// the effective cluster.
	for id, n := range m.nodes {
		if id != m.self.ID && n.Status == StatusOffline {
			delete(m.nodes, id)
		}
	}

	total := len(m.nodes)
	if votes > total/2 {
		m.self.Role = RoleLeader
		m.leader = m.self.ID
		m.mu.Unlock()
		m.emitEvent("leader_elected", m.self.ID, nil)
		m.mu.Lock()
	} else {
		m.self.Role = RoleFollower
	}
}

func (m *Manager) heartbeatLoop(ctx context.Context) {
	ticker := time.NewTicker(m.config.HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case <-ticker.C:
		}

		m.mu.RLock()
		if m.self.Role != RoleLeader {
			m.mu.RUnlock()
			continue
		}
		req := &HeartbeatRequest{
			Term:     m.term,
			LeaderID: m.self.ID,
			Nodes:    m.nodeListLocked(),
		}
		peers := m.peerAddressesLocked()
		m.mu.RUnlock()

		m.self.LastSeen = time.Now()

		for _, addr := range peers {
			go func(a string) {
				reply, err := m.sendHeartbeat(a, req)
				if err != nil {
					m.markNodeUnreachable(a)
					return
				}
				if reply.Term > req.Term {
					m.mu.Lock()
					if reply.Term > m.term {
						m.term = reply.Term
						m.self.Role = RoleFollower
						m.votedFor = ""
						oldLeader := m.leader
						m.leader = ""
						m.mu.Unlock()
						if oldLeader == m.self.ID {
							m.emitEvent("leader_lost", m.self.ID, nil)
						}
					} else {
						m.mu.Unlock()
					}
				}
			}(addr)
		}
	}
}

func (m *Manager) syncLoop(ctx context.Context) {
	ticker := time.NewTicker(m.config.SyncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case <-ticker.C:
		}

		m.syncStateNow()
	}
}

func (m *Manager) discoveryLoop(ctx context.Context) {
	if len(m.config.Seeds) == 0 {
		return
	}

	interval := m.config.SyncInterval
	if interval <= 0 {
		interval = 10 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case <-ticker.C:
		}

		m.mu.RLock()
		shouldRetry := len(m.nodes) <= 1
		m.mu.RUnlock()
		if !shouldRetry {
			continue
		}
		_ = m.Join(m.config.Seeds)
	}
}

func (m *Manager) syncStateNow() {
	m.mu.RLock()
	if m.self.Role != RoleLeader {
		m.mu.RUnlock()
		return
	}
	peers := m.peerAddressesLocked()
	m.mu.RUnlock()

	snap := m.state.Snapshot()
	req := &SyncRequest{Entries: snap}

	for _, addr := range peers {
		go func(a string) {
			reply, err := m.sendSync(a, req)
			if err != nil {
				return
			}
			// Merge follower data (higher version wins).
			m.state.mu.Lock()
			for k, v := range reply.Entries {
				if existing, ok := m.state.data[k]; !ok || v.Version > existing.Version {
					m.state.data[k] = v
				}
			}
			m.state.mu.Unlock()
		}(addr)
	}
}

// --- helpers ---

// nodeListLocked returns a copy of all known nodes. Must be called with
// m.mu held (read or write).
func (m *Manager) nodeListLocked() []*Node {
	nodes := make([]*Node, 0, len(m.nodes))
	for _, n := range m.nodes {
		nodes = append(nodes, cloneNode(n))
	}
	return nodes
}

// peerAddressesLocked returns the cluster addresses of all nodes except self.
// Must be called with m.mu held.
func (m *Manager) peerAddressesLocked() []string {
	addrs := make([]string, 0, len(m.nodes)-1)
	for id, n := range m.nodes {
		if id == m.self.ID {
			continue
		}
		addrs = append(addrs, n.Address)
	}
	return addrs
}

type peerInfo struct {
	id   string
	addr string
}

// peerNodesLocked returns id+address pairs for all nodes except self.
// Must be called with m.mu held.
func (m *Manager) peerNodesLocked() []peerInfo {
	peers := make([]peerInfo, 0, len(m.nodes)-1)
	for id, n := range m.nodes {
		if id == m.self.ID {
			continue
		}
		peers = append(peers, peerInfo{id: id, addr: n.Address})
	}
	return peers
}

func (m *Manager) markNodeUnreachable(addr string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, n := range m.nodes {
		if n.Address == addr {
			n.Status = StatusDegraded
			return
		}
	}
}

func (m *Manager) emitEvent(typ, nodeID string, details map[string]string) {
	ev := ClusterEvent{Type: typ, NodeID: nodeID, Details: details}
	select {
	case m.eventCh <- ev:
	default:
		// Drop event if channel is full.
	}
}
