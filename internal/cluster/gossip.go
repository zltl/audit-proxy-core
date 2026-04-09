package cluster

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// --- wire types for inter-node communication ---

// HeartbeatRequest is sent by the leader to all followers.
type HeartbeatRequest struct {
	Term     uint64  `json:"term"`
	LeaderID string  `json:"leader_id"`
	Nodes    []*Node `json:"nodes"`
}

// HeartbeatReply is returned in response to a heartbeat.
type HeartbeatReply struct {
	Term    uint64 `json:"term"`
	Success bool   `json:"success"`
}

// VoteRequest is sent by a candidate to request votes.
type VoteRequest struct {
	Term        uint64 `json:"term"`
	CandidateID string `json:"candidate_id"`
}

// VoteReply is the response to a VoteRequest.
type VoteReply struct {
	Term    uint64 `json:"term"`
	Granted bool   `json:"granted"`
}

// JoinRequest is sent by a node that wants to join the cluster.
type JoinRequest struct {
	Node *Node `json:"node"`
}

// JoinReply is returned in response to a join request.
type JoinReply struct {
	Success bool    `json:"success"`
	Leader  string  `json:"leader"`
	Nodes   []*Node `json:"nodes"`
}

// LeaveRequest is sent when a node gracefully leaves the cluster.
type LeaveRequest struct {
	NodeID string `json:"node_id"`
}

// SyncRequest carries state entries for synchronisation.
type SyncRequest struct {
	Entries map[string]StateEntry `json:"entries"`
}

// SyncReply is returned in response to a sync request.
type SyncReply struct {
	Success bool                  `json:"success"`
	Entries map[string]StateEntry `json:"entries"`
}

// StatusResponse is returned by GET /cluster/status.
type StatusResponse struct {
	NodeID  string  `json:"node_id"`
	Role    string  `json:"role"`
	Leader  string  `json:"leader"`
	Term    uint64  `json:"term"`
	Nodes   []*Node `json:"nodes"`
	Healthy bool    `json:"healthy"`
}

// --- HTTP handlers (cluster-internal, served on the cluster port) ---

func (m *Manager) clusterMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /cluster/heartbeat", m.handleHeartbeat)
	mux.HandleFunc("POST /cluster/vote-request", m.handleVoteRequest)
	mux.HandleFunc("POST /cluster/join", m.handleJoinRequest)
	mux.HandleFunc("POST /cluster/leave", m.handleLeaveRequest)
	mux.HandleFunc("POST /cluster/sync", m.handleSyncRequest)
	mux.HandleFunc("GET /cluster/status", m.handleStatus)
	return mux
}

func (m *Manager) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	var req HeartbeatRequest
	if err := decodeBody(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	m.mu.Lock()
	reply := HeartbeatReply{Term: m.term, Success: true}

	if req.Term < m.term {
		reply.Success = false
		m.mu.Unlock()
		encodeJSON(w, reply)
		return
	}

	if req.Term > m.term {
		m.term = req.Term
		m.votedFor = ""
	}
	m.leader = req.LeaderID
	m.self.Role = RoleFollower
	m.lastHeartbeat = time.Now()

	// Merge node list from leader.
	for _, n := range req.Nodes {
		if n.ID == m.self.ID {
			continue
		}
		existing, ok := m.nodes[n.ID]
		if !ok {
			m.nodes[n.ID] = n
			m.mu.Unlock()
			m.emitEvent("node_joined", n.ID, nil)
			m.mu.Lock()
		} else {
			existing.Name = n.Name
			existing.Address = n.Address
			existing.APIAddr = n.APIAddr
			existing.Status = n.Status
			existing.LastSeen = n.LastSeen
			existing.Role = n.Role
			existing.Version = n.Version
			existing.Metadata = cloneMetadata(n.Metadata)
			existing.Sessions = n.Sessions
			existing.Load = n.Load
		}
	}

	reply.Term = m.term
	m.mu.Unlock()
	encodeJSON(w, reply)
}

func (m *Manager) handleVoteRequest(w http.ResponseWriter, r *http.Request) {
	var req VoteRequest
	if err := decodeBody(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	reply := VoteReply{Term: m.term, Granted: false}

	if req.Term < m.term {
		encodeJSON(w, reply)
		return
	}

	if req.Term > m.term {
		m.term = req.Term
		m.votedFor = ""
		m.self.Role = RoleFollower
	}

	if m.votedFor == "" || m.votedFor == req.CandidateID {
		m.votedFor = req.CandidateID
		reply.Granted = true
		reply.Term = m.term
		m.lastHeartbeat = time.Now() // reset election timer
	}

	encodeJSON(w, reply)
}

func (m *Manager) handleJoinRequest(w http.ResponseWriter, r *http.Request) {
	var req JoinRequest
	if err := decodeBody(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	m.mu.Lock()
	node := cloneNode(req.Node)
	node.Status = StatusHealthy
	node.LastSeen = time.Now()
	m.nodes[node.ID] = node

	reply := JoinReply{
		Success: true,
		Leader:  m.leader,
		Nodes:   m.nodeListLocked(),
	}
	m.mu.Unlock()

	m.emitEvent("node_joined", req.Node.ID, nil)
	encodeJSON(w, reply)
}

func (m *Manager) handleLeaveRequest(w http.ResponseWriter, r *http.Request) {
	var req LeaveRequest
	if err := decodeBody(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	m.mu.Lock()
	delete(m.nodes, req.NodeID)
	wasLeader := m.leader == req.NodeID
	if wasLeader {
		m.leader = ""
	}
	m.mu.Unlock()

	m.emitEvent("node_left", req.NodeID, nil)

	encodeJSON(w, map[string]bool{"success": true})
}

func (m *Manager) handleSyncRequest(w http.ResponseWriter, r *http.Request) {
	var req SyncRequest
	if err := decodeBody(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	m.state.mu.Lock()
	// Merge incoming entries (higher version wins).
	for k, incoming := range req.Entries {
		if existing, ok := m.state.data[k]; !ok || incoming.Version > existing.Version {
			m.state.data[k] = incoming
		}
	}
	// Build reply with our full state.
	reply := SyncReply{
		Success: true,
		Entries: make(map[string]StateEntry, len(m.state.data)),
	}
	for k, v := range m.state.data {
		reply.Entries[k] = v
	}
	m.state.mu.Unlock()
	if m.configSync != nil {
		m.configSync.Reconcile()
	}

	encodeJSON(w, reply)
}

func (m *Manager) handleStatus(w http.ResponseWriter, r *http.Request) {
	m.mu.RLock()
	resp := StatusResponse{
		NodeID:  m.self.ID,
		Role:    string(m.self.Role),
		Leader:  m.leader,
		Term:    m.term,
		Nodes:   m.nodeListLocked(),
		Healthy: m.self.Status == StatusHealthy,
	}
	m.mu.RUnlock()
	encodeJSON(w, resp)
}

// --- HTTP client helpers for sending cluster RPCs ---

func (m *Manager) sendHeartbeat(addr string, req *HeartbeatRequest) (*HeartbeatReply, error) {
	var reply HeartbeatReply
	if err := m.postJSON(addr, "/cluster/heartbeat", req, &reply); err != nil {
		return nil, err
	}
	return &reply, nil
}

func (m *Manager) sendVoteRequest(addr string, req *VoteRequest) (*VoteReply, error) {
	var reply VoteReply
	if err := m.postJSON(addr, "/cluster/vote-request", req, &reply); err != nil {
		return nil, err
	}
	return &reply, nil
}

func (m *Manager) sendJoinRequest(addr string, req *JoinRequest) (*JoinReply, error) {
	var reply JoinReply
	if err := m.postJSON(addr, "/cluster/join", req, &reply); err != nil {
		return nil, err
	}
	return &reply, nil
}

func (m *Manager) sendLeaveNotification(addr string, req *LeaveRequest) error {
	return m.postJSON(addr, "/cluster/leave", req, nil)
}

func (m *Manager) sendSync(addr string, req *SyncRequest) (*SyncReply, error) {
	var reply SyncReply
	if err := m.postJSON(addr, "/cluster/sync", req, &reply); err != nil {
		return nil, err
	}
	return &reply, nil
}

func (m *Manager) postJSON(addr, path string, body, reply interface{}) error {
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	url := clusterBaseURL(m.config, addr) + path
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("post %s: create request: %w", path, err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("post %s: %w", path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("post %s: status %d: %s", path, resp.StatusCode, string(b))
	}

	if reply != nil {
		if err := json.NewDecoder(resp.Body).Decode(reply); err != nil {
			return fmt.Errorf("decode %s reply: %w", path, err)
		}
	}
	return nil
}

// --- helpers ---

func decodeBody(r *http.Request, dst interface{}) error {
	defer r.Body.Close()
	return json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(dst)
}

func encodeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
