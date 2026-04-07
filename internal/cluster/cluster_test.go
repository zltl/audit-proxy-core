package cluster

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// helper: short-timeout config for tests.
func testConfig(id, name, bind string) *ClusterConfig {
	return &ClusterConfig{
		NodeID:            id,
		NodeName:          name,
		BindAddr:          bind,
		HeartbeatInterval: 100 * time.Millisecond,
		ElectionTimeout:   300 * time.Millisecond,
		SyncInterval:      200 * time.Millisecond,
	}
}

// startManager is a test helper that creates, starts, and returns a Manager.
func startManager(t *testing.T, cfg *ClusterConfig) *Manager {
	t.Helper()
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		m.Stop()
	})
	if err := m.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	return m
}

// --- Tests ---

func TestNewManagerRequiresNodeID(t *testing.T) {
	_, err := NewManager(&ClusterConfig{BindAddr: "127.0.0.1:0"})
	if err == nil {
		t.Fatal("expected error for missing NodeID")
	}
}

func TestNewManagerRequiresBindAddr(t *testing.T) {
	_, err := NewManager(&ClusterConfig{NodeID: "n1"})
	if err == nil {
		t.Fatal("expected error for missing BindAddr")
	}
}

func TestConfigDefaults(t *testing.T) {
	cfg := &ClusterConfig{NodeID: "n1", BindAddr: "127.0.0.1:0"}
	cfg.defaults()
	if cfg.HeartbeatInterval != 5*time.Second {
		t.Errorf("HeartbeatInterval = %v, want 5s", cfg.HeartbeatInterval)
	}
	if cfg.ElectionTimeout != 15*time.Second {
		t.Errorf("ElectionTimeout = %v, want 15s", cfg.ElectionTimeout)
	}
	if cfg.SyncInterval != 10*time.Second {
		t.Errorf("SyncInterval = %v, want 10s", cfg.SyncInterval)
	}
}

func TestSingleNodeBecomesLeader(t *testing.T) {
	m := startManager(t, testConfig("node-1", "Node 1", "127.0.0.1:0"))

	// Single node with no seeds should become leader immediately.
	if !m.IsLeader() {
		t.Fatal("single node should be leader")
	}
	if m.Leader() == nil {
		t.Fatal("Leader() should not be nil")
	}
	if m.Leader().ID != "node-1" {
		t.Fatalf("Leader().ID = %q, want %q", m.Leader().ID, "node-1")
	}
}

func TestSingleNodeCount(t *testing.T) {
	m := startManager(t, testConfig("node-1", "Node 1", "127.0.0.1:0"))
	if m.NodeCount() != 1 {
		t.Fatalf("NodeCount() = %d, want 1", m.NodeCount())
	}
}

func TestSingleNodeEventLeaderElected(t *testing.T) {
	m := startManager(t, testConfig("node-1", "Node 1", "127.0.0.1:0"))

	select {
	case ev := <-m.Events():
		if ev.Type != "leader_elected" {
			t.Fatalf("event type = %q, want %q", ev.Type, "leader_elected")
		}
		if ev.NodeID != "node-1" {
			t.Fatalf("event NodeID = %q, want %q", ev.NodeID, "node-1")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for leader_elected event")
	}
}

func TestSingleNodeSelf(t *testing.T) {
	m := startManager(t, testConfig("node-1", "Node 1", "127.0.0.1:0"))
	self := m.Self()
	if self.ID != "node-1" {
		t.Fatalf("Self().ID = %q, want %q", self.ID, "node-1")
	}
	if self.Role != RoleLeader {
		t.Fatalf("Self().Role = %q, want %q", self.Role, RoleLeader)
	}
}

func TestSingleNodeTerm(t *testing.T) {
	m := startManager(t, testConfig("node-1", "Node 1", "127.0.0.1:0"))
	if m.Term() != 1 {
		t.Fatalf("Term() = %d, want 1", m.Term())
	}
}

func TestTwoNodeClusterLeaderElection(t *testing.T) {
	m1 := startManager(t, testConfig("node-1", "Node 1", "127.0.0.1:0"))
	addr1 := m1.Self().Address

	cfg2 := testConfig("node-2", "Node 2", "127.0.0.1:0")
	cfg2.Seeds = []string{addr1}
	m2 := startManager(t, cfg2)

	// Give heartbeats time to propagate.
	time.Sleep(500 * time.Millisecond)

	// Exactly one leader.
	leaders := 0
	if m1.IsLeader() {
		leaders++
	}
	if m2.IsLeader() {
		leaders++
	}
	if leaders != 1 {
		t.Fatalf("expected exactly 1 leader, got %d", leaders)
	}

	// Both nodes know about each other.
	if m1.NodeCount() < 2 {
		t.Fatalf("m1.NodeCount() = %d, want >= 2", m1.NodeCount())
	}
	if m2.NodeCount() < 2 {
		t.Fatalf("m2.NodeCount() = %d, want >= 2", m2.NodeCount())
	}
}

func TestNodeJoinEvent(t *testing.T) {
	m1 := startManager(t, testConfig("node-1", "Node 1", "127.0.0.1:0"))
	// Drain leader_elected event.
	<-m1.Events()

	addr1 := m1.Self().Address
	cfg2 := testConfig("node-2", "Node 2", "127.0.0.1:0")
	cfg2.Seeds = []string{addr1}
	startManager(t, cfg2)

	select {
	case ev := <-m1.Events():
		if ev.Type != "node_joined" {
			t.Fatalf("event type = %q, want %q", ev.Type, "node_joined")
		}
		if ev.NodeID != "node-2" {
			t.Fatalf("event NodeID = %q, want %q", ev.NodeID, "node-2")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for node_joined event")
	}
}

func TestNodeLeave(t *testing.T) {
	m1 := startManager(t, testConfig("node-1", "Node 1", "127.0.0.1:0"))
	addr1 := m1.Self().Address

	cfg2 := testConfig("node-2", "Node 2", "127.0.0.1:0")
	cfg2.Seeds = []string{addr1}
	m2 := startManager(t, cfg2)

	time.Sleep(500 * time.Millisecond)

	if m1.NodeCount() < 2 {
		t.Fatalf("before leave: m1.NodeCount() = %d, want >= 2", m1.NodeCount())
	}

	m2.Leave()
	time.Sleep(200 * time.Millisecond)

	// After leave, node-1 should have removed node-2.
	if m1.NodeCount() != 1 {
		t.Fatalf("after leave: m1.NodeCount() = %d, want 1", m1.NodeCount())
	}
}

func TestHeartbeatTimeoutTriggersElection(t *testing.T) {
	m1 := startManager(t, testConfig("node-1", "Node 1", "127.0.0.1:0"))
	addr1 := m1.Self().Address

	cfg2 := testConfig("node-2", "Node 2", "127.0.0.1:0")
	cfg2.Seeds = []string{addr1}
	m2 := startManager(t, cfg2)

	time.Sleep(500 * time.Millisecond)

	// Stop node-1 (the current leader) abruptly.
	m1.Stop()

	// Wait for election timeout + election + margin.
	time.Sleep(1200 * time.Millisecond)

	// node-2 should have become leader.
	if !m2.IsLeader() {
		t.Fatal("node-2 should have become leader after node-1 stopped")
	}
}

func TestStateSyncBetweenNodes(t *testing.T) {
	m1 := startManager(t, testConfig("node-1", "Node 1", "127.0.0.1:0"))
	addr1 := m1.Self().Address

	cfg2 := testConfig("node-2", "Node 2", "127.0.0.1:0")
	cfg2.Seeds = []string{addr1}
	m2 := startManager(t, cfg2)

	time.Sleep(500 * time.Millisecond)

	// Set value on leader.
	if err := m1.State().Set("greeting", []byte("hello")); err != nil {
		t.Fatalf("Set on leader: %v", err)
	}

	// Wait for sync.
	time.Sleep(500 * time.Millisecond)

	val, ok := m2.State().Get("greeting")
	if !ok {
		t.Fatal("key 'greeting' not found on follower")
	}
	if string(val) != "hello" {
		t.Fatalf("got %q, want %q", string(val), "hello")
	}
}

func TestStateSetOnFollowerForwardsToLeader(t *testing.T) {
	m1 := startManager(t, testConfig("node-1", "Node 1", "127.0.0.1:0"))
	addr1 := m1.Self().Address

	cfg2 := testConfig("node-2", "Node 2", "127.0.0.1:0")
	cfg2.Seeds = []string{addr1}
	m2 := startManager(t, cfg2)

	time.Sleep(500 * time.Millisecond)

	// Set on follower should forward to leader.
	if err := m2.State().Set("key1", []byte("value1")); err != nil {
		t.Fatalf("Set on follower: %v", err)
	}

	// The leader should have it immediately (forwarded via sync endpoint).
	val, ok := m1.State().Get("key1")
	if !ok {
		t.Fatal("key not found on leader after follower set")
	}
	if string(val) != "value1" {
		t.Fatalf("got %q, want %q", string(val), "value1")
	}
}

func TestStateSnapshot(t *testing.T) {
	m := startManager(t, testConfig("node-1", "Node 1", "127.0.0.1:0"))
	m.State().Set("a", []byte("1"))
	m.State().Set("b", []byte("2"))

	snap := m.State().Snapshot()
	if len(snap) != 2 {
		t.Fatalf("snapshot len = %d, want 2", len(snap))
	}
	if string(snap["a"].Value) != "1" {
		t.Fatalf("snap[a] = %q, want %q", string(snap["a"].Value), "1")
	}
}

func TestStateDelete(t *testing.T) {
	m := startManager(t, testConfig("node-1", "Node 1", "127.0.0.1:0"))
	m.State().Set("k", []byte("v"))
	if err := m.State().Delete("k"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	_, ok := m.State().Get("k")
	if ok {
		t.Fatal("key should have been deleted")
	}
}

func TestClusterStatusEndpoint(t *testing.T) {
	m := startManager(t, testConfig("node-1", "Node 1", "127.0.0.1:0"))
	addr := m.Self().Address

	resp, err := http.Get("http://" + addr + "/cluster/status")
	if err != nil {
		t.Fatalf("GET /cluster/status: %v", err)
	}
	defer resp.Body.Close()

	var status StatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if status.NodeID != "node-1" {
		t.Fatalf("NodeID = %q, want %q", status.NodeID, "node-1")
	}
	if status.Role != "leader" {
		t.Fatalf("Role = %q, want %q", status.Role, "leader")
	}
}

func TestHeartbeatEndpointDirectly(t *testing.T) {
	m := startManager(t, testConfig("node-1", "Node 1", "127.0.0.1:0"))
	addr := m.Self().Address

	hb := HeartbeatRequest{Term: 1, LeaderID: "node-1", Nodes: []*Node{}}
	body, _ := json.Marshal(hb)
	resp, err := http.Post("http://"+addr+"/cluster/heartbeat", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("POST /cluster/heartbeat: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestVoteRequestEndpointDirectly(t *testing.T) {
	m := startManager(t, testConfig("node-1", "Node 1", "127.0.0.1:0"))
	addr := m.Self().Address

	vr := VoteRequest{Term: 2, CandidateID: "node-2"}
	body, _ := json.Marshal(vr)
	resp, err := http.Post("http://"+addr+"/cluster/vote-request", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("POST /cluster/vote-request: %v", err)
	}
	defer resp.Body.Close()

	var reply VoteReply
	json.NewDecoder(resp.Body).Decode(&reply)
	if !reply.Granted {
		t.Fatal("expected vote to be granted for higher term")
	}
}

func TestJoinEndpointDirectly(t *testing.T) {
	m := startManager(t, testConfig("node-1", "Node 1", "127.0.0.1:0"))
	addr := m.Self().Address

	jr := JoinRequest{Node: &Node{
		ID:      "node-ext",
		Name:    "External",
		Address: "127.0.0.1:9999",
	}}
	body, _ := json.Marshal(jr)
	resp, err := http.Post("http://"+addr+"/cluster/join", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("POST /cluster/join: %v", err)
	}
	defer resp.Body.Close()

	var reply JoinReply
	json.NewDecoder(resp.Body).Decode(&reply)
	if !reply.Success {
		t.Fatal("expected join to succeed")
	}
	if m.NodeCount() != 2 {
		t.Fatalf("NodeCount() = %d, want 2", m.NodeCount())
	}
}

func TestLeaveEndpointDirectly(t *testing.T) {
	m := startManager(t, testConfig("node-1", "Node 1", "127.0.0.1:0"))
	addr := m.Self().Address

	// First join a fake node.
	jr := JoinRequest{Node: &Node{ID: "node-tmp", Address: "127.0.0.1:9998"}}
	body, _ := json.Marshal(jr)
	http.Post("http://"+addr+"/cluster/join", "application/json", strings.NewReader(string(body)))

	if m.NodeCount() != 2 {
		t.Fatalf("before leave: NodeCount() = %d, want 2", m.NodeCount())
	}

	lr := LeaveRequest{NodeID: "node-tmp"}
	body, _ = json.Marshal(lr)
	resp, err := http.Post("http://"+addr+"/cluster/leave", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("POST /cluster/leave: %v", err)
	}
	resp.Body.Close()

	if m.NodeCount() != 1 {
		t.Fatalf("after leave: NodeCount() = %d, want 1", m.NodeCount())
	}
}

func TestSyncEndpointDirectly(t *testing.T) {
	m := startManager(t, testConfig("node-1", "Node 1", "127.0.0.1:0"))
	addr := m.Self().Address

	sr := SyncRequest{Entries: map[string]StateEntry{
		"x": {Key: "x", Value: []byte("42"), Version: 1, UpdatedBy: "ext"},
	}}
	body, _ := json.Marshal(sr)
	resp, err := http.Post("http://"+addr+"/cluster/sync", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("POST /cluster/sync: %v", err)
	}
	defer resp.Body.Close()

	var reply SyncReply
	json.NewDecoder(resp.Body).Decode(&reply)
	if !reply.Success {
		t.Fatal("expected sync to succeed")
	}

	val, ok := m.State().Get("x")
	if !ok || string(val) != "42" {
		t.Fatalf("expected key x=42 after sync, got ok=%v val=%q", ok, string(val))
	}
}

func TestConcurrentStateAccess(t *testing.T) {
	m := startManager(t, testConfig("node-1", "Node 1", "127.0.0.1:0"))

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := "key"
			m.State().Set(key, []byte("val"))
			m.State().Get(key)
			m.State().Snapshot()
		}(i)
	}
	wg.Wait()
}

func TestConcurrentNodeOperations(t *testing.T) {
	m := startManager(t, testConfig("node-1", "Node 1", "127.0.0.1:0"))

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.IsLeader()
			m.Leader()
			m.Nodes()
			m.NodeCount()
			m.Self()
			m.Term()
		}()
	}
	wg.Wait()
}

func TestThreeNodeCluster(t *testing.T) {
	m1 := startManager(t, testConfig("n1", "N1", "127.0.0.1:0"))
	addr1 := m1.Self().Address

	cfg2 := testConfig("n2", "N2", "127.0.0.1:0")
	cfg2.Seeds = []string{addr1}
	m2 := startManager(t, cfg2)

	cfg3 := testConfig("n3", "N3", "127.0.0.1:0")
	cfg3.Seeds = []string{addr1}
	m3 := startManager(t, cfg3)

	time.Sleep(600 * time.Millisecond)

	// Exactly one leader.
	leaders := 0
	for _, m := range []*Manager{m1, m2, m3} {
		if m.IsLeader() {
			leaders++
		}
	}
	if leaders != 1 {
		t.Fatalf("expected 1 leader in 3-node cluster, got %d", leaders)
	}

	// All nodes should know about 3 nodes.
	for _, m := range []*Manager{m1, m2, m3} {
		if m.NodeCount() < 3 {
			t.Fatalf("NodeCount() = %d, want >= 3 (node %s)", m.NodeCount(), m.Self().ID)
		}
	}
}

func TestStopIsIdempotent(t *testing.T) {
	m := startManager(t, testConfig("node-1", "Node 1", "127.0.0.1:0"))
	if err := m.Stop(); err != nil {
		t.Fatalf("first Stop: %v", err)
	}
	if err := m.Stop(); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
}

func TestNodeRoles(t *testing.T) {
	if RoleLeader != "leader" {
		t.Fatalf("RoleLeader = %q", RoleLeader)
	}
	if RoleFollower != "follower" {
		t.Fatalf("RoleFollower = %q", RoleFollower)
	}
	if RoleCandidate != "candidate" {
		t.Fatalf("RoleCandidate = %q", RoleCandidate)
	}
}

func TestNodeStatuses(t *testing.T) {
	if StatusHealthy != "healthy" {
		t.Fatalf("StatusHealthy = %q", StatusHealthy)
	}
	if StatusDegraded != "degraded" {
		t.Fatalf("StatusDegraded = %q", StatusDegraded)
	}
	if StatusOffline != "offline" {
		t.Fatalf("StatusOffline = %q", StatusOffline)
	}
}

func TestClusterMuxRoutes(t *testing.T) {
	m, _ := NewManager(&ClusterConfig{NodeID: "test", BindAddr: "127.0.0.1:0"})
	mux := m.clusterMux()

	routes := []struct {
		method string
		path   string
	}{
		{"POST", "/cluster/heartbeat"},
		{"POST", "/cluster/vote-request"},
		{"POST", "/cluster/join"},
		{"POST", "/cluster/leave"},
		{"POST", "/cluster/sync"},
		{"GET", "/cluster/status"},
	}

	for _, rt := range routes {
		req := httptest.NewRequest(rt.method, rt.path, nil)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		// Any non-404/405 means the route is registered.
		if rr.Code == http.StatusNotFound || rr.Code == http.StatusMethodNotAllowed {
			t.Errorf("route %s %s returned %d", rt.method, rt.path, rr.Code)
		}
	}
}

func TestNodesReturnsSnapshots(t *testing.T) {
	m := startManager(t, testConfig("node-1", "Node 1", "127.0.0.1:0"))
	nodes := m.Nodes()
	if len(nodes) != 1 {
		t.Fatalf("len(Nodes()) = %d, want 1", len(nodes))
	}
	// Mutating the returned node should not affect the manager.
	nodes[0].Name = "mutated"
	if m.Self().Name != "Node 1" {
		t.Fatal("Nodes() returned a reference, not a copy")
	}
}
