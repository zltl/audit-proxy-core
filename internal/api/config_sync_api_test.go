package api

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/cluster"
)

func testAPIClusterConfig(id, bind string) *cluster.ClusterConfig {
	return &cluster.ClusterConfig{
		NodeID:            id,
		NodeName:          id,
		BindAddr:          bind,
		HeartbeatInterval: 100 * time.Millisecond,
		ElectionTimeout:   300 * time.Millisecond,
		SyncInterval:      200 * time.Millisecond,
	}
}

func startAPIClusterManager(t *testing.T, cfg *cluster.ClusterConfig) *cluster.Manager {
	t.Helper()
	mgr, err := cluster.NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = mgr.Stop()
	})
	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	return mgr
}

func TestConfigMutationRejectedOnFollowerWhenClusterEnabled(t *testing.T) {
	leader := startAPIClusterManager(t, testAPIClusterConfig("node-1", "127.0.0.1:0"))
	followerCfg := testAPIClusterConfig("node-2", "127.0.0.1:0")
	followerCfg.Seeds = []string{leader.Self().Address}
	follower := startAPIClusterManager(t, followerCfg)

	time.Sleep(500 * time.Millisecond)

	api, mux, _ := setupTestAPI(t)
	api.SetCluster(follower)

	rr := doRequest(mux, http.MethodPut, "/api/v2/config", map[string]interface{}{
		"listen_port": 3333,
	})
	if rr.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "cluster leader") {
		t.Fatalf("expected follower write rejection message, got %s", rr.Body.String())
	}
}

func TestConfigSyncStatusEndpointReturnsClusterStatus(t *testing.T) {
	leader := startAPIClusterManager(t, testAPIClusterConfig("node-1", "127.0.0.1:0"))

	if err := leader.PublishConfigSnapshot([]byte(`{"listen_port":3333}`), "sync-v1", "chg-1", "admin"); err != nil {
		t.Fatalf("PublishConfigSnapshot: %v", err)
	}

	api, mux, _ := setupTestAPI(t)
	api.SetCluster(leader)

	rr := doRequest(mux, http.MethodGet, "/api/v2/config/sync-status", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	resp := parseResponse(t, rr)
	data := resp.Data.(map[string]interface{})
	if data["version"] != "sync-v1" {
		t.Fatalf("expected sync version sync-v1, got %#v", data["version"])
	}
	nodes := data["nodes"].([]interface{})
	if len(nodes) != 1 {
		t.Fatalf("expected 1 node status, got %d", len(nodes))
	}
	node := nodes[0].(map[string]interface{})
	if node["status"] != "applied" {
		t.Fatalf("expected applied node status, got %#v", node["status"])
	}
}

func TestApplyClusterConfigSnapshotPersistsCentralConfigStore(t *testing.T) {
	leader := startAPIClusterManager(t, testAPIClusterConfig("node-1", "127.0.0.1:0"))
	followerCfg := testAPIClusterConfig("node-2", "127.0.0.1:0")
	followerCfg.Seeds = []string{leader.Self().Address}
	follower := startAPIClusterManager(t, followerCfg)

	api, _, _ := setupTestAPI(t)
	api.SetCluster(follower)
	follower.SetConfigSyncApplier(api.ApplyClusterConfigSnapshot)

	time.Sleep(500 * time.Millisecond)
	if err := leader.PublishConfigSnapshot([]byte(`{"listen_port":5555}`), "sync-v-store", "chg-store", "admin"); err != nil {
		t.Fatalf("PublishConfigSnapshot: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		entry := api.configStore.Get()
		if entry != nil && entry.Version == "sync-v-store" {
			if entry.Requester != "admin" {
				t.Fatalf("stored requester = %q, want admin", entry.Requester)
			}
			if string(entry.Snapshot) != `{"listen_port":5555}` {
				t.Fatalf("stored snapshot = %s, want synced payload", string(entry.Snapshot))
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}

	t.Fatal("timed out waiting for follower config store to persist synced snapshot")
}
