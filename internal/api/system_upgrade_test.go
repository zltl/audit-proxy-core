package api

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/models"
)

func TestSystemUpgradeStatusStandaloneReadyForRestart(t *testing.T) {
	_, mux, dp := setupTestAPI(t)
	dp.drain = &models.DrainStatus{Status: "draining", Draining: true, ActiveSessions: 0}

	rr := doRequest(mux, http.MethodGet, "/api/v2/system/upgrade", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	resp := parseResponse(t, rr)
	data := resp.Data.(map[string]interface{})
	if data["draining"] != true {
		t.Fatalf("expected draining=true, got %#v", data["draining"])
	}
	if data["ready_for_restart"] != true {
		t.Fatalf("expected ready_for_restart=true, got %#v", data["ready_for_restart"])
	}

	clusterData := data["cluster"].(map[string]interface{})
	if clusterData["enabled"] != false {
		t.Fatalf("expected standalone cluster disabled payload, got %#v", clusterData)
	}
}

func TestSystemUpgradeStatusLeaderRequiresHealthyPeerBeforeRestart(t *testing.T) {
	leader := startAPIClusterManager(t, testAPIClusterConfig("node-1", "127.0.0.1:0"))

	api, mux, dp := setupTestAPI(t)
	api.SetCluster(leader)
	dp.drain = &models.DrainStatus{Status: "draining", Draining: true, ActiveSessions: 0}

	rr := doRequest(mux, http.MethodGet, "/api/v2/system/upgrade", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	resp := parseResponse(t, rr)
	data := resp.Data.(map[string]interface{})
	if data["ready_for_restart"] != false {
		t.Fatalf("expected ready_for_restart=false for single-node leader, got %#v", data["ready_for_restart"])
	}

	clusterData := data["cluster"].(map[string]interface{})
	if clusterData["role"] != "leader" {
		t.Fatalf("expected leader role, got %#v", clusterData["role"])
	}
	if clusterData["other_healthy_nodes"].(float64) != 0 {
		t.Fatalf("expected zero healthy peers, got %#v", clusterData["other_healthy_nodes"])
	}
}

func TestSystemUpgradeToggleEnablesDrainMode(t *testing.T) {
	_, mux, dp := setupTestAPI(t)

	rr := doRequest(mux, http.MethodPut, "/api/v2/system/upgrade", map[string]bool{
		"draining": true,
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	resp := parseResponse(t, rr)
	data := resp.Data.(map[string]interface{})
	if data["status"] != "draining" || data["draining"] != true {
		t.Fatalf("unexpected drain payload: %#v", data)
	}
	if dp.drain == nil || !dp.drain.Draining {
		t.Fatalf("expected mock dataplane drain mode to be enabled, got %+v", dp.drain)
	}
}

func TestSystemUpgradeRejectsDrainingLastHealthyLeader(t *testing.T) {
	leader := startAPIClusterManager(t, testAPIClusterConfig("node-1", "127.0.0.1:0"))

	api, mux, _ := setupTestAPI(t)
	api.SetCluster(leader)

	rr := doRequest(mux, http.MethodPut, "/api/v2/system/upgrade", map[string]bool{
		"draining": true,
	})
	if rr.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "last healthy cluster leader") {
		t.Fatalf("expected last-leader rejection message, got %s", rr.Body.String())
	}
}

func TestSystemUpgradeStatusNotReadyWhenNodeIsLastHealthyInZone(t *testing.T) {
	leaderCfg := testAPIClusterConfig("node-1", "127.0.0.1:0")
	leaderCfg.Region = "us-east-1"
	leaderCfg.Zone = "us-east-1a"
	leader := startAPIClusterManager(t, leaderCfg)

	followerCfg := testAPIClusterConfig("node-2", "127.0.0.1:0")
	followerCfg.Region = "us-east-1"
	followerCfg.Zone = "us-east-1b"
	followerCfg.Seeds = []string{leader.Self().Address}
	startAPIClusterManager(t, followerCfg)

	time.Sleep(500 * time.Millisecond)

	api, mux, dp := setupTestAPI(t)
	api.SetCluster(leader)
	dp.drain = &models.DrainStatus{Status: "draining", Draining: true, ActiveSessions: 0}

	rr := doRequest(mux, http.MethodGet, "/api/v2/system/upgrade", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	resp := parseResponse(t, rr)
	data := resp.Data.(map[string]interface{})
	if data["ready_for_restart"] != false {
		t.Fatalf("expected ready_for_restart=false when last healthy in zone, got %#v", data["ready_for_restart"])
	}
	clusterData := data["cluster"].(map[string]interface{})
	topology := clusterData["topology"].(map[string]interface{})
	if topology["last_healthy_in_zone"] != true {
		t.Fatalf("expected last_healthy_in_zone=true, got %#v", topology["last_healthy_in_zone"])
	}
}

func TestSystemUpgradeRejectsDrainingLastHealthyRegionNode(t *testing.T) {
	leaderCfg := testAPIClusterConfig("node-1", "127.0.0.1:0")
	leaderCfg.Region = "us-east-1"
	leader := startAPIClusterManager(t, leaderCfg)

	followerCfg := testAPIClusterConfig("node-2", "127.0.0.1:0")
	followerCfg.Region = "us-west-2"
	followerCfg.Seeds = []string{leader.Self().Address}
	startAPIClusterManager(t, followerCfg)

	time.Sleep(500 * time.Millisecond)

	api, mux, _ := setupTestAPI(t)
	api.SetCluster(leader)

	rr := doRequest(mux, http.MethodPut, "/api/v2/system/upgrade", map[string]bool{
		"draining": true,
	})
	if rr.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "last healthy node in its region") {
		t.Fatalf("expected region failure-domain rejection message, got %s", rr.Body.String())
	}
}
