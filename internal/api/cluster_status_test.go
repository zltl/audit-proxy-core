package api

import (
	"net/http"
	"testing"
	"time"
)

func TestClusterStatusIncludesTopologySummary(t *testing.T) {
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

	api, mux, _ := setupTestAPI(t)
	api.SetCluster(leader)
	api.RegisterClusterRoutes(mux)

	rr := doRequest(mux, http.MethodGet, "/api/v2/cluster/status", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	resp := parseResponse(t, rr)
	data := resp.Data.(map[string]interface{})
	topology := data["topology"].(map[string]interface{})
	if topology["self_region"] != "us-east-1" {
		t.Fatalf("expected self_region=us-east-1, got %#v", topology["self_region"])
	}
	if topology["self_zone"] != "us-east-1/us-east-1a" {
		t.Fatalf("expected self_zone to include region-qualified zone, got %#v", topology["self_zone"])
	}
	if topology["cross_zone_redundant"] != true {
		t.Fatalf("expected cross_zone_redundant=true, got %#v", topology["cross_zone_redundant"])
	}
	if topology["cross_region_redundant"] != false {
		t.Fatalf("expected cross_region_redundant=false, got %#v", topology["cross_region_redundant"])
	}
}
