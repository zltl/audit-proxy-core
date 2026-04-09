package api

import (
	"testing"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/cluster"
)

func TestBuildClusterTopologySummarizesFailureDomains(t *testing.T) {
	self := cluster.Node{
		ID:       "node-1",
		Status:   cluster.StatusHealthy,
		Metadata: map[string]string{"region": "us-east-1", "zone": "us-east-1a"},
	}
	nodes := []*cluster.Node{
		&self,
		{
			ID:       "node-2",
			Status:   cluster.StatusHealthy,
			Metadata: map[string]string{"region": "us-east-1", "zone": "us-east-1b"},
		},
		{
			ID:       "node-3",
			Status:   cluster.StatusHealthy,
			Metadata: map[string]string{"region": "us-west-2", "zone": "us-west-2a"},
		},
		{
			ID:       "node-4",
			Status:   cluster.StatusOffline,
			Metadata: map[string]string{"region": "us-west-2", "zone": "us-west-2b"},
		},
	}

	topology := buildClusterTopology(self, nodes)
	if !topology.CrossRegionRedundant {
		t.Fatal("expected cross-region redundancy")
	}
	if !topology.CrossZoneRedundant {
		t.Fatal("expected cross-zone redundancy")
	}
	if topology.OtherHealthyNodesInRegion != 1 {
		t.Fatalf("OtherHealthyNodesInRegion = %d, want 1", topology.OtherHealthyNodesInRegion)
	}
	if topology.OtherHealthyNodesInOtherRegions != 1 {
		t.Fatalf("OtherHealthyNodesInOtherRegions = %d, want 1", topology.OtherHealthyNodesInOtherRegions)
	}
	if topology.OtherHealthyNodesInZone != 0 {
		t.Fatalf("OtherHealthyNodesInZone = %d, want 0", topology.OtherHealthyNodesInZone)
	}
	if topology.OtherHealthyNodesInOtherZones != 2 {
		t.Fatalf("OtherHealthyNodesInOtherZones = %d, want 2", topology.OtherHealthyNodesInOtherZones)
	}
	if !topology.LastHealthyInZone {
		t.Fatal("expected self to be the last healthy node in its zone")
	}
	if topology.LastHealthyInRegion {
		t.Fatal("expected another healthy node in the same region")
	}
	if got := topology.HealthyNodeCountsByRegion["us-east-1"]; got != 2 {
		t.Fatalf("HealthyNodeCountsByRegion[us-east-1] = %d, want 2", got)
	}
	if got := topology.HealthyNodeCountsByZone["us-east-1/us-east-1a"]; got != 1 {
		t.Fatalf("HealthyNodeCountsByZone[self] = %d, want 1", got)
	}
}
