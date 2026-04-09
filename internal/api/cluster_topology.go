package api

import (
	"sort"
	"strings"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/cluster"
)

type clusterTopologyPayload struct {
	SelfRegion                     string         `json:"self_region"`
	SelfZone                       string         `json:"self_zone"`
	Regions                        []string       `json:"regions"`
	HealthyRegions                 []string       `json:"healthy_regions"`
	Zones                          []string       `json:"zones"`
	HealthyZones                   []string       `json:"healthy_zones"`
	NodeCountsByRegion             map[string]int `json:"node_counts_by_region"`
	HealthyNodeCountsByRegion      map[string]int `json:"healthy_node_counts_by_region"`
	NodeCountsByZone               map[string]int `json:"node_counts_by_zone"`
	HealthyNodeCountsByZone        map[string]int `json:"healthy_node_counts_by_zone"`
	CrossRegionRedundant           bool           `json:"cross_region_redundant"`
	CrossZoneRedundant             bool           `json:"cross_zone_redundant"`
	OtherHealthyNodesInRegion      int            `json:"other_healthy_nodes_in_region"`
	OtherHealthyNodesInOtherRegions int           `json:"other_healthy_nodes_in_other_regions"`
	OtherHealthyNodesInZone        int            `json:"other_healthy_nodes_in_zone"`
	OtherHealthyNodesInOtherZones  int            `json:"other_healthy_nodes_in_other_zones"`
	LastHealthyInRegion            bool           `json:"last_healthy_in_region"`
	LastHealthyInZone              bool           `json:"last_healthy_in_zone"`
}

func buildClusterTopology(self cluster.Node, nodes []*cluster.Node) clusterTopologyPayload {
	topology := clusterTopologyPayload{
		SelfRegion:                nodeRegion(&self),
		SelfZone:                  nodeZone(&self),
		NodeCountsByRegion:        make(map[string]int),
		HealthyNodeCountsByRegion: make(map[string]int),
		NodeCountsByZone:          make(map[string]int),
		HealthyNodeCountsByZone:   make(map[string]int),
		Regions:                   []string{},
		HealthyRegions:            []string{},
		Zones:                     []string{},
		HealthyZones:              []string{},
	}

	regions := make(map[string]struct{})
	healthyRegions := make(map[string]struct{})
	zones := make(map[string]struct{})
	healthyZones := make(map[string]struct{})

	for _, node := range nodes {
		if node == nil {
			continue
		}
		region := nodeRegion(node)
		zone := nodeZone(node)
		healthy := node.Status != cluster.StatusOffline

		if region != "" {
			regions[region] = struct{}{}
			topology.NodeCountsByRegion[region]++
			if healthy {
				healthyRegions[region] = struct{}{}
				topology.HealthyNodeCountsByRegion[region]++
			}
		}
		if zone != "" {
			zones[zone] = struct{}{}
			topology.NodeCountsByZone[zone]++
			if healthy {
				healthyZones[zone] = struct{}{}
				topology.HealthyNodeCountsByZone[zone]++
			}
		}

		if !healthy || node.ID == self.ID {
			continue
		}
		if topology.SelfRegion != "" {
			if region == topology.SelfRegion {
				topology.OtherHealthyNodesInRegion++
			} else if region != "" {
				topology.OtherHealthyNodesInOtherRegions++
			}
		}
		if topology.SelfZone != "" {
			if zone == topology.SelfZone {
				topology.OtherHealthyNodesInZone++
			} else if zone != "" {
				topology.OtherHealthyNodesInOtherZones++
			}
		}
	}

	topology.Regions = sortedStringKeys(regions)
	topology.HealthyRegions = sortedStringKeys(healthyRegions)
	topology.Zones = sortedStringKeys(zones)
	topology.HealthyZones = sortedStringKeys(healthyZones)
	topology.CrossRegionRedundant = len(topology.HealthyRegions) > 1
	topology.CrossZoneRedundant = len(topology.HealthyZones) > 1
	if topology.SelfRegion != "" && topology.CrossRegionRedundant &&
		topology.HealthyNodeCountsByRegion[topology.SelfRegion] == 1 {
		topology.LastHealthyInRegion = true
	}
	if topology.SelfZone != "" && topology.CrossZoneRedundant &&
		topology.HealthyNodeCountsByZone[topology.SelfZone] == 1 {
		topology.LastHealthyInZone = true
	}

	return topology
}

func nodeRegion(node *cluster.Node) string {
	if node == nil || node.Metadata == nil {
		return ""
	}
	return strings.TrimSpace(node.Metadata["region"])
}

func nodeZone(node *cluster.Node) string {
	if node == nil || node.Metadata == nil {
		return ""
	}
	zone := strings.TrimSpace(node.Metadata["zone"])
	if zone == "" {
		return ""
	}
	region := nodeRegion(node)
	if region == "" {
		return zone
	}
	return region + "/" + zone
}

func sortedStringKeys(values map[string]struct{}) []string {
	if len(values) == 0 {
		return []string{}
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
