package api

import (
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/cluster"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/models"
)

var startTime = time.Now()

// handleSystemHealth returns the control plane health status.
func (a *API) handleSystemHealth(w http.ResponseWriter, r *http.Request) {
	// Also check data plane health
	dpStatus := "unknown"
	if health, err := a.dp.GetHealth(); err == nil {
		dpStatus = health.Status
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"status":         "healthy",
			"data_plane":     dpStatus,
			"uptime_seconds": int64(time.Since(startTime).Seconds()),
			"timestamp":      time.Now().UTC(),
		},
	})
}

// handleSystemInfo returns system information.
func (a *API) handleSystemInfo(w http.ResponseWriter, r *http.Request) {
	hostname, _ := os.Hostname()

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"version":        "2.0.0",
			"go_version":     runtime.Version(),
			"os":             runtime.GOOS,
			"arch":           runtime.GOARCH,
			"hostname":       hostname,
			"num_goroutines": runtime.NumGoroutine(),
			"num_cpus":       runtime.NumCPU(),
			"memory_alloc":   memStats.Alloc,
			"memory_sys":     memStats.Sys,
			"uptime_seconds": int64(time.Since(startTime).Seconds()),
			"started_at":     startTime.UTC(),
		},
	})
}

// handleSystemMetrics proxies metrics from the data plane.
func (a *API) handleSystemMetrics(w http.ResponseWriter, r *http.Request) {
	metrics, err := a.dp.GetMetrics()
	if err != nil {
		writeError(w, http.StatusBadGateway, "failed to fetch metrics: "+err.Error())
		return
	}

	// Return raw metrics (e.g., Prometheus format) as text
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(metrics))
}

func (a *API) systemUpgradeStatusPayload(state *models.DrainStatus) map[string]interface{} {
	activeSessions := 0
	draining := false
	status := "healthy"
	if state != nil {
		activeSessions = state.ActiveSessions
		draining = state.Draining
		if state.Status != "" {
			status = state.Status
		}
	}

	clusterEnabled := a.cluster != nil
	clusterRole := ""
	clusterLeader := ""
	otherHealthyNodes := 0
	topology := clusterTopologyPayload{
		NodeCountsByRegion:        map[string]int{},
		HealthyNodeCountsByRegion: map[string]int{},
		NodeCountsByZone:          map[string]int{},
		HealthyNodeCountsByZone:   map[string]int{},
		Regions:                   []string{},
		HealthyRegions:            []string{},
		Zones:                     []string{},
		HealthyZones:              []string{},
	}
	if a.cluster != nil {
		self := a.cluster.Self()
		nodes := a.cluster.Nodes()
		clusterRole = string(self.Role)
		if leader := a.cluster.Leader(); leader != nil {
			clusterLeader = leader.ID
		}
		for _, node := range nodes {
			if node.ID == self.ID || node.Status == cluster.StatusOffline {
				continue
			}
			otherHealthyNodes++
		}
		topology = buildClusterTopology(self, nodes)
	}

	readyForRestart := draining && activeSessions == 0 &&
		(!clusterEnabled || clusterRole != string(cluster.RoleLeader) || otherHealthyNodes > 0) &&
		(!clusterEnabled || (!topology.LastHealthyInZone && !topology.LastHealthyInRegion))

	return map[string]interface{}{
		"status":            status,
		"draining":          draining,
		"active_sessions":   activeSessions,
		"ready_for_restart": readyForRestart,
		"cluster": map[string]interface{}{
			"enabled":             clusterEnabled,
			"role":                clusterRole,
			"leader":              clusterLeader,
			"other_healthy_nodes": otherHealthyNodes,
			"topology":            topology,
		},
		"timestamp": time.Now().UTC(),
	}
}

func (a *API) handleSystemUpgradeStatus(w http.ResponseWriter, r *http.Request) {
	state, err := a.dp.GetDrainStatus()
	if err != nil {
		writeError(w, http.StatusBadGateway, "failed to fetch upgrade status: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    a.systemUpgradeStatusPayload(state),
	})
}

func (a *API) handleSystemUpgrade(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Draining bool `json:"draining"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if req.Draining && a.cluster != nil {
		self := a.cluster.Self()
		topology := buildClusterTopology(self, a.cluster.Nodes())
		if self.Role == cluster.RoleLeader {
			otherHealthyNodes := 0
			for _, node := range a.cluster.Nodes() {
				if node.ID == self.ID || node.Status == cluster.StatusOffline {
					continue
				}
				otherHealthyNodes++
			}
			if otherHealthyNodes == 0 {
				writeError(w, http.StatusConflict, "cannot drain the last healthy cluster leader")
				return
			}
		}
		if topology.LastHealthyInZone {
			writeError(w, http.StatusConflict, "cannot drain the last healthy node in its availability zone")
			return
		}
		if topology.LastHealthyInRegion {
			writeError(w, http.StatusConflict, "cannot drain the last healthy node in its region")
			return
		}
	}

	state, err := a.dp.SetDrainMode(req.Draining)
	if err != nil {
		writeError(w, http.StatusBadGateway, "failed to update drain mode: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    a.systemUpgradeStatusPayload(state),
	})
}
