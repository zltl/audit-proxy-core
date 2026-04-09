package api

import (
	"net/http"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/cluster"
)

// SetCluster attaches a cluster manager to the API for cluster endpoints.
func (a *API) SetCluster(cm *cluster.Manager) {
	a.cluster = cm
}

// RegisterClusterRoutes registers the public cluster API routes on the given mux.
func (a *API) RegisterClusterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v2/cluster/status", a.handleClusterStatus)
	mux.HandleFunc("GET /api/v2/cluster/nodes", a.handleClusterNodes)
	mux.HandleFunc("POST /api/v2/cluster/join", a.handleClusterJoin)
	mux.HandleFunc("POST /api/v2/cluster/leave", a.handleClusterLeave)
	mux.HandleFunc("GET /api/v2/cluster/leader", a.handleClusterLeader)
}

// handleConfigSyncStatus returns the current cluster-wide config sync view.
func (a *API) handleConfigSyncStatus(w http.ResponseWriter, r *http.Request) {
	if !a.requireCluster(w) {
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    a.cluster.GetConfigSyncStatus(),
	})
}

func (a *API) requireCluster(w http.ResponseWriter) bool {
	if a.cluster == nil {
		writeError(w, http.StatusServiceUnavailable, "clustering is not enabled")
		return false
	}
	return true
}

// handleClusterStatus returns an overview of the cluster: nodes, leader, health.
func (a *API) handleClusterStatus(w http.ResponseWriter, r *http.Request) {
	if !a.requireCluster(w) {
		return
	}

	cm := a.cluster
	self := cm.Self()
	leader := cm.Leader()
	nodes := cm.Nodes()
	topology := buildClusterTopology(self, nodes)

	leaderID := ""
	if leader != nil {
		leaderID = leader.ID
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"node_id":    self.ID,
			"role":       string(self.Role),
			"status":     string(self.Status),
			"leader":     leaderID,
			"term":       cm.Term(),
			"node_count": cm.NodeCount(),
			"nodes":      nodes,
			"topology":   topology,
		},
	})
}

// handleClusterNodes returns all known cluster members.
func (a *API) handleClusterNodes(w http.ResponseWriter, r *http.Request) {
	if !a.requireCluster(w) {
		return
	}

	nodes := a.cluster.Nodes()
	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    nodes,
		Total:   len(nodes),
	})
}

// handleClusterJoin triggers joining the cluster using the provided seeds.
func (a *API) handleClusterJoin(w http.ResponseWriter, r *http.Request) {
	if !a.requireCluster(w) {
		return
	}

	var req struct {
		Seeds []string `json:"seeds"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(req.Seeds) == 0 {
		writeError(w, http.StatusBadRequest, "at least one seed address is required")
		return
	}

	if err := a.cluster.Join(req.Seeds); err != nil {
		writeError(w, http.StatusBadGateway, "failed to join cluster: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    map[string]string{"message": "joined cluster"},
	})
}

// handleClusterLeave triggers a graceful leave from the cluster.
func (a *API) handleClusterLeave(w http.ResponseWriter, r *http.Request) {
	if !a.requireCluster(w) {
		return
	}

	if err := a.cluster.Leave(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to leave cluster: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    map[string]string{"message": "left cluster"},
	})
}

// handleClusterLeader returns the current cluster leader.
func (a *API) handleClusterLeader(w http.ResponseWriter, r *http.Request) {
	if !a.requireCluster(w) {
		return
	}

	leader := a.cluster.Leader()
	if leader == nil {
		writeJSON(w, http.StatusOK, APIResponse{
			Success: true,
			Data:    map[string]interface{}{"leader": nil, "message": "no leader elected"},
		})
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    leader,
	})
}
