package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/models"
)

// serverStore provides in-memory server management backed by a JSON file.
type serverStore struct {
	mu      sync.RWMutex
	servers map[string]models.Server
	path    string
}

func newServerStore(path string) *serverStore {
	ss := &serverStore{
		servers: make(map[string]models.Server),
		path:    path,
	}
	ss.load()
	return ss
}

func (ss *serverStore) load() {
	data, err := os.ReadFile(ss.path)
	if err != nil {
		return
	}
	var servers []models.Server
	if err := json.Unmarshal(data, &servers); err != nil {
		return
	}
	ss.mu.Lock()
	defer ss.mu.Unlock()
	for _, s := range servers {
		ss.servers[s.ID] = s
	}
}

func (ss *serverStore) save() error {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	servers := make([]models.Server, 0, len(ss.servers))
	for _, s := range ss.servers {
		servers = append(servers, s)
	}
	data, err := json.MarshalIndent(servers, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(ss.path, data, 0644)
}

func (ss *serverStore) list() []models.Server {
	ss.mu.RLock()
	defer ss.mu.RUnlock()

	servers := make([]models.Server, 0, len(ss.servers))
	for _, srv := range ss.servers {
		servers = append(servers, srv)
	}
	return servers
}

func serverEndpointKey(host string, port int) string {
	return strings.ToLower(host) + ":" + strconv.Itoa(port)
}

func mergeServerState(configured, runtime models.Server) models.Server {
	merged := configured

	if merged.ID == "" {
		merged.ID = runtime.ID
	}
	if merged.Name == "" {
		merged.Name = runtime.Name
	}
	if merged.Host == "" {
		merged.Host = runtime.Host
	}
	if merged.Port == 0 {
		merged.Port = runtime.Port
	}
	if merged.Group == "" {
		merged.Group = runtime.Group
	}
	if merged.Status == "" {
		merged.Status = runtime.Status
	}
	if merged.Weight == 0 {
		merged.Weight = runtime.Weight
	}
	if merged.MaxSessions == 0 {
		merged.MaxSessions = runtime.MaxSessions
	}
	if merged.Tags == nil && runtime.Tags != nil {
		merged.Tags = runtime.Tags
	}

	if runtime.Status != "" {
		merged.Status = runtime.Status
	}
	merged.Healthy = runtime.Healthy
	if runtime.Maintenance {
		merged.Maintenance = true
	}
	if runtime.Sessions > 0 {
		merged.Sessions = runtime.Sessions
	}
	if !runtime.CheckedAt.IsZero() {
		merged.CheckedAt = runtime.CheckedAt
	}

	return merged
}

func mergeManagedServers(configured, runtime []models.Server) []models.Server {
	merged := make([]models.Server, 0, len(configured)+len(runtime))
	byID := make(map[string]int)
	byEndpoint := make(map[string]int)

	add := func(srv models.Server) {
		idx := len(merged)
		merged = append(merged, srv)
		if srv.ID != "" {
			byID[srv.ID] = idx
		}
		if srv.Host != "" && srv.Port > 0 {
			byEndpoint[serverEndpointKey(srv.Host, srv.Port)] = idx
		}
	}

	for _, srv := range configured {
		add(srv)
	}

	for _, srv := range runtime {
		if idx, ok := byID[srv.ID]; ok {
			merged[idx] = mergeServerState(merged[idx], srv)
			continue
		}

		key := serverEndpointKey(srv.Host, srv.Port)
		if idx, ok := byEndpoint[key]; ok {
			merged[idx] = mergeServerState(merged[idx], srv)
			if srv.ID != "" {
				byID[srv.ID] = idx
			}
			continue
		}

		add(srv)
	}

	sort.SliceStable(merged, func(i, j int) bool {
		left := merged[i].Name
		if left == "" {
			left = merged[i].Host
		}
		right := merged[j].Name
		if right == "" {
			right = merged[j].Host
		}
		return left < right
	})

	return merged
}

func (a *API) listManagedServers() ([]models.Server, error) {
	runtimeServers, err := a.dp.ListUpstreams()
	if err != nil {
		return nil, err
	}
	return mergeManagedServers(a.servers.list(), runtimeServers), nil
}

// handleListServers lists upstream servers from the data plane.
func (a *API) handleListServers(w http.ResponseWriter, r *http.Request) {
	servers, err := a.listManagedServers()
	if err != nil {
		writeError(w, http.StatusBadGateway, "failed to fetch servers: "+err.Error())
		return
	}

	page, perPage := parsePagination(r)
	total := len(servers)
	start, end := paginate(total, page, perPage)

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    servers[start:end],
		Total:   total,
		Page:    page,
		PerPage: perPage,
	})
}

// handleAddServer adds a new upstream server.
func (a *API) handleAddServer(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string            `json:"name"`
		Host        string            `json:"host"`
		Port        int               `json:"port"`
		Group       string            `json:"group"`
		Weight      int               `json:"weight"`
		MaxSessions int               `json:"max_sessions"`
		Tags        map[string]string `json:"tags"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if req.Host == "" || req.Port == 0 {
		writeError(w, http.StatusBadRequest, "host and port are required")
		return
	}

	if req.Weight <= 0 {
		req.Weight = 1
	}

	srv := models.Server{
		ID:          fmt.Sprintf("srv-%d", time.Now().UnixNano()),
		Name:        req.Name,
		Host:        req.Host,
		Port:        req.Port,
		Group:       req.Group,
		Status:      "online",
		Healthy:     true,
		Weight:      req.Weight,
		MaxSessions: req.MaxSessions,
		Tags:        req.Tags,
		CheckedAt:   time.Now().UTC(),
	}

	a.servers.mu.Lock()
	a.servers.servers[srv.ID] = srv
	a.servers.mu.Unlock()

	if err := a.servers.save(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save server: "+err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, APIResponse{
		Success: true,
		Data:    srv,
	})
}

// handleGetServer returns a single server by ID.
func (a *API) handleGetServer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing server id")
		return
	}

	// Try local store first, then data plane
	a.servers.mu.RLock()
	srv, ok := a.servers.servers[id]
	a.servers.mu.RUnlock()

	if ok {
		writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: srv})
		return
	}

	servers, err := a.listManagedServers()
	if err != nil {
		writeError(w, http.StatusBadGateway, "failed to fetch servers: "+err.Error())
		return
	}

	for _, s := range servers {
		if s.ID == id {
			writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: s})
			return
		}
	}

	writeError(w, http.StatusNotFound, "server not found")
}

// handleUpdateServer updates server configuration.
func (a *API) handleUpdateServer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing server id")
		return
	}

	var req struct {
		Name        *string           `json:"name"`
		Host        *string           `json:"host"`
		Port        *int              `json:"port"`
		Group       *string           `json:"group"`
		Weight      *int              `json:"weight"`
		MaxSessions *int              `json:"max_sessions"`
		Tags        map[string]string `json:"tags"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	a.servers.mu.Lock()
	srv, ok := a.servers.servers[id]
	if !ok {
		a.servers.mu.Unlock()
		writeError(w, http.StatusNotFound, "server not found")
		return
	}

	if req.Name != nil {
		srv.Name = *req.Name
	}
	if req.Host != nil {
		srv.Host = *req.Host
	}
	if req.Port != nil {
		srv.Port = *req.Port
	}
	if req.Group != nil {
		srv.Group = *req.Group
	}
	if req.Weight != nil {
		srv.Weight = *req.Weight
	}
	if req.MaxSessions != nil {
		srv.MaxSessions = *req.MaxSessions
	}
	if req.Tags != nil {
		srv.Tags = req.Tags
	}
	a.servers.servers[id] = srv
	a.servers.mu.Unlock()

	if err := a.servers.save(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save server: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    srv,
	})
}

// handleDeleteServer removes an upstream server.
func (a *API) handleDeleteServer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing server id")
		return
	}

	a.servers.mu.Lock()
	if _, ok := a.servers.servers[id]; !ok {
		a.servers.mu.Unlock()
		writeError(w, http.StatusNotFound, "server not found")
		return
	}
	delete(a.servers.servers, id)
	a.servers.mu.Unlock()

	if err := a.servers.save(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save servers: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    map[string]string{"message": "server " + id + " removed"},
	})
}

// handleToggleMaintenance toggles maintenance mode for a server.
func (a *API) handleToggleMaintenance(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing server id")
		return
	}

	var req struct {
		Maintenance bool `json:"maintenance"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	a.servers.mu.Lock()
	srv, ok := a.servers.servers[id]
	if !ok {
		a.servers.mu.Unlock()
		writeError(w, http.StatusNotFound, "server not found")
		return
	}

	srv.Maintenance = req.Maintenance
	if req.Maintenance {
		srv.Status = "draining"
	} else {
		srv.Status = "online"
	}
	a.servers.servers[id] = srv
	a.servers.mu.Unlock()

	if err := a.servers.save(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save server: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    srv,
	})
}

// handleServersHealth returns a health summary for all servers.
func (a *API) handleServersHealth(w http.ResponseWriter, r *http.Request) {
	servers, err := a.listManagedServers()
	if err != nil {
		writeError(w, http.StatusBadGateway, "failed to fetch servers: "+err.Error())
		return
	}

	total := len(servers)
	healthy := 0
	unhealthy := 0
	maintenance := 0
	for _, s := range servers {
		switch {
		case s.Maintenance:
			maintenance++
		case s.Healthy:
			healthy++
		default:
			unhealthy++
		}
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data: map[string]int{
			"total":       total,
			"healthy":     healthy,
			"unhealthy":   unhealthy,
			"maintenance": maintenance,
		},
	})
}
