package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
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

// handleListServers lists upstream servers from the data plane.
func (a *API) handleListServers(w http.ResponseWriter, r *http.Request) {
	servers, err := a.dp.ListUpstreams()
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

	servers, err := a.dp.ListUpstreams()
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
		Name        *string            `json:"name"`
		Host        *string            `json:"host"`
		Port        *int               `json:"port"`
		Group       *string            `json:"group"`
		Weight      *int               `json:"weight"`
		MaxSessions *int               `json:"max_sessions"`
		Tags        map[string]string  `json:"tags"`
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
	servers, err := a.dp.ListUpstreams()
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
