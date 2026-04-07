package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/discovery"
)

// discoveryState holds the runtime state for asset discovery endpoints.
type discoveryState struct {
	inventory  *discovery.Inventory
	scanConfig *discovery.ScanConfig
}

// initDiscovery lazily initialises the discovery subsystem.
func (a *API) initDiscovery() *discoveryState {
	if a.discovery != nil {
		return a.discovery
	}
	dataDir := a.config.DataDir
	if dataDir == "" {
		dataDir = "."
	}
	a.discovery = &discoveryState{
		inventory: discovery.NewInventory(dataDir + "/discovery"),
		scanConfig: &discovery.ScanConfig{
			Ports:       []int{22, 2222},
			Timeout:     5 * time.Second,
			Concurrency: 50,
			SSHBanner:   true,
		},
	}
	return a.discovery
}

// RegisterDiscoveryRoutes adds the /api/v2/discovery/* endpoints to mux.
func (a *API) RegisterDiscoveryRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v2/discovery/scan", a.handleDiscoveryScan)
	mux.HandleFunc("GET /api/v2/discovery/assets", a.handleListDiscoveryAssets)
	mux.HandleFunc("GET /api/v2/discovery/assets/{id}", a.handleGetDiscoveryAsset)
	mux.HandleFunc("PUT /api/v2/discovery/assets/{id}", a.handleUpdateDiscoveryAsset)
	mux.HandleFunc("DELETE /api/v2/discovery/assets/{id}", a.handleDeleteDiscoveryAsset)
	mux.HandleFunc("POST /api/v2/discovery/register", a.handleDiscoveryRegister)
	mux.HandleFunc("GET /api/v2/discovery/config", a.handleGetDiscoveryConfig)
	mux.HandleFunc("PUT /api/v2/discovery/config", a.handleUpdateDiscoveryConfig)
}

// handleDiscoveryScan triggers a network scan and returns results.
func (a *API) handleDiscoveryScan(w http.ResponseWriter, r *http.Request) {
	ds := a.initDiscovery()

	var req struct {
		Targets     []string `json:"targets"`
		Ports       []int    `json:"ports"`
		Timeout     string   `json:"timeout"`
		Concurrency int      `json:"concurrency"`
		SSHBanner   *bool    `json:"ssh_banner"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if len(req.Targets) == 0 {
		writeError(w, http.StatusBadRequest, "targets is required")
		return
	}

	cfg := *ds.scanConfig
	cfg.Targets = req.Targets
	if len(req.Ports) > 0 {
		cfg.Ports = req.Ports
	}
	if req.Timeout != "" {
		if d, err := time.ParseDuration(req.Timeout); err == nil {
			cfg.Timeout = d
		}
	}
	if req.Concurrency > 0 {
		cfg.Concurrency = req.Concurrency
	}
	if req.SSHBanner != nil {
		cfg.SSHBanner = *req.SSHBanner
	}

	scanner := discovery.NewScanner(&cfg)
	results, err := scanner.Scan(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "scan failed: "+err.Error())
		return
	}

	newCount := ds.inventory.AddFromScan(results)
	_ = ds.inventory.Save()

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"results":    results,
			"total":      len(results),
			"new_assets": newCount,
		},
	})
}

// handleListDiscoveryAssets returns discovered assets with optional filters.
func (a *API) handleListDiscoveryAssets(w http.ResponseWriter, r *http.Request) {
	ds := a.initDiscovery()

	q := r.URL.Query()
	filter := discovery.AssetFilter{
		Status: q.Get("status"),
		Host:   q.Get("host"),
		OS:     q.Get("os"),
		Tag:    q.Get("tag"),
	}

	assets := ds.inventory.List(filter)
	page, perPage := parsePagination(r)
	total := len(assets)
	start, end := paginate(total, page, perPage)

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    assets[start:end],
		Total:   total,
		Page:    page,
		PerPage: perPage,
	})
}

// handleGetDiscoveryAsset returns a single asset.
func (a *API) handleGetDiscoveryAsset(w http.ResponseWriter, r *http.Request) {
	ds := a.initDiscovery()
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing asset id")
		return
	}

	asset, err := ds.inventory.Get(id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    asset,
	})
}

// handleUpdateDiscoveryAsset updates mutable fields on an asset.
func (a *API) handleUpdateDiscoveryAsset(w http.ResponseWriter, r *http.Request) {
	ds := a.initDiscovery()
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing asset id")
		return
	}

	var update discovery.AssetUpdate
	if err := readJSON(r, &update); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := ds.inventory.Update(id, update); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	_ = ds.inventory.Save()

	asset, _ := ds.inventory.Get(id)
	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    asset,
	})
}

// handleDeleteDiscoveryAsset removes an asset.
func (a *API) handleDeleteDiscoveryAsset(w http.ResponseWriter, r *http.Request) {
	ds := a.initDiscovery()
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing asset id")
		return
	}

	if err := ds.inventory.Delete(id); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	_ = ds.inventory.Save()

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    map[string]string{"message": "asset " + id + " deleted"},
	})
}

// handleDiscoveryRegister registers discovered assets as upstream servers.
func (a *API) handleDiscoveryRegister(w http.ResponseWriter, r *http.Request) {
	ds := a.initDiscovery()

	var req struct {
		IDs []string `json:"ids"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	registered := 0
	if len(req.IDs) > 0 {
		for _, id := range req.IDs {
			status := "registered"
			if err := ds.inventory.Update(id, discovery.AssetUpdate{Status: &status}); err == nil {
				registered++
			}
		}
	} else {
		count, err := ds.inventory.AutoRegister(a.dp)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "register failed: "+err.Error())
			return
		}
		registered = count
	}
	_ = ds.inventory.Save()

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"registered": registered,
		},
	})
}

// handleGetDiscoveryConfig returns the current scan configuration.
func (a *API) handleGetDiscoveryConfig(w http.ResponseWriter, r *http.Request) {
	ds := a.initDiscovery()

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"ports":       ds.scanConfig.Ports,
			"timeout":     ds.scanConfig.Timeout.String(),
			"concurrency": ds.scanConfig.Concurrency,
			"ssh_banner":  ds.scanConfig.SSHBanner,
		},
	})
}

// handleUpdateDiscoveryConfig updates the default scan configuration.
func (a *API) handleUpdateDiscoveryConfig(w http.ResponseWriter, r *http.Request) {
	ds := a.initDiscovery()

	var req struct {
		Ports       []int  `json:"ports"`
		Timeout     string `json:"timeout"`
		Concurrency int    `json:"concurrency"`
		SSHBanner   *bool  `json:"ssh_banner"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if len(req.Ports) > 0 {
		ds.scanConfig.Ports = req.Ports
	}
	if req.Timeout != "" {
		if d, err := time.ParseDuration(req.Timeout); err == nil {
			ds.scanConfig.Timeout = d
		}
	}
	if req.Concurrency > 0 {
		ds.scanConfig.Concurrency = req.Concurrency
	}
	if req.SSHBanner != nil {
		ds.scanConfig.SSHBanner = *req.SSHBanner
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"ports":       ds.scanConfig.Ports,
			"timeout":     ds.scanConfig.Timeout.String(),
			"concurrency": ds.scanConfig.Concurrency,
			"ssh_banner":  ds.scanConfig.SSHBanner,
		},
	})
}

// --- helpers for discovery ID decoding ---

// decodeAssetID converts a URL-safe asset ID back to the "host:port" format.
// The HTTP router may deliver "{id}" as "10.0.0.1:22" directly when the path
// uses a wildcard.  This helper also supports the older underscore-separated
// form "10.0.0.1_22".
func decodeAssetID(raw string) string {
	if strings.Contains(raw, ":") {
		return raw
	}
	idx := strings.LastIndex(raw, "_")
	if idx < 0 {
		return raw
	}
	host := raw[:idx]
	portStr := raw[idx+1:]
	if _, err := strconv.Atoi(portStr); err != nil {
		return raw
	}
	return host + ":" + portStr
}

// marshalScanConfig serialises a ScanConfig to JSON-friendly form.
func marshalScanConfig(cfg *discovery.ScanConfig) ([]byte, error) {
	m := map[string]interface{}{
		"ports":       cfg.Ports,
		"timeout":     cfg.Timeout.String(),
		"concurrency": cfg.Concurrency,
		"ssh_banner":  cfg.SSHBanner,
	}
	return json.Marshal(m)
}
