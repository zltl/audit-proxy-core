package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/discovery"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/models"
)

// discoveryState holds the runtime state for asset discovery endpoints.
type discoveryState struct {
	inventory     *discovery.Inventory
	scanConfig    *discovery.ScanConfig
	syncSources   *discoverySyncSourceStore
	syncScheduler *discoverySyncScheduler
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
		syncSources: newDiscoverySyncSourceStore(dataFilePath(a.config.DataDir, "discovery_sources.json")),
	}
	return a.discovery
}

func discoveryManagedServerID(assetID string) string {
	replacer := strings.NewReplacer(":", "-", "/", "-", "\\", "-", " ", "-")
	return "discovery-" + replacer.Replace(strings.ToLower(assetID))
}

func cloneStringMap(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func (a *API) syncDiscoveryAssetServer(asset *discovery.Asset) bool {
	if asset == nil || asset.Status != "registered" {
		return false
	}

	now := time.Now().UTC()
	checkedAt := asset.LastSeen.UTC()
	if checkedAt.IsZero() {
		checkedAt = now
	}

	tags := cloneStringMap(asset.Tags)
	if tags == nil {
		tags = make(map[string]string)
	}
	tags["source"] = "discovery"
	tags["discovery_asset_id"] = asset.ID
	if asset.SSHVersion != "" {
		tags["ssh_version"] = asset.SSHVersion
	}
	if asset.OS != "" {
		tags["os"] = asset.OS
	}

	serverID := discoveryManagedServerID(asset.ID)

	a.servers.mu.Lock()
	defer a.servers.mu.Unlock()

	existing, ok := a.servers.servers[serverID]
	server := models.Server{
		ID:          serverID,
		Host:        asset.Host,
		Port:        asset.Port,
		Name:        asset.Name,
		Group:       "discovery",
		Status:      "online",
		Healthy:     true,
		Weight:      1,
		MaxSessions: existing.MaxSessions,
		Maintenance: existing.Maintenance,
		Sessions:    existing.Sessions,
		Tags:        tags,
		CheckedAt:   checkedAt,
	}
	if server.Name == "" {
		server.Name = asset.Host
	}
	if existing.Group != "" {
		server.Group = existing.Group
	}
	if group := tags["group"]; group != "" {
		server.Group = group
	}
	if existing.Weight > 0 {
		server.Weight = existing.Weight
	}
	if len(existing.Tags) > 0 {
		mergedTags := cloneStringMap(existing.Tags)
		for k, v := range tags {
			mergedTags[k] = v
		}
		server.Tags = mergedTags
	}

	if ok && reflect.DeepEqual(existing, server) {
		return false
	}
	a.servers.servers[server.ID] = server
	return true
}

func (a *API) removeDiscoveryAssetServer(assetID string) bool {
	serverID := discoveryManagedServerID(assetID)

	a.servers.mu.Lock()
	defer a.servers.mu.Unlock()

	if _, ok := a.servers.servers[serverID]; !ok {
		return false
	}
	delete(a.servers.servers, serverID)
	return true
}

// RegisterDiscoveryRoutes adds the /api/v2/discovery/* endpoints to mux.
func (a *API) RegisterDiscoveryRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v2/discovery/scan", a.handleDiscoveryScan)
	mux.HandleFunc("POST /api/v2/discovery/cloud/import", a.handleDiscoveryCloudImport)
	mux.HandleFunc("POST /api/v2/discovery/cmdb/import", a.handleDiscoveryCMDBImport)
	mux.HandleFunc("POST /api/v2/discovery/ansible/import", a.handleDiscoveryAnsibleImport)
	mux.HandleFunc("GET /api/v2/discovery/sources", a.handleListDiscoverySyncSources)
	mux.HandleFunc("POST /api/v2/discovery/sources", a.handleCreateDiscoverySyncSource)
	mux.HandleFunc("GET /api/v2/discovery/sources/{id}", a.handleGetDiscoverySyncSource)
	mux.HandleFunc("PUT /api/v2/discovery/sources/{id}", a.handleUpdateDiscoverySyncSource)
	mux.HandleFunc("DELETE /api/v2/discovery/sources/{id}", a.handleDeleteDiscoverySyncSource)
	mux.HandleFunc("POST /api/v2/discovery/sources/{id}/run", a.handleRunDiscoverySyncSource)
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

// handleDiscoveryAnsibleImport imports Ansible JSON or INI inventory into the
// shared discovery inventory.
func (a *API) handleDiscoveryAnsibleImport(w http.ResponseWriter, r *http.Request) {
	ds := a.initDiscovery()

	var req struct {
		Format       string            `json:"format"`
		URI          string            `json:"uri"`
		Headers      map[string]string `json:"headers"`
		Content      json.RawMessage   `json:"content"`
		ContentText  string            `json:"content_text"`
		Port         int               `json:"port"`
		AutoRegister bool              `json:"auto_register"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	payload, err := resolveDiscoveryImportPayload(r.Context(), req.URI, req.Headers, req.Content, req.ContentText)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	assets, err := discovery.ImportAnsibleAssets(req.Format, payload, discovery.AnsibleImportConfig{DefaultPort: req.Port})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.AutoRegister {
		for i := range assets {
			assets[i].AutoRegister = true
		}
	}

	newCount := ds.inventory.UpsertAssets(assets)
	if err := ds.inventory.Save(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save inventory: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"format":        discovery.DetectAnsibleFormat(req.Format, payload),
			"imported":      len(assets),
			"new_assets":    newCount,
			"auto_register": req.AutoRegister,
		},
	})
}

// handleDiscoveryCMDBImport imports CMDB inventory payloads into the shared
// discovery inventory. ServiceNow has built-in defaults; custom APIs supply
// explicit field mappings.
func (a *API) handleDiscoveryCMDBImport(w http.ResponseWriter, r *http.Request) {
	ds := a.initDiscovery()

	var req struct {
		Provider     string            `json:"provider"`
		URI          string            `json:"uri"`
		Headers      map[string]string `json:"headers"`
		Content      json.RawMessage   `json:"content"`
		ItemsPath    string            `json:"items_path"`
		IDField      string            `json:"id_field"`
		NameField    string            `json:"name_field"`
		HostField    string            `json:"host_field"`
		PortField    string            `json:"port_field"`
		OSField      string            `json:"os_field"`
		StatusField  string            `json:"status_field"`
		TagFields    []string          `json:"tag_fields"`
		StaticTags   map[string]string `json:"static_tags"`
		Port         int               `json:"port"`
		AutoRegister bool              `json:"auto_register"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(req.Provider) == "" {
		writeError(w, http.StatusBadRequest, "provider is required")
		return
	}

	payload, err := resolveDiscoveryImportPayload(r.Context(), req.URI, req.Headers, req.Content, "")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	assets, err := discovery.ImportCMDBAssets(req.Provider, payload, discovery.CMDBImportConfig{
		ItemsPath:   req.ItemsPath,
		IDField:     req.IDField,
		NameField:   req.NameField,
		HostField:   req.HostField,
		PortField:   req.PortField,
		OSField:     req.OSField,
		StatusField: req.StatusField,
		TagFields:   req.TagFields,
		StaticTags:  req.StaticTags,
		DefaultPort: req.Port,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.AutoRegister {
		for i := range assets {
			assets[i].AutoRegister = true
		}
	}

	newCount := ds.inventory.UpsertAssets(assets)
	if err := ds.inventory.Save(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save inventory: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"provider":      req.Provider,
			"imported":      len(assets),
			"new_assets":    newCount,
			"auto_register": req.AutoRegister,
		},
	})
}

// handleDiscoveryCloudImport imports provider-native cloud inventory JSON into
// the discovery inventory while reusing the normal register/sync flow.
func (a *API) handleDiscoveryCloudImport(w http.ResponseWriter, r *http.Request) {
	ds := a.initDiscovery()

	var req struct {
		Provider     string            `json:"provider"`
		URI          string            `json:"uri"`
		Headers      map[string]string `json:"headers"`
		Content      json.RawMessage   `json:"content"`
		TagFilters   map[string]string `json:"tag_filters"`
		Port         int               `json:"port"`
		AutoRegister bool              `json:"auto_register"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(req.Provider) == "" {
		writeError(w, http.StatusBadRequest, "provider is required")
		return
	}

	payload, err := resolveDiscoveryImportPayload(r.Context(), req.URI, req.Headers, req.Content, "")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	assets, err := discovery.ImportCloudAssets(req.Provider, payload, req.TagFilters, req.Port)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.AutoRegister {
		for i := range assets {
			assets[i].AutoRegister = true
		}
	}

	newCount := ds.inventory.UpsertAssets(assets)
	if err := ds.inventory.Save(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save inventory: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"provider":      req.Provider,
			"imported":      len(assets),
			"new_assets":    newCount,
			"auto_register": req.AutoRegister,
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
	serverChanged := false
	if asset != nil && asset.Status == "registered" {
		serverChanged = a.syncDiscoveryAssetServer(asset)
	} else {
		serverChanged = a.removeDiscoveryAssetServer(id)
	}
	if serverChanged {
		if err := a.servers.save(); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to save servers: "+err.Error())
			return
		}
	}

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
	if a.removeDiscoveryAssetServer(id) {
		if err := a.servers.save(); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to save servers: "+err.Error())
			return
		}
	}

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
	serverChanged := false
	if len(req.IDs) > 0 {
		for _, id := range req.IDs {
			status := "registered"
			if err := ds.inventory.Update(id, discovery.AssetUpdate{Status: &status}); err == nil {
				if asset, getErr := ds.inventory.Get(id); getErr == nil && a.syncDiscoveryAssetServer(asset) {
					serverChanged = true
				}
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
		for _, asset := range ds.inventory.List(discovery.AssetFilter{Status: "registered"}) {
			if a.syncDiscoveryAssetServer(asset) {
				serverChanged = true
			}
		}
	}
	_ = ds.inventory.Save()
	if serverChanged {
		if err := a.servers.save(); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to save servers: "+err.Error())
			return
		}
	}

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

func fetchDiscoveryImportPayload(ctx context.Context, uri string, headers map[string]string) ([]byte, error) {
	uri = strings.TrimSpace(uri)
	if uri == "" {
		return nil, fmt.Errorf("uri is required")
	}
	if !strings.HasPrefix(uri, "http://") && !strings.HasPrefix(uri, "https://") {
		return nil, fmt.Errorf("unsupported uri scheme: only http:// and https:// are allowed")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, fmt.Errorf("build fetch request: %w", err)
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", uri, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("fetch %s: unexpected status %s", uri, resp.Status)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", uri, err)
	}
	return data, nil
}
