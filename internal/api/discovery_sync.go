package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/discovery"
)

const (
	discoverySyncSourceTagKey = "discovery_sync_source_id"

	discoverySyncKindCloud   = "cloud"
	discoverySyncKindCMDB    = "cmdb"
	discoverySyncKindAnsible = "ansible"

	defaultDiscoverySyncInterval = time.Hour
)

var errDiscoverySyncSourceNotFound = errors.New("discovery sync source not found")

type discoverySyncSource struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	Kind          string            `json:"kind"`
	Provider      string            `json:"provider,omitempty"`
	Format        string            `json:"format,omitempty"`
	URI           string            `json:"uri,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
	Content       json.RawMessage   `json:"content,omitempty"`
	ContentText   string            `json:"content_text,omitempty"`
	Interval      string            `json:"interval"`
	Enabled       bool              `json:"enabled"`
	AutoRegister  bool              `json:"auto_register,omitempty"`
	Port          int               `json:"port,omitempty"`
	TagFilters    map[string]string `json:"tag_filters,omitempty"`
	ItemsPath     string            `json:"items_path,omitempty"`
	IDField       string            `json:"id_field,omitempty"`
	NameField     string            `json:"name_field,omitempty"`
	HostField     string            `json:"host_field,omitempty"`
	PortField     string            `json:"port_field,omitempty"`
	OSField       string            `json:"os_field,omitempty"`
	StatusField   string            `json:"status_field,omitempty"`
	TagFields     []string          `json:"tag_fields,omitempty"`
	StaticTags    map[string]string `json:"static_tags,omitempty"`
	NextRunAt     time.Time         `json:"next_run_at,omitempty"`
	LastRunAt     time.Time         `json:"last_run_at,omitempty"`
	LastSuccessAt time.Time         `json:"last_success_at,omitempty"`
	LastStatus    string            `json:"last_status,omitempty"`
	LastError     string            `json:"last_error,omitempty"`
	LastImported  int               `json:"last_imported,omitempty"`
	LastNewAssets int               `json:"last_new_assets,omitempty"`
	LastOfflined  int               `json:"last_offlined,omitempty"`
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
}

type discoverySyncSourceInput struct {
	Name         string            `json:"name"`
	Kind         string            `json:"kind"`
	Provider     string            `json:"provider,omitempty"`
	Format       string            `json:"format,omitempty"`
	URI          string            `json:"uri,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	Content      json.RawMessage   `json:"content,omitempty"`
	ContentText  string            `json:"content_text,omitempty"`
	Interval     string            `json:"interval"`
	Enabled      *bool             `json:"enabled,omitempty"`
	AutoRegister bool              `json:"auto_register,omitempty"`
	Port         int               `json:"port,omitempty"`
	TagFilters   map[string]string `json:"tag_filters,omitempty"`
	ItemsPath    string            `json:"items_path,omitempty"`
	IDField      string            `json:"id_field,omitempty"`
	NameField    string            `json:"name_field,omitempty"`
	HostField    string            `json:"host_field,omitempty"`
	PortField    string            `json:"port_field,omitempty"`
	OSField      string            `json:"os_field,omitempty"`
	StatusField  string            `json:"status_field,omitempty"`
	TagFields    []string          `json:"tag_fields,omitempty"`
	StaticTags   map[string]string `json:"static_tags,omitempty"`
}

type discoverySyncSourceStore struct {
	mu      sync.RWMutex
	path    string
	sources map[string]discoverySyncSource
}

type discoverySyncRunResult struct {
	Imported   int `json:"imported"`
	NewAssets  int `json:"new_assets"`
	Offlined   int `json:"offlined"`
	Registered int `json:"registered"`
}

type discoverySyncScheduler struct {
	api   *API
	store *discoverySyncSourceStore
	now   func() time.Time
	runMu sync.Mutex
}

func newDiscoverySyncSourceStore(path string) *discoverySyncSourceStore {
	store := &discoverySyncSourceStore{
		path:    path,
		sources: make(map[string]discoverySyncSource),
	}
	store.load()
	return store
}

func (s *discoverySyncSourceStore) load() {
	if s == nil || strings.TrimSpace(s.path) == "" {
		return
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	var sources []discoverySyncSource
	if err := json.Unmarshal(data, &sources); err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, source := range sources {
		s.sources[source.ID] = source
	}
}

func (s *discoverySyncSourceStore) saveLocked() error {
	sources := make([]discoverySyncSource, 0, len(s.sources))
	for _, source := range s.sources {
		sources = append(sources, source)
	}
	sort.Slice(sources, func(i, j int) bool {
		if sources[i].Name == sources[j].Name {
			return sources[i].ID < sources[j].ID
		}
		return sources[i].Name < sources[j].Name
	})
	data, err := json.MarshalIndent(sources, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0o600)
}

func (s *discoverySyncSourceStore) list() []discoverySyncSource {
	if s == nil {
		return []discoverySyncSource{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	sources := make([]discoverySyncSource, 0, len(s.sources))
	for _, source := range s.sources {
		sources = append(sources, source)
	}
	sort.Slice(sources, func(i, j int) bool {
		if sources[i].Name == sources[j].Name {
			return sources[i].ID < sources[j].ID
		}
		return sources[i].Name < sources[j].Name
	})
	return sources
}

func (s *discoverySyncSourceStore) get(id string) (discoverySyncSource, bool) {
	if s == nil {
		return discoverySyncSource{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	source, ok := s.sources[id]
	return source, ok
}

func (s *discoverySyncSourceStore) create(source discoverySyncSource) (discoverySyncSource, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if source.ID == "" {
		source.ID = newDiscoverySyncSourceID()
	}
	if _, exists := s.sources[source.ID]; exists {
		return discoverySyncSource{}, fmt.Errorf("discovery sync source already exists")
	}
	s.sources[source.ID] = source
	if err := s.saveLocked(); err != nil {
		delete(s.sources, source.ID)
		return discoverySyncSource{}, err
	}
	return source, nil
}

func (s *discoverySyncSourceStore) update(id string, source discoverySyncSource) (discoverySyncSource, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.sources[id]; !exists {
		return discoverySyncSource{}, errDiscoverySyncSourceNotFound
	}
	source.ID = id
	s.sources[id] = source
	if err := s.saveLocked(); err != nil {
		return discoverySyncSource{}, err
	}
	return source, nil
}

func (s *discoverySyncSourceStore) patch(id string, mutate func(*discoverySyncSource) error) (discoverySyncSource, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	source, exists := s.sources[id]
	if !exists {
		return discoverySyncSource{}, errDiscoverySyncSourceNotFound
	}
	if err := mutate(&source); err != nil {
		return discoverySyncSource{}, err
	}
	s.sources[id] = source
	if err := s.saveLocked(); err != nil {
		return discoverySyncSource{}, err
	}
	return source, nil
}

func (s *discoverySyncSourceStore) delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.sources[id]; !exists {
		return errDiscoverySyncSourceNotFound
	}
	delete(s.sources, id)
	return s.saveLocked()
}

func newDiscoverySyncScheduler(api *API, store *discoverySyncSourceStore) *discoverySyncScheduler {
	return &discoverySyncScheduler{
		api:   api,
		store: store,
		now:   func() time.Time { return time.Now().UTC() },
	}
}

func (s *discoverySyncScheduler) start(ctx context.Context, interval time.Duration) {
	if s == nil {
		return
	}
	if interval <= 0 {
		interval = 30 * time.Second
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			s.runDueSourcesOnce(ctx)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

func (s *discoverySyncScheduler) runDueSourcesOnce(ctx context.Context) {
	if s == nil {
		return
	}
	now := s.now()
	for _, source := range s.store.list() {
		if !source.Enabled {
			continue
		}
		if !source.NextRunAt.IsZero() && source.NextRunAt.After(now) {
			continue
		}
		_, _, _ = s.runSource(ctx, source.ID)
	}
}

func (s *discoverySyncScheduler) runSource(ctx context.Context, id string) (discoverySyncSource, discoverySyncRunResult, error) {
	if s == nil || s.api == nil {
		return discoverySyncSource{}, discoverySyncRunResult{}, fmt.Errorf("discovery sync scheduler is not initialized")
	}
	s.runMu.Lock()
	defer s.runMu.Unlock()
	return s.api.runDiscoverySyncSource(ctx, id)
}

func newDiscoverySyncSourceID() string {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return fmt.Sprintf("discsrc-%d", time.Now().UnixNano())
	}
	return "discsrc-" + hex.EncodeToString(raw[:])
}

func sanitizeDiscoverySyncSource(source discoverySyncSource) discoverySyncSource {
	sanitized := source
	if len(source.Headers) > 0 {
		sanitized.Headers = make(map[string]string, len(source.Headers))
		for key, value := range source.Headers {
			if isSensitiveDiscoveryHeader(key) {
				sanitized.Headers[key] = "[redacted]"
			} else {
				sanitized.Headers[key] = value
			}
		}
	}
	return sanitized
}

func isSensitiveDiscoveryHeader(key string) bool {
	key = strings.ToLower(strings.TrimSpace(key))
	return strings.Contains(key, "authorization") ||
		strings.Contains(key, "token") ||
		strings.Contains(key, "secret") ||
		strings.Contains(key, "api-key") ||
		strings.Contains(key, "apikey")
}

func normalizeDiscoverySyncSourceInput(req discoverySyncSourceInput, existing *discoverySyncSource, now time.Time) (discoverySyncSource, error) {
	source := discoverySyncSource{}
	if existing != nil {
		source = *existing
	}
	source.Name = strings.TrimSpace(req.Name)
	source.Kind = strings.ToLower(strings.TrimSpace(req.Kind))
	source.Provider = strings.TrimSpace(req.Provider)
	source.Format = strings.TrimSpace(req.Format)
	source.URI = strings.TrimSpace(req.URI)
	source.Headers = cloneStringMap(req.Headers)
	source.Content = cloneRawMessage(req.Content)
	source.ContentText = req.ContentText
	source.Interval = strings.TrimSpace(req.Interval)
	source.AutoRegister = req.AutoRegister
	source.Port = req.Port
	source.TagFilters = cloneStringMap(req.TagFilters)
	source.ItemsPath = strings.TrimSpace(req.ItemsPath)
	source.IDField = strings.TrimSpace(req.IDField)
	source.NameField = strings.TrimSpace(req.NameField)
	source.HostField = strings.TrimSpace(req.HostField)
	source.PortField = strings.TrimSpace(req.PortField)
	source.OSField = strings.TrimSpace(req.OSField)
	source.StatusField = strings.TrimSpace(req.StatusField)
	source.TagFields = append([]string(nil), req.TagFields...)
	source.StaticTags = cloneStringMap(req.StaticTags)
	if req.Enabled != nil {
		source.Enabled = *req.Enabled
	} else if existing == nil {
		source.Enabled = true
	}

	if source.Interval == "" {
		source.Interval = defaultDiscoverySyncInterval.String()
	}
	if _, err := time.ParseDuration(source.Interval); err != nil {
		return discoverySyncSource{}, fmt.Errorf("invalid interval: %w", err)
	}
	switch source.Kind {
	case discoverySyncKindCloud:
		if strings.TrimSpace(source.Provider) == "" {
			return discoverySyncSource{}, fmt.Errorf("provider is required")
		}
	case discoverySyncKindCMDB:
		if strings.TrimSpace(source.Provider) == "" {
			return discoverySyncSource{}, fmt.Errorf("provider is required")
		}
	case discoverySyncKindAnsible:
	default:
		return discoverySyncSource{}, fmt.Errorf("unsupported discovery source kind %q", source.Kind)
	}
	if len(source.Content) == 0 && source.ContentText == "" && source.URI == "" {
		return discoverySyncSource{}, fmt.Errorf("content, content_text, or uri is required")
	}
	if source.Name == "" {
		source.Name = defaultDiscoverySyncSourceName(source)
	}
	if existing == nil {
		source.CreatedAt = now
	}
	source.UpdatedAt = now
	return source, nil
}

func defaultDiscoverySyncSourceName(source discoverySyncSource) string {
	switch source.Kind {
	case discoverySyncKindCloud:
		if source.Provider != "" {
			return "cloud-" + source.Provider
		}
	case discoverySyncKindCMDB:
		if source.Provider != "" {
			return "cmdb-" + source.Provider
		}
	case discoverySyncKindAnsible:
		if source.Format != "" {
			return "ansible-" + source.Format
		}
		return "ansible-inventory"
	}
	return "discovery-source"
}

func cloneRawMessage(msg json.RawMessage) json.RawMessage {
	if len(msg) == 0 {
		return nil
	}
	cloned := make(json.RawMessage, len(msg))
	copy(cloned, msg)
	return cloned
}

func resolveDiscoveryImportPayload(ctx context.Context, uri string, headers map[string]string, content json.RawMessage, contentText string) ([]byte, error) {
	payload := []byte(content)
	if contentText != "" {
		payload = []byte(contentText)
	}
	if len(payload) > 0 {
		return payload, nil
	}
	if strings.TrimSpace(uri) == "" {
		return nil, fmt.Errorf("content, content_text, or uri is required")
	}
	return fetchDiscoveryImportPayload(ctx, uri, headers)
}

func (a *API) StartDiscoverySync(ctx context.Context, interval time.Duration) {
	if a == nil || ctx == nil {
		return
	}
	ds := a.initDiscovery()
	if ds.syncScheduler == nil {
		ds.syncScheduler = newDiscoverySyncScheduler(a, ds.syncSources)
		ds.syncScheduler.start(ctx, interval)
	}
}

func (a *API) importDiscoverySourceAssets(ctx context.Context, source discoverySyncSource) ([]discovery.Asset, string, error) {
	payload, err := resolveDiscoveryImportPayload(ctx, source.URI, source.Headers, source.Content, source.ContentText)
	if err != nil {
		return nil, "", err
	}
	switch source.Kind {
	case discoverySyncKindCloud:
		assets, err := discovery.ImportCloudAssets(source.Provider, payload, source.TagFilters, source.Port)
		return assets, source.Provider, err
	case discoverySyncKindCMDB:
		assets, err := discovery.ImportCMDBAssets(source.Provider, payload, discovery.CMDBImportConfig{
			ItemsPath:   source.ItemsPath,
			IDField:     source.IDField,
			NameField:   source.NameField,
			HostField:   source.HostField,
			PortField:   source.PortField,
			OSField:     source.OSField,
			StatusField: source.StatusField,
			TagFields:   source.TagFields,
			StaticTags:  source.StaticTags,
			DefaultPort: source.Port,
		})
		return assets, source.Provider, err
	case discoverySyncKindAnsible:
		assets, err := discovery.ImportAnsibleAssets(source.Format, payload, discovery.AnsibleImportConfig{DefaultPort: source.Port})
		return assets, discovery.DetectAnsibleFormat(source.Format, payload), err
	default:
		return nil, "", fmt.Errorf("unsupported discovery source kind %q", source.Kind)
	}
}

func (a *API) runDiscoverySyncSource(ctx context.Context, id string) (discoverySyncSource, discoverySyncRunResult, error) {
	ds := a.initDiscovery()
	source, ok := ds.syncSources.get(id)
	if !ok {
		return discoverySyncSource{}, discoverySyncRunResult{}, errDiscoverySyncSourceNotFound
	}
	now := time.Now().UTC()
	assets, _, err := a.importDiscoverySourceAssets(ctx, source)
	result := discoverySyncRunResult{}
	if err == nil {
		seenIDs := make(map[string]bool, len(assets))
		for i := range assets {
			if assets[i].Tags == nil {
				assets[i].Tags = make(map[string]string)
			}
			assets[i].Tags[discoverySyncSourceTagKey] = source.ID
			assets[i].Tags["discovery_sync_source_name"] = source.Name
			seenIDs[assets[i].ID] = true
			if source.AutoRegister {
				assets[i].AutoRegister = true
			}
		}

		result.Imported = len(assets)
		result.NewAssets = ds.inventory.UpsertAssets(assets)
		offlinedIDs := ds.inventory.MarkTaggedAssetsOffline(discoverySyncSourceTagKey, source.ID, seenIDs)
		result.Offlined = len(offlinedIDs)

		serverChanged := false
		for _, assetID := range offlinedIDs {
			if a.removeDiscoveryAssetServer(assetID) {
				serverChanged = true
			}
		}
		if source.AutoRegister {
			for _, asset := range assets {
				status := "registered"
				if updateErr := ds.inventory.Update(asset.ID, discovery.AssetUpdate{Status: &status, AutoRegister: &source.AutoRegister}); updateErr == nil {
					if synced, getErr := ds.inventory.Get(asset.ID); getErr == nil && a.syncDiscoveryAssetServer(synced) {
						serverChanged = true
					}
					result.Registered++
				}
			}
		}
		if saveErr := ds.inventory.Save(); saveErr != nil {
			err = fmt.Errorf("failed to save inventory: %w", saveErr)
		} else if serverChanged {
			if saveErr := a.servers.save(); saveErr != nil {
				err = fmt.Errorf("failed to save servers: %w", saveErr)
			}
		}
	}

	interval, parseErr := time.ParseDuration(source.Interval)
	if parseErr != nil || interval <= 0 {
		interval = defaultDiscoverySyncInterval
	}
	updated, patchErr := ds.syncSources.patch(id, func(current *discoverySyncSource) error {
		current.LastRunAt = now
		current.UpdatedAt = now
		current.NextRunAt = now.Add(interval)
		current.LastImported = result.Imported
		current.LastNewAssets = result.NewAssets
		current.LastOfflined = result.Offlined
		if err != nil {
			current.LastStatus = "error"
			current.LastError = err.Error()
			return nil
		}
		current.LastStatus = "success"
		current.LastError = ""
		current.LastSuccessAt = now
		return nil
	})
	if patchErr != nil {
		return discoverySyncSource{}, result, patchErr
	}
	return updated, result, err
}

func (a *API) handleListDiscoverySyncSources(w http.ResponseWriter, r *http.Request) {
	ds := a.initDiscovery()
	sources := ds.syncSources.list()
	data := make([]discoverySyncSource, 0, len(sources))
	for _, source := range sources {
		data = append(data, sanitizeDiscoverySyncSource(source))
	}
	writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: data, Total: len(data)})
}

func (a *API) handleCreateDiscoverySyncSource(w http.ResponseWriter, r *http.Request) {
	ds := a.initDiscovery()
	var req discoverySyncSourceInput
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	source, err := normalizeDiscoverySyncSourceInput(req, nil, time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	created, err := ds.syncSources.create(source)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, APIResponse{Success: true, Data: sanitizeDiscoverySyncSource(created)})
}

func (a *API) handleGetDiscoverySyncSource(w http.ResponseWriter, r *http.Request) {
	ds := a.initDiscovery()
	source, ok := ds.syncSources.get(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, errDiscoverySyncSourceNotFound.Error())
		return
	}
	writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: sanitizeDiscoverySyncSource(source)})
}

func (a *API) handleUpdateDiscoverySyncSource(w http.ResponseWriter, r *http.Request) {
	ds := a.initDiscovery()
	id := r.PathValue("id")
	existing, ok := ds.syncSources.get(id)
	if !ok {
		writeError(w, http.StatusNotFound, errDiscoverySyncSourceNotFound.Error())
		return
	}
	var req discoverySyncSourceInput
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	source, err := normalizeDiscoverySyncSourceInput(req, &existing, time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	source.NextRunAt = existing.NextRunAt
	source.LastRunAt = existing.LastRunAt
	source.LastSuccessAt = existing.LastSuccessAt
	source.LastStatus = existing.LastStatus
	source.LastError = existing.LastError
	source.LastImported = existing.LastImported
	source.LastNewAssets = existing.LastNewAssets
	source.LastOfflined = existing.LastOfflined
	updated, err := ds.syncSources.update(id, source)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: sanitizeDiscoverySyncSource(updated)})
}

func (a *API) handleDeleteDiscoverySyncSource(w http.ResponseWriter, r *http.Request) {
	ds := a.initDiscovery()
	id := r.PathValue("id")
	if err := ds.syncSources.delete(id); err != nil {
		if errors.Is(err, errDiscoverySyncSourceNotFound) {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: map[string]string{"message": "discovery sync source " + id + " deleted"}})
}

func (a *API) handleRunDiscoverySyncSource(w http.ResponseWriter, r *http.Request) {
	source, result, err := a.runDiscoverySyncSource(r.Context(), r.PathValue("id"))
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, errDiscoverySyncSourceNotFound) {
			status = http.StatusNotFound
		} else if strings.Contains(err.Error(), "required") || strings.Contains(err.Error(), "unsupported") || strings.Contains(err.Error(), "invalid") || strings.Contains(err.Error(), "parse ") || strings.Contains(err.Error(), "uri") {
			status = http.StatusBadRequest
		}
		writeError(w, status, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"source": sanitizeDiscoverySyncSource(source),
			"result": result,
		},
	})
}
