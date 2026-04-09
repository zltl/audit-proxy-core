package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

type ConfigStoreEntry struct {
	Version   string          `json:"version"`
	ChangeID  string          `json:"change_id,omitempty"`
	Requester string          `json:"requester,omitempty"`
	Source    string          `json:"source,omitempty"`
	UpdatedAt time.Time       `json:"updated_at"`
	Snapshot  json.RawMessage `json:"snapshot"`
}

func (e ConfigStoreEntry) MarshalJSON() ([]byte, error) {
	type alias struct {
		Version        string    `json:"version"`
		ChangeID       string    `json:"change_id,omitempty"`
		Requester      string    `json:"requester,omitempty"`
		Source         string    `json:"source,omitempty"`
		UpdatedAt      time.Time `json:"updated_at"`
		Snapshot       string    `json:"snapshot"`
		SnapshotFormat string    `json:"snapshot_format,omitempty"`
	}
	return json.Marshal(alias{
		Version:        e.Version,
		ChangeID:       e.ChangeID,
		Requester:      e.Requester,
		Source:         e.Source,
		UpdatedAt:      e.UpdatedAt,
		Snapshot:       string(e.Snapshot),
		SnapshotFormat: firstNonEmpty(detectConfigFormat(e.Snapshot), "text"),
	})
}

func (e *ConfigStoreEntry) UnmarshalJSON(data []byte) error {
	type alias struct {
		Version   string          `json:"version"`
		ChangeID  string          `json:"change_id,omitempty"`
		Requester string          `json:"requester,omitempty"`
		Source    string          `json:"source,omitempty"`
		UpdatedAt time.Time       `json:"updated_at"`
		Snapshot  json.RawMessage `json:"snapshot"`
	}
	var payload alias
	if err := json.Unmarshal(data, &payload); err != nil {
		return err
	}
	e.Version = payload.Version
	e.ChangeID = payload.ChangeID
	e.Requester = payload.Requester
	e.Source = payload.Source
	e.UpdatedAt = payload.UpdatedAt
	if len(payload.Snapshot) == 0 {
		e.Snapshot = nil
		return nil
	}
	var snapshotString string
	if err := json.Unmarshal(payload.Snapshot, &snapshotString); err == nil {
		e.Snapshot = append(json.RawMessage(nil), []byte(snapshotString)...)
		return nil
	}
	e.Snapshot = append(json.RawMessage(nil), payload.Snapshot...)
	return nil
}

type configStore struct {
	mu      sync.RWMutex
	path    string
	current *ConfigStoreEntry
}

func newConfigStore(path string) *configStore {
	s := &configStore{path: path}
	s.load()
	return s
}

func (s *configStore) Get() *ConfigStoreEntry {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneConfigStoreEntry(s.current)
}

func (s *configStore) Save(snapshot []byte, version, changeID, requester, source string,
	updatedAt time.Time) error {
	if s == nil {
		return nil
	}
	entry := &ConfigStoreEntry{
		Version:   version,
		ChangeID:  changeID,
		Requester: requester,
		Source:    source,
		UpdatedAt: updatedAt.UTC(),
		Snapshot:  append(json.RawMessage(nil), snapshot...),
	}

	s.mu.Lock()
	s.current = entry
	raw, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		s.mu.Unlock()
		return err
	}
	if s.path == "" {
		s.mu.Unlock()
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		s.mu.Unlock()
		return err
	}
	err = os.WriteFile(s.path, raw, 0o600)
	s.mu.Unlock()
	return err
}

func (s *configStore) load() {
	if s == nil || s.path == "" {
		return
	}
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return
	}

	var entry ConfigStoreEntry
	if err := json.Unmarshal(raw, &entry); err != nil {
		return
	}

	s.mu.Lock()
	s.current = cloneConfigStoreEntry(&entry)
	s.mu.Unlock()
}

func cloneConfigStoreEntry(entry *ConfigStoreEntry) *ConfigStoreEntry {
	if entry == nil {
		return nil
	}
	cloned := *entry
	cloned.Snapshot = append(json.RawMessage(nil), entry.Snapshot...)
	return &cloned
}

func (a *API) loadPersistedConfigEntry() (*ConfigStoreEntry, error) {
	if a == nil {
		return nil, nil
	}
	if storeBackendIsPostgres(a.config.ConfigStoreBackend) {
		if a.storageDB == nil {
			return nil, fmt.Errorf("postgres config store backend is enabled but database is unavailable")
		}
		return a.storageDB.LoadCurrentConfig()
	}
	if a.configStore == nil {
		return nil, nil
	}
	return a.configStore.Get(), nil
}

func (a *API) bootstrapConfigStore() error {
	if a == nil {
		return nil
	}
	if storeBackendIsPostgres(a.config.ConfigStoreBackend) {
		return a.bootstrapPostgresConfigStore()
	}
	if a.configStore == nil || a.configStore.Get() != nil {
		return nil
	}
	snapshot, err := a.loadLocalConfigSnapshot()
	if err != nil || len(snapshot) == 0 {
		return nil
	}
	return a.persistCentralConfigSnapshot(snapshot, "", "", "bootstrap", "bootstrap")
}

func (a *API) bootstrapPostgresConfigStore() error {
	if a == nil || a.storageDB == nil {
		return nil
	}
	current, err := a.storageDB.LoadCurrentConfig()
	if err != nil {
		return err
	}
	if current == nil {
		if fileEntry := a.configStore.Get(); fileEntry != nil && len(fileEntry.Snapshot) > 0 {
			entry := cloneConfigStoreEntry(fileEntry)
			if entry.Version == "" {
				entry.Version = time.Now().UTC().Format("20060102-150405.000000000")
			}
			if entry.Requester == "" {
				entry.Requester = "bootstrap"
			}
			if entry.Source == "" {
				entry.Source = "bootstrap"
			}
			if entry.UpdatedAt.IsZero() {
				entry.UpdatedAt = time.Now().UTC()
			}
			if err := a.storageDB.SaveCurrentConfig(entry); err != nil {
				return err
			}
		} else {
			snapshot, err := a.loadLocalConfigSnapshot()
			if err == nil && len(snapshot) > 0 {
				if err := a.persistCentralConfigSnapshot(snapshot, "", "", "bootstrap", "bootstrap"); err != nil {
					return err
				}
			}
		}
	}

	hasVersions, err := a.storageDB.HasConfigVersions()
	if err != nil || hasVersions {
		return err
	}
	entries, err := os.ReadDir(a.configVersionDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	type versionImport struct {
		version   string
		createdAt time.Time
		snapshot  []byte
	}

	imports := make([]versionImport, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		version := entry.Name()[:len(entry.Name())-len(filepath.Ext(entry.Name()))]
		path := filepath.Join(a.configVersionDir(), entry.Name())
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		imports = append(imports, versionImport{
			version:   version,
			createdAt: parseConfigVersionTimestamp(version, info.ModTime().UTC()),
			snapshot:  raw,
		})
	}

	sort.Slice(imports, func(i, j int) bool {
		return imports[i].version < imports[j].version
	})
	for _, item := range imports {
		if err := a.storageDB.SaveConfigVersion(item.version, item.snapshot, item.createdAt); err != nil {
			return err
		}
	}
	return nil
}

func parseConfigVersionTimestamp(version string, fallback time.Time) time.Time {
	if version != "" {
		if parsed, err := time.ParseInLocation("20060102-150405.000000000", version, time.UTC); err == nil {
			return parsed.UTC()
		}
	}
	if fallback.IsZero() {
		return time.Now().UTC()
	}
	return fallback.UTC()
}

func (a *API) persistCentralConfigSnapshot(snapshot []byte, version, changeID, requester,
	source string) error {
	if a == nil || len(snapshot) == 0 {
		return nil
	}
	if version == "" {
		version = time.Now().UTC().Format("20060102-150405.000000000")
	}
	if requester == "" {
		requester = "system"
	}
	if source == "" {
		source = a.currentConfigStoreSource()
	}
	if storeBackendIsPostgres(a.config.ConfigStoreBackend) {
		if a.storageDB == nil {
			return fmt.Errorf("postgres config store backend is enabled but database is unavailable")
		}
		return a.storageDB.SaveCurrentConfig(&ConfigStoreEntry{
			Version:   version,
			ChangeID:  changeID,
			Requester: requester,
			Source:    source,
			UpdatedAt: time.Now().UTC(),
			Snapshot:  append(json.RawMessage(nil), snapshot...),
		})
	}
	if a.configStore == nil {
		return nil
	}
	return a.configStore.Save(snapshot, version, changeID, requester, source, time.Now().UTC())
}

func (a *API) currentConfigStoreSource() string {
	if a == nil || a.cluster == nil {
		return "local"
	}
	if self := a.cluster.Self(); self.ID != "" {
		return self.ID
	}
	return "cluster"
}

func (a *API) handleGetConfigStore(w http.ResponseWriter, r *http.Request) {
	if err := a.bootstrapConfigStore(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load centralized config snapshot: "+err.Error())
		return
	}
	entry, err := a.loadPersistedConfigEntry()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load centralized config snapshot: "+err.Error())
		return
	}
	if entry == nil || len(entry.Snapshot) == 0 {
		writeError(w, http.StatusNotFound, "no centralized config snapshot available")
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"version":    entry.Version,
			"change_id":  entry.ChangeID,
			"requester":  entry.Requester,
			"source":     entry.Source,
			"updated_at": entry.UpdatedAt,
			"config":     sanitizeConfigSnapshot(entry.Snapshot),
		},
	})
}
