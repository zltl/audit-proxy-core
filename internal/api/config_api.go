package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// handleGetConfig returns the current configuration, sanitized of secrets.
func (a *API) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	if current, err := a.loadCurrentConfigSnapshot(); err == nil {
		if cfg, err := parseConfigDocument(current, ""); err == nil {
			sanitizeConfig(cfg)
			writeJSON(w, http.StatusOK, APIResponse{
				Success: true,
				Data:    cfg,
			})
			return
		}
	}

	cfg, err := a.dp.GetConfig()
	if err != nil {
		writeError(w, http.StatusBadGateway, "failed to fetch config: "+err.Error())
		return
	}
	sanitizeConfig(cfg)

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    cfg,
	})
}

// handleUpdateConfig updates the configuration, saves a version, and triggers reload.
func (a *API) handleUpdateConfig(w http.ResponseWriter, r *http.Request) {
	if !a.requireConfigLeader(w) {
		return
	}

	var newConfig map[string]interface{}
	if err := readJSON(r, &newConfig); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	newConfig = a.prepareConfigDocument(newConfig)

	if a.config.ConfigApprovalEnabled {
		requester := r.Header.Get("X-User")
		if requester == "" {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		change, err := a.createConfigChange(requester, newConfig)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusAccepted, APIResponse{
			Success: true,
			Data: map[string]interface{}{
				"message": "configuration change submitted for approval",
				"change":  serializeConfigChange(change),
			},
		})
		return
	}

	if err := a.applyConfigDocument(newConfig); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if err := a.publishCurrentConfigClusterWide("", r.Header.Get("X-User")); err != nil {
		writeError(w, http.StatusInternalServerError, "configuration updated locally but failed to publish cluster sync: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    map[string]string{"message": "configuration updated and reloaded"},
	})
}

// handleListConfigVersions lists all saved configuration versions.
func (a *API) handleListConfigVersions(w http.ResponseWriter, r *http.Request) {
	versions, err := a.listConfigVersions()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    versions,
		Total:   len(versions),
	})
}

// handleGetConfigVersion returns a specific configuration version.
func (a *API) handleGetConfigVersion(w http.ResponseWriter, r *http.Request) {
	version := r.PathValue("version")
	if version == "" {
		writeError(w, http.StatusBadRequest, "missing version parameter")
		return
	}

	data, err := a.loadConfigVersionSnapshot(version)
	if err != nil {
		if errors.Is(err, errConfigVersionNotFound) {
			writeError(w, http.StatusNotFound, "config version not found")
			return
		}
		if strings.Contains(err.Error(), "invalid version parameter") {
			writeError(w, http.StatusBadRequest, "invalid version parameter")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to read config version: "+err.Error())
		return
	}

	if cfg, err := parseConfigDocument(data, ""); err == nil {
		sanitizeConfig(cfg)
		writeJSON(w, http.StatusOK, APIResponse{
			Success: true,
			Data:    cfg,
		})
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    sanitizeConfigSnapshot(data),
	})
}

// handleRollbackConfig restores a previous configuration version.
func (a *API) handleRollbackConfig(w http.ResponseWriter, r *http.Request) {
	if !a.requireConfigLeader(w) {
		return
	}

	var req struct {
		Version string `json:"version"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if req.Version == "" {
		writeError(w, http.StatusBadRequest, "version is required")
		return
	}

	data, err := a.loadConfigVersionSnapshot(req.Version)
	if err != nil {
		if errors.Is(err, errConfigVersionNotFound) {
			writeError(w, http.StatusNotFound, "config version not found")
			return
		}
		if strings.Contains(err.Error(), "invalid version parameter") {
			writeError(w, http.StatusBadRequest, "invalid version parameter")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to read config version: "+err.Error())
		return
	}

	// Save current config as version before rollback
	if err := a.saveConfigVersion(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save current config: "+err.Error())
		return
	}

	configPath := a.config.ConfigFile
	if configPath == "" {
		configPath = "config.ini"
	}

	// #nosec G703,G306 -- configPath is the trusted operator-configured control-plane config file path.
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to write config: "+err.Error())
		return
	}

	if err := a.dp.ReloadConfig(); err != nil {
		writeError(w, http.StatusBadGateway, "config restored but reload failed: "+err.Error())
		return
	}
	if err := a.publishCurrentConfigClusterWide("", r.Header.Get("X-User")); err != nil {
		writeError(w, http.StatusInternalServerError, "config restored locally but failed to publish cluster sync: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    map[string]string{"message": "rolled back to version " + req.Version},
	})
}

// handleReloadConfig triggers a configuration reload on the data plane.
func (a *API) handleReloadConfig(w http.ResponseWriter, r *http.Request) {
	if !a.requireConfigLeader(w) {
		return
	}

	if err := a.dp.ReloadConfig(); err != nil {
		writeError(w, http.StatusBadGateway, "reload failed: "+err.Error())
		return
	}
	if err := a.publishCurrentConfigClusterWide("", r.Header.Get("X-User")); err != nil {
		writeError(w, http.StatusInternalServerError, "config reloaded locally but failed to publish cluster sync: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    map[string]string{"message": "configuration reloaded"},
	})
}

// saveConfigVersion saves the current config file as a versioned snapshot.
func (a *API) saveConfigVersion() error {
	_, err := a.saveConfigVersionSnapshot(nil)
	return err
}

func (a *API) saveConfigVersionSnapshot(snapshot []byte) (string, error) {
	var err error
	if snapshot == nil {
		snapshot, err = a.loadCurrentConfigSnapshot()
		if err != nil {
			return "", err
		}
	}

	verDir := a.configVersionDir()
	if storeBackendIsPostgres(a.config.ConfigStoreBackend) {
		versionName := time.Now().UTC().Format("20060102-150405.000000000")
		if err := a.storageDB.SaveConfigVersion(versionName, snapshot, time.Now().UTC()); err != nil {
			return "", err
		}
		return versionName, nil
	}
	if err := os.MkdirAll(verDir, 0o700); err != nil {
		return "", err
	}

	versionName := time.Now().UTC().Format("20060102-150405.000000000")
	versionPath := filepath.Join(verDir, versionName+".json")
	// #nosec G703,G306 -- versionPath is generated under the controlled config version directory.
	if err := os.WriteFile(versionPath, snapshot, 0o600); err != nil {
		return "", err
	}
	return versionName, nil
}

// configVersionDir returns the directory for config version storage.
func (a *API) configVersionDir() string {
	if a.config.ConfigVerDir != "" {
		return a.config.ConfigVerDir
	}
	return "config_versions"
}

func (a *API) configVersionFilePath(version string) (string, error) {
	if err := validateConfigVersionKey(version); err != nil {
		return "", err
	}

	verDir := a.configVersionDir()
	absDir, err := filepath.Abs(verDir)
	if err != nil {
		return "", err
	}

	filePath := filepath.Join(absDir, version+".json")
	prefix := absDir + string(filepath.Separator)
	if filePath != filepath.Join(absDir, version+".json") || (!strings.HasPrefix(filePath, prefix) && filePath != absDir) {
		return "", fmt.Errorf("invalid version parameter")
	}
	return filePath, nil
}

func validateConfigVersionKey(version string) error {
	if version == "" {
		return fmt.Errorf("version is required")
	}
	if strings.Contains(version, string(filepath.Separator)) || version == "." || version == ".." {
		return fmt.Errorf("invalid version parameter")
	}
	return nil
}

func (a *API) loadConfigVersionSnapshot(version string) ([]byte, error) {
	if err := validateConfigVersionKey(version); err != nil {
		return nil, err
	}
	if storeBackendIsPostgres(a.config.ConfigStoreBackend) {
		if a.storageDB == nil {
			return nil, fmt.Errorf("postgres config store backend is enabled but database is unavailable")
		}
		return a.storageDB.LoadConfigVersion(version)
	}
	filePath, err := a.configVersionFilePath(version)
	if err != nil {
		return nil, err
	}
	// #nosec G703 -- filePath is validated to remain under the config version directory.
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errConfigVersionNotFound
		}
		return nil, err
	}
	return data, nil
}

// listConfigVersions reads the version directory and returns metadata.
func (a *API) listConfigVersions() ([]map[string]interface{}, error) {
	if storeBackendIsPostgres(a.config.ConfigStoreBackend) {
		if a.storageDB == nil {
			return nil, fmt.Errorf("postgres config store backend is enabled but database is unavailable")
		}
		return a.storageDB.ListConfigVersions()
	}
	verDir := a.configVersionDir()
	entries, err := os.ReadDir(verDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []map[string]interface{}{}, nil
		}
		return nil, fmt.Errorf("failed to read config versions: %w", err)
	}

	var versions []map[string]interface{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), ".json")
		versions = append(versions, map[string]interface{}{
			"version":   name,
			"size":      info.Size(),
			"timestamp": info.ModTime().UTC(),
		})
	}

	// Sort by version name descending (most recent first)
	sort.Slice(versions, func(i, j int) bool {
		vi := versions[i]["version"].(string)
		vj := versions[j]["version"].(string)
		return vi > vj
	})

	return versions, nil
}

func (a *API) prepareConfigDocument(newConfig map[string]interface{}) map[string]interface{} {
	if current := a.loadCurrentConfigDocument(); current != nil {
		if merged, ok := preserveRedactedConfigValues(current, newConfig).(map[string]interface{}); ok {
			return merged
		}
	}
	return newConfig
}

func (a *API) configFilePath() string {
	if a.config.ConfigFile != "" {
		return a.config.ConfigFile
	}
	return "config.ini"
}

func (a *API) applyConfigDocument(newConfig map[string]interface{}) error {
	currentSnapshot, err := a.loadCurrentConfigSnapshot()
	if err != nil {
		return fmt.Errorf("failed to load current config: %w", err)
	}

	if _, err := a.saveConfigVersionSnapshot(currentSnapshot); err != nil {
		return fmt.Errorf("failed to save config version: %w", err)
	}

	configData, err := json.MarshalIndent(newConfig, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	configPath := a.configFilePath()
	// #nosec G306 -- configPath is the trusted operator-configured control-plane config file path.
	if err := os.WriteFile(configPath, configData, 0o600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	if err := a.dp.ReloadConfig(); err != nil {
		rollbackErr := os.WriteFile(configPath, currentSnapshot, 0o600)
		if rollbackErr != nil {
			return fmt.Errorf("config saved but reload failed: %v (rollback failed: %v)", err, rollbackErr)
		}
		return fmt.Errorf("config saved but reload failed: %w", err)
	}

	return nil
}

func (a *API) ApplyClusterConfigSnapshot(snapshot []byte) error {
	var newConfig map[string]interface{}
	if err := json.Unmarshal(snapshot, &newConfig); err != nil {
		return fmt.Errorf("invalid synced config snapshot: %w", err)
	}
	if err := a.applyConfigDocument(newConfig); err != nil {
		return err
	}

	version := ""
	changeID := ""
	requester := "cluster"
	if a.cluster != nil {
		if desired, err := a.cluster.GetDesiredConfigPayload(); err == nil && desired != nil {
			version = desired.Version
			changeID = desired.ChangeID
			if desired.Requester != "" {
				requester = desired.Requester
			}
		}
	}
	return a.persistCentralConfigSnapshot(snapshot, version, changeID, requester, a.currentConfigStoreSource())
}

func (a *API) publishCurrentConfigClusterWide(changeID, requester string) error {
	snapshot, err := a.loadLocalConfigSnapshot()
	if err != nil {
		if current, loadErr := a.loadPersistedConfigEntry(); loadErr == nil && current != nil && len(current.Snapshot) > 0 {
			snapshot = append([]byte(nil), current.Snapshot...)
		} else if a.cluster == nil {
			return nil
		} else {
			return fmt.Errorf("load current config snapshot: %w", err)
		}
	}
	version := time.Now().UTC().Format("20060102-150405.000000000")
	if requester == "" {
		requester = "system"
	}
	if err := a.persistCentralConfigSnapshot(snapshot, version, changeID, requester, a.currentConfigStoreSource()); err != nil {
		return fmt.Errorf("persist central config snapshot: %w", err)
	}
	if a.cluster == nil {
		return nil
	}
	return a.cluster.PublishConfigSnapshot(snapshot, version, changeID, requester)
}

func (a *API) requireConfigLeader(w http.ResponseWriter) bool {
	if a.cluster == nil || a.cluster.IsLeader() {
		return true
	}
	msg := "configuration changes must be submitted to the cluster leader"
	if leader := a.cluster.Leader(); leader != nil {
		if leader.APIAddr != "" {
			msg += " at " + leader.APIAddr
		} else if leader.ID != "" {
			msg += " (" + leader.ID + ")"
		}
	}
	writeError(w, http.StatusConflict, msg)
	return false
}
