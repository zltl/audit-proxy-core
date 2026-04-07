package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/models"
)

// handleGetConfig returns the current configuration, sanitized of secrets.
func (a *API) handleGetConfig(w http.ResponseWriter, r *http.Request) {
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
	var newConfig map[string]interface{}
	if err := readJSON(r, &newConfig); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Save current config as a version before overwriting
	if err := a.saveConfigVersion(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save config version: "+err.Error())
		return
	}

	// Write the new config to the config file
	configData, err := json.MarshalIndent(newConfig, "", "  ")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to marshal config: "+err.Error())
		return
	}

	configPath := a.config.ConfigFile
	if configPath == "" {
		configPath = "config.ini"
	}

	if err := os.WriteFile(configPath, configData, 0644); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to write config file: "+err.Error())
		return
	}

	// Trigger reload on the data plane
	if err := a.dp.ReloadConfig(); err != nil {
		writeError(w, http.StatusBadGateway, "config saved but reload failed: "+err.Error())
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

	verDir := a.configVersionDir()
	filePath := filepath.Join(verDir, version+".json")

	// Prevent directory traversal
	absPath, err := filepath.Abs(filePath)
	if err != nil || !strings.HasPrefix(absPath, verDir) {
		writeError(w, http.StatusBadRequest, "invalid version parameter")
		return
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			writeError(w, http.StatusNotFound, "config version not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to read config version: "+err.Error())
		return
	}

	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		// Return as raw content if not valid JSON
		writeJSON(w, http.StatusOK, APIResponse{
			Success: true,
			Data: models.ConfigVersion{
				Content: string(data),
			},
		})
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    cfg,
	})
}

// handleRollbackConfig restores a previous configuration version.
func (a *API) handleRollbackConfig(w http.ResponseWriter, r *http.Request) {
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

	verDir := a.configVersionDir()
	filePath := filepath.Join(verDir, req.Version+".json")

	// Prevent directory traversal
	absPath, err := filepath.Abs(filePath)
	if err != nil || !strings.HasPrefix(absPath, verDir) {
		writeError(w, http.StatusBadRequest, "invalid version parameter")
		return
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			writeError(w, http.StatusNotFound, "config version not found")
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

	if err := os.WriteFile(configPath, data, 0644); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to write config: "+err.Error())
		return
	}

	if err := a.dp.ReloadConfig(); err != nil {
		writeError(w, http.StatusBadGateway, "config restored but reload failed: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    map[string]string{"message": "rolled back to version " + req.Version},
	})
}

// handleReloadConfig triggers a configuration reload on the data plane.
func (a *API) handleReloadConfig(w http.ResponseWriter, r *http.Request) {
	if err := a.dp.ReloadConfig(); err != nil {
		writeError(w, http.StatusBadGateway, "reload failed: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    map[string]string{"message": "configuration reloaded"},
	})
}

// saveConfigVersion saves the current config file as a versioned snapshot.
func (a *API) saveConfigVersion() error {
	configPath := a.config.ConfigFile
	if configPath == "" {
		configPath = "config.ini"
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // nothing to version
		}
		return err
	}

	verDir := a.configVersionDir()
	if err := os.MkdirAll(verDir, 0755); err != nil {
		return err
	}

	versionName := time.Now().UTC().Format("20060102-150405")
	versionPath := filepath.Join(verDir, versionName+".json")
	return os.WriteFile(versionPath, data, 0644)
}

// configVersionDir returns the directory for config version storage.
func (a *API) configVersionDir() string {
	if a.config.ConfigVerDir != "" {
		return a.config.ConfigVerDir
	}
	return "config_versions"
}

// listConfigVersions reads the version directory and returns metadata.
func (a *API) listConfigVersions() ([]map[string]interface{}, error) {
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

// sanitizeConfig removes sensitive fields from a config map.
func sanitizeConfig(cfg map[string]interface{}) {
	sensitiveKeys := []string{"password", "secret", "token", "key", "pass_hash", "private_key"}
	for k := range cfg {
		kLower := strings.ToLower(k)
		for _, sk := range sensitiveKeys {
			if strings.Contains(kLower, sk) {
				cfg[k] = "***REDACTED***"
				break
			}
		}
		// Recurse into nested maps
		if nested, ok := cfg[k].(map[string]interface{}); ok {
			sanitizeConfig(nested)
		}
	}
}
