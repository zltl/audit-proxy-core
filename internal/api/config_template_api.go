package api

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
)

// ConfigTemplate represents a built-in configuration preset.
type ConfigTemplate struct {
	Name        string                 `json:"name"`
	Environment string                 `json:"environment"`
	Description string                 `json:"description"`
	Config      map[string]interface{} `json:"config"`
}

func builtinConfigTemplates() []ConfigTemplate {
	return []ConfigTemplate{
		{
			Name:        "production",
			Environment: "production",
			Description: "Higher session capacity with stricter defaults for audited production environments.",
			Config: map[string]interface{}{
				"log_level":             "warn",
				"log_format":            "json",
				"max_sessions":          500,
				"session_timeout":       7200,
				"auth_timeout":          45,
				"per_user_max_sessions": 20,
				"show_progress":         false,
				"log_rejections":        true,
				"mfa_enabled":           true,
				"webhook_enabled":       true,
			},
		},
		{
			Name:        "testing",
			Environment: "testing",
			Description: "Balanced defaults for integration and pre-production testing.",
			Config: map[string]interface{}{
				"log_level":             "info",
				"log_format":            "json",
				"max_sessions":          100,
				"session_timeout":       3600,
				"auth_timeout":          60,
				"per_user_max_sessions": 10,
				"show_progress":         true,
				"log_rejections":        true,
				"mfa_enabled":           false,
				"webhook_enabled":       false,
			},
		},
		{
			Name:        "development",
			Environment: "development",
			Description: "Verbose local-development defaults with shorter limits and progress output enabled.",
			Config: map[string]interface{}{
				"log_level":             "debug",
				"log_format":            "text",
				"max_sessions":          25,
				"session_timeout":       1800,
				"auth_timeout":          120,
				"per_user_max_sessions": 5,
				"show_progress":         true,
				"log_rejections":        false,
				"mfa_enabled":           false,
				"webhook_enabled":       false,
				"auth_backend":          "local",
			},
		},
	}
}

func findBuiltinConfigTemplate(name string) (*ConfigTemplate, bool) {
	for _, template := range builtinConfigTemplates() {
		if strings.EqualFold(template.Name, name) {
			cp := template
			cp.Config = cloneConfigPayload(template.Config)
			return &cp, true
		}
	}
	return nil, false
}

func (a *API) handleListConfigTemplates(w http.ResponseWriter, r *http.Request) {
	templates := builtinConfigTemplates()
	sort.Slice(templates, func(i, j int) bool {
		return templates[i].Name < templates[j].Name
	})

	items := make([]map[string]interface{}, 0, len(templates))
	for _, template := range templates {
		items = append(items, serializeConfigTemplate(template, nil))
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    items,
		Total:   len(items),
	})
}

func (a *API) handleGetConfigTemplate(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "missing template name")
		return
	}

	template, ok := findBuiltinConfigTemplate(name)
	if !ok {
		writeError(w, http.StatusNotFound, "config template not found")
		return
	}

	current, _ := a.loadCurrentConfigDocument().(map[string]interface{})
	resolved := cloneConfigPayload(template.Config)
	if current != nil {
		if merged, ok := mergeConfigOverlay(current, template.Config).(map[string]interface{}); ok {
			resolved = merged
		}
	}
	resolved = a.prepareConfigDocument(resolved)

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    serializeConfigTemplate(*template, resolved),
	})
}

func serializeConfigTemplate(template ConfigTemplate, resolved map[string]interface{}) map[string]interface{} {
	resp := map[string]interface{}{
		"name":        template.Name,
		"environment": template.Environment,
		"description": template.Description,
		"config":      sanitizeConfigPayload(template.Config),
	}
	if resolved != nil {
		resp["resolved_config"] = sanitizeConfigPayload(resolved)
	}
	return resp
}

func mergeConfigOverlay(base, overlay interface{}) interface{} {
	switch overlayTyped := overlay.(type) {
	case map[string]interface{}:
		baseMap, _ := base.(map[string]interface{})
		merged := make(map[string]interface{}, len(baseMap)+len(overlayTyped))
		for key, value := range baseMap {
			merged[key] = cloneUntypedConfigValue(value)
		}
		for key, value := range overlayTyped {
			merged[key] = mergeConfigOverlay(baseMap[key], value)
		}
		return merged
	case []interface{}:
		return cloneUntypedConfigValue(overlayTyped)
	default:
		return cloneUntypedConfigValue(overlayTyped)
	}
}

func cloneUntypedConfigValue(value interface{}) interface{} {
	raw, err := json.Marshal(value)
	if err != nil {
		return value
	}
	var cloned interface{}
	if err := json.Unmarshal(raw, &cloned); err != nil {
		return value
	}
	return cloned
}
