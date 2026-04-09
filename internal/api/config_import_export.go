package api

import (
	"net/http"
	"strings"
)

type configImportRequest struct {
	Format  string `json:"format"`
	Content string `json:"content"`
}

func (a *API) handleExportConfig(w http.ResponseWriter, r *http.Request) {
	format := strings.TrimSpace(r.URL.Query().Get("format"))
	normalized := normalizeConfigFormat(format)
	if format != "" && normalized == "" {
		writeError(w, http.StatusBadRequest, "unsupported config format")
		return
	}
	if normalized == "" {
		normalized = configFormatJSON
	}

	current, err := a.loadCurrentConfigSnapshot()
	if err != nil {
		writeError(w, http.StatusBadGateway, "failed to load current config: "+err.Error())
		return
	}
	doc, err := parseConfigDocument(current, "")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to parse current config: "+err.Error())
		return
	}
	rendered, err := renderConfigDocument(doc, normalized)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to render config export: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"format":  normalized,
			"content": string(rendered),
		},
	})
}

func (a *API) handleImportConfig(w http.ResponseWriter, r *http.Request) {
	var req configImportRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(req.Content) == "" {
		writeError(w, http.StatusBadRequest, "config content is required")
		return
	}

	normalized := normalizeConfigFormat(req.Format)
	if strings.TrimSpace(req.Format) != "" && normalized == "" {
		writeError(w, http.StatusBadRequest, "unsupported config format")
		return
	}

	doc, err := parseConfigDocument([]byte(req.Content), normalized)
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to parse config import: "+err.Error())
		return
	}
	doc = a.prepareConfigDocument(doc)

	fromLabel, fromContent, err := a.loadConfigDiffSource("current")
	if err != nil {
		writeError(w, http.StatusBadGateway, "failed to load current config: "+err.Error())
		return
	}
	toContent, err := sanitizedNormalizedConfigValue(doc)
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to normalize imported config: "+err.Error())
		return
	}
	diff := buildUnifiedConfigDiff(fromLabel, "imported", fromContent, toContent)

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"format":           firstNonEmpty(normalized, detectConfigFormat([]byte(req.Content))),
			"config":           doc,
			"sanitized_config": sanitizeConfigPayload(doc),
			"changed":          diff != noConfigDiffMessage,
			"diff":             diff,
		},
	})
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
