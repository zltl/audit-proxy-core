package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// APIResponse is the standard envelope for all API responses.
type APIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
	Total   int         `json:"total,omitempty"`
	Page    int         `json:"page,omitempty"`
	PerPage int         `json:"per_page,omitempty"`
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		http.Error(w, `{"success":false,"error":"failed to encode response"}`, http.StatusInternalServerError)
	}
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, APIResponse{
		Success: false,
		Error:   message,
	})
}

// readJSON decodes the request body into dst.
func readJSON(r *http.Request, dst interface{}) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1 MB limit
	if err != nil {
		return fmt.Errorf("failed to read request body: %w", err)
	}
	defer r.Body.Close()
	if len(body) == 0 {
		return fmt.Errorf("request body is empty")
	}
	if err := json.Unmarshal(body, dst); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	return nil
}

// getPathParam extracts the trailing part of a URL path after a given prefix.
// For example, getPathParam(r, "/api/v2/sessions/") returns the session ID.
func getPathParam(r *http.Request, prefix string) string {
	p := strings.TrimPrefix(r.URL.Path, prefix)
	p = strings.TrimSuffix(p, "/")
	// If there's a sub-path, only return the first segment
	if idx := strings.Index(p, "/"); idx != -1 {
		return p[:idx]
	}
	return p
}

// parsePagination extracts page and per_page query parameters with defaults.
func parsePagination(r *http.Request) (page, perPage int) {
	page = 1
	perPage = 50

	if v := r.URL.Query().Get("page"); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 {
			page = p
		}
	}
	if v := r.URL.Query().Get("per_page"); v != "" {
		if pp, err := strconv.Atoi(v); err == nil && pp > 0 && pp <= 200 {
			perPage = pp
		}
	}
	return
}

// paginate returns the slice bounds for the given page and perPage on a total count.
func paginate(total, page, perPage int) (start, end int) {
	start = (page - 1) * perPage
	if start > total {
		start = total
	}
	end = start + perPage
	if end > total {
		end = total
	}
	return
}
