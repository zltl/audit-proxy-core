package api

import (
	"net/http"
	"sync"

	"github.com/zltl/audit-proxy-core/internal/features"
)

// featureGate tracks which experimental subsystems the operator opted into.
// The vocabulary itself lives in internal/features so the configuration loader
// can validate names without depending on the HTTP layer.
type featureGate struct {
	mu      sync.RWMutex
	enabled map[string]bool
}

func newFeatureGate(raw string) *featureGate {
	g := &featureGate{enabled: make(map[string]bool)}
	for _, name := range features.Parse(raw) {
		g.enabled[name] = true
	}
	return g
}

func (g *featureGate) enabledFor(name string) bool {
	if g == nil {
		return false
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.enabled[name]
}

// FeatureEnabled reports whether an experimental subsystem is switched on.
func (a *API) FeatureEnabled(name string) bool {
	if a == nil {
		return false
	}
	return a.features.enabledFor(name)
}

// requireFeature wraps a handler so that it returns 503 with an actionable
// message unless the named experimental subsystem has been enabled.
func (a *API) requireFeature(name string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if a.FeatureEnabled(name) {
			next(w, r)
			return
		}
		msg := "experimental subsystem " + name + " is disabled"
		if reason := features.Reasons[name]; reason != "" {
			msg += ": " + reason
		}
		msg += ". Set experimental_features=" + name + " to enable it if that trade-off is acceptable."
		writeError(w, http.StatusServiceUnavailable, msg)
	}
}

// handleListFeatures reports the state of every gate so operators and the UI can
// tell a disabled subsystem apart from a broken one.
func (a *API) handleListFeatures(w http.ResponseWriter, _ *http.Request) {
	items := make([]map[string]interface{}, 0, len(features.All))
	for _, name := range features.All {
		items = append(items, map[string]interface{}{
			"name":    name,
			"enabled": a.FeatureEnabled(name),
			"reason":  features.Reasons[name],
		})
	}
	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    map[string]interface{}{"experimental": items},
	})
}
