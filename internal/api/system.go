package api

import (
	"net/http"
	"os"
	"runtime"
	"time"
)

var startTime = time.Now()

// handleSystemHealth returns the control plane health status.
func (a *API) handleSystemHealth(w http.ResponseWriter, r *http.Request) {
	// Also check data plane health
	dpStatus := "unknown"
	if health, err := a.dp.GetHealth(); err == nil {
		dpStatus = health.Status
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"status":           "healthy",
			"data_plane":       dpStatus,
			"uptime_seconds":   int64(time.Since(startTime).Seconds()),
			"timestamp":        time.Now().UTC(),
		},
	})
}

// handleSystemInfo returns system information.
func (a *API) handleSystemInfo(w http.ResponseWriter, r *http.Request) {
	hostname, _ := os.Hostname()

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"version":        "2.0.0",
			"go_version":     runtime.Version(),
			"os":             runtime.GOOS,
			"arch":           runtime.GOARCH,
			"hostname":       hostname,
			"num_goroutines": runtime.NumGoroutine(),
			"num_cpus":       runtime.NumCPU(),
			"memory_alloc":   memStats.Alloc,
			"memory_sys":     memStats.Sys,
			"uptime_seconds": int64(time.Since(startTime).Seconds()),
			"started_at":     startTime.UTC(),
		},
	})
}

// handleSystemMetrics proxies metrics from the data plane.
func (a *API) handleSystemMetrics(w http.ResponseWriter, r *http.Request) {
	metrics, err := a.dp.GetMetrics()
	if err != nil {
		writeError(w, http.StatusBadGateway, "failed to fetch metrics: "+err.Error())
		return
	}

	// Return raw metrics (e.g., Prometheus format) as text
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(metrics))
}
