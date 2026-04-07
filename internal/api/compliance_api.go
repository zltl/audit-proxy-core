package api

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/compliance"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/siem"
)

// complianceState holds report generator and cached reports.
type complianceState struct {
	gen     *compliance.ReportGenerator
	mu      sync.RWMutex
	reports []*compliance.Report
}

// siemState holds the SIEM forwarder and its config.
type siemState struct {
	mu        sync.RWMutex
	forwarder *siem.Forwarder
	config    *siem.SIEMConfig
}

// SetCompliance attaches a compliance report generator to the API.
func (a *API) SetCompliance(gen *compliance.ReportGenerator) {
	if a.compliance == nil {
		a.compliance = &complianceState{}
	}
	a.compliance.gen = gen
}

// SetSIEM attaches a SIEM forwarder to the API.
func (a *API) SetSIEM(fwd *siem.Forwarder, cfg *siem.SIEMConfig) {
	if a.siemState == nil {
		a.siemState = &siemState{}
	}
	a.siemState.forwarder = fwd
	a.siemState.config = cfg
}

// RegisterComplianceRoutes registers compliance and SIEM API routes on the given mux.
func (a *API) RegisterComplianceRoutes(mux *http.ServeMux) {
	// Compliance
	mux.HandleFunc("GET /api/v2/compliance/frameworks", a.handleListFrameworks)
	mux.HandleFunc("POST /api/v2/compliance/reports", a.handleGenerateReport)
	mux.HandleFunc("GET /api/v2/compliance/reports", a.handleListReports)
	mux.HandleFunc("GET /api/v2/compliance/reports/{id}", a.handleGetReport)
	mux.HandleFunc("GET /api/v2/compliance/reports/{id}/export", a.handleExportReport)
	mux.HandleFunc("GET /api/v2/compliance/score", a.handleComplianceScore)

	// SIEM
	mux.HandleFunc("GET /api/v2/siem/config", a.handleGetSIEMConfig)
	mux.HandleFunc("PUT /api/v2/siem/config", a.handleUpdateSIEMConfig)
	mux.HandleFunc("POST /api/v2/siem/test", a.handleTestSIEM)
	mux.HandleFunc("GET /api/v2/siem/status", a.handleSIEMStatus)
}

func (a *API) requireCompliance(w http.ResponseWriter) bool {
	if a.compliance == nil || a.compliance.gen == nil {
		writeError(w, http.StatusServiceUnavailable, "compliance reporting is not enabled")
		return false
	}
	return true
}

func (a *API) requireSIEM(w http.ResponseWriter) bool {
	if a.siemState == nil || a.siemState.forwarder == nil {
		writeError(w, http.StatusServiceUnavailable, "SIEM integration is not enabled")
		return false
	}
	return true
}

// ---------------------------------------------------------------------------
// Compliance endpoints
// ---------------------------------------------------------------------------

func (a *API) handleListFrameworks(w http.ResponseWriter, r *http.Request) {
	type frameworkInfo struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
	}

	frameworks := []frameworkInfo{
		{ID: "soc2", Name: "SOC 2", Description: "Service Organization Control 2 - Trust Services Criteria"},
		{ID: "hipaa", Name: "HIPAA", Description: "Health Insurance Portability and Accountability Act"},
		{ID: "gdpr", Name: "GDPR", Description: "General Data Protection Regulation"},
		{ID: "pci-dss", Name: "PCI DSS", Description: "Payment Card Industry Data Security Standard"},
		{ID: "iso27001", Name: "ISO 27001", Description: "Information Security Management System"},
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    frameworks,
		Total:   len(frameworks),
	})
}

func (a *API) handleGenerateReport(w http.ResponseWriter, r *http.Request) {
	if !a.requireCompliance(w) {
		return
	}

	var req struct {
		Framework string `json:"framework"`
		Start     string `json:"start"`
		End       string `json:"end"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if req.Framework == "" {
		writeError(w, http.StatusBadRequest, "framework is required")
		return
	}

	start := time.Now().AddDate(0, -1, 0)
	end := time.Now()
	if req.Start != "" {
		if t, err := time.Parse(time.RFC3339, req.Start); err == nil {
			start = t
		}
	}
	if req.End != "" {
		if t, err := time.Parse(time.RFC3339, req.End); err == nil {
			end = t
		}
	}

	generatedBy := r.Header.Get("X-User")
	if generatedBy == "" {
		generatedBy = "system"
	}

	report, err := a.compliance.gen.Generate(compliance.Framework(req.Framework), start, end, generatedBy)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	a.compliance.mu.Lock()
	a.compliance.reports = append(a.compliance.reports, report)
	a.compliance.mu.Unlock()

	writeJSON(w, http.StatusCreated, APIResponse{
		Success: true,
		Data:    report,
	})
}

func (a *API) handleListReports(w http.ResponseWriter, r *http.Request) {
	if !a.requireCompliance(w) {
		return
	}

	a.compliance.mu.RLock()
	reports := a.compliance.reports
	a.compliance.mu.RUnlock()

	if reports == nil {
		reports = []*compliance.Report{}
	}

	page, perPage := parsePagination(r)
	total := len(reports)
	start, end := paginate(total, page, perPage)

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    reports[start:end],
		Total:   total,
		Page:    page,
		PerPage: perPage,
	})
}

func (a *API) handleGetReport(w http.ResponseWriter, r *http.Request) {
	if !a.requireCompliance(w) {
		return
	}

	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing report id")
		return
	}

	a.compliance.mu.RLock()
	defer a.compliance.mu.RUnlock()

	for _, rpt := range a.compliance.reports {
		if rpt.ID == id {
			writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: rpt})
			return
		}
	}

	writeError(w, http.StatusNotFound, "report not found")
}

func (a *API) handleExportReport(w http.ResponseWriter, r *http.Request) {
	if !a.requireCompliance(w) {
		return
	}

	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing report id")
		return
	}

	a.compliance.mu.RLock()
	var report *compliance.Report
	for _, rpt := range a.compliance.reports {
		if rpt.ID == id {
			report = rpt
			break
		}
	}
	a.compliance.mu.RUnlock()

	if report == nil {
		writeError(w, http.StatusNotFound, "report not found")
		return
	}

	format := r.URL.Query().Get("format")
	switch format {
	case "csv":
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=compliance_report_"+id+".csv")
		if err := a.compliance.gen.ExportCSV(report, w); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
		}
	default:
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=compliance_report_"+id+".json")
		if err := a.compliance.gen.ExportJSON(report, w); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
		}
	}
}

func (a *API) handleComplianceScore(w http.ResponseWriter, r *http.Request) {
	if !a.requireCompliance(w) {
		return
	}

	now := time.Now()
	start := now.AddDate(0, -1, 0)

	scores := make(map[string]interface{})
	for _, fw := range compliance.AllFrameworks() {
		report, err := a.compliance.gen.Generate(fw, start, now, "system")
		if err != nil {
			continue
		}
		scores[string(fw)] = map[string]interface{}{
			"score":       report.Score,
			"pass_count":  report.PassCount,
			"fail_count":  report.FailCount,
			"total_count": report.TotalCount,
		}
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    scores,
	})
}

// ---------------------------------------------------------------------------
// SIEM endpoints
// ---------------------------------------------------------------------------

func (a *API) handleGetSIEMConfig(w http.ResponseWriter, r *http.Request) {
	if !a.requireSIEM(w) {
		return
	}

	a.siemState.mu.RLock()
	cfg := a.siemState.config
	a.siemState.mu.RUnlock()

	// Redact token
	safe := *cfg
	if safe.Token != "" {
		safe.Token = "***"
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    safe,
	})
}

func (a *API) handleUpdateSIEMConfig(w http.ResponseWriter, r *http.Request) {
	if !a.requireSIEM(w) {
		return
	}

	var newCfg siem.SIEMConfig
	if err := readJSON(r, &newCfg); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if newCfg.Endpoint == "" {
		writeError(w, http.StatusBadRequest, "endpoint is required")
		return
	}

	fwd, err := siem.NewForwarder(&newCfg)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	a.siemState.mu.Lock()
	a.siemState.forwarder = fwd
	a.siemState.config = &newCfg
	a.siemState.mu.Unlock()

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    map[string]string{"message": "SIEM configuration updated"},
	})
}

func (a *API) handleTestSIEM(w http.ResponseWriter, r *http.Request) {
	if !a.requireSIEM(w) {
		return
	}

	testEvent := siem.Event{
		Timestamp: time.Now().UTC(),
		Source:    "ssh-proxy",
		EventType: "siem.test",
		Severity:  "info",
		Data: map[string]interface{}{
			"message": "SIEM integration test event",
			"test":    true,
		},
	}

	a.siemState.mu.RLock()
	fwd := a.siemState.forwarder
	a.siemState.mu.RUnlock()

	if err := fwd.Send(testEvent); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to send test event: "+err.Error())
		return
	}

	if err := fwd.Flush(); err != nil {
		writeJSON(w, http.StatusOK, APIResponse{
			Success: true,
			Data: map[string]interface{}{
				"message": "test event sent but flush failed",
				"error":   err.Error(),
			},
		})
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    map[string]string{"message": "test event sent successfully"},
	})
}

func (a *API) handleSIEMStatus(w http.ResponseWriter, r *http.Request) {
	if !a.requireSIEM(w) {
		return
	}

	a.siemState.mu.RLock()
	fwd := a.siemState.forwarder
	cfg := a.siemState.config
	a.siemState.mu.RUnlock()

	status := fwd.Status()

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"type":        string(cfg.Type),
			"endpoint":    cfg.Endpoint,
			"running":     status.Running,
			"buffer_size": status.BufferSize,
			"last_flush":  status.LastFlush,
			"last_error":  status.LastError,
			"events_sent": status.EventsSent,
		},
	})
}

// marshalSIEMConfig is a helper for JSON serialization of SIEMConfig with
// the flush interval as a string.
func marshalSIEMConfig(cfg *siem.SIEMConfig) json.RawMessage {
	type alias siem.SIEMConfig
	raw, _ := json.Marshal(&struct {
		*alias
		FlushInterval string `json:"flush_interval"`
	}{
		alias:         (*alias)(cfg),
		FlushInterval: cfg.FlushInterval.String(),
	})
	return raw
}
