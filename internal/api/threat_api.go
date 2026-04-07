package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/threat"
)

// SetThreat attaches a threat detector to the API for threat detection endpoints.
func (a *API) SetThreat(d *threat.Detector) {
	a.threat = d
}

// RegisterThreatRoutes registers all threat detection routes on the given mux.
func (a *API) RegisterThreatRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v2/threats/alerts", a.handleListThreatAlerts)
	mux.HandleFunc("GET /api/v2/threats/alerts/{id}", a.handleGetThreatAlert)
	mux.HandleFunc("POST /api/v2/threats/alerts/{id}/ack", a.handleAckThreatAlert)
	mux.HandleFunc("POST /api/v2/threats/alerts/{id}/resolve", a.handleResolveThreatAlert)
	mux.HandleFunc("POST /api/v2/threats/alerts/{id}/false-positive", a.handleFalsePositiveThreatAlert)
	mux.HandleFunc("GET /api/v2/threats/rules", a.handleListThreatRules)
	mux.HandleFunc("PUT /api/v2/threats/rules/{id}", a.handleUpdateThreatRule)
	mux.HandleFunc("GET /api/v2/threats/stats", a.handleThreatStats)
	mux.HandleFunc("POST /api/v2/threats/simulate", a.handleSimulateThreat)
}

func (a *API) requireThreat(w http.ResponseWriter) bool {
	if a.threat == nil {
		writeError(w, http.StatusServiceUnavailable, "threat detection is not enabled")
		return false
	}
	return true
}

func (a *API) handleListThreatAlerts(w http.ResponseWriter, r *http.Request) {
	if !a.requireThreat(w) {
		return
	}
	q := r.URL.Query()
	filter := threat.AlertFilter{
		Severity: threat.Severity(q.Get("severity")),
		Status:   threat.AlertStatus(q.Get("status")),
		Username: q.Get("username"),
		SourceIP: q.Get("source_ip"),
		RuleID:   q.Get("rule_id"),
	}
	alerts := a.threat.GetAlerts(filter)
	if alerts == nil {
		alerts = make([]*threat.Alert, 0)
	}
	page, perPage := parsePagination(r)
	total := len(alerts)
	start, end := paginate(total, page, perPage)
	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    alerts[start:end],
		Total:   total,
		Page:    page,
		PerPage: perPage,
	})
}

func (a *API) handleGetThreatAlert(w http.ResponseWriter, r *http.Request) {
	if !a.requireThreat(w) {
		return
	}
	id := r.PathValue("id")
	alert, err := a.threat.GetAlert(id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: alert})
}

func (a *API) handleAckThreatAlert(w http.ResponseWriter, r *http.Request) {
	if !a.requireThreat(w) {
		return
	}
	id := r.PathValue("id")
	var body struct {
		User string `json:"user"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := a.threat.AcknowledgeAlert(id, body.User); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	alert, _ := a.threat.GetAlert(id)
	writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: alert})
}

func (a *API) handleResolveThreatAlert(w http.ResponseWriter, r *http.Request) {
	if !a.requireThreat(w) {
		return
	}
	id := r.PathValue("id")
	var body struct {
		User string `json:"user"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := a.threat.ResolveAlert(id, body.User); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	alert, _ := a.threat.GetAlert(id)
	writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: alert})
}

func (a *API) handleFalsePositiveThreatAlert(w http.ResponseWriter, r *http.Request) {
	if !a.requireThreat(w) {
		return
	}
	id := r.PathValue("id")
	var body struct {
		User string `json:"user"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := a.threat.MarkFalsePositive(id, body.User); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	alert, _ := a.threat.GetAlert(id)
	writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: alert})
}

func (a *API) handleListThreatRules(w http.ResponseWriter, r *http.Request) {
	if !a.requireThreat(w) {
		return
	}
	rules := a.threat.Rules()
	writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: rules, Total: len(rules)})
}

func (a *API) handleUpdateThreatRule(w http.ResponseWriter, r *http.Request) {
	if !a.requireThreat(w) {
		return
	}
	id := r.PathValue("id")
	var body struct {
		Enabled   *bool   `json:"enabled,omitempty"`
		Threshold *int    `json:"threshold,omitempty"`
		Window    *string `json:"window,omitempty"`
		Pattern   *string `json:"pattern,omitempty"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var windowDur *time.Duration
	if body.Window != nil {
		d, err := time.ParseDuration(*body.Window)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid window duration: "+err.Error())
			return
		}
		windowDur = &d
	}
	if err := a.threat.UpdateRule(id, body.Enabled, body.Threshold, windowDur, body.Pattern); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: "rule updated"})
}

func (a *API) handleThreatStats(w http.ResponseWriter, r *http.Request) {
	if !a.requireThreat(w) {
		return
	}
	stats := a.threat.Stats()
	writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: stats})
}

func (a *API) handleSimulateThreat(w http.ResponseWriter, r *http.Request) {
	if !a.requireThreat(w) {
		return
	}
	var event threat.Event
	if err := readJSON(r, &event); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}
	alerts := a.threat.ProcessEvent(&event)
	if alerts == nil {
		alerts = make([]*threat.Alert, 0)
	}
	result := struct {
		AlertsGenerated int             `json:"alerts_generated"`
		Alerts          []*threat.Alert `json:"alerts"`
	}{
		AlertsGenerated: len(alerts),
		Alerts:          alerts,
	}
	data, _ := json.Marshal(result)
	var parsed interface{}
	_ = json.Unmarshal(data, &parsed)
	writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: parsed})
}
