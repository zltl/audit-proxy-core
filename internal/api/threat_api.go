package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/models"
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
	mux.HandleFunc("POST /api/v2/threats/rules", a.handleCreateThreatRule)
	mux.HandleFunc("GET /api/v2/threats/risk", a.handleListThreatRiskAssessments)
	mux.HandleFunc("PUT /api/v2/threats/rules/{id}", a.handleUpdateThreatRule)
	mux.HandleFunc("DELETE /api/v2/threats/rules/{id}", a.handleDeleteThreatRule)
	mux.HandleFunc("GET /api/v2/threats/stats", a.handleThreatStats)
	mux.HandleFunc("POST /api/v2/threats/simulate", a.handleSimulateThreat)
	mux.HandleFunc("POST /api/v2/threats/ingest", a.handleIngestThreatWebhook)
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

func (a *API) handleCreateThreatRule(w http.ResponseWriter, r *http.Request) {
	if !a.requireThreat(w) {
		return
	}
	rule, err := readThreatRulePayload(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	created, err := a.threat.CreateRule(rule)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, APIResponse{Success: true, Data: created})
}

func (a *API) handleUpdateThreatRule(w http.ResponseWriter, r *http.Request) {
	if !a.requireThreat(w) {
		return
	}
	id := r.PathValue("id")
	var body struct {
		Enabled     *bool               `json:"enabled,omitempty"`
		Threshold   *int                `json:"threshold,omitempty"`
		Window      *string             `json:"window,omitempty"`
		Pattern     *string             `json:"pattern,omitempty"`
		Name        *string             `json:"name,omitempty"`
		Description *string             `json:"description,omitempty"`
		Severity    *threat.Severity    `json:"severity,omitempty"`
		Expression  *threat.RuleDSLExpr `json:"expression,omitempty"`
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
	if err := a.threat.UpdateRuleConfig(id, threat.RuleUpdate{
		Enabled:     body.Enabled,
		Threshold:   body.Threshold,
		Window:      windowDur,
		Pattern:     body.Pattern,
		Name:        body.Name,
		Description: body.Description,
		Severity:    body.Severity,
		Expression:  body.Expression,
	}); err != nil {
		status := http.StatusNotFound
		if strings.Contains(err.Error(), "cannot delete built-in") || strings.Contains(err.Error(), "invalid") || strings.Contains(err.Error(), "required") {
			status = http.StatusBadRequest
		}
		writeError(w, status, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: "rule updated"})
}

func (a *API) handleDeleteThreatRule(w http.ResponseWriter, r *http.Request) {
	if !a.requireThreat(w) {
		return
	}
	id := r.PathValue("id")
	if err := a.threat.DeleteRule(id); err != nil {
		status := http.StatusNotFound
		if strings.Contains(err.Error(), "cannot delete built-in") {
			status = http.StatusBadRequest
		}
		writeError(w, status, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    map[string]string{"message": "rule deleted"},
	})
}

func readThreatRulePayload(r *http.Request) (*threat.Rule, error) {
	var body struct {
		ID          string              `json:"id,omitempty"`
		Name        string              `json:"name"`
		Description string              `json:"description,omitempty"`
		Type        threat.RuleType     `json:"type,omitempty"`
		Severity    threat.Severity     `json:"severity,omitempty"`
		Enabled     *bool               `json:"enabled,omitempty"`
		EventTypes  []string            `json:"event_types,omitempty"`
		Threshold   int                 `json:"threshold,omitempty"`
		Window      string              `json:"window,omitempty"`
		Pattern     string              `json:"pattern,omitempty"`
		Field       string              `json:"field,omitempty"`
		GroupBy     string              `json:"group_by,omitempty"`
		Expression  *threat.RuleDSLExpr `json:"expression,omitempty"`
	}
	if err := readJSON(r, &body); err != nil {
		return nil, err
	}
	var window time.Duration
	if strings.TrimSpace(body.Window) != "" {
		parsed, err := time.ParseDuration(strings.TrimSpace(body.Window))
		if err != nil {
			return nil, fmt.Errorf("invalid window duration: %w", err)
		}
		window = parsed
	}
	enabled := true
	if body.Enabled != nil {
		enabled = *body.Enabled
	}
	return &threat.Rule{
		ID:          body.ID,
		Name:        body.Name,
		Description: body.Description,
		Type:        body.Type,
		Severity:    body.Severity,
		Enabled:     enabled,
		Conditions: threat.RuleConditions{
			EventTypes: body.EventTypes,
			Threshold:  body.Threshold,
			Window:     window,
			Pattern:    body.Pattern,
			Field:      body.Field,
			GroupBy:    body.GroupBy,
			Expression: body.Expression,
		},
	}, nil
}

func (a *API) handleListThreatRiskAssessments(w http.ResponseWriter, r *http.Request) {
	if !a.requireThreat(w) {
		return
	}
	q := r.URL.Query()
	assessments := a.threat.GetRiskAssessments(threat.RiskFilter{
		Username: q.Get("username"),
		SourceIP: q.Get("source_ip"),
		Level:    threat.RiskLevel(q.Get("level")),
	})
	if assessments == nil {
		assessments = make([]*threat.RiskAssessment, 0)
	}
	page, perPage := parsePagination(r)
	total := len(assessments)
	start, end := paginate(total, page, perPage)
	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    assessments[start:end],
		Total:   total,
		Page:    page,
		PerPage: perPage,
	})
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
	a.enrichThreatEvent(&event)
	alerts := a.threat.ProcessEvent(&event)
	if alerts == nil {
		alerts = make([]*threat.Alert, 0)
	}
	result := struct {
		AlertsGenerated int                    `json:"alerts_generated"`
		Alerts          []*threat.Alert        `json:"alerts"`
		RiskAssessment  *threat.RiskAssessment `json:"risk_assessment,omitempty"`
	}{
		AlertsGenerated: len(alerts),
		Alerts:          alerts,
		RiskAssessment:  a.threat.CurrentRiskAssessment(&event),
	}
	data, _ := json.Marshal(result)
	var parsed interface{}
	_ = json.Unmarshal(data, &parsed)
	writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: parsed})
}

type threatWebhookPayload struct {
	Event      string `json:"event"`
	Timestamp  int64  `json:"timestamp"`
	Username   string `json:"username"`
	ClientAddr string `json:"client_addr"`
	Detail     string `json:"detail"`
}

func (a *API) handleIngestThreatWebhook(w http.ResponseWriter, r *http.Request) {
	if !a.requireThreat(w) {
		return
	}
	cfg, err := a.loadWebhookDebugConfig()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "data-plane webhook verification is not configured")
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "read request body: "+err.Error())
		return
	}
	if err := verifyThreatWebhookRequest(cfg, r, body); err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}

	var payload threatWebhookPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid webhook payload: "+err.Error())
		return
	}
	if strings.TrimSpace(payload.Event) == "" {
		writeError(w, http.StatusBadRequest, "webhook event is required")
		return
	}
	if !cfg.allowsEvent(payload.Event) {
		writeError(w, http.StatusForbidden, "webhook event is not enabled in data-plane configuration")
		return
	}

	event, handled := mapThreatWebhookPayload(payload)
	result := map[string]interface{}{
		"accepted": true,
		"event":    payload.Event,
		"handled":  handled,
	}
	if !handled {
		writeJSON(w, http.StatusAccepted, APIResponse{Success: true, Data: result})
		return
	}

	a.enrichThreatEvent(event)
	alerts := a.threat.ProcessEvent(event)
	if alerts == nil {
		alerts = make([]*threat.Alert, 0)
	}
	result["alerts_generated"] = len(alerts)
	result["alerts"] = alerts
	if assessment := a.threat.CurrentRiskAssessment(event); assessment != nil {
		result["risk_assessment"] = assessment
	}
	if event.Details != nil {
		if country := strings.TrimSpace(stringValue(event.Details["geo_country"])); country != "" {
			result["geo_country"] = country
		}
		if city := strings.TrimSpace(stringValue(event.Details["geo_city"])); city != "" {
			result["geo_city"] = city
		}
		if code := strings.TrimSpace(stringValue(event.Details["geo_country_code"])); code != "" {
			result["geo_country_code"] = code
		}
	}
	writeJSON(w, http.StatusAccepted, APIResponse{Success: true, Data: result})
}

func verifyThreatWebhookRequest(cfg *webhookDebugConfig, r *http.Request, body []byte) error {
	if cfg == nil {
		return fmt.Errorf("webhook verification is not configured")
	}
	if !cfg.Enabled {
		return fmt.Errorf("data-plane webhook delivery is not enabled")
	}
	if strings.TrimSpace(cfg.AuthHeader) == "" && strings.TrimSpace(cfg.HMACSecret) == "" {
		return fmt.Errorf("configure webhook auth_header or hmac_secret before using the ingest endpoint")
	}
	if auth := strings.TrimSpace(cfg.AuthHeader); auth != "" {
		if got := strings.TrimSpace(r.Header.Get("Authorization")); got != auth {
			return fmt.Errorf("invalid Authorization header")
		}
	}
	if secret := strings.TrimSpace(cfg.HMACSecret); secret != "" {
		rawSig := strings.TrimSpace(r.Header.Get("X-SSH-Proxy-Signature"))
		if !strings.HasPrefix(rawSig, "sha256=") {
			return fmt.Errorf("missing X-SSH-Proxy-Signature header")
		}
		gotSig := strings.TrimPrefix(rawSig, "sha256=")
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		expected := hex.EncodeToString(mac.Sum(nil))
		if !hmac.Equal([]byte(strings.ToLower(gotSig)), []byte(expected)) {
			return fmt.Errorf("invalid webhook signature")
		}
	}
	return nil
}

func mapThreatWebhookPayload(payload threatWebhookPayload) (*threat.Event, bool) {
	event := &threat.Event{
		Timestamp: time.Unix(payload.Timestamp, 0).UTC(),
		Username:  strings.TrimSpace(payload.Username),
		SourceIP:  normalizeThreatSourceIP(payload.ClientAddr),
		Details: map[string]interface{}{
			"webhook_event": payload.Event,
		},
	}
	if payload.Detail != "" {
		event.Details["detail"] = payload.Detail
	}
	switch strings.ToLower(strings.TrimSpace(payload.Event)) {
	case "auth.success":
		event.Type = "auth_success"
	case "auth.failure":
		event.Type = "auth_failure"
	case "session.start":
		event.Type = "connection"
		if target := threatWebhookTarget(payload.Detail); target != "" {
			event.Target = target
			event.Details["target"] = target
		}
	case "session.end":
		event.Type = "session_end"
		if target := threatWebhookTarget(payload.Detail); target != "" {
			event.Target = target
			event.Details["target"] = target
		}
	default:
		return event, false
	}
	return event, true
}

func (a *API) enrichThreatEvent(event *threat.Event) {
	if event == nil {
		return
	}
	if event.Details == nil {
		event.Details = make(map[string]interface{})
	}
	a.enrichThreatEventSourceType(event)
	a.enrichThreatEventSessionContext(event)
}

func (a *API) enrichThreatEventSourceType(event *threat.Event) {
	if event == nil || event.Details == nil {
		return
	}
	if existing := strings.TrimSpace(stringValue(event.Details["source_type"])); existing != "" {
		return
	}
	sourceIP := strings.TrimSpace(event.SourceIP)
	if sourceIP == "" {
		return
	}

	var officeCIDRs []netip.Prefix
	var vpnCIDRs []netip.Prefix
	if office, vpn, err := a.loadThreatSourceCIDRs(); err == nil {
		officeCIDRs = office
		vpnCIDRs = vpn
	}
	if sourceType := classifyThreatSourceType(sourceIP, officeCIDRs, vpnCIDRs); sourceType != "" {
		event.Details["source_type"] = sourceType
	}
}

func (a *API) enrichThreatEventSessionContext(event *threat.Event) {
	if event == nil || a.dp == nil {
		return
	}
	if event.Type != "connection" && event.Type != "session_end" {
		return
	}
	sessions, err := a.dp.ListSessions()
	if err != nil {
		return
	}
	session := matchThreatEventSession(event, sessions)
	if session == nil {
		return
	}
	if event.Details == nil {
		event.Details = make(map[string]interface{})
	}
	if session.TargetHost != "" {
		event.Target = session.TargetHost
		event.Details["target"] = session.TargetHost
	}
	if session.TargetPort > 0 {
		event.Details["target_port"] = session.TargetPort
	}
	if session.ID != "" {
		event.Details["session_id"] = session.ID
	}
	if session.ClientVersion != "" {
		event.Details["client_version"] = session.ClientVersion
	}
	if session.ClientOS != "" {
		event.Details["client_os"] = session.ClientOS
	}
	if session.DeviceFingerprint != "" {
		event.Details["device_fingerprint"] = session.DeviceFingerprint
	}
}

func (a *API) loadThreatSourceCIDRs() ([]netip.Prefix, []netip.Prefix, error) {
	if a.config == nil || strings.TrimSpace(a.config.ConfigFile) == "" {
		return nil, nil, fmt.Errorf("config file is not configured")
	}
	raw, err := os.ReadFile(a.config.ConfigFile)
	if err != nil {
		return nil, nil, err
	}
	doc, err := parseConfigDocument(raw, "")
	if err != nil {
		return nil, nil, err
	}
	office, err := parseThreatCIDRList(
		configStringList(doc["source_office_cidrs"]),
		configStringList(nestedConfigValue(doc, "network_sources", "office_cidrs")),
	)
	if err != nil {
		return nil, nil, err
	}
	vpn, err := parseThreatCIDRList(
		configStringList(doc["source_vpn_cidrs"]),
		configStringList(nestedConfigValue(doc, "network_sources", "vpn_cidrs")),
	)
	if err != nil {
		return nil, nil, err
	}
	return office, vpn, nil
}

func classifyThreatSourceType(sourceIP string, officeCIDRs, vpnCIDRs []netip.Prefix) string {
	addr, err := netip.ParseAddr(strings.TrimSpace(sourceIP))
	if err != nil {
		return ""
	}
	for _, prefix := range vpnCIDRs {
		if prefix.Contains(addr) {
			return "vpn"
		}
	}
	for _, prefix := range officeCIDRs {
		if prefix.Contains(addr) {
			return "office"
		}
	}
	if addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() {
		return ""
	}
	if addr.IsGlobalUnicast() {
		return "public"
	}
	return ""
}

func matchThreatEventSession(event *threat.Event, sessions []models.Session) *models.Session {
	var best *models.Session
	for i := range sessions {
		session := &sessions[i]
		if event.Username != "" && session.Username != event.Username {
			continue
		}
		if event.SourceIP != "" && normalizeThreatSourceIP(session.SourceIP) != event.SourceIP {
			continue
		}
		if event.Target != "" && !strings.EqualFold(session.TargetHost, event.Target) {
			continue
		}
		if best == nil || session.StartTime.After(best.StartTime) {
			best = session
		}
	}
	return best
}

func parseThreatCIDRList(groups ...[]string) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	for _, group := range groups {
		for _, raw := range group {
			value := strings.TrimSpace(raw)
			if value == "" {
				continue
			}
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				addr, addrErr := netip.ParseAddr(value)
				if addrErr != nil {
					return nil, err
				}
				bits := 32
				if addr.Is6() {
					bits = 128
				}
				prefix = netip.PrefixFrom(addr, bits)
			}
			prefixes = append(prefixes, prefix)
		}
	}
	return prefixes, nil
}

func configStringList(value interface{}) []string {
	switch typed := value.(type) {
	case string:
		return parseCommaSeparatedList(typed)
	case []string:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			if trimmed := strings.TrimSpace(item); trimmed != "" {
				out = append(out, trimmed)
			}
		}
		return out
	case []interface{}:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			if trimmed := strings.TrimSpace(fmt.Sprint(item)); trimmed != "" {
				out = append(out, trimmed)
			}
		}
		return out
	default:
		return nil
	}
}

func nestedConfigValue(doc map[string]interface{}, section, key string) interface{} {
	if doc == nil {
		return nil
	}
	raw, ok := doc[section]
	if !ok {
		return nil
	}
	obj, ok := raw.(map[string]interface{})
	if !ok {
		return nil
	}
	return obj[key]
}

func normalizeThreatSourceIP(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		return host
	}
	return strings.Trim(value, "[]")
}

func threatWebhookTarget(detail string) string {
	value := strings.TrimSpace(detail)
	if value == "" {
		return ""
	}
	if _, target, ok := strings.Cut(value, "@"); ok {
		value = target
	}
	if host, port, err := net.SplitHostPort(value); err == nil {
		if host != "" && port != "" {
			return host
		}
	}
	if idx := strings.LastIndex(value, ":"); idx > 0 {
		if _, err := strconv.Atoi(value[idx+1:]); err == nil {
			return value[:idx]
		}
	}
	return value
}

func stringValue(value interface{}) string {
	if s, ok := value.(string); ok {
		return s
	}
	return ""
}
