package api

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/models"
)

type commandIntentInsight struct {
	EventID    string    `json:"event_id"`
	Username   string    `json:"username"`
	TargetHost string    `json:"target_host,omitempty"`
	Command    string    `json:"command"`
	Intent     string    `json:"intent"`
	Risk       string    `json:"risk"`
	Confidence float64   `json:"confidence"`
	Labels     []string  `json:"labels,omitempty"`
	Timestamp  time.Time `json:"timestamp"`
}

type anomalyDeviation struct {
	EventID    string    `json:"event_id"`
	Username   string    `json:"username"`
	TargetHost string    `json:"target_host,omitempty"`
	Command    string    `json:"command"`
	Intent     string    `json:"intent"`
	Score      float64   `json:"score"`
	Reasons    []string  `json:"reasons"`
	Timestamp  time.Time `json:"timestamp"`
}

type userBaselineProfile struct {
	Username      string             `json:"username"`
	TotalCommands int                `json:"total_commands"`
	TopTargets    []string           `json:"top_targets,omitempty"`
	TopIntents    []string           `json:"top_intents,omitempty"`
	ActiveHours   []int              `json:"active_hours,omitempty"`
	Deviations    []anomalyDeviation `json:"deviations,omitempty"`
}

type privilegeRecommendation struct {
	Username      string            `json:"username"`
	SuggestedRole string            `json:"suggested_role"`
	AllowOps      []string          `json:"allow_ops,omitempty"`
	DenyOps       []string          `json:"deny_ops,omitempty"`
	Conditions    map[string]string `json:"conditions,omitempty"`
	Resources     []string          `json:"resources,omitempty"`
	Rationale     []string          `json:"rationale,omitempty"`
}

type policyPreview struct {
	RawText    string            `json:"raw_text"`
	Rule       models.PolicyRule `json:"rule"`
	Notes      []string          `json:"notes,omitempty"`
	Confidence float64           `json:"confidence"`
}

type auditSummaryInsight struct {
	From             time.Time `json:"from,omitempty"`
	To               time.Time `json:"to,omitempty"`
	TotalEvents      int       `json:"total_events"`
	CommandEvents    int       `json:"command_events"`
	FailedLogins     int       `json:"failed_logins"`
	HighRiskCommands int       `json:"high_risk_commands"`
	TopUsers         []string  `json:"top_users,omitempty"`
	TopTargets       []string  `json:"top_targets,omitempty"`
	Summary          string    `json:"summary"`
}

type commandBaselineAggregate struct {
	total        int
	hours        map[int]int
	targets      map[string]int
	intents      map[string]int
	recentEvents []models.AuditEvent
}

type commandIntentRule struct {
	Intent     string
	Risk       string
	Confidence float64
	Keywords   []string
	Labels     []string
}

var commandIntentRules = []commandIntentRule{
	{Intent: "destructive-change", Risk: "high", Confidence: 0.99, Keywords: []string{"rm -rf", "mkfs", "shutdown", "reboot", "dd if=", "chmod 777", "iptables -f"}, Labels: []string{"destructive", "change"}},
	{Intent: "user-admin", Risk: "high", Confidence: 0.95, Keywords: []string{"useradd", "usermod", "userdel", "passwd", "sudo ", "su -", "visudo"}, Labels: []string{"identity", "privilege"}},
	{Intent: "kubernetes-admin", Risk: "high", Confidence: 0.96, Keywords: []string{"kubectl", "helm ", "k9s"}, Labels: []string{"kubernetes", "platform"}},
	{Intent: "database-admin", Risk: "medium", Confidence: 0.92, Keywords: []string{"mysql ", "psql ", "redis-cli", "mongosh", "pg_dump", "mysqldump"}, Labels: []string{"database"}},
	{Intent: "service-operation", Risk: "medium", Confidence: 0.9, Keywords: []string{"systemctl", "service ", "journalctl"}, Labels: []string{"service"}},
	{Intent: "package-management", Risk: "medium", Confidence: 0.88, Keywords: []string{"apt ", "apt-get", "yum ", "dnf ", "apk ", "pip ", "npm ", "go install"}, Labels: []string{"packages"}},
	{Intent: "file-transfer", Risk: "medium", Confidence: 0.9, Keywords: []string{"scp ", "sftp ", "rsync ", "curl ", "wget "}, Labels: []string{"network", "transfer"}},
	{Intent: "filesystem-maintenance", Risk: "medium", Confidence: 0.82, Keywords: []string{"cp ", "mv ", "mkdir ", "touch ", "sed -i", "tee ", "tar ", "unzip "}, Labels: []string{"filesystem"}},
	{Intent: "network-diagnostics", Risk: "low", Confidence: 0.82, Keywords: []string{"ping ", "traceroute", "dig ", "nslookup", "ss ", "netstat", "nc ", "openssl s_client"}, Labels: []string{"network", "diagnostics"}},
	{Intent: "discovery", Risk: "low", Confidence: 0.75, Keywords: []string{"ls", "pwd", "whoami", "hostname", "uname", "df ", "du ", "find ", "grep ", "cat ", "ps ", "top"}, Labels: []string{"read-only", "discovery"}},
}

func (a *API) RegisterInsightsRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v2/insights/command-intents", a.handleListCommandIntents)
	mux.HandleFunc("GET /api/v2/insights/anomalies", a.handleListAnomalies)
	mux.HandleFunc("GET /api/v2/insights/recommendations", a.handleListPrivilegeRecommendations)
	mux.HandleFunc("POST /api/v2/insights/policy-preview", a.handlePreviewNaturalLanguagePolicy)
	mux.HandleFunc("GET /api/v2/insights/audit-summary", a.handleGetAuditSummaryInsight)
}

func (a *API) handleListCommandIntents(w http.ResponseWriter, r *http.Request) {
	events, err := a.loadAuditEvents()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	items := buildCommandIntentInsights(filterAuditEvents(events, r.URL.Query().Get("user"), r.URL.Query().Get("target_host"), time.Time{}, time.Time{}))
	page, perPage := parsePagination(r)
	total := len(items)
	start, end := paginate(total, page, perPage)
	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    items[start:end],
		Total:   total,
		Page:    page,
		PerPage: perPage,
	})
}

func (a *API) handleListAnomalies(w http.ResponseWriter, r *http.Request) {
	events, err := a.loadAuditEvents()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	events = filterAuditEvents(events, r.URL.Query().Get("user"), "", time.Time{}, time.Time{})
	profiles := buildBaselineProfiles(events)
	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    profiles,
		Total:   len(profiles),
	})
}

func (a *API) handleListPrivilegeRecommendations(w http.ResponseWriter, r *http.Request) {
	events, err := a.loadAuditEvents()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	recommendations := buildPrivilegeRecommendations(filterAuditEvents(events, r.URL.Query().Get("user"), "", time.Time{}, time.Time{}))
	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    recommendations,
		Total:   len(recommendations),
	})
}

func (a *API) handlePreviewNaturalLanguagePolicy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Text string `json:"text"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	preview, err := parseNaturalLanguagePolicy(req.Text)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    preview,
	})
}

func (a *API) handleGetAuditSummaryInsight(w http.ResponseWriter, r *http.Request) {
	events, err := a.loadAuditEvents()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	query := r.URL.Query()
	var fromTime, toTime time.Time
	if raw := strings.TrimSpace(query.Get("from")); raw != "" {
		fromTime, _ = time.Parse(time.RFC3339, raw)
	}
	if raw := strings.TrimSpace(query.Get("to")); raw != "" {
		toTime, _ = time.Parse(time.RFC3339, raw)
	}
	filtered := filterAuditEvents(events, query.Get("user"), "", fromTime, toTime)
	summary := buildAuditSummaryInsight(filtered, fromTime, toTime)
	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    summary,
	})
}

func filterAuditEvents(events []models.AuditEvent, userFilter, targetFilter string, fromTime, toTime time.Time) []models.AuditEvent {
	userFilter = strings.TrimSpace(userFilter)
	targetFilter = strings.TrimSpace(targetFilter)
	filtered := make([]models.AuditEvent, 0, len(events))
	for _, event := range events {
		if userFilter != "" && !strings.EqualFold(event.Username, userFilter) {
			continue
		}
		if targetFilter != "" && !strings.Contains(strings.ToLower(event.TargetHost), strings.ToLower(targetFilter)) {
			continue
		}
		if !fromTime.IsZero() && event.Timestamp.Before(fromTime) {
			continue
		}
		if !toTime.IsZero() && event.Timestamp.After(toTime) {
			continue
		}
		filtered = append(filtered, event)
	}
	return filtered
}

func buildCommandIntentInsights(events []models.AuditEvent) []commandIntentInsight {
	items := make([]commandIntentInsight, 0)
	for _, event := range events {
		if !isCommandAuditEvent(event) {
			continue
		}
		intent, risk, confidence, labels := classifyCommandIntent(event.Details)
		items = append(items, commandIntentInsight{
			EventID:    event.ID,
			Username:   event.Username,
			TargetHost: event.TargetHost,
			Command:    event.Details,
			Intent:     intent,
			Risk:       risk,
			Confidence: confidence,
			Labels:     labels,
			Timestamp:  event.Timestamp,
		})
	}
	return items
}

func buildBaselineProfiles(events []models.AuditEvent) []userBaselineProfile {
	aggregates := make(map[string]*commandBaselineAggregate)
	for _, event := range events {
		if !isCommandAuditEvent(event) {
			continue
		}
		username := strings.TrimSpace(event.Username)
		if username == "" {
			username = "unknown"
		}
		item := aggregates[username]
		if item == nil {
			item = &commandBaselineAggregate{
				hours:   make(map[int]int),
				targets: make(map[string]int),
				intents: make(map[string]int),
			}
			aggregates[username] = item
		}
		item.total++
		item.hours[event.Timestamp.UTC().Hour()]++
		if strings.TrimSpace(event.TargetHost) != "" {
			item.targets[event.TargetHost]++
		}
		intent, _, _, _ := classifyCommandIntent(event.Details)
		item.intents[intent]++
		item.recentEvents = append(item.recentEvents, event)
	}
	profiles := make([]userBaselineProfile, 0, len(aggregates))
	for username, aggregate := range aggregates {
		sort.Slice(aggregate.recentEvents, func(i, j int) bool {
			return aggregate.recentEvents[i].Timestamp.After(aggregate.recentEvents[j].Timestamp)
		})
		recent := aggregate.recentEvents
		if len(recent) > 20 {
			recent = recent[:20]
		}
		profile := userBaselineProfile{
			Username:      username,
			TotalCommands: aggregate.total,
			TopTargets:    topStringCounts(aggregate.targets, 3),
			TopIntents:    topStringCounts(aggregate.intents, 3),
			ActiveHours:   topHourCounts(aggregate.hours, 4),
			Deviations:    buildDeviationList(username, recent, aggregate),
		}
		profiles = append(profiles, profile)
	}
	sort.Slice(profiles, func(i, j int) bool {
		if len(profiles[i].Deviations) == len(profiles[j].Deviations) {
			return profiles[i].Username < profiles[j].Username
		}
		return len(profiles[i].Deviations) > len(profiles[j].Deviations)
	})
	return profiles
}

func buildDeviationList(username string, events []models.AuditEvent, aggregate *commandBaselineAggregate) []anomalyDeviation {
	deviations := make([]anomalyDeviation, 0)
	topTargets := setFromSlice(topStringCounts(aggregate.targets, 2))
	topIntents := setFromSlice(topStringCounts(aggregate.intents, 2))
	topHours := make(map[int]struct{})
	for _, hour := range topHourCounts(aggregate.hours, 3) {
		topHours[hour] = struct{}{}
	}
	for _, event := range events {
		intent, risk, _, _ := classifyCommandIntent(event.Details)
		reasons := make([]string, 0, 4)
		hour := event.Timestamp.UTC().Hour()
		if _, ok := topTargets[event.TargetHost]; !ok && event.TargetHost != "" && aggregate.targets[event.TargetHost] <= 1 {
			reasons = append(reasons, "rare-target")
		}
		if _, ok := topIntents[intent]; !ok && aggregate.intents[intent] <= 1 {
			reasons = append(reasons, "rare-intent")
		}
		if _, ok := topHours[hour]; (!ok && aggregate.total >= 4) || hour < 8 || hour >= 20 {
			reasons = append(reasons, "off-pattern-hours")
		}
		if risk == "high" {
			reasons = append(reasons, "high-risk-command")
		}
		if len(reasons) == 0 {
			continue
		}
		deviations = append(deviations, anomalyDeviation{
			EventID:    event.ID,
			Username:   username,
			TargetHost: event.TargetHost,
			Command:    event.Details,
			Intent:     intent,
			Score:      float64(len(reasons)),
			Reasons:    reasons,
			Timestamp:  event.Timestamp,
		})
	}
	return deviations
}

func buildPrivilegeRecommendations(events []models.AuditEvent) []privilegeRecommendation {
	byUser := make(map[string][]models.AuditEvent)
	for _, event := range events {
		if !isCommandAuditEvent(event) {
			continue
		}
		username := strings.TrimSpace(event.Username)
		if username == "" {
			username = "unknown"
		}
		byUser[username] = append(byUser[username], event)
	}
	items := make([]privilegeRecommendation, 0, len(byUser))
	for username, userEvents := range byUser {
		intents := make(map[string]int)
		targets := make(map[string]int)
		highRisk := 0
		workHoursOnly := true
		for _, event := range userEvents {
			intent, risk, _, _ := classifyCommandIntent(event.Details)
			intents[intent]++
			if event.TargetHost != "" {
				targets[event.TargetHost]++
			}
			if risk == "high" {
				highRisk++
			}
			hour := event.Timestamp.UTC().Hour()
			if hour < 9 || hour >= 18 {
				workHoursOnly = false
			}
		}
		recommendation := privilegeRecommendation{
			Username:      username,
			SuggestedRole: "operator",
			AllowOps:      []string{"shell", "exec"},
			DenyOps:       []string{"scp", "sftp", "port_forward"},
			Resources:     topStringCounts(targets, 3),
			Conditions:    map[string]string{},
			Rationale:     []string{},
		}
		if onlyIntents(intents, "discovery", "network-diagnostics") {
			recommendation.SuggestedRole = "viewer"
			recommendation.Rationale = append(recommendation.Rationale, "Observed commands are read-mostly discovery or diagnostics.")
		}
		if intents["file-transfer"] > 0 {
			recommendation.AllowOps = appendUniqueStrings(recommendation.AllowOps, "scp", "sftp")
			recommendation.DenyOps = removeStrings(recommendation.DenyOps, "scp", "sftp")
			recommendation.Rationale = append(recommendation.Rationale, "Observed file transfer commands require SCP/SFTP access.")
		}
		if intents["network-diagnostics"] > 0 {
			recommendation.AllowOps = appendUniqueStrings(recommendation.AllowOps, "port_forward")
			recommendation.DenyOps = removeStrings(recommendation.DenyOps, "port_forward")
		}
		if highRisk > 0 {
			recommendation.SuggestedRole = "admin"
			recommendation.Rationale = append(recommendation.Rationale, "Observed high-risk commands indicate elevated privileges are already being used.")
		}
		if workHoursOnly {
			recommendation.Conditions["login_window"] = "09:00-18:00"
			recommendation.Conditions["login_days"] = "mon-fri"
			recommendation.Rationale = append(recommendation.Rationale, "Observed activity stayed within work hours; a login window is a safe default.")
		}
		items = append(items, recommendation)
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].Username < items[j].Username
	})
	return items
}

func buildAuditSummaryInsight(events []models.AuditEvent, fromTime, toTime time.Time) auditSummaryInsight {
	commandInsights := buildCommandIntentInsights(events)
	topUsers := countAuditStrings(events, func(event models.AuditEvent) string { return event.Username })
	topTargets := countAuditStrings(events, func(event models.AuditEvent) string { return event.TargetHost })
	failedLogins := 0
	highRiskCommands := 0
	for _, event := range events {
		if strings.Contains(strings.ToLower(event.EventType), "login") && strings.Contains(strings.ToLower(event.Details), "fail") {
			failedLogins++
		}
	}
	for _, item := range commandInsights {
		if item.Risk == "high" {
			highRiskCommands++
		}
	}
	summary := fmt.Sprintf(
		"Observed %d audit events, including %d command events, %d failed logins, and %d high-risk commands. Top users: %s. Top targets: %s.",
		len(events),
		len(commandInsights),
		failedLogins,
		highRiskCommands,
		joinOrNone(topUsers),
		joinOrNone(topTargets),
	)
	return auditSummaryInsight{
		From:             fromTime,
		To:               toTime,
		TotalEvents:      len(events),
		CommandEvents:    len(commandInsights),
		FailedLogins:     failedLogins,
		HighRiskCommands: highRiskCommands,
		TopUsers:         topUsers,
		TopTargets:       topTargets,
		Summary:          summary,
	}
}

func parseNaturalLanguagePolicy(text string) (policyPreview, error) {
	raw := strings.TrimSpace(text)
	if raw == "" {
		return policyPreview{}, fmt.Errorf("text is required")
	}
	lower := strings.ToLower(raw)
	rule := models.PolicyRule{
		Name:       "nl-preview",
		Action:     "allow",
		Role:       "operator",
		Resources:  []string{"*"},
		Operations: []string{"shell"},
		Conditions: map[string]string{},
	}
	notes := make([]string, 0, 4)
	confidence := 0.65

	if strings.Contains(lower, "deny") || strings.Contains(raw, "禁止") {
		rule.Action = "deny"
		confidence += 0.1
	}
	switch {
	case strings.Contains(raw, "运维团队") || strings.Contains(lower, "ops team"):
		rule.Role = "operator"
		confidence += 0.1
	case strings.Contains(raw, "开发团队") || strings.Contains(lower, "developer"):
		rule.Role = "developer"
		confidence += 0.1
	case strings.Contains(raw, "审计") || strings.Contains(lower, "auditor"):
		rule.Role = "viewer"
		confidence += 0.1
	case strings.Contains(raw, "管理员") || strings.Contains(lower, "admin"):
		rule.Role = "admin"
		confidence += 0.1
	}
	switch {
	case strings.Contains(raw, "生产服务器") || strings.Contains(lower, "production"):
		rule.Resources = []string{"prod-*"}
		notes = append(notes, "Mapped production servers to prod-* resource pattern.")
		confidence += 0.1
	case strings.Contains(raw, "测试服务器") || strings.Contains(lower, "staging"):
		rule.Resources = []string{"staging-*"}
		notes = append(notes, "Mapped staging/test servers to staging-* resource pattern.")
		confidence += 0.1
	case strings.Contains(raw, "开发服务器") || strings.Contains(lower, "development"):
		rule.Resources = []string{"dev-*"}
		notes = append(notes, "Mapped development servers to dev-* resource pattern.")
		confidence += 0.1
	}
	switch {
	case strings.Contains(raw, "工作时间") || strings.Contains(lower, "business hours"):
		rule.Conditions["login_window"] = "09:00-18:00"
		rule.Conditions["login_days"] = "mon-fri"
		notes = append(notes, "Expanded work-hours language to 09:00-18:00 on weekdays.")
		confidence += 0.1
	case strings.Contains(raw, "只读") || strings.Contains(lower, "read-only"):
		rule.Operations = []string{"shell"}
		rule.Conditions["access_mode"] = "read-only"
		notes = append(notes, "Mapped read-only intent to shell-only access mode.")
		confidence += 0.1
	}
	if strings.Contains(raw, "上传") || strings.Contains(lower, "upload") {
		rule.Operations = appendUniqueStrings(rule.Operations, "scp", "sftp")
	}
	if strings.Contains(raw, "端口转发") || strings.Contains(lower, "port forward") {
		rule.Operations = appendUniqueStrings(rule.Operations, "port_forward")
	}
	if strings.Contains(raw, "执行命令") || strings.Contains(lower, "exec") || strings.Contains(raw, "访问") {
		rule.Operations = appendUniqueStrings(rule.Operations, "exec")
	}
	sort.Strings(rule.Operations)
	return policyPreview{
		RawText:    raw,
		Rule:       rule,
		Notes:      notes,
		Confidence: confidence,
	}, nil
}

func isCommandAuditEvent(event models.AuditEvent) bool {
	if strings.EqualFold(strings.TrimSpace(event.EventType), "command") {
		return strings.TrimSpace(event.Details) != ""
	}
	return false
}

func classifyCommandIntent(command string) (string, string, float64, []string) {
	lower := strings.ToLower(strings.TrimSpace(command))
	if lower == "" {
		return "unknown", "low", 0.0, nil
	}
	for _, rule := range commandIntentRules {
		for _, keyword := range rule.Keywords {
			if strings.Contains(lower, strings.ToLower(keyword)) {
				return rule.Intent, rule.Risk, rule.Confidence, append([]string(nil), rule.Labels...)
			}
		}
	}
	return "general-execution", "low", 0.55, []string{"generic"}
}

func topStringCounts(counts map[string]int, limit int) []string {
	type item struct {
		Key   string
		Count int
	}
	rows := make([]item, 0, len(counts))
	for key, count := range counts {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		rows = append(rows, item{Key: key, Count: count})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Count == rows[j].Count {
			return rows[i].Key < rows[j].Key
		}
		return rows[i].Count > rows[j].Count
	})
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}
	values := make([]string, 0, len(rows))
	for _, row := range rows {
		values = append(values, row.Key)
	}
	return values
}

func topHourCounts(counts map[int]int, limit int) []int {
	type item struct {
		Hour  int
		Count int
	}
	rows := make([]item, 0, len(counts))
	for hour, count := range counts {
		rows = append(rows, item{Hour: hour, Count: count})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Count == rows[j].Count {
			return rows[i].Hour < rows[j].Hour
		}
		return rows[i].Count > rows[j].Count
	})
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}
	hours := make([]int, 0, len(rows))
	for _, row := range rows {
		hours = append(hours, row.Hour)
	}
	sort.Ints(hours)
	return hours
}

func countAuditStrings(events []models.AuditEvent, selector func(models.AuditEvent) string) []string {
	counts := make(map[string]int)
	for _, event := range events {
		value := strings.TrimSpace(selector(event))
		if value == "" {
			continue
		}
		counts[value]++
	}
	return topStringCounts(counts, 3)
}

func setFromSlice(values []string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		out[value] = struct{}{}
	}
	return out
}

func onlyIntents(counts map[string]int, allowed ...string) bool {
	allowedSet := setFromSlice(allowed)
	for intent, count := range counts {
		if count == 0 {
			continue
		}
		if _, ok := allowedSet[intent]; !ok {
			return false
		}
	}
	return len(counts) > 0
}

func appendUniqueStrings(values []string, extras ...string) []string {
	seen := setFromSlice(values)
	for _, extra := range extras {
		if _, ok := seen[extra]; ok {
			continue
		}
		seen[extra] = struct{}{}
		values = append(values, extra)
	}
	return values
}

func removeStrings(values []string, remove ...string) []string {
	blocked := setFromSlice(remove)
	out := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := blocked[value]; ok {
			continue
		}
		out = append(out, value)
	}
	return out
}

func joinOrNone(values []string) string {
	if len(values) == 0 {
		return "none"
	}
	return strings.Join(values, ", ")
}
