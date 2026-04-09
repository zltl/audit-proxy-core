package threat

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// RiskLevel is the contextual risk tier derived from a multi-factor assessment.
type RiskLevel string

const (
	RiskLevelLow      RiskLevel = "low"
	RiskLevelMedium   RiskLevel = "medium"
	RiskLevelHigh     RiskLevel = "high"
	RiskLevelCritical RiskLevel = "critical"
)

// RiskFactor is one explainable input into the contextual risk assessment.
type RiskFactor struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Score  int    `json:"score"`
	Detail string `json:"detail,omitempty"`
}

// RiskAssessment is the latest dynamic risk view for a user/source tuple.
type RiskAssessment struct {
	EntityID          string       `json:"entity_id"`
	Username          string       `json:"username,omitempty"`
	SourceIP          string       `json:"source_ip,omitempty"`
	Target            string       `json:"target,omitempty"`
	EventType         string       `json:"event_type"`
	SourceType        string       `json:"source_type,omitempty"`
	DeviceFingerprint string       `json:"device_fingerprint,omitempty"`
	Score             int          `json:"score"`
	Level             RiskLevel    `json:"level"`
	Summary           string       `json:"summary,omitempty"`
	Factors           []RiskFactor `json:"factors,omitempty"`
	LastEventAt       time.Time    `json:"last_event_at"`
	UpdatedAt         time.Time    `json:"updated_at"`
}

// RiskFilter narrows the returned list of current contextual risk assessments.
type RiskFilter struct {
	Username string    `json:"username,omitempty"`
	SourceIP string    `json:"source_ip,omitempty"`
	Level    RiskLevel `json:"level,omitempty"`
}

type riskProfile struct {
	KnownDevices          map[string]time.Time
	LastSuccessfulEventAt time.Time
	LastSuccessfulSource  string
	LastSuccessfulTarget  string
	LastSuccessfulGeo     GeoLocation
	HasLastSuccessfulGeo  bool
}

func isRiskRelevantEvent(eventType string) bool {
	switch eventType {
	case "auth_failure", "auth_success", "connection":
		return true
	default:
		return false
	}
}

func (d *Detector) assessRisk(event *Event) *RiskAssessment {
	if event == nil || !isRiskRelevantEvent(event.Type) {
		return nil
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	assessment := &RiskAssessment{
		EntityID:          riskAssessmentKey(event.Username, event.SourceIP),
		Username:          strings.TrimSpace(event.Username),
		SourceIP:          strings.TrimSpace(event.SourceIP),
		Target:            strings.TrimSpace(event.Target),
		EventType:         strings.TrimSpace(event.Type),
		SourceType:        d.sourceTypeForEvent(event),
		DeviceFingerprint: stringFromDetails(detailsValue(event, "device_fingerprint")),
		LastEventAt:       event.Timestamp.UTC(),
		UpdatedAt:         time.Now().UTC(),
	}

	var factors []RiskFactor
	if factor, ok := d.offHoursRiskFactor(event); ok {
		factors = append(factors, factor)
	}
	if factor, ok := d.sourceTypeRiskFactor(event, assessment.SourceType); ok {
		factors = append(factors, factor)
	}
	if factor, ok := d.newDeviceRiskFactor(event); ok {
		factors = append(factors, factor)
	}
	if factor, ok := d.geoChangeRiskFactor(event); ok {
		factors = append(factors, factor)
	}
	if factor, ok := d.recentFailureRiskFactor(event); ok {
		factors = append(factors, factor)
	}
	if factor, ok := d.targetSpreadRiskFactor(event); ok {
		factors = append(factors, factor)
	}

	sort.Slice(factors, func(i, j int) bool {
		if factors[i].Score == factors[j].Score {
			return factors[i].ID < factors[j].ID
		}
		return factors[i].Score > factors[j].Score
	})

	total := 0
	for _, factor := range factors {
		total += factor.Score
	}
	if total > 100 {
		total = 100
	}
	assessment.Score = total
	assessment.Level = riskLevelForScore(total)
	assessment.Factors = factors
	assessment.Summary = riskSummary(assessment)
	return assessment
}

func (d *Detector) attachRiskAssessment(event *Event, assessment *RiskAssessment) {
	if event == nil || assessment == nil {
		return
	}
	if event.Details == nil {
		event.Details = make(map[string]interface{})
	}
	event.Details["risk_score"] = assessment.Score
	event.Details["risk_level"] = string(assessment.Level)
	event.Details["risk_factors"] = assessment.Factors
	event.Details["risk_assessment"] = assessment
	if assessment.SourceType != "" {
		event.Details["source_type"] = assessment.SourceType
	}
}

func (d *Detector) storeRiskAssessment(assessment *RiskAssessment) {
	if assessment == nil || assessment.EntityID == "" {
		return
	}
	d.mu.Lock()
	d.assessments[assessment.EntityID] = cloneRiskAssessment(assessment)
	d.mu.Unlock()
}

// GetRiskAssessments returns current contextual risk assessments sorted by score.
func (d *Detector) GetRiskAssessments(filter RiskFilter) []*RiskAssessment {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var result []*RiskAssessment
	for _, assessment := range d.assessments {
		if filter.Username != "" && assessment.Username != filter.Username {
			continue
		}
		if filter.SourceIP != "" && assessment.SourceIP != filter.SourceIP {
			continue
		}
		if filter.Level != "" && assessment.Level != filter.Level {
			continue
		}
		result = append(result, cloneRiskAssessment(assessment))
	}
	sortRiskAssessments(result)
	return result
}

func (d *Detector) CurrentRiskAssessment(event *Event) *RiskAssessment {
	if event == nil {
		return nil
	}
	key := riskAssessmentKey(event.Username, event.SourceIP)
	if key == "" {
		return nil
	}
	d.mu.RLock()
	assessment := cloneRiskAssessment(d.assessments[key])
	d.mu.RUnlock()
	return assessment
}

func (d *Detector) updateRiskProfile(event *Event) {
	if event == nil || event.Username == "" {
		return
	}
	if event.Type != "auth_success" && event.Type != "connection" {
		return
	}

	d.mu.Lock()
	profile := d.riskProfiles[event.Username]
	if profile == nil {
		profile = &riskProfile{KnownDevices: make(map[string]time.Time)}
		d.riskProfiles[event.Username] = profile
	}
	if profile.KnownDevices == nil {
		profile.KnownDevices = make(map[string]time.Time)
	}
	if fingerprint := stringFromDetails(detailsValue(event, "device_fingerprint")); fingerprint != "" {
		profile.KnownDevices[fingerprint] = event.Timestamp.UTC()
	}
	profile.LastSuccessfulEventAt = event.Timestamp.UTC()
	profile.LastSuccessfulSource = strings.TrimSpace(event.SourceIP)
	profile.LastSuccessfulTarget = strings.TrimSpace(event.Target)
	if location, ok := geoLocationFromDetails(event.Details); ok {
		profile.LastSuccessfulGeo = location
		profile.HasLastSuccessfulGeo = true
	}
	d.mu.Unlock()
}

func (d *Detector) offHoursRiskFactor(event *Event) (RiskFactor, bool) {
	if event == nil || event.Timestamp.IsZero() {
		return RiskFactor{}, false
	}
	ts := event.Timestamp.UTC()
	score := 0
	reasons := make([]string, 0, 2)
	if ts.Hour() < d.config.BusinessHourStart || ts.Hour() >= d.config.BusinessHourEnd {
		score += 15
		reasons = append(reasons, fmt.Sprintf("outside business hours %02d:00-%02d:00 UTC", d.config.BusinessHourStart, d.config.BusinessHourEnd))
	}
	if ts.Weekday() == time.Saturday || ts.Weekday() == time.Sunday {
		score += 10
		reasons = append(reasons, "weekend activity")
	}
	if score == 0 {
		return RiskFactor{}, false
	}
	return RiskFactor{
		ID:     "off_hours_access",
		Name:   "Off-hours access",
		Score:  score,
		Detail: strings.Join(reasons, "; "),
	}, true
}

func (d *Detector) sourceTypeForEvent(event *Event) string {
	if event == nil {
		return ""
	}
	if explicit := strings.ToLower(strings.TrimSpace(stringFromDetails(detailsValue(event, "source_type")))); explicit != "" {
		return explicit
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(event.SourceIP))
	if err != nil {
		return ""
	}
	if addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() {
		return ""
	}
	if addr.IsGlobalUnicast() {
		return "public"
	}
	return ""
}

func (d *Detector) sourceTypeRiskFactor(event *Event, sourceType string) (RiskFactor, bool) {
	switch strings.ToLower(strings.TrimSpace(sourceType)) {
	case "public":
		return RiskFactor{
			ID:     "public_network",
			Name:   "Public network",
			Score:  20,
			Detail: "access originated from an untrusted public source network",
		}, true
	case "vpn":
		return RiskFactor{
			ID:     "vpn_network",
			Name:   "VPN source",
			Score:  8,
			Detail: "access originated from a remote VPN source instead of the office network",
		}, true
	default:
		return RiskFactor{}, false
	}
}

func (d *Detector) newDeviceRiskFactor(event *Event) (RiskFactor, bool) {
	if event == nil || strings.TrimSpace(event.Username) == "" {
		return RiskFactor{}, false
	}
	fingerprint := stringFromDetails(detailsValue(event, "device_fingerprint"))
	if fingerprint == "" {
		return RiskFactor{}, false
	}

	d.mu.RLock()
	profile := cloneRiskProfile(d.riskProfiles[event.Username])
	d.mu.RUnlock()
	if profile == nil || len(profile.KnownDevices) == 0 {
		return RiskFactor{}, false
	}
	if _, ok := profile.KnownDevices[fingerprint]; ok {
		return RiskFactor{}, false
	}
	detail := "previously unseen device fingerprint"
	if clientVersion := stringFromDetails(detailsValue(event, "client_version")); clientVersion != "" {
		detail = fmt.Sprintf("previously unseen device fingerprint for %s", clientVersion)
	}
	return RiskFactor{
		ID:     "new_device",
		Name:   "New device",
		Score:  25,
		Detail: detail,
	}, true
}

func (d *Detector) geoChangeRiskFactor(event *Event) (RiskFactor, bool) {
	if event == nil || strings.TrimSpace(event.Username) == "" {
		return RiskFactor{}, false
	}
	bt := d.trackerFor("username", event.Username, event.SourceIP)
	if bt == nil {
		return RiskFactor{}, false
	}
	if evidence := d.geoImpossibleTravelEvidence(bt, 30*time.Minute, event); evidence != "" {
		return RiskFactor{
			ID:     "geo_velocity",
			Name:   "Geo anomaly",
			Score:  35,
			Detail: evidence,
		}, true
	}

	currentLoc, ok := geoLocationFromDetails(event.Details)
	if !ok {
		return RiskFactor{}, false
	}

	events := bt.EventsInWindow(1 * time.Hour)
	for _, prior := range events {
		if prior.Timestamp.After(event.Timestamp) || prior.SourceIP == "" || prior.SourceIP == event.SourceIP {
			continue
		}
		if prior.Type != "auth_success" && prior.Type != "connection" {
			continue
		}
		priorLoc, ok := geoLocationFromDetails(prior.Details)
		if !ok || priorLoc.countryKey() == "" || priorLoc.countryKey() == currentLoc.countryKey() {
			continue
		}
		elapsed := event.Timestamp.Sub(prior.Timestamp)
		if elapsed < 0 {
			continue
		}
		return RiskFactor{
			ID:    "country_change",
			Name:  "Location change",
			Score: 15,
			Detail: fmt.Sprintf("country changed from %s to %s since the previous successful login %s ago",
				priorLoc.label(), currentLoc.label(), elapsed.Round(time.Minute)),
		}, true
	}
	return RiskFactor{}, false
}

func (d *Detector) recentFailureRiskFactor(event *Event) (RiskFactor, bool) {
	if event == nil {
		return RiskFactor{}, false
	}
	window := 15 * time.Minute
	count := 0
	if event.Username != "" {
		if bt := d.trackerFor("username", event.Username, event.SourceIP); bt != nil {
			count = maxInt(count, countEventsOfType(bt.EventsInWindow(window), "auth_failure"))
		}
	}
	if event.SourceIP != "" {
		if bt := d.trackerFor("source_ip", event.Username, event.SourceIP); bt != nil {
			count = maxInt(count, countEventsOfType(bt.EventsInWindow(window), "auth_failure"))
		}
	}
	if count < 3 {
		return RiskFactor{}, false
	}
	score := count * 4
	if score > 20 {
		score = 20
	}
	return RiskFactor{
		ID:     "recent_failures",
		Name:   "Recent auth failures",
		Score:  score,
		Detail: fmt.Sprintf("%d authentication failures observed in the last %s", count, window),
	}, true
}

func (d *Detector) targetSpreadRiskFactor(event *Event) (RiskFactor, bool) {
	if event == nil || event.Username == "" {
		return RiskFactor{}, false
	}
	bt := d.trackerFor("username", event.Username, event.SourceIP)
	if bt == nil {
		return RiskFactor{}, false
	}
	targets := bt.UniqueValuesInWindow("target", 15*time.Minute)
	if len(targets) < 3 {
		return RiskFactor{}, false
	}
	score := 15
	if len(targets) >= 5 {
		score = 20
	}
	return RiskFactor{
		ID:     "target_spread",
		Name:   "Target spread",
		Score:  score,
		Detail: fmt.Sprintf("user reached %d distinct targets in the last 15m", len(targets)),
	}, true
}

func riskAssessmentFromEvent(event *Event) *RiskAssessment {
	if event == nil || event.Details == nil {
		return nil
	}
	assessment, _ := event.Details["risk_assessment"].(*RiskAssessment)
	return assessment
}

func riskAssessmentKey(username, sourceIP string) string {
	username = strings.TrimSpace(username)
	sourceIP = strings.TrimSpace(sourceIP)
	switch {
	case username != "" && sourceIP != "":
		return "user:" + username + "|ip:" + sourceIP
	case username != "":
		return "user:" + username
	case sourceIP != "":
		return "ip:" + sourceIP
	default:
		return ""
	}
}

func riskLevelForScore(score int) RiskLevel {
	switch {
	case score >= 80:
		return RiskLevelCritical
	case score >= 60:
		return RiskLevelHigh
	case score >= 35:
		return RiskLevelMedium
	default:
		return RiskLevelLow
	}
}

func riskSummary(assessment *RiskAssessment) string {
	if assessment == nil {
		return ""
	}
	if len(assessment.Factors) == 0 {
		return fmt.Sprintf("Contextual risk score %d (%s)", assessment.Score, assessment.Level)
	}
	parts := make([]string, 0, len(assessment.Factors))
	for _, factor := range assessment.Factors {
		parts = append(parts, fmt.Sprintf("%s (+%d)", factor.Name, factor.Score))
	}
	return fmt.Sprintf("Contextual risk score %d (%s): %s", assessment.Score, assessment.Level, strings.Join(parts, ", "))
}

func sortRiskAssessments(assessments []*RiskAssessment) {
	sort.Slice(assessments, func(i, j int) bool {
		if assessments[i].Score == assessments[j].Score {
			return assessments[i].UpdatedAt.After(assessments[j].UpdatedAt)
		}
		return assessments[i].Score > assessments[j].Score
	})
}

func cloneRiskAssessment(assessment *RiskAssessment) *RiskAssessment {
	if assessment == nil {
		return nil
	}
	out := *assessment
	if len(assessment.Factors) > 0 {
		out.Factors = append([]RiskFactor(nil), assessment.Factors...)
	}
	return &out
}

func cloneRiskProfile(profile *riskProfile) *riskProfile {
	if profile == nil {
		return nil
	}
	out := *profile
	if profile.KnownDevices != nil {
		out.KnownDevices = make(map[string]time.Time, len(profile.KnownDevices))
		for key, value := range profile.KnownDevices {
			out.KnownDevices[key] = value
		}
	}
	return &out
}

func detailsValue(event *Event, key string) interface{} {
	if event == nil || event.Details == nil {
		return nil
	}
	return event.Details[key]
}

func countEventsOfType(events []trackedEvent, eventType string) int {
	count := 0
	for _, event := range events {
		if event.Type == eventType {
			count++
		}
	}
	return count
}

func maxInt(left, right int) int {
	if right > left {
		return right
	}
	return left
}
