package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/smtp"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/compliance"
)

var errReportScheduleNotFound = errors.New("report schedule not found")

type ReportEmailConfig struct {
	SMTPAddr     string
	SMTPUsername string
	SMTPPassword string
	EmailFrom    string
}

type reportSchedule struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Type       string    `json:"type"`
	Framework  string    `json:"framework,omitempty"`
	TemplateID string    `json:"template_id,omitempty"`
	Subject    string    `json:"subject,omitempty"`
	GDPRType   string    `json:"gdpr_type,omitempty"`
	Format     string    `json:"format"`
	Interval   string    `json:"interval"`
	Lookback   string    `json:"lookback,omitempty"`
	Recipients []string  `json:"recipients"`
	Enabled    bool      `json:"enabled"`
	NextRunAt  time.Time `json:"next_run_at,omitempty"`
	LastRunAt  time.Time `json:"last_run_at,omitempty"`
	LastStatus string    `json:"last_status,omitempty"`
	LastError  string    `json:"last_error,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	CreatedBy  string    `json:"created_by,omitempty"`
	UpdatedBy  string    `json:"updated_by,omitempty"`
}

type reportScheduleStore struct {
	mu        sync.RWMutex
	path      string
	schedules map[string]reportSchedule
}

type reportScheduler struct {
	api      *API
	store    *reportScheduleStore
	cfg      ReportEmailConfig
	sendMail func(addr string, a smtp.Auth, from string, to []string, msg []byte) error
	now      func() time.Time
}

func newReportScheduleStore(path string) *reportScheduleStore {
	store := &reportScheduleStore{
		path:      path,
		schedules: make(map[string]reportSchedule),
	}
	store.load()
	return store
}

func (s *reportScheduleStore) load() {
	if s == nil || strings.TrimSpace(s.path) == "" {
		return
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	var schedules []reportSchedule
	if err := json.Unmarshal(data, &schedules); err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, schedule := range schedules {
		s.schedules[schedule.ID] = schedule
	}
}

func (s *reportScheduleStore) saveLocked() error {
	schedules := make([]reportSchedule, 0, len(s.schedules))
	for _, schedule := range s.schedules {
		schedules = append(schedules, schedule)
	}
	sort.Slice(schedules, func(i, j int) bool {
		if schedules[i].Name == schedules[j].Name {
			return schedules[i].ID < schedules[j].ID
		}
		return schedules[i].Name < schedules[j].Name
	})
	data, err := json.MarshalIndent(schedules, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0o600)
}

func (s *reportScheduleStore) list() []reportSchedule {
	if s == nil {
		return []reportSchedule{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	schedules := make([]reportSchedule, 0, len(s.schedules))
	for _, schedule := range s.schedules {
		schedules = append(schedules, schedule)
	}
	sort.Slice(schedules, func(i, j int) bool {
		if schedules[i].Name == schedules[j].Name {
			return schedules[i].ID < schedules[j].ID
		}
		return schedules[i].Name < schedules[j].Name
	})
	return schedules
}

func (s *reportScheduleStore) get(id string) (reportSchedule, bool) {
	if s == nil {
		return reportSchedule{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	schedule, ok := s.schedules[id]
	return schedule, ok
}

func (s *reportScheduleStore) create(schedule reportSchedule) (reportSchedule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if schedule.ID == "" {
		schedule.ID = newReportScheduleID()
	}
	if _, exists := s.schedules[schedule.ID]; exists {
		return reportSchedule{}, fmt.Errorf("report schedule already exists")
	}
	s.schedules[schedule.ID] = schedule
	if err := s.saveLocked(); err != nil {
		delete(s.schedules, schedule.ID)
		return reportSchedule{}, err
	}
	return schedule, nil
}

func (s *reportScheduleStore) update(id string, schedule reportSchedule) (reportSchedule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.schedules[id]; !exists {
		return reportSchedule{}, errReportScheduleNotFound
	}
	schedule.ID = id
	s.schedules[id] = schedule
	if err := s.saveLocked(); err != nil {
		return reportSchedule{}, err
	}
	return schedule, nil
}

func (s *reportScheduleStore) patch(id string, mutate func(*reportSchedule) error) (reportSchedule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	schedule, exists := s.schedules[id]
	if !exists {
		return reportSchedule{}, errReportScheduleNotFound
	}
	if err := mutate(&schedule); err != nil {
		return reportSchedule{}, err
	}
	s.schedules[id] = schedule
	if err := s.saveLocked(); err != nil {
		return reportSchedule{}, err
	}
	return schedule, nil
}

func (s *reportScheduleStore) delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.schedules[id]; !exists {
		return errReportScheduleNotFound
	}
	delete(s.schedules, id)
	return s.saveLocked()
}

func newReportScheduler(api *API, store *reportScheduleStore, cfg ReportEmailConfig) *reportScheduler {
	return &reportScheduler{
		api:      api,
		store:    store,
		cfg:      cfg,
		sendMail: smtp.SendMail,
		now:      func() time.Time { return time.Now().UTC() },
	}
}

func (s *reportScheduler) configured() bool {
	return strings.TrimSpace(s.cfg.SMTPAddr) != "" && strings.TrimSpace(s.cfg.EmailFrom) != ""
}

func (s *reportScheduler) start(ctx context.Context) {
	if s == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			s.runDueSchedulesOnce()
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

func (s *reportScheduler) runDueSchedulesOnce() {
	if s == nil || !s.configured() {
		return
	}
	now := s.now()
	for _, schedule := range s.store.list() {
		if !schedule.Enabled {
			continue
		}
		if !schedule.NextRunAt.IsZero() && schedule.NextRunAt.After(now) {
			continue
		}
		_, _ = s.runSchedule(schedule.ID)
	}
}

func (s *reportScheduler) runSchedule(id string) (reportSchedule, error) {
	schedule, ok := s.store.get(id)
	if !ok {
		return reportSchedule{}, errReportScheduleNotFound
	}
	now := s.now()
	if !schedule.Enabled {
		return reportSchedule{}, fmt.Errorf("report schedule is disabled")
	}
	attachmentName, contentType, payload, subject, err := s.renderSchedule(schedule, now)
	if err == nil {
		err = s.sendEmail(schedule.Recipients, subject, attachmentName, contentType, payload)
	}
	interval, parseErr := time.ParseDuration(schedule.Interval)
	if parseErr != nil {
		interval = time.Hour
	}
	updated, patchErr := s.store.patch(id, func(current *reportSchedule) error {
		current.LastRunAt = now
		current.NextRunAt = now.Add(interval)
		current.UpdatedAt = now
		if err != nil {
			current.LastStatus = "error"
			current.LastError = err.Error()
		} else {
			current.LastStatus = "sent"
			current.LastError = ""
		}
		return nil
	})
	if patchErr != nil {
		return reportSchedule{}, patchErr
	}
	return updated, err
}

func (s *reportScheduler) renderSchedule(schedule reportSchedule, now time.Time) (attachmentName, contentType string, payload []byte, subject string, err error) {
	switch schedule.Type {
	case "framework":
		start, end, err := scheduledReportWindow(schedule, now)
		if err != nil {
			return "", "", nil, "", err
		}
		report, err := s.api.compliance.gen.Generate(compliance.Framework(schedule.Framework), start, end, "scheduler")
		if err != nil {
			return "", "", nil, "", err
		}
		var buf bytes.Buffer
		switch normalizeScheduleFormat(schedule.Format, "csv") {
		case "json":
			contentType = "application/json"
			attachmentName = schedule.ID + ".json"
			err = s.api.compliance.gen.ExportJSON(report, &buf)
		default:
			contentType = "text/csv"
			attachmentName = schedule.ID + ".csv"
			err = s.api.compliance.gen.ExportCSV(report, &buf)
		}
		if err != nil {
			return "", "", nil, "", err
		}
		return attachmentName, contentType, buf.Bytes(), fmt.Sprintf("%s (%s)", schedule.Name, schedule.Framework), nil
	case "gdpr":
		start, end, err := scheduledReportWindow(schedule, now)
		if err != nil {
			return "", "", nil, "", err
		}
		report, err := s.api.compliance.gen.GenerateGDPRDataReport(compliance.GDPRDataReportKind(schedule.GDPRType), schedule.Subject, start, end, "scheduler")
		if err != nil {
			return "", "", nil, "", err
		}
		var buf bytes.Buffer
		switch normalizeScheduleFormat(schedule.Format, "json") {
		case "csv":
			contentType = "text/csv"
			attachmentName = schedule.ID + ".csv"
			err = s.api.compliance.gen.ExportGDPRDataCSV(report, &buf)
		default:
			contentType = "application/json"
			attachmentName = schedule.ID + ".json"
			err = s.api.compliance.gen.ExportGDPRDataJSON(report, &buf)
		}
		if err != nil {
			return "", "", nil, "", err
		}
		return attachmentName, contentType, buf.Bytes(), fmt.Sprintf("%s (GDPR %s)", schedule.Name, schedule.GDPRType), nil
	case "template":
		template, ok := s.api.compliance.templates.get(schedule.TemplateID)
		if !ok {
			return "", "", nil, "", fmt.Errorf("report template not found")
		}
		result, err := s.api.compliance.gen.ExecuteCustomReportTemplate(template)
		if err != nil {
			return "", "", nil, "", err
		}
		var buf bytes.Buffer
		switch normalizeScheduleFormat(schedule.Format, template.DefaultFormat) {
		case "pdf":
			contentType = "application/pdf"
			attachmentName = schedule.ID + ".pdf"
			err = s.api.compliance.gen.ExportCustomReportPDF(result, &buf)
		default:
			contentType = "text/csv"
			attachmentName = schedule.ID + ".csv"
			err = s.api.compliance.gen.ExportCustomReportCSV(result, &buf)
		}
		if err != nil {
			return "", "", nil, "", err
		}
		return attachmentName, contentType, buf.Bytes(), fmt.Sprintf("%s (%s)", schedule.Name, template.Name), nil
	default:
		return "", "", nil, "", fmt.Errorf("unsupported schedule type: %s", schedule.Type)
	}
}

func scheduledReportWindow(schedule reportSchedule, now time.Time) (time.Time, time.Time, error) {
	lookback := strings.TrimSpace(schedule.Lookback)
	if lookback == "" {
		lookback = schedule.Interval
	}
	duration, err := time.ParseDuration(lookback)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("invalid lookback: %w", err)
	}
	return now.Add(-duration), now, nil
}

func (s *reportScheduler) sendEmail(to []string, subject, attachmentName, contentType string, payload []byte) error {
	if !s.configured() {
		return fmt.Errorf("report email transport is not configured")
	}
	host := s.cfg.SMTPAddr
	if idx := strings.IndexByte(host, ':'); idx > 0 {
		host = host[:idx]
	}
	var auth smtp.Auth
	if s.cfg.SMTPUsername != "" || s.cfg.SMTPPassword != "" {
		auth = smtp.PlainAuth("", s.cfg.SMTPUsername, s.cfg.SMTPPassword, host)
	}
	msg := buildReportEmailMessage(s.cfg.EmailFrom, to, subject, attachmentName, contentType, payload)
	if err := s.sendMail(s.cfg.SMTPAddr, auth, s.cfg.EmailFrom, to, []byte(msg)); err != nil {
		return fmt.Errorf("send smtp mail: %w", err)
	}
	return nil
}

func buildReportEmailMessage(from string, to []string, subject, attachmentName, contentType string, payload []byte) string {
	boundary := "sshproxy-report-boundary"
	var buf strings.Builder
	buf.WriteString(fmt.Sprintf("From: %s\r\n", from))
	buf.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(to, ", ")))
	buf.WriteString(fmt.Sprintf("Subject: %s\r\n", subject))
	buf.WriteString("MIME-Version: 1.0\r\n")
	buf.WriteString(fmt.Sprintf("Content-Type: multipart/mixed; boundary=%q\r\n", boundary))
	buf.WriteString("\r\n")
	buf.WriteString("--" + boundary + "\r\n")
	buf.WriteString("Content-Type: text/plain; charset=UTF-8\r\n\r\n")
	buf.WriteString("Scheduled compliance report generated by ssh-proxy-core.\r\n\r\n")
	buf.WriteString("--" + boundary + "\r\n")
	buf.WriteString(fmt.Sprintf("Content-Type: %s\r\n", contentType))
	buf.WriteString("Content-Transfer-Encoding: base64\r\n")
	buf.WriteString(fmt.Sprintf("Content-Disposition: attachment; filename=%q\r\n\r\n", attachmentName))
	encoded := base64.StdEncoding.EncodeToString(payload)
	for len(encoded) > 76 {
		buf.WriteString(encoded[:76] + "\r\n")
		encoded = encoded[76:]
	}
	buf.WriteString(encoded + "\r\n")
	buf.WriteString("--" + boundary + "--\r\n")
	return buf.String()
}

func normalizeScheduleFormat(format, fallback string) string {
	format = strings.ToLower(strings.TrimSpace(format))
	if format == "" {
		format = strings.ToLower(strings.TrimSpace(fallback))
	}
	if format == "" {
		return "csv"
	}
	return format
}

func newReportScheduleID() string {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return fmt.Sprintf("sched-%d", time.Now().UnixNano())
	}
	return "sched-" + hex.EncodeToString(raw[:])
}

func (a *API) StartReportScheduler(ctx context.Context, cfg ReportEmailConfig) {
	if a == nil || a.compliance == nil {
		return
	}
	if a.compliance.schedules == nil {
		a.compliance.schedules = newReportScheduleStore(dataFilePath(a.config.DataDir, "report_schedules.json"))
	}
	if a.compliance.scheduler == nil {
		a.compliance.scheduler = newReportScheduler(a, a.compliance.schedules, cfg)
		a.compliance.scheduler.start(ctx)
	}
}

func (a *API) handleListReportSchedules(w http.ResponseWriter, r *http.Request) {
	if !a.requireCompliance(w) {
		return
	}
	schedules := a.compliance.schedules.list()
	writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: schedules, Total: len(schedules)})
}

func (a *API) handleGetReportSchedule(w http.ResponseWriter, r *http.Request) {
	if !a.requireCompliance(w) {
		return
	}
	schedule, ok := a.compliance.schedules.get(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "report schedule not found")
		return
	}
	writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: schedule})
}

func (a *API) handleCreateReportSchedule(w http.ResponseWriter, r *http.Request) {
	if !a.requireCompliance(w) {
		return
	}
	schedule, err := a.readReportSchedulePayload(r, reportSchedule{})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	schedule, err = a.compliance.schedules.create(schedule)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, APIResponse{Success: true, Data: schedule})
}

func (a *API) handleUpdateReportSchedule(w http.ResponseWriter, r *http.Request) {
	if !a.requireCompliance(w) {
		return
	}
	existing, ok := a.compliance.schedules.get(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "report schedule not found")
		return
	}
	schedule, err := a.readReportSchedulePayload(r, existing)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	schedule, err = a.compliance.schedules.update(existing.ID, schedule)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: schedule})
}

func (a *API) handleDeleteReportSchedule(w http.ResponseWriter, r *http.Request) {
	if !a.requireCompliance(w) {
		return
	}
	if err := a.compliance.schedules.delete(r.PathValue("id")); err != nil {
		if errors.Is(err, errReportScheduleNotFound) {
			writeError(w, http.StatusNotFound, "report schedule not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: map[string]string{"message": "Report schedule deleted"}})
}

func (a *API) handleRunReportSchedule(w http.ResponseWriter, r *http.Request) {
	if !a.requireCompliance(w) {
		return
	}
	if a.compliance.scheduler == nil || !a.compliance.scheduler.configured() {
		writeError(w, http.StatusServiceUnavailable, "report email transport is not configured")
		return
	}
	schedule, err := a.compliance.scheduler.runSchedule(r.PathValue("id"))
	if err != nil {
		if errors.Is(err, errReportScheduleNotFound) {
			writeError(w, http.StatusNotFound, "report schedule not found")
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: schedule})
}

func (a *API) readReportSchedulePayload(r *http.Request, base reportSchedule) (reportSchedule, error) {
	var req struct {
		ID         string   `json:"id"`
		Name       string   `json:"name"`
		Type       string   `json:"type"`
		Framework  string   `json:"framework"`
		TemplateID string   `json:"template_id"`
		Subject    string   `json:"subject"`
		GDPRType   string   `json:"gdpr_type"`
		Format     string   `json:"format"`
		Interval   string   `json:"interval"`
		Lookback   string   `json:"lookback"`
		Recipients []string `json:"recipients"`
		Enabled    *bool    `json:"enabled"`
	}
	if err := readJSON(r, &req); err != nil {
		return reportSchedule{}, err
	}
	now := time.Now().UTC()
	if base.ID == "" {
		base.CreatedAt = now
	}
	base.ID = strings.TrimSpace(req.ID)
	base.Name = strings.TrimSpace(req.Name)
	base.Type = strings.ToLower(strings.TrimSpace(req.Type))
	base.Framework = strings.TrimSpace(req.Framework)
	base.TemplateID = strings.TrimSpace(req.TemplateID)
	base.Subject = strings.TrimSpace(req.Subject)
	base.GDPRType = strings.ToLower(strings.TrimSpace(req.GDPRType))
	base.Format = strings.ToLower(strings.TrimSpace(req.Format))
	base.Interval = strings.TrimSpace(req.Interval)
	base.Lookback = strings.TrimSpace(req.Lookback)
	base.Recipients = sanitizeRecipients(req.Recipients)
	if req.Enabled == nil && base.ID == "" {
		base.Enabled = true
	}
	if req.Enabled != nil {
		base.Enabled = *req.Enabled
	}
	base.UpdatedAt = now
	user := strings.TrimSpace(r.Header.Get("X-User"))
	if base.CreatedBy == "" {
		base.CreatedBy = user
	}
	base.UpdatedBy = user
	if err := a.validateReportSchedule(base); err != nil {
		return reportSchedule{}, err
	}
	if base.NextRunAt.IsZero() || base.ID == "" {
		interval, _ := time.ParseDuration(base.Interval)
		base.NextRunAt = now.Add(interval)
	}
	return base, nil
}

func (a *API) validateReportSchedule(schedule reportSchedule) error {
	if strings.TrimSpace(schedule.Name) == "" {
		return fmt.Errorf("schedule name is required")
	}
	if len(schedule.Recipients) == 0 {
		return fmt.Errorf("at least one recipient is required")
	}
	interval, err := time.ParseDuration(schedule.Interval)
	if err != nil || interval <= 0 {
		return fmt.Errorf("valid interval is required")
	}
	if schedule.Lookback != "" {
		lookback, err := time.ParseDuration(schedule.Lookback)
		if err != nil || lookback <= 0 {
			return fmt.Errorf("lookback must be a valid duration")
		}
	}
	switch schedule.Type {
	case "framework":
		if !isSupportedFramework(schedule.Framework) {
			return fmt.Errorf("unsupported framework")
		}
		switch normalizeScheduleFormat(schedule.Format, "csv") {
		case "csv", "json":
		default:
			return fmt.Errorf("framework schedules support csv or json format")
		}
	case "gdpr":
		if strings.TrimSpace(schedule.Subject) == "" {
			return fmt.Errorf("subject is required for gdpr schedules")
		}
		switch compliance.GDPRDataReportKind(schedule.GDPRType) {
		case compliance.GDPRDataReportAccess, compliance.GDPRDataReportDeletion:
		default:
			return fmt.Errorf("unsupported gdpr report type")
		}
		switch normalizeScheduleFormat(schedule.Format, "json") {
		case "csv", "json":
		default:
			return fmt.Errorf("gdpr schedules support csv or json format")
		}
	case "template":
		if _, ok := a.compliance.templates.get(schedule.TemplateID); !ok {
			return fmt.Errorf("report template not found")
		}
		switch normalizeScheduleFormat(schedule.Format, "csv") {
		case "csv", "pdf":
		default:
			return fmt.Errorf("template schedules support csv or pdf format")
		}
	default:
		return fmt.Errorf("unsupported schedule type")
	}
	return nil
}

func sanitizeRecipients(in []string) []string {
	out := make([]string, 0, len(in))
	for _, recipient := range in {
		recipient = strings.TrimSpace(recipient)
		if recipient != "" {
			out = append(out, recipient)
		}
	}
	return out
}

func isSupportedFramework(framework string) bool {
	for _, candidate := range compliance.AllFrameworks() {
		if string(candidate) == framework {
			return true
		}
	}
	return false
}
