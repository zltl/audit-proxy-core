package api

import (
	"encoding/json"
	"net/http"
	"net/smtp"
	"strings"
	"testing"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/compliance"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/models"
)

func setupComplianceTestAPI(t *testing.T) (*API, *http.ServeMux) {
	t.Helper()
	api, mux, _ := setupTestAPI(t)
	if err := api.users.create(models.User{
		Username:    "alice",
		DisplayName: "Alice",
		Email:       "alice@example.com",
		Role:        "operator",
		Enabled:     true,
	}); err != nil {
		t.Fatalf("users.create(alice): %v", err)
	}
	gen := compliance.NewReportGenerator(api.config.AuditLogDir, api.config.ConfigFile, api.config.DataDir)
	gen.SetSubjectDataProvider(api.ComplianceDataProvider())
	gen.SetQueryDataProvider(api.ComplianceDataProvider())
	api.SetCompliance(gen)
	api.RegisterComplianceRoutes(mux)
	return api, mux
}

func TestGenerateGDPRDataReportRoute(t *testing.T) {
	_, mux := setupComplianceTestAPI(t)
	rr := doRequest(mux, http.MethodPost, "/api/v2/compliance/gdpr/reports", map[string]any{
		"type":    "access",
		"subject": "alice",
		"start":   time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339),
		"end":     time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339),
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("POST /api/v2/compliance/gdpr/reports status = %d body = %s", rr.Code, rr.Body.String())
	}
	var resp APIResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json.Unmarshal(): %v", err)
	}
	data, err := json.Marshal(resp.Data)
	if err != nil {
		t.Fatalf("json.Marshal(resp.Data): %v", err)
	}
	var report compliance.GDPRDataReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("json.Unmarshal(report): %v", err)
	}
	if report.Subject != "alice" || report.Kind != compliance.GDPRDataReportAccess {
		t.Fatalf("unexpected report = %+v", report)
	}
	if len(report.Sessions) != 2 {
		t.Fatalf("sessions = %d, want 2", len(report.Sessions))
	}
	if len(report.AuditEvents) != 1 {
		t.Fatalf("audit events = %d, want 1", len(report.AuditEvents))
	}
}

func TestExportGDPRDataReportCSVRoute(t *testing.T) {
	_, mux := setupComplianceTestAPI(t)
	create := doRequest(mux, http.MethodPost, "/api/v2/compliance/gdpr/reports", map[string]any{
		"type":    "deletion",
		"subject": "alice",
		"start":   time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339),
		"end":     time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339),
	})
	if create.Code != http.StatusCreated {
		t.Fatalf("POST /api/v2/compliance/gdpr/reports status = %d body = %s", create.Code, create.Body.String())
	}
	var resp APIResponse
	if err := json.Unmarshal(create.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json.Unmarshal(): %v", err)
	}
	data, err := json.Marshal(resp.Data)
	if err != nil {
		t.Fatalf("json.Marshal(resp.Data): %v", err)
	}
	var report compliance.GDPRDataReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("json.Unmarshal(report): %v", err)
	}

	export := doRequest(mux, http.MethodGet, "/api/v2/compliance/gdpr/reports/"+report.ID+"/export?format=csv", nil)
	if export.Code != http.StatusOK {
		t.Fatalf("GET export status = %d body = %s", export.Code, export.Body.String())
	}
	if contentType := export.Header().Get("Content-Type"); !strings.Contains(contentType, "text/csv") {
		t.Fatalf("Content-Type = %q, want text/csv", contentType)
	}
	if !strings.Contains(export.Body.String(), "record_type") {
		t.Fatalf("expected csv header in body, got %s", export.Body.String())
	}
}

func TestCreateAndExportCustomReportTemplateRoute(t *testing.T) {
	_, mux := setupComplianceTestAPI(t)
	create := doRequest(mux, http.MethodPost, "/api/v2/compliance/templates", map[string]any{
		"name":           "Sessions by user",
		"query":          "SELECT username, COUNT(*) AS sessions FROM sessions GROUP BY username ORDER BY username",
		"default_format": "csv",
	})
	if create.Code != http.StatusCreated {
		t.Fatalf("POST /api/v2/compliance/templates status = %d body = %s", create.Code, create.Body.String())
	}
	var resp APIResponse
	if err := json.Unmarshal(create.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json.Unmarshal(): %v", err)
	}
	data, err := json.Marshal(resp.Data)
	if err != nil {
		t.Fatalf("json.Marshal(resp.Data): %v", err)
	}
	var template compliance.CustomReportTemplate
	if err := json.Unmarshal(data, &template); err != nil {
		t.Fatalf("json.Unmarshal(template): %v", err)
	}
	if template.ID == "" {
		t.Fatal("expected template ID")
	}

	export := doRequest(mux, http.MethodGet, "/api/v2/compliance/templates/"+template.ID+"/export?format=csv", nil)
	if export.Code != http.StatusOK {
		t.Fatalf("GET template export status = %d body = %s", export.Code, export.Body.String())
	}
	if !strings.Contains(export.Body.String(), "username,sessions") {
		t.Fatalf("unexpected csv body: %s", export.Body.String())
	}
}

func TestCreateAndRunReportScheduleRoute(t *testing.T) {
	api, mux := setupComplianceTestAPI(t)
	api.compliance.scheduler = newReportScheduler(api, api.compliance.schedules, ReportEmailConfig{
		SMTPAddr:  "smtp.example.com:25",
		EmailFrom: "reports@example.com",
	})
	var sentMessage string
	api.compliance.scheduler.sendMail = func(addr string, _ smtp.Auth, from string, to []string, msg []byte) error {
		if addr != "smtp.example.com:25" || from != "reports@example.com" {
			t.Fatalf("unexpected smtp transport: %s %s", addr, from)
		}
		if len(to) != 1 || to[0] != "audit@example.com" {
			t.Fatalf("unexpected recipients: %+v", to)
		}
		sentMessage = string(msg)
		return nil
	}

	createTemplate := doRequest(mux, http.MethodPost, "/api/v2/compliance/templates", map[string]any{
		"name":           "Sessions by user",
		"query":          "SELECT username, COUNT(*) AS sessions FROM sessions GROUP BY username ORDER BY username",
		"default_format": "csv",
	})
	if createTemplate.Code != http.StatusCreated {
		t.Fatalf("POST /api/v2/compliance/templates status = %d body = %s", createTemplate.Code, createTemplate.Body.String())
	}
	var templateResp APIResponse
	if err := json.Unmarshal(createTemplate.Body.Bytes(), &templateResp); err != nil {
		t.Fatalf("json.Unmarshal(template response): %v", err)
	}
	templateData, _ := json.Marshal(templateResp.Data)
	var template compliance.CustomReportTemplate
	if err := json.Unmarshal(templateData, &template); err != nil {
		t.Fatalf("json.Unmarshal(template): %v", err)
	}

	createSchedule := doRequest(mux, http.MethodPost, "/api/v2/compliance/schedules", map[string]any{
		"name":        "Nightly custom report",
		"type":        "template",
		"template_id": template.ID,
		"format":      "csv",
		"interval":    "1h",
		"recipients":  []string{"audit@example.com"},
	})
	if createSchedule.Code != http.StatusCreated {
		t.Fatalf("POST /api/v2/compliance/schedules status = %d body = %s", createSchedule.Code, createSchedule.Body.String())
	}
	var scheduleResp APIResponse
	if err := json.Unmarshal(createSchedule.Body.Bytes(), &scheduleResp); err != nil {
		t.Fatalf("json.Unmarshal(schedule response): %v", err)
	}
	scheduleData, _ := json.Marshal(scheduleResp.Data)
	var schedule reportSchedule
	if err := json.Unmarshal(scheduleData, &schedule); err != nil {
		t.Fatalf("json.Unmarshal(schedule): %v", err)
	}

	run := doRequest(mux, http.MethodPost, "/api/v2/compliance/schedules/"+schedule.ID+"/run", nil)
	if run.Code != http.StatusOK {
		t.Fatalf("POST /api/v2/compliance/schedules/{id}/run status = %d body = %s", run.Code, run.Body.String())
	}
	if !strings.Contains(sentMessage, "Content-Disposition: attachment; filename=") {
		t.Fatalf("expected attachment in email message, got %s", sentMessage)
	}
	if !strings.Contains(sentMessage, "Scheduled compliance report generated by ssh-proxy-core.") {
		t.Fatalf("expected email body, got %s", sentMessage)
	}
}
