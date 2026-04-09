package compliance

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/models"
)

// SubjectDataProvider supplies per-user data inventory for GDPR reports.
type SubjectDataProvider interface {
	GetUser(username string) (models.User, bool, error)
	ListSessions(username string, start, end time.Time) ([]models.Session, error)
	ListAuditEvents(username string, start, end time.Time) ([]models.AuditEvent, error)
}

// GDPRDataReportKind identifies the type of GDPR subject report.
type GDPRDataReportKind string

const (
	GDPRDataReportAccess   GDPRDataReportKind = "access"
	GDPRDataReportDeletion GDPRDataReportKind = "deletion"
)

// GDPRAccountSnapshot is the sanitized subject account state included in GDPR reports.
type GDPRAccountSnapshot struct {
	Username    string    `json:"username"`
	DisplayName string    `json:"display_name,omitempty"`
	Email       string    `json:"email,omitempty"`
	Role        string    `json:"role,omitempty"`
	Enabled     bool      `json:"enabled"`
	MFAEnabled  bool      `json:"mfa_enabled"`
	CreatedAt   time.Time `json:"created_at,omitempty"`
	UpdatedAt   time.Time `json:"updated_at,omitempty"`
	LastLogin   time.Time `json:"last_login,omitempty"`
	AllowedIPs  []string  `json:"allowed_ips,omitempty"`
}

// GDPRSessionSnapshot captures one session artifact belonging to the subject.
type GDPRSessionSnapshot struct {
	ID                string    `json:"id"`
	Status            string    `json:"status"`
	SourceIP          string    `json:"source_ip,omitempty"`
	TargetHost        string    `json:"target_host,omitempty"`
	TargetPort        int       `json:"target_port,omitempty"`
	InstanceID        string    `json:"instance_id,omitempty"`
	ClientVersion     string    `json:"client_version,omitempty"`
	ClientOS          string    `json:"client_os,omitempty"`
	DeviceFingerprint string    `json:"device_fingerprint,omitempty"`
	RecordingFile     string    `json:"recording_file,omitempty"`
	StartTime         time.Time `json:"start_time,omitempty"`
	Duration          string    `json:"duration,omitempty"`
	BytesIn           int64     `json:"bytes_in,omitempty"`
	BytesOut          int64     `json:"bytes_out,omitempty"`
}

// GDPRAuditEventSnapshot captures one audit artifact belonging to the subject.
type GDPRAuditEventSnapshot struct {
	ID         string    `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	EventType  string    `json:"event_type"`
	SourceIP   string    `json:"source_ip,omitempty"`
	TargetHost string    `json:"target_host,omitempty"`
	SessionID  string    `json:"session_id,omitempty"`
	Details    string    `json:"details,omitempty"`
}

// GDPRDataArtifact summarizes one class of retained subject data.
type GDPRDataArtifact struct {
	Kind        string   `json:"kind"`
	Count       int      `json:"count"`
	Identifiers []string `json:"identifiers,omitempty"`
	Description string   `json:"description,omitempty"`
}

// GDPRDeletionCheck describes whether a mutable or retained data scope still exists.
type GDPRDeletionCheck struct {
	Scope  string `json:"scope"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

// GDPRDataReport is a subject-centric GDPR access/deletion report.
type GDPRDataReport struct {
	ID          string             `json:"id"`
	Kind        GDPRDataReportKind `json:"kind"`
	Subject     string             `json:"subject"`
	GeneratedAt time.Time          `json:"generated_at"`
	GeneratedBy string             `json:"generated_by"`
	Period      struct {
		Start time.Time `json:"start"`
		End   time.Time `json:"end"`
	} `json:"period"`
	Account        *GDPRAccountSnapshot     `json:"account,omitempty"`
	Artifacts      []GDPRDataArtifact       `json:"artifacts"`
	Sessions       []GDPRSessionSnapshot    `json:"sessions,omitempty"`
	AuditEvents    []GDPRAuditEventSnapshot `json:"audit_events,omitempty"`
	DeletionChecks []GDPRDeletionCheck      `json:"deletion_checks,omitempty"`
	RetentionNotes []string                 `json:"retention_notes,omitempty"`
	Summary        string                   `json:"summary"`
}

// SetSubjectDataProvider configures the generator with a source of subject data.
func (rg *ReportGenerator) SetSubjectDataProvider(provider SubjectDataProvider) {
	rg.subjectData = provider
}

// GenerateGDPRDataReport builds a per-subject access or deletion report.
func (rg *ReportGenerator) GenerateGDPRDataReport(kind GDPRDataReportKind, subject string, start, end time.Time, generatedBy string) (*GDPRDataReport, error) {
	if rg == nil || rg.subjectData == nil {
		return nil, fmt.Errorf("gdpr data reporting is not enabled")
	}
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return nil, fmt.Errorf("subject is required")
	}
	kind, err := normalizeGDPRDataReportKind(kind)
	if err != nil {
		return nil, err
	}

	id, err := randomHex(16)
	if err != nil {
		return nil, fmt.Errorf("generate report id: %w", err)
	}

	user, userExists, err := rg.subjectData.GetUser(subject)
	if err != nil {
		return nil, fmt.Errorf("lookup subject account: %w", err)
	}
	sessions, err := rg.subjectData.ListSessions(subject, start, end)
	if err != nil {
		return nil, fmt.Errorf("list subject sessions: %w", err)
	}
	auditEvents, err := rg.subjectData.ListAuditEvents(subject, start, end)
	if err != nil {
		return nil, fmt.Errorf("list subject audit events: %w", err)
	}

	report := &GDPRDataReport{
		ID:          id,
		Kind:        kind,
		Subject:     subject,
		GeneratedAt: time.Now().UTC(),
		GeneratedBy: generatedBy,
		Sessions:    make([]GDPRSessionSnapshot, 0, len(sessions)),
		AuditEvents: make([]GDPRAuditEventSnapshot, 0, len(auditEvents)),
	}
	report.Period.Start = start
	report.Period.End = end

	if userExists {
		report.Account = &GDPRAccountSnapshot{
			Username:    user.Username,
			DisplayName: user.DisplayName,
			Email:       user.Email,
			Role:        user.Role,
			Enabled:     user.Enabled,
			MFAEnabled:  user.MFAEnabled,
			CreatedAt:   user.CreatedAt,
			UpdatedAt:   user.UpdatedAt,
			LastLogin:   user.LastLogin,
			AllowedIPs:  append([]string(nil), user.AllowedIPs...),
		}
	}

	for _, session := range sessions {
		report.Sessions = append(report.Sessions, GDPRSessionSnapshot{
			ID:                session.ID,
			Status:            session.Status,
			SourceIP:          session.SourceIP,
			TargetHost:        session.TargetHost,
			TargetPort:        session.TargetPort,
			InstanceID:        session.InstanceID,
			ClientVersion:     session.ClientVersion,
			ClientOS:          session.ClientOS,
			DeviceFingerprint: session.DeviceFingerprint,
			RecordingFile:     session.RecordingFile,
			StartTime:         session.StartTime,
			Duration:          session.Duration,
			BytesIn:           session.BytesIn,
			BytesOut:          session.BytesOut,
		})
	}
	for _, event := range auditEvents {
		report.AuditEvents = append(report.AuditEvents, GDPRAuditEventSnapshot{
			ID:         event.ID,
			Timestamp:  event.Timestamp,
			EventType:  event.EventType,
			SourceIP:   event.SourceIP,
			TargetHost: event.TargetHost,
			SessionID:  event.SessionID,
			Details:    event.Details,
		})
	}

	report.Artifacts = buildGDPRArtifacts(report)
	if kind == GDPRDataReportDeletion {
		report.DeletionChecks = []GDPRDeletionCheck{
			{
				Scope:  "user_account",
				Status: condValue(userExists, "present", "removed"),
				Detail: condValue(userExists, "Subject still has an active control-plane user record", "No active control-plane user record was found"),
			},
			{
				Scope:  "session_metadata",
				Status: condValue(len(report.Sessions) > 0, "retained", "none"),
				Detail: condValue(len(report.Sessions) > 0, fmt.Sprintf("%d historical session records remain for auditability", len(report.Sessions)), "No persisted session records were found for this subject"),
			},
			{
				Scope:  "audit_events",
				Status: condValue(len(report.AuditEvents) > 0, "retained", "none"),
				Detail: condValue(len(report.AuditEvents) > 0, fmt.Sprintf("%d audit events remain under security retention requirements", len(report.AuditEvents)), "No audit events were found for this subject in the selected period"),
			},
		}
		report.RetentionNotes = []string{
			"Audit events may remain retained to satisfy security investigations and compliance retention requirements.",
			"Historical session metadata may remain retained to preserve session traceability and recording lookups.",
		}
	}
	report.Summary = buildGDPRDataSummary(kind, subject, userExists, len(report.Sessions), len(report.AuditEvents))
	return report, nil
}

// ExportGDPRDataJSON writes a GDPR subject report as indented JSON.
func (rg *ReportGenerator) ExportGDPRDataJSON(report *GDPRDataReport, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// ExportGDPRDataCSV writes a GDPR subject report as a flattened CSV.
func (rg *ReportGenerator) ExportGDPRDataCSV(report *GDPRDataReport, w io.Writer) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	if err := cw.Write([]string{
		"record_type", "subject", "report_kind", "id", "timestamp", "name", "status", "source_ip", "target_host", "session_id", "details",
	}); err != nil {
		return err
	}

	if report.Account != nil {
		if err := cw.Write([]string{
			"account", report.Subject, string(report.Kind), report.Account.Username, "",
			report.Account.Email, condValue(report.Account.Enabled, "enabled", "disabled"), "", "", "", report.Account.Role,
		}); err != nil {
			return err
		}
	}
	for _, session := range report.Sessions {
		if err := cw.Write([]string{
			"session", report.Subject, string(report.Kind), session.ID, session.StartTime.Format(time.RFC3339),
			session.TargetHost, session.Status, session.SourceIP, session.TargetHost, "", session.Duration,
		}); err != nil {
			return err
		}
	}
	for _, event := range report.AuditEvents {
		if err := cw.Write([]string{
			"audit_event", report.Subject, string(report.Kind), event.ID, event.Timestamp.Format(time.RFC3339),
			event.EventType, "", event.SourceIP, event.TargetHost, event.SessionID, event.Details,
		}); err != nil {
			return err
		}
	}
	for _, check := range report.DeletionChecks {
		if err := cw.Write([]string{
			"deletion_check", report.Subject, string(report.Kind), "", "",
			check.Scope, check.Status, "", "", "", check.Detail,
		}); err != nil {
			return err
		}
	}
	return cw.Error()
}

func normalizeGDPRDataReportKind(kind GDPRDataReportKind) (GDPRDataReportKind, error) {
	switch GDPRDataReportKind(strings.ToLower(strings.TrimSpace(string(kind)))) {
	case "", GDPRDataReportAccess:
		return GDPRDataReportAccess, nil
	case GDPRDataReportDeletion:
		return GDPRDataReportDeletion, nil
	default:
		return "", fmt.Errorf("unsupported gdpr report type: %s", kind)
	}
}

func buildGDPRArtifacts(report *GDPRDataReport) []GDPRDataArtifact {
	artifacts := make([]GDPRDataArtifact, 0, 3)
	artifacts = append(artifacts, GDPRDataArtifact{
		Kind:        "user_account",
		Count:       boolCount(report.Account != nil),
		Identifiers: identifiersForAccount(report.Account),
		Description: "Control-plane user record and profile metadata",
	})
	artifacts = append(artifacts, GDPRDataArtifact{
		Kind:        "session_metadata",
		Count:       len(report.Sessions),
		Identifiers: sampleSessionIDs(report.Sessions),
		Description: "Persisted SSH session metadata associated with the subject",
	})
	artifacts = append(artifacts, GDPRDataArtifact{
		Kind:        "audit_events",
		Count:       len(report.AuditEvents),
		Identifiers: sampleAuditEventIDs(report.AuditEvents),
		Description: "Security audit events associated with the subject",
	})
	return artifacts
}

func buildGDPRDataSummary(kind GDPRDataReportKind, subject string, userExists bool, sessionCount, auditCount int) string {
	switch kind {
	case GDPRDataReportDeletion:
		return fmt.Sprintf(
			"GDPR deletion report for %s: account %s, %d session records retained, %d audit events retained.",
			subject,
			condValue(userExists, "still present", "removed"),
			sessionCount,
			auditCount,
		)
	default:
		return fmt.Sprintf(
			"GDPR access report for %s: account %s, %d session records, %d audit events.",
			subject,
			condValue(userExists, "present", "not found"),
			sessionCount,
			auditCount,
		)
	}
}

func identifiersForAccount(account *GDPRAccountSnapshot) []string {
	if account == nil {
		return nil
	}
	return []string{account.Username}
}

func sampleSessionIDs(sessions []GDPRSessionSnapshot) []string {
	ids := make([]string, 0, min(len(sessions), 10))
	for i := 0; i < len(sessions) && i < 10; i++ {
		ids = append(ids, sessions[i].ID)
	}
	return ids
}

func sampleAuditEventIDs(events []GDPRAuditEventSnapshot) []string {
	ids := make([]string, 0, min(len(events), 10))
	for i := 0; i < len(events) && i < 10; i++ {
		ids = append(ids, events[i].ID)
	}
	return ids
}

func boolCount(ok bool) int {
	if ok {
		return 1
	}
	return 0
}

func condValue[T any](cond bool, yes, no T) T {
	if cond {
		return yes
	}
	return no
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
