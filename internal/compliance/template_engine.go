package compliance

import (
	"bytes"
	"database/sql"
	"encoding/csv"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/models"
	_ "modernc.org/sqlite"
)

// QueryDataProvider supplies inventory snapshots for custom report templates.
type QueryDataProvider interface {
	SnapshotUsers() ([]models.User, error)
	SnapshotSessions() ([]models.Session, error)
	SnapshotAuditEvents() ([]models.AuditEvent, error)
	SnapshotServers() ([]models.Server, error)
}

// CustomReportTemplate defines one user-configurable SQL report.
type CustomReportTemplate struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Description   string    `json:"description,omitempty"`
	Query         string    `json:"query"`
	DefaultFormat string    `json:"default_format,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	CreatedBy     string    `json:"created_by,omitempty"`
	UpdatedBy     string    `json:"updated_by,omitempty"`
}

// CustomReportResult is the materialized output of a template query.
type CustomReportResult struct {
	TemplateID   string     `json:"template_id"`
	TemplateName string     `json:"template_name"`
	GeneratedAt  time.Time  `json:"generated_at"`
	Columns      []string   `json:"columns"`
	Rows         [][]string `json:"rows"`
}

type pdfObject struct {
	num  int
	body string
}

// SetQueryDataProvider configures the generator with the snapshot data source used by custom templates.
func (rg *ReportGenerator) SetQueryDataProvider(provider QueryDataProvider) {
	rg.queryData = provider
}

// ValidateCustomReportTemplate ensures the template can only execute read-only SQL.
func (rg *ReportGenerator) ValidateCustomReportTemplate(template CustomReportTemplate) error {
	if strings.TrimSpace(template.Name) == "" {
		return fmt.Errorf("template name is required")
	}
	query := strings.TrimSpace(template.Query)
	if query == "" {
		return fmt.Errorf("template query is required")
	}
	if strings.Contains(query, ";") {
		return fmt.Errorf("template query must be a single statement")
	}
	lower := strings.ToLower(query)
	if !(strings.HasPrefix(lower, "select ") || strings.HasPrefix(lower, "with ")) {
		return fmt.Errorf("template query must start with SELECT or WITH")
	}
	for _, keyword := range []string{
		" insert ", " update ", " delete ", " drop ", " alter ", " create ", " replace ",
		" attach ", " detach ", " pragma ", " vacuum ", " reindex ", " transaction ",
	} {
		if strings.Contains(" "+lower+" ", keyword) {
			return fmt.Errorf("template query contains forbidden keyword %q", strings.TrimSpace(keyword))
		}
	}
	switch normalizeCustomReportFormat(template.DefaultFormat) {
	case "csv", "pdf":
		return nil
	default:
		return fmt.Errorf("unsupported default format: %s", template.DefaultFormat)
	}
}

// ExecuteCustomReportTemplate runs a template against an in-memory snapshot database.
func (rg *ReportGenerator) ExecuteCustomReportTemplate(template CustomReportTemplate) (*CustomReportResult, error) {
	if rg == nil || rg.queryData == nil {
		return nil, fmt.Errorf("custom report templates are not enabled")
	}
	if err := rg.ValidateCustomReportTemplate(template); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return nil, fmt.Errorf("open snapshot database: %w", err)
	}
	defer db.Close()
	if err := loadTemplateSnapshot(db, rg.queryData); err != nil {
		return nil, err
	}

	rows, err := db.Query(strings.TrimSpace(template.Query))
	if err != nil {
		return nil, fmt.Errorf("execute template query: %w", err)
	}
	defer rows.Close()

	columns, err := rows.Columns()
	if err != nil {
		return nil, fmt.Errorf("read query columns: %w", err)
	}
	result := &CustomReportResult{
		TemplateID:   template.ID,
		TemplateName: template.Name,
		GeneratedAt:  time.Now().UTC(),
		Columns:      append([]string(nil), columns...),
		Rows:         [][]string{},
	}
	for rows.Next() {
		row, err := scanRowStrings(rows, len(columns))
		if err != nil {
			return nil, err
		}
		result.Rows = append(result.Rows, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate query rows: %w", err)
	}
	return result, nil
}

// ExportCustomReportCSV writes the result as CSV.
func (rg *ReportGenerator) ExportCustomReportCSV(result *CustomReportResult, w io.Writer) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()
	if err := cw.Write(result.Columns); err != nil {
		return err
	}
	for _, row := range result.Rows {
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	return cw.Error()
}

// ExportCustomReportPDF writes the result as a simple table-like PDF document.
func (rg *ReportGenerator) ExportCustomReportPDF(result *CustomReportResult, w io.Writer) error {
	lines := []string{
		"Custom Compliance Report",
		"Template: " + result.TemplateName,
		"Generated: " + result.GeneratedAt.Format(time.RFC3339),
		"",
		strings.Join(result.Columns, " | "),
	}
	for _, row := range result.Rows {
		lines = append(lines, strings.Join(row, " | "))
	}
	_, err := w.Write(buildSimplePDF(lines))
	return err
}

func normalizeCustomReportFormat(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "csv":
		return "csv"
	case "pdf":
		return "pdf"
	default:
		return strings.ToLower(strings.TrimSpace(raw))
	}
}

func loadTemplateSnapshot(db *sql.DB, provider QueryDataProvider) error {
	for _, stmt := range []string{
		`CREATE TABLE users (
			username TEXT,
			display_name TEXT,
			email TEXT,
			role TEXT,
			enabled INTEGER,
			mfa_enabled INTEGER,
			created_at TEXT,
			updated_at TEXT,
			last_login TEXT
		);`,
		`CREATE TABLE sessions (
			id TEXT,
			username TEXT,
			source_ip TEXT,
			client_version TEXT,
			client_os TEXT,
			device_fingerprint TEXT,
			instance_id TEXT,
			target_host TEXT,
			target_port INTEGER,
			start_time TEXT,
			duration TEXT,
			bytes_in INTEGER,
			bytes_out INTEGER,
			status TEXT,
			recording_file TEXT
		);`,
		`CREATE TABLE audit_events (
			id TEXT,
			timestamp TEXT,
			event_type TEXT,
			username TEXT,
			source_ip TEXT,
			target_host TEXT,
			details TEXT,
			session_id TEXT
		);`,
		`CREATE TABLE servers (
			id TEXT,
			host TEXT,
			port INTEGER,
			name TEXT,
			group_name TEXT,
			status TEXT,
			healthy INTEGER,
			maintenance INTEGER,
			weight INTEGER,
			max_sessions INTEGER,
			sessions INTEGER,
			checked_at TEXT
		);`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("init snapshot schema: %w", err)
		}
	}

	users, err := provider.SnapshotUsers()
	if err != nil {
		return fmt.Errorf("load users for report templates: %w", err)
	}
	for _, user := range users {
		if _, err := db.Exec(
			`INSERT INTO users(username, display_name, email, role, enabled, mfa_enabled, created_at, updated_at, last_login)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			user.Username,
			user.DisplayName,
			user.Email,
			user.Role,
			boolInt(user.Enabled),
			boolInt(user.MFAEnabled),
			timeString(user.CreatedAt),
			timeString(user.UpdatedAt),
			timeString(user.LastLogin),
		); err != nil {
			return fmt.Errorf("insert users snapshot: %w", err)
		}
	}

	sessions, err := provider.SnapshotSessions()
	if err != nil {
		return fmt.Errorf("load sessions for report templates: %w", err)
	}
	for _, session := range sessions {
		if _, err := db.Exec(
			`INSERT INTO sessions(id, username, source_ip, client_version, client_os, device_fingerprint, instance_id, target_host, target_port, start_time, duration, bytes_in, bytes_out, status, recording_file)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			session.ID,
			session.Username,
			session.SourceIP,
			session.ClientVersion,
			session.ClientOS,
			session.DeviceFingerprint,
			session.InstanceID,
			session.TargetHost,
			session.TargetPort,
			timeString(session.StartTime),
			session.Duration,
			session.BytesIn,
			session.BytesOut,
			session.Status,
			session.RecordingFile,
		); err != nil {
			return fmt.Errorf("insert sessions snapshot: %w", err)
		}
	}

	events, err := provider.SnapshotAuditEvents()
	if err != nil {
		return fmt.Errorf("load audit events for report templates: %w", err)
	}
	for _, event := range events {
		if _, err := db.Exec(
			`INSERT INTO audit_events(id, timestamp, event_type, username, source_ip, target_host, details, session_id)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			event.ID,
			timeString(event.Timestamp),
			event.EventType,
			event.Username,
			event.SourceIP,
			event.TargetHost,
			event.Details,
			event.SessionID,
		); err != nil {
			return fmt.Errorf("insert audit snapshot: %w", err)
		}
	}

	servers, err := provider.SnapshotServers()
	if err != nil {
		return fmt.Errorf("load servers for report templates: %w", err)
	}
	for _, server := range servers {
		if _, err := db.Exec(
			`INSERT INTO servers(id, host, port, name, group_name, status, healthy, maintenance, weight, max_sessions, sessions, checked_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			server.ID,
			server.Host,
			server.Port,
			server.Name,
			server.Group,
			server.Status,
			boolInt(server.Healthy),
			boolInt(server.Maintenance),
			server.Weight,
			server.MaxSessions,
			server.Sessions,
			timeString(server.CheckedAt),
		); err != nil {
			return fmt.Errorf("insert server snapshot: %w", err)
		}
	}
	return nil
}

func scanRowStrings(rows *sql.Rows, width int) ([]string, error) {
	values := make([]interface{}, width)
	dest := make([]interface{}, width)
	for i := range values {
		dest[i] = &values[i]
	}
	if err := rows.Scan(dest...); err != nil {
		return nil, fmt.Errorf("scan query row: %w", err)
	}
	out := make([]string, width)
	for i, value := range values {
		out[i] = stringifySQLValue(value)
	}
	return out, nil
}

func stringifySQLValue(value interface{}) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return v
	case []byte:
		return string(v)
	case int64:
		return strconv.FormatInt(v, 10)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		if v {
			return "true"
		}
		return "false"
	case time.Time:
		return v.Format(time.RFC3339)
	default:
		return fmt.Sprint(v)
	}
}

func boolInt(ok bool) int {
	if ok {
		return 1
	}
	return 0
}

func timeString(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func buildSimplePDF(lines []string) []byte {
	const (
		pageWidth    = 612
		pageHeight   = 792
		marginLeft   = 36
		marginTop    = 756
		lineHeight   = 14
		linesPerPage = 48
	)
	if len(lines) == 0 {
		lines = []string{""}
	}

	pages := make([][]string, 0, (len(lines)+linesPerPage-1)/linesPerPage)
	for len(lines) > 0 {
		n := linesPerPage
		if len(lines) < n {
			n = len(lines)
		}
		pages = append(pages, append([]string(nil), lines[:n]...))
		lines = lines[n:]
	}

	objects := []pdfObject{
		{num: 1, body: "<< /Type /Catalog /Pages 2 0 R >>"},
		{num: 3, body: "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"},
	}

	kids := make([]string, 0, len(pages))
	nextNum := 4
	for _, pageLines := range pages {
		pageNum := nextNum
		contentNum := nextNum + 1
		kids = append(kids, fmt.Sprintf("%d 0 R", pageNum))
		stream := buildPDFTextStream(pageLines, marginLeft, marginTop, lineHeight)
		objects = append(objects, pdfObject{
			num: pageNum,
			body: fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %d %d] /Resources << /Font << /F1 3 0 R >> >> /Contents %d 0 R >>",
				pageWidth, pageHeight, contentNum),
		})
		objects = append(objects, pdfObject{
			num:  contentNum,
			body: fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(stream), stream),
		})
		nextNum += 2
	}
	objects = append(objects, pdfObject{
		num:  2,
		body: fmt.Sprintf("<< /Type /Pages /Count %d /Kids [%s] >>", len(pages), strings.Join(kids, " ")),
	})

	sortPDFObjects(objects)

	var buf bytes.Buffer
	buf.WriteString("%PDF-1.4\n")
	offsets := make([]int, len(objects)+1)
	for _, object := range objects {
		offsets[object.num] = buf.Len()
		fmt.Fprintf(&buf, "%d 0 obj\n%s\nendobj\n", object.num, object.body)
	}
	xrefStart := buf.Len()
	fmt.Fprintf(&buf, "xref\n0 %d\n", len(objects)+1)
	buf.WriteString("0000000000 65535 f \n")
	for i := 1; i <= len(objects); i++ {
		fmt.Fprintf(&buf, "%010d 00000 n \n", offsets[i])
	}
	fmt.Fprintf(&buf, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objects)+1, xrefStart)
	return buf.Bytes()
}

func buildPDFTextStream(lines []string, marginLeft, marginTop, lineHeight int) string {
	var buf strings.Builder
	fmt.Fprintf(&buf, "BT\n/F1 10 Tf\n%d %d Td\n%d TL\n", marginLeft, marginTop, lineHeight)
	for i, line := range lines {
		if i > 0 {
			buf.WriteString("T*\n")
		}
		fmt.Fprintf(&buf, "(%s) Tj\n", escapePDFText(truncatePDFLine(line)))
	}
	buf.WriteString("ET")
	return buf.String()
}

func escapePDFText(raw string) string {
	raw = strings.ReplaceAll(raw, `\`, `\\`)
	raw = strings.ReplaceAll(raw, "(", `\(`)
	raw = strings.ReplaceAll(raw, ")", `\)`)
	return raw
}

func truncatePDFLine(line string) string {
	const maxLineLen = 110
	if len(line) <= maxLineLen {
		return line
	}
	return line[:maxLineLen-3] + "..."
}

func sortPDFObjects(objects []pdfObject) {
	for i := 0; i < len(objects); i++ {
		for j := i + 1; j < len(objects); j++ {
			if objects[j].num < objects[i].num {
				objects[i], objects[j] = objects[j], objects[i]
			}
		}
	}
}
