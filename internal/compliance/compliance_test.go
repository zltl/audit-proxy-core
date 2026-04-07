package compliance

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// helper: create a temp dir with a minimal config file
func setupTestEnv(t *testing.T, configContent string) (auditDir, configPath, dataDir string) {
	t.Helper()
	base := t.TempDir()
	auditDir = filepath.Join(base, "audit")
	dataDir = filepath.Join(base, "data")
	os.MkdirAll(auditDir, 0755)
	os.MkdirAll(dataDir, 0755)

	configPath = filepath.Join(base, "config.ini")
	os.WriteFile(configPath, []byte(configContent), 0644)
	return
}

func fullConfig() string {
	return `[auth]
backend = local

[mfa]
enabled = true

[user:admin]
password_hash = $6$salt$hash
enabled = true

[user:test]
password_hash = $6$salt$hash
enabled = true

[route:admin]
upstream = 10.0.0.1
port = 22

[route:*]
upstream = 10.0.0.2
port = 22

[policy:admin]
allow = all

[policy:test]
allow = shell, exec

[ip_acl]
mode = whitelist
rules = 10.0.0.0/8:allow

[logging]
level = info
audit_dir = /var/log/ssh-proxy

[webhook]
enabled = true
url = https://hooks.example.com/events

[admin]
tls_enabled = true
tls_cert = /etc/cert.pem
tls_key = /etc/key.pem
`
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestNewReportGenerator(t *testing.T) {
	rg := NewReportGenerator("/audit", "/config.ini", "/data")
	if rg == nil {
		t.Fatal("expected non-nil ReportGenerator")
	}
	if rg.auditLogDir != "/audit" {
		t.Errorf("auditLogDir = %q, want /audit", rg.auditLogDir)
	}
}

func TestGenerateSOC2(t *testing.T) {
	auditDir, configPath, dataDir := setupTestEnv(t, fullConfig())
	// create audit log so CC7.1 passes
	os.WriteFile(filepath.Join(auditDir, "test.jsonl"), []byte(`{"id":"1"}`+"\n"), 0644)

	rg := NewReportGenerator(auditDir, configPath, dataDir)
	report, err := rg.Generate(FrameworkSOC2, time.Now().AddDate(0, -1, 0), time.Now(), "tester")
	if err != nil {
		t.Fatalf("Generate SOC2: %v", err)
	}

	if report.Framework != FrameworkSOC2 {
		t.Errorf("framework = %q, want soc2", report.Framework)
	}
	if report.TotalCount != 7 {
		t.Errorf("total controls = %d, want 7", report.TotalCount)
	}
	if report.ID == "" {
		t.Error("report ID should be non-empty")
	}
	if report.GeneratedBy != "tester" {
		t.Errorf("generatedBy = %q, want tester", report.GeneratedBy)
	}
}

func TestGenerateHIPAA(t *testing.T) {
	auditDir, configPath, dataDir := setupTestEnv(t, fullConfig())
	os.WriteFile(filepath.Join(auditDir, "test.jsonl"), []byte(`{"id":"1"}`+"\n"), 0644)

	rg := NewReportGenerator(auditDir, configPath, dataDir)
	report, err := rg.Generate(FrameworkHIPAA, time.Now().AddDate(0, -1, 0), time.Now(), "tester")
	if err != nil {
		t.Fatalf("Generate HIPAA: %v", err)
	}
	if report.TotalCount != 4 {
		t.Errorf("total controls = %d, want 4", report.TotalCount)
	}
}

func TestGeneratePCI(t *testing.T) {
	auditDir, configPath, dataDir := setupTestEnv(t, fullConfig())
	os.WriteFile(filepath.Join(auditDir, "test.jsonl"), []byte(`{"id":"1"}`+"\n"), 0644)

	rg := NewReportGenerator(auditDir, configPath, dataDir)
	report, err := rg.Generate(FrameworkPCI, time.Now().AddDate(0, -1, 0), time.Now(), "tester")
	if err != nil {
		t.Fatalf("Generate PCI: %v", err)
	}
	if report.TotalCount != 4 {
		t.Errorf("total controls = %d, want 4", report.TotalCount)
	}
}

func TestGenerateGDPR(t *testing.T) {
	auditDir, configPath, dataDir := setupTestEnv(t, fullConfig())
	os.WriteFile(filepath.Join(auditDir, "test.jsonl"), []byte(`{"id":"1"}`+"\n"), 0644)

	rg := NewReportGenerator(auditDir, configPath, dataDir)
	report, err := rg.Generate(FrameworkGDPR, time.Now().AddDate(0, -1, 0), time.Now(), "tester")
	if err != nil {
		t.Fatalf("Generate GDPR: %v", err)
	}
	if report.TotalCount != 3 {
		t.Errorf("total controls = %d, want 3", report.TotalCount)
	}
}

func TestGenerateISO27001(t *testing.T) {
	auditDir, configPath, dataDir := setupTestEnv(t, fullConfig())
	os.WriteFile(filepath.Join(auditDir, "test.jsonl"), []byte(`{"id":"1"}`+"\n"), 0644)

	rg := NewReportGenerator(auditDir, configPath, dataDir)
	report, err := rg.Generate(FrameworkISO27001, time.Now().AddDate(0, -1, 0), time.Now(), "tester")
	if err != nil {
		t.Fatalf("Generate ISO27001: %v", err)
	}
	if report.TotalCount != 3 {
		t.Errorf("total controls = %d, want 3", report.TotalCount)
	}
}

func TestUnsupportedFramework(t *testing.T) {
	rg := NewReportGenerator("", "", "")
	_, err := rg.Generate(Framework("nope"), time.Now(), time.Now(), "x")
	if err == nil {
		t.Fatal("expected error for unsupported framework")
	}
}

func TestScoreCalculation_AllPass(t *testing.T) {
	auditDir, configPath, dataDir := setupTestEnv(t, fullConfig())
	// Create audit log + sig file for full pass
	os.WriteFile(filepath.Join(auditDir, "test.jsonl"), []byte(`{"id":"1"}`+"\n"), 0644)
	os.WriteFile(filepath.Join(auditDir, "test.sig"), []byte("signature"), 0644)
	// Create config versions dir for CC8.1
	os.MkdirAll(filepath.Join(dataDir, "config_versions"), 0755)

	rg := NewReportGenerator(auditDir, configPath, dataDir)
	report, err := rg.Generate(FrameworkSOC2, time.Now().AddDate(0, -1, 0), time.Now(), "tester")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if report.Score != 100 {
		t.Errorf("score = %.1f, want 100", report.Score)
	}
	if report.PassCount != report.TotalCount {
		t.Errorf("pass=%d != total=%d", report.PassCount, report.TotalCount)
	}
}

func TestScoreCalculation_Partial(t *testing.T) {
	// Config with auth but no mfa — CC6.1 is partial
	auditDir, configPath, dataDir := setupTestEnv(t, `[auth]
backend = local
[user:test]
password_hash = hash
[route:test]
upstream = 10.0.0.1
[policy:test]
allow = shell
[ip_acl]
mode = whitelist
[logging]
level = info
[webhook]
enabled = true
`)
	os.WriteFile(filepath.Join(auditDir, "test.jsonl"), []byte(`{"id":"1"}`+"\n"), 0644)
	os.WriteFile(filepath.Join(auditDir, "test.sig"), []byte("sig"), 0644)
	os.MkdirAll(filepath.Join(dataDir, "config_versions"), 0755)

	rg := NewReportGenerator(auditDir, configPath, dataDir)
	report, err := rg.Generate(FrameworkSOC2, time.Now().AddDate(0, -1, 0), time.Now(), "tester")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// CC6.1 is partial, rest pass -> score = (6 + 0.5) / 7 * 100 ≈ 92.86
	if report.Score < 90 || report.Score > 95 {
		t.Errorf("score = %.1f, expected ~92.9", report.Score)
	}
}

func TestScoreCalculation_NoConfig(t *testing.T) {
	rg := NewReportGenerator("", "", "")
	report, err := rg.Generate(FrameworkSOC2, time.Now().AddDate(0, -1, 0), time.Now(), "tester")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if report.Score != 0 {
		t.Errorf("score = %.1f, want 0", report.Score)
	}
	if report.FailCount != report.TotalCount {
		t.Errorf("fail=%d != total=%d", report.FailCount, report.TotalCount)
	}
}

func TestExportCSV(t *testing.T) {
	auditDir, configPath, dataDir := setupTestEnv(t, fullConfig())
	rg := NewReportGenerator(auditDir, configPath, dataDir)
	report, err := rg.Generate(FrameworkSOC2, time.Now().AddDate(0, -1, 0), time.Now(), "tester")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	var buf bytes.Buffer
	if err := rg.ExportCSV(report, &buf); err != nil {
		t.Fatalf("ExportCSV: %v", err)
	}

	r := csv.NewReader(&buf)
	records, err := r.ReadAll()
	if err != nil {
		t.Fatalf("read csv: %v", err)
	}

	// header + 7 controls
	if len(records) != 8 {
		t.Errorf("csv rows = %d, want 8", len(records))
	}
	if records[0][0] != "control_id" {
		t.Errorf("csv header[0] = %q, want control_id", records[0][0])
	}
}

func TestExportJSON(t *testing.T) {
	auditDir, configPath, dataDir := setupTestEnv(t, fullConfig())
	rg := NewReportGenerator(auditDir, configPath, dataDir)
	report, err := rg.Generate(FrameworkSOC2, time.Now().AddDate(0, -1, 0), time.Now(), "tester")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	var buf bytes.Buffer
	if err := rg.ExportJSON(report, &buf); err != nil {
		t.Fatalf("ExportJSON: %v", err)
	}

	var decoded Report
	if err := json.NewDecoder(&buf).Decode(&decoded); err != nil {
		t.Fatalf("decode json: %v", err)
	}
	if decoded.ID != report.ID {
		t.Errorf("json report ID mismatch")
	}
	if len(decoded.Controls) != len(report.Controls) {
		t.Errorf("json controls count mismatch")
	}
}

func TestReportIDUniqueness(t *testing.T) {
	rg := NewReportGenerator("", "", "")
	ids := make(map[string]bool)
	for i := 0; i < 50; i++ {
		report, err := rg.Generate(FrameworkGDPR, time.Now(), time.Now(), "test")
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		if ids[report.ID] {
			t.Fatalf("duplicate report ID: %s", report.ID)
		}
		ids[report.ID] = true
	}
}

func TestReportPeriod(t *testing.T) {
	rg := NewReportGenerator("", "", "")
	start := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2024, 6, 30, 0, 0, 0, 0, time.UTC)
	report, err := rg.Generate(FrameworkGDPR, start, end, "test")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !report.Period.Start.Equal(start) {
		t.Errorf("period start = %v, want %v", report.Period.Start, start)
	}
	if !report.Period.End.Equal(end) {
		t.Errorf("period end = %v, want %v", report.Period.End, end)
	}
}

func TestControlEvidencePresent(t *testing.T) {
	auditDir, configPath, dataDir := setupTestEnv(t, fullConfig())
	os.WriteFile(filepath.Join(auditDir, "test.jsonl"), []byte(`{"id":"1"}`+"\n"), 0644)

	rg := NewReportGenerator(auditDir, configPath, dataDir)
	report, _ := rg.Generate(FrameworkSOC2, time.Now().AddDate(0, -1, 0), time.Now(), "t")

	for _, c := range report.Controls {
		if c.Status == ControlPass && len(c.Evidence) == 0 {
			t.Errorf("control %s passed but has no evidence", c.ID)
		}
	}
}

func TestControlRemediationOnFail(t *testing.T) {
	rg := NewReportGenerator("", "", "")
	report, _ := rg.Generate(FrameworkSOC2, time.Now(), time.Now(), "t")

	for _, c := range report.Controls {
		if c.Status == ControlFail && c.Remediation == "" {
			t.Errorf("control %s failed but has no remediation", c.ID)
		}
	}
}

func TestAllFrameworks(t *testing.T) {
	frameworks := AllFrameworks()
	if len(frameworks) != 5 {
		t.Errorf("AllFrameworks() = %d, want 5", len(frameworks))
	}
}

func TestAuditLogExistsCheck(t *testing.T) {
	base := t.TempDir()
	auditDir := filepath.Join(base, "audit")
	os.MkdirAll(auditDir, 0755)

	rg := NewReportGenerator(auditDir, "", "")
	if rg.auditLogExists() {
		t.Error("empty dir should not have audit logs")
	}

	os.WriteFile(filepath.Join(auditDir, "test.jsonl"), []byte("{}"), 0644)
	if !rg.auditLogExists() {
		t.Error("should find .jsonl audit logs")
	}
}

func TestSummaryContainsFramework(t *testing.T) {
	rg := NewReportGenerator("", "", "")
	report, _ := rg.Generate(FrameworkHIPAA, time.Now(), time.Now(), "t")
	if !strings.Contains(report.Summary, "hipaa") {
		t.Errorf("summary %q should contain framework name", report.Summary)
	}
}

func TestExportCSVRoundTrip(t *testing.T) {
	rg := NewReportGenerator("", "", "")
	report, _ := rg.Generate(FrameworkPCI, time.Now(), time.Now(), "t")

	var buf bytes.Buffer
	rg.ExportCSV(report, &buf)

	r := csv.NewReader(&buf)
	header, err := r.Read()
	if err != nil {
		t.Fatal(err)
	}
	if len(header) != 8 {
		t.Errorf("header cols = %d, want 8", len(header))
	}

	count := 0
	for {
		_, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		count++
	}
	if count != report.TotalCount {
		t.Errorf("csv data rows = %d, want %d", count, report.TotalCount)
	}
}
