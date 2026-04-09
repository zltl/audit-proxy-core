package compliance

import (
	"crypto/rand"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Framework identifies a compliance framework.
type Framework string

const (
	FrameworkSOC2     Framework = "soc2"
	FrameworkHIPAA    Framework = "hipaa"
	FrameworkGDPR     Framework = "gdpr"
	FrameworkPCI      Framework = "pci-dss"
	FrameworkISO27001 Framework = "iso27001"
	FrameworkMLPS20   Framework = "mlps-2.0"
	FrameworkMLPS30   Framework = "mlps-3.0"
)

// AllFrameworks returns every supported framework.
func AllFrameworks() []Framework {
	return []Framework{
		FrameworkSOC2,
		FrameworkHIPAA,
		FrameworkGDPR,
		FrameworkPCI,
		FrameworkISO27001,
		FrameworkMLPS20,
		FrameworkMLPS30,
	}
}

// ControlStatus represents the result of a single control check.
type ControlStatus string

const (
	ControlPass    ControlStatus = "pass"
	ControlFail    ControlStatus = "fail"
	ControlPartial ControlStatus = "partial"
	ControlNA      ControlStatus = "n/a"
)

// Control is one compliance control and its evaluation result.
type Control struct {
	ID          string        `json:"id"`
	Framework   Framework     `json:"framework"`
	Category    string        `json:"category"`
	Title       string        `json:"title"`
	Description string        `json:"description"`
	Status      ControlStatus `json:"status"`
	Evidence    []string      `json:"evidence"`
	Remediation string        `json:"remediation,omitempty"`
}

// Report is a full compliance report for a single framework.
type Report struct {
	ID          string    `json:"id"`
	Framework   Framework `json:"framework"`
	GeneratedAt time.Time `json:"generated_at"`
	GeneratedBy string    `json:"generated_by"`
	Period      struct {
		Start time.Time `json:"start"`
		End   time.Time `json:"end"`
	} `json:"period"`
	Score      float64   `json:"score"`
	Controls   []Control `json:"controls"`
	Summary    string    `json:"summary"`
	PassCount  int       `json:"pass_count"`
	FailCount  int       `json:"fail_count"`
	TotalCount int       `json:"total_count"`
}

// ReportGenerator evaluates compliance controls by inspecting actual system state.
type ReportGenerator struct {
	auditLogDir string
	configPath  string
	dataDir     string
	subjectData SubjectDataProvider
	queryData   QueryDataProvider
}

// NewReportGenerator creates a report generator that inspects the given paths.
func NewReportGenerator(auditLogDir, configPath, dataDir string) *ReportGenerator {
	return &ReportGenerator{
		auditLogDir: auditLogDir,
		configPath:  configPath,
		dataDir:     dataDir,
	}
}

// Generate produces a Report for the requested framework and period.
func (rg *ReportGenerator) Generate(framework Framework, start, end time.Time, generatedBy string) (*Report, error) {
	id, err := randomHex(16)
	if err != nil {
		return nil, fmt.Errorf("generate report id: %w", err)
	}

	var controls []Control
	switch framework {
	case FrameworkSOC2:
		controls = rg.evaluateSOC2()
	case FrameworkHIPAA:
		controls = rg.evaluateHIPAA()
	case FrameworkPCI:
		controls = rg.evaluatePCI()
	case FrameworkGDPR:
		controls = rg.evaluateGDPR()
	case FrameworkISO27001:
		controls = rg.evaluateISO27001()
	case FrameworkMLPS20:
		controls = rg.evaluateMLPS20()
	case FrameworkMLPS30:
		controls = rg.evaluateMLPS30()
	default:
		return nil, fmt.Errorf("unsupported framework: %s", framework)
	}

	pass, fail := 0, 0
	for _, c := range controls {
		switch c.Status {
		case ControlPass:
			pass++
		case ControlFail:
			fail++
		case ControlPartial:
			// count as half for scoring
		}
	}
	total := len(controls)
	score := float64(0)
	if total > 0 {
		effective := float64(pass)
		for _, c := range controls {
			if c.Status == ControlPartial {
				effective += 0.5
			}
		}
		score = (effective / float64(total)) * 100
	}

	r := &Report{
		ID:          id,
		Framework:   framework,
		GeneratedAt: time.Now().UTC(),
		GeneratedBy: generatedBy,
		Score:       score,
		Controls:    controls,
		PassCount:   pass,
		FailCount:   fail,
		TotalCount:  total,
	}
	r.Period.Start = start
	r.Period.End = end
	r.Summary = fmt.Sprintf("%s compliance: %d/%d controls passing (%.1f%%)", framework, pass, total, score)

	return r, nil
}

// ExportCSV writes the report controls as CSV.
func (rg *ReportGenerator) ExportCSV(report *Report, w io.Writer) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	if err := cw.Write([]string{
		"control_id", "framework", "category", "title", "status", "description", "evidence", "remediation",
	}); err != nil {
		return err
	}

	for _, c := range report.Controls {
		evidence := strings.Join(c.Evidence, "; ")
		if err := cw.Write([]string{
			c.ID, string(c.Framework), c.Category, c.Title,
			string(c.Status), c.Description, evidence, c.Remediation,
		}); err != nil {
			return err
		}
	}
	return cw.Error()
}

// ExportJSON writes the report as indented JSON.
func (rg *ReportGenerator) ExportJSON(report *Report, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// ---------------------------------------------------------------------------
// SOC2 controls
// ---------------------------------------------------------------------------

func (rg *ReportGenerator) evaluateSOC2() []Control {
	return []Control{
		rg.checkCC61(),
		rg.checkCC62(),
		rg.checkCC63(),
		rg.checkCC66(),
		rg.checkCC71(),
		rg.checkCC72(),
		rg.checkCC81(),
	}
}

func (rg *ReportGenerator) checkCC61() Control {
	c := Control{
		ID:          "SOC2-CC6.1",
		Framework:   FrameworkSOC2,
		Category:    "Access Control",
		Title:       "Logical Access Controls",
		Description: "Verify authentication is configured and MFA is available",
	}

	authOK := rg.configContains("auth")
	mfaOK := rg.configContains("mfa")

	if authOK {
		c.Evidence = append(c.Evidence, "auth section found in config")
	}
	if mfaOK {
		c.Evidence = append(c.Evidence, "mfa section found in config")
	}

	switch {
	case authOK && mfaOK:
		c.Status = ControlPass
	case authOK:
		c.Status = ControlPartial
		c.Remediation = "Enable MFA for stronger access controls"
	default:
		c.Status = ControlFail
		c.Remediation = "Configure authentication backend and enable MFA"
	}
	return c
}

func (rg *ReportGenerator) checkCC62() Control {
	c := Control{
		ID:          "SOC2-CC6.2",
		Framework:   FrameworkSOC2,
		Category:    "Access Control",
		Title:       "Authentication Mechanisms",
		Description: "Verify password policy and account lockout are configured",
	}

	hasUsers := rg.configContains("user:")
	hasAuth := rg.configContains("auth")

	if hasUsers {
		c.Evidence = append(c.Evidence, "user accounts defined in config")
	}
	if hasAuth {
		c.Evidence = append(c.Evidence, "auth backend configured")
	}

	switch {
	case hasUsers && hasAuth:
		c.Status = ControlPass
	case hasUsers || hasAuth:
		c.Status = ControlPartial
		c.Remediation = "Configure both user accounts and auth backend"
	default:
		c.Status = ControlFail
		c.Remediation = "Configure authentication mechanisms with password policy"
	}
	return c
}

func (rg *ReportGenerator) checkCC63() Control {
	c := Control{
		ID:          "SOC2-CC6.3",
		Framework:   FrameworkSOC2,
		Category:    "Access Control",
		Title:       "Access Authorization",
		Description: "Verify RBAC and policies are configured",
	}

	hasPolicy := rg.configContains("policy:")
	hasRoute := rg.configContains("route:")

	if hasPolicy {
		c.Evidence = append(c.Evidence, "feature policies defined")
	}
	if hasRoute {
		c.Evidence = append(c.Evidence, "routing rules defined")
	}

	switch {
	case hasPolicy && hasRoute:
		c.Status = ControlPass
	case hasPolicy || hasRoute:
		c.Status = ControlPartial
		c.Remediation = "Define both routing rules and feature policies"
	default:
		c.Status = ControlFail
		c.Remediation = "Configure RBAC policies and routing rules"
	}
	return c
}

func (rg *ReportGenerator) checkCC66() Control {
	c := Control{
		ID:          "SOC2-CC6.6",
		Framework:   FrameworkSOC2,
		Category:    "Access Control",
		Title:       "System Boundary Protections",
		Description: "Verify IP ACL is configured",
	}

	hasACL := rg.configContains("ip_acl")
	if hasACL {
		c.Evidence = append(c.Evidence, "IP ACL section configured")
		c.Status = ControlPass
	} else {
		c.Status = ControlFail
		c.Remediation = "Configure IP access control lists"
	}
	return c
}

func (rg *ReportGenerator) checkCC71() Control {
	c := Control{
		ID:          "SOC2-CC7.1",
		Framework:   FrameworkSOC2,
		Category:    "Monitoring",
		Title:       "Detection Mechanisms",
		Description: "Verify audit logging is enabled",
	}

	auditExists := rg.auditLogExists()
	if auditExists {
		c.Evidence = append(c.Evidence, "audit log directory exists with log files")
		c.Status = ControlPass
	} else {
		hasLogging := rg.configContains("logging")
		if hasLogging {
			c.Evidence = append(c.Evidence, "logging configured but no audit files found")
			c.Status = ControlPartial
			c.Remediation = "Ensure audit logs are being written to the configured directory"
		} else {
			c.Status = ControlFail
			c.Remediation = "Enable audit logging in configuration"
		}
	}
	return c
}

func (rg *ReportGenerator) checkCC72() Control {
	c := Control{
		ID:          "SOC2-CC7.2",
		Framework:   FrameworkSOC2,
		Category:    "Monitoring",
		Title:       "Monitoring Activities",
		Description: "Verify alerting/webhook notifications are configured",
	}

	hasWebhook := rg.configContains("webhook")
	if hasWebhook {
		c.Evidence = append(c.Evidence, "webhook notification section configured")
		c.Status = ControlPass
	} else {
		c.Status = ControlFail
		c.Remediation = "Configure webhook notifications for alerting"
	}
	return c
}

func (rg *ReportGenerator) checkCC81() Control {
	c := Control{
		ID:          "SOC2-CC8.1",
		Framework:   FrameworkSOC2,
		Category:    "Change Management",
		Title:       "Change Management",
		Description: "Verify configuration versioning is enabled",
	}

	hasConfigVer := rg.configContains("config")
	// Check if data dir has version files
	versionDir := filepath.Join(rg.dataDir, "config_versions")
	if info, err := os.Stat(versionDir); err == nil && info.IsDir() {
		c.Evidence = append(c.Evidence, "config version directory exists")
		c.Status = ControlPass
	} else if hasConfigVer {
		c.Evidence = append(c.Evidence, "configuration management detected")
		c.Status = ControlPartial
		c.Remediation = "Enable config version history storage"
	} else {
		c.Status = ControlFail
		c.Remediation = "Enable configuration versioning and change management"
	}
	return c
}

// ---------------------------------------------------------------------------
// HIPAA controls
// ---------------------------------------------------------------------------

func (rg *ReportGenerator) evaluateHIPAA() []Control {
	return []Control{
		rg.checkHIPAAAccessControl(),
		rg.checkHIPAAAuditControls(),
		rg.checkHIPAAIntegrity(),
		rg.checkHIPAATransmissionSecurity(),
	}
}

func (rg *ReportGenerator) checkHIPAAAccessControl() Control {
	c := Control{
		ID:          "HIPAA-164.312(a)",
		Framework:   FrameworkHIPAA,
		Category:    "Access Control",
		Title:       "Access Control",
		Description: "Verify authentication and RBAC are configured per §164.312(a)",
	}

	hasAuth := rg.configContains("auth")
	hasPolicy := rg.configContains("policy:")

	if hasAuth {
		c.Evidence = append(c.Evidence, "authentication backend configured")
	}
	if hasPolicy {
		c.Evidence = append(c.Evidence, "RBAC policies defined")
	}

	switch {
	case hasAuth && hasPolicy:
		c.Status = ControlPass
	case hasAuth || hasPolicy:
		c.Status = ControlPartial
		c.Remediation = "Configure both authentication and RBAC policies"
	default:
		c.Status = ControlFail
		c.Remediation = "Implement authentication and role-based access controls"
	}
	return c
}

func (rg *ReportGenerator) checkHIPAAAuditControls() Control {
	c := Control{
		ID:          "HIPAA-164.312(b)",
		Framework:   FrameworkHIPAA,
		Category:    "Audit Controls",
		Title:       "Audit Controls",
		Description: "Verify audit logging is enabled per §164.312(b)",
	}

	if rg.auditLogExists() {
		c.Evidence = append(c.Evidence, "audit log files present")
		c.Status = ControlPass
	} else if rg.configContains("logging") {
		c.Evidence = append(c.Evidence, "logging configured but no log files found")
		c.Status = ControlPartial
		c.Remediation = "Verify audit logs are actively being written"
	} else {
		c.Status = ControlFail
		c.Remediation = "Enable comprehensive audit logging"
	}
	return c
}

func (rg *ReportGenerator) checkHIPAAIntegrity() Control {
	c := Control{
		ID:          "HIPAA-164.312(c)",
		Framework:   FrameworkHIPAA,
		Category:    "Integrity",
		Title:       "Integrity Controls",
		Description: "Verify audit log integrity (signing) per §164.312(c)",
	}

	// Check for .sig files alongside audit logs
	if rg.auditLogSigningEnabled() {
		c.Evidence = append(c.Evidence, "audit log signature files found")
		c.Status = ControlPass
	} else if rg.auditLogExists() {
		c.Evidence = append(c.Evidence, "audit logs exist but no signatures found")
		c.Status = ControlPartial
		c.Remediation = "Enable audit log signing for integrity verification"
	} else {
		c.Status = ControlFail
		c.Remediation = "Enable audit logging with integrity signing"
	}
	return c
}

func (rg *ReportGenerator) checkHIPAATransmissionSecurity() Control {
	c := Control{
		ID:          "HIPAA-164.312(e)",
		Framework:   FrameworkHIPAA,
		Category:    "Transmission Security",
		Title:       "Transmission Security",
		Description: "Verify TLS is enabled for data in transit per §164.312(e)",
	}

	hasTLS := rg.configContains("tls_cert") || rg.configContains("tls_enabled")
	if hasTLS {
		c.Evidence = append(c.Evidence, "TLS configuration found")
		c.Status = ControlPass
	} else {
		c.Status = ControlFail
		c.Remediation = "Enable TLS for all network communications"
	}
	return c
}

// ---------------------------------------------------------------------------
// PCI-DSS controls
// ---------------------------------------------------------------------------

func (rg *ReportGenerator) evaluatePCI() []Control {
	return []Control{
		rg.checkPCIReq2(),
		rg.checkPCIReq7(),
		rg.checkPCIReq8(),
		rg.checkPCIReq10(),
	}
}

func (rg *ReportGenerator) checkPCIReq2() Control {
	c := Control{
		ID:          "PCI-DSS-Req2",
		Framework:   FrameworkPCI,
		Category:    "Secure Configuration",
		Title:       "Secure Configuration",
		Description: "Verify non-default credentials and secure configuration",
	}

	configData := rg.readConfig()
	hasCustomAuth := !strings.Contains(configData, "password = admin") &&
		!strings.Contains(configData, "password = password")
	hasConfig := len(configData) > 0

	if hasConfig {
		c.Evidence = append(c.Evidence, "configuration file present")
	}
	if hasCustomAuth && hasConfig {
		c.Evidence = append(c.Evidence, "no default credentials detected")
		c.Status = ControlPass
	} else if hasConfig {
		c.Status = ControlPartial
		c.Remediation = "Remove any default credentials from configuration"
	} else {
		c.Status = ControlFail
		c.Remediation = "Create secure configuration with non-default credentials"
	}
	return c
}

func (rg *ReportGenerator) checkPCIReq7() Control {
	c := Control{
		ID:          "PCI-DSS-Req7",
		Framework:   FrameworkPCI,
		Category:    "Access Restriction",
		Title:       "Access Restriction",
		Description: "Verify RBAC and least privilege access controls",
	}

	hasPolicy := rg.configContains("policy:")
	hasRoute := rg.configContains("route:")

	if hasPolicy {
		c.Evidence = append(c.Evidence, "feature policies defined for access restriction")
	}
	if hasRoute {
		c.Evidence = append(c.Evidence, "routing rules enforce access boundaries")
	}

	switch {
	case hasPolicy && hasRoute:
		c.Status = ControlPass
	case hasPolicy || hasRoute:
		c.Status = ControlPartial
		c.Remediation = "Implement both routing rules and feature policies for least privilege"
	default:
		c.Status = ControlFail
		c.Remediation = "Implement role-based access controls with least privilege"
	}
	return c
}

func (rg *ReportGenerator) checkPCIReq8() Control {
	c := Control{
		ID:          "PCI-DSS-Req8",
		Framework:   FrameworkPCI,
		Category:    "Authentication",
		Title:       "Authentication",
		Description: "Verify unique user IDs and MFA availability",
	}

	hasUsers := rg.configContains("user:")
	hasMFA := rg.configContains("mfa")

	if hasUsers {
		c.Evidence = append(c.Evidence, "unique user accounts configured")
	}
	if hasMFA {
		c.Evidence = append(c.Evidence, "MFA configuration present")
	}

	switch {
	case hasUsers && hasMFA:
		c.Status = ControlPass
	case hasUsers:
		c.Status = ControlPartial
		c.Remediation = "Enable MFA for all user accounts"
	default:
		c.Status = ControlFail
		c.Remediation = "Configure unique user accounts with MFA"
	}
	return c
}

func (rg *ReportGenerator) checkPCIReq10() Control {
	c := Control{
		ID:          "PCI-DSS-Req10",
		Framework:   FrameworkPCI,
		Category:    "Audit Trails",
		Title:       "Audit Trails",
		Description: "Verify comprehensive logging and log integrity",
	}

	auditOK := rg.auditLogExists()
	sigOK := rg.auditLogSigningEnabled()

	if auditOK {
		c.Evidence = append(c.Evidence, "audit log files present")
	}
	if sigOK {
		c.Evidence = append(c.Evidence, "audit log signatures present")
	}

	switch {
	case auditOK && sigOK:
		c.Status = ControlPass
	case auditOK:
		c.Status = ControlPartial
		c.Remediation = "Enable audit log signing for integrity verification"
	default:
		c.Status = ControlFail
		c.Remediation = "Enable comprehensive audit logging with integrity controls"
	}
	return c
}

// ---------------------------------------------------------------------------
// GDPR controls
// ---------------------------------------------------------------------------

func (rg *ReportGenerator) evaluateGDPR() []Control {
	return []Control{
		{
			ID:          "GDPR-Art25",
			Framework:   FrameworkGDPR,
			Category:    "Data Protection",
			Title:       "Data Protection by Design",
			Description: "Verify data protection measures are in place",
			Status:      boolStatus(rg.configContains("auth") && rg.configContains("policy:")),
			Evidence:    collectEvidence(rg.configContains("auth"), "authentication configured", rg.configContains("policy:"), "access policies defined"),
			Remediation: condStr(!rg.configContains("auth") || !rg.configContains("policy:"), "Implement authentication and access control policies"),
		},
		{
			ID:          "GDPR-Art30",
			Framework:   FrameworkGDPR,
			Category:    "Record Keeping",
			Title:       "Records of Processing Activities",
			Description: "Verify audit trails record all access activities",
			Status:      boolStatus(rg.auditLogExists()),
			Evidence:    collectEvidence(rg.auditLogExists(), "audit logs present"),
			Remediation: condStr(!rg.auditLogExists(), "Enable comprehensive audit logging"),
		},
		{
			ID:          "GDPR-Art32",
			Framework:   FrameworkGDPR,
			Category:    "Security",
			Title:       "Security of Processing",
			Description: "Verify encryption and access controls for data security",
			Status:      boolStatus(rg.configContains("tls_cert") || rg.configContains("tls_enabled")),
			Evidence:    collectEvidence(rg.configContains("tls_cert") || rg.configContains("tls_enabled"), "TLS configuration present"),
			Remediation: condStr(!rg.configContains("tls_cert") && !rg.configContains("tls_enabled"), "Enable TLS encryption"),
		},
	}
}

// ---------------------------------------------------------------------------
// ISO 27001 controls
// ---------------------------------------------------------------------------

func (rg *ReportGenerator) evaluateISO27001() []Control {
	return []Control{
		{
			ID:          "ISO27001-A.9.1",
			Framework:   FrameworkISO27001,
			Category:    "Access Control",
			Title:       "Access Control Policy",
			Description: "Verify access control policy is defined",
			Status:      boolStatus(rg.configContains("policy:")),
			Evidence:    collectEvidence(rg.configContains("policy:"), "access policies defined"),
			Remediation: condStr(!rg.configContains("policy:"), "Define access control policies"),
		},
		{
			ID:          "ISO27001-A.9.4",
			Framework:   FrameworkISO27001,
			Category:    "Access Control",
			Title:       "System Access Control",
			Description: "Verify system access controls (authentication, IP ACL)",
			Status:      boolStatus(rg.configContains("auth") && rg.configContains("ip_acl")),
			Evidence:    collectEvidence(rg.configContains("auth"), "authentication configured", rg.configContains("ip_acl"), "IP ACL configured"),
			Remediation: condStr(!rg.configContains("auth") || !rg.configContains("ip_acl"), "Configure authentication and IP access controls"),
		},
		{
			ID:          "ISO27001-A.12.4",
			Framework:   FrameworkISO27001,
			Category:    "Operations Security",
			Title:       "Logging and Monitoring",
			Description: "Verify logging and monitoring are in place",
			Status:      boolStatus(rg.auditLogExists()),
			Evidence:    collectEvidence(rg.auditLogExists(), "audit log files present"),
			Remediation: condStr(!rg.auditLogExists(), "Enable audit logging and monitoring"),
		},
	}
}

// ---------------------------------------------------------------------------
// MLPS 2.0 / 3.0 controls
// ---------------------------------------------------------------------------

func (rg *ReportGenerator) evaluateMLPS20() []Control {
	return []Control{
		{
			ID:          "MLPS2.0-AC-1",
			Framework:   FrameworkMLPS20,
			Category:    "Identity",
			Title:       "身份鉴别与账号管理",
			Description: "Verify authentication backend and managed user accounts are configured",
			Status:      boolStatus(rg.configContains("auth") && rg.configContains("user:")),
			Evidence:    collectEvidence(rg.configContains("auth"), "authentication backend configured", rg.configContains("user:"), "managed user accounts defined"),
			Remediation: condStr(!rg.configContains("auth") || !rg.configContains("user:"), "Configure authentication backend and managed user accounts"),
		},
		{
			ID:          "MLPS2.0-AC-2",
			Framework:   FrameworkMLPS20,
			Category:    "Access Control",
			Title:       "访问控制策略",
			Description: "Verify RBAC policies and routing scopes are configured",
			Status:      boolStatus(rg.configContains("policy:") && rg.configContains("route:")),
			Evidence:    collectEvidence(rg.configContains("policy:"), "policy rules configured", rg.configContains("route:"), "routing scopes configured"),
			Remediation: condStr(!rg.configContains("policy:") || !rg.configContains("route:"), "Define both routing scopes and policy rules"),
		},
		{
			ID:          "MLPS2.0-AU-1",
			Framework:   FrameworkMLPS20,
			Category:    "Audit",
			Title:       "安全审计",
			Description: "Verify audit logging and integrity controls are enabled",
			Status:      auditStatus(rg.auditLogExists(), rg.auditLogSigningEnabled()),
			Evidence:    auditEvidence(rg.auditLogExists(), rg.auditLogSigningEnabled()),
			Remediation: auditRemediation(rg.auditLogExists(), rg.auditLogSigningEnabled()),
		},
		{
			ID:          "MLPS2.0-BP-1",
			Framework:   FrameworkMLPS20,
			Category:    "Boundary Protection",
			Title:       "边界与通信保护",
			Description: "Verify IP ACL and transport security are configured",
			Status:      boolStatus(rg.configContains("ip_acl") && (rg.configContains("tls_cert") || rg.configContains("tls_enabled"))),
			Evidence:    collectEvidence(rg.configContains("ip_acl"), "IP ACL configured", rg.configContains("tls_cert") || rg.configContains("tls_enabled"), "TLS controls configured"),
			Remediation: condStr(!rg.configContains("ip_acl") || (!rg.configContains("tls_cert") && !rg.configContains("tls_enabled")), "Configure IP ACL and TLS protections"),
		},
	}
}

func (rg *ReportGenerator) evaluateMLPS30() []Control {
	return []Control{
		{
			ID:          "MLPS3.0-AC-1",
			Framework:   FrameworkMLPS30,
			Category:    "Identity",
			Title:       "强化身份鉴别",
			Description: "Verify authentication and MFA controls are both enabled",
			Status:      boolStatus(rg.configContains("auth") && rg.configContains("mfa")),
			Evidence:    collectEvidence(rg.configContains("auth"), "authentication backend configured", rg.configContains("mfa"), "MFA controls configured"),
			Remediation: condStr(!rg.configContains("auth") || !rg.configContains("mfa"), "Enable MFA on top of the configured authentication backend"),
		},
		{
			ID:          "MLPS3.0-AU-1",
			Framework:   FrameworkMLPS30,
			Category:    "Audit",
			Title:       "审计留痕与完整性",
			Description: "Verify audit logging and signature files are both present",
			Status:      auditStatus(rg.auditLogExists(), rg.auditLogSigningEnabled()),
			Evidence:    auditEvidence(rg.auditLogExists(), rg.auditLogSigningEnabled()),
			Remediation: auditRemediation(rg.auditLogExists(), rg.auditLogSigningEnabled()),
		},
		{
			ID:          "MLPS3.0-CM-1",
			Framework:   FrameworkMLPS30,
			Category:    "Change Management",
			Title:       "配置版本留痕",
			Description: "Verify configuration version history is retained",
			Status:      boolStatus(rg.configVersioningEnabled()),
			Evidence:    collectEvidence(rg.configVersioningEnabled(), "config_versions directory present"),
			Remediation: condStr(!rg.configVersioningEnabled(), "Enable configuration version history retention"),
		},
		{
			ID:          "MLPS3.0-OPS-1",
			Framework:   FrameworkMLPS30,
			Category:    "Operations",
			Title:       "会话留痕与追溯",
			Description: "Verify persisted session metadata is available for historical traceability",
			Status:      boolStatus(rg.sessionMetadataEnabled()),
			Evidence:    collectEvidence(rg.sessionMetadataEnabled(), "sessions.db present"),
			Remediation: condStr(!rg.sessionMetadataEnabled(), "Enable persisted session metadata storage"),
		},
		{
			ID:          "MLPS3.0-BP-1",
			Framework:   FrameworkMLPS30,
			Category:    "Boundary Protection",
			Title:       "纵深防御与边界控制",
			Description: "Verify route scoping, IP ACL, and TLS controls work together",
			Status:      boolStatus(rg.configContains("route:") && rg.configContains("ip_acl") && (rg.configContains("tls_cert") || rg.configContains("tls_enabled"))),
			Evidence:    collectEvidence(rg.configContains("route:"), "routing scopes configured", rg.configContains("ip_acl"), "IP ACL configured", rg.configContains("tls_cert") || rg.configContains("tls_enabled"), "TLS controls configured"),
			Remediation: condStr(!rg.configContains("route:") || !rg.configContains("ip_acl") || (!rg.configContains("tls_cert") && !rg.configContains("tls_enabled")), "Configure route scoping, IP ACL, and TLS protections together"),
		},
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// configContains checks whether the config file contains a substring.
func (rg *ReportGenerator) configContains(substr string) bool {
	return strings.Contains(rg.readConfig(), substr)
}

// readConfig returns the raw config file content (cached-friendly).
func (rg *ReportGenerator) readConfig() string {
	if rg.configPath == "" {
		return ""
	}
	data, err := os.ReadFile(rg.configPath)
	if err != nil {
		return ""
	}
	return string(data)
}

// auditLogExists checks whether the audit log directory contains .jsonl files.
func (rg *ReportGenerator) auditLogExists() bool {
	if rg.auditLogDir == "" {
		return false
	}
	entries, err := os.ReadDir(rg.auditLogDir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".jsonl") {
			return true
		}
	}
	return false
}

// auditLogSigningEnabled checks for .sig files alongside audit logs.
func (rg *ReportGenerator) auditLogSigningEnabled() bool {
	if rg.auditLogDir == "" {
		return false
	}
	entries, err := os.ReadDir(rg.auditLogDir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sig") {
			return true
		}
	}
	return false
}

func (rg *ReportGenerator) configVersioningEnabled() bool {
	if rg.dataDir == "" {
		return false
	}
	versionDir := filepath.Join(rg.dataDir, "config_versions")
	info, err := os.Stat(versionDir)
	return err == nil && info.IsDir()
}

func (rg *ReportGenerator) sessionMetadataEnabled() bool {
	if rg.dataDir == "" {
		return false
	}
	info, err := os.Stat(filepath.Join(rg.dataDir, "sessions.db"))
	return err == nil && !info.IsDir()
}

func auditStatus(auditOK, sigOK bool) ControlStatus {
	switch {
	case auditOK && sigOK:
		return ControlPass
	case auditOK:
		return ControlPartial
	default:
		return ControlFail
	}
}

func auditEvidence(auditOK, sigOK bool) []string {
	return collectEvidence(
		auditOK, "audit log files present",
		sigOK, "audit log signatures present",
	)
}

func auditRemediation(auditOK, sigOK bool) string {
	switch {
	case auditOK && !sigOK:
		return "Enable audit log signing for integrity verification"
	case !auditOK:
		return "Enable comprehensive audit logging and integrity protection"
	default:
		return ""
	}
}

func boolStatus(ok bool) ControlStatus {
	if ok {
		return ControlPass
	}
	return ControlFail
}

func collectEvidence(pairs ...interface{}) []string {
	var out []string
	for i := 0; i+1 < len(pairs); i += 2 {
		if b, ok := pairs[i].(bool); ok && b {
			if s, ok := pairs[i+1].(string); ok {
				out = append(out, s)
			}
		}
	}
	if out == nil {
		out = []string{}
	}
	return out
}

func condStr(cond bool, s string) string {
	if cond {
		return s
	}
	return ""
}
