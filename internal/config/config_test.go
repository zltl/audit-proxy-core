package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateAllowsSelfSignedTLS(t *testing.T) {
	cfg := defaults()
	cfg.SessionSecret = "secret"
	cfg.TLSSelfSigned = true

	if err := validate(cfg); err != nil {
		t.Fatalf("validate(self-signed) = %v", err)
	}
}

func TestValidateRejectsPartialFileTLS(t *testing.T) {
	cfg := defaults()
	cfg.SessionSecret = "secret"
	cfg.TLSCert = "/tmp/cert.pem"

	err := validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "tls_cert and tls_key") {
		t.Fatalf("validate(partial tls files) = %v, want tls_cert/tls_key error", err)
	}
}

func TestValidateRejectsConflictingTLSModes(t *testing.T) {
	cfg := defaults()
	cfg.SessionSecret = "secret"
	cfg.TLSSelfSigned = true
	cfg.TLSLetsEncrypt = true
	cfg.TLSLetsEncryptHosts = "proxy.example.com"

	err := validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("validate(conflicting tls modes) = %v, want mutually exclusive error", err)
	}
}

func TestValidateRejectsLetsEncryptWithoutHosts(t *testing.T) {
	cfg := defaults()
	cfg.SessionSecret = "secret"
	cfg.TLSLetsEncrypt = true

	err := validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "tls_lets_encrypt_hosts") {
		t.Fatalf("validate(lets encrypt without hosts) = %v, want host error", err)
	}
}

func TestValidateRejectsClusterMTLSMissingFields(t *testing.T) {
	cfg := defaults()
	cfg.SessionSecret = "secret"
	cfg.ClusterEnabled = true
	cfg.ClusterNodeID = "node-1"
	cfg.ClusterBindAddr = "127.0.0.1:9444"
	cfg.ClusterTLSCert = "/tmp/cluster.pem"

	err := validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "cluster_tls_cert, cluster_tls_key, and cluster_tls_ca") {
		t.Fatalf("validate(cluster mTLS missing fields) = %v, want cluster tls error", err)
	}
}

func TestValidateAllowsClusterDiscoverySeeds(t *testing.T) {
	cfg := defaults()
	cfg.SessionSecret = "secret"
	cfg.ClusterEnabled = true
	cfg.ClusterNodeID = "node-1"
	cfg.ClusterBindAddr = "127.0.0.1:9444"
	cfg.ClusterSeeds = []string{
		"dns://proxy.internal:9444",
		"k8s://ssh-proxy.default:9444",
		"consul://127.0.0.1:8500/ssh-proxy?tag=prod",
	}

	if err := validate(cfg); err != nil {
		t.Fatalf("validate(cluster discovery seeds) = %v", err)
	}
}

func TestValidateRejectsInvalidClusterDiscoverySeed(t *testing.T) {
	cfg := defaults()
	cfg.SessionSecret = "secret"
	cfg.ClusterEnabled = true
	cfg.ClusterNodeID = "node-1"
	cfg.ClusterBindAddr = "127.0.0.1:9444"
	cfg.ClusterSeeds = []string{"ftp://proxy.internal:9444"}

	err := validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "invalid cluster_seeds entry") {
		t.Fatalf("validate(invalid cluster discovery seed) = %v, want cluster_seeds error", err)
	}
}

func TestValidateAllowsClusterTopologyMetadataAndIntervals(t *testing.T) {
	cfg := defaults()
	cfg.SessionSecret = "secret"
	cfg.ClusterEnabled = true
	cfg.ClusterNodeID = "node-1"
	cfg.ClusterBindAddr = "127.0.0.1:9444"
	cfg.ClusterRegion = "us-east-1"
	cfg.ClusterZone = "us-east-1a"
	cfg.ClusterHeartbeatInterval = "5s"
	cfg.ClusterElectionTimeout = "20s"
	cfg.ClusterSyncInterval = "8s"

	if err := validate(cfg); err != nil {
		t.Fatalf("validate(cluster topology metadata and intervals) = %v", err)
	}
}

func TestValidateRejectsInvalidClusterDuration(t *testing.T) {
	cfg := defaults()
	cfg.SessionSecret = "secret"
	cfg.ClusterEnabled = true
	cfg.ClusterNodeID = "node-1"
	cfg.ClusterBindAddr = "127.0.0.1:9444"
	cfg.ClusterSyncInterval = "0s"

	err := validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "cluster_sync_interval must be a positive duration") {
		t.Fatalf("validate(invalid cluster duration) = %v, want cluster_sync_interval duration error", err)
	}
}

func TestValidateRejectsHSTSPreloadWithoutIncludeSubdomains(t *testing.T) {
	cfg := defaults()
	cfg.SessionSecret = "secret"
	cfg.HSTSEnabled = true
	cfg.HSTSPreload = true

	err := validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "hsts_preload requires hsts_include_subdomains") {
		t.Fatalf("validate(hsts preload) = %v, want hsts preload error", err)
	}
}

func TestValidateRejectsIncompleteSAMLConfig(t *testing.T) {
	cfg := defaults()
	cfg.SessionSecret = "secret"
	cfg.SAMLEnabled = true
	cfg.SAMLRootURL = "https://proxy.example.com"
	cfg.SAMLIDPMetadataURL = "https://idp.example.com/metadata"

	err := validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "saml_sp_cert and saml_sp_key") {
		t.Fatalf("validate(saml missing keypair) = %v, want SAML keypair error", err)
	}
}

func TestValidateAllowsCompleteSAMLConfig(t *testing.T) {
	cfg := defaults()
	cfg.SessionSecret = "secret"
	cfg.SAMLEnabled = true
	cfg.SAMLRootURL = "https://proxy.example.com"
	cfg.SAMLIDPMetadataURL = "https://idp.example.com/metadata"
	cfg.SAMLSPCert = "/tmp/sp.pem"
	cfg.SAMLSPKey = "/tmp/sp.key"

	if err := validate(cfg); err != nil {
		t.Fatalf("validate(complete saml config) = %v", err)
	}
}

func TestValidateRejectsIncompleteJITEmailConfig(t *testing.T) {
	cfg := defaults()
	cfg.SessionSecret = "secret"
	cfg.JITNotifyEmailTo = "approver@example.com"
	cfg.JITNotifyEmailFrom = "proxy@example.com"

	err := validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "jit_notify_smtp_addr") {
		t.Fatalf("validate(incomplete jit email config) = %v, want smtp addr error", err)
	}
}

func TestValidateRejectsInvalidJITWebhookURL(t *testing.T) {
	cfg := defaults()
	cfg.SessionSecret = "secret"
	cfg.JITNotifySlackWebhookURL = "not-a-url"

	err := validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "jit_notify_slack_webhook_url must be a valid absolute URL") {
		t.Fatalf("validate(invalid jit slack url) = %v, want absolute URL error", err)
	}
}

func TestValidateAllowsCompleteJITNotificationConfig(t *testing.T) {
	cfg := defaults()
	cfg.SessionSecret = "secret"
	cfg.JITNotifySMTPAddr = "mail.example.com:587"
	cfg.JITNotifyEmailFrom = "proxy@example.com"
	cfg.JITNotifyEmailTo = "approver@example.com,security@example.com"
	cfg.JITNotifySlackWebhookURL = "https://hooks.slack.com/services/T000/B000/XXX"
	cfg.JITNotifyDingTalkWebhookURL = "https://oapi.dingtalk.com/robot/send?access_token=abc"
	cfg.JITNotifyWeComWebhookURL = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=abc"
	cfg.JITNotifyTeamsWebhookURL = "https://outlook.office.com/webhook/abc/IncomingWebhook/def/ghi"
	cfg.JITNotifyPagerDutyRoutingKey = "pagerduty-key"
	cfg.JITNotifyOpsgenieAPIURL = "https://api.opsgenie.com/v2/alerts"
	cfg.JITNotifyOpsgenieAPIKey = "opsgenie-key"

	if err := validate(cfg); err != nil {
		t.Fatalf("validate(complete jit notification config) = %v", err)
	}
}

func TestValidateRejectsOpsgenieURLWithoutKey(t *testing.T) {
	cfg := defaults()
	cfg.SessionSecret = "secret"
	cfg.JITNotifyOpsgenieAPIURL = "https://api.opsgenie.com/v2/alerts"

	err := validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "jit_notify_opsgenie_api_key") {
		t.Fatalf("validate(opsgenie url without key) = %v, want jit_notify_opsgenie_api_key error", err)
	}
}

func TestValidateThreatResponseDefaultsActionsWhenEnabled(t *testing.T) {
	cfg := defaults()
	cfg.SessionSecret = "secret"
	cfg.ThreatResponseEnabled = true

	if err := validate(cfg); err != nil {
		t.Fatalf("validate(threat response defaults) = %v", err)
	}
	if !cfg.ThreatResponseBlockSourceIP || !cfg.ThreatResponseKillSessions || !cfg.ThreatResponseNotify {
		t.Fatalf("threat response actions = block:%v kill:%v notify:%v, want all true", cfg.ThreatResponseBlockSourceIP, cfg.ThreatResponseKillSessions, cfg.ThreatResponseNotify)
	}
	if cfg.ThreatResponseMinSeverity != "high" {
		t.Fatalf("threat_response_min_severity = %q, want high", cfg.ThreatResponseMinSeverity)
	}
}

func TestValidateAllowsExplicitThreatResponseSeverity(t *testing.T) {
	cfg := defaults()
	cfg.SessionSecret = "secret"
	cfg.ThreatResponseEnabled = true
	cfg.ThreatResponseNotify = true
	cfg.ThreatResponseMinSeverity = "critical"

	if err := validate(cfg); err != nil {
		t.Fatalf("validate(threat response critical) = %v", err)
	}
	if cfg.ThreatResponseMinSeverity != "critical" {
		t.Fatalf("threat_response_min_severity = %q, want critical", cfg.ThreatResponseMinSeverity)
	}
}

func TestValidateRejectsInvalidThreatResponseSeverity(t *testing.T) {
	cfg := defaults()
	cfg.SessionSecret = "secret"
	cfg.ThreatResponseMinSeverity = "urgent"

	err := validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "threat_response_min_severity") {
		t.Fatalf("validate(invalid threat response severity) = %v, want threat_response_min_severity error", err)
	}
}

func TestValidateAllowsNonNegativeDLPFileSizeLimits(t *testing.T) {
	cfg := defaults()
	cfg.SessionSecret = "secret"
	cfg.DLPFileMaxUploadBytes = 1024
	cfg.DLPFileMaxDownloadBytes = 2048

	if err := validate(cfg); err != nil {
		t.Fatalf("validate(dlp file size limits) = %v", err)
	}
}

func TestValidateRejectsNegativeDLPFileSizeLimit(t *testing.T) {
	cfg := defaults()
	cfg.SessionSecret = "secret"
	cfg.DLPFileMaxUploadBytes = -1

	err := validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "dlp_file_max_upload_bytes") {
		t.Fatalf("validate(negative dlp file size limit) = %v, want dlp_file_max_upload_bytes error", err)
	}
}

func TestValidateDefaultsSensitiveDetectorsWhenEnabled(t *testing.T) {
	cfg := defaults()
	cfg.SessionSecret = "secret"
	cfg.DLPSensitiveScanEnabled = true

	if err := validate(cfg); err != nil {
		t.Fatalf("validate(dlp sensitive defaults) = %v", err)
	}
	if !cfg.DLPSensitiveDetectCreditCard || !cfg.DLPSensitiveDetectCNIDCard || !cfg.DLPSensitiveDetectAPIKey {
		t.Fatalf("sensitive detectors = cc:%v cnid:%v api:%v, want all true", cfg.DLPSensitiveDetectCreditCard, cfg.DLPSensitiveDetectCNIDCard, cfg.DLPSensitiveDetectAPIKey)
	}
	if cfg.DLPSensitiveMaxScanBytes != 1024*1024 {
		t.Fatalf("dlp_sensitive_max_scan_bytes = %d, want 1048576", cfg.DLPSensitiveMaxScanBytes)
	}
}

func TestValidateRejectsNegativeSensitiveScanBytes(t *testing.T) {
	cfg := defaults()
	cfg.SessionSecret = "secret"
	cfg.DLPSensitiveScanEnabled = true
	cfg.DLPSensitiveMaxScanBytes = -1

	err := validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "dlp_sensitive_max_scan_bytes") {
		t.Fatalf("validate(negative dlp sensitive scan bytes) = %v, want dlp_sensitive_max_scan_bytes error", err)
	}
}

func TestValidateAllowsClipboardAuditWithSensitiveScan(t *testing.T) {
	cfg := defaults()
	cfg.SessionSecret = "secret"
	cfg.DLPSensitiveScanEnabled = true
	cfg.DLPClipboardAuditEnabled = true

	if err := validate(cfg); err != nil {
		t.Fatalf("validate(clipboard audit) = %v", err)
	}
}

func TestValidateRejectsClipboardAuditWithoutSensitiveScan(t *testing.T) {
	cfg := defaults()
	cfg.SessionSecret = "secret"
	cfg.DLPClipboardAuditEnabled = true

	err := validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "dlp_clipboard_audit_enabled") {
		t.Fatalf("validate(clipboard audit without sensitive scan) = %v, want dlp_clipboard_audit_enabled error", err)
	}
}

func TestValidateAllowsTransferApprovalDefaults(t *testing.T) {
	cfg := defaults()
	cfg.SessionSecret = "secret"
	cfg.DLPTransferApprovalEnabled = true

	if err := validate(cfg); err != nil {
		t.Fatalf("validate(transfer approval defaults) = %v", err)
	}
	if cfg.DLPTransferApprovalRoles != "admin" {
		t.Fatalf("dlp_transfer_approval_roles = %q, want admin", cfg.DLPTransferApprovalRoles)
	}
	if cfg.DLPTransferApprovalTimeout != "30m" {
		t.Fatalf("dlp_transfer_approval_timeout = %q, want 30m", cfg.DLPTransferApprovalTimeout)
	}
}

func TestValidateRejectsInvalidTransferApprovalTimeout(t *testing.T) {
	cfg := defaults()
	cfg.SessionSecret = "secret"
	cfg.DLPTransferApprovalEnabled = true
	cfg.DLPTransferApprovalTimeout = "0s"

	err := validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "dlp_transfer_approval_timeout") {
		t.Fatalf("validate(invalid transfer approval timeout) = %v, want dlp_transfer_approval_timeout error", err)
	}
}

func TestValidateRejectsInvalidSAMLRootURL(t *testing.T) {
	cfg := defaults()
	cfg.SessionSecret = "secret"
	cfg.SAMLEnabled = true
	cfg.SAMLRootURL = "proxy.example.com"
	cfg.SAMLIDPMetadataURL = "https://idp.example.com/metadata"
	cfg.SAMLSPCert = "/tmp/sp.pem"
	cfg.SAMLSPKey = "/tmp/sp.key"

	err := validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "saml_root_url must be a valid absolute URL") {
		t.Fatalf("validate(invalid saml root url) = %v, want absolute URL error", err)
	}
}

func TestValidateRejectsInvalidSAMLMetadataURL(t *testing.T) {
	cfg := defaults()
	cfg.SessionSecret = "secret"
	cfg.SAMLEnabled = true
	cfg.SAMLRootURL = "https://proxy.example.com"
	cfg.SAMLIDPMetadataURL = "not-a-url"
	cfg.SAMLSPCert = "/tmp/sp.pem"
	cfg.SAMLSPKey = "/tmp/sp.key"

	err := validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "saml_idp_metadata_url must be a valid absolute URL") {
		t.Fatalf("validate(invalid saml metadata url) = %v, want absolute URL error", err)
	}
}

func TestValidateAllowsReadableGeoIPDataFile(t *testing.T) {
	cfg := defaults()
	cfg.SessionSecret = "secret"
	cfg.GeoIPDataFile = filepath.Join(t.TempDir(), "geoip.json")
	if err := os.WriteFile(cfg.GeoIPDataFile, []byte(`[]`), 0o600); err != nil {
		t.Fatalf("WriteFile(geoip) error = %v", err)
	}

	if err := validate(cfg); err != nil {
		t.Fatalf("validate(geoip file) = %v", err)
	}
}

func TestValidateRejectsMissingGeoIPDataFile(t *testing.T) {
	cfg := defaults()
	cfg.SessionSecret = "secret"
	cfg.GeoIPDataFile = filepath.Join(t.TempDir(), "missing.json")

	err := validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "geoip_data_file must point to a readable file") {
		t.Fatalf("validate(missing geoip file) = %v, want geoip_data_file error", err)
	}
}

func TestValidateAllowsRecordingObjectStorageConfig(t *testing.T) {
	cfg := defaults()
	cfg.SessionSecret = "secret"
	cfg.RecordingObjectStorageEnabled = true
	cfg.RecordingObjectStorageEndpoint = "https://s3.example.com"
	cfg.RecordingObjectStorageBucket = "session-recordings"
	cfg.RecordingObjectStorageAccessKey = "access"
	cfg.RecordingObjectStorageSecretKey = "secret"

	if err := validate(cfg); err != nil {
		t.Fatalf("validate(recording object storage) = %v", err)
	}
}

func TestValidateRejectsIncompleteRecordingObjectStorageConfig(t *testing.T) {
	cfg := defaults()
	cfg.SessionSecret = "secret"
	cfg.RecordingObjectStorageEnabled = true
	cfg.RecordingObjectStorageBucket = "session-recordings"

	err := validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "recording_object_storage_endpoint") {
		t.Fatalf("validate(incomplete recording object storage) = %v, want endpoint error", err)
	}
}

func TestValidateAllowsAuditArchiveObjectStorageConfig(t *testing.T) {
	cfg := defaults()
	cfg.SessionSecret = "secret"
	cfg.AuditArchiveObjectStorageEnabled = true
	cfg.AuditArchiveObjectStorageEndpoint = "https://s3.example.com"
	cfg.AuditArchiveObjectStorageBucket = "audit-logs"
	cfg.AuditArchiveObjectStorageAccessKey = "access"
	cfg.AuditArchiveObjectStorageSecretKey = "secret"

	if err := validate(cfg); err != nil {
		t.Fatalf("validate(audit archive object storage) = %v", err)
	}
}

func TestValidateRejectsIncompleteAuditArchiveObjectStorageConfig(t *testing.T) {
	cfg := defaults()
	cfg.SessionSecret = "secret"
	cfg.AuditArchiveObjectStorageEnabled = true
	cfg.AuditArchiveObjectStorageBucket = "audit-logs"

	err := validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "audit_archive_object_storage_endpoint") {
		t.Fatalf("validate(incomplete audit archive object storage) = %v, want endpoint error", err)
	}
}

func TestValidateAllowsPostgresStoreBackends(t *testing.T) {
	cfg := defaults()
	cfg.SessionSecret = "secret"
	cfg.ConfigStoreBackend = "postgresql"
	cfg.UserStoreBackend = "postgres"
	cfg.PostgresDatabaseURL = "postgres://proxy:secret@db.example.com:5432/sshproxy?sslmode=require"

	if err := validate(cfg); err != nil {
		t.Fatalf("validate(postgres store backends) = %v", err)
	}
	if cfg.ConfigStoreBackend != "postgres" || cfg.UserStoreBackend != "postgres" {
		t.Fatalf("normalized backends = %q / %q", cfg.ConfigStoreBackend, cfg.UserStoreBackend)
	}
}

func TestValidateRejectsPostgresBackendWithoutDatabaseURL(t *testing.T) {
	cfg := defaults()
	cfg.SessionSecret = "secret"
	cfg.ConfigStoreBackend = "postgres"

	err := validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "postgres_database_url") {
		t.Fatalf("validate(postgres backend without url) = %v, want postgres_database_url error", err)
	}
}

func TestValidateRejectsUnknownStoreBackend(t *testing.T) {
	cfg := defaults()
	cfg.SessionSecret = "secret"
	cfg.UserStoreBackend = "sqlite"

	err := validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "user_store_backend") {
		t.Fatalf("validate(unknown store backend) = %v, want user_store_backend error", err)
	}
}

func TestValidateAllowsTimescaleAuditStoreWithSharedPostgresURL(t *testing.T) {
	cfg := defaults()
	cfg.SessionSecret = "secret"
	cfg.AuditStoreBackend = "timescaledb"
	cfg.PostgresDatabaseURL = "postgres://proxy:secret@db.example.com:5432/sshproxy?sslmode=require"

	if err := validate(cfg); err != nil {
		t.Fatalf("validate(timescaledb audit store) = %v", err)
	}
	if cfg.AuditStoreBackend != "timescaledb" {
		t.Fatalf("normalized audit store backend = %q", cfg.AuditStoreBackend)
	}
}

func TestValidateAllowsElasticsearchAuditStore(t *testing.T) {
	cfg := defaults()
	cfg.SessionSecret = "secret"
	cfg.AuditStoreBackend = "elastic"
	cfg.AuditStoreEndpoint = "https://elastic.example.com:9200"
	cfg.AuditStoreToken = "secret-token"

	if err := validate(cfg); err != nil {
		t.Fatalf("validate(elasticsearch audit store) = %v", err)
	}
	if cfg.AuditStoreBackend != "elasticsearch" {
		t.Fatalf("normalized audit store backend = %q", cfg.AuditStoreBackend)
	}
	if cfg.AuditStoreIndex != "ssh-proxy-audit" {
		t.Fatalf("default audit store index = %q", cfg.AuditStoreIndex)
	}
}

func TestValidateAllowsDatabasePoolAndReplicaConfig(t *testing.T) {
	cfg := defaults()
	cfg.SessionSecret = "secret"
	cfg.ConfigStoreBackend = "postgres"
	cfg.UserStoreBackend = "postgres"
	cfg.AuditStoreBackend = "postgres"
	cfg.PostgresDatabaseURL = "postgres://proxy:secret@db.example.com:5432/sshproxy?sslmode=require"
	cfg.PostgresReadDatabaseURLs = "postgres://proxy:secret@db-ro-1.example.com:5432/sshproxy?sslmode=require, postgres://proxy:secret@db-ro-2.example.com:5432/sshproxy?sslmode=require"
	cfg.AuditStoreReadDatabaseURLs = "postgres://proxy:secret@audit-ro.example.com:5432/sshproxy?sslmode=require"
	cfg.DatabaseMaxOpenConns = 24
	cfg.DatabaseMaxIdleConns = 12
	cfg.DatabaseConnMaxLifetime = "45m"
	cfg.DatabaseConnMaxIdleTime = "10m"
	cfg.DatabaseReadAfterWriteWindow = "3s"

	if err := validate(cfg); err != nil {
		t.Fatalf("validate(database pool config) = %v", err)
	}
}

func TestValidateRejectsDatabasePoolMismatch(t *testing.T) {
	cfg := defaults()
	cfg.SessionSecret = "secret"
	cfg.DatabaseMaxOpenConns = 4
	cfg.DatabaseMaxIdleConns = 5

	err := validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "database_max_idle_conns") {
		t.Fatalf("validate(database pool mismatch) = %v, want database_max_idle_conns error", err)
	}
}

func TestValidateRejectsAuditStoreWithoutDatabaseURL(t *testing.T) {
	cfg := defaults()
	cfg.SessionSecret = "secret"
	cfg.AuditStoreBackend = "postgres"

	err := validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "audit_store_database_url") {
		t.Fatalf("validate(audit store without url) = %v, want audit store db url error", err)
	}
}

func TestValidateRejectsSearchAuditStoreWithoutEndpoint(t *testing.T) {
	cfg := defaults()
	cfg.SessionSecret = "secret"
	cfg.AuditStoreBackend = "opensearch"

	err := validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "audit_store_endpoint") {
		t.Fatalf("validate(search audit store without endpoint) = %v, want audit store endpoint error", err)
	}
}

func TestValidateRejectsPartialSearchAuditStoreBasicAuth(t *testing.T) {
	cfg := defaults()
	cfg.SessionSecret = "secret"
	cfg.AuditStoreBackend = "elasticsearch"
	cfg.AuditStoreEndpoint = "https://elastic.example.com:9200"
	cfg.AuditStoreUsername = "elastic"

	err := validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "audit_store_username and audit_store_password") {
		t.Fatalf("validate(partial search audit store basic auth) = %v, want audit store basic auth error", err)
	}
}

func TestValidateAllowsKafkaAuditQueue(t *testing.T) {
	cfg := defaults()
	cfg.SessionSecret = "secret"
	cfg.AuditQueueBackend = "kafka"
	cfg.AuditQueueEndpoint = "kafka-1.example.com:9092,kafka-2.example.com:9092"
	cfg.AuditQueueTopic = "ssh-proxy-audit"

	if err := validate(cfg); err != nil {
		t.Fatalf("validate(kafka audit queue) = %v", err)
	}
}

func TestValidateAllowsRabbitMQAuditQueue(t *testing.T) {
	cfg := defaults()
	cfg.SessionSecret = "secret"
	cfg.AuditQueueBackend = "rabbitmq"
	cfg.AuditQueueEndpoint = "amqps://guest:guest@mq.example.com:5671/%2f"
	cfg.AuditQueueExchange = "audit.events"
	cfg.AuditQueueRoutingKey = "ssh-proxy.audit"

	if err := validate(cfg); err != nil {
		t.Fatalf("validate(rabbitmq audit queue) = %v", err)
	}
}

func TestValidateRejectsKafkaAuditQueueWithoutTopic(t *testing.T) {
	cfg := defaults()
	cfg.SessionSecret = "secret"
	cfg.AuditQueueBackend = "kafka"
	cfg.AuditQueueEndpoint = "kafka-1.example.com:9092"

	err := validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "audit_queue_topic") {
		t.Fatalf("validate(kafka audit queue without topic) = %v, want audit_queue_topic error", err)
	}
}

func TestValidateRejectsRabbitMQAuditQueueWithoutRoutingKey(t *testing.T) {
	cfg := defaults()
	cfg.SessionSecret = "secret"
	cfg.AuditQueueBackend = "rabbitmq"
	cfg.AuditQueueEndpoint = "amqp://guest:guest@mq.example.com:5672/%2f"
	cfg.AuditQueueExchange = "audit.events"

	err := validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "audit_queue_routing_key") {
		t.Fatalf("validate(rabbitmq audit queue without routing key) = %v, want audit_queue_routing_key error", err)
	}
}
