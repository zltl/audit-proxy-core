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

	if err := validate(cfg); err != nil {
		t.Fatalf("validate(complete jit notification config) = %v", err)
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
