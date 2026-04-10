// Package config handles loading and validating the control-plane
// configuration. Values are read from a JSON file and can be overridden by
// environment variables prefixed with SSH_PROXY_CP_.
package config

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/cluster"
)

// Config holds every tunable for the control-plane process.
type Config struct {
	// ListenAddr is the address the HTTP(S) server binds to (e.g. ":8443").
	ListenAddr string `json:"listen_addr"`

	// TLSCert is the path to a PEM-encoded TLS certificate.  When both
	// TLSCert and TLSKey are set the server uses HTTPS.
	TLSCert string `json:"tls_cert"`

	// TLSKey is the path to the corresponding PEM-encoded private key.
	TLSKey string `json:"tls_key"`

	// TLSSelfSigned generates an in-memory self-signed server certificate when enabled.
	TLSSelfSigned bool `json:"tls_self_signed"`

	// TLSSelfSignedHosts is an optional comma-separated SAN list for self-signed certificates.
	TLSSelfSignedHosts string `json:"tls_self_signed_hosts"`

	// TLSLetsEncrypt enables automatic Let's Encrypt certificate issuance and renewal.
	TLSLetsEncrypt bool `json:"tls_lets_encrypt"`

	// TLSLetsEncryptHosts is a comma-separated host allowlist for Let's Encrypt issuance.
	TLSLetsEncryptHosts string `json:"tls_lets_encrypt_hosts"`

	// TLSLetsEncryptCacheDir stores the local autocert cache. Defaults under data_dir when empty.
	TLSLetsEncryptCacheDir string `json:"tls_lets_encrypt_cache_dir"`

	// HSTSEnabled adds the Strict-Transport-Security header on HTTPS responses.
	HSTSEnabled bool `json:"hsts_enabled"`

	// HSTSIncludeSubdomains adds includeSubDomains to the HSTS policy.
	HSTSIncludeSubdomains bool `json:"hsts_include_subdomains"`

	// HSTSPreload adds preload to the HSTS policy. Requires includeSubDomains.
	HSTSPreload bool `json:"hsts_preload"`

	// DataPlaneAddr is the base URL of the C data-plane admin API.
	DataPlaneAddr string `json:"data_plane_addr"`

	// DataPlaneToken is the Bearer token sent to the data-plane API.
	DataPlaneToken string `json:"data_plane_token"`

	// DataPlaneConfigFile points at the managed data-plane config.ini used for
	// webhook verification, compliance checks, and other file-backed features.
	DataPlaneConfigFile string `json:"data_plane_config_file"`

	// GeoIPDataFile points at a JSON CIDR→location database used to enrich threat events.
	GeoIPDataFile string `json:"geoip_data_file"`

	// GRPCListenAddr enables the internal gRPC listener when non-empty
	// (e.g. "127.0.0.1:9445").
	GRPCListenAddr string `json:"grpc_listen_addr"`

	// ConfigApprovalEnabled makes PUT /api/v2/config queue a persisted approval
	// request instead of applying changes immediately.
	ConfigApprovalEnabled bool `json:"config_approval_enabled"`

	// ConfigStoreBackend selects how centralized config snapshots + version history
	// are persisted. Supported values: "file" (default) or "postgres".
	ConfigStoreBackend string `json:"config_store_backend"`

	// UserStoreBackend selects how /api/v2/users data is persisted. Supported
	// values: "file" (default) or "postgres".
	UserStoreBackend string `json:"user_store_backend"`

	// PostgresDatabaseURL is the DSN/URL used when either config_store_backend or
	// user_store_backend is set to "postgres".
	PostgresDatabaseURL string `json:"postgres_database_url"`

	// PostgresReadDatabaseURLs is a comma-separated list of read-replica DSNs/URLs
	// used for read-mostly config/user queries. When empty, reads stay on the writer.
	PostgresReadDatabaseURLs string `json:"postgres_read_database_urls"`

	// AuditStoreBackend selects how audit events are indexed for query APIs.
	// Supported values: "file" (default), "postgres", "timescaledb",
	// "elasticsearch", or "opensearch".
	AuditStoreBackend string `json:"audit_store_backend"`

	// AuditStoreDatabaseURL optionally overrides the DSN/URL used by the audit
	// store. When empty, postgres_database_url is reused for postgres-compatible
	// backends.
	AuditStoreDatabaseURL string `json:"audit_store_database_url"`

	// AuditStoreReadDatabaseURLs is a comma-separated list of read-replica DSNs/URLs
	// dedicated to audit queries. When empty, audit reads stay on the writer unless
	// postgres_read_database_urls is reused.
	AuditStoreReadDatabaseURLs string `json:"audit_store_read_database_urls"`

	// AuditStoreEndpoint is the base URL of an Elasticsearch/OpenSearch cluster
	// used when audit_store_backend is a search backend.
	AuditStoreEndpoint string `json:"audit_store_endpoint"`

	// AuditStoreToken is an optional bearer token used for Elasticsearch/OpenSearch APIs.
	AuditStoreToken string `json:"audit_store_token"`

	// AuditStoreUsername is the optional basic-auth username used for Elasticsearch/OpenSearch APIs.
	AuditStoreUsername string `json:"audit_store_username"`

	// AuditStorePassword is the optional basic-auth password paired with AuditStoreUsername.
	AuditStorePassword string `json:"audit_store_password"`

	// AuditStoreIndex is the Elasticsearch/OpenSearch index name used for audit documents.
	AuditStoreIndex string `json:"audit_store_index"`

	// AuditStoreInsecureTLS skips TLS verification for Elasticsearch/OpenSearch APIs.
	AuditStoreInsecureTLS bool `json:"audit_store_insecure_tls"`

	// DatabaseMaxOpenConns is the writer/reader pool upper bound for each SQL DSN.
	DatabaseMaxOpenConns int `json:"database_max_open_conns"`

	// DatabaseMaxIdleConns is the idle connection pool size for each SQL DSN.
	DatabaseMaxIdleConns int `json:"database_max_idle_conns"`

	// DatabaseConnMaxLifetime caps how long pooled SQL connections live (for example "30m").
	DatabaseConnMaxLifetime string `json:"database_conn_max_lifetime"`

	// DatabaseConnMaxIdleTime caps how long pooled SQL connections may stay idle.
	DatabaseConnMaxIdleTime string `json:"database_conn_max_idle_time"`

	// DatabaseReadAfterWriteWindow keeps reads on the writer briefly after a local write
	// to reduce replica-lag surprises for immediate read-after-write workflows.
	DatabaseReadAfterWriteWindow string `json:"database_read_after_write_window"`

	// SSHProxyAddr is the TCP address of the SSH proxy entrypoint used by the
	// browser terminal bridge.
	SSHProxyAddr string `json:"ssh_proxy_addr"`

	// SessionSecret is the HMAC key used to sign web session cookies.
	SessionSecret string `json:"session_secret"`

	// AdminUser is the default administrator username.
	AdminUser string `json:"admin_user"`

	// AdminPassHash is the bcrypt hash of the default admin password.
	AdminPassHash string `json:"admin_pass_hash"`

	// AuditLogDir is the directory where audit-log files are written.
	AuditLogDir string `json:"audit_log_dir"`

	// RecordingDir is the directory for SSH session recordings.
	RecordingDir string `json:"recording_dir"`

	// DLPFileAllowNames is a comma-separated filename allowlist for browser
	// terminal file transfers. Globs use path.Match syntax.
	DLPFileAllowNames string `json:"dlp_file_allow_names"`

	// DLPFileDenyNames is a comma-separated filename denylist for browser
	// terminal file transfers. Deny rules override allow rules.
	DLPFileDenyNames string `json:"dlp_file_deny_names"`

	// DLPFileAllowExtensions is a comma-separated extension allowlist for browser
	// terminal file transfers. Values may be written with or without a leading dot.
	DLPFileAllowExtensions string `json:"dlp_file_allow_extensions"`

	// DLPFileDenyExtensions is a comma-separated extension denylist for browser
	// terminal file transfers.
	DLPFileDenyExtensions string `json:"dlp_file_deny_extensions"`

	// DLPFileAllowPaths is a comma-separated path allowlist for browser terminal
	// file transfers. Paths are matched against normalized transfer paths.
	DLPFileAllowPaths string `json:"dlp_file_allow_paths"`

	// DLPFileDenyPaths is a comma-separated path denylist for browser terminal
	// file transfers.
	DLPFileDenyPaths string `json:"dlp_file_deny_paths"`

	// DLPFileMaxUploadBytes rejects browser-terminal uploads larger than this
	// many bytes. Zero disables the size limit.
	DLPFileMaxUploadBytes int64 `json:"dlp_file_max_upload_bytes"`

	// DLPFileMaxDownloadBytes rejects browser-terminal downloads larger than this
	// many bytes. Zero disables the size limit.
	DLPFileMaxDownloadBytes int64 `json:"dlp_file_max_download_bytes"`

	// DLPSensitiveScanEnabled enables browser-terminal content inspection using
	// the configured built-in detectors before upload/save completes.
	DLPSensitiveScanEnabled bool `json:"dlp_sensitive_scan_enabled"`

	// DLPSensitiveDetectCreditCard enables built-in credit-card regex detection.
	DLPSensitiveDetectCreditCard bool `json:"dlp_sensitive_detect_credit_card"`

	// DLPSensitiveDetectCNIDCard enables built-in mainland China ID-card regex detection.
	DLPSensitiveDetectCNIDCard bool `json:"dlp_sensitive_detect_cn_id_card"`

	// DLPSensitiveDetectAPIKey enables built-in API-key and secret-token regex detection.
	DLPSensitiveDetectAPIKey bool `json:"dlp_sensitive_detect_api_key"`

	// DLPSensitiveMaxScanBytes caps how many bytes are scanned for sensitive
	// content in a single browser-terminal transfer. Zero means "scan all bytes".
	DLPSensitiveMaxScanBytes int64 `json:"dlp_sensitive_max_scan_bytes"`

	// DLPTransferApprovalEnabled turns sensitive-content DLP violations into
	// persisted approval requests that approvers can decide via the control-plane API.
	DLPTransferApprovalEnabled bool `json:"dlp_transfer_approval_enabled"`

	// DLPTransferApprovalRoles is a comma-separated list of roles allowed to
	// approve or deny terminal transfer approval requests.
	DLPTransferApprovalRoles string `json:"dlp_transfer_approval_roles"`

	// DLPTransferApprovalTimeout controls how long pending or approved transfer
	// approvals remain valid.
	DLPTransferApprovalTimeout string `json:"dlp_transfer_approval_timeout"`

	// DLPClipboardAuditEnabled enables browser-terminal clipboard paste auditing
	// using the same built-in sensitive detectors as transfer content scanning.
	DLPClipboardAuditEnabled bool `json:"dlp_clipboard_audit_enabled"`

	// RecordingObjectStorageEnabled enables near-real-time archival of session
	// recordings to an S3-compatible object store such as S3, MinIO, or OSS.
	RecordingObjectStorageEnabled bool `json:"recording_object_storage_enabled"`

	// RecordingObjectStorageEndpoint is the S3-compatible endpoint. It accepts
	// either host[:port] or a full http(s):// URL.
	RecordingObjectStorageEndpoint string `json:"recording_object_storage_endpoint"`

	// RecordingObjectStorageBucket is the destination bucket/container name.
	RecordingObjectStorageBucket string `json:"recording_object_storage_bucket"`

	// RecordingObjectStorageAccessKey is the static access key for uploads/downloads.
	RecordingObjectStorageAccessKey string `json:"recording_object_storage_access_key"`

	// RecordingObjectStorageSecretKey is the secret key paired with the access key.
	RecordingObjectStorageSecretKey string `json:"recording_object_storage_secret_key"`

	// RecordingObjectStorageRegion is the optional bucket region.
	RecordingObjectStorageRegion string `json:"recording_object_storage_region"`

	// RecordingObjectStoragePrefix is the object-key prefix used for archived recordings.
	RecordingObjectStoragePrefix string `json:"recording_object_storage_prefix"`

	// RecordingObjectStorageUseSSL forces TLS when the endpoint omits a URL scheme.
	RecordingObjectStorageUseSSL bool `json:"recording_object_storage_use_ssl"`

	// AuditArchiveObjectStorageEnabled enables near-real-time archival of audit
	// log files to an S3-compatible object store such as S3, MinIO, or OSS.
	AuditArchiveObjectStorageEnabled bool `json:"audit_archive_object_storage_enabled"`

	// AuditArchiveObjectStorageEndpoint is the S3-compatible endpoint. It accepts
	// either host[:port] or a full http(s):// URL.
	AuditArchiveObjectStorageEndpoint string `json:"audit_archive_object_storage_endpoint"`

	// AuditArchiveObjectStorageBucket is the destination bucket/container name.
	AuditArchiveObjectStorageBucket string `json:"audit_archive_object_storage_bucket"`

	// AuditArchiveObjectStorageAccessKey is the static access key for uploads/downloads.
	AuditArchiveObjectStorageAccessKey string `json:"audit_archive_object_storage_access_key"`

	// AuditArchiveObjectStorageSecretKey is the secret key paired with the access key.
	AuditArchiveObjectStorageSecretKey string `json:"audit_archive_object_storage_secret_key"`

	// AuditArchiveObjectStorageRegion is the optional bucket region.
	AuditArchiveObjectStorageRegion string `json:"audit_archive_object_storage_region"`

	// AuditArchiveObjectStoragePrefix is the object-key prefix used for archived audit logs.
	AuditArchiveObjectStoragePrefix string `json:"audit_archive_object_storage_prefix"`

	// AuditArchiveObjectStorageUseSSL forces TLS when the endpoint omits a URL scheme.
	AuditArchiveObjectStorageUseSSL bool `json:"audit_archive_object_storage_use_ssl"`

	// AuditQueueBackend enables background audit event forwarding to a message queue.
	// Supported values: "", "kafka", or "rabbitmq".
	AuditQueueBackend string `json:"audit_queue_backend"`

	// AuditQueueEndpoint identifies the queue target. For kafka it is a
	// comma-separated host:port broker list; for rabbitmq it is an amqp:// or
	// amqps:// connection URL.
	AuditQueueEndpoint string `json:"audit_queue_endpoint"`

	// AuditQueueTopic is required when AuditQueueBackend is "kafka".
	AuditQueueTopic string `json:"audit_queue_topic"`

	// AuditQueueExchange is required when AuditQueueBackend is "rabbitmq".
	AuditQueueExchange string `json:"audit_queue_exchange"`

	// AuditQueueRoutingKey is required when AuditQueueBackend is "rabbitmq".
	AuditQueueRoutingKey string `json:"audit_queue_routing_key"`

	// DataDir stores control-plane state such as users, servers, JIT, and
	// config version history.
	DataDir string `json:"data_dir"`

	// StaticDir overrides the embedded static asset directory when set.
	StaticDir string `json:"static_dir"`

	// Debug enables verbose logging.
	Debug bool `json:"debug"`

	// ClusterEnabled enables the embedded cluster manager and public cluster APIs.
	ClusterEnabled bool `json:"cluster_enabled"`

	// ClusterNodeID identifies this node in the control-plane cluster.
	ClusterNodeID string `json:"cluster_node_id"`

	// ClusterNodeName is a human-readable cluster node name.
	ClusterNodeName string `json:"cluster_node_name"`

	// ClusterBindAddr is the cluster gossip/listen address.
	ClusterBindAddr string `json:"cluster_bind_addr"`

	// ClusterAPIAddr is the advertised public API address for this node.
	ClusterAPIAddr string `json:"cluster_api_addr"`

	// ClusterRegion labels this node's region for cross-region topology awareness.
	ClusterRegion string `json:"cluster_region"`

	// ClusterZone labels this node's availability zone / fault domain.
	ClusterZone string `json:"cluster_zone"`

	// ClusterSeeds lists seed node addresses or discovery URIs (dns://, k8s://, consul://)
	// used to join an existing cluster.
	ClusterSeeds []string `json:"cluster_seeds"`

	// ClusterHeartbeatInterval overrides the leader heartbeat cadence (for example "5s").
	ClusterHeartbeatInterval string `json:"cluster_heartbeat_interval"`

	// ClusterElectionTimeout overrides the follower election timeout (for example "15s").
	ClusterElectionTimeout string `json:"cluster_election_timeout"`

	// ClusterSyncInterval overrides the background state/discovery sync cadence (for example "10s").
	ClusterSyncInterval string `json:"cluster_sync_interval"`

	// ClusterTLSCert is the PEM certificate used for mutual TLS on cluster-internal HTTP traffic.
	ClusterTLSCert string `json:"cluster_tls_cert"`

	// ClusterTLSKey is the private key paired with ClusterTLSCert.
	ClusterTLSKey string `json:"cluster_tls_key"`

	// ClusterTLSCA is the CA bundle used to verify and require peer certificates.
	ClusterTLSCA string `json:"cluster_tls_ca"`

	// OIDCEnabled enables OIDC/OAuth2 single sign-on.
	OIDCEnabled bool `json:"oidc_enabled"`

	// OIDCIssuer is the OIDC provider's issuer URL (e.g. https://accounts.google.com).
	OIDCIssuer string `json:"oidc_issuer"`

	// OIDCClientID is the OAuth2 client ID registered with the provider.
	OIDCClientID string `json:"oidc_client_id"`

	// OIDCClientSecret is the OAuth2 client secret (may be empty for public clients with PKCE).
	OIDCClientSecret string `json:"oidc_client_secret"`

	// OIDCRedirectURL is the callback URL (e.g. https://proxy.example.com/auth/callback).
	OIDCRedirectURL string `json:"oidc_redirect_url"`

	// OIDCScopes are the OAuth2 scopes to request (default: ["openid","profile","email"]).
	OIDCScopes []string `json:"oidc_scopes"`

	// OIDCRolesClaim is the JWT claim used to extract group/role info (default: "groups").
	OIDCRolesClaim string `json:"oidc_roles_claim"`

	// OIDCRoleMappings maps IdP group names to internal roles (e.g. {"admins":"admin"}).
	OIDCRoleMappings map[string]string `json:"oidc_role_mappings"`

	// SAMLEnabled enables SAML 2.0 single sign-on for the control-plane web UI.
	SAMLEnabled bool `json:"saml_enabled"`

	// SAMLRootURL is the externally reachable base URL of the control plane (e.g. https://proxy.example.com).
	SAMLRootURL string `json:"saml_root_url"`

	// SAMLEntityID overrides the SP entity ID. Defaults to <saml_root_url>/auth/saml/metadata.
	SAMLEntityID string `json:"saml_entity_id"`

	// SAMLIDPMetadataURL points to the IdP metadata endpoint (ADFS / Shibboleth / OneLogin / etc.).
	SAMLIDPMetadataURL string `json:"saml_idp_metadata_url"`

	// SAMLIDPMetadataFile loads IdP metadata from a local XML file instead of a URL.
	SAMLIDPMetadataFile string `json:"saml_idp_metadata_file"`

	// SAMLSPCert is the PEM certificate used by the SP to sign authentication requests and publish metadata.
	SAMLSPCert string `json:"saml_sp_cert"`

	// SAMLSPKey is the PEM private key paired with SAMLSPCert.
	SAMLSPKey string `json:"saml_sp_key"`

	// SAMLUsernameAttribute is the preferred assertion attribute used as the local username.
	SAMLUsernameAttribute string `json:"saml_username_attribute"`

	// SAMLRolesAttribute is the preferred assertion attribute used for role mapping.
	SAMLRolesAttribute string `json:"saml_roles_attribute"`

	// SAMLRoleMappings maps assertion group/role values to control-plane roles.
	SAMLRoleMappings map[string]string `json:"saml_role_mappings"`

	// SAMLAllowIDPInitiated enables direct IdP-initiated SSO in addition to SP-initiated login.
	SAMLAllowIDPInitiated bool `json:"saml_allow_idp_initiated"`

	// JITNotifySMTPAddr is the SMTP relay address used for JIT approval emails (e.g. mail.example.com:587).
	JITNotifySMTPAddr string `json:"jit_notify_smtp_addr"`

	// JITNotifySMTPUsername is the optional SMTP username used for JIT notification emails.
	JITNotifySMTPUsername string `json:"jit_notify_smtp_username"`

	// JITNotifySMTPPassword is the optional SMTP password paired with JITNotifySMTPUsername.
	JITNotifySMTPPassword string `json:"jit_notify_smtp_password"`

	// JITNotifyEmailFrom is the RFC 5322 From address used for JIT approval emails.
	JITNotifyEmailFrom string `json:"jit_notify_email_from"`

	// JITNotifyEmailTo is a comma-separated list of approver mailbox recipients.
	JITNotifyEmailTo string `json:"jit_notify_email_to"`

	// JITNotifySlackWebhookURL is the Slack Incoming Webhook URL for JIT approval notifications.
	JITNotifySlackWebhookURL string `json:"jit_notify_slack_webhook_url"`

	// JITNotifyDingTalkWebhookURL is the DingTalk robot webhook URL for JIT approval notifications.
	JITNotifyDingTalkWebhookURL string `json:"jit_notify_dingtalk_webhook_url"`

	// JITNotifyWeComWebhookURL is the WeCom robot webhook URL for JIT approval notifications.
	JITNotifyWeComWebhookURL string `json:"jit_notify_wecom_webhook_url"`

	// JITNotifyTeamsWebhookURL is the Microsoft Teams incoming webhook URL for
	// JIT approval and threat-response notifications.
	JITNotifyTeamsWebhookURL string `json:"jit_notify_teams_webhook_url"`

	// JITNotifyPagerDutyRoutingKey enables PagerDuty Events API v2 delivery for
	// JIT/threat notifications.
	JITNotifyPagerDutyRoutingKey string `json:"jit_notify_pagerduty_routing_key"`

	// JITNotifyOpsgenieAPIURL overrides the default Opsgenie alerts API endpoint.
	JITNotifyOpsgenieAPIURL string `json:"jit_notify_opsgenie_api_url"`

	// JITNotifyOpsgenieAPIKey enables Opsgenie alert delivery for JIT/threat notifications.
	JITNotifyOpsgenieAPIKey string `json:"jit_notify_opsgenie_api_key"`

	// JITNotifySubjectTemplate overrides the default subject used for JIT-event notifications.
	JITNotifySubjectTemplate string `json:"jit_notify_subject_template"`

	// JITNotifyBodyTemplate overrides the default body used for JIT-event notifications.
	JITNotifyBodyTemplate string `json:"jit_notify_body_template"`

	// JITNotifyMessageSubjectTemplate overrides the subject used for generic message notifications.
	JITNotifyMessageSubjectTemplate string `json:"jit_notify_message_subject_template"`

	// JITNotifyMessageBodyTemplate overrides the body used for generic message notifications.
	JITNotifyMessageBodyTemplate string `json:"jit_notify_message_body_template"`

	// JITChatOpsSlackSigningSecret enables the Slack slash-command approval bot
	// endpoint by verifying Slack request signatures with this secret.
	JITChatOpsSlackSigningSecret string `json:"jit_chatops_slack_signing_secret"`

	// ThreatResponseEnabled consumes new threat alerts and can automatically
	// block the source IP, terminate matching sessions, and notify admins.
	ThreatResponseEnabled bool `json:"threat_response_enabled"`

	// ThreatResponseBlockSourceIP prepends a deny rule for alert source_ip to
	// the managed data-plane ip_acl rules.
	ThreatResponseBlockSourceIP bool `json:"threat_response_block_source_ip"`

	// ThreatResponseKillSessions terminates active sessions matching the alert
	// username/source_ip/target tuple.
	ThreatResponseKillSessions bool `json:"threat_response_kill_sessions"`

	// ThreatResponseNotify reuses the jit_notify_* sinks to fan out threat
	// response notifications.
	ThreatResponseNotify bool `json:"threat_response_notify"`

	// ThreatResponseMinSeverity is the minimum alert severity that triggers
	// automatic response actions. Supported values: low, medium, high, critical.
	ThreatResponseMinSeverity string `json:"threat_response_min_severity"`
}

// Load reads a JSON configuration file at path and returns a Config.
// After loading the file, every field can be overridden by an environment
// variable named SSH_PROXY_CP_<UPPER_SNAKE_FIELD>.  For example the field
// ListenAddr is overridden by SSH_PROXY_CP_LISTEN_ADDR.
func Load(path string) (*Config, error) {
	cfg := defaults()

	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("config: read %s: %w", path, err)
		}
		if err := json.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("config: parse %s: %w", path, err)
		}
	}

	applyEnv(cfg)

	if err := validate(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// defaults returns a Config populated with sane default values.
func defaults() *Config {
	return &Config{
		ListenAddr:                      ":8443",
		DataPlaneAddr:                   "http://127.0.0.1:9090",
		DataPlaneConfigFile:             "/etc/ssh-proxy/config.ini",
		SSHProxyAddr:                    "127.0.0.1:2222",
		AdminUser:                       "admin",
		AuditLogDir:                     "/var/log/ssh-proxy",
		RecordingDir:                    "/var/lib/ssh-proxy/recordings",
		RecordingObjectStoragePrefix:    "recordings",
		AuditArchiveObjectStoragePrefix: "audit",
		DataDir:                         "/var/lib/ssh-proxy",
		ConfigStoreBackend:              "file",
		UserStoreBackend:                "file",
		AuditStoreBackend:               "file",
		AuditStoreIndex:                 "ssh-proxy-audit",
		DatabaseMaxOpenConns:            10,
		DatabaseMaxIdleConns:            5,
		DatabaseConnMaxLifetime:         "30m",
		DatabaseConnMaxIdleTime:         "5m",
		DatabaseReadAfterWriteWindow:    "2s",
		DLPSensitiveMaxScanBytes:        1024 * 1024,
		DLPTransferApprovalTimeout:      "30m",
		DLPTransferApprovalRoles:        "admin",
		SAMLAllowIDPInitiated:           true,
		ThreatResponseMinSeverity:       "high",
	}
}

// applyEnv overrides string, bool, and int fields from environment variables.
// The mapping is: FieldName → SSH_PROXY_CP_<UPPER_SNAKE>.
func applyEnv(cfg *Config) {
	v := reflect.ValueOf(cfg).Elem()
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		envKey := "SSH_PROXY_CP_" + toUpperSnake(field.Name)
		envVal, ok := os.LookupEnv(envKey)
		if !ok {
			continue
		}
		fv := v.Field(i)
		switch fv.Kind() {
		case reflect.String:
			fv.SetString(envVal)
		case reflect.Bool:
			fv.SetBool(strings.EqualFold(envVal, "true") || envVal == "1")
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			if parsed, err := strconv.ParseInt(strings.TrimSpace(envVal), 10, 64); err == nil {
				fv.SetInt(parsed)
			}
		}
	}
}

// toUpperSnake converts a Go CamelCase field name to UPPER_SNAKE_CASE.
// e.g. "DataPlaneAddr" → "DATA_PLANE_ADDR".
func toUpperSnake(name string) string {
	var buf strings.Builder
	for i, r := range name {
		if i > 0 && r >= 'A' && r <= 'Z' {
			buf.WriteByte('_')
		}
		if r >= 'a' && r <= 'z' {
			buf.WriteRune(r - 'a' + 'A')
		} else {
			buf.WriteRune(r)
		}
	}
	return buf.String()
}

// validate ensures required fields are present.
func validate(cfg *Config) error {
	configStoreBackend, err := normalizeStoreBackend(cfg.ConfigStoreBackend)
	if err != nil {
		return fmt.Errorf("config: config_store_backend %w", err)
	}
	userStoreBackend, err := normalizeStoreBackend(cfg.UserStoreBackend)
	if err != nil {
		return fmt.Errorf("config: user_store_backend %w", err)
	}
	auditStoreBackend, err := normalizeAuditStoreBackend(cfg.AuditStoreBackend)
	if err != nil {
		return fmt.Errorf("config: audit_store_backend %w", err)
	}
	cfg.ConfigStoreBackend = configStoreBackend
	cfg.UserStoreBackend = userStoreBackend
	cfg.AuditStoreBackend = auditStoreBackend
	auditQueueBackend, err := normalizeAuditQueueBackend(cfg.AuditQueueBackend)
	if err != nil {
		return fmt.Errorf("config: audit_queue_backend %w", err)
	}
	cfg.AuditQueueBackend = auditQueueBackend
	cfg.AuditStoreIndex = strings.TrimSpace(cfg.AuditStoreIndex)
	if cfg.AuditStoreIndex == "" {
		cfg.AuditStoreIndex = "ssh-proxy-audit"
	}
	minSeverity, err := normalizeThreatResponseSeverity(cfg.ThreatResponseMinSeverity)
	if err != nil {
		return fmt.Errorf("config: threat_response_min_severity %w", err)
	}
	cfg.ThreatResponseMinSeverity = minSeverity
	if cfg.ThreatResponseEnabled &&
		!cfg.ThreatResponseBlockSourceIP &&
		!cfg.ThreatResponseKillSessions &&
		!cfg.ThreatResponseNotify {
		cfg.ThreatResponseBlockSourceIP = true
		cfg.ThreatResponseKillSessions = true
		cfg.ThreatResponseNotify = true
	}
	if cfg.DLPFileMaxUploadBytes < 0 {
		return fmt.Errorf("config: dlp_file_max_upload_bytes must be >= 0")
	}
	if cfg.DLPFileMaxDownloadBytes < 0 {
		return fmt.Errorf("config: dlp_file_max_download_bytes must be >= 0")
	}
	if cfg.DLPSensitiveScanEnabled &&
		!cfg.DLPSensitiveDetectCreditCard &&
		!cfg.DLPSensitiveDetectCNIDCard &&
		!cfg.DLPSensitiveDetectAPIKey {
		cfg.DLPSensitiveDetectCreditCard = true
		cfg.DLPSensitiveDetectCNIDCard = true
		cfg.DLPSensitiveDetectAPIKey = true
	}
	if cfg.DLPSensitiveMaxScanBytes < 0 {
		return fmt.Errorf("config: dlp_sensitive_max_scan_bytes must be >= 0")
	}
	if cfg.DLPClipboardAuditEnabled && !cfg.DLPSensitiveScanEnabled {
		return fmt.Errorf("config: dlp_clipboard_audit_enabled requires dlp_sensitive_scan_enabled")
	}
	if cfg.DLPTransferApprovalEnabled {
		if strings.TrimSpace(cfg.DLPTransferApprovalRoles) == "" {
			cfg.DLPTransferApprovalRoles = "admin"
		}
		timeout, err := time.ParseDuration(strings.TrimSpace(cfg.DLPTransferApprovalTimeout))
		if err != nil || timeout <= 0 {
			return fmt.Errorf("config: dlp_transfer_approval_timeout must be a positive duration")
		}
	}
	if err := normalizeDatabasePool(cfg); err != nil {
		return fmt.Errorf("config: %w", err)
	}

	if cfg.ListenAddr == "" {
		return fmt.Errorf("config: listen_addr is required")
	}
	if cfg.SessionSecret == "" {
		return fmt.Errorf("config: session_secret is required (set SSH_PROXY_CP_SESSION_SECRET or in config file)")
	}
	tlsModes := 0
	if cfg.TLSCert != "" || cfg.TLSKey != "" {
		if cfg.TLSCert == "" || cfg.TLSKey == "" {
			return fmt.Errorf("config: tls_cert and tls_key must both be set")
		}
		tlsModes++
	}
	if cfg.TLSSelfSigned {
		tlsModes++
	}
	if cfg.TLSLetsEncrypt {
		if strings.TrimSpace(cfg.TLSLetsEncryptHosts) == "" {
			return fmt.Errorf("config: tls_lets_encrypt_hosts is required when tls_lets_encrypt is true")
		}
		tlsModes++
	}
	if tlsModes > 1 {
		return fmt.Errorf("config: tls_cert/tls_key, tls_self_signed, and tls_lets_encrypt are mutually exclusive")
	}
	if cfg.HSTSPreload && !cfg.HSTSIncludeSubdomains {
		return fmt.Errorf("config: hsts_preload requires hsts_include_subdomains")
	}
	if (cfg.ConfigStoreBackend == "postgres" || cfg.UserStoreBackend == "postgres") &&
		strings.TrimSpace(cfg.PostgresDatabaseURL) == "" {
		return fmt.Errorf("config: postgres_database_url is required when a postgres-backed store is enabled")
	}
	if auditStoreUsesSQL(cfg.AuditStoreBackend) &&
		strings.TrimSpace(cfg.AuditStoreDatabaseURL) == "" &&
		strings.TrimSpace(cfg.PostgresDatabaseURL) == "" {
		return fmt.Errorf("config: audit_store_database_url or postgres_database_url is required when audit_store_backend is enabled")
	}
	if auditStoreUsesSearch(cfg.AuditStoreBackend) {
		endpoint := strings.TrimSpace(cfg.AuditStoreEndpoint)
		if endpoint == "" {
			return fmt.Errorf("config: audit_store_endpoint is required when audit_store_backend is elasticsearch or opensearch")
		}
		parsed, err := url.Parse(endpoint)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return fmt.Errorf("config: audit_store_endpoint must be a valid absolute URL when audit_store_backend is elasticsearch or opensearch")
		}
		if (strings.TrimSpace(cfg.AuditStoreUsername) == "") != (strings.TrimSpace(cfg.AuditStorePassword) == "") {
			return fmt.Errorf("config: audit_store_username and audit_store_password must be set together")
		}
	}
	if cfg.AuditQueueBackend != "" {
		endpoint := strings.TrimSpace(cfg.AuditQueueEndpoint)
		if endpoint == "" {
			return fmt.Errorf("config: audit_queue_endpoint is required when audit_queue_backend is enabled")
		}
		switch cfg.AuditQueueBackend {
		case "kafka":
			brokers := strings.Split(endpoint, ",")
			validBrokers := 0
			for _, broker := range brokers {
				broker = strings.TrimSpace(broker)
				if broker == "" {
					continue
				}
				validBrokers++
				if _, _, err := net.SplitHostPort(broker); err != nil {
					return fmt.Errorf("config: audit_queue_endpoint broker %q must be host:port when audit_queue_backend is kafka", broker)
				}
			}
			if validBrokers == 0 {
				return fmt.Errorf("config: audit_queue_endpoint must list at least one broker when audit_queue_backend is kafka")
			}
			if strings.TrimSpace(cfg.AuditQueueTopic) == "" {
				return fmt.Errorf("config: audit_queue_topic is required when audit_queue_backend is kafka")
			}
		case "rabbitmq":
			parsed, err := url.Parse(endpoint)
			if err != nil || parsed.Host == "" || (parsed.Scheme != "amqp" && parsed.Scheme != "amqps") {
				return fmt.Errorf("config: audit_queue_endpoint must be a valid amqp:// or amqps:// URL when audit_queue_backend is rabbitmq")
			}
			if strings.TrimSpace(cfg.AuditQueueExchange) == "" {
				return fmt.Errorf("config: audit_queue_exchange is required when audit_queue_backend is rabbitmq")
			}
			if strings.TrimSpace(cfg.AuditQueueRoutingKey) == "" {
				return fmt.Errorf("config: audit_queue_routing_key is required when audit_queue_backend is rabbitmq")
			}
		}
	}
	if cfg.ClusterEnabled {
		if cfg.ClusterNodeID == "" {
			return fmt.Errorf("config: cluster_node_id is required when cluster_enabled is true")
		}
		if cfg.ClusterBindAddr == "" {
			return fmt.Errorf("config: cluster_bind_addr is required when cluster_enabled is true")
		}
		for _, seed := range cfg.ClusterSeeds {
			if err := cluster.ValidateSeedReference(seed); err != nil {
				return fmt.Errorf("config: invalid cluster_seeds entry %q: %w", seed, err)
			}
		}
		for _, durationField := range []struct {
			name  string
			value string
		}{
			{name: "cluster_heartbeat_interval", value: cfg.ClusterHeartbeatInterval},
			{name: "cluster_election_timeout", value: cfg.ClusterElectionTimeout},
			{name: "cluster_sync_interval", value: cfg.ClusterSyncInterval},
		} {
			if strings.TrimSpace(durationField.value) == "" {
				continue
			}
			dur, err := time.ParseDuration(strings.TrimSpace(durationField.value))
			if err != nil || dur <= 0 {
				return fmt.Errorf("config: %s must be a positive duration", durationField.name)
			}
		}
		clusterTLSModes := 0
		if cfg.ClusterTLSCert != "" || cfg.ClusterTLSKey != "" || cfg.ClusterTLSCA != "" {
			if cfg.ClusterTLSCert == "" || cfg.ClusterTLSKey == "" || cfg.ClusterTLSCA == "" {
				return fmt.Errorf("config: cluster_tls_cert, cluster_tls_key, and cluster_tls_ca must all be set together")
			}
			clusterTLSModes++
		}
		_ = clusterTLSModes
	}
	if cfg.SAMLEnabled {
		if strings.TrimSpace(cfg.SAMLRootURL) == "" {
			return fmt.Errorf("config: saml_root_url is required when saml_enabled is true")
		}
		rootURL, err := url.Parse(strings.TrimSpace(cfg.SAMLRootURL))
		if err != nil || rootURL.Scheme == "" || rootURL.Host == "" {
			return fmt.Errorf("config: saml_root_url must be a valid absolute URL")
		}
		hasMetadataURL := strings.TrimSpace(cfg.SAMLIDPMetadataURL) != ""
		hasMetadataFile := strings.TrimSpace(cfg.SAMLIDPMetadataFile) != ""
		if hasMetadataURL == hasMetadataFile {
			return fmt.Errorf("config: exactly one of saml_idp_metadata_url or saml_idp_metadata_file must be set when saml_enabled is true")
		}
		if hasMetadataURL {
			metadataURL, err := url.Parse(strings.TrimSpace(cfg.SAMLIDPMetadataURL))
			if err != nil || metadataURL.Scheme == "" || metadataURL.Host == "" {
				return fmt.Errorf("config: saml_idp_metadata_url must be a valid absolute URL")
			}
		}
		if (cfg.SAMLSPCert == "") != (cfg.SAMLSPKey == "") || cfg.SAMLSPCert == "" {
			return fmt.Errorf("config: saml_sp_cert and saml_sp_key must both be set when saml_enabled is true")
		}
	}
	emailConfigured := strings.TrimSpace(cfg.JITNotifyEmailTo) != "" ||
		strings.TrimSpace(cfg.JITNotifySMTPAddr) != "" ||
		strings.TrimSpace(cfg.JITNotifyEmailFrom) != "" ||
		strings.TrimSpace(cfg.JITNotifySMTPUsername) != "" ||
		strings.TrimSpace(cfg.JITNotifySMTPPassword) != ""
	if emailConfigured {
		if strings.TrimSpace(cfg.JITNotifyEmailTo) == "" {
			return fmt.Errorf("config: jit_notify_email_to is required when JIT email notifications are configured")
		}
		if strings.TrimSpace(cfg.JITNotifySMTPAddr) == "" {
			return fmt.Errorf("config: jit_notify_smtp_addr is required when JIT email notifications are configured")
		}
		if strings.TrimSpace(cfg.JITNotifyEmailFrom) == "" {
			return fmt.Errorf("config: jit_notify_email_from is required when JIT email notifications are configured")
		}
		if (cfg.JITNotifySMTPUsername == "") != (cfg.JITNotifySMTPPassword == "") {
			return fmt.Errorf("config: jit_notify_smtp_username and jit_notify_smtp_password must be set together")
		}
		if _, _, err := net.SplitHostPort(strings.TrimSpace(cfg.JITNotifySMTPAddr)); err != nil {
			return fmt.Errorf("config: jit_notify_smtp_addr must be host:port")
		}
	}
	for _, endpoint := range []struct {
		name  string
		value string
	}{
		{name: "jit_notify_slack_webhook_url", value: cfg.JITNotifySlackWebhookURL},
		{name: "jit_notify_dingtalk_webhook_url", value: cfg.JITNotifyDingTalkWebhookURL},
		{name: "jit_notify_wecom_webhook_url", value: cfg.JITNotifyWeComWebhookURL},
		{name: "jit_notify_teams_webhook_url", value: cfg.JITNotifyTeamsWebhookURL},
	} {
		if endpoint.value == "" {
			continue
		}
		parsed, err := url.Parse(strings.TrimSpace(endpoint.value))
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return fmt.Errorf("config: %s must be a valid absolute URL", endpoint.name)
		}
	}
	if strings.TrimSpace(cfg.JITNotifyOpsgenieAPIURL) != "" {
		parsed, err := url.Parse(strings.TrimSpace(cfg.JITNotifyOpsgenieAPIURL))
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return fmt.Errorf("config: jit_notify_opsgenie_api_url must be a valid absolute URL")
		}
	}
	if strings.TrimSpace(cfg.JITNotifyOpsgenieAPIURL) != "" && strings.TrimSpace(cfg.JITNotifyOpsgenieAPIKey) == "" {
		return fmt.Errorf("config: jit_notify_opsgenie_api_key is required when jit_notify_opsgenie_api_url is configured")
	}
	if strings.TrimSpace(cfg.GeoIPDataFile) != "" {
		if _, err := os.Stat(strings.TrimSpace(cfg.GeoIPDataFile)); err != nil {
			return fmt.Errorf("config: geoip_data_file must point to a readable file: %w", err)
		}
	}
	if err := validateObjectStorageConfig(
		cfg.RecordingObjectStorageEnabled,
		cfg.RecordingObjectStorageEndpoint,
		cfg.RecordingObjectStorageBucket,
		cfg.RecordingObjectStorageAccessKey,
		cfg.RecordingObjectStorageSecretKey,
		"recording_object_storage",
	); err != nil {
		return err
	}
	if err := validateObjectStorageConfig(
		cfg.AuditArchiveObjectStorageEnabled,
		cfg.AuditArchiveObjectStorageEndpoint,
		cfg.AuditArchiveObjectStorageBucket,
		cfg.AuditArchiveObjectStorageAccessKey,
		cfg.AuditArchiveObjectStorageSecretKey,
		"audit_archive_object_storage",
	); err != nil {
		return err
	}
	return nil
}

func validateObjectStorageConfig(enabled bool, endpoint, bucket, accessKey, secretKey, prefix string) error {
	configured := enabled ||
		strings.TrimSpace(endpoint) != "" ||
		strings.TrimSpace(bucket) != "" ||
		strings.TrimSpace(accessKey) != "" ||
		strings.TrimSpace(secretKey) != ""
	if !configured {
		return nil
	}
	required := []struct {
		name  string
		value string
	}{
		{name: prefix + "_endpoint", value: endpoint},
		{name: prefix + "_bucket", value: bucket},
		{name: prefix + "_access_key", value: accessKey},
		{name: prefix + "_secret_key", value: secretKey},
	}
	for _, field := range required {
		if strings.TrimSpace(field.value) == "" {
			return fmt.Errorf("config: %s is required when %s is enabled", field.name, prefix)
		}
	}
	endpoint = strings.TrimSpace(endpoint)
	if strings.Contains(endpoint, "://") {
		parsed, err := url.Parse(endpoint)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return fmt.Errorf("config: %s_endpoint must be a valid absolute URL when a scheme is provided", prefix)
		}
	}
	return nil
}

func normalizeStoreBackend(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "file":
		return "file", nil
	case "postgres", "postgresql":
		return "postgres", nil
	default:
		return "", fmt.Errorf("must be one of: file, postgres")
	}
}

func normalizeAuditStoreBackend(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "file":
		return "file", nil
	case "postgres", "postgresql":
		return "postgres", nil
	case "timescaledb":
		return "timescaledb", nil
	case "elastic", "elasticsearch":
		return "elasticsearch", nil
	case "opensearch":
		return "opensearch", nil
	default:
		return "", fmt.Errorf("must be one of: file, postgres, timescaledb, elasticsearch, opensearch")
	}
}

func normalizeAuditQueueBackend(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return "", nil
	case "kafka":
		return "kafka", nil
	case "rabbitmq":
		return "rabbitmq", nil
	default:
		return "", fmt.Errorf("must be one of: kafka, rabbitmq")
	}
}

func normalizeThreatResponseSeverity(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "high":
		return "high", nil
	case "low", "medium", "critical":
		return strings.ToLower(strings.TrimSpace(raw)), nil
	default:
		return "", fmt.Errorf("must be one of low, medium, high, or critical")
	}
}

func auditStoreUsesSQL(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "postgres", "postgresql", "timescaledb":
		return true
	default:
		return false
	}
}

func auditStoreUsesSearch(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "elastic", "elasticsearch", "opensearch":
		return true
	default:
		return false
	}
}

func normalizeDatabasePool(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	if cfg.DatabaseMaxOpenConns < 0 {
		return fmt.Errorf("database_max_open_conns must be >= 0")
	}
	if cfg.DatabaseMaxOpenConns == 0 {
		cfg.DatabaseMaxOpenConns = 10
	}
	if cfg.DatabaseMaxIdleConns < 0 {
		return fmt.Errorf("database_max_idle_conns must be >= 0")
	}
	if cfg.DatabaseMaxIdleConns == 0 {
		cfg.DatabaseMaxIdleConns = 5
	}
	if cfg.DatabaseMaxIdleConns > cfg.DatabaseMaxOpenConns {
		return fmt.Errorf("database_max_idle_conns must be <= database_max_open_conns")
	}
	if strings.TrimSpace(cfg.DatabaseConnMaxLifetime) == "" {
		cfg.DatabaseConnMaxLifetime = "30m"
	}
	if strings.TrimSpace(cfg.DatabaseConnMaxIdleTime) == "" {
		cfg.DatabaseConnMaxIdleTime = "5m"
	}
	if strings.TrimSpace(cfg.DatabaseReadAfterWriteWindow) == "" {
		cfg.DatabaseReadAfterWriteWindow = "2s"
	}
	for _, durationField := range []struct {
		name  string
		value string
	}{
		{name: "database_conn_max_lifetime", value: cfg.DatabaseConnMaxLifetime},
		{name: "database_conn_max_idle_time", value: cfg.DatabaseConnMaxIdleTime},
		{name: "database_read_after_write_window", value: cfg.DatabaseReadAfterWriteWindow},
	} {
		d, err := time.ParseDuration(strings.TrimSpace(durationField.value))
		if err != nil {
			return fmt.Errorf("%s must be a valid duration: %w", durationField.name, err)
		}
		if d < 0 {
			return fmt.Errorf("%s must be >= 0", durationField.name)
		}
	}
	return nil
}
