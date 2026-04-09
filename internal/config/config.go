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
	// Supported values: "file" (default), "postgres", or "timescaledb".
	AuditStoreBackend string `json:"audit_store_backend"`

	// AuditStoreDatabaseURL optionally overrides the DSN/URL used by the audit
	// store. When empty, postgres_database_url is reused for postgres-compatible
	// backends.
	AuditStoreDatabaseURL string `json:"audit_store_database_url"`

	// AuditStoreReadDatabaseURLs is a comma-separated list of read-replica DSNs/URLs
	// dedicated to audit queries. When empty, audit reads stay on the writer unless
	// postgres_read_database_urls is reused.
	AuditStoreReadDatabaseURLs string `json:"audit_store_read_database_urls"`

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
		ListenAddr:                   ":8443",
		DataPlaneAddr:                "http://127.0.0.1:9090",
		DataPlaneConfigFile:          "/etc/ssh-proxy/config.ini",
		SSHProxyAddr:                 "127.0.0.1:2222",
		AdminUser:                    "admin",
		AuditLogDir:                  "/var/log/ssh-proxy",
		RecordingDir:                 "/var/lib/ssh-proxy/recordings",
		RecordingObjectStoragePrefix: "recordings",
		DataDir:                      "/var/lib/ssh-proxy",
		ConfigStoreBackend:           "file",
		UserStoreBackend:             "file",
		AuditStoreBackend:            "file",
		DatabaseMaxOpenConns:         10,
		DatabaseMaxIdleConns:         5,
		DatabaseConnMaxLifetime:      "30m",
		DatabaseConnMaxIdleTime:      "5m",
		DatabaseReadAfterWriteWindow: "2s",
		SAMLAllowIDPInitiated:        true,
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
	if cfg.AuditStoreBackend != "file" &&
		strings.TrimSpace(cfg.AuditStoreDatabaseURL) == "" &&
		strings.TrimSpace(cfg.PostgresDatabaseURL) == "" {
		return fmt.Errorf("config: audit_store_database_url or postgres_database_url is required when audit_store_backend is enabled")
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
	} {
		if endpoint.value == "" {
			continue
		}
		parsed, err := url.Parse(strings.TrimSpace(endpoint.value))
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return fmt.Errorf("config: %s must be a valid absolute URL", endpoint.name)
		}
	}
	if strings.TrimSpace(cfg.GeoIPDataFile) != "" {
		if _, err := os.Stat(strings.TrimSpace(cfg.GeoIPDataFile)); err != nil {
			return fmt.Errorf("config: geoip_data_file must point to a readable file: %w", err)
		}
	}
	recordingArchiveConfigured := cfg.RecordingObjectStorageEnabled ||
		strings.TrimSpace(cfg.RecordingObjectStorageEndpoint) != "" ||
		strings.TrimSpace(cfg.RecordingObjectStorageBucket) != "" ||
		strings.TrimSpace(cfg.RecordingObjectStorageAccessKey) != "" ||
		strings.TrimSpace(cfg.RecordingObjectStorageSecretKey) != ""
	if recordingArchiveConfigured {
		required := []struct {
			name  string
			value string
		}{
			{name: "recording_object_storage_endpoint", value: cfg.RecordingObjectStorageEndpoint},
			{name: "recording_object_storage_bucket", value: cfg.RecordingObjectStorageBucket},
			{name: "recording_object_storage_access_key", value: cfg.RecordingObjectStorageAccessKey},
			{name: "recording_object_storage_secret_key", value: cfg.RecordingObjectStorageSecretKey},
		}
		for _, field := range required {
			if strings.TrimSpace(field.value) == "" {
				return fmt.Errorf("config: %s is required when recording object storage is enabled", field.name)
			}
		}
		endpoint := strings.TrimSpace(cfg.RecordingObjectStorageEndpoint)
		if strings.Contains(endpoint, "://") {
			parsed, err := url.Parse(endpoint)
			if err != nil || parsed.Scheme == "" || parsed.Host == "" {
				return fmt.Errorf("config: recording_object_storage_endpoint must be a valid absolute URL when a scheme is provided")
			}
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
	default:
		return "", fmt.Errorf("must be one of: file, postgres, timescaledb")
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
