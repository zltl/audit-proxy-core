// Package config handles loading and validating the control-plane
// configuration. Values are read from a JSON file and can be overridden by
// environment variables prefixed with SSH_PROXY_CP_.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
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

	// DataPlaneAddr is the base URL of the C data-plane admin API.
	DataPlaneAddr string `json:"data_plane_addr"`

	// DataPlaneToken is the Bearer token sent to the data-plane API.
	DataPlaneToken string `json:"data_plane_token"`

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

	// StaticDir overrides the embedded static asset directory when set.
	StaticDir string `json:"static_dir"`

	// Debug enables verbose logging.
	Debug bool `json:"debug"`

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
		ListenAddr:    ":8443",
		DataPlaneAddr: "http://127.0.0.1:9090",
		AdminUser:     "admin",
		AuditLogDir:   "/var/log/ssh-proxy",
		RecordingDir:  "/var/lib/ssh-proxy/recordings",
	}
}

// applyEnv overrides string and bool fields from environment variables.
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
	if cfg.ListenAddr == "" {
		return fmt.Errorf("config: listen_addr is required")
	}
	if cfg.SessionSecret == "" {
		return fmt.Errorf("config: session_secret is required (set SSH_PROXY_CP_SESSION_SECRET or in config file)")
	}
	return nil
}
