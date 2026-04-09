package api

import (
	"net/http"
	"os"
	"strings"
	"testing"
)

func TestGetConfigParsesINIFile(t *testing.T) {
	api, mux, _ := setupTestAPI(t)
	iniConfig := `[server]
bind_addr = 127.0.0.1
port = 2200
host_key = /etc/ssh-proxy/host_key
show_progress = false

[logging]
level = warn
format = json

[limits]
max_sessions = 250
session_timeout = 7200
auth_timeout = 90

[router]
retry_max = 4
retry_initial_delay_ms = 150
retry_max_delay_ms = 2500
retry_backoff_factor = 1.5
circuit_breaker_enabled = true
circuit_breaker_failure_threshold = 5
circuit_breaker_open_seconds = 45

[ip_acl]
mode = whitelist
rules = 10.0.0.0/8:allow
log_rejections = true

[auth]
backend = ldap
ldap_uri = ldaps://ldap.example.com:636
ldap_bind_pw = bind-secret

[mfa]
enabled = true
issuer = Prod
time_step = 45

[webhook]
enabled = true
url = https://hooks.example.com
hmac_secret = hook-secret
events = auth.success, session.start

[network_sources]
office_cidrs = 10.0.0.0/8
vpn_cidrs = 100.64.0.0/10
geoip_data_file = /etc/ssh-proxy/geoip.json

[route:admin]
upstream = prod-1
port = 22
user = ubuntu
region = California
city = San Francisco
latitude = 37.7749
longitude = -122.4194

[policy:admin]
allow = shell, exec
deny = port_forward
allowed_source_types = office, vpn
login_window = 09:00-18:00
login_days = mon-fri
login_timezone = +08:00
`
	if err := os.WriteFile(api.config.ConfigFile, []byte(iniConfig), 0o600); err != nil {
		t.Fatal(err)
	}

	rr := doRequest(mux, http.MethodGet, "/api/v2/config", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	resp := parseResponse(t, rr)
	data := resp.Data.(map[string]interface{})
	if data["bind_addr"] != "127.0.0.1" {
		t.Fatalf("expected bind_addr from INI, got %#v", data["bind_addr"])
	}
	if data["port"].(float64) != 2200 {
		t.Fatalf("expected parsed port, got %#v", data["port"])
	}
	if data["auth_backend"] != "ldap" {
		t.Fatalf("expected ldap backend, got %#v", data["auth_backend"])
	}
	if data["ldap_bind_pw"] != redactedConfigValue {
		t.Fatalf("expected redacted ldap bind password, got %#v", data["ldap_bind_pw"])
	}
	if data["webhook_hmac_secret"] != redactedConfigValue {
		t.Fatalf("expected redacted webhook secret, got %#v", data["webhook_hmac_secret"])
	}
	if data["source_office_cidrs"] != "10.0.0.0/8" || data["source_vpn_cidrs"] != "100.64.0.0/10" {
		t.Fatalf("expected parsed network source cidrs, got office=%#v vpn=%#v", data["source_office_cidrs"], data["source_vpn_cidrs"])
	}
	if data["source_geoip_data_file"] != "/etc/ssh-proxy/geoip.json" {
		t.Fatalf("expected parsed geoip data path, got %#v", data["source_geoip_data_file"])
	}
	if !data["mfa_enabled"].(bool) {
		t.Fatalf("expected mfa_enabled true, got %#v", data["mfa_enabled"])
	}
	if data["router_retry_max"].(float64) != 4 ||
		data["router_retry_initial_delay_ms"].(float64) != 150 ||
		data["router_retry_max_delay_ms"].(float64) != 2500 ||
		data["router_retry_backoff_factor"].(float64) != 1.5 ||
		!data["router_circuit_breaker_enabled"].(bool) ||
		data["router_circuit_breaker_failure_threshold"].(float64) != 5 ||
		data["router_circuit_breaker_open_seconds"].(float64) != 45 {
		t.Fatalf("expected parsed router circuit-breaker fields, got retry=%#v threshold=%#v", data["router_retry_max"], data["router_circuit_breaker_failure_threshold"])
	}
	routes := data["routes"].([]interface{})
	if len(routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(routes))
	}
	route := routes[0].(map[string]interface{})
	if route["region"] != "California" || route["city"] != "San Francisco" ||
		route["latitude"].(float64) != 37.7749 || route["longitude"].(float64) != -122.4194 {
		t.Fatalf("expected parsed route geo fields, got %#v", route)
	}
	policies := data["policies"].([]interface{})
	if len(policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(policies))
	}
	policy := policies[0].(map[string]interface{})
	if policy["login_window"] != "09:00-18:00" || policy["login_days"] != "mon-fri" || policy["login_timezone"] != "+08:00" {
		t.Fatalf("expected parsed policy time-window fields, got %#v", policy)
	}
	if got := policy["allowed_source_types"].([]interface{}); len(got) != 2 || got[0] != "office" || got[1] != "vpn" {
		t.Fatalf("expected parsed policy source types, got %#v", policy["allowed_source_types"])
	}
}

func TestExportConfigRendersINIAndYAML(t *testing.T) {
	api, mux, _ := setupTestAPI(t)
	configJSON := `{
  "bind_addr": "0.0.0.0",
  "port": 2222,
  "log_level": "info",
  "log_format": "json",
  "router_retry_max": 4,
  "router_retry_initial_delay_ms": 150,
  "router_retry_max_delay_ms": 2500,
  "router_retry_backoff_factor": 1.5,
  "router_circuit_breaker_enabled": true,
  "router_circuit_breaker_failure_threshold": 5,
  "router_circuit_breaker_open_seconds": 45,
  "webhook_enabled": true,
  "webhook_url": "https://hooks.example.com",
  "webhook_hmac_secret": "super-secret",
  "source_office_cidrs": "10.0.0.0/8",
  "source_vpn_cidrs": "100.64.0.0/10",
  "source_geoip_data_file": "/etc/ssh-proxy/geoip.json",
  "routes": [
    {
      "pattern": "*",
      "upstream": "bastion",
      "port": 22,
      "user": "ubuntu",
      "region": "California",
      "city": "San Francisco",
      "latitude": 37.7749,
      "longitude": -122.4194
    }
  ],
  "policies": [
    {
      "pattern": "*",
      "allow": ["shell", "exec"],
      "allowed_source_types": ["office", "vpn"],
      "denied_source_types": ["public"],
      "login_window": "09:00-18:00",
      "login_days": "mon-fri",
      "login_timezone": "+08:00"
    }
  ]
}`
	if err := os.WriteFile(api.config.ConfigFile, []byte(configJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	rr := doRequest(mux, http.MethodGet, "/api/v2/config/export?format=ini", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	resp := parseResponse(t, rr)
	data := resp.Data.(map[string]interface{})
	content := data["content"].(string)
	for _, needle := range []string{"[server]", "bind_addr = 0.0.0.0", "[router]", "retry_max = 4", "retry_initial_delay_ms = 150", "retry_max_delay_ms = 2500", "retry_backoff_factor = 1.5", "circuit_breaker_enabled = true", "circuit_breaker_failure_threshold = 5", "circuit_breaker_open_seconds = 45", "[webhook]", "hmac_secret = super-secret", "[network_sources]", "office_cidrs = 10.0.0.0/8", "vpn_cidrs = 100.64.0.0/10", "geoip_data_file = /etc/ssh-proxy/geoip.json", "[route:*]", "region = California", "city = San Francisco", "latitude = 37.7749", "longitude = -122.4194", "[policy:*]", "allowed_source_types = office, vpn", "denied_source_types = public", "login_window = 09:00-18:00", "login_days = mon-fri", "login_timezone = +08:00"} {
		if !strings.Contains(content, needle) {
			t.Fatalf("expected INI export to contain %q, got %s", needle, content)
		}
	}

	rr = doRequest(mux, http.MethodGet, "/api/v2/config/export?format=yaml", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	resp = parseResponse(t, rr)
	data = resp.Data.(map[string]interface{})
	content = data["content"].(string)
	for _, needle := range []string{"bind_addr: 0.0.0.0", "router_retry_max: 4", "router_retry_initial_delay_ms: 150", "router_retry_max_delay_ms: 2500", "router_retry_backoff_factor: 1.5", "router_circuit_breaker_enabled: true", "router_circuit_breaker_failure_threshold: 5", "router_circuit_breaker_open_seconds: 45", "webhook_hmac_secret: super-secret", "source_office_cidrs: 10.0.0.0/8", "source_vpn_cidrs: 100.64.0.0/10", "source_geoip_data_file: /etc/ssh-proxy/geoip.json", "routes:", "region: California", "city: San Francisco", "latitude: 37.7749", "longitude: -122.4194", "allowed_source_types:", "denied_source_types:", "login_window: 09:00-18:00", "login_days: mon-fri", "login_timezone: \"+08:00\""} {
		if !strings.Contains(content, needle) {
			t.Fatalf("expected YAML export to contain %q, got %s", needle, content)
		}
	}
}

func TestImportConfigParsesINIAndBuildsSanitizedDiff(t *testing.T) {
	api, mux, _ := setupTestAPI(t)
	if err := os.WriteFile(api.config.ConfigFile, []byte(`{"bind_addr":"0.0.0.0","port":2222,"webhook_hmac_secret":"current-secret"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	rr := doRequest(mux, http.MethodPost, "/api/v2/config/import", map[string]interface{}{
		"format": "ini",
		"content": `[server]
bind_addr = 127.0.0.1
port = 2022

[webhook]
enabled = true
hmac_secret = imported-secret

[network_sources]
geoip_data_file = /tmp/geoip.json

[router]
retry_max = 4
circuit_breaker_enabled = true
circuit_breaker_failure_threshold = 5
circuit_breaker_open_seconds = 45

[route:ops]
upstream = ops-1
port = 22
user = ubuntu
region = Hesse
city = Frankfurt
latitude = 50.1109
longitude = 8.6821
`,
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	resp := parseResponse(t, rr)
	data := resp.Data.(map[string]interface{})
	if data["format"] != configFormatINI {
		t.Fatalf("expected format ini, got %#v", data["format"])
	}
	config := data["config"].(map[string]interface{})
	if config["bind_addr"] != "127.0.0.1" {
		t.Fatalf("expected imported bind_addr, got %#v", config["bind_addr"])
	}
	if config["webhook_hmac_secret"] != "imported-secret" {
		t.Fatalf("expected raw imported secret in config payload, got %#v", config["webhook_hmac_secret"])
	}
	sanitized := data["sanitized_config"].(map[string]interface{})
	if sanitized["webhook_hmac_secret"] != redactedConfigValue {
		t.Fatalf("expected sanitized secret, got %#v", sanitized["webhook_hmac_secret"])
	}
	if config["source_geoip_data_file"] != "/tmp/geoip.json" {
		t.Fatalf("expected imported geoip data path, got %#v", config["source_geoip_data_file"])
	}
	if config["router_retry_max"].(float64) != 4 ||
		!config["router_circuit_breaker_enabled"].(bool) ||
		config["router_circuit_breaker_failure_threshold"].(float64) != 5 ||
		config["router_circuit_breaker_open_seconds"].(float64) != 45 {
		t.Fatalf("expected imported router circuit-breaker fields, got %#v", config)
	}
	routes := config["routes"].([]interface{})
	if len(routes) != 1 {
		t.Fatalf("expected 1 imported route, got %d", len(routes))
	}
	importedRoute := routes[0].(map[string]interface{})
	if importedRoute["region"] != "Hesse" || importedRoute["city"] != "Frankfurt" {
		t.Fatalf("expected imported route geo metadata, got %#v", importedRoute)
	}
	diff := data["diff"].(string)
	if !strings.Contains(diff, redactedConfigValue) {
		t.Fatalf("expected sanitized diff to redact secrets, got %s", diff)
	}
	if strings.Contains(diff, "imported-secret") {
		t.Fatalf("diff leaked imported secret: %s", diff)
	}
	if !data["changed"].(bool) {
		t.Fatal("expected import diff to report changes")
	}
}
