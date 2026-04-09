package api

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"
)

const (
	configFormatJSON = "json"
	configFormatYAML = "yaml"
	configFormatINI  = "ini"
)

type configFieldSpec struct {
	DocKey  string
	Section string
	Key     string
	Kind    string
}

var iniConfigFieldSpecs = []configFieldSpec{
	{DocKey: "bind_addr", Section: "server", Key: "bind_addr", Kind: "string"},
	{DocKey: "port", Section: "server", Key: "port", Kind: "int"},
	{DocKey: "host_key", Section: "server", Key: "host_key", Kind: "string"},
	{DocKey: "banner", Section: "server", Key: "banner", Kind: "string"},
	{DocKey: "motd", Section: "server", Key: "motd", Kind: "string"},
	{DocKey: "show_progress", Section: "server", Key: "show_progress", Kind: "bool"},

	{DocKey: "log_level", Section: "logging", Key: "level", Kind: "string"},
	{DocKey: "audit_dir", Section: "logging", Key: "audit_dir", Kind: "string"},
	{DocKey: "audit_max_file_size", Section: "logging", Key: "audit_max_file_size", Kind: "int"},
	{DocKey: "audit_max_archived_files", Section: "logging", Key: "audit_max_archived_files", Kind: "int"},
	{DocKey: "audit_retention_days", Section: "logging", Key: "audit_retention_days", Kind: "int"},
	{DocKey: "audit_encryption_key", Section: "logging", Key: "audit_encryption_key", Kind: "string"},
	{DocKey: "audit_encryption_key_file", Section: "logging", Key: "audit_encryption_key_file", Kind: "string"},
	{DocKey: "log_format", Section: "logging", Key: "format", Kind: "string"},
	{DocKey: "log_transfers", Section: "logging", Key: "log_transfers", Kind: "bool"},
	{DocKey: "log_port_forwards", Section: "logging", Key: "log_port_forwards", Kind: "bool"},

	{DocKey: "max_sessions", Section: "limits", Key: "max_sessions", Kind: "int"},
	{DocKey: "session_timeout", Section: "limits", Key: "session_timeout", Kind: "int"},
	{DocKey: "auth_timeout", Section: "limits", Key: "auth_timeout", Kind: "int"},
	{DocKey: "per_user_max_sessions", Section: "limits", Key: "per_user_max_sessions", Kind: "int"},

	{DocKey: "ip_acl_mode", Section: "ip_acl", Key: "mode", Kind: "string"},
	{DocKey: "ip_acl_rules", Section: "ip_acl", Key: "rules", Kind: "string"},
	{DocKey: "log_rejections", Section: "ip_acl", Key: "log_rejections", Kind: "bool"},

	{DocKey: "auth_backend", Section: "auth", Key: "backend", Kind: "string"},
	{DocKey: "ldap_uri", Section: "auth", Key: "ldap_uri", Kind: "string"},
	{DocKey: "ldap_base_dn", Section: "auth", Key: "ldap_base_dn", Kind: "string"},
	{DocKey: "ldap_bind_dn", Section: "auth", Key: "ldap_bind_dn", Kind: "string"},
	{DocKey: "ldap_bind_pw", Section: "auth", Key: "ldap_bind_pw", Kind: "string"},
	{DocKey: "ldap_user_filter", Section: "auth", Key: "ldap_user_filter", Kind: "string"},
	{DocKey: "ldap_timeout", Section: "auth", Key: "ldap_timeout", Kind: "int"},
	{DocKey: "ldap_group_attr", Section: "auth", Key: "ldap_group_attr", Kind: "string"},
	{DocKey: "ldap_email_attr", Section: "auth", Key: "ldap_email_attr", Kind: "string"},
	{DocKey: "ldap_department_attr", Section: "auth", Key: "ldap_department_attr", Kind: "string"},
	{DocKey: "ldap_manager_attr", Section: "auth", Key: "ldap_manager_attr", Kind: "string"},

	{DocKey: "lockout_enabled", Section: "security", Key: "lockout_enabled", Kind: "bool"},
	{DocKey: "lockout_threshold", Section: "security", Key: "lockout_threshold", Kind: "int"},
	{DocKey: "lockout_duration", Section: "security", Key: "lockout_duration", Kind: "int"},
	{DocKey: "ip_ban_enabled", Section: "security", Key: "ip_ban_enabled", Kind: "bool"},
	{DocKey: "ip_ban_threshold", Section: "security", Key: "ip_ban_threshold", Kind: "int"},
	{DocKey: "ip_ban_duration", Section: "security", Key: "ip_ban_duration", Kind: "int"},
	{DocKey: "password_min_length", Section: "security", Key: "password_min_length", Kind: "int"},
	{DocKey: "password_require_uppercase", Section: "security", Key: "password_require_uppercase", Kind: "bool"},
	{DocKey: "password_require_lowercase", Section: "security", Key: "password_require_lowercase", Kind: "bool"},
	{DocKey: "password_require_digit", Section: "security", Key: "password_require_digit", Kind: "bool"},
	{DocKey: "password_require_special", Section: "security", Key: "password_require_special", Kind: "bool"},
	{DocKey: "password_max_age_days", Section: "security", Key: "password_max_age_days", Kind: "int"},
	{DocKey: "trusted_user_ca_key", Section: "security", Key: "trusted_user_ca_key", Kind: "string"},
	{DocKey: "trusted_user_ca_keys_file", Section: "security", Key: "trusted_user_ca_keys_file", Kind: "string"},
	{DocKey: "revoked_user_cert_serial", Section: "security", Key: "revoked_user_cert_serial", Kind: "string"},
	{DocKey: "revoked_user_cert_serials_file", Section: "security", Key: "revoked_user_cert_serials_file", Kind: "string"},
	{DocKey: "master_key", Section: "security", Key: "master_key", Kind: "string"},
	{DocKey: "master_key_file", Section: "security", Key: "master_key_file", Kind: "string"},

	{DocKey: "mfa_enabled", Section: "mfa", Key: "enabled", Kind: "bool"},
	{DocKey: "mfa_issuer", Section: "mfa", Key: "issuer", Kind: "string"},
	{DocKey: "mfa_time_step", Section: "mfa", Key: "time_step", Kind: "int"},
	{DocKey: "mfa_digits", Section: "mfa", Key: "digits", Kind: "int"},
	{DocKey: "mfa_window", Section: "mfa", Key: "window", Kind: "int"},

	{DocKey: "router_retry_max", Section: "router", Key: "retry_max", Kind: "int"},
	{DocKey: "router_retry_initial_delay_ms", Section: "router", Key: "retry_initial_delay_ms", Kind: "int"},
	{DocKey: "router_retry_max_delay_ms", Section: "router", Key: "retry_max_delay_ms", Kind: "int"},
	{DocKey: "router_retry_backoff_factor", Section: "router", Key: "retry_backoff_factor", Kind: "float"},
	{DocKey: "router_pool_enabled", Section: "router", Key: "pool_enabled", Kind: "bool"},
	{DocKey: "router_pool_max_idle", Section: "router", Key: "pool_max_idle", Kind: "int"},
	{DocKey: "router_pool_max_idle_time", Section: "router", Key: "pool_max_idle_time", Kind: "int"},
	{DocKey: "router_circuit_breaker_enabled", Section: "router", Key: "circuit_breaker_enabled", Kind: "bool"},
	{DocKey: "router_circuit_breaker_failure_threshold", Section: "router", Key: "circuit_breaker_failure_threshold", Kind: "int"},
	{DocKey: "router_circuit_breaker_open_seconds", Section: "router", Key: "circuit_breaker_open_seconds", Kind: "int"},

	{DocKey: "admin_enabled", Section: "admin", Key: "enabled", Kind: "bool"},
	{DocKey: "admin_auth_token", Section: "admin", Key: "auth_token", Kind: "string"},
	{DocKey: "admin_token_expiry", Section: "admin", Key: "token_expiry", Kind: "int"},
	{DocKey: "admin_tls_enabled", Section: "admin", Key: "tls_enabled", Kind: "bool"},
	{DocKey: "admin_tls_cert", Section: "admin", Key: "tls_cert", Kind: "string"},
	{DocKey: "admin_tls_key", Section: "admin", Key: "tls_key", Kind: "string"},

	{DocKey: "webhook_enabled", Section: "webhook", Key: "enabled", Kind: "bool"},
	{DocKey: "webhook_url", Section: "webhook", Key: "url", Kind: "string"},
	{DocKey: "webhook_auth_header", Section: "webhook", Key: "auth_header", Kind: "string"},
	{DocKey: "webhook_hmac_secret", Section: "webhook", Key: "hmac_secret", Kind: "string"},
	{DocKey: "webhook_dead_letter_path", Section: "webhook", Key: "dead_letter_path", Kind: "string"},
	{DocKey: "webhook_events", Section: "webhook", Key: "events", Kind: "string"},
	{DocKey: "webhook_retry_max", Section: "webhook", Key: "retry_max", Kind: "int"},
	{DocKey: "webhook_retry_delay_ms", Section: "webhook", Key: "retry_delay_ms", Kind: "int"},
	{DocKey: "webhook_timeout_ms", Section: "webhook", Key: "timeout_ms", Kind: "int"},
	{DocKey: "webhook_queue_size", Section: "webhook", Key: "queue_size", Kind: "int"},

	{DocKey: "source_office_cidrs", Section: "network_sources", Key: "office_cidrs", Kind: "string"},
	{DocKey: "source_vpn_cidrs", Section: "network_sources", Key: "vpn_cidrs", Kind: "string"},
	{DocKey: "source_geoip_data_file", Section: "network_sources", Key: "geoip_data_file", Kind: "string"},

	{DocKey: "session_store_type", Section: "session_store", Key: "type", Kind: "string"},
	{DocKey: "session_store_path", Section: "session_store", Key: "path", Kind: "string"},
	{DocKey: "session_store_sync_interval", Section: "session_store", Key: "sync_interval", Kind: "int"},
	{DocKey: "session_store_instance_id", Section: "session_store", Key: "instance_id", Kind: "string"},
}

var iniFieldBySectionAndKey = map[string]configFieldSpec{}
var iniFieldByDocKey = map[string]configFieldSpec{}

func init() {
	for _, spec := range iniConfigFieldSpecs {
		iniFieldBySectionAndKey[spec.Section+"."+spec.Key] = spec
		iniFieldByDocKey[spec.DocKey] = spec
	}
}

func normalizeConfigFormat(format string) string {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "auto":
		return ""
	case configFormatJSON:
		return configFormatJSON
	case "yml", configFormatYAML:
		return configFormatYAML
	case configFormatINI:
		return configFormatINI
	default:
		return ""
	}
}

func detectConfigFormat(raw []byte) string {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return configFormatJSON
	}
	if trimmed[0] == '{' || trimmed[0] == '[' {
		var doc interface{}
		if json.Unmarshal(trimmed, &doc) == nil {
			return configFormatJSON
		}
	}
	if _, err := parseINIConfigDocument(raw); err == nil {
		return configFormatINI
	}
	var doc interface{}
	if yaml.Unmarshal(raw, &doc) == nil {
		return configFormatYAML
	}
	return ""
}

func parseConfigDocument(raw []byte, format string) (map[string]interface{}, error) {
	format = normalizeConfigFormat(format)
	if format == "" {
		format = detectConfigFormat(raw)
	}
	switch format {
	case configFormatJSON:
		var doc map[string]interface{}
		if err := json.Unmarshal(raw, &doc); err != nil {
			return nil, err
		}
		return doc, nil
	case configFormatYAML:
		var doc interface{}
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			return nil, err
		}
		normalized, ok := normalizeYAMLValue(doc).(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("yaml config must be an object")
		}
		return normalized, nil
	case configFormatINI:
		return parseINIConfigDocument(raw)
	default:
		return nil, fmt.Errorf("unsupported config format")
	}
}

func renderConfigDocument(doc map[string]interface{}, format string) ([]byte, error) {
	switch normalizeConfigFormat(format) {
	case configFormatJSON:
		return json.MarshalIndent(doc, "", "  ")
	case configFormatYAML:
		return yaml.Marshal(doc)
	case configFormatINI:
		return renderINIConfigDocument(doc), nil
	default:
		return nil, fmt.Errorf("unsupported config format")
	}
}

func normalizeYAMLValue(value interface{}) interface{} {
	switch typed := value.(type) {
	case map[string]interface{}:
		normalized := make(map[string]interface{}, len(typed))
		for key, item := range typed {
			normalized[key] = normalizeYAMLValue(item)
		}
		return normalized
	case map[interface{}]interface{}:
		normalized := make(map[string]interface{}, len(typed))
		for key, item := range typed {
			normalized[fmt.Sprint(key)] = normalizeYAMLValue(item)
		}
		return normalized
	case []interface{}:
		normalized := make([]interface{}, len(typed))
		for i, item := range typed {
			normalized[i] = normalizeYAMLValue(item)
		}
		return normalized
	default:
		return typed
	}
}

func parseINIConfigDocument(raw []byte) (map[string]interface{}, error) {
	doc := make(map[string]interface{})
	var (
		currentSection string
		sectionParam   string
		seenSection    bool
	)

	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if section, ok := parseINISectionHeader(line); ok {
			currentSection, sectionParam = classifyINISection(section)
			seenSection = true
			continue
		}

		key, value, ok := parseINIKeyValue(line)
		if !ok || currentSection == "" {
			continue
		}

		switch currentSection {
		case "route":
			routes := ensureConfigObjectSlice(doc, "routes")
			var route map[string]interface{}
			routes, route = ensureNamedConfigObject(routes, "pattern", sectionParam)
			switch key {
			case "upstream", "upstream_host", "host":
				route["upstream"] = value
			case "port", "upstream_port":
				route["port"] = parseTypedINIValue(value, "int")
			case "user", "upstream_user":
				route["user"] = value
			case "privkey", "private_key":
				route["privkey"] = value
			case "country_code", "country", "region", "city":
				route[key] = value
			case "latitude", "longitude":
				route[key] = parseTypedINIValue(value, "float")
			case "enabled":
				route["enabled"] = parseTypedINIValue(value, "bool")
			}
			doc["routes"] = routes
		case "policy":
			policies := ensureConfigObjectSlice(doc, "policies")
			var policy map[string]interface{}
			policies, policy = ensureNamedConfigObject(policies, "pattern", sectionParam)
			switch key {
			case "allow", "allowed":
				policy["allow"] = parseCommaSeparatedList(value)
			case "deny", "denied":
				policy["deny"] = parseCommaSeparatedList(value)
			case "allowed_source_types", "source_types":
				policy["allowed_source_types"] = parseCommaSeparatedList(value)
			case "denied_source_types":
				policy["denied_source_types"] = parseCommaSeparatedList(value)
			case "login_window", "allowed_login_window", "time_window":
				policy["login_window"] = value
			case "login_days", "allowed_login_days":
				policy["login_days"] = value
			case "login_timezone", "timezone":
				policy["login_timezone"] = value
			}
			doc["policies"] = policies
		case "user":
			users := ensureConfigObjectSlice(doc, "users")
			var user map[string]interface{}
			users, user = ensureNamedConfigObject(users, "username", sectionParam)
			switch key {
			case "pubkey":
				appendStringField(user, "pubkey", value)
			case "enabled":
				user["enabled"] = parseTypedINIValue(value, "bool")
			case "password_changed_at":
				user["password_changed_at"] = parseTypedINIValue(value, "int")
			case "password_change_required":
				user["password_change_required"] = parseTypedINIValue(value, "bool")
			default:
				user[key] = value
			}
			doc["users"] = users
		default:
			if spec, ok := iniFieldBySectionAndKey[currentSection+"."+key]; ok {
				doc[spec.DocKey] = parseTypedINIValue(value, spec.Kind)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan ini config: %w", err)
	}
	if !seenSection && len(doc) == 0 {
		return nil, fmt.Errorf("ini config contained no sections")
	}
	return doc, nil
}

func renderINIConfigDocument(doc map[string]interface{}) []byte {
	var buf strings.Builder
	for _, section := range []string{
		"server",
		"logging",
		"limits",
		"ip_acl",
		"auth",
		"security",
		"mfa",
		"router",
		"admin",
		"webhook",
		"network_sources",
		"session_store",
	} {
		var lines []string
		for _, spec := range iniConfigFieldSpecs {
			if spec.Section != section {
				continue
			}
			value, ok := doc[spec.DocKey]
			if !ok {
				continue
			}
			lines = append(lines, spec.Key+" = "+formatINIValue(value, spec.Kind))
		}
		if len(lines) == 0 {
			continue
		}
		if buf.Len() > 0 {
			buf.WriteByte('\n')
		}
		buf.WriteString("[" + section + "]\n")
		for _, line := range lines {
			buf.WriteString(line)
			buf.WriteByte('\n')
		}
	}

	for _, user := range sortedConfigObjects(doc["users"], "username") {
		username := stringFromValue(user["username"])
		if username == "" {
			continue
		}
		if buf.Len() > 0 {
			buf.WriteByte('\n')
		}
		buf.WriteString("[user:" + username + "]\n")
		for _, key := range []string{"password_hash", "pubkey_file", "enabled", "password_changed_at", "password_change_required", "totp_secret", "mfa_enabled"} {
			value, ok := user[key]
			if !ok {
				continue
			}
			kind := "string"
			if key == "enabled" || key == "password_change_required" || key == "mfa_enabled" {
				kind = "bool"
			} else if key == "password_changed_at" {
				kind = "int"
			}
			buf.WriteString(key + " = " + formatINIValue(value, kind) + "\n")
		}
		switch pubkeys := user["pubkey"].(type) {
		case string:
			if pubkeys != "" {
				buf.WriteString("pubkey = " + formatINIValue(pubkeys, "string") + "\n")
			}
		case []interface{}:
			for _, item := range pubkeys {
				buf.WriteString("pubkey = " + formatINIValue(item, "string") + "\n")
			}
		}
	}

	for _, route := range sortedConfigObjects(doc["routes"], "pattern") {
		pattern := stringFromValue(route["pattern"])
		if pattern == "" {
			continue
		}
		if buf.Len() > 0 {
			buf.WriteByte('\n')
		}
		buf.WriteString("[route:" + pattern + "]\n")
		for _, key := range []string{"upstream", "port", "user", "privkey", "country_code", "country", "region", "city", "latitude", "longitude", "enabled"} {
			value, ok := route[key]
			if !ok {
				continue
			}
			kind := "string"
			if key == "port" {
				kind = "int"
			} else if key == "latitude" || key == "longitude" {
				kind = "float"
			} else if key == "enabled" {
				kind = "bool"
			}
			buf.WriteString(key + " = " + formatINIValue(value, kind) + "\n")
		}
	}

	for _, policy := range sortedConfigObjects(doc["policies"], "pattern") {
		pattern := stringFromValue(policy["pattern"])
		if pattern == "" {
			continue
		}
		if buf.Len() > 0 {
			buf.WriteByte('\n')
		}
		buf.WriteString("[policy:" + pattern + "]\n")
		if value, ok := policy["allow"]; ok {
			buf.WriteString("allow = " + formatINIValue(value, "csv") + "\n")
		}
		if value, ok := policy["deny"]; ok {
			buf.WriteString("deny = " + formatINIValue(value, "csv") + "\n")
		}
		if value, ok := policy["allowed_source_types"]; ok {
			buf.WriteString("allowed_source_types = " + formatINIValue(value, "csv") + "\n")
		}
		if value, ok := policy["denied_source_types"]; ok {
			buf.WriteString("denied_source_types = " + formatINIValue(value, "csv") + "\n")
		}
		if value, ok := policy["login_window"]; ok {
			buf.WriteString("login_window = " + formatINIValue(value, "string") + "\n")
		}
		if value, ok := policy["login_days"]; ok {
			buf.WriteString("login_days = " + formatINIValue(value, "string") + "\n")
		}
		if value, ok := policy["login_timezone"]; ok {
			buf.WriteString("login_timezone = " + formatINIValue(value, "string") + "\n")
		}
	}

	return []byte(buf.String())
}

func parseINISectionHeader(line string) (string, bool) {
	if !strings.HasPrefix(line, "[") || !strings.HasSuffix(line, "]") {
		return "", false
	}
	section := strings.TrimSpace(line[1 : len(line)-1])
	if section == "" {
		return "", false
	}
	return section, true
}

func classifyINISection(section string) (string, string) {
	lower := strings.ToLower(section)
	switch {
	case strings.HasPrefix(lower, "route:"):
		return "route", strings.TrimSpace(section[len("route:"):])
	case strings.HasPrefix(lower, "policy:"):
		return "policy", strings.TrimSpace(section[len("policy:"):])
	case strings.HasPrefix(lower, "user:"):
		return "user", strings.TrimSpace(section[len("user:"):])
	default:
		return lower, ""
	}
}

func parseINIKeyValue(line string) (string, string, bool) {
	key, value, ok := strings.Cut(line, "=")
	if !ok {
		return "", "", false
	}
	key = strings.ToLower(strings.TrimSpace(key))
	value = strings.TrimSpace(stripINIInlineComment(value))
	if key == "" {
		return "", "", false
	}
	if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'')) {
		if unquoted, err := strconv.Unquote(value); err == nil {
			value = unquoted
		} else {
			value = value[1 : len(value)-1]
		}
	}
	return key, value, true
}

func stripINIInlineComment(value string) string {
	inSingleQuote := false
	inDoubleQuote := false
	for i, r := range value {
		switch r {
		case '\'':
			if !inDoubleQuote {
				inSingleQuote = !inSingleQuote
			}
		case '"':
			if !inSingleQuote {
				inDoubleQuote = !inDoubleQuote
			}
		case '#', ';':
			if inSingleQuote || inDoubleQuote {
				continue
			}
			if i == 0 || unicode.IsSpace(rune(value[i-1])) {
				return strings.TrimRightFunc(value[:i], unicode.IsSpace)
			}
		}
	}
	return value
}

func parseTypedINIValue(value, kind string) interface{} {
	switch kind {
	case "bool":
		return value == "1" || strings.EqualFold(value, "true") || strings.EqualFold(value, "yes") || strings.EqualFold(value, "on")
	case "int":
		if n, err := strconv.Atoi(value); err == nil {
			return n
		}
		if n, err := strconv.ParseFloat(value, 64); err == nil {
			return int(n)
		}
		return value
	case "float":
		if n, err := strconv.ParseFloat(value, 64); err == nil {
			return n
		}
		return value
	default:
		return value
	}
}

func ensureConfigObjectSlice(doc map[string]interface{}, key string) []interface{} {
	if existing, ok := doc[key].([]interface{}); ok {
		return existing
	}
	slice := []interface{}{}
	doc[key] = slice
	return slice
}

func ensureNamedConfigObject(items []interface{}, key, name string) ([]interface{}, map[string]interface{}) {
	for _, item := range items {
		if obj, ok := item.(map[string]interface{}); ok && stringFromValue(obj[key]) == name {
			return items, obj
		}
	}
	obj := map[string]interface{}{key: name}
	items = append(items, obj)
	return items, obj
}

func appendStringField(obj map[string]interface{}, key, value string) {
	switch current := obj[key].(type) {
	case nil:
		obj[key] = value
	case string:
		obj[key] = []interface{}{current, value}
	case []interface{}:
		obj[key] = append(current, value)
	}
}

func parseCommaSeparatedList(value string) []string {
	parts := strings.Split(value, ",")
	items := make([]string, 0, len(parts))
	for _, part := range parts {
		item := strings.TrimSpace(part)
		if item != "" {
			items = append(items, item)
		}
	}
	return items
}

func sortedConfigObjects(value interface{}, idKey string) []map[string]interface{} {
	var objects []map[string]interface{}
	items, _ := value.([]interface{})
	for _, item := range items {
		if obj, ok := item.(map[string]interface{}); ok {
			objects = append(objects, obj)
		}
	}
	sort.Slice(objects, func(i, j int) bool {
		return stringFromValue(objects[i][idKey]) < stringFromValue(objects[j][idKey])
	})
	return objects
}

func formatINIValue(value interface{}, kind string) string {
	switch kind {
	case "bool":
		if boolFromValue(value) {
			return "true"
		}
		return "false"
	case "int":
		return strconv.Itoa(intFromValue(value))
	case "float":
		switch typed := value.(type) {
		case float32:
			return strconv.FormatFloat(float64(typed), 'f', -1, 64)
		case float64:
			return strconv.FormatFloat(typed, 'f', -1, 64)
		case string:
			return typed
		default:
			return strconv.Itoa(intFromValue(value))
		}
	case "csv":
		return strings.Join(stringSliceFromValue(value), ", ")
	default:
		text := stringFromValue(value)
		if text == "" {
			return `""`
		}
		if strings.Contains(text, "\n") || strings.HasPrefix(text, " ") || strings.HasSuffix(text, " ") {
			return strconv.Quote(text)
		}
		return text
	}
}

func stringSliceFromValue(value interface{}) []string {
	switch typed := value.(type) {
	case []string:
		return typed
	case []interface{}:
		items := make([]string, 0, len(typed))
		for _, item := range typed {
			text := strings.TrimSpace(stringFromValue(item))
			if text != "" {
				items = append(items, text)
			}
		}
		return items
	case string:
		return parseCommaSeparatedList(typed)
	default:
		return nil
	}
}
