package discovery

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// CMDBImportConfig controls how custom CMDB payloads are normalized into
// discovery assets.
type CMDBImportConfig struct {
	ItemsPath   string            `json:"items_path"`
	IDField     string            `json:"id_field"`
	NameField   string            `json:"name_field"`
	HostField   string            `json:"host_field"`
	PortField   string            `json:"port_field"`
	OSField     string            `json:"os_field"`
	StatusField string            `json:"status_field"`
	TagFields   []string          `json:"tag_fields"`
	StaticTags  map[string]string `json:"static_tags"`
	DefaultPort int               `json:"default_port"`
}

// ImportCMDBAssets normalizes ServiceNow or custom HTTP API CMDB payloads into
// discovery assets.
func ImportCMDBAssets(provider string, payload []byte, cfg CMDBImportConfig) ([]Asset, error) {
	provider = normalizeCMDBProvider(provider)
	if cfg.DefaultPort <= 0 {
		cfg.DefaultPort = 22
	}

	switch provider {
	case "servicenow":
		return parseServiceNowAssets(payload, cfg)
	case "custom-api":
		return parseCustomCMDBAssets(payload, cfg)
	default:
		return nil, fmt.Errorf("unsupported cmdb provider %q", provider)
	}
}

func normalizeCMDBProvider(provider string) string {
	provider = strings.ToLower(strings.TrimSpace(provider))
	provider = strings.NewReplacer("_", "-", " ", "-").Replace(provider)
	switch provider {
	case "servicenow", "service-now":
		return "servicenow"
	case "custom", "custom-api", "http-api":
		return "custom-api"
	default:
		return provider
	}
}

func parseServiceNowAssets(payload []byte, cfg CMDBImportConfig) ([]Asset, error) {
	itemsPath := cfg.ItemsPath
	if itemsPath == "" {
		itemsPath = "result"
	}
	items, err := decodeObjectArray(payload, itemsPath)
	if err != nil {
		return nil, fmt.Errorf("parse servicenow inventory: %w", err)
	}

	var assets []Asset
	for _, item := range items {
		id := firstPathString(item, "sys_id", "sys_id.value", "sys_id.display_value")
		host := firstPathString(item, "ip_address", "ip_address.value", "fqdn", "host_name", "name")
		name := firstPathString(item, "name", "host_name", "fqdn", "display_name")
		port := firstPositiveInt(pathInt(item, "u_ssh_port"), pathInt(item, "ssh_port"), cfg.DefaultPort)
		osName := firstPathString(item, "os", "os_version", "u_os")
		status := firstPathString(item, "install_status", "operational_status", "status")
		tags := collectServiceNowTags(item)
		mergeTags(tags, cfg.StaticTags)
		if asset, ok := newCMDBAsset("servicenow", id, name, host, port, osName, tags, status); ok {
			assets = append(assets, asset)
		}
	}
	return assets, nil
}

func parseCustomCMDBAssets(payload []byte, cfg CMDBImportConfig) ([]Asset, error) {
	if strings.TrimSpace(cfg.HostField) == "" {
		return nil, fmt.Errorf("host_field is required for custom-api provider")
	}
	items, err := decodeObjectArray(payload, cfg.ItemsPath)
	if err != nil {
		return nil, fmt.Errorf("parse custom cmdb inventory: %w", err)
	}

	var assets []Asset
	for _, item := range items {
		id := pathString(item, cfg.IDField)
		host := pathString(item, cfg.HostField)
		name := firstNonEmpty(pathString(item, cfg.NameField), host)
		port := firstPositiveInt(pathInt(item, cfg.PortField), cfg.DefaultPort)
		osName := pathString(item, cfg.OSField)
		status := pathString(item, cfg.StatusField)
		tags := make(map[string]string, len(cfg.TagFields)+len(cfg.StaticTags)+2)
		for _, field := range cfg.TagFields {
			if value := pathString(item, field); value != "" {
				tags[field] = value
			}
		}
		mergeTags(tags, cfg.StaticTags)
		if asset, ok := newCMDBAsset("custom-api", id, name, host, port, osName, tags, status); ok {
			assets = append(assets, asset)
		}
	}
	return assets, nil
}

func newCMDBAsset(provider, assetID, name, host string, port int, osName string, tags map[string]string, sourceStatus string) (Asset, bool) {
	host = strings.TrimSpace(host)
	if host == "" {
		return Asset{}, false
	}
	assetID = strings.TrimSpace(assetID)
	if assetID == "" {
		assetID = host
	}
	if port <= 0 {
		port = 22
	}
	tags = cloneTags(tags)
	tags["source"] = "cmdb"
	tags["cmdb_provider"] = provider
	tags["cmdb_asset_id"] = assetID
	if sourceStatus != "" {
		tags["provider_status"] = strings.ToLower(strings.TrimSpace(sourceStatus))
	}
	asset := Asset{
		ID:     provider + ":" + assetID,
		Host:   host,
		Port:   port,
		Name:   strings.TrimSpace(name),
		OS:     strings.TrimSpace(osName),
		Tags:   tags,
		Status: "discovered",
	}
	if asset.Name == "" {
		asset.Name = host
	}
	return asset, true
}

func decodeObjectArray(payload []byte, path string) ([]map[string]interface{}, error) {
	var root interface{}
	if err := json.Unmarshal(payload, &root); err != nil {
		return nil, err
	}
	value := root
	var ok bool
	if strings.TrimSpace(path) != "" {
		value, ok = lookupPathValue(root, path)
		if !ok {
			return nil, fmt.Errorf("path %q not found", path)
		}
	}
	switch typed := value.(type) {
	case []interface{}:
		items := make([]map[string]interface{}, 0, len(typed))
		for _, raw := range typed {
			if item, ok := raw.(map[string]interface{}); ok {
				items = append(items, item)
			}
		}
		return items, nil
	case map[string]interface{}:
		return []map[string]interface{}{typed}, nil
	default:
		return nil, fmt.Errorf("path %q does not resolve to an object array", path)
	}
}

func collectServiceNowTags(item map[string]interface{}) map[string]string {
	tags := make(map[string]string)
	for _, field := range []string{"sys_class_name", "environment", "company", "location", "asset_tag"} {
		if value := pathString(item, field); value != "" {
			tags[field] = value
		}
	}
	for key := range item {
		if strings.HasPrefix(key, "u_") && key != "u_ssh_port" {
			if value := pathString(item, key); value != "" {
				tags[key] = value
			}
		}
	}
	return tags
}

func mergeTags(dst, src map[string]string) {
	for key, value := range src {
		dst[key] = value
	}
}

func firstPathString(item map[string]interface{}, paths ...string) string {
	for _, path := range paths {
		if value := pathString(item, path); value != "" {
			return value
		}
	}
	return ""
}

func pathString(item map[string]interface{}, path string) string {
	if path == "" {
		return ""
	}
	value, ok := lookupPathValue(item, path)
	if !ok {
		return ""
	}
	return stringifyValue(value)
}

func pathInt(item map[string]interface{}, path string) int {
	if path == "" {
		return 0
	}
	value, ok := lookupPathValue(item, path)
	if !ok {
		return 0
	}
	switch typed := value.(type) {
	case float64:
		return int(typed)
	case int:
		return typed
	case json.Number:
		i, _ := typed.Int64()
		return int(i)
	case string:
		i, _ := strconv.Atoi(strings.TrimSpace(typed))
		return i
	default:
		if s := stringifyValue(value); s != "" {
			i, _ := strconv.Atoi(s)
			return i
		}
		return 0
	}
}

func firstPositiveInt(values ...int) int {
	for _, value := range values {
		if value > 0 {
			return value
		}
	}
	return 0
}

func stringifyValue(value interface{}) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case json.Number:
		return typed.String()
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case bool:
		if typed {
			return "true"
		}
		return "false"
	case map[string]interface{}:
		if s := firstNonEmpty(stringifyValue(typed["display_value"]), stringifyValue(typed["value"])); s != "" {
			return s
		}
	case nil:
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(value))
}

func lookupPathValue(root interface{}, path string) (interface{}, bool) {
	current := root
	for _, part := range strings.Split(strings.TrimSpace(path), ".") {
		if part == "" {
			continue
		}
		switch typed := current.(type) {
		case map[string]interface{}:
			next, ok := typed[part]
			if !ok {
				return nil, false
			}
			current = next
		default:
			return nil, false
		}
	}
	return current, true
}
