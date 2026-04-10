package discovery

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// AnsibleImportConfig controls normalization of Ansible inventory sources.
type AnsibleImportConfig struct {
	DefaultPort int `json:"default_port"`
}

type ansibleHostRecord struct {
	Name string
	Vars map[string]string
}

// ImportAnsibleAssets normalizes Ansible JSON or INI inventory into discovery
// assets.
func ImportAnsibleAssets(format string, payload []byte, cfg AnsibleImportConfig) ([]Asset, error) {
	if cfg.DefaultPort <= 0 {
		cfg.DefaultPort = 22
	}
	switch DetectAnsibleFormat(format, payload) {
	case "json":
		return parseAnsibleJSONAssets(payload, cfg)
	case "ini":
		return parseAnsibleINIAssets(payload, cfg)
	default:
		return nil, fmt.Errorf("unsupported ansible format %q", format)
	}
}

// DetectAnsibleFormat resolves json/ini inventory format from explicit input or
// payload content.
func DetectAnsibleFormat(format string, payload []byte) string {
	format = strings.ToLower(strings.TrimSpace(format))
	if format == "json" || format == "ini" {
		return format
	}
	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) == 0 {
		return "ini"
	}
	switch trimmed[0] {
	case '{':
		return "json"
	case '[':
		for _, b := range trimmed[1:] {
			switch b {
			case ' ', '\t', '\r', '\n':
				continue
			case '{', '[', '"', ']':
				return "json"
			default:
				return "ini"
			}
		}
		return "json"
	default:
		return "ini"
	}
}

func parseAnsibleJSONAssets(payload []byte, cfg AnsibleImportConfig) ([]Asset, error) {
	var root map[string]interface{}
	if err := json.Unmarshal(payload, &root); err != nil {
		return nil, fmt.Errorf("parse ansible json inventory: %w", err)
	}

	hostRecords := make(map[string]*ansibleHostRecord)
	if meta, ok := root["_meta"].(map[string]interface{}); ok {
		if hostVars, ok := meta["hostvars"].(map[string]interface{}); ok {
			for host, raw := range hostVars {
				record := &ansibleHostRecord{Name: host, Vars: map[string]string{}}
				if typed, ok := raw.(map[string]interface{}); ok {
					record.Vars = flattenScalarVars(typed)
				}
				hostRecords[host] = record
			}
		}
	}

	groupHosts := make(map[string][]string)
	groupChildren := make(map[string][]string)
	for key, raw := range root {
		if key == "_meta" {
			continue
		}
		group, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		groupHosts[key] = interfaceSliceToStrings(group["hosts"])
		groupChildren[key] = interfaceSliceToStrings(group["children"])
	}
	for _, hosts := range groupHosts {
		for _, host := range hosts {
			if _, ok := hostRecords[host]; !ok {
				hostRecords[host] = &ansibleHostRecord{Name: host, Vars: map[string]string{}}
			}
		}
	}

	hostGroups := resolveGroupMembership(groupHosts, groupChildren)
	return buildAnsibleAssets(hostRecords, hostGroups, cfg.DefaultPort), nil
}

func parseAnsibleINIAssets(payload []byte, cfg AnsibleImportConfig) ([]Asset, error) {
	hostRecords := make(map[string]*ansibleHostRecord)
	groupHosts := make(map[string][]string)
	groupChildren := make(map[string][]string)

	currentSection := "ungrouped"
	scanner := bufio.NewScanner(bytes.NewReader(payload))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		if idx := strings.IndexAny(line, "#;"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if line == "" {
			continue
		}

		switch {
		case strings.HasSuffix(currentSection, ":vars"):
			continue
		case strings.HasSuffix(currentSection, ":children"):
			parent := strings.TrimSuffix(currentSection, ":children")
			groupChildren[parent] = append(groupChildren[parent], strings.Fields(line)[0])
		default:
			host, vars := parseAnsibleINIHostLine(line)
			if host == "" {
				continue
			}
			record, ok := hostRecords[host]
			if !ok {
				record = &ansibleHostRecord{Name: host, Vars: map[string]string{}}
				hostRecords[host] = record
			}
			for key, value := range vars {
				record.Vars[key] = value
			}
			groupHosts[currentSection] = append(groupHosts[currentSection], host)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("parse ansible ini inventory: %w", err)
	}

	hostGroups := resolveGroupMembership(groupHosts, groupChildren)
	return buildAnsibleAssets(hostRecords, hostGroups, cfg.DefaultPort), nil
}

func parseAnsibleINIHostLine(line string) (string, map[string]string) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return "", nil
	}
	vars := make(map[string]string)
	for _, field := range fields[1:] {
		key, value, ok := strings.Cut(field, "=")
		if ok {
			vars[key] = value
		}
	}
	return fields[0], vars
}

func buildAnsibleAssets(records map[string]*ansibleHostRecord, hostGroups map[string][]string, defaultPort int) []Asset {
	hosts := make([]string, 0, len(records))
	for host := range records {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)

	assets := make([]Asset, 0, len(hosts))
	for _, host := range hosts {
		record := records[host]
		groups := append([]string(nil), hostGroups[host]...)
		sort.Strings(groups)

		tags := make(map[string]string, len(record.Vars)+4)
		for key, value := range record.Vars {
			if value == "" || key == "ansible_host" || key == "ansible_port" || key == "inventory_hostname" {
				continue
			}
			tags[key] = value
		}
		if len(groups) > 0 {
			tags["ansible_groups"] = strings.Join(groups, ",")
		}
		tags["ansible_inventory_host"] = host

		name := firstNonEmpty(record.Vars["inventory_hostname"], host)
		address := firstNonEmpty(record.Vars["ansible_host"], host)
		port := firstPositiveInt(parseIntString(record.Vars["ansible_port"]), defaultPort)
		osName := firstNonEmpty(record.Vars["ansible_distribution"], record.Vars["ansible_os_family"])
		if asset, ok := newAnsibleAsset(host, name, address, port, osName, tags); ok {
			assets = append(assets, asset)
		}
	}
	return assets
}

func newAnsibleAsset(inventoryHost, name, host string, port int, osName string, tags map[string]string) (Asset, bool) {
	host = strings.TrimSpace(host)
	if host == "" {
		return Asset{}, false
	}
	if port <= 0 {
		port = 22
	}
	tags = cloneTags(tags)
	tags["source"] = "ansible"
	tags["ansible_inventory_host"] = inventoryHost
	asset := Asset{
		ID:     "ansible:" + inventoryHost,
		Host:   host,
		Port:   port,
		Name:   strings.TrimSpace(name),
		OS:     strings.TrimSpace(osName),
		Tags:   tags,
		Status: "discovered",
	}
	if asset.Name == "" {
		asset.Name = inventoryHost
	}
	return asset, true
}

func flattenScalarVars(vars map[string]interface{}) map[string]string {
	flat := make(map[string]string, len(vars))
	for key, value := range vars {
		if scalar := stringifyValue(value); scalar != "" {
			flat[key] = scalar
		}
	}
	return flat
}

func interfaceSliceToStrings(value interface{}) []string {
	items, ok := value.([]interface{})
	if !ok {
		return nil
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		if scalar := stringifyValue(item); scalar != "" {
			result = append(result, scalar)
		}
	}
	return result
}

func resolveGroupMembership(groupHosts map[string][]string, groupChildren map[string][]string) map[string][]string {
	hostGroups := make(map[string]map[string]bool)
	var visit func(root, current string, seen map[string]bool)
	visit = func(root, current string, seen map[string]bool) {
		if seen[current] {
			return
		}
		seen[current] = true
		for _, host := range groupHosts[current] {
			if hostGroups[host] == nil {
				hostGroups[host] = make(map[string]bool)
			}
			hostGroups[host][root] = true
		}
		for _, child := range groupChildren[current] {
			visit(root, child, seen)
		}
	}
	for group := range groupHosts {
		visit(group, group, map[string]bool{})
	}
	for group := range groupChildren {
		visit(group, group, map[string]bool{})
	}

	flattened := make(map[string][]string, len(hostGroups))
	for host, groups := range hostGroups {
		for group := range groups {
			flattened[host] = append(flattened[host], group)
		}
		sort.Strings(flattened[host])
	}
	return flattened
}

func parseIntString(value string) int {
	i, _ := strconv.Atoi(strings.TrimSpace(value))
	return i
}
