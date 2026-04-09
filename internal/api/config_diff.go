package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
)

const redactedConfigValue = "***REDACTED***"

var sensitiveConfigKeys = []string{"password", "secret", "token", "key", "pass_hash", "private_key", "pw"}

type configDiffRequest struct {
	FromVersion string                 `json:"from_version"`
	ToVersion   string                 `json:"to_version"`
	ToConfig    map[string]interface{} `json:"to_config"`
}

type configDiffLine struct {
	kind   byte
	text   string
	oldNum int
	newNum int
}

func isSensitiveConfigKey(key string) bool {
	key = strings.ToLower(key)
	for _, sensitive := range sensitiveConfigKeys {
		if strings.Contains(key, sensitive) {
			return true
		}
	}
	return false
}

func sanitizeConfig(cfg map[string]interface{}) {
	for key, value := range cfg {
		cfg[key] = sanitizeConfigValue(key, value)
	}
}

func sanitizeConfigValue(key string, value interface{}) interface{} {
	if isSensitiveConfigKey(key) {
		return redactedConfigValue
	}
	return sanitizeUntypedConfigValue(value)
}

func sanitizeUntypedConfigValue(value interface{}) interface{} {
	switch typed := value.(type) {
	case map[string]interface{}:
		sanitizeConfig(typed)
		return typed
	case []interface{}:
		for i, item := range typed {
			typed[i] = sanitizeUntypedConfigValue(item)
		}
		return typed
	default:
		return value
	}
}

func sanitizeConfigSnapshot(data []byte) interface{} {
	if parsed, err := parseConfigDocument(data, ""); err == nil {
		sanitizeConfig(parsed)
		return parsed
	}
	return map[string]string{"content": sanitizeConfigText(data)}
}

func sanitizeConfigText(data []byte) string {
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	for i, line := range lines {
		lines[i] = sanitizeConfigLine(line)
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}

func sanitizeConfigLine(line string) string {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") || strings.HasPrefix(trimmed, "[") {
		return line
	}

	sep := strings.IndexAny(line, ":=")
	if sep == -1 {
		return line
	}
	keyPart := line[:sep]
	if !isSensitiveConfigKey(keyPart) {
		return line
	}

	separator := line[sep : sep+1]
	suffix := ""
	if strings.HasSuffix(strings.TrimSpace(line), ",") {
		suffix = ","
	}
	if separator == ":" {
		return strings.TrimRight(keyPart, " \t") + ": " + `"` + redactedConfigValue + `"` + suffix
	}
	return strings.TrimRight(keyPart, " \t") + " = " + redactedConfigValue + suffix
}

func preserveRedactedConfigValues(current, incoming interface{}) interface{} {
	switch typed := incoming.(type) {
	case string:
		if typed == redactedConfigValue && current != nil {
			return current
		}
		return typed
	case map[string]interface{}:
		currentMap, _ := current.(map[string]interface{})
		merged := make(map[string]interface{}, len(typed))
		for key, value := range typed {
			merged[key] = preserveRedactedConfigValues(currentMap[key], value)
		}
		return merged
	case []interface{}:
		currentSlice, _ := current.([]interface{})
		merged := make([]interface{}, len(typed))
		for i, value := range typed {
			var currentValue interface{}
			if i < len(currentSlice) {
				currentValue = currentSlice[i]
			}
			merged[i] = preserveRedactedConfigValues(currentValue, value)
		}
		return merged
	default:
		return incoming
	}
}

func (a *API) handleDiffConfig(w http.ResponseWriter, r *http.Request) {
	var req configDiffRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.ToVersion != "" && len(req.ToConfig) > 0 {
		writeError(w, http.StatusBadRequest, "to_version and to_config are mutually exclusive")
		return
	}

	fromLabel, fromContent, err := a.loadConfigDiffSource(req.FromVersion)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	toLabel := req.ToVersion
	if toLabel == "" && len(req.ToConfig) == 0 {
		toLabel = "current"
	}

	var toContent []byte
	if len(req.ToConfig) > 0 {
		toLabel = "pending"
		toContent, err = sanitizedNormalizedConfigValue(req.ToConfig)
	} else {
		toLabel, toContent, err = a.loadConfigDiffSource(toLabel)
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	diff := buildUnifiedConfigDiff(fromLabel, toLabel, fromContent, toContent)
	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"from_version": fromLabel,
			"to_version":   toLabel,
			"changed":      diff != noConfigDiffMessage,
			"diff":         diff,
		},
	})
}

func (a *API) loadConfigDiffSource(version string) (string, []byte, error) {
	if version == "" || version == "current" {
		data, err := a.loadCurrentConfigSnapshot()
		if err != nil {
			return "", nil, fmt.Errorf("failed to load current config: %w", err)
		}
		normalized, err := sanitizedNormalizedConfigBytes(data)
		if err != nil {
			return "", nil, fmt.Errorf("failed to normalize current config: %w", err)
		}
		return "current", normalized, nil
	}

	data, err := a.loadConfigVersionSnapshot(version)
	if err != nil {
		if errors.Is(err, errConfigVersionNotFound) {
			return "", nil, fmt.Errorf("config version not found")
		}
		if strings.Contains(err.Error(), "invalid version parameter") {
			return "", nil, fmt.Errorf("invalid version parameter")
		}
		return "", nil, fmt.Errorf("failed to read config version: %w", err)
	}
	normalized, err := sanitizedNormalizedConfigBytes(data)
	if err != nil {
		return "", nil, fmt.Errorf("failed to normalize config version: %w", err)
	}
	return version, normalized, nil
}

func (a *API) loadCurrentConfigSnapshot() ([]byte, error) {
	if storeBackendIsPostgres(a.config.ConfigStoreBackend) {
		if current, err := a.loadPersistedConfigEntry(); err != nil {
			return nil, err
		} else if current != nil && len(current.Snapshot) > 0 {
			return append([]byte(nil), current.Snapshot...), nil
		}
		if data, err := a.loadConfigFileSnapshot(); err == nil {
			return data, nil
		}
		if a.cluster != nil {
			if desired, err := a.cluster.GetDesiredConfigPayload(); err == nil && desired != nil &&
				len(desired.Snapshot) > 0 {
				return append([]byte(nil), desired.Snapshot...), nil
			}
		}
		return a.loadLocalConfigSnapshot()
	}
	if data, err := a.loadConfigFileSnapshot(); err == nil {
		return data, nil
	}
	if a.cluster != nil {
		if desired, err := a.cluster.GetDesiredConfigPayload(); err == nil && desired != nil &&
			len(desired.Snapshot) > 0 {
			return append([]byte(nil), desired.Snapshot...), nil
		}
	}
	if current, err := a.loadPersistedConfigEntry(); err == nil {
		if current != nil && len(current.Snapshot) > 0 {
			return append([]byte(nil), current.Snapshot...), nil
		}
	}
	return a.loadLocalConfigSnapshot()
}

func (a *API) loadConfigFileSnapshot() ([]byte, error) {
	configPath := a.config.ConfigFile
	if configPath == "" {
		configPath = "config.ini"
	}
	return os.ReadFile(configPath)
}

func (a *API) loadLocalConfigSnapshot() ([]byte, error) {
	data, err := a.loadConfigFileSnapshot()
	if err == nil {
		return data, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	if a == nil || a.dp == nil {
		configPath := "config.ini"
		if a != nil && a.config != nil && a.config.ConfigFile != "" {
			configPath = a.config.ConfigFile
		}
		return nil, fmt.Errorf("config file %s not found and data plane is unavailable", configPath)
	}
	cfg, err := a.dp.GetConfig()
	if err != nil {
		return nil, err
	}
	return json.Marshal(cfg)
}

func (a *API) loadCurrentConfigDocument() interface{} {
	data, err := a.loadCurrentConfigSnapshot()
	if err != nil {
		return nil
	}
	current, err := parseConfigDocument(data, "")
	if err != nil {
		return nil
	}
	return current
}

func sanitizedNormalizedConfigValue(value interface{}) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return sanitizedNormalizedConfigBytes(raw)
}

func sanitizedNormalizedConfigBytes(raw []byte) ([]byte, error) {
	if parsed, err := parseConfigDocument(raw, ""); err == nil {
		sanitizeConfig(parsed)
		return json.MarshalIndent(parsed, "", "  ")
	}
	return []byte(sanitizeConfigText(raw)), nil
}

const noConfigDiffMessage = "No differences.\n"

func buildUnifiedConfigDiff(fromLabel, toLabel string, fromContent, toContent []byte) string {
	fromLines := splitConfigDiffLines(fromContent)
	toLines := splitConfigDiffLines(toContent)
	diffLines := computeConfigDiffLines(fromLines, toLines)
	if !hasConfigDiffChanges(diffLines) {
		return noConfigDiffMessage
	}

	var b strings.Builder
	b.WriteString("--- ")
	b.WriteString(fromLabel)
	b.WriteByte('\n')
	b.WriteString("+++ ")
	b.WriteString(toLabel)
	b.WriteByte('\n')

	for _, hunk := range buildConfigDiffHunks(diffLines, 3) {
		oldStart, newStart, oldCount, newCount := configDiffRange(diffLines[hunk[0] : hunk[1]+1])
		fmt.Fprintf(&b, "@@ -%d,%d +%d,%d @@\n", oldStart, oldCount, newStart, newCount)
		for _, line := range diffLines[hunk[0] : hunk[1]+1] {
			b.WriteByte(line.kind)
			b.WriteString(line.text)
			b.WriteByte('\n')
		}
	}

	return b.String()
}

func splitConfigDiffLines(content []byte) []string {
	normalized := strings.TrimSuffix(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n")
	if normalized == "" {
		return nil
	}
	return strings.Split(normalized, "\n")
}

func computeConfigDiffLines(fromLines, toLines []string) []configDiffLine {
	lcs := make([][]int, len(fromLines)+1)
	for i := range lcs {
		lcs[i] = make([]int, len(toLines)+1)
	}
	for i := len(fromLines) - 1; i >= 0; i-- {
		for j := len(toLines) - 1; j >= 0; j-- {
			if fromLines[i] == toLines[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
				continue
			}
			if lcs[i+1][j] >= lcs[i][j+1] {
				lcs[i][j] = lcs[i+1][j]
			} else {
				lcs[i][j] = lcs[i][j+1]
			}
		}
	}

	diff := make([]configDiffLine, 0, len(fromLines)+len(toLines))
	i, j := 0, 0
	oldNum, newNum := 1, 1
	for i < len(fromLines) && j < len(toLines) {
		if fromLines[i] == toLines[j] {
			diff = append(diff, configDiffLine{kind: ' ', text: fromLines[i], oldNum: oldNum, newNum: newNum})
			i++
			j++
			oldNum++
			newNum++
			continue
		}
		if lcs[i+1][j] >= lcs[i][j+1] {
			diff = append(diff, configDiffLine{kind: '-', text: fromLines[i], oldNum: oldNum, newNum: newNum})
			i++
			oldNum++
			continue
		}
		diff = append(diff, configDiffLine{kind: '+', text: toLines[j], oldNum: oldNum, newNum: newNum})
		j++
		newNum++
	}
	for ; i < len(fromLines); i, oldNum = i+1, oldNum+1 {
		diff = append(diff, configDiffLine{kind: '-', text: fromLines[i], oldNum: oldNum, newNum: newNum})
	}
	for ; j < len(toLines); j, newNum = j+1, newNum+1 {
		diff = append(diff, configDiffLine{kind: '+', text: toLines[j], oldNum: oldNum, newNum: newNum})
	}
	return diff
}

func hasConfigDiffChanges(lines []configDiffLine) bool {
	for _, line := range lines {
		if line.kind != ' ' {
			return true
		}
	}
	return false
}

func buildConfigDiffHunks(lines []configDiffLine, context int) [][2]int {
	changeIndexes := make([]int, 0)
	for i, line := range lines {
		if line.kind != ' ' {
			changeIndexes = append(changeIndexes, i)
		}
	}
	if len(changeIndexes) == 0 {
		return nil
	}

	hunks := make([][2]int, 0)
	start := maxInt(changeIndexes[0]-context, 0)
	end := minInt(changeIndexes[0]+context, len(lines)-1)
	for _, idx := range changeIndexes[1:] {
		nextStart := maxInt(idx-context, 0)
		nextEnd := minInt(idx+context, len(lines)-1)
		if nextStart <= end+1 {
			end = maxInt(end, nextEnd)
			continue
		}
		hunks = append(hunks, [2]int{start, end})
		start = nextStart
		end = nextEnd
	}
	hunks = append(hunks, [2]int{start, end})
	return hunks
}

func configDiffRange(lines []configDiffLine) (oldStart, newStart, oldCount, newCount int) {
	if len(lines) == 0 {
		return 1, 1, 0, 0
	}
	oldStart = maxInt(lines[0].oldNum, 1)
	newStart = maxInt(lines[0].newNum, 1)
	for _, line := range lines {
		if line.kind != '+' {
			oldCount++
		}
		if line.kind != '-' {
			newCount++
		}
	}
	return oldStart, newStart, oldCount, newCount
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
