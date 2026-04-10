package dlp

import (
	"fmt"
	"path"
	"regexp"
	"strings"
)

// FileTransferMeta describes a browser terminal file transfer candidate.
type FileTransferMeta struct {
	Direction string
	Name      string
	Path      string
	Size      int64
}

// FileTransferDecision is the result of evaluating a candidate against policy.
type FileTransferDecision struct {
	Allowed bool
	Reason  string
}

// SensitivePattern describes a client-side sensitive-content detector.
type SensitivePattern struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Pattern string `json:"pattern"`
	Flags   string `json:"flags,omitempty"`
}

// FileTransferPolicyOptions contains raw allow/deny patterns.
type FileTransferPolicyOptions struct {
	AllowNames                []string
	DenyNames                 []string
	AllowExtensions           []string
	DenyExtensions            []string
	AllowPaths                []string
	DenyPaths                 []string
	MaxUploadBytes            int64
	MaxDownloadBytes          int64
	SensitiveScanEnabled      bool
	SensitiveDetectCreditCard bool
	SensitiveDetectCNIDCard   bool
	SensitiveDetectAPIKey     bool
	SensitiveMaxScanBytes     int64
}

// FileTransferPolicy evaluates file transfer candidates.
type FileTransferPolicy struct {
	allowNames            []string
	denyNames             []string
	allowExtensions       []string
	denyExtensions        []string
	allowPaths            []string
	denyPaths             []string
	maxUploadBytes        int64
	maxDownloadBytes      int64
	sensitiveRules        []sensitiveRule
	sensitiveMaxScanBytes int64
}

type sensitiveRule struct {
	pattern SensitivePattern
	re      *regexp.Regexp
}

// NewFileTransferPolicy normalizes raw allow/deny patterns into an evaluator.
func NewFileTransferPolicy(opts FileTransferPolicyOptions) FileTransferPolicy {
	return FileTransferPolicy{
		allowNames:            normalizePatterns(opts.AllowNames, false),
		denyNames:             normalizePatterns(opts.DenyNames, false),
		allowExtensions:       normalizePatterns(opts.AllowExtensions, true),
		denyExtensions:        normalizePatterns(opts.DenyExtensions, true),
		allowPaths:            normalizePatterns(opts.AllowPaths, false),
		denyPaths:             normalizePatterns(opts.DenyPaths, false),
		maxUploadBytes:        opts.MaxUploadBytes,
		maxDownloadBytes:      opts.MaxDownloadBytes,
		sensitiveRules:        buildSensitiveRules(opts),
		sensitiveMaxScanBytes: opts.SensitiveMaxScanBytes,
	}
}

// ParsePatternList splits a comma-separated config field into trimmed patterns.
func ParsePatternList(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	return out
}

// HasRules reports whether the policy contains any configured allow/deny rules.
func (p FileTransferPolicy) HasRules() bool {
	return len(p.allowNames) > 0 ||
		len(p.denyNames) > 0 ||
		len(p.allowExtensions) > 0 ||
		len(p.denyExtensions) > 0 ||
		len(p.allowPaths) > 0 ||
		len(p.denyPaths) > 0 ||
		p.maxUploadBytes > 0 ||
		p.maxDownloadBytes > 0 ||
		len(p.sensitiveRules) > 0
}

// Evaluate decides whether a file transfer candidate is allowed.
func (p FileTransferPolicy) Evaluate(meta FileTransferMeta) FileTransferDecision {
	name := normalizeTransferName(meta.Name, meta.Path)
	normalizedPath := normalizeTransferPath(meta.Path, name)
	extensions := extensionCandidates(name)

	if matched, pattern := matchesAnyPattern(p.denyNames, name); matched {
		return FileTransferDecision{
			Allowed: false,
			Reason:  "filename " + name + " matches deny rule " + pattern,
		}
	}
	if matched, pattern := matchesAnyPattern(p.denyPaths, normalizedPath); matched {
		return FileTransferDecision{
			Allowed: false,
			Reason:  "path " + normalizedPath + " matches deny rule " + pattern,
		}
	}
	if matched, pattern := matchesAnyExtension(p.denyExtensions, extensions); matched {
		return FileTransferDecision{
			Allowed: false,
			Reason:  "extension " + describeExtensions(extensions) + " matches deny rule " + pattern,
		}
	}
	if limit := p.maxBytesForDirection(meta.Direction); limit > 0 && meta.Size > limit {
		return FileTransferDecision{
			Allowed: false,
			Reason:  fmt.Sprintf("%s size %d bytes exceeds limit %d bytes", describeDirection(meta.Direction), meta.Size, limit),
		}
	}

	if len(p.allowNames) > 0 {
		if matched, _ := matchesAnyPattern(p.allowNames, name); !matched {
			return FileTransferDecision{
				Allowed: false,
				Reason:  "filename " + name + " is not in the allowlist",
			}
		}
	}
	if len(p.allowPaths) > 0 {
		if matched, _ := matchesAnyPattern(p.allowPaths, normalizedPath); !matched {
			return FileTransferDecision{
				Allowed: false,
				Reason:  "path " + normalizedPath + " is not in the allowlist",
			}
		}
	}
	if len(p.allowExtensions) > 0 {
		if matched, _ := matchesAnyExtension(p.allowExtensions, extensions); !matched {
			return FileTransferDecision{
				Allowed: false,
				Reason:  "extension " + describeExtensions(extensions) + " is not in the allowlist",
			}
		}
	}

	return FileTransferDecision{Allowed: true}
}

func normalizePatterns(values []string, extension bool) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if extension {
			value = normalizeExtensionPattern(value)
		}
		out = append(out, value)
	}
	return out
}

func normalizeExtensionPattern(pattern string) string {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	if pattern == "" {
		return ""
	}
	first := pattern[0]
	if first != '.' && first != '*' && first != '?' {
		pattern = "." + pattern
	}
	return pattern
}

func normalizeTransferName(name, transferPath string) string {
	name = strings.TrimSpace(name)
	if name != "" {
		return name
	}
	normalizedPath := normalizeTransferPath(transferPath, "")
	base := path.Base(normalizedPath)
	if base == "." || base == "/" {
		return ""
	}
	return base
}

func normalizeTransferPath(transferPath, fallbackName string) string {
	transferPath = strings.TrimSpace(strings.ReplaceAll(transferPath, "\\", "/"))
	if transferPath == "" {
		transferPath = fallbackName
	}
	if transferPath == "" {
		return ""
	}
	cleaned := path.Clean(transferPath)
	if cleaned == "." {
		return fallbackName
	}
	return strings.TrimPrefix(cleaned, "./")
}

func extensionCandidates(name string) []string {
	name = strings.TrimSpace(strings.ToLower(name))
	if name == "" {
		return nil
	}
	extensions := make([]string, 0, 2)
	for idx := 0; idx < len(name); idx++ {
		if name[idx] != '.' || idx == len(name)-1 {
			continue
		}
		if idx == 0 && !strings.Contains(name[1:], ".") {
			continue
		}
		extensions = append(extensions, name[idx:])
	}
	return extensions
}

func describeExtensions(extensions []string) string {
	if len(extensions) == 0 {
		return "<none>"
	}
	return extensions[0]
}

func matchesAnyExtension(patterns, extensions []string) (bool, string) {
	for _, extension := range extensions {
		if matched, pattern := matchesAnyPattern(patterns, extension); matched {
			return true, pattern
		}
	}
	return false, ""
}

func matchesAnyPattern(patterns []string, value string) (bool, string) {
	for _, patternValue := range patterns {
		if patternValue == value {
			return true, patternValue
		}
		matched, err := path.Match(patternValue, value)
		if err == nil && matched {
			return true, patternValue
		}
	}
	return false, ""
}

// HasSensitiveInspection reports whether content inspection is enabled.
func (p FileTransferPolicy) HasSensitiveInspection() bool {
	return len(p.sensitiveRules) > 0
}

// SensitivePatterns returns the browser-safe regex configuration for active detectors.
func (p FileTransferPolicy) SensitivePatterns() []SensitivePattern {
	if len(p.sensitiveRules) == 0 {
		return nil
	}
	patterns := make([]SensitivePattern, 0, len(p.sensitiveRules))
	for _, rule := range p.sensitiveRules {
		patterns = append(patterns, rule.pattern)
	}
	return patterns
}

// SensitiveMaxScanBytes returns the content scan cap. Zero means "scan all bytes".
func (p FileTransferPolicy) SensitiveMaxScanBytes() int64 {
	return p.sensitiveMaxScanBytes
}

// InspectContent evaluates text content against active sensitive detectors.
func (p FileTransferPolicy) InspectContent(content string) FileTransferDecision {
	for _, rule := range p.sensitiveRules {
		if rule.re.MatchString(content) {
			return FileTransferDecision{
				Allowed: false,
				Reason:  "content matches " + rule.pattern.Name + " detector",
			}
		}
	}
	return FileTransferDecision{Allowed: true}
}

func (p FileTransferPolicy) maxBytesForDirection(direction string) int64 {
	switch strings.ToLower(strings.TrimSpace(direction)) {
	case "upload":
		return p.maxUploadBytes
	case "download":
		return p.maxDownloadBytes
	default:
		switch {
		case p.maxUploadBytes > 0 && p.maxDownloadBytes > 0:
			if p.maxUploadBytes < p.maxDownloadBytes {
				return p.maxUploadBytes
			}
			return p.maxDownloadBytes
		case p.maxUploadBytes > 0:
			return p.maxUploadBytes
		default:
			return p.maxDownloadBytes
		}
	}
}

func describeDirection(direction string) string {
	switch strings.ToLower(strings.TrimSpace(direction)) {
	case "upload", "download":
		return strings.ToLower(strings.TrimSpace(direction))
	default:
		return "file"
	}
}

func buildSensitiveRules(opts FileTransferPolicyOptions) []sensitiveRule {
	if !opts.SensitiveScanEnabled {
		return nil
	}
	patterns := make([]SensitivePattern, 0, 3)
	if opts.SensitiveDetectCreditCard {
		patterns = append(patterns, SensitivePattern{
			ID:      "credit-card",
			Name:    "credit card",
			Pattern: `(?:\b\d{4}[- ]?){3}\d{4}\b`,
		})
	}
	if opts.SensitiveDetectCNIDCard {
		patterns = append(patterns, SensitivePattern{
			ID:      "cn-id-card",
			Name:    "Chinese ID card",
			Pattern: `\b[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b`,
		})
	}
	if opts.SensitiveDetectAPIKey {
		patterns = append(patterns, SensitivePattern{
			ID:      "api-key",
			Name:    "API key",
			Pattern: `(?:api[_-]?key|access[_-]?key|secret[_-]?key)\s*[:=]\s*['"]?[A-Za-z0-9_\-\/+=]{16,}['"]?|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z\-_]{35}`,
			Flags:   "i",
		})
	}
	rules := make([]sensitiveRule, 0, len(patterns))
	for _, pattern := range patterns {
		re, err := regexp.Compile(goRegexpPattern(pattern))
		if err != nil {
			continue
		}
		rules = append(rules, sensitiveRule{
			pattern: pattern,
			re:      re,
		})
	}
	return rules
}

func goRegexpPattern(pattern SensitivePattern) string {
	flags := strings.ToLower(strings.TrimSpace(pattern.Flags))
	if flags == "" {
		return pattern.Pattern
	}
	var prefix strings.Builder
	prefix.WriteString("(?")
	if strings.Contains(flags, "i") {
		prefix.WriteByte('i')
	}
	prefix.WriteByte(')')
	return prefix.String() + pattern.Pattern
}
