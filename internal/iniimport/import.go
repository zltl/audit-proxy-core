package iniimport

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/zltl/audit-proxy-core/internal/store"
)

// Result summarises what an import did, so the operator can confirm the outcome
// matched the file they handed over rather than trusting a silent success.
type Result struct {
	Users        int
	PublicKeys   int
	Targets      int
	AccessRules  int
	Credentials  int
	Secrets      int
	IPRules      int
	CommandRules int
	// Warnings records everything the import could not carry over faithfully.
	// These are not fatal, but each one is a difference between the old
	// configuration and the new database that somebody has to look at.
	Warnings []string
}

func (r *Result) warn(format string, args ...interface{}) {
	r.Warnings = append(r.Warnings, fmt.Sprintf(format, args...))
}

// Options tunes an import.
type Options struct {
	// ImportPrivateKeys reads the key files referenced by route definitions and
	// stores their contents as sealed secrets. Off by default because it moves
	// key material into the database, which is a decision to make deliberately.
	ImportPrivateKeys bool
	// DefaultRulePriority is where generated access rules start; per-user rules
	// are placed ahead of the wildcard fallback.
	DefaultRulePriority int
	// BaseDir resolves relative paths found in the file.
	BaseDir string
}

func (o Options) withDefaults() Options {
	if o.DefaultRulePriority == 0 {
		o.DefaultRulePriority = 100
	}
	return o
}

// Import reads an INI file and writes its contents into the store.
//
// It is safe to re-run: users, targets, and rules are keyed by their names, so
// a second import updates rather than duplicating.
func Import(path string, st *store.Store, opts Options) (*Result, error) {
	doc, err := ParseFile(path)
	if err != nil {
		return nil, fmt.Errorf("iniimport: %w", err)
	}
	if opts.BaseDir == "" {
		opts.BaseDir = filepath.Dir(path)
	}
	return ImportDocument(doc, st, opts)
}

// ImportDocument writes an already-parsed document into the store.
func ImportDocument(doc *Document, st *store.Store, opts Options) (*Result, error) {
	opts = opts.withDefaults()
	result := &Result{}

	if err := importUsers(doc, st, result); err != nil {
		return result, err
	}
	targets, err := importTargets(doc, st, opts, result)
	if err != nil {
		return result, err
	}
	if err := importAccessRules(doc, st, targets, opts, result); err != nil {
		return result, err
	}
	if err := importIPRules(doc, st, result); err != nil {
		return result, err
	}
	return result, nil
}

// --------------------------------------------------------------------------
// Users
// --------------------------------------------------------------------------

func importUsers(doc *Document, st *store.Store, result *Result) error {
	for _, section := range doc.SectionsOfKind("user") {
		username := section.Arg
		if username == "" {
			result.warn("skipped a [user:] section with no username")
			continue
		}

		user := store.User{
			Username:     username,
			Source:       store.SourceLocal,
			PasswordHash: section.GetDefault("password_hash", ""),
			Status:       store.UserActive,
		}
		if enabled, ok := section.Get("enabled"); ok && !parseBool(enabled, true) {
			user.Status = store.UserDisabled
		}
		if changedAt, ok := section.Get("password_changed_at"); ok {
			if sec, err := strconv.ParseInt(strings.TrimSpace(changedAt), 10, 64); err == nil && sec > 0 {
				user.PasswordChangedAt = time.Unix(sec, 0).UTC()
			}
		}
		user.PasswordChangeRequired = parseBool(section.GetDefault("password_change_required", "false"), false)

		if secret := strings.TrimSpace(section.GetDefault("totp_secret", "")); secret != "" {
			if !st.HasSealer() {
				result.warn("user %q has a TOTP secret but no encryption key is configured; MFA was not imported", username)
			} else {
				ref, err := st.PutSecretString("totp", secret)
				if err != nil {
					return fmt.Errorf("iniimport: seal TOTP secret for %q: %w", username, err)
				}
				result.Secrets++
				user.MFAType = store.MFATOTP
				user.MFASecretRef = ref
				// The file format has no notion of a confirmed enrolment, so an
				// imported secret is treated as already proven: it was in use.
				user.MFAPending = false
			}
		}

		if err := upsertUser(st, user); err != nil {
			return fmt.Errorf("iniimport: import user %q: %w", username, err)
		}
		result.Users++

		stored, err := st.GetUser(username)
		if err != nil {
			return fmt.Errorf("iniimport: reload user %q: %w", username, err)
		}
		n, err := importUserKeys(section, st, stored, result)
		if err != nil {
			return err
		}
		result.PublicKeys += n
	}
	return nil
}

func upsertUser(st *store.Store, user store.User) error {
	_, err := st.CreateUser(user)
	if err == nil {
		return nil
	}
	if !isConflict(err) {
		return err
	}
	_, err = st.UpdateUser(user.Username, func(existing *store.User) error {
		existing.Status = user.Status
		existing.Source = user.Source
		if user.PasswordHash != "" {
			existing.PasswordHash = user.PasswordHash
		}
		if !user.PasswordChangedAt.IsZero() {
			existing.PasswordChangedAt = user.PasswordChangedAt
		}
		existing.PasswordChangeRequired = user.PasswordChangeRequired
		if user.MFASecretRef != "" {
			existing.MFAType = user.MFAType
			existing.MFASecretRef = user.MFASecretRef
			existing.MFAPending = user.MFAPending
		}
		return nil
	})
	return err
}

func importUserKeys(section Section, st *store.Store, user store.User, result *Result) (int, error) {
	lines := section.All("pubkey")
	for _, path := range section.All("pubkey_file") {
		raw, err := os.ReadFile(strings.TrimSpace(path))
		if err != nil {
			result.warn("user %q: cannot read pubkey_file %s: %v", user.Username, path, err)
			continue
		}
		lines = append(lines, strings.Split(string(raw), "\n")...)
	}

	imported := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parsed, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			result.warn("user %q: skipped an unparseable public key: %v", user.Username, err)
			continue
		}
		fingerprint := ssh.FingerprintSHA256(parsed)
		_, err = st.AddPublicKey(store.PublicKey{
			UserID:      user.ID,
			Fingerprint: fingerprint,
			Algorithm:   parsed.Type(),
			PublicKey:   strings.TrimSpace(string(ssh.MarshalAuthorizedKey(parsed))),
			Comment:     comment,
		})
		if err != nil {
			if isConflict(err) {
				// Already imported by an earlier run, or the same key appears
				// under two users; either way the existing row wins and the
				// operator is told.
				result.warn("user %q: public key %s is already registered", user.Username, fingerprint)
				continue
			}
			return imported, fmt.Errorf("iniimport: add public key for %q: %w", user.Username, err)
		}
		imported++
	}
	return imported, nil
}

// --------------------------------------------------------------------------
// Targets and routes
// --------------------------------------------------------------------------

// routeBinding is one [route:<pattern>] entry after resolution.
type routeBinding struct {
	Pattern string
	Target  store.Target
	Login   string
	PrivKey string
	Enabled bool
}

func importTargets(doc *Document, st *store.Store, opts Options, result *Result) ([]routeBinding, error) {
	// Several routes commonly point at the same host; dedupe so the trust store
	// has one entry per host rather than one per route.
	byAddress := make(map[string]store.Target)
	bindings := make([]routeBinding, 0)

	for _, section := range doc.SectionsOfKind("route") {
		pattern := section.Arg
		if pattern == "" {
			result.warn("skipped a [route:] section with no pattern")
			continue
		}
		host := strings.TrimSpace(firstNonEmpty(
			section.GetDefault("upstream", ""),
			section.GetDefault("upstream_host", ""),
			section.GetDefault("host", ""),
		))
		if host == "" {
			result.warn("route %q has no upstream host and was skipped", pattern)
			continue
		}
		port := parseInt(firstNonEmpty(
			section.GetDefault("port", ""),
			section.GetDefault("upstream_port", ""),
		), 22)

		address := fmt.Sprintf("%s:%d", host, port)
		target, seen := byAddress[address]
		if !seen {
			var err error
			target, err = upsertTarget(st, store.Target{
				Name:    targetNameFor(host, port),
				Host:    host,
				Port:    port,
				Enabled: true,
			})
			if err != nil {
				return nil, fmt.Errorf("iniimport: import target %s: %w", address, err)
			}
			byAddress[address] = target
			result.Targets++
		}

		bindings = append(bindings, routeBinding{
			Pattern: pattern,
			Target:  target,
			Login: strings.TrimSpace(firstNonEmpty(
				section.GetDefault("user", ""),
				section.GetDefault("upstream_user", ""),
			)),
			PrivKey: strings.TrimSpace(firstNonEmpty(
				section.GetDefault("privkey", ""),
				section.GetDefault("private_key", ""),
			)),
			Enabled: parseBool(section.GetDefault("enabled", "true"), true),
		})
	}

	if err := importCredentials(bindings, st, opts, result); err != nil {
		return bindings, err
	}
	return bindings, nil
}

func upsertTarget(st *store.Store, target store.Target) (store.Target, error) {
	created, err := st.CreateTarget(target)
	if err == nil {
		return created, nil
	}
	if !isConflict(err) {
		return store.Target{}, err
	}
	return st.UpdateTarget(target.Name, func(existing *store.Target) error {
		existing.Host = target.Host
		existing.Port = target.Port
		existing.Enabled = target.Enabled
		return nil
	})
}

// targetNameFor derives a stable, readable target name from an address.
func targetNameFor(host string, port int) string {
	name := strings.ToLower(strings.TrimSpace(host))
	name = strings.NewReplacer(":", "-", "/", "-", " ", "-").Replace(name)
	if port != 22 {
		name = fmt.Sprintf("%s-%d", name, port)
	}
	return name
}

func importCredentials(bindings []routeBinding, st *store.Store, opts Options, result *Result) error {
	seen := make(map[string]bool)
	for _, binding := range bindings {
		if binding.Login == "" {
			continue
		}
		key := binding.Target.ID + "\x00" + binding.Login
		if seen[key] {
			continue
		}
		seen[key] = true

		cred := store.Credential{
			TargetID: binding.Target.ID,
			Login:    binding.Login,
			Kind:     store.CredentialAgent,
		}

		if binding.PrivKey != "" {
			path := binding.PrivKey
			if strings.HasPrefix(path, "~/") {
				if home, err := os.UserHomeDir(); err == nil {
					path = filepath.Join(home, path[2:])
				}
			}
			if !filepath.IsAbs(path) && opts.BaseDir != "" {
				path = filepath.Join(opts.BaseDir, path)
			}

			switch {
			case !opts.ImportPrivateKeys:
				result.warn("route %q references private key %s; re-run with private key import enabled, or attach a credential through the API",
					binding.Pattern, binding.PrivKey)
			case !st.HasSealer():
				result.warn("route %q references private key %s but no encryption key is configured; the key was not imported",
					binding.Pattern, binding.PrivKey)
			default:
				raw, err := os.ReadFile(path)
				if err != nil {
					result.warn("route %q: cannot read private key %s: %v", binding.Pattern, path, err)
					break
				}
				if _, err := ssh.ParsePrivateKey(raw); err != nil {
					result.warn("route %q: %s is not a usable private key: %v", binding.Pattern, path, err)
					break
				}
				ref, err := st.PutSecret("upstream_private_key", raw)
				if err != nil {
					return fmt.Errorf("iniimport: seal private key for route %q: %w", binding.Pattern, err)
				}
				result.Secrets++
				cred.Kind = store.CredentialPrivateKey
				cred.SecretRef = ref
			}
		}

		if _, err := st.PutCredential(cred); err != nil {
			return fmt.Errorf("iniimport: import credential for route %q: %w", binding.Pattern, err)
		}
		result.Credentials++
	}
	return nil
}

// --------------------------------------------------------------------------
// Access rules
// --------------------------------------------------------------------------

// policySpec is a [policy:...] section resolved into feature masks.
type policySpec struct {
	Subject  string
	Upstream string
	Allowed  store.FeatureSet
	Denied   store.FeatureSet
}

func importAccessRules(doc *Document, st *store.Store, bindings []routeBinding, opts Options, result *Result) error {
	policies := collectPolicies(doc, result)
	perUserLimit := 0
	if limits, ok := doc.Section("limits"); ok {
		perUserLimit = parseInt(limits.GetDefault("per_user_max_sessions", "0"), 0)
	}
	sessionTimeout := 0
	if limits, ok := doc.Section("limits"); ok {
		sessionTimeout = parseInt(limits.GetDefault("session_timeout", "0"), 0)
	}

	for i, binding := range bindings {
		allowed, denied := resolvePolicy(policies, binding.Pattern, binding.Target.Host)

		subjectKind := store.SubjectUser
		subject := binding.Pattern
		priority := opts.DefaultRulePriority
		if subject == "*" {
			subjectKind = store.SubjectAny
			subject = "*"
			// The catch-all must be considered after the specific rules, or it
			// would shadow them.
			priority = opts.DefaultRulePriority + 1000
		}

		var logins []string
		if binding.Login != "" {
			logins = []string{binding.Login}
		}

		rule := store.AccessRule{
			ID:             fmt.Sprintf("ini-route-%02d-%s", i, sanitizeID(binding.Pattern)),
			Name:           fmt.Sprintf("imported route %s", binding.Pattern),
			Priority:       priority,
			Effect:         store.EffectAllow,
			SubjectKind:    subjectKind,
			Subject:        subject,
			TargetSelector: binding.Target.Name,
			UpstreamLogins: logins,
			Features:       allowed,
			DeniedFeatures: denied,
			MaxConcurrent:  perUserLimit,
			RecordPolicy:   store.RecordFull,
			Enabled:        binding.Enabled,
		}
		if sessionTimeout > 0 {
			rule.MaxSessionTTL = time.Duration(sessionTimeout) * time.Second
		}
		if _, err := st.PutAccessRule(rule); err != nil {
			return fmt.Errorf("iniimport: import access rule for route %q: %w", binding.Pattern, err)
		}
		result.AccessRules++
	}
	return nil
}

func collectPolicies(doc *Document, result *Result) []policySpec {
	var specs []policySpec
	for _, section := range doc.SectionsOfKind("policy") {
		if section.Arg == "" {
			result.warn("skipped a [policy:] section with no subject")
			continue
		}
		subject, upstream, _ := strings.Cut(section.Arg, "@")
		spec := policySpec{Subject: strings.TrimSpace(subject), Upstream: strings.TrimSpace(upstream)}

		allowRaw := firstNonEmpty(section.GetDefault("allow", ""), section.GetDefault("allowed", ""))
		denyRaw := firstNonEmpty(section.GetDefault("deny", ""), section.GetDefault("denied", ""))

		var unknown []string
		spec.Allowed, unknown = store.ParseFeatureSet(allowRaw)
		for _, name := range unknown {
			result.warn("policy %q: unknown feature %q in allow list", section.Arg, name)
		}
		spec.Denied, unknown = store.ParseFeatureSet(denyRaw)
		for _, name := range unknown {
			result.warn("policy %q: unknown feature %q in deny list", section.Arg, name)
		}
		specs = append(specs, spec)
	}

	// A policy naming both a subject and an upstream is more specific than one
	// naming only a subject, and a named subject beats the wildcard.
	sort.SliceStable(specs, func(i, j int) bool {
		return policySpecificity(specs[i]) > policySpecificity(specs[j])
	})
	return specs
}

func policySpecificity(spec policySpec) int {
	score := 0
	if spec.Subject != "*" && spec.Subject != "" {
		score += 2
	}
	if spec.Upstream != "" && spec.Upstream != "*" {
		score++
	}
	return score
}

func resolvePolicy(specs []policySpec, subject, upstreamHost string) (allowed, denied store.FeatureSet) {
	for _, spec := range specs {
		if spec.Subject != "*" && !strings.EqualFold(spec.Subject, subject) {
			continue
		}
		if spec.Upstream != "" && spec.Upstream != "*" && !strings.EqualFold(spec.Upstream, upstreamHost) {
			continue
		}
		return spec.Allowed, spec.Denied
	}
	// With no policy at all the legacy data plane permitted everything, so an
	// import that silently narrowed access would break working deployments.
	// The features are recorded explicitly rather than left blank so the result
	// is visible in the rule instead of being an implicit default.
	return store.FeatureAll, store.FeatureNone
}

// --------------------------------------------------------------------------
// IP ACL
// --------------------------------------------------------------------------

func importIPRules(doc *Document, st *store.Store, result *Result) error {
	section, ok := doc.Section("ip_acl")
	if !ok {
		return nil
	}
	raw, ok := section.Get("rules")
	if !ok || strings.TrimSpace(raw) == "" {
		return nil
	}
	mode := strings.ToLower(strings.TrimSpace(section.GetDefault("mode", "blacklist")))

	priority := 10
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		cidr, action, hasAction := strings.Cut(entry, ":")
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		ruleAction := store.IPDeny
		if hasAction {
			if strings.EqualFold(strings.TrimSpace(action), "allow") {
				ruleAction = store.IPAllow
			}
		} else if mode == "whitelist" {
			ruleAction = store.IPAllow
		}

		if _, err := st.PutIPRule(store.IPRule{
			ID:       "ini-ip-" + sanitizeID(cidr),
			CIDR:     cidr,
			Action:   ruleAction,
			Priority: priority,
			Comment:  "imported from config.ini",
		}); err != nil {
			return fmt.Errorf("iniimport: import ip rule %q: %w", entry, err)
		}
		result.IPRules++
		priority += 10
	}

	if mode == "whitelist" {
		// A whitelist only means anything if everything else is refused, and
		// the legacy format left that implicit.
		if _, err := st.PutIPRule(store.IPRule{
			ID:       "ini-ip-default-deny",
			CIDR:     "0.0.0.0/0",
			Action:   store.IPDeny,
			Priority: priority + 1000,
			Comment:  "imported whitelist mode: refuse anything not listed",
		}); err != nil {
			return fmt.Errorf("iniimport: add whitelist default deny: %w", err)
		}
		result.IPRules++
	}
	return nil
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

func isConflict(err error) bool {
	return err != nil && strings.Contains(err.Error(), store.ErrConflict.Error())
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func parseBool(raw string, fallback bool) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on", "enabled":
		return true
	case "0", "false", "no", "off", "disabled":
		return false
	default:
		return fallback
	}
}

func parseInt(raw string, fallback int) int {
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return fallback
	}
	return n
}

// sanitizeID makes an arbitrary configuration name safe to embed in a stable
// row identifier, so re-importing updates the same row.
func sanitizeID(raw string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(raw)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-', r == '_':
			b.WriteRune(r)
		case r == '*':
			b.WriteString("any")
		default:
			b.WriteByte('-')
		}
	}
	out := b.String()
	if out == "" {
		return "unnamed"
	}
	return out
}
