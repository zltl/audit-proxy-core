package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

const accessRuleColumns = `id, name, priority, effect, subject_kind, subject, target_selector,
	upstream_logins, features, denied_features, source_cidrs, time_windows,
	max_session_seconds, idle_timeout_seconds, max_concurrent_sessions, record_policy,
	command_policy_id, approval_required, enabled, created_at, updated_at`

// PutAccessRule inserts or replaces an access rule.
func (s *Store) PutAccessRule(r AccessRule) (AccessRule, error) {
	if r.ID == "" {
		r.ID = NewID("acl")
	}
	if r.Effect == "" {
		r.Effect = EffectAllow
	}
	if r.SubjectKind == "" {
		r.SubjectKind = SubjectUser
	}
	if r.Subject == "" {
		r.Subject = "*"
	}
	if r.TargetSelector == "" {
		r.TargetSelector = "*"
	}
	if r.RecordPolicy == "" {
		r.RecordPolicy = RecordFull
	}
	if r.Priority == 0 {
		r.Priority = 100
	}
	now := s.clock()
	if r.CreatedAt.IsZero() {
		r.CreatedAt = now
	}
	r.UpdatedAt = now

	windows, err := encodeJSON(r.TimeWindows)
	if err != nil {
		return AccessRule{}, err
	}

	query := fmt.Sprintf(`INSERT INTO dp_access_rules (%s) VALUES (%s)
		ON CONFLICT(id) DO UPDATE SET
			name = excluded.name,
			priority = excluded.priority,
			effect = excluded.effect,
			subject_kind = excluded.subject_kind,
			subject = excluded.subject,
			target_selector = excluded.target_selector,
			upstream_logins = excluded.upstream_logins,
			features = excluded.features,
			denied_features = excluded.denied_features,
			source_cidrs = excluded.source_cidrs,
			time_windows = excluded.time_windows,
			max_session_seconds = excluded.max_session_seconds,
			idle_timeout_seconds = excluded.idle_timeout_seconds,
			max_concurrent_sessions = excluded.max_concurrent_sessions,
			record_policy = excluded.record_policy,
			command_policy_id = excluded.command_policy_id,
			approval_required = excluded.approval_required,
			enabled = excluded.enabled,
			updated_at = excluded.updated_at`, accessRuleColumns, s.binds(21))

	if _, err := s.db.Exec(query,
		r.ID, r.Name, r.Priority, string(r.Effect), string(r.SubjectKind), r.Subject,
		r.TargetSelector, encodeStringSlice(r.UpstreamLogins), int64(r.Features),
		int64(r.DeniedFeatures), encodeStringSlice(r.SourceCIDRs), windows,
		int64(r.MaxSessionTTL/time.Second), int64(r.IdleTimeout/time.Second),
		r.MaxConcurrent, string(r.RecordPolicy), r.CommandPolicyID, r.ApprovalRequired,
		r.Enabled, s.unix(r.CreatedAt), s.unix(r.UpdatedAt)); err != nil {
		return AccessRule{}, err
	}
	return r, nil
}

// GetAccessRule resolves a rule by identifier.
func (s *Store) GetAccessRule(id string) (AccessRule, error) {
	query := fmt.Sprintf(`SELECT %s FROM dp_access_rules WHERE id = %s LIMIT 1`, accessRuleColumns, s.bind(1))
	r, err := scanAccessRule(s.db.QueryRow(query, id))
	if errors.Is(err, sql.ErrNoRows) {
		return AccessRule{}, ErrNotFound
	}
	return r, err
}

// ListAccessRules returns rules in evaluation order.
//
// Ordering is priority ascending, then deny before allow at the same priority,
// so that an author who gives a carve-out and a blanket grant the same priority
// gets the safe interpretation rather than one that depends on insertion order.
func (s *Store) ListAccessRules() ([]AccessRule, error) {
	rows, err := s.db.Query(fmt.Sprintf(
		`SELECT %s FROM dp_access_rules ORDER BY priority ASC, effect DESC, id ASC`, accessRuleColumns))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	rules := make([]AccessRule, 0)
	for rows.Next() {
		r, err := scanAccessRule(rows)
		if err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

// ListEnabledAccessRules is ListAccessRules restricted to active rules.
func (s *Store) ListEnabledAccessRules() ([]AccessRule, error) {
	all, err := s.ListAccessRules()
	if err != nil {
		return nil, err
	}
	enabled := make([]AccessRule, 0, len(all))
	for _, r := range all {
		if r.Enabled {
			enabled = append(enabled, r)
		}
	}
	return enabled, nil
}

// DeleteAccessRule removes a rule.
func (s *Store) DeleteAccessRule(id string) error {
	query := fmt.Sprintf(`DELETE FROM dp_access_rules WHERE id = %s`, s.bind(1))
	return requireAffected(s.db.Exec(query, id))
}

func scanAccessRule(row rowScanner) (AccessRule, error) {
	var (
		r                              AccessRule
		effect, subjectKind, recordPol string
		logins, cidrs, windows         string
		features, denied               int64
		maxSession, idleTimeout        int64
		createdAt, updatedAt           int64
	)
	if err := row.Scan(&r.ID, &r.Name, &r.Priority, &effect, &subjectKind, &r.Subject,
		&r.TargetSelector, &logins, &features, &denied, &cidrs, &windows,
		&maxSession, &idleTimeout, &r.MaxConcurrent, &recordPol, &r.CommandPolicyID,
		&r.ApprovalRequired, &r.Enabled, &createdAt, &updatedAt); err != nil {
		return AccessRule{}, err
	}
	r.Effect = Effect(effect)
	r.SubjectKind = SubjectKind(subjectKind)
	r.RecordPolicy = RecordPolicy(recordPol)
	r.UpstreamLogins = decodeStringSlice(logins)
	r.SourceCIDRs = decodeStringSlice(cidrs)
	r.TimeWindows = decodeTimeWindows(windows)
	r.Features = FeatureSet(features)
	r.DeniedFeatures = FeatureSet(denied)
	r.MaxSessionTTL = time.Duration(maxSession) * time.Second
	r.IdleTimeout = time.Duration(idleTimeout) * time.Second
	r.CreatedAt = fromUnix(createdAt)
	r.UpdatedAt = fromUnix(updatedAt)
	return r, nil
}

// --------------------------------------------------------------------------
// Roles
// --------------------------------------------------------------------------

// PutRole creates or updates a role definition.
func (s *Store) PutRole(r Role) error {
	r.Name = strings.ToLower(strings.TrimSpace(r.Name))
	if r.Name == "" {
		return fmt.Errorf("store: role name is required")
	}
	if r.CreatedAt.IsZero() {
		r.CreatedAt = s.clock()
	}
	query := fmt.Sprintf(`INSERT INTO dp_roles(name, description, builtin, created_at)
		VALUES (%s) ON CONFLICT(name) DO UPDATE SET description = excluded.description`, s.binds(4))
	_, err := s.db.Exec(query, r.Name, r.Description, r.Builtin, s.unix(r.CreatedAt))
	return err
}

// ListRoles returns all role definitions.
func (s *Store) ListRoles() ([]Role, error) {
	rows, err := s.db.Query(`SELECT name, description, builtin, created_at FROM dp_roles ORDER BY name ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	roles := make([]Role, 0)
	for rows.Next() {
		var (
			r         Role
			createdAt int64
		)
		if err := rows.Scan(&r.Name, &r.Description, &r.Builtin, &createdAt); err != nil {
			return nil, err
		}
		r.CreatedAt = fromUnix(createdAt)
		roles = append(roles, r)
	}
	return roles, rows.Err()
}

// DeleteRole removes a role. Built-in roles cannot be removed, because the
// authorization policy refers to them by name.
func (s *Store) DeleteRole(name string) error {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, builtin := range BuiltinRoles {
		if builtin.Name == name {
			return fmt.Errorf("store: role %q is built in and cannot be deleted", name)
		}
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(fmt.Sprintf(`DELETE FROM dp_role_bindings WHERE role = %s`, s.bind(1)), name); err != nil {
		return err
	}
	result, err := tx.Exec(fmt.Sprintf(`DELETE FROM dp_roles WHERE name = %s`, s.bind(1)), name)
	if err != nil {
		return err
	}
	if affected, err := rowsAffected(result); err != nil {
		return err
	} else if affected == 0 {
		return fmt.Errorf("%w: role %q", ErrNotFound, name)
	}
	return tx.Commit()
}

// BindRole grants a role to a subject.
func (s *Store) BindRole(b RoleBinding) (RoleBinding, error) {
	if b.SubjectKind == "" {
		b.SubjectKind = SubjectUser
	}
	b.Subject = strings.TrimSpace(b.Subject)
	b.Role = strings.ToLower(strings.TrimSpace(b.Role))
	if b.Subject == "" || b.Role == "" {
		return RoleBinding{}, fmt.Errorf("store: role binding needs a subject and a role")
	}
	if b.ID == "" {
		b.ID = NewID("rb")
	}
	if b.CreatedAt.IsZero() {
		b.CreatedAt = s.clock()
	}
	query := fmt.Sprintf(`INSERT INTO dp_role_bindings(id, subject_kind, subject, role, created_at)
		VALUES (%s) ON CONFLICT(subject_kind, subject, role) DO NOTHING`, s.binds(5))
	if _, err := s.db.Exec(query, b.ID, string(b.SubjectKind), b.Subject, b.Role, s.unix(b.CreatedAt)); err != nil {
		return RoleBinding{}, err
	}
	return b, nil
}

// UnbindRole revokes a role from a subject.
func (s *Store) UnbindRole(kind SubjectKind, subject, role string) error {
	query := fmt.Sprintf(`DELETE FROM dp_role_bindings WHERE subject_kind = %s AND subject = %s AND role = %s`,
		s.bind(1), s.bind(2), s.bind(3))
	return requireAffected(s.db.Exec(query, string(kind), strings.TrimSpace(subject),
		strings.ToLower(strings.TrimSpace(role))))
}

// RolesForUser returns the roles bound to a username.
func (s *Store) RolesForUser(username string) ([]string, error) {
	query := fmt.Sprintf(`SELECT role FROM dp_role_bindings
		WHERE subject_kind = %s AND subject = %s ORDER BY role ASC`, s.bind(1), s.bind(2))
	rows, err := s.db.Query(query, string(SubjectUser), strings.TrimSpace(username))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	roles := make([]string, 0)
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}
	return roles, rows.Err()
}

// ListRoleBindings returns every role grant.
func (s *Store) ListRoleBindings() ([]RoleBinding, error) {
	rows, err := s.db.Query(`SELECT id, subject_kind, subject, role, created_at
		FROM dp_role_bindings ORDER BY subject ASC, role ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	bindings := make([]RoleBinding, 0)
	for rows.Next() {
		var (
			b         RoleBinding
			kind      string
			createdAt int64
		)
		if err := rows.Scan(&b.ID, &kind, &b.Subject, &b.Role, &createdAt); err != nil {
			return nil, err
		}
		b.SubjectKind = SubjectKind(kind)
		b.CreatedAt = fromUnix(createdAt)
		bindings = append(bindings, b)
	}
	return bindings, rows.Err()
}

// --------------------------------------------------------------------------
// IP rules
// --------------------------------------------------------------------------

// PutIPRule inserts or replaces a source-network rule.
func (s *Store) PutIPRule(r IPRule) (IPRule, error) {
	r.CIDR = strings.TrimSpace(r.CIDR)
	if r.CIDR == "" {
		return IPRule{}, fmt.Errorf("store: ip rule cidr is required")
	}
	if r.ID == "" {
		r.ID = NewID("ip")
	}
	if r.Action == "" {
		r.Action = IPDeny
	}
	if r.Priority == 0 {
		r.Priority = 100
	}
	if r.CreatedAt.IsZero() {
		r.CreatedAt = s.clock()
	}
	query := fmt.Sprintf(`INSERT INTO dp_ip_rules(id, cidr, action, priority, comment, expires_at, created_at)
		VALUES (%s) ON CONFLICT(id) DO UPDATE SET
			cidr = excluded.cidr,
			action = excluded.action,
			priority = excluded.priority,
			comment = excluded.comment,
			expires_at = excluded.expires_at`, s.binds(7))
	if _, err := s.db.Exec(query, r.ID, r.CIDR, string(r.Action), r.Priority, r.Comment,
		s.unix(r.ExpiresAt), s.unix(r.CreatedAt)); err != nil {
		return IPRule{}, err
	}
	return r, nil
}

// ListIPRules returns source-network rules in evaluation order.
func (s *Store) ListIPRules() ([]IPRule, error) {
	rows, err := s.db.Query(`SELECT id, cidr, action, priority, comment, expires_at, created_at
		FROM dp_ip_rules ORDER BY priority ASC, created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	rules := make([]IPRule, 0)
	for rows.Next() {
		var (
			r                    IPRule
			action               string
			expiresAt, createdAt int64
		)
		if err := rows.Scan(&r.ID, &r.CIDR, &action, &r.Priority, &r.Comment, &expiresAt, &createdAt); err != nil {
			return nil, err
		}
		r.Action = IPRuleAction(action)
		r.ExpiresAt = fromUnix(expiresAt)
		r.CreatedAt = fromUnix(createdAt)
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

// DeleteIPRule removes a source-network rule.
func (s *Store) DeleteIPRule(id string) error {
	query := fmt.Sprintf(`DELETE FROM dp_ip_rules WHERE id = %s`, s.bind(1))
	return requireAffected(s.db.Exec(query, id))
}

// PurgeExpiredIPRules removes time-limited blocks that have lapsed, which is how
// automatic threat-response bans age out.
func (s *Store) PurgeExpiredIPRules() (int64, error) {
	query := fmt.Sprintf(`DELETE FROM dp_ip_rules WHERE expires_at > 0 AND expires_at < %s`, s.bind(1))
	result, err := s.db.Exec(query, s.unix(s.clock()))
	if err != nil {
		return 0, err
	}
	return rowsAffected(result)
}

// --------------------------------------------------------------------------
// Command policies
// --------------------------------------------------------------------------

// PutCommandPolicy creates or updates a named command policy.
func (s *Store) PutCommandPolicy(p CommandPolicy) (CommandPolicy, error) {
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" {
		return CommandPolicy{}, fmt.Errorf("store: command policy name is required")
	}
	if p.ID == "" {
		p.ID = NewID("cmdpol")
	}
	now := s.clock()
	if p.CreatedAt.IsZero() {
		p.CreatedAt = now
	}
	p.UpdatedAt = now
	query := fmt.Sprintf(`INSERT INTO dp_command_policies(id, name, description, created_at, updated_at)
		VALUES (%s) ON CONFLICT(name) DO UPDATE SET
			description = excluded.description,
			updated_at = excluded.updated_at`, s.binds(5))
	if _, err := s.db.Exec(query, p.ID, p.Name, p.Description, s.unix(p.CreatedAt), s.unix(p.UpdatedAt)); err != nil {
		return CommandPolicy{}, err
	}
	return p, nil
}

// ListCommandPolicies returns every command policy.
func (s *Store) ListCommandPolicies() ([]CommandPolicy, error) {
	rows, err := s.db.Query(`SELECT id, name, description, created_at, updated_at
		FROM dp_command_policies ORDER BY name ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	policies := make([]CommandPolicy, 0)
	for rows.Next() {
		var (
			p                    CommandPolicy
			createdAt, updatedAt int64
		)
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &createdAt, &updatedAt); err != nil {
			return nil, err
		}
		p.CreatedAt = fromUnix(createdAt)
		p.UpdatedAt = fromUnix(updatedAt)
		policies = append(policies, p)
	}
	return policies, rows.Err()
}

// PutCommandRule inserts or replaces a rule inside a command policy.
func (s *Store) PutCommandRule(r CommandRule) (CommandRule, error) {
	if strings.TrimSpace(r.PolicyID) == "" {
		return CommandRule{}, fmt.Errorf("store: command rule needs a policy_id")
	}
	if strings.TrimSpace(r.Pattern) == "" {
		return CommandRule{}, fmt.Errorf("store: command rule needs a pattern")
	}
	if r.ID == "" {
		r.ID = NewID("cmdrule")
	}
	if r.Action == "" {
		r.Action = CommandAudit
	}
	if r.Priority == 0 {
		r.Priority = 100
	}
	if r.Severity == "" {
		r.Severity = "medium"
	}
	if r.CreatedAt.IsZero() {
		r.CreatedAt = s.clock()
	}
	query := fmt.Sprintf(`INSERT INTO dp_command_rules
		(id, policy_id, priority, pattern, action, rewrite, severity, message, enabled, created_at)
		VALUES (%s) ON CONFLICT(id) DO UPDATE SET
			policy_id = excluded.policy_id,
			priority = excluded.priority,
			pattern = excluded.pattern,
			action = excluded.action,
			rewrite = excluded.rewrite,
			severity = excluded.severity,
			message = excluded.message,
			enabled = excluded.enabled`, s.binds(10))
	if _, err := s.db.Exec(query, r.ID, r.PolicyID, r.Priority, r.Pattern, string(r.Action),
		r.Rewrite, r.Severity, r.Message, r.Enabled, s.unix(r.CreatedAt)); err != nil {
		return CommandRule{}, err
	}
	return r, nil
}

// ListCommandRules returns a policy's rules in evaluation order.
func (s *Store) ListCommandRules(policyID string) ([]CommandRule, error) {
	query := fmt.Sprintf(`SELECT id, policy_id, priority, pattern, action, rewrite, severity,
		message, enabled, created_at FROM dp_command_rules WHERE policy_id = %s
		ORDER BY priority ASC, created_at ASC`, s.bind(1))
	rows, err := s.db.Query(query, policyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	rules := make([]CommandRule, 0)
	for rows.Next() {
		var (
			r         CommandRule
			action    string
			createdAt int64
		)
		if err := rows.Scan(&r.ID, &r.PolicyID, &r.Priority, &r.Pattern, &action, &r.Rewrite,
			&r.Severity, &r.Message, &r.Enabled, &createdAt); err != nil {
			return nil, err
		}
		r.Action = CommandAction(action)
		r.CreatedAt = fromUnix(createdAt)
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

// DeleteCommandRule removes a single command rule.
func (s *Store) DeleteCommandRule(id string) error {
	query := fmt.Sprintf(`DELETE FROM dp_command_rules WHERE id = %s`, s.bind(1))
	return requireAffected(s.db.Exec(query, id))
}

// DeleteCommandPolicy removes a policy and its rules.
func (s *Store) DeleteCommandPolicy(id string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(fmt.Sprintf(`DELETE FROM dp_command_rules WHERE policy_id = %s`, s.bind(1)), id); err != nil {
		return err
	}
	result, err := tx.Exec(fmt.Sprintf(`DELETE FROM dp_command_policies WHERE id = %s`, s.bind(1)), id)
	if err != nil {
		return err
	}
	if affected, err := rowsAffected(result); err != nil {
		return err
	} else if affected == 0 {
		return fmt.Errorf("%w: command policy %q", ErrNotFound, id)
	}
	return tx.Commit()
}
