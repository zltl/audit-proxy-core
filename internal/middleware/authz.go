package middleware

import (
	"net/http"
	"sort"
	"strings"
)

// Role names understood by the control plane, ordered from least to most
// privileged. OIDC and SAML role mappers emit these same strings.
const (
	RoleViewer   = "viewer"
	RoleOperator = "operator"
	RoleAdmin    = "admin"
)

// roleRank maps a role to its position in the privilege hierarchy. Unknown or
// empty roles rank as viewer so that a session minted before roles existed can
// still read, but can never mutate anything.
func roleRank(role string) int {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case RoleAdmin:
		return 3
	case RoleOperator:
		return 2
	case RoleViewer:
		return 1
	default:
		return 1
	}
}

// RoleAtLeast reports whether have satisfies want in the role hierarchy.
func RoleAtLeast(have, want string) bool {
	return roleRank(have) >= roleRank(want)
}

// RouteRule requires a minimum role for requests matching a path prefix. When
// Methods is empty the rule applies to every method.
type RouteRule struct {
	Prefix  string
	Methods []string
	Role    string
}

func (r RouteRule) matches(method, path string) bool {
	if !strings.HasPrefix(path, r.Prefix) {
		return false
	}
	if len(r.Methods) == 0 {
		return true
	}
	for _, m := range r.Methods {
		if strings.EqualFold(m, method) {
			return true
		}
	}
	return false
}

// AuthzConfig is the control plane's central authorization table. Keeping every
// rule in one place is what makes it possible to reason about coverage: any
// route not named by a rule still falls through to the method-based defaults
// rather than being silently unprotected.
type AuthzConfig struct {
	Rules []RouteRule
	// ReadRole applies to safe methods that no rule matched.
	ReadRole string
	// WriteRole applies to mutating methods that no rule matched.
	WriteRole string
	// PublicPrefixes are skipped entirely; defaults to the shared list used by
	// the Auth middleware.
	PublicPrefixes []string
}

var writeMethods = []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}

// DefaultAuthzConfig returns the shipped policy.
//
// The baseline is: reading requires viewer, mutating requires operator. Rules
// then raise the bar for anything that changes who can reach what — identities,
// routing, credentials, security policy, and cluster/system lifecycle — because
// those are equivalent to granting access rather than using it.
func DefaultAuthzConfig() AuthzConfig {
	admin := func(prefix string, methods ...string) RouteRule {
		return RouteRule{Prefix: prefix, Methods: methods, Role: RoleAdmin}
	}
	operator := func(prefix string, methods ...string) RouteRule {
		return RouteRule{Prefix: prefix, Methods: methods, Role: RoleOperator}
	}

	return AuthzConfig{
		ReadRole:  RoleViewer,
		WriteRole: RoleOperator,
		Rules: []RouteRule{
			// Identity and access management.
			admin("/api/v2/users"),
			// The data-plane tables decide who may reach which host as which
			// account; every endpoint under them grants access rather than
			// merely using it.
			admin("/api/v2/dp/"),
			admin("/api/v2/rbac/"),

			// Anything that changes what a session may reach.
			admin("/api/v2/servers", writeMethods...),
			admin("/api/v2/config", writeMethods...),
			operator("/api/v2/config"),
			// Host certificates and revocation are administrative. Signing a
			// user certificate is deliberately self-service: the handler binds
			// the principals to the caller's own identity unless they are an
			// admin, which is a finer-grained check than a role gate can make.
			admin("/api/v2/ca/sign-host"),
			admin("/api/v2/ca/revoke"),
			operator("/api/v2/ca/certs"),
			{Prefix: "/api/v2/ca/sign-user", Role: RoleViewer},
			admin("/api/v2/jit/policy"),
			admin("/api/v2/commands/rules", writeMethods...),
			admin("/api/v2/threats/rules", writeMethods...),
			admin("/api/v2/gateway/"),
			admin("/api/v2/discovery/", writeMethods...),

			// Platform lifecycle and log destinations.
			admin("/api/v2/system/"),
			admin("/api/v2/cluster/", writeMethods...),
			admin("/api/v2/siem/", writeMethods...),
			admin("/api/v2/webhooks/", writeMethods...),
			admin("/api/v2/compliance/", writeMethods...),

			// Audit trail is append-only from the outside.
			admin("/api/v2/audit/", writeMethods...),

			// Day-to-day operations.
			operator("/api/v2/sessions/", writeMethods...),
			operator("/api/v2/automation/", writeMethods...),
			operator("/api/v2/terminal/", writeMethods...),
			operator("/ws/terminal"),
		},
	}
}

// normalizeAuthzPath collapses the versioned API aliases so a single rule set
// covers every advertised version. The v3 surface is registered as an alias of
// v2 on the mux, but middleware runs before that rewrite.
func normalizeAuthzPath(path string) string {
	if strings.HasPrefix(path, "/api/v3/") {
		return "/api/v2/" + strings.TrimPrefix(path, "/api/v3/")
	}
	return path
}

func isSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

// RequiredRole resolves the minimum role for a request under this policy.
func (c AuthzConfig) RequiredRole(method, path string) string {
	path = normalizeAuthzPath(path)
	for _, rule := range c.Rules {
		if rule.matches(method, path) {
			return rule.Role
		}
	}
	if isSafeMethod(method) {
		return c.ReadRole
	}
	return c.WriteRole
}

// Allows reports whether a principal holding role may perform the request.
func (c AuthzConfig) Allows(role, method, path string) bool {
	return RoleAtLeast(role, c.RequiredRole(method, path))
}

// prepare sorts rules so that the most specific prefix wins regardless of the
// order they were declared in, and fills in defaults.
func (c AuthzConfig) prepare() AuthzConfig {
	if c.ReadRole == "" {
		c.ReadRole = RoleViewer
	}
	if c.WriteRole == "" {
		c.WriteRole = RoleOperator
	}
	if c.PublicPrefixes == nil {
		c.PublicPrefixes = publicPrefixes
	}
	rules := make([]RouteRule, len(c.Rules))
	copy(rules, c.Rules)
	sort.SliceStable(rules, func(i, j int) bool {
		if len(rules[i].Prefix) != len(rules[j].Prefix) {
			return len(rules[i].Prefix) > len(rules[j].Prefix)
		}
		// For an identical prefix, a method-scoped rule is more specific than a
		// catch-all one.
		return len(rules[i].Methods) > 0 && len(rules[j].Methods) == 0
	})
	c.Rules = rules
	return c
}

// Authorize enforces the role policy. It must be chained inside Auth, which is
// what populates the X-Auth-Role header from the verified session cookie.
func Authorize(cfg AuthzConfig) func(http.Handler) http.Handler {
	policy := cfg.prepare()
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for _, p := range policy.PublicPrefixes {
				if r.URL.Path == p || strings.HasPrefix(r.URL.Path, p) {
					next.ServeHTTP(w, r)
					return
				}
			}
			role := r.Header.Get("X-Auth-Role")
			if policy.Allows(role, r.Method, r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}
			required := policy.RequiredRole(r.Method, r.URL.Path)
			if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/ws/") {
				http.Error(w, `{"error":"forbidden","required_role":"`+required+`"}`, http.StatusForbidden)
				return
			}
			http.Error(w, "forbidden: "+required+" role required", http.StatusForbidden)
		})
	}
}

// RequireRole wraps a single handler with a minimum-role check. Prefer adding a
// rule to AuthzConfig; this exists for handlers registered outside the main mux.
func RequireRole(role string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !RoleAtLeast(r.Header.Get("X-Auth-Role"), role) {
			http.Error(w, `{"error":"forbidden","required_role":"`+role+`"}`, http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
