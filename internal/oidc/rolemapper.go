package oidc

// RoleMapping maps OIDC/IdP group claims to internal control-plane roles.
type RoleMapping struct {
	Claim    string            // JWT claim name (default: "groups")
	Mappings map[string]string // IdP group → internal role (e.g., "admins" → "admin")
	Default  string            // fallback role when no mapping matches
}

// MapRoles inspects the given JWT claims and returns the highest-privilege
// internal role that matches. Priority: admin > operator > viewer.
// If no mapping matches, the Default role is returned.
func (rm *RoleMapping) MapRoles(claims map[string]interface{}) string {
	claim := rm.Claim
	if claim == "" {
		claim = "groups"
	}

	groups := extractStringSlice(claims, claim)
	if len(groups) == 0 {
		// Try nested claim (e.g. realm_access.roles for Keycloak).
		if ra, ok := claims["realm_access"].(map[string]interface{}); ok {
			groups = extractStringSlice(ra, "roles")
		}
	}

	// Priority ordering: pick the highest-privilege match.
	rolePriority := map[string]int{
		"admin":    3,
		"operator": 2,
		"viewer":   1,
	}

	bestRole := rm.Default
	bestPri := rolePriority[bestRole]

	for _, g := range groups {
		mapped, ok := rm.Mappings[g]
		if !ok {
			continue
		}
		if pri := rolePriority[mapped]; pri > bestPri {
			bestRole = mapped
			bestPri = pri
		}
	}

	return bestRole
}
