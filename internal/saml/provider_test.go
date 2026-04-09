package saml

import (
	"encoding/xml"
	"testing"

	crewsaml "github.com/crewjam/saml"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/oidc"
)

func TestSanitizeRedirectURI(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "relative path", in: "/servers?tab=ssh#active", want: "/servers?tab=ssh#active"},
		{name: "root default", in: "  ?view=compact  ", want: "/?view=compact"},
		{name: "absolute url rejected", in: "https://evil.example.com/steal", want: ""},
		{name: "scheme-relative rejected", in: "//evil.example.com/steal", want: ""},
		{name: "path without slash rejected", in: "dashboard", want: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitizeRedirectURI(tc.in); got != tc.want {
				t.Fatalf("sanitizeRedirectURI(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestCollectAttributesSupportsCommonAliasesAndRoleMapping(t *testing.T) {
	assertion := &crewsaml.Assertion{
		Subject: &crewsaml.Subject{
			NameID: &crewsaml.NameID{Value: "alice@example.com"},
		},
		AttributeStatements: []crewsaml.AttributeStatement{{
			Attributes: []crewsaml.Attribute{
				{
					Name:   "http://schemas.microsoft.com/ws/2008/06/identity/claims/role",
					Values: []crewsaml.AttributeValue{{Value: "Operators"}},
				},
				{
					Name:   "urn:oid:0.9.2342.19200300.100.1.3",
					Values: []crewsaml.AttributeValue{{Value: "alice@example.com"}},
				},
				{
					Name:         "urn:oid:0.9.2342.19200300.100.1.1",
					FriendlyName: "uid",
					Values:       []crewsaml.AttributeValue{{Value: "alice"}},
				},
			},
		}},
	}

	attributes := collectAttributes(assertion)
	if got := firstAttributeValue(attributes, "groups"); got != "Operators" {
		t.Fatalf("groups alias = %q, want Operators", got)
	}
	if got := firstAttributeValue(attributes, "roles"); got != "Operators" {
		t.Fatalf("roles alias = %q, want Operators", got)
	}
	if got := firstAttributeValue(attributes, "email"); got != "alice@example.com" {
		t.Fatalf("email alias = %q, want alice@example.com", got)
	}
	if got := firstAttributeValue(attributes, "username"); got != "alice" {
		t.Fatalf("username alias = %q, want alice", got)
	}
	if got := firstAttributeValue(attributes, "sub"); got != "alice@example.com" {
		t.Fatalf("subject alias = %q, want alice@example.com", got)
	}

	provider := &Provider{
		roleMapper: &oidc.RoleMapping{
			Claim:    "groups",
			Mappings: map[string]string{"Operators": "operator"},
			Default:  "viewer",
		},
	}
	claims := attributesToClaims(attributes, subjectFromAssertion(assertion))
	if got := provider.roleMapper.MapRoles(claims); got != "operator" {
		t.Fatalf("MapRoles() = %q, want operator", got)
	}
}

func TestResolveUsernamePrefersConfiguredAttributeAndFallsBack(t *testing.T) {
	provider := &Provider{usernameAttribute: "uid"}

	attributes := map[string][]string{
		"uid":   {"alice"},
		"email": {"alice@example.com"},
	}
	if got := provider.resolveUsername(attributes, "subject@example.com"); got != "alice" {
		t.Fatalf("resolveUsername(configured) = %q, want alice", got)
	}

	provider.usernameAttribute = "employeeNumber"
	attributes = map[string][]string{
		"mail": {"alice@example.com"},
	}
	if got := provider.resolveUsername(attributes, "subject@example.com"); got != "alice@example.com" {
		t.Fatalf("resolveUsername(email fallback) = %q, want alice@example.com", got)
	}

	if got := provider.resolveUsername(nil, "subject@example.com"); got != "subject@example.com" {
		t.Fatalf("resolveUsername(subject fallback) = %q, want subject@example.com", got)
	}
}

func TestValidateTrackedRequestChecksInResponseTo(t *testing.T) {
	raw, err := xml.Marshal(crewsaml.Response{InResponseTo: "req-123"})
	if err != nil {
		t.Fatalf("xml.Marshal(response): %v", err)
	}

	if err := validateTrackedRequest(raw, "req-123"); err != nil {
		t.Fatalf("validateTrackedRequest(match) = %v", err)
	}
	if err := validateTrackedRequest(raw, "req-456"); err == nil {
		t.Fatal("validateTrackedRequest(mismatch) unexpectedly succeeded")
	}
}
