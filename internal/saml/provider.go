package saml

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	crewsaml "github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/oidc"
)

const (
	LoginPath    = "/auth/saml/login"
	ACSPath      = "/auth/saml/acs"
	MetadataPath = "/auth/saml/metadata"

	defaultRedirectURI = "/dashboard"
)

// Config describes the SAML service-provider settings for web SSO.
type Config struct {
	RootURL            string
	EntityID           string
	IDPMetadataURL     string
	IDPMetadataFile    string
	CertFile           string
	KeyFile            string
	UsernameAttribute  string
	RolesAttribute     string
	RoleMappings       map[string]string
	AllowIDPInitiated  bool
	DefaultRedirectURI string
}

// LoginResult contains the authenticated principal derived from a SAML assertion.
type LoginResult struct {
	Username    string
	Subject     string
	Role        string
	RedirectURI string
	Attributes  map[string][]string
	Claims      map[string]interface{}
}

// Provider validates SAML assertions and drives SP-initiated and IdP-initiated logins.
type Provider struct {
	serviceProvider    crewsaml.ServiceProvider
	requestTracker     samlsp.CookieRequestTracker
	roleMapper         *oidc.RoleMapping
	usernameAttribute  string
	defaultRedirectURI string
}

// NewProvider initializes a SAML service provider from IdP metadata and an SP key pair.
func NewProvider(cfg *Config) (*Provider, error) {
	if cfg == nil {
		return nil, fmt.Errorf("saml: config is required")
	}

	baseURL, err := parsePublicBaseURL(cfg.RootURL)
	if err != nil {
		return nil, err
	}

	idpMetadata, err := loadIDPMetadata(context.Background(), cfg)
	if err != nil {
		return nil, err
	}

	signer, certificate, err := loadSPKeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, err
	}

	defaultRedirect := sanitizeRedirectURI(cfg.DefaultRedirectURI)
	if defaultRedirect == "" {
		defaultRedirect = defaultRedirectURI
	}

	metadataURL := buildRouteURL(baseURL, MetadataPath)
	acsURL := buildRouteURL(baseURL, ACSPath)
	sloURL := buildRouteURL(baseURL, "/auth/saml/logout")
	entityID := strings.TrimSpace(cfg.EntityID)
	if entityID == "" {
		entityID = metadataURL.String()
	}

	sp := crewsaml.ServiceProvider{
		EntityID:           entityID,
		Key:                signer,
		Certificate:        certificate,
		HTTPClient:         &http.Client{Timeout: 10 * time.Second},
		MetadataURL:        *metadataURL,
		AcsURL:             *acsURL,
		SloURL:             *sloURL,
		IDPMetadata:        idpMetadata,
		AuthnNameIDFormat:  crewsaml.UnspecifiedNameIDFormat,
		AllowIDPInitiated:  cfg.AllowIDPInitiated,
		DefaultRedirectURI: defaultRedirect,
		SignatureMethod:    signatureMethodForKey(signer),
	}

	tracker := samlsp.DefaultRequestTracker(samlsp.Options{
		URL:                *baseURL,
		Key:                signer,
		Certificate:        certificate,
		AllowIDPInitiated:  cfg.AllowIDPInitiated,
		DefaultRedirectURI: defaultRedirect,
		CookieSameSite:     http.SameSiteNoneMode,
	}, &sp)

	rolesAttribute := strings.TrimSpace(cfg.RolesAttribute)
	if rolesAttribute == "" {
		rolesAttribute = "groups"
	}

	return &Provider{
		serviceProvider: sp,
		requestTracker:  tracker,
		roleMapper: &oidc.RoleMapping{
			Claim:    rolesAttribute,
			Mappings: cfg.RoleMappings,
			Default:  "viewer",
		},
		usernameAttribute:  strings.TrimSpace(cfg.UsernameAttribute),
		defaultRedirectURI: defaultRedirect,
	}, nil
}

// Metadata returns the generated SP metadata XML to register with the IdP.
func (p *Provider) Metadata() ([]byte, error) {
	buf, err := xml.MarshalIndent(p.serviceProvider.Metadata(), "", "  ")
	if err != nil {
		return nil, fmt.Errorf("saml: marshal metadata: %w", err)
	}
	return buf, nil
}

// ServeMetadata writes the generated SP metadata XML.
func (p *Provider) ServeMetadata(w http.ResponseWriter, _ *http.Request) {
	buf, err := p.Metadata()
	if err != nil {
		http.Error(w, "failed to render SAML metadata", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	if _, err := w.Write(buf); err != nil {
		http.Error(w, "failed to write SAML metadata", http.StatusInternalServerError)
	}
}

// StartAuthFlow initiates SP-initiated login and redirects the browser to the IdP.
func (p *Provider) StartAuthFlow(w http.ResponseWriter, r *http.Request, returnTo string) error {
	binding := crewsaml.HTTPRedirectBinding
	bindingLocation := p.serviceProvider.GetSSOBindingLocation(binding)
	if bindingLocation == "" {
		binding = crewsaml.HTTPPostBinding
		bindingLocation = p.serviceProvider.GetSSOBindingLocation(binding)
	}
	if bindingLocation == "" {
		return fmt.Errorf("saml: idp metadata does not expose an HTTP-Redirect or HTTP-POST SSO binding")
	}

	authReq, err := p.serviceProvider.MakeAuthenticationRequest(bindingLocation, binding, crewsaml.HTTPPostBinding)
	if err != nil {
		return fmt.Errorf("saml: build authn request: %w", err)
	}

	redirectURI := sanitizeRedirectURI(returnTo)
	if redirectURI == "" {
		redirectURI = p.defaultRedirectURI
	}

	trackedRequest := cloneRequestForRedirect(r, redirectURI)
	relayState, err := p.requestTracker.TrackRequest(w, trackedRequest, authReq.ID)
	if err != nil {
		return fmt.Errorf("saml: track request: %w", err)
	}

	switch binding {
	case crewsaml.HTTPRedirectBinding:
		redirectURL, err := authReq.Redirect(relayState, &p.serviceProvider)
		if err != nil {
			return fmt.Errorf("saml: sign redirect request: %w", err)
		}
		http.Redirect(w, r, redirectURL.String(), http.StatusFound)
		return nil
	case crewsaml.HTTPPostBinding:
		w.Header().Set("Content-Security-Policy", "default-src; script-src 'sha256-AjPdJSbZmeWHnEc5ykvJFay8FTWeTeRbs9dutfZ0HqE='; reflected-xss block; referrer no-referrer;")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, err := w.Write([]byte("<!DOCTYPE html><html><body>" + string(authReq.Post(relayState)) + "</body></html>"))
		if err != nil {
			return fmt.Errorf("saml: write post binding form: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("saml: unsupported SSO binding %q", binding)
	}
}

// ParseResponse validates the ACS POST and returns the derived login identity.
func (p *Provider) ParseResponse(w http.ResponseWriter, r *http.Request) (*LoginResult, error) {
	if err := r.ParseForm(); err != nil {
		return nil, fmt.Errorf("saml: parse form: %w", err)
	}

	relayState := r.Form.Get("RelayState")
	trackedRequest, trackedErr := p.lookupTrackedRequest(r, relayState)
	if trackedErr != nil {
		return nil, trackedErr
	}

	possibleRequestIDs := p.possibleRequestIDs(r)
	assertion, err := p.serviceProvider.ParseResponse(r, possibleRequestIDs)
	if err != nil {
		return nil, err
	}

	if trackedRequest != nil {
		rawResponse, decodeErr := decodeRawResponse(r)
		if decodeErr != nil {
			return nil, decodeErr
		}
		if err := validateTrackedRequest(rawResponse, trackedRequest.SAMLRequestID); err != nil {
			return nil, err
		}
		if err := p.requestTracker.StopTrackingRequest(w, r, relayState); err != nil {
			return nil, fmt.Errorf("saml: stop tracking request: %w", err)
		}
	}

	attributes := collectAttributes(assertion)
	subject := subjectFromAssertion(assertion)
	claims := attributesToClaims(attributes, subject)
	username := p.resolveUsername(attributes, subject)
	if username == "" {
		return nil, fmt.Errorf("saml: assertion did not contain a usable principal")
	}

	role := "viewer"
	if p.roleMapper != nil {
		role = p.roleMapper.MapRoles(claims)
	}

	redirectURI := p.defaultRedirectURI
	if trackedRequest != nil {
		if safe := sanitizeRedirectURI(trackedRequest.URI); safe != "" {
			redirectURI = safe
		}
	} else if safe := sanitizeRedirectURI(relayState); safe != "" {
		redirectURI = safe
	}

	return &LoginResult{
		Username:    username,
		Subject:     subject,
		Role:        role,
		RedirectURI: redirectURI,
		Attributes:  attributes,
		Claims:      claims,
	}, nil
}

// Authenticate validates the ACS POST and returns the derived identity plus redirect target.
func (p *Provider) Authenticate(w http.ResponseWriter, r *http.Request) (*LoginResult, string, error) {
	result, err := p.ParseResponse(w, r)
	if err != nil {
		return nil, "", err
	}
	return result, result.RedirectURI, nil
}

func (p *Provider) possibleRequestIDs(r *http.Request) []string {
	trackedRequests := p.requestTracker.GetTrackedRequests(r)
	ids := make([]string, 0, len(trackedRequests))
	for _, trackedRequest := range trackedRequests {
		if trackedRequest.SAMLRequestID == "" {
			continue
		}
		ids = append(ids, trackedRequest.SAMLRequestID)
	}
	return ids
}

func (p *Provider) lookupTrackedRequest(r *http.Request, relayState string) (*samlsp.TrackedRequest, error) {
	if relayState == "" {
		return nil, nil
	}
	trackedRequest, err := p.requestTracker.GetTrackedRequest(r, relayState)
	if err == http.ErrNoCookie {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("saml: load tracked request: %w", err)
	}
	return trackedRequest, nil
}

func (p *Provider) resolveUsername(attributes map[string][]string, subject string) string {
	candidates := []string{}
	if p.usernameAttribute != "" {
		candidates = append(candidates, p.usernameAttribute)
	}
	candidates = append(candidates,
		"email",
		"mail",
		"emailaddress",
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
		"urn:oid:0.9.2342.19200300.100.1.3",
		"upn",
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn",
		"username",
		"uid",
		"urn:oid:0.9.2342.19200300.100.1.1",
		"name",
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
	)
	for _, candidate := range candidates {
		if value := firstAttributeValue(attributes, candidate); value != "" {
			return value
		}
	}
	return subject
}

func loadIDPMetadata(ctx context.Context, cfg *Config) (*crewsaml.EntityDescriptor, error) {
	urlConfigured := strings.TrimSpace(cfg.IDPMetadataURL) != ""
	fileConfigured := strings.TrimSpace(cfg.IDPMetadataFile) != ""
	if !urlConfigured && !fileConfigured {
		return nil, fmt.Errorf("saml: either idp metadata url or file is required")
	}
	if urlConfigured && fileConfigured {
		return nil, fmt.Errorf("saml: idp metadata url and file are mutually exclusive")
	}

	var (
		metadata *crewsaml.EntityDescriptor
		err      error
	)
	if urlConfigured {
		metadataURL, parseErr := url.Parse(strings.TrimSpace(cfg.IDPMetadataURL))
		if parseErr != nil {
			return nil, fmt.Errorf("saml: parse idp metadata url: %w", parseErr)
		}
		metadata, err = samlsp.FetchMetadata(ctx, &http.Client{Timeout: 10 * time.Second}, *metadataURL)
		if err != nil {
			return nil, fmt.Errorf("saml: fetch idp metadata: %w", err)
		}
	} else {
		data, readErr := os.ReadFile(strings.TrimSpace(cfg.IDPMetadataFile))
		if readErr != nil {
			return nil, fmt.Errorf("saml: read idp metadata file: %w", readErr)
		}
		metadata, err = samlsp.ParseMetadata(data)
		if err != nil {
			return nil, fmt.Errorf("saml: parse idp metadata file: %w", err)
		}
	}

	if metadata == nil {
		return nil, fmt.Errorf("saml: idp metadata is empty")
	}
	if metadata.EntityID == "" {
		return nil, fmt.Errorf("saml: idp metadata missing entityID")
	}
	if !metadata.ValidUntil.IsZero() && time.Now().After(metadata.ValidUntil) {
		return nil, fmt.Errorf("saml: idp metadata expired at %s", metadata.ValidUntil.Format(time.RFC3339))
	}
	if len(metadata.IDPSSODescriptors) == 0 {
		return nil, fmt.Errorf("saml: idp metadata missing IDPSSODescriptor")
	}
	if !hasSupportedSSOBinding(metadata) {
		return nil, fmt.Errorf("saml: idp metadata missing HTTP-Redirect or HTTP-POST SSO endpoint")
	}
	return metadata, nil
}

func hasSupportedSSOBinding(metadata *crewsaml.EntityDescriptor) bool {
	for _, descriptor := range metadata.IDPSSODescriptors {
		for _, endpoint := range descriptor.SingleSignOnServices {
			if endpoint.Binding == crewsaml.HTTPRedirectBinding || endpoint.Binding == crewsaml.HTTPPostBinding {
				return true
			}
		}
	}
	return false
}

func loadSPKeyPair(certPath, keyPath string) (crypto.Signer, *x509.Certificate, error) {
	keyPair, err := tls.LoadX509KeyPair(strings.TrimSpace(certPath), strings.TrimSpace(keyPath))
	if err != nil {
		return nil, nil, fmt.Errorf("saml: load sp key pair: %w", err)
	}

	leaf := keyPair.Leaf
	if leaf == nil {
		leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
		if err != nil {
			return nil, nil, fmt.Errorf("saml: parse sp certificate: %w", err)
		}
	}

	signer, ok := keyPair.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, nil, fmt.Errorf("saml: private key must implement crypto.Signer")
	}
	if _, ok := signer.(*rsa.PrivateKey); !ok {
		if _, ok := signer.(*ecdsa.PrivateKey); !ok {
			return nil, nil, fmt.Errorf("saml: unsupported private key type %T", signer)
		}
	}

	return signer, leaf, nil
}

func parsePublicBaseURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("saml: parse base url: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("saml: base url must include scheme and host")
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed, nil
}

func buildRouteURL(base *url.URL, routePath string) *url.URL {
	built := *base
	built.Path = joinURLPath(base.Path, routePath)
	built.RawPath = ""
	built.RawQuery = ""
	built.Fragment = ""
	return &built
}

func joinURLPath(basePath, routePath string) string {
	basePath = strings.TrimSuffix(basePath, "/")
	routePath = strings.TrimPrefix(routePath, "/")
	if basePath == "" {
		return "/" + routePath
	}
	return basePath + "/" + routePath
}

func cloneRequestForRedirect(r *http.Request, redirectURI string) *http.Request {
	clone := r.Clone(r.Context())
	parsed, _ := url.Parse(redirectURI)
	clone.URL = parsed
	return clone
}

func decodeRawResponse(r *http.Request) ([]byte, error) {
	encoded := strings.TrimSpace(r.Form.Get("SAMLResponse"))
	if encoded == "" {
		return nil, fmt.Errorf("saml: missing SAMLResponse")
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("saml: decode SAMLResponse: %w", err)
	}
	return decoded, nil
}

func validateTrackedRequest(rawResponse []byte, expectedRequestID string) error {
	var response crewsaml.Response
	if err := xml.Unmarshal(rawResponse, &response); err != nil {
		return fmt.Errorf("saml: parse response correlation data: %w", err)
	}

	matched := false
	if response.InResponseTo != "" {
		if response.InResponseTo != expectedRequestID {
			return fmt.Errorf("saml: response InResponseTo mismatch")
		}
		matched = true
	}

	if response.Assertion != nil && response.Assertion.Subject != nil {
		for _, confirmation := range response.Assertion.Subject.SubjectConfirmations {
			if confirmation.SubjectConfirmationData == nil || confirmation.SubjectConfirmationData.InResponseTo == "" {
				continue
			}
			if confirmation.SubjectConfirmationData.InResponseTo != expectedRequestID {
				return fmt.Errorf("saml: assertion InResponseTo mismatch")
			}
			matched = true
		}
	}

	if !matched && response.EncryptedAssertion == nil {
		return fmt.Errorf("saml: tracked response missing InResponseTo")
	}
	return nil
}

func collectAttributes(assertion *crewsaml.Assertion) map[string][]string {
	attributes := make(map[string][]string)
	if assertion == nil {
		return attributes
	}

	for _, statement := range assertion.AttributeStatements {
		for _, attribute := range statement.Attributes {
			values := make([]string, 0, len(attribute.Values))
			for _, value := range attribute.Values {
				trimmed := strings.TrimSpace(value.Value)
				if trimmed == "" {
					continue
				}
				values = append(values, trimmed)
			}
			if len(values) == 0 {
				continue
			}
			appendAttributeValues(attributes, attribute.Name, values)
			appendAttributeValues(attributes, attribute.FriendlyName, values)
			for _, alias := range attributeAliases(attribute.Name, attribute.FriendlyName) {
				appendAttributeValues(attributes, alias, values)
			}
		}
	}

	subject := subjectFromAssertion(assertion)
	if subject != "" {
		appendAttributeValues(attributes, "nameid", []string{subject})
		appendAttributeValues(attributes, "subject", []string{subject})
		appendAttributeValues(attributes, "sub", []string{subject})
	}

	return attributes
}

func attributeAliases(name, friendlyName string) []string {
	aliases := []string{}
	for _, candidate := range []string{name, friendlyName} {
		switch normalizeAttributeKey(candidate) {
		case "groups", "group", "memberof", "member_of", "roles", "role", "edupersonaffiliation", "urn:oid:1.3.6.1.4.1.5923.1.1.1.1", "http://schemas.microsoft.com/ws/2008/06/identity/claims/role", "http://schemas.xmlsoap.org/claims/group":
			aliases = append(aliases, "groups", "roles")
		case "email", "mail", "emailaddress", "useremail", "urn:oid:0.9.2342.19200300.100.1.3", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress":
			aliases = append(aliases, "email")
		case "upn", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn":
			aliases = append(aliases, "upn")
		case "uid", "urn:oid:0.9.2342.19200300.100.1.1", "username":
			aliases = append(aliases, "username")
		case "name", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name":
			aliases = append(aliases, "name")
		}
	}
	return aliases
}

func normalizeAttributeKey(value string) string {
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, "-", "")
	return strings.ToLower(value)
}

func appendAttributeValues(target map[string][]string, key string, values []string) {
	key = strings.TrimSpace(key)
	if key == "" || len(values) == 0 {
		return
	}
	seen := make(map[string]struct{}, len(target[key]))
	for _, existing := range target[key] {
		seen[existing] = struct{}{}
	}
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		target[key] = append(target[key], value)
		seen[value] = struct{}{}
	}
}

func attributesToClaims(attributes map[string][]string, subject string) map[string]interface{} {
	claims := make(map[string]interface{}, len(attributes)+3)
	for key, values := range attributes {
		switch len(values) {
		case 0:
			continue
		case 1:
			claims[key] = values[0]
		default:
			claimValues := make([]interface{}, 0, len(values))
			for _, value := range values {
				claimValues = append(claimValues, value)
			}
			claims[key] = claimValues
		}
	}
	if subject != "" {
		claims["sub"] = subject
		claims["nameid"] = subject
		claims["subject"] = subject
	}
	return claims
}

func subjectFromAssertion(assertion *crewsaml.Assertion) string {
	if assertion == nil || assertion.Subject == nil || assertion.Subject.NameID == nil {
		return ""
	}
	return strings.TrimSpace(assertion.Subject.NameID.Value)
}

func firstAttributeValue(attributes map[string][]string, key string) string {
	for name, values := range attributes {
		if !strings.EqualFold(name, key) || len(values) == 0 {
			continue
		}
		return strings.TrimSpace(values[0])
	}
	return ""
}

func sanitizeRedirectURI(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "//") {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.IsAbs() {
		return ""
	}
	if parsed.Path == "" {
		parsed.Path = "/"
	}
	if !strings.HasPrefix(parsed.Path, "/") {
		return ""
	}
	return (&url.URL{Path: parsed.Path, RawQuery: parsed.RawQuery, Fragment: parsed.Fragment}).String()
}

func signatureMethodForKey(key crypto.Signer) string {
	switch key.(type) {
	case *rsa.PrivateKey:
		return dsig.RSASHA256SignatureMethod
	case *ecdsa.PrivateKey:
		return dsig.ECDSASHA256SignatureMethod
	default:
		panic(fmt.Sprintf("unsupported saml signing key type %T", key))
	}
}
