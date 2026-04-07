package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// OIDCConfig holds the configuration needed to connect to an OIDC provider.
type OIDCConfig struct {
	Issuer       string   // OIDC Issuer URL (e.g., https://accounts.google.com)
	ClientID     string
	ClientSecret string
	RedirectURL  string   // e.g., https://proxy.example.com/auth/callback
	Scopes       []string // default: ["openid", "profile", "email"]
	RolesClaim   string   // JWT claim for roles mapping (default: "groups")
}

// Provider represents a discovered OIDC provider with cached JWKS keys.
type Provider struct {
	Issuer                string
	AuthorizationEndpoint string
	TokenEndpoint         string
	UserinfoEndpoint      string
	JwksURI               string
	EndSessionEndpoint    string

	config     *OIDCConfig
	keys       []JSONWebKey
	keysMu     sync.RWMutex
	keysExpiry time.Time
	httpClient *http.Client
	stopRefresh chan struct{}
}

// discoveryDoc is the subset of the OpenID Connect Discovery 1.0 document
// that we need.
type discoveryDoc struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JwksURI               string `json:"jwks_uri"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
}

// TokenResponse is the token endpoint response.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

// UserInfo is the userinfo endpoint response.
type UserInfo struct {
	Subject string `json:"sub"`
	Name    string `json:"name"`
	Email   string `json:"email"`
	Groups  []string
	Claims  map[string]interface{}
}

// NewProvider discovers the OIDC provider configuration from the
// .well-known/openid-configuration endpoint and fetches the JWKS keys.
func NewProvider(cfg *OIDCConfig) (*Provider, error) {
	if cfg.Issuer == "" {
		return nil, fmt.Errorf("oidc: issuer URL is required")
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "profile", "email"}
	}
	if cfg.RolesClaim == "" {
		cfg.RolesClaim = "groups"
	}

	p := &Provider{
		config:      cfg,
		httpClient:  &http.Client{Timeout: 10 * time.Second},
		stopRefresh: make(chan struct{}),
	}

	if err := p.discover(); err != nil {
		return nil, err
	}

	if err := p.refreshKeys(); err != nil {
		return nil, fmt.Errorf("oidc: initial JWKS fetch: %w", err)
	}

	// Start background key refresh (every hour).
	go p.keyRefreshLoop()

	return p, nil
}

// Close stops the background JWKS refresh goroutine.
func (p *Provider) Close() {
	close(p.stopRefresh)
}

// discover fetches and parses the .well-known/openid-configuration document.
func (p *Provider) discover() error {
	wellKnown := strings.TrimRight(p.config.Issuer, "/") + "/.well-known/openid-configuration"
	resp, err := p.httpClient.Get(wellKnown)
	if err != nil {
		return fmt.Errorf("oidc: discovery request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("oidc: discovery returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("oidc: read discovery: %w", err)
	}

	var doc discoveryDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("oidc: parse discovery: %w", err)
	}

	p.Issuer = doc.Issuer
	p.AuthorizationEndpoint = doc.AuthorizationEndpoint
	p.TokenEndpoint = doc.TokenEndpoint
	p.UserinfoEndpoint = doc.UserinfoEndpoint
	p.JwksURI = doc.JwksURI
	p.EndSessionEndpoint = doc.EndSessionEndpoint

	if p.AuthorizationEndpoint == "" || p.TokenEndpoint == "" || p.JwksURI == "" {
		return fmt.Errorf("oidc: discovery document missing required endpoints")
	}

	return nil
}

// AuthURL builds the authorization URL for redirecting the user to the IdP.
// It includes PKCE parameters (code_challenge, code_challenge_method).
func (p *Provider) AuthURL(state, codeChallenge string) string {
	scopes := strings.Join(p.config.Scopes, " ")
	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {p.config.ClientID},
		"redirect_uri":          {p.config.RedirectURL},
		"scope":                 {scopes},
		"state":                 {state},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	}
	return p.AuthorizationEndpoint + "?" + params.Encode()
}

// Exchange trades an authorization code for tokens using the token endpoint.
// The PKCE code verifier is included for public-client flows.
func (p *Provider) Exchange(ctx context.Context, code, verifier string) (*TokenResponse, error) {
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {p.config.RedirectURL},
		"client_id":     {p.config.ClientID},
		"code_verifier": {verifier},
	}
	if p.config.ClientSecret != "" {
		data.Set("client_secret", p.config.ClientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.TokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("oidc: build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc: token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("oidc: read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc: token endpoint returned %d: %s", resp.StatusCode, body)
	}

	var tok TokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, fmt.Errorf("oidc: parse token response: %w", err)
	}
	return &tok, nil
}

// VerifyIDToken validates the signature and standard claims of an ID token.
func (p *Provider) VerifyIDToken(ctx context.Context, rawToken string) (*IDToken, error) {
	p.keysMu.RLock()
	keys := p.keys
	p.keysMu.RUnlock()

	if err := VerifySignature(rawToken, keys); err != nil {
		// Try refreshing keys once in case the IdP rotated them.
		if refreshErr := p.refreshKeys(); refreshErr == nil {
			p.keysMu.RLock()
			keys = p.keys
			p.keysMu.RUnlock()
			if err2 := VerifySignature(rawToken, keys); err2 != nil {
				return nil, err2
			}
		} else {
			return nil, err
		}
	}

	tok, err := DecodeIDToken(rawToken)
	if err != nil {
		return nil, err
	}

	if err := ValidateClaims(tok, p.Issuer, p.config.ClientID); err != nil {
		return nil, err
	}

	return tok, nil
}

// Userinfo fetches the user info from the OIDC userinfo endpoint.
func (p *Provider) Userinfo(ctx context.Context, accessToken string) (*UserInfo, error) {
	if p.UserinfoEndpoint == "" {
		return nil, fmt.Errorf("oidc: userinfo endpoint not available")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.UserinfoEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("oidc: build userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc: userinfo request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("oidc: read userinfo response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc: userinfo endpoint returned %d: %s", resp.StatusCode, body)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(body, &claims); err != nil {
		return nil, fmt.Errorf("oidc: parse userinfo: %w", err)
	}

	info := &UserInfo{Claims: claims}
	info.Subject, _ = claims["sub"].(string)
	info.Name, _ = claims["name"].(string)
	info.Email, _ = claims["email"].(string)
	info.Groups = extractStringSlice(claims, p.config.RolesClaim)

	return info, nil
}

// refreshKeys fetches the JWKS from the provider's jwks_uri.
func (p *Provider) refreshKeys() error {
	resp, err := p.httpClient.Get(p.JwksURI)
	if err != nil {
		return fmt.Errorf("oidc: JWKS fetch: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("oidc: read JWKS: %w", err)
	}

	var jwks struct {
		Keys []JSONWebKey `json:"keys"`
	}
	if err := json.Unmarshal(body, &jwks); err != nil {
		return fmt.Errorf("oidc: parse JWKS: %w", err)
	}

	p.keysMu.Lock()
	p.keys = jwks.Keys
	p.keysExpiry = time.Now().Add(1 * time.Hour)
	p.keysMu.Unlock()

	return nil
}

// keyRefreshLoop periodically refreshes the JWKS keys.
func (p *Provider) keyRefreshLoop() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := p.refreshKeys(); err != nil {
				// Log and continue; existing keys remain valid.
				fmt.Printf("oidc: background JWKS refresh failed: %v\n", err)
			}
		case <-p.stopRefresh:
			return
		}
	}
}

// Keys returns the current cached JWKS keys (for testing).
func (p *Provider) Keys() []JSONWebKey {
	p.keysMu.RLock()
	defer p.keysMu.RUnlock()
	return p.keys
}

// SetKeys replaces the cached JWKS keys (for testing).
func (p *Provider) SetKeys(keys []JSONWebKey) {
	p.keysMu.Lock()
	defer p.keysMu.Unlock()
	p.keys = keys
}
