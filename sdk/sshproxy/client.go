package sshproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const defaultUserAgent = "ssh-proxy-go-sdk/0.1"

// Config configures a control-plane SDK client.
type Config struct {
	BaseURL    string
	Token      string
	UserAgent  string
	HTTPClient *http.Client
}

// Client is a typed Go SDK client for the SSH Proxy control-plane API.
type Client struct {
	baseURL   string
	token     string
	userAgent string
	http      *http.Client
}

// APIError is returned when the control plane rejects a request.
type APIError struct {
	StatusCode int
	Message    string
	Body       string
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("sshproxy API error (HTTP %d): %s", e.StatusCode, e.Message)
	}
	if e.Body != "" {
		return fmt.Sprintf("sshproxy API error (HTTP %d): %s", e.StatusCode, e.Body)
	}
	return fmt.Sprintf("sshproxy API error (HTTP %d)", e.StatusCode)
}

type rawEnvelope struct {
	Success bool            `json:"success"`
	Data    json.RawMessage `json:"data"`
	Error   string          `json:"error"`
	Total   int             `json:"total"`
	Page    int             `json:"page"`
	PerPage int             `json:"per_page"`
}

// Page is a paginated API result.
type Page[T any] struct {
	Items   []T
	Total   int
	Page    int
	PerPage int
}

// User mirrors the public user API model.
type User struct {
	Username    string    `json:"username"`
	DisplayName string    `json:"display_name"`
	Email       string    `json:"email"`
	Role        string    `json:"role"`
	Enabled     bool      `json:"enabled"`
	MFAEnabled  bool      `json:"mfa_enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	LastLogin   time.Time `json:"last_login"`
	AllowedIPs  []string  `json:"allowed_ips,omitempty"`
}

// Session mirrors the public session API model.
type Session struct {
	ID            string    `json:"id"`
	Username      string    `json:"username"`
	SourceIP      string    `json:"source_ip"`
	TargetHost    string    `json:"target_host"`
	TargetPort    int       `json:"target_port"`
	StartTime     time.Time `json:"start_time"`
	Duration      string    `json:"duration"`
	BytesIn       int64     `json:"bytes_in"`
	BytesOut      int64     `json:"bytes_out"`
	Status        string    `json:"status"`
	RecordingFile string    `json:"recording_file,omitempty"`
}

// Server mirrors the public server API model.
type Server struct {
	ID          string            `json:"id"`
	Host        string            `json:"host"`
	Port        int               `json:"port"`
	Name        string            `json:"name"`
	Group       string            `json:"group"`
	Status      string            `json:"status"`
	Healthy     bool              `json:"healthy"`
	Maintenance bool              `json:"maintenance"`
	Weight      int               `json:"weight"`
	MaxSessions int               `json:"max_sessions"`
	Sessions    int               `json:"sessions"`
	Tags        map[string]string `json:"tags,omitempty"`
	CheckedAt   time.Time         `json:"checked_at"`
}

// RecordingMetadata describes a session recording file.
type RecordingMetadata struct {
	SessionID     string `json:"session_id"`
	RecordingFile string `json:"recording_file"`
}

// SignedCertificate is the result of a user certificate signing request.
type SignedCertificate struct {
	Certificate string `json:"certificate"`
	Serial      uint64 `json:"serial"`
	KeyID       string `json:"key_id"`
	ExpiresAt   string `json:"expires_at"`
}

// CreateUserRequest creates a control-plane user.
type CreateUserRequest struct {
	Username    string   `json:"username"`
	DisplayName string   `json:"display_name,omitempty"`
	Email       string   `json:"email,omitempty"`
	Role        string   `json:"role,omitempty"`
	Password    string   `json:"password"`
	AllowedIPs  []string `json:"allowed_ips,omitempty"`
}

// UpdateUserRequest updates mutable user fields.
type UpdateUserRequest struct {
	DisplayName *string  `json:"display_name,omitempty"`
	Email       *string  `json:"email,omitempty"`
	Role        *string  `json:"role,omitempty"`
	Enabled     *bool    `json:"enabled,omitempty"`
	AllowedIPs  []string `json:"allowed_ips,omitempty"`
}

// CreateServerRequest creates a managed upstream server.
type CreateServerRequest struct {
	Name        string            `json:"name"`
	Host        string            `json:"host"`
	Port        int               `json:"port"`
	Group       string            `json:"group,omitempty"`
	Weight      int               `json:"weight,omitempty"`
	MaxSessions int               `json:"max_sessions,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
}

// UpdateServerRequest updates a managed upstream server.
type UpdateServerRequest struct {
	Name        *string           `json:"name,omitempty"`
	Host        *string           `json:"host,omitempty"`
	Port        *int              `json:"port,omitempty"`
	Group       *string           `json:"group,omitempty"`
	Weight      *int              `json:"weight,omitempty"`
	MaxSessions *int              `json:"max_sessions,omitempty"`
	Maintenance *bool             `json:"maintenance,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
}

// SessionsFilter narrows session listing queries.
type SessionsFilter struct {
	Status  string
	User    string
	IP      string
	Page    int
	PerPage int
}

// SignUserCertificateRequest requests a short-lived SSH user certificate.
type SignUserCertificateRequest struct {
	PublicKey       string   `json:"public_key"`
	Principals      []string `json:"principals"`
	TTL             string   `json:"ttl,omitempty"`
	ForceCommand    string   `json:"force_command,omitempty"`
	SourceAddresses []string `json:"source_addresses,omitempty"`
}

// NewClient creates a new Go SDK client for the SSH Proxy control plane.
func NewClient(cfg Config) (*Client, error) {
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("base URL is required")
	}
	parsed, err := url.Parse(cfg.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse base URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("base URL must use http or https")
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("base URL must include a host")
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	userAgent := cfg.UserAgent
	if userAgent == "" {
		userAgent = defaultUserAgent
	}

	return &Client{
		baseURL:   strings.TrimRight(parsed.String(), "/"),
		token:     cfg.Token,
		userAgent: userAgent,
		http:      httpClient,
	}, nil
}

// ListUsers returns all control-plane users.
func (c *Client) ListUsers(ctx context.Context) (*Page[User], error) {
	var users []User
	env, err := c.doJSON(ctx, http.MethodGet, "/api/v2/users", nil, nil, &users)
	if err != nil {
		return nil, err
	}
	return &Page[User]{Items: users, Total: env.Total, Page: env.Page, PerPage: env.PerPage}, nil
}

// CreateUser creates a new user.
func (c *Client) CreateUser(ctx context.Context, req CreateUserRequest) (*User, error) {
	var user User
	if _, err := c.doJSON(ctx, http.MethodPost, "/api/v2/users", nil, req, &user); err != nil {
		return nil, err
	}
	return &user, nil
}

// GetUser fetches a user by username.
func (c *Client) GetUser(ctx context.Context, username string) (*User, error) {
	var user User
	if _, err := c.doJSON(ctx, http.MethodGet, "/api/v2/users/"+url.PathEscape(username), nil, nil, &user); err != nil {
		return nil, err
	}
	return &user, nil
}

// UpdateUser updates a user by username.
func (c *Client) UpdateUser(ctx context.Context, username string, req UpdateUserRequest) (*User, error) {
	var user User
	if _, err := c.doJSON(ctx, http.MethodPut, "/api/v2/users/"+url.PathEscape(username), nil, req, &user); err != nil {
		return nil, err
	}
	return &user, nil
}

// DeleteUser deletes a user by username.
func (c *Client) DeleteUser(ctx context.Context, username string) error {
	_, err := c.doJSON(ctx, http.MethodDelete, "/api/v2/users/"+url.PathEscape(username), nil, nil, nil)
	return err
}

// ListServers returns managed upstream servers.
func (c *Client) ListServers(ctx context.Context) (*Page[Server], error) {
	var servers []Server
	env, err := c.doJSON(ctx, http.MethodGet, "/api/v2/servers", nil, nil, &servers)
	if err != nil {
		return nil, err
	}
	return &Page[Server]{Items: servers, Total: env.Total, Page: env.Page, PerPage: env.PerPage}, nil
}

// CreateServer creates a managed upstream server.
func (c *Client) CreateServer(ctx context.Context, req CreateServerRequest) (*Server, error) {
	var server Server
	if _, err := c.doJSON(ctx, http.MethodPost, "/api/v2/servers", nil, req, &server); err != nil {
		return nil, err
	}
	return &server, nil
}

// UpdateServer updates a managed upstream server.
func (c *Client) UpdateServer(ctx context.Context, id string, req UpdateServerRequest) (*Server, error) {
	var server Server
	if _, err := c.doJSON(ctx, http.MethodPut, "/api/v2/servers/"+url.PathEscape(id), nil, req, &server); err != nil {
		return nil, err
	}
	return &server, nil
}

// DeleteServer deletes a managed upstream server.
func (c *Client) DeleteServer(ctx context.Context, id string) error {
	_, err := c.doJSON(ctx, http.MethodDelete, "/api/v2/servers/"+url.PathEscape(id), nil, nil, nil)
	return err
}

// ListSessions lists sessions using the provided filter.
func (c *Client) ListSessions(ctx context.Context, filter SessionsFilter) (*Page[Session], error) {
	query := url.Values{}
	if filter.Status != "" {
		query.Set("status", filter.Status)
	}
	if filter.User != "" {
		query.Set("user", filter.User)
	}
	if filter.IP != "" {
		query.Set("ip", filter.IP)
	}
	if filter.Page > 0 {
		query.Set("page", fmt.Sprintf("%d", filter.Page))
	}
	if filter.PerPage > 0 {
		query.Set("per_page", fmt.Sprintf("%d", filter.PerPage))
	}

	var sessions []Session
	env, err := c.doJSON(ctx, http.MethodGet, "/api/v2/sessions", query, nil, &sessions)
	if err != nil {
		return nil, err
	}
	return &Page[Session]{Items: sessions, Total: env.Total, Page: env.Page, PerPage: env.PerPage}, nil
}

// GetConfig fetches the current control-plane configuration.
func (c *Client) GetConfig(ctx context.Context) (map[string]interface{}, error) {
	var cfg map[string]interface{}
	if _, err := c.doJSON(ctx, http.MethodGet, "/api/v2/config", nil, nil, &cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// GetSessionRecording returns the recording metadata for a session.
func (c *Client) GetSessionRecording(ctx context.Context, id string) (*RecordingMetadata, error) {
	var metadata RecordingMetadata
	if _, err := c.doJSON(ctx, http.MethodGet, "/api/v2/sessions/"+url.PathEscape(id)+"/recording", nil, nil, &metadata); err != nil {
		return nil, err
	}
	return &metadata, nil
}

// SignUserCertificate signs a short-lived SSH user certificate.
func (c *Client) SignUserCertificate(ctx context.Context, req SignUserCertificateRequest) (*SignedCertificate, error) {
	var cert SignedCertificate
	if _, err := c.doJSON(ctx, http.MethodPost, "/api/v2/ca/sign-user", nil, req, &cert); err != nil {
		return nil, err
	}
	return &cert, nil
}

func (c *Client) doJSON(ctx context.Context, method, path string, query url.Values, body interface{}, out interface{}) (*rawEnvelope, error) {
	req, err := c.newRequest(ctx, method, path, query, body)
	if err != nil {
		return nil, err
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, req.URL.String(), err)
	}
	defer resp.Body.Close()

	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	var env rawEnvelope
	if err := json.Unmarshal(payload, &env); err != nil {
		return nil, &APIError{StatusCode: resp.StatusCode, Body: string(payload)}
	}

	if resp.StatusCode >= 400 || !env.Success {
		return nil, &APIError{StatusCode: resp.StatusCode, Message: env.Error, Body: string(payload)}
	}

	if out != nil && len(env.Data) > 0 && string(env.Data) != "null" {
		if err := json.Unmarshal(env.Data, out); err != nil {
			return nil, fmt.Errorf("decode response data: %w", err)
		}
	}

	return &env, nil
}

func (c *Client) newRequest(ctx context.Context, method, path string, query url.Values, body interface{}) (*http.Request, error) {
	endpoint, err := url.Parse(c.baseURL + path)
	if err != nil {
		return nil, fmt.Errorf("parse request URL: %w", err)
	}
	if len(query) > 0 {
		endpoint.RawQuery = query.Encode()
	}

	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request body: %w", err)
		}
		reader = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, endpoint.String(), reader)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	if c.token != "" {
		if strings.HasPrefix(c.token, "Bearer ") {
			req.Header.Set("Authorization", c.token)
		} else {
			req.Header.Set("Authorization", "Bearer "+c.token)
		}
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}
