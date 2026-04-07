// Package dataplane provides an HTTP client that talks to the C data-plane
// admin API.  All methods use standard net/http with proper timeouts and
// Bearer-token authentication.
package dataplane

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/models"
)

// Client communicates with the C data-plane admin API.
type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

// New creates a Client for the data-plane at baseURL.  The token is sent as a
// Bearer authorisation header on every request.
func New(baseURL, token string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		http: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// GetHealth returns the data-plane health status.
func (c *Client) GetHealth() (*models.HealthStatus, error) {
	var hs models.HealthStatus
	if err := c.getJSON("/health", &hs); err != nil {
		return nil, fmt.Errorf("dataplane: get health: %w", err)
	}
	return &hs, nil
}

// ListSessions returns all active proxy sessions.
func (c *Client) ListSessions() ([]models.Session, error) {
	var ss []models.Session
	if err := c.getJSON("/sessions", &ss); err != nil {
		return nil, fmt.Errorf("dataplane: list sessions: %w", err)
	}
	return ss, nil
}

// KillSession terminates the session identified by id.
func (c *Client) KillSession(id string) error {
	req, err := c.newRequest(http.MethodDelete, "/sessions/"+id, nil)
	if err != nil {
		return fmt.Errorf("dataplane: kill session: %w", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("dataplane: kill session: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("dataplane: kill session %s: status %d", id, resp.StatusCode)
	}
	return nil
}

// GetMetrics returns the raw Prometheus-style metrics text from the data plane.
func (c *Client) GetMetrics() (string, error) {
	req, err := c.newRequest(http.MethodGet, "/metrics", nil)
	if err != nil {
		return "", fmt.Errorf("dataplane: get metrics: %w", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("dataplane: get metrics: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("dataplane: read metrics body: %w", err)
	}
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("dataplane: get metrics: status %d", resp.StatusCode)
	}
	return string(body), nil
}

// ListUpstreams returns all configured upstream servers.
func (c *Client) ListUpstreams() ([]models.Server, error) {
	var ss []models.Server
	if err := c.getJSON("/upstreams", &ss); err != nil {
		return nil, fmt.Errorf("dataplane: list upstreams: %w", err)
	}
	return ss, nil
}

// ReloadConfig asks the data plane to reload its configuration.
func (c *Client) ReloadConfig() error {
	req, err := c.newRequest(http.MethodPost, "/config/reload", nil)
	if err != nil {
		return fmt.Errorf("dataplane: reload config: %w", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("dataplane: reload config: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("dataplane: reload config: status %d", resp.StatusCode)
	}
	return nil
}

// GetConfig retrieves the running configuration from the data plane.
func (c *Client) GetConfig() (map[string]interface{}, error) {
	var result map[string]interface{}
	if err := c.getJSON("/config", &result); err != nil {
		return nil, fmt.Errorf("dataplane: get config: %w", err)
	}
	return result, nil
}

// newRequest builds an *http.Request with the auth header set.
func (c *Client) newRequest(method, path string, body io.Reader) (*http.Request, error) {
	url := c.baseURL + path
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	return req, nil
}

// getJSON is a convenience helper that GETs path and JSON-decodes the response
// into dst.
func (c *Client) getJSON(path string, dst interface{}) error {
	req, err := c.newRequest(http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected status %d for %s", resp.StatusCode, path)
	}
	return json.NewDecoder(resp.Body).Decode(dst)
}
