package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ClientConfig holds the configuration loaded from file or environment.
type ClientConfig struct {
	Server                   string `json:"server"`
	Token                    string `json:"token"`
	SessionCookie            string `json:"session_cookie"`
	SSHAddr                  string `json:"ssh_addr"`
	IdentityFile             string `json:"identity_file"`
	Insecure                 bool   `json:"insecure"`
	PinnedServerPubKeySHA256 string `json:"pinned_server_pubkey_sha256"`
}

// Client is the HTTP API client for the SSH Proxy control plane.
type Client struct {
	baseURL       string
	token         string
	sessionCookie string
	csrfToken     string
	http          *http.Client
}

// NewClient creates a Client by reading configuration from
// ~/.sshproxy/config.json and/or environment variables. Env vars take
// precedence over the config file.
func NewClient() *Client {
	cfg := loadConfig()

	return &Client{
		baseURL:       cfg.Server,
		token:         cfg.Token,
		sessionCookie: cfg.SessionCookie,
		http: &http.Client{
			Timeout:   30 * time.Second,
			Transport: buildHTTPTransport(cfg),
		},
	}
}

// NewClientFromConfig creates a Client from an explicit ClientConfig (useful
// for testing).
func NewClientFromConfig(cfg ClientConfig) *Client {
	return &Client{
		baseURL:       cfg.Server,
		token:         cfg.Token,
		sessionCookie: cfg.SessionCookie,
		http: &http.Client{
			Timeout:   30 * time.Second,
			Transport: buildHTTPTransport(cfg),
		},
	}
}

func loadConfig() ClientConfig {
	var cfg ClientConfig

	// Try to read config file
	cfgPath, err := configFilePath()
	if err == nil {
		data, err := os.ReadFile(cfgPath)
		if err == nil {
			_ = json.Unmarshal(data, &cfg)
		}
	}

	// Environment variables override file values
	if env := os.Getenv("SSHPROXY_SERVER"); env != "" {
		cfg.Server = env
	}
	if env := os.Getenv("SSHPROXY_TOKEN"); env != "" {
		cfg.Token = env
	}
	if env := os.Getenv("SSHPROXY_SSH_ADDR"); env != "" {
		cfg.SSHAddr = env
	}
	if env := os.Getenv("SSHPROXY_IDENTITY_FILE"); env != "" {
		cfg.IdentityFile = env
	}
	if env := os.Getenv("SSHPROXY_PINNED_SERVER_PUBKEY_SHA256"); env != "" {
		cfg.PinnedServerPubKeySHA256 = env
	}

	return cfg
}

func buildHTTPTransport(cfg ClientConfig) *http.Transport {
	transport := &http.Transport{}
	if cfg.Insecure || cfg.PinnedServerPubKeySHA256 != "" {
		tlsCfg := &tls.Config{
			InsecureSkipVerify: cfg.Insecure, // #nosec G402 -- explicit user opt-in for self-signed endpoints and/or pin validation.
		}
		if cfg.PinnedServerPubKeySHA256 != "" {
			pin := normalizePinnedPubKey(cfg.PinnedServerPubKeySHA256)
			tlsCfg.VerifyConnection = func(cs tls.ConnectionState) error {
				return verifyPinnedServerPubKey(pin, cs)
			}
		}
		transport.TLSClientConfig = tlsCfg
	}
	return transport
}

func normalizePinnedPubKey(pin string) string {
	pin = strings.TrimSpace(pin)
	if pin == "" {
		return ""
	}
	if strings.HasPrefix(pin, "sha256/") {
		return pin
	}
	return "sha256/" + pin
}

func verifyPinnedServerPubKey(expectedPin string, cs tls.ConnectionState) error {
	if expectedPin == "" {
		return nil
	}
	if len(cs.PeerCertificates) == 0 {
		return fmt.Errorf("tls pin verification failed: no peer certificate")
	}

	gotPin, err := publicKeyPin(cs.PeerCertificates[0])
	if err != nil {
		return err
	}
	if gotPin != expectedPin {
		return fmt.Errorf("tls pin verification failed: got %s want %s", gotPin, expectedPin)
	}
	return nil
}

func publicKeyPin(cert *x509.Certificate) (string, error) {
	if cert == nil {
		return "", fmt.Errorf("tls pin verification failed: nil certificate")
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return "sha256/" + base64.StdEncoding.EncodeToString(sum[:]), nil
}

func configFilePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	return filepath.Join(home, ".sshproxy", "config.json"), nil
}

func saveConfig(cfg ClientConfig) error {
	cfgPath, err := configFilePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o700); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if err := os.WriteFile(cfgPath, data, 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}

// Get performs an HTTP GET request and returns the response body.
func (c *Client) Get(path string) ([]byte, error) {
	return c.do("GET", path, nil)
}

// Post performs an HTTP POST request with a JSON body.
func (c *Client) Post(path string, body interface{}) ([]byte, error) {
	return c.do("POST", path, body)
}

// Put performs an HTTP PUT request with a JSON body.
func (c *Client) Put(path string, body interface{}) ([]byte, error) {
	return c.do("PUT", path, body)
}

// Delete performs an HTTP DELETE request.
func (c *Client) Delete(path string) ([]byte, error) {
	return c.do("DELETE", path, nil)
}

type RawResponse struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

// GetRaw performs an HTTP GET request and returns the full response body.
func (c *Client) GetRaw(path string) (*RawResponse, error) {
	return c.doRaw("GET", path, nil)
}

func (c *Client) do(method, path string, body interface{}) ([]byte, error) {
	resp, err := c.doRaw(method, path, body)
	if err != nil {
		return nil, err
	}

	var envelope struct {
		Success *bool           `json:"success"`
		Data    json.RawMessage `json:"data"`
		Error   string          `json:"error"`
	}
	if err := json.Unmarshal(resp.Body, &envelope); err == nil && envelope.Success != nil {
		if !*envelope.Success {
			return nil, fmt.Errorf("API error (HTTP %d): %s", resp.StatusCode, envelope.Error)
		}
		if len(envelope.Data) > 0 && string(envelope.Data) != "null" {
			return envelope.Data, nil
		}
	}

	return resp.Body, nil
}

func (c *Client) doRaw(method, path string, body interface{}) (*RawResponse, error) {
	if c.sessionCookie != "" && requiresCSRF(method) && c.csrfToken == "" && !skipCSRFBootstrap(path) {
		if err := c.ensureCSRFToken(); err != nil {
			return nil, err
		}
	}

	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request body: %w", err)
		}
		reqBody = bytes.NewReader(data)
	}

	url := c.baseURL + path
	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	if c.token != "" {
		if len(c.token) > 7 && c.token[:7] == "Bearer " {
			req.Header.Set("Authorization", c.token)
		} else {
			req.Header.Set("Authorization", "Bearer "+c.token)
		}
	}
	if c.sessionCookie != "" {
		req.AddCookie(&http.Cookie{Name: "session", Value: c.sessionCookie, Path: "/"})
	}
	if requiresCSRF(method) && c.csrfToken != "" {
		req.Header.Set("X-CSRF-Token", c.csrfToken)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	if csrfToken := resp.Header.Get("X-CSRF-Token"); csrfToken != "" {
		c.csrfToken = csrfToken
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		var envelope struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(respBody, &envelope); err == nil && envelope.Error != "" {
			return nil, fmt.Errorf("API error (HTTP %d): %s", resp.StatusCode, envelope.Error)
		}
		return nil, fmt.Errorf("API error (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	return &RawResponse{
		StatusCode: resp.StatusCode,
		Header:     resp.Header.Clone(),
		Body:       respBody,
	}, nil
}

func (c *Client) ensureCSRFToken() error {
	if c.sessionCookie == "" || c.csrfToken != "" {
		return nil
	}

	req, err := http.NewRequest(http.MethodGet, c.baseURL+"/api/v1/auth/me", nil)
	if err != nil {
		return fmt.Errorf("create CSRF bootstrap request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.AddCookie(&http.Cookie{Name: "session", Value: c.sessionCookie, Path: "/"})

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("bootstrap CSRF token: %w", err)
	}
	defer resp.Body.Close()

	if csrfToken := resp.Header.Get("X-CSRF-Token"); csrfToken != "" {
		c.csrfToken = csrfToken
		return nil
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode >= http.StatusBadRequest {
		return fmt.Errorf("bootstrap CSRF token: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return fmt.Errorf("bootstrap CSRF token: missing X-CSRF-Token header")
}

func requiresCSRF(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch:
		return true
	default:
		return false
	}
}

func skipCSRFBootstrap(path string) bool {
	return strings.HasPrefix(path, "/api/v2/cli/login/")
}
