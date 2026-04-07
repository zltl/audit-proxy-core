package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// ClientConfig holds the configuration loaded from file or environment.
type ClientConfig struct {
	Server   string `json:"server"`
	Token    string `json:"token"`
	Insecure bool   `json:"insecure"`
}

// Client is the HTTP API client for the SSH Proxy control plane.
type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

// NewClient creates a Client by reading configuration from
// ~/.sshproxy/config.json and/or environment variables. Env vars take
// precedence over the config file.
func NewClient() *Client {
	cfg := loadConfig()

	transport := &http.Transport{}
	if cfg.Insecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}

	return &Client{
		baseURL: cfg.Server,
		token:   cfg.Token,
		http: &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
		},
	}
}

// NewClientFromConfig creates a Client from an explicit ClientConfig (useful
// for testing).
func NewClientFromConfig(cfg ClientConfig) *Client {
	transport := &http.Transport{}
	if cfg.Insecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}
	return &Client{
		baseURL: cfg.Server,
		token:   cfg.Token,
		http: &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
		},
	}
}

func loadConfig() ClientConfig {
	var cfg ClientConfig

	// Try to read config file
	home, err := os.UserHomeDir()
	if err == nil {
		cfgPath := filepath.Join(home, ".sshproxy", "config.json")
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

	return cfg
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

func (c *Client) do(method, path string, body interface{}) ([]byte, error) {
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
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return respBody, fmt.Errorf("API error (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}
