// Command terraform-provider-sshproxy is a CLI bridge between Terraform
// (using the external data source / local-exec provisioner pattern) and
// the SSH Proxy control-plane API.
//
// Usage:
//
//	terraform-provider-sshproxy <action> [args...]
//
// Actions:
//
//	read-users        — output users as JSON
//	read-servers      — output servers as JSON
//	create-user       — create user from JSON stdin
//	update-user       — update user from JSON stdin
//	delete-user <id>  — delete user
//	create-server     — create server from JSON stdin
//	update-server     — update server from JSON stdin
//	delete-server <id>— delete server
//	read-config       — output current config
//	apply-config      — apply config from JSON stdin
//
// Environment variables:
//
//	SSHPROXY_SERVER — control-plane base URL  (e.g. https://proxy.example.com:8443)
//	SSHPROXY_TOKEN  — API authentication token
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// apiClient wraps HTTP calls to the SSH Proxy control-plane API.
type apiClient struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

// apiResponse mirrors the server's standard JSON envelope.
type apiResponse struct {
	Success bool            `json:"success"`
	Data    json.RawMessage `json:"data,omitempty"`
	Error   string          `json:"error,omitempty"`
}

func newClient() (*apiClient, error) {
	server := os.Getenv("SSHPROXY_SERVER")
	if server == "" {
		return nil, fmt.Errorf("SSHPROXY_SERVER environment variable is not set")
	}
	server = strings.TrimRight(server, "/")

	return &apiClient{
		baseURL: server,
		token:   os.Getenv("SSHPROXY_TOKEN"),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}, nil
}

func (c *apiClient) do(method, path string, body io.Reader) (*apiResponse, error) {
	url := c.baseURL + path

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	var apiResp apiResponse
	if err := json.Unmarshal(data, &apiResp); err != nil {
		return nil, fmt.Errorf("parse response: %w (body: %s)", err, string(data))
	}

	if !apiResp.Success {
		return &apiResp, fmt.Errorf("API error: %s", apiResp.Error)
	}
	return &apiResp, nil
}

func (c *apiClient) get(path string) (*apiResponse, error) {
	return c.do("GET", path, nil)
}

func (c *apiClient) post(path string, body io.Reader) (*apiResponse, error) {
	return c.do("POST", path, body)
}

func (c *apiClient) put(path string, body io.Reader) (*apiResponse, error) {
	return c.do("PUT", path, body)
}

func (c *apiClient) delete(path string) (*apiResponse, error) {
	return c.do("DELETE", path, nil)
}

// dispatch maps the CLI action to the appropriate API call.
func dispatch(action string, args []string, stdin io.Reader, client *apiClient) (json.RawMessage, error) {
	switch action {
	case "read-users":
		resp, err := client.get("/api/v2/users")
		if err != nil {
			return nil, err
		}
		return resp.Data, nil

	case "read-servers":
		resp, err := client.get("/api/v2/servers")
		if err != nil {
			return nil, err
		}
		return resp.Data, nil

	case "create-user":
		body, err := io.ReadAll(stdin)
		if err != nil {
			return nil, fmt.Errorf("read stdin: %w", err)
		}
		resp, err := client.post("/api/v2/users", bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		return resp.Data, nil

	case "update-user":
		body, err := io.ReadAll(stdin)
		if err != nil {
			return nil, fmt.Errorf("read stdin: %w", err)
		}
		var payload struct {
			Username string `json:"username"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			return nil, fmt.Errorf("parse user payload: %w", err)
		}
		if payload.Username == "" {
			return nil, fmt.Errorf("username is required in JSON payload")
		}
		resp, err := client.put("/api/v2/users/"+payload.Username, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		return resp.Data, nil

	case "delete-user":
		if len(args) < 1 {
			return nil, fmt.Errorf("delete-user requires a username argument")
		}
		resp, err := client.delete("/api/v2/users/" + args[0])
		if err != nil {
			return nil, err
		}
		return resp.Data, nil

	case "create-server":
		body, err := io.ReadAll(stdin)
		if err != nil {
			return nil, fmt.Errorf("read stdin: %w", err)
		}
		resp, err := client.post("/api/v2/servers", bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		return resp.Data, nil

	case "update-server":
		body, err := io.ReadAll(stdin)
		if err != nil {
			return nil, fmt.Errorf("read stdin: %w", err)
		}
		var payload struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			return nil, fmt.Errorf("parse server payload: %w", err)
		}
		if payload.ID == "" {
			return nil, fmt.Errorf("id is required in JSON payload")
		}
		resp, err := client.put("/api/v2/servers/"+payload.ID, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		return resp.Data, nil

	case "delete-server":
		if len(args) < 1 {
			return nil, fmt.Errorf("delete-server requires a server ID argument")
		}
		resp, err := client.delete("/api/v2/servers/" + args[0])
		if err != nil {
			return nil, err
		}
		return resp.Data, nil

	case "read-config":
		resp, err := client.get("/api/v2/config")
		if err != nil {
			return nil, err
		}
		return resp.Data, nil

	case "apply-config":
		body, err := io.ReadAll(stdin)
		if err != nil {
			return nil, fmt.Errorf("read stdin: %w", err)
		}
		resp, err := client.put("/api/v2/config", bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		return resp.Data, nil

	default:
		return nil, fmt.Errorf("unknown action: %s", action)
	}
}

// usage prints usage instructions to stderr.
func usage() {
	fmt.Fprintln(os.Stderr, `Usage: terraform-provider-sshproxy <action> [args...]

Actions:
  read-users        Output users as JSON
  read-servers      Output servers as JSON
  create-user       Create user from JSON stdin
  update-user       Update user from JSON stdin
  delete-user <id>  Delete user
  create-server     Create server from JSON stdin
  update-server     Update server from JSON stdin
  delete-server <id>Delete server
  read-config       Output current config
  apply-config      Apply config from JSON stdin

Environment:
  SSHPROXY_SERVER   Control-plane base URL (required)
  SSHPROXY_TOKEN    API authentication token`)
}

func run(args []string, stdin io.Reader) (int, string) {
	if len(args) < 2 {
		usage()
		return 1, "missing action argument"
	}

	action := args[1]
	remaining := args[2:]

	client, err := newClient()
	if err != nil {
		return 1, err.Error()
	}

	result, err := dispatch(action, remaining, stdin, client)
	if err != nil {
		return 1, err.Error()
	}

	// Pretty-print the result.
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, result, "", "  "); err != nil {
		// Fallback to raw output.
		fmt.Println(string(result))
		return 0, ""
	}
	fmt.Println(pretty.String())
	return 0, ""
}

func main() {
	code, msg := run(os.Args, os.Stdin)
	if msg != "" {
		fmt.Fprintf(os.Stderr, "error: %s\n", msg)
	}
	os.Exit(code)
}
