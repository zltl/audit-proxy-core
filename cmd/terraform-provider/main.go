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
//	read-user <id>    — output a single user as JSON
//	read-routes       — output routes as JSON
//	read-route ...    — output a single route as JSON
//	read-policies     — output policies as JSON
//	read-policy <id>  — output a single policy as JSON
//	read-servers      — output servers as JSON
//	read-server <id>  — output a single server as JSON
//	create-user       — create user from JSON stdin
//	update-user       — update user from JSON stdin
//	delete-user <id>  — delete user
//	create-route      — create route from JSON stdin
//	update-route      — update route from JSON stdin
//	delete-route ...  — delete route
//	create-policy     — create policy from JSON stdin
//	update-policy     — update policy from JSON stdin
//	delete-policy <id>— delete policy
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
	neturl "net/url"
	"os"
	"strconv"
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

	parsed, err := neturl.Parse(server)
	if err != nil {
		return nil, fmt.Errorf("parse SSHPROXY_SERVER: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("SSHPROXY_SERVER must use http or https")
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("SSHPROXY_SERVER must include a host")
	}
	server = strings.TrimRight(parsed.String(), "/")

	return &apiClient{
		baseURL: server,
		token:   os.Getenv("SSHPROXY_TOKEN"),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}, nil
}

func (c *apiClient) do(method, path string, body io.Reader) (*apiResponse, error) {
	if !strings.HasPrefix(path, "/") {
		return nil, fmt.Errorf("path must start with '/'")
	}

	url := c.baseURL + path

	req, err := http.NewRequest(method, url, body) // #nosec G704 -- url is built from a validated operator-supplied control-plane endpoint plus fixed API paths.
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req) // #nosec G704 -- outbound requests intentionally target the validated control-plane endpoint.
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

func readConfigDocument(client *apiClient) (map[string]interface{}, error) {
	resp, err := client.get("/api/v2/config")
	if err != nil {
		return nil, err
	}

	var cfg map[string]interface{}
	if err := json.Unmarshal(resp.Data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config document: %w", err)
	}
	if cfg == nil {
		cfg = map[string]interface{}{}
	}
	return cfg, nil
}

func writeConfigDocument(client *apiClient, cfg map[string]interface{}) (json.RawMessage, error) {
	body, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("marshal config document: %w", err)
	}
	resp, err := client.put("/api/v2/config", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	return resp.Data, nil
}

func readJSONObject(stdin io.Reader, subject string) (map[string]interface{}, error) {
	body, err := io.ReadAll(stdin)
	if err != nil {
		return nil, fmt.Errorf("read stdin: %w", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("parse %s payload: %w", subject, err)
	}
	if payload == nil {
		return nil, fmt.Errorf("%s payload must be a JSON object", subject)
	}
	return payload, nil
}

func marshalValue(v interface{}) (json.RawMessage, error) {
	body, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(body), nil
}

func collectionFromConfig(cfg map[string]interface{}, key string) ([]interface{}, error) {
	raw, ok := cfg[key]
	if !ok || raw == nil {
		return []interface{}{}, nil
	}
	items, ok := raw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("config %q is not an array", key)
	}
	return items, nil
}

func objectAt(items []interface{}, index int) (map[string]interface{}, bool) {
	if index < 0 || index >= len(items) {
		return nil, false
	}
	obj, ok := items[index].(map[string]interface{})
	return obj, ok
}

func getStringField(obj map[string]interface{}, key string) string {
	value, _ := obj[key].(string)
	return value
}

func getPortField(obj map[string]interface{}, key string) string {
	switch v := obj[key].(type) {
	case float64:
		return strconv.Itoa(int(v))
	case int:
		return strconv.Itoa(v)
	case int32:
		return strconv.Itoa(int(v))
	case int64:
		return strconv.FormatInt(v, 10)
	case json.Number:
		return v.String()
	case string:
		return v
	default:
		return ""
	}
}

func findRouteIndex(items []interface{}, pattern, upstream, port string) (int, map[string]interface{}) {
	for i := range items {
		obj, ok := objectAt(items, i)
		if !ok {
			continue
		}
		if pattern != "" && getStringField(obj, "pattern") != pattern {
			continue
		}
		if upstream != "" && getStringField(obj, "upstream") != upstream {
			continue
		}
		if port != "" && getPortField(obj, "port") != port {
			continue
		}
		return i, obj
	}
	return -1, nil
}

func findPolicyIndex(items []interface{}, pattern string) (int, map[string]interface{}) {
	for i := range items {
		obj, ok := objectAt(items, i)
		if !ok {
			continue
		}
		if getStringField(obj, "pattern") == pattern {
			return i, obj
		}
	}
	return -1, nil
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

	case "read-user":
		if len(args) < 1 {
			return nil, fmt.Errorf("read-user requires a username argument")
		}
		resp, err := client.get("/api/v2/users/" + args[0])
		if err != nil {
			return nil, err
		}
		return resp.Data, nil

	case "read-routes":
		cfg, err := readConfigDocument(client)
		if err != nil {
			return nil, err
		}
		items, err := collectionFromConfig(cfg, "routes")
		if err != nil {
			return nil, err
		}
		return marshalValue(items)

	case "read-route":
		if len(args) < 1 {
			return nil, fmt.Errorf("read-route requires at least a pattern argument")
		}
		cfg, err := readConfigDocument(client)
		if err != nil {
			return nil, err
		}
		items, err := collectionFromConfig(cfg, "routes")
		if err != nil {
			return nil, err
		}
		upstream := ""
		if len(args) > 1 {
			upstream = args[1]
		}
		port := ""
		if len(args) > 2 {
			port = args[2]
		}
		_, route := findRouteIndex(items, args[0], upstream, port)
		if route == nil {
			return nil, fmt.Errorf("route not found")
		}
		return marshalValue(route)

	case "read-policies":
		cfg, err := readConfigDocument(client)
		if err != nil {
			return nil, err
		}
		items, err := collectionFromConfig(cfg, "policies")
		if err != nil {
			return nil, err
		}
		return marshalValue(items)

	case "read-policy":
		if len(args) < 1 {
			return nil, fmt.Errorf("read-policy requires a pattern argument")
		}
		cfg, err := readConfigDocument(client)
		if err != nil {
			return nil, err
		}
		items, err := collectionFromConfig(cfg, "policies")
		if err != nil {
			return nil, err
		}
		_, policy := findPolicyIndex(items, args[0])
		if policy == nil {
			return nil, fmt.Errorf("policy not found")
		}
		return marshalValue(policy)

	case "read-servers":
		resp, err := client.get("/api/v2/servers")
		if err != nil {
			return nil, err
		}
		return resp.Data, nil

	case "read-server":
		if len(args) < 1 {
			return nil, fmt.Errorf("read-server requires a server ID argument")
		}
		resp, err := client.get("/api/v2/servers/" + args[0])
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

	case "create-route":
		payload, err := readJSONObject(stdin, "route")
		if err != nil {
			return nil, err
		}
		pattern := getStringField(payload, "pattern")
		upstream := getStringField(payload, "upstream")
		if pattern == "" || upstream == "" {
			return nil, fmt.Errorf("route payload must include pattern and upstream")
		}
		cfg, err := readConfigDocument(client)
		if err != nil {
			return nil, err
		}
		items, err := collectionFromConfig(cfg, "routes")
		if err != nil {
			return nil, err
		}
		if index, _ := findRouteIndex(items, pattern, upstream, getPortField(payload, "port")); index >= 0 {
			return nil, fmt.Errorf("route already exists")
		}
		cfg["routes"] = append(items, payload)
		if _, err := writeConfigDocument(client, cfg); err != nil {
			return nil, err
		}
		return marshalValue(payload)

	case "update-route":
		payload, err := readJSONObject(stdin, "route")
		if err != nil {
			return nil, err
		}
		pattern := getStringField(payload, "pattern")
		upstream := getStringField(payload, "upstream")
		if pattern == "" || upstream == "" {
			return nil, fmt.Errorf("route payload must include pattern and upstream")
		}
		cfg, err := readConfigDocument(client)
		if err != nil {
			return nil, err
		}
		items, err := collectionFromConfig(cfg, "routes")
		if err != nil {
			return nil, err
		}
		index, _ := findRouteIndex(items, pattern, upstream, getPortField(payload, "port"))
		if index < 0 {
			return nil, fmt.Errorf("route not found")
		}
		items[index] = payload
		cfg["routes"] = items
		if _, err := writeConfigDocument(client, cfg); err != nil {
			return nil, err
		}
		return marshalValue(payload)

	case "delete-route":
		if len(args) < 1 {
			return nil, fmt.Errorf("delete-route requires at least a pattern argument")
		}
		cfg, err := readConfigDocument(client)
		if err != nil {
			return nil, err
		}
		items, err := collectionFromConfig(cfg, "routes")
		if err != nil {
			return nil, err
		}
		upstream := ""
		if len(args) > 1 {
			upstream = args[1]
		}
		port := ""
		if len(args) > 2 {
			port = args[2]
		}
		index, _ := findRouteIndex(items, args[0], upstream, port)
		if index < 0 {
			return nil, fmt.Errorf("route not found")
		}
		cfg["routes"] = append(items[:index], items[index+1:]...)
		if _, err := writeConfigDocument(client, cfg); err != nil {
			return nil, err
		}
		return marshalValue(map[string]string{"message": "deleted"})

	case "create-policy":
		payload, err := readJSONObject(stdin, "policy")
		if err != nil {
			return nil, err
		}
		pattern := getStringField(payload, "pattern")
		if pattern == "" {
			return nil, fmt.Errorf("policy payload must include pattern")
		}
		cfg, err := readConfigDocument(client)
		if err != nil {
			return nil, err
		}
		items, err := collectionFromConfig(cfg, "policies")
		if err != nil {
			return nil, err
		}
		if index, _ := findPolicyIndex(items, pattern); index >= 0 {
			return nil, fmt.Errorf("policy already exists")
		}
		cfg["policies"] = append(items, payload)
		if _, err := writeConfigDocument(client, cfg); err != nil {
			return nil, err
		}
		return marshalValue(payload)

	case "update-policy":
		payload, err := readJSONObject(stdin, "policy")
		if err != nil {
			return nil, err
		}
		pattern := getStringField(payload, "pattern")
		if pattern == "" {
			return nil, fmt.Errorf("policy payload must include pattern")
		}
		cfg, err := readConfigDocument(client)
		if err != nil {
			return nil, err
		}
		items, err := collectionFromConfig(cfg, "policies")
		if err != nil {
			return nil, err
		}
		index, _ := findPolicyIndex(items, pattern)
		if index < 0 {
			return nil, fmt.Errorf("policy not found")
		}
		items[index] = payload
		cfg["policies"] = items
		if _, err := writeConfigDocument(client, cfg); err != nil {
			return nil, err
		}
		return marshalValue(payload)

	case "delete-policy":
		if len(args) < 1 {
			return nil, fmt.Errorf("delete-policy requires a pattern argument")
		}
		cfg, err := readConfigDocument(client)
		if err != nil {
			return nil, err
		}
		items, err := collectionFromConfig(cfg, "policies")
		if err != nil {
			return nil, err
		}
		index, _ := findPolicyIndex(items, args[0])
		if index < 0 {
			return nil, fmt.Errorf("policy not found")
		}
		cfg["policies"] = append(items[:index], items[index+1:]...)
		if _, err := writeConfigDocument(client, cfg); err != nil {
			return nil, err
		}
		return marshalValue(map[string]string{"message": "deleted"})

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
  read-user <id>    Output a single user as JSON
  read-routes       Output routes as JSON
  read-route ...    Output a single route as JSON
  read-policies     Output policies as JSON
  read-policy <id>  Output a single policy as JSON
  read-servers      Output servers as JSON
  read-server <id>  Output a single server as JSON
  create-user       Create user from JSON stdin
  update-user       Update user from JSON stdin
  delete-user <id>  Delete user
  create-route      Create route from JSON stdin
  update-route      Update route from JSON stdin
  delete-route ...  Delete route
  create-policy     Create policy from JSON stdin
  update-policy     Update policy from JSON stdin
  delete-policy <id>Delete policy
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
