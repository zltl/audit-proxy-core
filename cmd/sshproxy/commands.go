package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
)

// runStatus handles "sshproxy status"
func runStatus(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	fs.BoolVar(&jsonOutput, "json", false, "output in JSON format")
	fs.BoolVar(&noColor, "no-color", noColor, "disable color output")
	fs.Parse(args)

	client := NewClient()
	data, err := client.Get("/api/v1/status")
	if err != nil {
		printError(fmt.Sprintf("failed to get status: %v", err))
		os.Exit(1)
	}

	if jsonOutput {
		var v interface{}
		json.Unmarshal(data, &v)
		printJSON(v)
		return
	}

	var status struct {
		ControlPlane   string `json:"control_plane"`
		DataPlane      string `json:"data_plane"`
		ClusterNodes   int    `json:"cluster_nodes"`
		Leader         string `json:"leader"`
		ActiveSessions int    `json:"active_sessions"`
		TotalUsers     int    `json:"total_users"`
		Uptime         string `json:"uptime"`
	}
	if err := json.Unmarshal(data, &status); err != nil {
		printError(fmt.Sprintf("failed to parse status: %v", err))
		os.Exit(1)
	}

	fmt.Printf("Control Plane:   %s\n", colorizeHealth(status.ControlPlane))
	fmt.Printf("Data Plane:      %s\n", colorizeHealth(status.DataPlane))
	fmt.Printf("Cluster:         %d nodes (leader: %s)\n", status.ClusterNodes, status.Leader)
	fmt.Printf("Active Sessions: %d\n", status.ActiveSessions)
	fmt.Printf("Total Users:     %d\n", status.TotalUsers)
	fmt.Printf("Uptime:          %s\n", status.Uptime)
}

func colorizeHealth(s string) string {
	switch strings.ToLower(s) {
	case "healthy":
		return color(colorGreen, s)
	case "degraded":
		return color(colorYellow, s)
	default:
		return color(colorRed, s)
	}
}

// runSessions handles "sshproxy sessions ..."
func runSessions(args []string) {
	if len(args) == 0 {
		printError("usage: sshproxy sessions <list|kill> [options]")
		os.Exit(1)
	}

	switch args[0] {
	case "list":
		runSessionsList(args[1:])
	case "kill":
		runSessionsKill(args[1:])
	default:
		printError(fmt.Sprintf("unknown sessions command: %s", args[0]))
		os.Exit(1)
	}
}

func runSessionsList(args []string) {
	fs := flag.NewFlagSet("sessions list", flag.ExitOnError)
	user := fs.String("user", "", "filter by user")
	status := fs.String("status", "active", "filter by status (active|all)")
	fs.BoolVar(&jsonOutput, "json", false, "output in JSON format")
	fs.BoolVar(&noColor, "no-color", noColor, "disable color output")
	fs.Parse(args)

	path := "/api/v1/sessions?status=" + *status
	if *user != "" {
		path += "&user=" + *user
	}

	client := NewClient()
	data, err := client.Get(path)
	if err != nil {
		printError(fmt.Sprintf("failed to list sessions: %v", err))
		os.Exit(1)
	}

	if jsonOutput {
		var v interface{}
		json.Unmarshal(data, &v)
		printJSON(v)
		return
	}

	var sessions []struct {
		ID       string `json:"id"`
		User     string `json:"user"`
		SourceIP string `json:"source_ip"`
		Target   string `json:"target"`
		Duration string `json:"duration"`
		Status   string `json:"status"`
	}
	if err := json.Unmarshal(data, &sessions); err != nil {
		printError(fmt.Sprintf("failed to parse sessions: %v", err))
		os.Exit(1)
	}

	headers := []string{"ID", "USER", "SOURCE IP", "TARGET", "DURATION", "STATUS"}
	rows := make([][]string, len(sessions))
	for i, s := range sessions {
		rows[i] = []string{s.ID, s.User, s.SourceIP, s.Target, formatDuration(s.Duration), s.Status}
	}
	printTable(headers, rows)
}

func runSessionsKill(args []string) {
	fs := flag.NewFlagSet("sessions kill", flag.ExitOnError)
	fs.BoolVar(&jsonOutput, "json", false, "output in JSON format")
	fs.BoolVar(&noColor, "no-color", noColor, "disable color output")
	fs.Parse(args)

	if fs.NArg() == 0 {
		printError("usage: sshproxy sessions kill <session-id>")
		os.Exit(1)
	}
	sessionID := fs.Arg(0)

	client := NewClient()
	data, err := client.Delete("/api/v1/sessions/" + sessionID)
	if err != nil {
		printError(fmt.Sprintf("failed to kill session %s: %v", sessionID, err))
		os.Exit(1)
	}

	if jsonOutput {
		var v interface{}
		json.Unmarshal(data, &v)
		printJSON(v)
		return
	}
	printSuccess(fmt.Sprintf("Session %s terminated", sessionID))
}

// runUsers handles "sshproxy users ..."
func runUsers(args []string) {
	if len(args) == 0 {
		printError("usage: sshproxy users <list|create|delete|update> [options]")
		os.Exit(1)
	}

	switch args[0] {
	case "list":
		runUsersList(args[1:])
	case "create":
		runUsersCreate(args[1:])
	case "delete":
		runUsersDelete(args[1:])
	case "update":
		runUsersUpdate(args[1:])
	default:
		printError(fmt.Sprintf("unknown users command: %s", args[0]))
		os.Exit(1)
	}
}

func runUsersList(args []string) {
	fs := flag.NewFlagSet("users list", flag.ExitOnError)
	fs.BoolVar(&jsonOutput, "json", false, "output in JSON format")
	fs.BoolVar(&noColor, "no-color", noColor, "disable color output")
	fs.Parse(args)

	client := NewClient()
	data, err := client.Get("/api/v1/users")
	if err != nil {
		printError(fmt.Sprintf("failed to list users: %v", err))
		os.Exit(1)
	}

	if jsonOutput {
		var v interface{}
		json.Unmarshal(data, &v)
		printJSON(v)
		return
	}

	var users []struct {
		Username    string `json:"username"`
		DisplayName string `json:"display_name"`
		Role        string `json:"role"`
		MFA         bool   `json:"mfa"`
		Status      string `json:"status"`
		LastLogin   string `json:"last_login"`
	}
	if err := json.Unmarshal(data, &users); err != nil {
		printError(fmt.Sprintf("failed to parse users: %v", err))
		os.Exit(1)
	}

	headers := []string{"USERNAME", "DISPLAY NAME", "ROLE", "MFA", "STATUS", "LAST LOGIN"}
	rows := make([][]string, len(users))
	for i, u := range users {
		mfa := "✗"
		if u.MFA {
			mfa = "✓"
		}
		rows[i] = []string{u.Username, u.DisplayName, u.Role, mfa, u.Status, formatTime(u.LastLogin)}
	}
	printTable(headers, rows)
}

func runUsersCreate(args []string) {
	fs := flag.NewFlagSet("users create", flag.ExitOnError)
	username := fs.String("username", "", "username (required)")
	displayName := fs.String("display-name", "", "display name")
	role := fs.String("role", "operator", "role (admin|operator|viewer)")
	fs.BoolVar(&jsonOutput, "json", false, "output in JSON format")
	fs.BoolVar(&noColor, "no-color", noColor, "disable color output")
	fs.Parse(args)

	if *username == "" {
		printError("--username is required")
		os.Exit(1)
	}

	body := map[string]string{
		"username":     *username,
		"display_name": *displayName,
		"role":         *role,
	}

	client := NewClient()
	data, err := client.Post("/api/v1/users", body)
	if err != nil {
		printError(fmt.Sprintf("failed to create user: %v", err))
		os.Exit(1)
	}

	if jsonOutput {
		var v interface{}
		json.Unmarshal(data, &v)
		printJSON(v)
		return
	}
	printSuccess(fmt.Sprintf("User %s created", *username))
}

func runUsersDelete(args []string) {
	fs := flag.NewFlagSet("users delete", flag.ExitOnError)
	fs.BoolVar(&jsonOutput, "json", false, "output in JSON format")
	fs.BoolVar(&noColor, "no-color", noColor, "disable color output")
	fs.Parse(args)

	if fs.NArg() == 0 {
		printError("usage: sshproxy users delete <username>")
		os.Exit(1)
	}
	username := fs.Arg(0)

	client := NewClient()
	data, err := client.Delete("/api/v1/users/" + username)
	if err != nil {
		printError(fmt.Sprintf("failed to delete user %s: %v", username, err))
		os.Exit(1)
	}

	if jsonOutput {
		var v interface{}
		json.Unmarshal(data, &v)
		printJSON(v)
		return
	}
	printSuccess(fmt.Sprintf("User %s deleted", username))
}

func runUsersUpdate(args []string) {
	fs := flag.NewFlagSet("users update", flag.ExitOnError)
	displayName := fs.String("display-name", "", "display name")
	role := fs.String("role", "", "role (admin|operator|viewer)")
	fs.BoolVar(&jsonOutput, "json", false, "output in JSON format")
	fs.BoolVar(&noColor, "no-color", noColor, "disable color output")
	fs.Parse(args)

	if fs.NArg() == 0 {
		printError("usage: sshproxy users update <username> [--display-name NAME] [--role ROLE]")
		os.Exit(1)
	}
	username := fs.Arg(0)

	body := map[string]string{}
	if *displayName != "" {
		body["display_name"] = *displayName
	}
	if *role != "" {
		body["role"] = *role
	}

	client := NewClient()
	data, err := client.Put("/api/v1/users/"+username, body)
	if err != nil {
		printError(fmt.Sprintf("failed to update user %s: %v", username, err))
		os.Exit(1)
	}

	if jsonOutput {
		var v interface{}
		json.Unmarshal(data, &v)
		printJSON(v)
		return
	}
	printSuccess(fmt.Sprintf("User %s updated", username))
}

// runServers handles "sshproxy servers ..."
func runServers(args []string) {
	if len(args) == 0 {
		printError("usage: sshproxy servers <list|add|remove> [options]")
		os.Exit(1)
	}

	switch args[0] {
	case "list":
		runServersList(args[1:])
	case "add":
		runServersAdd(args[1:])
	case "remove":
		runServersRemove(args[1:])
	default:
		printError(fmt.Sprintf("unknown servers command: %s", args[0]))
		os.Exit(1)
	}
}

func runServersList(args []string) {
	fs := flag.NewFlagSet("servers list", flag.ExitOnError)
	fs.BoolVar(&jsonOutput, "json", false, "output in JSON format")
	fs.BoolVar(&noColor, "no-color", noColor, "disable color output")
	fs.Parse(args)

	client := NewClient()
	data, err := client.Get("/api/v1/servers")
	if err != nil {
		printError(fmt.Sprintf("failed to list servers: %v", err))
		os.Exit(1)
	}

	if jsonOutput {
		var v interface{}
		json.Unmarshal(data, &v)
		printJSON(v)
		return
	}

	var servers []struct {
		Name     string `json:"name"`
		Address  string `json:"address"`
		Port     int    `json:"port"`
		Status   string `json:"status"`
		LastSeen string `json:"last_seen"`
	}
	if err := json.Unmarshal(data, &servers); err != nil {
		printError(fmt.Sprintf("failed to parse servers: %v", err))
		os.Exit(1)
	}

	headers := []string{"NAME", "ADDRESS", "PORT", "STATUS", "LAST SEEN"}
	rows := make([][]string, len(servers))
	for i, s := range servers {
		rows[i] = []string{s.Name, s.Address, fmt.Sprintf("%d", s.Port), s.Status, formatTime(s.LastSeen)}
	}
	printTable(headers, rows)
}

func runServersAdd(args []string) {
	fs := flag.NewFlagSet("servers add", flag.ExitOnError)
	name := fs.String("name", "", "server name (required)")
	address := fs.String("address", "", "server address (required)")
	port := fs.Int("port", 22, "SSH port")
	fs.BoolVar(&jsonOutput, "json", false, "output in JSON format")
	fs.BoolVar(&noColor, "no-color", noColor, "disable color output")
	fs.Parse(args)

	if *name == "" || *address == "" {
		printError("--name and --address are required")
		os.Exit(1)
	}

	body := map[string]interface{}{
		"name":    *name,
		"address": *address,
		"port":    *port,
	}

	client := NewClient()
	data, err := client.Post("/api/v1/servers", body)
	if err != nil {
		printError(fmt.Sprintf("failed to add server: %v", err))
		os.Exit(1)
	}

	if jsonOutput {
		var v interface{}
		json.Unmarshal(data, &v)
		printJSON(v)
		return
	}
	printSuccess(fmt.Sprintf("Server %s added", *name))
}

func runServersRemove(args []string) {
	fs := flag.NewFlagSet("servers remove", flag.ExitOnError)
	fs.BoolVar(&jsonOutput, "json", false, "output in JSON format")
	fs.BoolVar(&noColor, "no-color", noColor, "disable color output")
	fs.Parse(args)

	if fs.NArg() == 0 {
		printError("usage: sshproxy servers remove <server-name>")
		os.Exit(1)
	}
	name := fs.Arg(0)

	client := NewClient()
	data, err := client.Delete("/api/v1/servers/" + name)
	if err != nil {
		printError(fmt.Sprintf("failed to remove server %s: %v", name, err))
		os.Exit(1)
	}

	if jsonOutput {
		var v interface{}
		json.Unmarshal(data, &v)
		printJSON(v)
		return
	}
	printSuccess(fmt.Sprintf("Server %s removed", name))
}

// runAudit handles "sshproxy audit ..."
func runAudit(args []string) {
	if len(args) == 0 {
		printError("usage: sshproxy audit search [options]")
		os.Exit(1)
	}

	switch args[0] {
	case "search":
		runAuditSearch(args[1:])
	default:
		printError(fmt.Sprintf("unknown audit command: %s", args[0]))
		os.Exit(1)
	}
}

func runAuditSearch(args []string) {
	fs := flag.NewFlagSet("audit search", flag.ExitOnError)
	eventType := fs.String("type", "", "filter by event type")
	user := fs.String("user", "", "filter by user")
	since := fs.String("since", "", "filter events since duration (e.g. 24h, 7d)")
	fs.BoolVar(&jsonOutput, "json", false, "output in JSON format")
	fs.BoolVar(&noColor, "no-color", noColor, "disable color output")
	fs.Parse(args)

	path := "/api/v1/audit?"
	params := []string{}
	if *eventType != "" {
		params = append(params, "type="+*eventType)
	}
	if *user != "" {
		params = append(params, "user="+*user)
	}
	if *since != "" {
		params = append(params, "since="+*since)
	}
	path += strings.Join(params, "&")

	client := NewClient()
	data, err := client.Get(path)
	if err != nil {
		printError(fmt.Sprintf("failed to search audit logs: %v", err))
		os.Exit(1)
	}

	if jsonOutput {
		var v interface{}
		json.Unmarshal(data, &v)
		printJSON(v)
		return
	}

	var events []struct {
		Timestamp string `json:"timestamp"`
		Type      string `json:"type"`
		User      string `json:"user"`
		Action    string `json:"action"`
		Resource  string `json:"resource"`
		Result    string `json:"result"`
	}
	if err := json.Unmarshal(data, &events); err != nil {
		printError(fmt.Sprintf("failed to parse audit logs: %v", err))
		os.Exit(1)
	}

	headers := []string{"TIMESTAMP", "TYPE", "USER", "ACTION", "RESOURCE", "RESULT"}
	rows := make([][]string, len(events))
	for i, e := range events {
		rows[i] = []string{formatTime(e.Timestamp), e.Type, e.User, e.Action, e.Resource, e.Result}
	}
	printTable(headers, rows)
}

// runConfig handles "sshproxy config ..."
func runConfig(args []string) {
	if len(args) == 0 {
		printError("usage: sshproxy config <show|edit|reload|history> [options]")
		os.Exit(1)
	}

	switch args[0] {
	case "show":
		runConfigShow(args[1:])
	case "edit":
		runConfigEdit(args[1:])
	case "reload":
		runConfigReload(args[1:])
	case "history":
		runConfigHistory(args[1:])
	default:
		printError(fmt.Sprintf("unknown config command: %s", args[0]))
		os.Exit(1)
	}
}

func runConfigShow(args []string) {
	fs := flag.NewFlagSet("config show", flag.ExitOnError)
	fs.BoolVar(&jsonOutput, "json", false, "output in JSON format")
	fs.BoolVar(&noColor, "no-color", noColor, "disable color output")
	fs.Parse(args)

	client := NewClient()
	data, err := client.Get("/api/v1/config")
	if err != nil {
		printError(fmt.Sprintf("failed to get config: %v", err))
		os.Exit(1)
	}

	if jsonOutput {
		var v interface{}
		json.Unmarshal(data, &v)
		printJSON(v)
		return
	}

	// Pretty-print raw JSON config
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, data, "", "  "); err != nil {
		fmt.Println(string(data))
		return
	}
	fmt.Println(pretty.String())
}

func runConfigEdit(args []string) {
	fs := flag.NewFlagSet("config edit", flag.ExitOnError)
	key := fs.String("key", "", "configuration key (required)")
	value := fs.String("value", "", "configuration value (required)")
	fs.BoolVar(&jsonOutput, "json", false, "output in JSON format")
	fs.BoolVar(&noColor, "no-color", noColor, "disable color output")
	fs.Parse(args)

	if *key == "" || *value == "" {
		printError("--key and --value are required")
		os.Exit(1)
	}

	body := map[string]string{
		"key":   *key,
		"value": *value,
	}

	client := NewClient()
	data, err := client.Put("/api/v1/config", body)
	if err != nil {
		printError(fmt.Sprintf("failed to update config: %v", err))
		os.Exit(1)
	}

	if jsonOutput {
		var v interface{}
		json.Unmarshal(data, &v)
		printJSON(v)
		return
	}
	printSuccess(fmt.Sprintf("Configuration key %s updated", *key))
}

func runConfigReload(args []string) {
	fs := flag.NewFlagSet("config reload", flag.ExitOnError)
	fs.BoolVar(&jsonOutput, "json", false, "output in JSON format")
	fs.BoolVar(&noColor, "no-color", noColor, "disable color output")
	fs.Parse(args)

	client := NewClient()
	data, err := client.Post("/api/v1/config/reload", nil)
	if err != nil {
		printError(fmt.Sprintf("failed to reload config: %v", err))
		os.Exit(1)
	}

	if jsonOutput {
		var v interface{}
		json.Unmarshal(data, &v)
		printJSON(v)
		return
	}
	printSuccess("Configuration reloaded")
}

func runConfigHistory(args []string) {
	fs := flag.NewFlagSet("config history", flag.ExitOnError)
	fs.BoolVar(&jsonOutput, "json", false, "output in JSON format")
	fs.BoolVar(&noColor, "no-color", noColor, "disable color output")
	fs.Parse(args)

	client := NewClient()
	data, err := client.Get("/api/v1/config/history")
	if err != nil {
		printError(fmt.Sprintf("failed to get config history: %v", err))
		os.Exit(1)
	}

	if jsonOutput {
		var v interface{}
		json.Unmarshal(data, &v)
		printJSON(v)
		return
	}

	var entries []struct {
		Timestamp string `json:"timestamp"`
		User      string `json:"user"`
		Key       string `json:"key"`
		OldValue  string `json:"old_value"`
		NewValue  string `json:"new_value"`
	}
	if err := json.Unmarshal(data, &entries); err != nil {
		printError(fmt.Sprintf("failed to parse config history: %v", err))
		os.Exit(1)
	}

	headers := []string{"TIMESTAMP", "USER", "KEY", "OLD VALUE", "NEW VALUE"}
	rows := make([][]string, len(entries))
	for i, e := range entries {
		rows[i] = []string{formatTime(e.Timestamp), e.User, e.Key, e.OldValue, e.NewValue}
	}
	printTable(headers, rows)
}

// runCert handles "sshproxy cert ..."
func runCert(args []string) {
	if len(args) == 0 {
		printError("usage: sshproxy cert sign [options]")
		os.Exit(1)
	}

	switch args[0] {
	case "sign":
		runCertSign(args[1:])
	default:
		printError(fmt.Sprintf("unknown cert command: %s", args[0]))
		os.Exit(1)
	}
}

func runCertSign(args []string) {
	fs := flag.NewFlagSet("cert sign", flag.ExitOnError)
	user := fs.String("user", "", "username (required)")
	ttl := fs.String("ttl", "8h", "certificate TTL")
	principals := fs.String("principals", "", "comma-separated principals")
	fs.BoolVar(&jsonOutput, "json", false, "output in JSON format")
	fs.BoolVar(&noColor, "no-color", noColor, "disable color output")
	fs.Parse(args)

	if *user == "" {
		printError("--user is required")
		os.Exit(1)
	}

	body := map[string]interface{}{
		"username": *user,
		"ttl":      *ttl,
	}
	if *principals != "" {
		body["principals"] = strings.Split(*principals, ",")
	}

	client := NewClient()
	data, err := client.Post("/api/v1/cert/sign", body)
	if err != nil {
		printError(fmt.Sprintf("failed to sign certificate: %v", err))
		os.Exit(1)
	}

	if jsonOutput {
		var v interface{}
		json.Unmarshal(data, &v)
		printJSON(v)
		return
	}

	var cert struct {
		Certificate string `json:"certificate"`
		ExpiresAt   string `json:"expires_at"`
	}
	if err := json.Unmarshal(data, &cert); err != nil {
		printError(fmt.Sprintf("failed to parse certificate response: %v", err))
		os.Exit(1)
	}

	printSuccess(fmt.Sprintf("Certificate signed for user %s (expires: %s)", *user, formatTime(cert.ExpiresAt)))
	fmt.Println(cert.Certificate)
}

// runJIT handles "sshproxy jit ..."
func runJIT(args []string) {
	if len(args) == 0 {
		printError("usage: sshproxy jit <request|approve|deny|list> [options]")
		os.Exit(1)
	}

	switch args[0] {
	case "list":
		runJITList(args[1:])
	case "request":
		runJITRequest(args[1:])
	case "approve":
		runJITApprove(args[1:])
	case "deny":
		runJITDeny(args[1:])
	default:
		printError(fmt.Sprintf("unknown jit command: %s", args[0]))
		os.Exit(1)
	}
}

func runJITList(args []string) {
	fs := flag.NewFlagSet("jit list", flag.ExitOnError)
	fs.BoolVar(&jsonOutput, "json", false, "output in JSON format")
	fs.BoolVar(&noColor, "no-color", noColor, "disable color output")
	fs.Parse(args)

	client := NewClient()
	data, err := client.Get("/api/v1/jit/requests")
	if err != nil {
		printError(fmt.Sprintf("failed to list JIT requests: %v", err))
		os.Exit(1)
	}

	if jsonOutput {
		var v interface{}
		json.Unmarshal(data, &v)
		printJSON(v)
		return
	}

	var requests []struct {
		ID        string `json:"id"`
		User      string `json:"user"`
		Target    string `json:"target"`
		Reason    string `json:"reason"`
		Duration  string `json:"duration"`
		Status    string `json:"status"`
		CreatedAt string `json:"created_at"`
	}
	if err := json.Unmarshal(data, &requests); err != nil {
		printError(fmt.Sprintf("failed to parse JIT requests: %v", err))
		os.Exit(1)
	}

	headers := []string{"ID", "USER", "TARGET", "REASON", "DURATION", "STATUS", "CREATED"}
	rows := make([][]string, len(requests))
	for i, r := range requests {
		rows[i] = []string{r.ID, r.User, r.Target, r.Reason, formatDuration(r.Duration), r.Status, formatTime(r.CreatedAt)}
	}
	printTable(headers, rows)
}

func runJITRequest(args []string) {
	fs := flag.NewFlagSet("jit request", flag.ExitOnError)
	target := fs.String("target", "", "target server (required)")
	reason := fs.String("reason", "", "reason for access (required)")
	duration := fs.String("duration", "1h", "requested duration")
	fs.BoolVar(&jsonOutput, "json", false, "output in JSON format")
	fs.BoolVar(&noColor, "no-color", noColor, "disable color output")
	fs.Parse(args)

	if *target == "" || *reason == "" {
		printError("--target and --reason are required")
		os.Exit(1)
	}

	body := map[string]string{
		"target":   *target,
		"reason":   *reason,
		"duration": *duration,
	}

	client := NewClient()
	data, err := client.Post("/api/v1/jit/requests", body)
	if err != nil {
		printError(fmt.Sprintf("failed to create JIT request: %v", err))
		os.Exit(1)
	}

	if jsonOutput {
		var v interface{}
		json.Unmarshal(data, &v)
		printJSON(v)
		return
	}

	var resp struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		printSuccess("JIT access request submitted")
		return
	}
	printSuccess(fmt.Sprintf("JIT access request %s submitted", resp.ID))
}

func runJITApprove(args []string) {
	fs := flag.NewFlagSet("jit approve", flag.ExitOnError)
	fs.BoolVar(&jsonOutput, "json", false, "output in JSON format")
	fs.BoolVar(&noColor, "no-color", noColor, "disable color output")
	fs.Parse(args)

	if fs.NArg() == 0 {
		printError("usage: sshproxy jit approve <request-id>")
		os.Exit(1)
	}
	requestID := fs.Arg(0)

	client := NewClient()
	data, err := client.Post("/api/v1/jit/requests/"+requestID+"/approve", nil)
	if err != nil {
		printError(fmt.Sprintf("failed to approve JIT request %s: %v", requestID, err))
		os.Exit(1)
	}

	if jsonOutput {
		var v interface{}
		json.Unmarshal(data, &v)
		printJSON(v)
		return
	}
	printSuccess(fmt.Sprintf("JIT request %s approved", requestID))
}

func runJITDeny(args []string) {
	fs := flag.NewFlagSet("jit deny", flag.ExitOnError)
	fs.BoolVar(&jsonOutput, "json", false, "output in JSON format")
	fs.BoolVar(&noColor, "no-color", noColor, "disable color output")
	fs.Parse(args)

	if fs.NArg() == 0 {
		printError("usage: sshproxy jit deny <request-id>")
		os.Exit(1)
	}
	requestID := fs.Arg(0)

	client := NewClient()
	data, err := client.Post("/api/v1/jit/requests/"+requestID+"/deny", nil)
	if err != nil {
		printError(fmt.Sprintf("failed to deny JIT request %s: %v", requestID, err))
		os.Exit(1)
	}

	if jsonOutput {
		var v interface{}
		json.Unmarshal(data, &v)
		printJSON(v)
		return
	}
	printSuccess(fmt.Sprintf("JIT request %s denied", requestID))
}

// runThreat handles "sshproxy threat ..."
func runThreat(args []string) {
	if len(args) == 0 {
		printError("usage: sshproxy threat alerts [options]")
		os.Exit(1)
	}

	switch args[0] {
	case "alerts":
		runThreatAlerts(args[1:])
	default:
		printError(fmt.Sprintf("unknown threat command: %s", args[0]))
		os.Exit(1)
	}
}

func runThreatAlerts(args []string) {
	fs := flag.NewFlagSet("threat alerts", flag.ExitOnError)
	severity := fs.String("severity", "", "filter by severity (low|medium|high|critical)")
	status := fs.String("status", "", "filter by status (active|resolved)")
	fs.BoolVar(&jsonOutput, "json", false, "output in JSON format")
	fs.BoolVar(&noColor, "no-color", noColor, "disable color output")
	fs.Parse(args)

	path := "/api/v1/threat/alerts?"
	params := []string{}
	if *severity != "" {
		params = append(params, "severity="+*severity)
	}
	if *status != "" {
		params = append(params, "status="+*status)
	}
	path += strings.Join(params, "&")

	client := NewClient()
	data, err := client.Get(path)
	if err != nil {
		printError(fmt.Sprintf("failed to get threat alerts: %v", err))
		os.Exit(1)
	}

	if jsonOutput {
		var v interface{}
		json.Unmarshal(data, &v)
		printJSON(v)
		return
	}

	var alerts []struct {
		ID        string `json:"id"`
		Severity  string `json:"severity"`
		Type      string `json:"type"`
		Source    string `json:"source"`
		Message   string `json:"message"`
		Status    string `json:"status"`
		Timestamp string `json:"timestamp"`
	}
	if err := json.Unmarshal(data, &alerts); err != nil {
		printError(fmt.Sprintf("failed to parse threat alerts: %v", err))
		os.Exit(1)
	}

	headers := []string{"ID", "SEVERITY", "TYPE", "SOURCE", "MESSAGE", "STATUS", "TIMESTAMP"}
	rows := make([][]string, len(alerts))
	for i, a := range alerts {
		rows[i] = []string{a.ID, colorizeSeverity(a.Severity), a.Type, a.Source, a.Message, a.Status, formatTime(a.Timestamp)}
	}
	printTable(headers, rows)
}

func colorizeSeverity(s string) string {
	switch strings.ToLower(s) {
	case "critical", "high":
		return color(colorRed, s)
	case "medium":
		return color(colorYellow, s)
	default:
		return s
	}
}

// runCompliance handles "sshproxy compliance ..."
func runCompliance(args []string) {
	if len(args) == 0 {
		printError("usage: sshproxy compliance report [options]")
		os.Exit(1)
	}

	switch args[0] {
	case "report":
		runComplianceReport(args[1:])
	default:
		printError(fmt.Sprintf("unknown compliance command: %s", args[0]))
		os.Exit(1)
	}
}

func runComplianceReport(args []string) {
	fs := flag.NewFlagSet("compliance report", flag.ExitOnError)
	framework := fs.String("framework", "", "compliance framework (required: soc2|hipaa|pci)")
	format := fs.String("format", "table", "output format (table|csv|json)")
	fs.BoolVar(&noColor, "no-color", noColor, "disable color output")
	fs.Parse(args)

	if *framework == "" {
		printError("--framework is required (soc2|hipaa|pci)")
		os.Exit(1)
	}

	if *format == "json" {
		jsonOutput = true
	}

	path := "/api/v1/compliance/report?framework=" + *framework
	if *format != "" {
		path += "&format=" + *format
	}

	client := NewClient()
	data, err := client.Get(path)
	if err != nil {
		printError(fmt.Sprintf("failed to generate compliance report: %v", err))
		os.Exit(1)
	}

	if jsonOutput {
		var v interface{}
		json.Unmarshal(data, &v)
		printJSON(v)
		return
	}

	if *format == "csv" {
		fmt.Print(string(data))
		return
	}

	var controls []struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Status      string `json:"status"`
		Description string `json:"description"`
	}
	if err := json.Unmarshal(data, &controls); err != nil {
		printError(fmt.Sprintf("failed to parse compliance report: %v", err))
		os.Exit(1)
	}

	headers := []string{"CONTROL ID", "NAME", "STATUS", "DESCRIPTION"}
	rows := make([][]string, len(controls))
	for i, c := range controls {
		status := c.Status
		switch strings.ToLower(status) {
		case "pass", "compliant":
			status = color(colorGreen, status)
		case "fail", "non-compliant":
			status = color(colorRed, status)
		case "partial":
			status = color(colorYellow, status)
		}
		rows[i] = []string{c.ID, c.Name, status, c.Description}
	}
	printTable(headers, rows)
}

// runVersion handles "sshproxy version"
func runVersion(args []string) {
	fs := flag.NewFlagSet("version", flag.ExitOnError)
	fs.BoolVar(&jsonOutput, "json", false, "output in JSON format")
	fs.BoolVar(&noColor, "no-color", noColor, "disable color output")
	fs.Parse(args)

	info := map[string]string{
		"version":    Version,
		"commit":     Commit,
		"build_date": BuildDate,
		"go_version": GoVersion,
	}

	if jsonOutput {
		printJSON(info)
		return
	}

	fmt.Printf("sshproxy %s\n", Version)
	fmt.Printf("  commit:     %s\n", Commit)
	fmt.Printf("  built:      %s\n", BuildDate)
	fmt.Printf("  go version: %s\n", GoVersion)
}
