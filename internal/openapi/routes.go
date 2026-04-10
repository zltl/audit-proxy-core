package openapi

import "net/http"

// Routes returns the documented REST API surface currently exposed by the control plane.
func Routes() []Route {
	return []Route{
		// Public/auth API.
		{
			Method:         http.MethodGet,
			Path:           "/api/v1/health",
			Tag:            "Auth",
			Summary:        "Get public health",
			Description:    "Returns the public health summary without requiring authentication.",
			OperationID:    "getPublicHealth",
			SuccessStatus:  http.StatusOK,
			SuccessSchema:  publicHealthSchema(),
			SuccessExample: map[string]interface{}{"control_plane": "healthy", "data_plane": map[string]interface{}{"status": "healthy"}},
		},
		{
			Method:         http.MethodGet,
			Path:           "/api/v1/auth/me",
			Tag:            "Auth",
			Summary:        "Get current user",
			Description:    "Returns the authenticated control-plane user represented by the session cookie.",
			OperationID:    "getCurrentUser",
			RequiresAuth:   true,
			SuccessStatus:  http.StatusOK,
			SuccessSchema:  currentUserSchema(),
			SuccessExample: map[string]interface{}{"username": "admin", "role": "admin"},
		},

		// Dashboard.
		jsonRoute(http.MethodGet, "/api/v2/dashboard/stats", "Dashboard", "getDashboardStats", "Get dashboard statistics", "Returns aggregate dashboard counters and recent activity.", envelopeSchema(jsonObjectSchema("Dashboard statistics payload"), false), listParameters()),
		jsonRoute(http.MethodGet, "/api/v2/dashboard/activity", "Dashboard", "getDashboardActivity", "Get dashboard activity feed", "Returns recent events for the dashboard timeline.", envelopeSchema(arraySchema(refSchema("AuditEvent")), true), listParameters()),

		// Sessions.
		jsonRoute(http.MethodGet, "/api/v2/sessions", "Sessions", "listSessions", "List sessions", "Lists live and persisted proxy session metadata with optional status, user, and IP filters. Historical rows are loaded from the control-plane session database under data_dir/sessions.db.", envelopeSchema(arraySchema(refSchema("Session")), true), listParameters(
			queryStringParam("status", "Optional session status filter"),
			queryStringParam("user", "Optional username filter"),
			queryStringParam("ip", "Optional source IP filter"),
		)),
		jsonRoute(http.MethodGet, "/api/v2/sessions/{id}", "Sessions", "getSession", "Get session", "Returns a single session by identifier. Closed or terminated sessions are still available after the live session disappears because metadata is persisted in the control-plane session database.", envelopeSchema(refSchema("Session"), false), nil),
		jsonRoute(http.MethodDelete, "/api/v2/sessions/{id}", "Sessions", "deleteSession", "Terminate session", "Terminates an active session by identifier.", messageEnvelope("Session terminated"), nil,
			withCSRF(),
		),
		jsonRoute(http.MethodPost, "/api/v2/sessions/bulk-kill", "Sessions", "bulkKillSessions", "Terminate multiple sessions", "Terminates multiple sessions in a single request.", envelopeSchema(jsonObjectSchema("Map of session IDs to termination results"), false), nil,
			withCSRF(),
			withRequestBody("Session IDs to terminate", objectSchema(map[string]*Schema{
				"ids": arraySchema(stringSchema("Session identifier")),
			}, "ids"), map[string]interface{}{"ids": []string{"sess-1", "sess-2"}}),
		),
		jsonRoute(http.MethodGet, "/api/v2/sessions/{id}/recording", "Sessions", "getSessionRecording", "Get session recording metadata", "Returns the recording file path for a session when available.", envelopeSchema(objectSchema(map[string]*Schema{
			"session_id":     stringSchema("Session identifier"),
			"recording_file": stringSchema("Recording file path"),
		}, "session_id", "recording_file"), false), nil),
		jsonRoute(http.MethodGet, "/api/v2/sessions/{id}/recording/download", "Sessions", "downloadSessionRecording", "Download session recording", "Downloads the session recording in asciicast v2 format. When recording object storage is enabled, the control-plane automatically falls back to the archived object if the local file is no longer present.", &Schema{Type: "string", Format: "binary", Description: "Asciicast v2 session recording"}, nil,
			withSuccessContentType("application/x-asciicast"),
		),
		jsonRoute(http.MethodGet, "/api/v2/terminal/recordings/{id}/download", "Sessions", "downloadTerminalRecording", "Download web terminal recording", "Downloads the synchronized web terminal audit recording in asciicast v2 format.", &Schema{Type: "string", Format: "binary", Description: "Asciicast v2 web terminal recording"}, nil,
			withSuccessContentType("application/x-asciicast"),
		),
		jsonRoute(http.MethodPost, "/api/v2/terminal/clipboard-audit", "Terminal", "createClipboardAudit", "Record clipboard audit event", "Records a browser-terminal clipboard paste audit event without uploading the raw clipboard text; the client only sends detector names, target, source, and text length.", envelopeSchema(refSchema("AuditEvent"), false), nil,
			withCSRF(),
			withStatus(http.StatusCreated),
			withRequestBody("Clipboard audit event payload", objectSchema(map[string]*Schema{
				"target":            stringSchema("Target host:port selected in the terminal"),
				"source":            stringSchema("Paste source such as dom-paste or toolbar"),
				"text_length":       integerSchema("Length of the pasted text"),
				"sensitive":         boolSchema("Whether any configured detector matched"),
				"matched_detectors": arraySchema(stringSchema("Matched detector identifier")),
			}, "source", "text_length"), map[string]interface{}{"target": "srv1.local:22", "source": "toolbar", "text_length": 48, "sensitive": true, "matched_detectors": []string{"api-key"}}),
		),
		jsonRoute(http.MethodPost, "/api/v2/terminal/transfer-approvals", "Terminal", "createTransferApproval", "Request transfer approval", "Creates or reuses a persisted approval request for a sensitive browser-terminal file transfer. If an equivalent request is already approved and unexpired, the existing approved request is returned so the client can retry immediately.", envelopeSchema(jsonObjectSchema("Transfer approval request"), false), nil,
			withCSRF(),
			withRequestBody("Transfer approval request", objectSchema(map[string]*Schema{
				"target":    stringSchema("Target host:port selected in the terminal"),
				"direction": stringSchema("Transfer direction: upload or download"),
				"name":      stringSchema("File name"),
				"path":      stringSchema("Client-side relative or remote path"),
				"size":      integerSchema("File size in bytes"),
				"reason":    stringSchema("Why approval is required"),
			}, "target", "direction", "name", "reason"), map[string]interface{}{"target": "srv1.local:22", "direction": "upload", "name": "secrets.txt", "path": "uploads/secrets.txt", "size": 128, "reason": "content matches API key detector"}),
		),
		jsonRoute(http.MethodGet, "/api/v2/terminal/transfer-approvals", "Terminal", "listTransferApprovals", "List transfer approvals", "Lists persisted terminal transfer approval requests. Non-approvers only see their own requests.", envelopeSchema(arraySchema(jsonObjectSchema("Transfer approval request")), true), listParameters(
			queryStringParam("status", "Optional approval status filter"),
			queryStringParam("requester", "Optional requester filter"),
			queryStringParam("approver", "Optional approver filter"),
			queryStringParam("target", "Optional target filter"),
			queryStringParam("direction", "Optional direction filter"),
		)),
		jsonRoute(http.MethodGet, "/api/v2/terminal/transfer-approvals/{id}", "Terminal", "getTransferApproval", "Get transfer approval", "Returns one transfer approval request. Requesters can read their own requests; approvers can read all requests.", envelopeSchema(jsonObjectSchema("Transfer approval request"), false), nil),
		jsonRoute(http.MethodPost, "/api/v2/terminal/transfer-approvals/{id}/approve", "Terminal", "approveTransferApproval", "Approve transfer approval", "Approves a pending terminal transfer approval request so the requester can retry the sensitive transfer.", envelopeSchema(jsonObjectSchema("Approved transfer approval"), false), nil,
			withCSRF(),
		),
		jsonRoute(http.MethodPost, "/api/v2/terminal/transfer-approvals/{id}/deny", "Terminal", "denyTransferApproval", "Deny transfer approval", "Denies a pending terminal transfer approval request.", envelopeSchema(jsonObjectSchema("Denied transfer approval"), false), nil,
			withCSRF(),
			withRequestBody("Optional denial reason", objectSchema(map[string]*Schema{
				"reason": stringSchema("Why the request was denied"),
			}), map[string]interface{}{"reason": "contains payment data"}),
		),

		// Users.
		jsonRoute(http.MethodGet, "/api/v2/users", "Users", "listUsers", "List users", "Lists users with pagination.", envelopeSchema(arraySchema(refSchema("User")), true), listParameters()),
		jsonRoute(http.MethodPost, "/api/v2/users", "Users", "createUser", "Create user", "Creates a new user account.", envelopeSchema(refSchema("User"), false), nil,
			withStatus(http.StatusCreated),
			withCSRF(),
			withRequestBody("New user definition", objectSchema(map[string]*Schema{
				"username":     stringSchema("Unique username"),
				"password":     stringSchema("Initial password"),
				"display_name": stringSchema("Display name"),
				"email":        stringSchema("Email address"),
				"role":         stringSchema("Role: admin, operator, or viewer"),
				"allowed_ips":  arraySchema(stringSchema("Allowed source CIDR or IP")),
			}, "username", "password"), map[string]interface{}{"username": "alice", "password": "Str0ngPass!", "role": "operator"}),
		),
		jsonRoute(http.MethodGet, "/api/v2/users/{username}", "Users", "getUser", "Get user", "Returns one user by username.", envelopeSchema(refSchema("User"), false), nil),
		jsonRoute(http.MethodPut, "/api/v2/users/{username}", "Users", "updateUser", "Update user", "Updates a user's profile and role.", envelopeSchema(refSchema("User"), false), nil,
			withCSRF(),
			withRequestBody("User fields to update", jsonObjectSchema("Partial user update document"), map[string]interface{}{"display_name": "Alice Admin", "role": "admin"}),
		),
		jsonRoute(http.MethodDelete, "/api/v2/users/{username}", "Users", "deleteUser", "Delete user", "Deletes a user account.", messageEnvelope("User deleted"), nil, withCSRF()),
		jsonRoute(http.MethodPut, "/api/v2/users/{username}/password", "Users", "changeUserPassword", "Change user password", "Updates a user's password.", messageEnvelope("Password updated"), nil,
			withCSRF(),
			withRequestBody("Password change payload", objectSchema(map[string]*Schema{
				"password": stringSchema("New password"),
			}, "password"), map[string]interface{}{"password": "N3wPassw0rd!"}),
		),
		jsonRoute(http.MethodPut, "/api/v2/users/{username}/mfa", "Users", "configureUserMFA", "Configure MFA", "Enables or disables TOTP MFA for the user.", envelopeSchema(jsonObjectSchema("MFA configuration result"), false), nil,
			withCSRF(),
			withRequestBody("MFA configuration payload", objectSchema(map[string]*Schema{
				"enabled": boolSchema("Enable or disable MFA"),
			}, "enabled"), map[string]interface{}{"enabled": true}),
		),
		jsonRoute(http.MethodGet, "/api/v2/users/{username}/mfa/qrcode", "Users", "getUserMFAQRCode", "Get MFA QR code", "Returns a QR code payload for TOTP enrollment.", envelopeSchema(jsonObjectSchema("QR code response"), false), nil),

		// Servers.
		jsonRoute(http.MethodGet, "/api/v2/servers", "Servers", "listServers", "List servers", "Lists upstream servers from the data plane.", envelopeSchema(arraySchema(refSchema("Server")), true), listParameters()),
		jsonRoute(http.MethodPost, "/api/v2/servers", "Servers", "createServer", "Create server", "Creates a server entry in the local inventory.", envelopeSchema(refSchema("Server"), false), nil,
			withStatus(http.StatusCreated),
			withCSRF(),
			withRequestBody("Server definition", objectSchema(map[string]*Schema{
				"name":         stringSchema("Display name"),
				"host":         stringSchema("Hostname or IP"),
				"port":         integerSchema("SSH port"),
				"group":        stringSchema("Server group"),
				"weight":       integerSchema("Load-balancing weight"),
				"max_sessions": integerSchema("Maximum concurrent sessions"),
			}, "host", "port"), map[string]interface{}{"name": "primary-db", "host": "db.internal", "port": 22}),
		),
		jsonRoute(http.MethodGet, "/api/v2/servers/health", "Servers", "getServersHealth", "Get server health summary", "Returns aggregate server health information.", envelopeSchema(jsonObjectSchema("Server health summary"), false), nil),
		jsonRoute(http.MethodGet, "/api/v2/servers/{id}", "Servers", "getServer", "Get server", "Returns a single server by identifier.", envelopeSchema(refSchema("Server"), false), nil),
		jsonRoute(http.MethodPut, "/api/v2/servers/{id}", "Servers", "updateServer", "Update server", "Updates a server record.", envelopeSchema(refSchema("Server"), false), nil,
			withCSRF(),
			withRequestBody("Partial server update document", jsonObjectSchema("Server fields to update"), map[string]interface{}{"name": "new-name"}),
		),
		jsonRoute(http.MethodDelete, "/api/v2/servers/{id}", "Servers", "deleteServer", "Delete server", "Deletes a server record from the local inventory.", messageEnvelope("Server deleted"), nil, withCSRF()),
		jsonRoute(http.MethodPut, "/api/v2/servers/{id}/maintenance", "Servers", "toggleServerMaintenance", "Toggle maintenance mode", "Enables or disables maintenance mode for a server.", envelopeSchema(refSchema("Server"), false), nil,
			withCSRF(),
			withRequestBody("Maintenance mode request", objectSchema(map[string]*Schema{
				"maintenance": boolSchema("Maintenance mode state"),
			}, "maintenance"), map[string]interface{}{"maintenance": true}),
		),

		// Audit.
		jsonRoute(http.MethodGet, "/api/v2/audit/events", "Audit", "listAuditEvents", "List audit events", "Lists audit events with pagination.", envelopeSchema(arraySchema(refSchema("AuditEvent")), true), listParameters()),
		jsonRoute(http.MethodGet, "/api/v2/audit/events/{id}", "Audit", "getAuditEvent", "Get audit event", "Returns a single audit event.", envelopeSchema(refSchema("AuditEvent"), false), nil),
		jsonRoute(http.MethodGet, "/api/v2/audit/search", "Audit", "searchAuditEvents", "Search audit events", "Searches audit events by query parameters.", envelopeSchema(arraySchema(refSchema("AuditEvent")), true), listParameters(
			queryStringParam("q", "Free-text audit search query"),
			queryStringParam("event_type", "Event type filter"),
			queryStringParam("username", "Username filter"),
			queryStringParam("target_host", "Target host filter"),
		)),
		jsonRoute(http.MethodGet, "/api/v2/audit/export", "Audit", "exportAuditEvents", "Export audit events", "Exports matching audit events.", envelopeSchema(jsonObjectSchema("Audit export metadata"), false), listParameters(
			queryStringParam("format", "Export format such as json, ndjson, or csv"),
		)),
		jsonRoute(http.MethodGet, "/api/v2/audit/stats", "Audit", "getAuditStats", "Get audit statistics", "Returns audit volume and trend statistics.", envelopeSchema(jsonObjectSchema("Audit statistics"), false), nil),

		// Config.
		jsonRoute(http.MethodGet, "/api/v2/config", "Config", "getConfig", "Get config", "Returns the current sanitized configuration.", envelopeSchema(jsonObjectSchema("Sanitized configuration object"), false), nil),
		jsonRoute(http.MethodGet, "/api/v2/config/export", "Config", "exportConfig", "Export config", "Exports the current configuration as JSON, YAML, or INI. The returned content is a raw backup and may contain secrets.", envelopeSchema(jsonObjectSchema("Configuration export payload"), false), listParameters(
			queryStringParam("format", "Optional export format: json, yaml, or ini"),
		)),
		jsonRoute(http.MethodPost, "/api/v2/config/import", "Config", "importConfig", "Import config", "Parses JSON, YAML, or INI config content and returns a canonical config document together with a sanitized diff preview. This endpoint does not persist the imported config.", envelopeSchema(jsonObjectSchema("Config import preview"), false), nil,
			withCSRF(),
			withRequestBody("Config import request", objectSchema(map[string]*Schema{
				"format":  stringSchema("Optional format override: json, yaml, or ini"),
				"content": stringSchema("Raw configuration content to parse"),
			}, "content"), map[string]interface{}{"format": "ini", "content": "[server]\nbind_addr = 0.0.0.0\nport = 2222\n"}),
		),
		jsonRoute(http.MethodGet, "/api/v2/config/templates", "Config", "listConfigTemplates", "List config templates", "Returns the built-in development, testing, and production configuration templates used by the settings UI.", envelopeSchema(arraySchema(jsonObjectSchema("Config template metadata")), true), nil),
		jsonRoute(http.MethodGet, "/api/v2/config/templates/{name}", "Config", "getConfigTemplate", "Get config template", "Returns one built-in configuration template plus a sanitized resolved config preview produced by overlaying the template onto the current config.", envelopeSchema(jsonObjectSchema("Config template detail"), false), nil),
		jsonRoute(http.MethodGet, "/api/v2/config/store", "Config", "getCentralConfigStore", "Get central config store", "Returns the persisted centralized configuration snapshot metadata plus a sanitized config document. In clustered deployments, followers update this store when synced snapshots are applied.", envelopeSchema(jsonObjectSchema("Centralized config store snapshot"), false), nil),
		jsonRoute(http.MethodPut, "/api/v2/config", "Config", "updateConfig", "Update config", "Writes a new configuration and triggers a data-plane reload. When the control-plane JSON config sets `config_approval_enabled=true`, this endpoint instead queues a persisted approval request and returns the pending change metadata. In clustered deployments, write operations must be submitted to the leader and successful applies are distributed automatically to followers.", envelopeSchema(jsonObjectSchema("Config update result"), false), nil,
			withCSRF(),
			withRequestBody("Replacement configuration document", jsonObjectSchema("Configuration object"), map[string]interface{}{"server": map[string]interface{}{"listen": ":8443"}}),
		),
		jsonRoute(http.MethodPost, "/api/v2/config/diff", "Config", "diffConfig", "Diff config", "Compares the current or versioned configuration against another version or a pending config document.", envelopeSchema(refSchema("ConfigDiff"), false), nil,
			withCSRF(),
			withRequestBody("Configuration diff request", objectSchema(map[string]*Schema{
				"from_version": stringSchema("Base version identifier, or omit for current"),
				"to_version":   stringSchema("Target version identifier, defaults to current"),
				"to_config":    jsonObjectSchema("Pending configuration object"),
			}), map[string]interface{}{"from_version": "20260408-011500", "to_version": "current"}),
		),
		jsonRoute(http.MethodPost, "/api/v2/config/changes", "Config", "createConfigChange", "Create config change", "Creates a persisted configuration change request for later approval.", envelopeSchema(jsonObjectSchema("Config change request"), false), nil,
			withCSRF(),
			withRequestBody("Pending configuration document", jsonObjectSchema("Configuration object"), map[string]interface{}{"server": map[string]interface{}{"listen": ":9443"}}),
			withStatus(http.StatusCreated),
		),
		jsonRoute(http.MethodGet, "/api/v2/config/changes", "Config", "listConfigChanges", "List config changes", "Lists persisted configuration change requests with optional status and actor filters.", envelopeSchema(arraySchema(jsonObjectSchema("Config change request")), true), listParameters(
			queryStringParam("status", "Optional change status filter"),
			queryStringParam("requester", "Optional requester filter"),
			queryStringParam("approver", "Optional approver filter"),
		)),
		jsonRoute(http.MethodGet, "/api/v2/config/changes/{id}", "Config", "getConfigChange", "Get config change", "Returns one persisted configuration change request together with its sanitized diff preview.", envelopeSchema(jsonObjectSchema("Config change request and diff"), false), nil),
		jsonRoute(http.MethodPost, "/api/v2/config/changes/{id}/approve", "Config", "approveConfigChange", "Approve config change", "Approves a pending configuration change, writes it to disk, reloads the data plane, and publishes the new desired snapshot for cluster followers when clustering is enabled.", envelopeSchema(jsonObjectSchema("Approved config change"), false), nil,
			withCSRF(),
		),
		jsonRoute(http.MethodPost, "/api/v2/config/changes/{id}/deny", "Config", "denyConfigChange", "Deny config change", "Denies a pending configuration change request.", envelopeSchema(jsonObjectSchema("Denied config change"), false), nil,
			withCSRF(),
		),
		jsonRoute(http.MethodGet, "/api/v2/config/sync-status", "Config", "getConfigSyncStatus", "Get config sync status", "Returns the current cluster-wide configuration sync status. Requires clustering to be enabled.", envelopeSchema(jsonObjectSchema("Config sync status"), false), nil),
		jsonRoute(http.MethodGet, "/api/v2/config/versions", "Config", "listConfigVersions", "List config versions", "Lists versioned configuration snapshots.", envelopeSchema(arraySchema(refSchema("ConfigVersionListItem")), false), nil),
		jsonRoute(http.MethodGet, "/api/v2/config/versions/{version}", "Config", "getConfigVersion", "Get config version", "Returns one configuration snapshot by version identifier.", envelopeSchema(jsonObjectSchema("Configuration snapshot"), false), nil),
		jsonRoute(http.MethodPost, "/api/v2/config/rollback", "Config", "rollbackConfig", "Rollback config", "Rolls the configuration back to a previous version, reloads the data plane, and republishes the restored snapshot to cluster followers when clustering is enabled.", messageEnvelope("Rolled back configuration"), nil,
			withCSRF(),
			withRequestBody("Rollback target version", objectSchema(map[string]*Schema{
				"version": stringSchema("Version identifier"),
			}, "version"), map[string]interface{}{"version": "20260408-011500"}),
		),
		jsonRoute(http.MethodPost, "/api/v2/config/reload", "Config", "reloadConfig", "Reload config", "Triggers a configuration reload on the data plane. In clustered deployments this also republishes the current snapshot so followers reload the same config.", messageEnvelope("Configuration reloaded"), nil,
			withCSRF(),
			withRequestBody("Empty JSON object", objectSchema(map[string]*Schema{}), map[string]interface{}{}),
		),

		// Threats.
		jsonRoute(http.MethodGet, "/api/v2/threats/alerts", "Threats", "listThreatAlerts", "List threat alerts", "Lists threat alerts with optional severity, status, user, source IP, and rule filters.", envelopeSchema(arraySchema(jsonObjectSchema("Threat alert")), true), listParameters(
			queryStringParam("severity", "Optional alert severity filter"),
			queryStringParam("status", "Optional alert status filter"),
			queryStringParam("username", "Optional username filter"),
			queryStringParam("source_ip", "Optional source IP filter"),
			queryStringParam("rule_id", "Optional rule identifier filter"),
		)),
		jsonRoute(http.MethodGet, "/api/v2/threats/alerts/{id}", "Threats", "getThreatAlert", "Get threat alert", "Returns a single threat alert by identifier.", envelopeSchema(jsonObjectSchema("Threat alert"), false), nil),
		jsonRoute(http.MethodPost, "/api/v2/threats/alerts/{id}/ack", "Threats", "ackThreatAlert", "Acknowledge threat alert", "Marks an active alert as acknowledged.", envelopeSchema(jsonObjectSchema("Threat alert"), false), nil,
			withCSRF(),
			withRequestBody("Alert acknowledgement payload", objectSchema(map[string]*Schema{
				"user": stringSchema("User acknowledging the alert"),
			}), map[string]interface{}{"user": "admin"}),
		),
		jsonRoute(http.MethodPost, "/api/v2/threats/alerts/{id}/resolve", "Threats", "resolveThreatAlert", "Resolve threat alert", "Marks an active alert as resolved.", envelopeSchema(jsonObjectSchema("Threat alert"), false), nil,
			withCSRF(),
			withRequestBody("Alert resolution payload", objectSchema(map[string]*Schema{
				"user": stringSchema("User resolving the alert"),
			}), map[string]interface{}{"user": "admin"}),
		),
		jsonRoute(http.MethodPost, "/api/v2/threats/alerts/{id}/false-positive", "Threats", "markThreatAlertFalsePositive", "Mark false positive", "Marks an alert as a false positive.", envelopeSchema(jsonObjectSchema("Threat alert"), false), nil,
			withCSRF(),
			withRequestBody("False positive payload", objectSchema(map[string]*Schema{
				"user": stringSchema("User marking the alert"),
			}), map[string]interface{}{"user": "admin"}),
		),
		jsonRoute(http.MethodGet, "/api/v2/threats/rules", "Threats", "listThreatRules", "List threat rules", "Returns built-in and custom threat rules, including JSON DSL-based custom detections.", envelopeSchema(arraySchema(jsonObjectSchema("Threat rule")), true), nil),
		jsonRoute(http.MethodPost, "/api/v2/threats/rules", "Threats", "createThreatRule", "Create custom threat rule", "Creates a custom threat rule backed by the detector's JSON DSL or generic pattern/threshold rule types.", envelopeSchema(jsonObjectSchema("Threat rule"), false), nil,
			withCSRF(),
			withRequestBody("Threat rule create payload", objectSchema(map[string]*Schema{
				"id":          stringSchema("Optional rule ID; auto-generated when omitted"),
				"name":        stringSchema("Rule display name"),
				"description": stringSchema("Rule description"),
				"type":        stringSchema("Rule type: dsl, pattern, or threshold"),
				"severity":    stringSchema("Severity level"),
				"enabled":     boolSchema("Whether the rule is enabled"),
				"event_types": arraySchema(stringSchema("Event type filter")),
				"threshold":   integerSchema("Threshold for threshold rules"),
				"window":      stringSchema("Window duration such as 5m"),
				"pattern":     stringSchema("Regex for pattern rules"),
				"field":       stringSchema("Field path such as details.command"),
				"group_by":    stringSchema("Suppression grouping key"),
				"expression":  jsonObjectSchema("JSON DSL expression"),
			}), map[string]interface{}{
				"name":        "Kubectl Exec Detection",
				"type":        "dsl",
				"severity":    "high",
				"event_types": []string{"command"},
				"expression": map[string]interface{}{
					"operator": "and",
					"children": []map[string]interface{}{
						{"operator": "contains", "field": "details.command", "value": "kubectl"},
						{"operator": "contains", "field": "details.command", "value": "exec"},
					},
				},
			}),
		),
		jsonRoute(http.MethodGet, "/api/v2/threats/risk", "Threats", "listThreatRiskAssessments", "List threat risk assessments", "Lists the latest multi-factor contextual risk assessments for each user/source tuple.", envelopeSchema(arraySchema(jsonObjectSchema("Threat risk assessment")), true), listParameters(
			queryStringParam("username", "Optional username filter"),
			queryStringParam("source_ip", "Optional source IP filter"),
			queryStringParam("level", "Optional risk level filter"),
		)),
		jsonRoute(http.MethodPut, "/api/v2/threats/rules/{id}", "Threats", "updateThreatRule", "Update threat rule", "Updates built-in rule overrides or editable custom rule fields such as severity and JSON DSL expressions.", messageEnvelope("rule updated"), nil,
			withCSRF(),
			withRequestBody("Threat rule update payload", objectSchema(map[string]*Schema{
				"enabled":     boolSchema("Whether the rule is enabled"),
				"threshold":   integerSchema("Threshold override"),
				"window":      stringSchema("Duration override such as 30m"),
				"pattern":     stringSchema("Pattern override for regex-based rules"),
				"name":        stringSchema("Optional display name override"),
				"description": stringSchema("Optional description override"),
				"severity":    stringSchema("Optional severity override"),
				"expression":  jsonObjectSchema("Optional JSON DSL replacement for custom rules"),
			}), map[string]interface{}{"enabled": true, "threshold": 5, "window": "30m"}),
		),
		jsonRoute(http.MethodDelete, "/api/v2/threats/rules/{id}", "Threats", "deleteThreatRule", "Delete custom threat rule", "Deletes a custom threat rule. Built-in rules cannot be deleted.", messageEnvelope("rule deleted"), nil,
			withCSRF(),
		),
		jsonRoute(http.MethodGet, "/api/v2/threats/stats", "Threats", "getThreatStats", "Get threat statistics", "Returns aggregate threat alert counts and active risk score metrics.", envelopeSchema(jsonObjectSchema("Threat statistics"), false), nil),
		jsonRoute(http.MethodPost, "/api/v2/threats/simulate", "Threats", "simulateThreatEvent", "Simulate threat event", "Injects a synthetic threat event into the detector and returns any generated alerts.", envelopeSchema(jsonObjectSchema("Threat simulation result"), false), nil,
			withCSRF(),
			withRequestBody("Threat event payload", objectSchema(map[string]*Schema{
				"timestamp": dateTimeSchema("Event timestamp"),
				"type":      stringSchema("Threat event type"),
				"username":  stringSchema("Username"),
				"source_ip": stringSchema("Source IP"),
				"target":    stringSchema("Target host"),
				"details":   jsonObjectSchema("Arbitrary event detail map"),
			}, "type"), map[string]interface{}{"type": "auth_success", "username": "alice", "source_ip": "203.0.113.10"}),
		),
		jsonRoute(http.MethodPost, "/api/v2/threats/ingest", "Threats", "ingestThreatWebhook", "Ingest signed threat webhook", "Accepts signed data-plane webhook events, enriches them with GeoIP context, and feeds the runtime threat detector. This endpoint is intentionally public, but it requires the configured webhook Authorization header and/or X-SSH-Proxy-Signature HMAC.", envelopeSchema(jsonObjectSchema("Threat ingest result"), false), nil,
			withNoAuth(),
			withStatus(http.StatusAccepted),
			withRequestBody("Data-plane webhook payload", objectSchema(map[string]*Schema{
				"event":       stringSchema("Data-plane webhook event name"),
				"timestamp":   integerSchema("Unix epoch timestamp in seconds"),
				"username":    stringSchema("Associated username"),
				"client_addr": stringSchema("Source client IP address"),
				"detail":      stringSchema("Freeform detail payload"),
			}, "event", "timestamp"), map[string]interface{}{"event": "auth.success", "timestamp": 1736937000, "username": "alice", "client_addr": "203.0.113.10"}),
		),

		// System.
		jsonRoute(http.MethodGet, "/api/v2/system/health", "System", "getSystemHealth", "Get system health", "Returns control-plane health together with summarized data-plane health.", envelopeSchema(objectSchema(map[string]*Schema{
			"status":         stringSchema("Control-plane status"),
			"data_plane":     stringSchema("Data-plane status"),
			"uptime_seconds": integerSchema("Uptime in seconds"),
			"timestamp":      dateTimeSchema("Response timestamp"),
		}, "status", "data_plane"), false), nil),
		jsonRoute(http.MethodGet, "/api/v2/system/info", "System", "getSystemInfo", "Get system info", "Returns runtime information about the control plane.", envelopeSchema(objectSchema(map[string]*Schema{
			"version":        stringSchema("Control-plane version"),
			"go_version":     stringSchema("Go runtime version"),
			"os":             stringSchema("Operating system"),
			"arch":           stringSchema("CPU architecture"),
			"hostname":       stringSchema("System hostname"),
			"num_goroutines": integerSchema("Current goroutine count"),
			"num_cpus":       integerSchema("CPU count"),
			"memory_alloc":   integerSchema("Allocated memory"),
			"memory_sys":     integerSchema("Reserved memory"),
			"uptime_seconds": integerSchema("Uptime in seconds"),
			"started_at":     dateTimeSchema("Process start time"),
		}, "version", "go_version", "os", "arch"), false), nil),
		jsonRoute(http.MethodGet, "/api/v2/system/upgrade", "System", "getSystemUpgradeStatus", "Get rolling upgrade status", "Returns the local drain state, active session count, cross-AZ / cross-region topology summary, and whether the node is ready to restart during a rolling upgrade.", envelopeSchema(objectSchema(map[string]*Schema{
			"status":            stringSchema("Local node status such as healthy or draining"),
			"draining":          boolSchema("Whether drain mode is enabled"),
			"active_sessions":   integerSchema("Number of active local sessions"),
			"ready_for_restart": boolSchema("Whether the node can be safely restarted"),
			"cluster": objectSchema(map[string]*Schema{
				"enabled":             boolSchema("Whether clustering is enabled"),
				"role":                stringSchema("Local cluster role"),
				"leader":              stringSchema("Current leader node ID"),
				"other_healthy_nodes": integerSchema("Count of healthy peer nodes"),
				"topology":            jsonObjectSchema("Cluster topology and failure-domain summary"),
			}, "enabled"),
			"timestamp": dateTimeSchema("Response timestamp"),
		}, "status", "draining", "active_sessions", "ready_for_restart"), false), nil),
		jsonRoute(http.MethodPut, "/api/v2/system/upgrade", "System", "updateSystemUpgradeState", "Update rolling upgrade drain mode", "Enables or disables local drain mode so load balancers can remove the node before restart and new SSH sessions are rejected while existing ones drain. In topology-aware clustered deployments, the API also refuses drains that would remove the last healthy node from a region or availability zone.", envelopeSchema(objectSchema(map[string]*Schema{
			"status":            stringSchema("Local node status such as healthy or draining"),
			"draining":          boolSchema("Whether drain mode is enabled"),
			"active_sessions":   integerSchema("Number of active local sessions"),
			"ready_for_restart": boolSchema("Whether the node can be safely restarted"),
			"cluster": objectSchema(map[string]*Schema{
				"enabled":             boolSchema("Whether clustering is enabled"),
				"role":                stringSchema("Local cluster role"),
				"leader":              stringSchema("Current leader node ID"),
				"other_healthy_nodes": integerSchema("Count of healthy peer nodes"),
				"topology":            jsonObjectSchema("Cluster topology and failure-domain summary"),
			}, "enabled"),
			"timestamp": dateTimeSchema("Response timestamp"),
		}, "status", "draining", "active_sessions", "ready_for_restart"), false), nil,
			withCSRF(),
			withRequestBody("Rolling upgrade drain mode request", objectSchema(map[string]*Schema{
				"draining": boolSchema("Whether to enable drain mode"),
			}, "draining"), map[string]interface{}{"draining": true}),
		),
		{
			Method:             http.MethodGet,
			Path:               "/api/v2/system/metrics",
			Tag:                "System",
			Summary:            "Get system metrics",
			Description:        "Proxies raw Prometheus-style metrics from the data plane.",
			OperationID:        "getSystemMetrics",
			RequiresAuth:       true,
			SuccessStatus:      http.StatusOK,
			SuccessDescription: "Prometheus text exposition format",
			SuccessContentType: "text/plain",
			SuccessSchema:      stringSchema("Prometheus metrics text"),
			AdditionalResponses: map[string]Response{
				"502": jsonErrorResponse("Unable to fetch metrics from the data plane"),
			},
		},

		// SSH CA.
		jsonRoute(http.MethodPost, "/api/v2/ca/sign-user", "SSH CA", "signUserCert", "Sign user certificate", "Signs a short-lived SSH user certificate.", envelopeSchema(jsonObjectSchema("Signed SSH certificate response"), false), nil,
			withCSRF(),
			withRequestBody("SSH user certificate signing request", objectSchema(map[string]*Schema{
				"public_key":       stringSchema("OpenSSH public key"),
				"principals":       arraySchema(stringSchema("Allowed principal")),
				"ttl":              stringSchema("Certificate TTL such as 8h"),
				"force_command":    stringSchema("Optional forced command"),
				"source_addresses": arraySchema(stringSchema("Allowed source CIDR")),
			}, "public_key", "principals"), map[string]interface{}{"public_key": "ssh-ed25519 AAAA...", "principals": []string{"alice"}, "ttl": "8h"}),
		),
		jsonRoute(http.MethodPost, "/api/v2/ca/sign-host", "SSH CA", "signHostCert", "Sign host certificate", "Signs an SSH host certificate.", envelopeSchema(jsonObjectSchema("Signed SSH host certificate response"), false), nil,
			withCSRF(),
			withRequestBody("SSH host certificate signing request", objectSchema(map[string]*Schema{
				"public_key": stringSchema("OpenSSH public key"),
				"hostname":   stringSchema("Host principal"),
				"ttl":        stringSchema("Certificate TTL"),
			}, "public_key", "hostname"), map[string]interface{}{"public_key": "ssh-ed25519 AAAA...", "hostname": "db.internal", "ttl": "24h"}),
		),
		jsonRoute(http.MethodGet, "/api/v2/ca/public-keys", "SSH CA", "getCAPublicKeys", "Get CA public keys", "Returns user and host CA public keys.", envelopeSchema(jsonObjectSchema("CA public keys"), false), nil),
		jsonRoute(http.MethodGet, "/api/v2/ca/certs", "SSH CA", "listCertificates", "List certificates", "Lists issued certificates.", envelopeSchema(arraySchema(jsonObjectSchema("Issued certificate")), true), listParameters()),
		jsonRoute(http.MethodGet, "/api/v2/ca/crl", "SSH CA", "exportCRL", "Export revocation list", "Returns the current revoked certificate serial list.", envelopeSchema(jsonObjectSchema("Certificate revocation list"), false), nil),
		jsonRoute(http.MethodPost, "/api/v2/ca/revoke", "SSH CA", "revokeCertificate", "Revoke certificate", "Revokes a certificate by serial number.", messageEnvelope("Certificate revoked"), nil,
			withCSRF(),
			withRequestBody("Certificate revocation request", objectSchema(map[string]*Schema{
				"serial": integerSchema("Certificate serial number"),
			}, "serial"), map[string]interface{}{"serial": 1001}),
		),

		// Discovery.
		jsonRoute(http.MethodPost, "/api/v2/discovery/scan", "Discovery", "scanDiscoveryTargets", "Run discovery scan", "Scans target networks for SSH assets.", envelopeSchema(jsonObjectSchema("Discovery scan results"), false), nil,
			withCSRF(),
			withRequestBody("Network discovery scan request", objectSchema(map[string]*Schema{
				"targets":     arraySchema(stringSchema("CIDR, hostname, or IP")),
				"ports":       arraySchema(integerSchema("Port number")),
				"timeout":     stringSchema("Probe timeout"),
				"concurrency": integerSchema("Scanner concurrency"),
				"ssh_banner":  boolSchema("Whether to capture SSH banners"),
			}, "targets"), map[string]interface{}{"targets": []string{"10.0.0.0/24"}, "ports": []int{22}, "concurrency": 50}),
		),
		jsonRoute(http.MethodPost, "/api/v2/discovery/cloud/import", "Discovery", "importCloudDiscoveryAssets", "Import cloud assets", "Imports AWS/Azure/GCP/Aliyun/Tencent instance inventory JSON into the discovery inventory.", envelopeSchema(jsonObjectSchema("Cloud discovery import result"), false), nil,
			withCSRF(),
			withRequestBody("Cloud discovery import request", objectSchema(map[string]*Schema{
				"provider":      stringSchema("Cloud provider: aws, azure, gcp, aliyun, tencent"),
				"uri":           stringSchema("Optional http:// or https:// source"),
				"headers":       jsonObjectSchema("Optional HTTP headers for uri fetch"),
				"content":       jsonObjectSchema("Provider-native inventory JSON document"),
				"tag_filters":   jsonObjectSchema("Tag filters that imported assets must match"),
				"port":          integerSchema("SSH port to assign to imported assets"),
				"auto_register": boolSchema("Whether to flag imported assets for later auto-register"),
			}, "provider"), map[string]interface{}{
				"provider": "aws",
				"content": map[string]interface{}{
					"Reservations": []map[string]interface{}{
						{
							"Instances": []map[string]interface{}{
								{
									"InstanceId":       "i-1234567890",
									"PrivateIpAddress": "10.0.0.10",
									"Tags": []map[string]interface{}{
										{"Key": "Name", "Value": "bastion-01"},
									},
								},
							},
						},
					},
				},
			}),
		),
		jsonRoute(http.MethodPost, "/api/v2/discovery/cmdb/import", "Discovery", "importCMDBDiscoveryAssets", "Import CMDB assets", "Imports ServiceNow or custom HTTP API CMDB payloads into the discovery inventory.", envelopeSchema(jsonObjectSchema("CMDB discovery import result"), false), nil,
			withCSRF(),
			withRequestBody("CMDB discovery import request", objectSchema(map[string]*Schema{
				"provider":      stringSchema("CMDB provider: servicenow or custom-api"),
				"uri":           stringSchema("Optional http:// or https:// source"),
				"headers":       jsonObjectSchema("Optional HTTP headers for uri fetch"),
				"content":       jsonObjectSchema("CMDB inventory JSON document"),
				"items_path":    stringSchema("Optional array/object path inside the document"),
				"id_field":      stringSchema("Custom API asset id field"),
				"name_field":    stringSchema("Custom API asset name field"),
				"host_field":    stringSchema("Custom API host/address field"),
				"port_field":    stringSchema("Custom API SSH port field"),
				"os_field":      stringSchema("Custom API OS field"),
				"status_field":  stringSchema("Custom API status field"),
				"tag_fields":    arraySchema(stringSchema("Custom API fields to copy into tags")),
				"static_tags":   jsonObjectSchema("Static tags to apply to every imported asset"),
				"port":          integerSchema("Default SSH port when the source omits one"),
				"auto_register": boolSchema("Whether to flag imported assets for later auto-register"),
			}, "provider"), map[string]interface{}{
				"provider": "servicenow",
				"content": map[string]interface{}{
					"result": []map[string]interface{}{
						{
							"sys_id":      "cmdb-123",
							"name":        "prod-bastion",
							"ip_address":  "10.20.0.10",
							"os":          "Ubuntu 22.04",
							"u_ssh_port":  "2222",
							"environment": "prod",
						},
					},
				},
			}),
		),
		jsonRoute(http.MethodPost, "/api/v2/discovery/ansible/import", "Discovery", "importAnsibleDiscoveryAssets", "Import Ansible inventory", "Imports Ansible JSON or INI inventory into the discovery inventory.", envelopeSchema(jsonObjectSchema("Ansible discovery import result"), false), nil,
			withCSRF(),
			withRequestBody("Ansible discovery import request", objectSchema(map[string]*Schema{
				"format":        stringSchema("Inventory format: json, ini, or omitted for auto-detect"),
				"uri":           stringSchema("Optional http:// or https:// source"),
				"headers":       jsonObjectSchema("Optional HTTP headers for uri fetch"),
				"content":       jsonObjectSchema("Ansible JSON inventory document"),
				"content_text":  stringSchema("Ansible INI inventory text"),
				"port":          integerSchema("Default SSH port when the source omits one"),
				"auto_register": boolSchema("Whether to flag imported assets for later auto-register"),
			}), map[string]interface{}{
				"format": "json",
				"content": map[string]interface{}{
					"_meta": map[string]interface{}{
						"hostvars": map[string]interface{}{
							"web-1": map[string]interface{}{
								"ansible_host": "10.50.0.10",
								"ansible_port": "2222",
								"env":          "prod",
							},
						},
					},
					"web": map[string]interface{}{
						"hosts": []string{"web-1"},
					},
				},
			}),
		),
		jsonRoute(http.MethodGet, "/api/v2/discovery/sources", "Discovery", "listDiscoverySyncSources", "List discovery sync sources", "Lists persisted discovery sync sources used for scheduled cloud/CMDB/Ansible imports.", envelopeSchema(arraySchema(jsonObjectSchema("Discovery sync source")), true), listParameters()),
		jsonRoute(http.MethodPost, "/api/v2/discovery/sources", "Discovery", "createDiscoverySyncSource", "Create discovery sync source", "Creates a persisted discovery sync source definition for scheduled cloud/CMDB/Ansible imports.", envelopeSchema(jsonObjectSchema("Discovery sync source"), false), nil,
			withCSRF(),
			withRequestBody("Discovery sync source definition", objectSchema(map[string]*Schema{
				"name":          stringSchema("Human-friendly source name"),
				"kind":          stringSchema("Source kind: cloud, cmdb, ansible"),
				"provider":      stringSchema("Provider identifier such as aws, servicenow, or custom-api"),
				"format":        stringSchema("Ansible format override: json or ini"),
				"uri":           stringSchema("Optional http:// or https:// source"),
				"headers":       jsonObjectSchema("Optional HTTP headers for uri fetch"),
				"content":       jsonObjectSchema("Inline JSON content"),
				"content_text":  stringSchema("Inline text content such as Ansible INI"),
				"interval":      stringSchema("Sync interval duration"),
				"enabled":       boolSchema("Whether background sync is enabled"),
				"auto_register": boolSchema("Whether imported assets should auto-register"),
				"port":          integerSchema("Default SSH port"),
				"tag_filters":   jsonObjectSchema("Cloud tag filters"),
				"items_path":    stringSchema("CMDB object/array path"),
				"id_field":      stringSchema("CMDB custom ID field"),
				"name_field":    stringSchema("CMDB custom name field"),
				"host_field":    stringSchema("CMDB custom host field"),
				"port_field":    stringSchema("CMDB custom port field"),
				"os_field":      stringSchema("CMDB custom OS field"),
				"status_field":  stringSchema("CMDB custom status field"),
				"tag_fields":    arraySchema(stringSchema("CMDB custom tag field")),
				"static_tags":   jsonObjectSchema("Static tags applied to every asset"),
			}, "kind"), map[string]interface{}{
				"name":          "aws-prod-sync",
				"kind":          "cloud",
				"provider":      "aws",
				"interval":      "15m",
				"auto_register": true,
				"uri":           "https://inventory.example.com/aws.json",
				"headers":       map[string]interface{}{"Authorization": "Bearer ..."},
			}),
		),
		jsonRoute(http.MethodGet, "/api/v2/discovery/sources/{id}", "Discovery", "getDiscoverySyncSource", "Get discovery sync source", "Returns one persisted discovery sync source by identifier.", envelopeSchema(jsonObjectSchema("Discovery sync source"), false), nil),
		jsonRoute(http.MethodPut, "/api/v2/discovery/sources/{id}", "Discovery", "updateDiscoverySyncSource", "Update discovery sync source", "Replaces one persisted discovery sync source definition.", envelopeSchema(jsonObjectSchema("Discovery sync source"), false), nil,
			withCSRF(),
			withRequestBody("Discovery sync source definition", jsonObjectSchema("Discovery sync source"), map[string]interface{}{
				"name":          "servicenow-prod",
				"kind":          "cmdb",
				"provider":      "servicenow",
				"interval":      "30m",
				"enabled":       true,
				"auto_register": false,
			}),
		),
		jsonRoute(http.MethodDelete, "/api/v2/discovery/sources/{id}", "Discovery", "deleteDiscoverySyncSource", "Delete discovery sync source", "Deletes a persisted discovery sync source definition.", messageEnvelope("Discovery sync source deleted"), nil, withCSRF()),
		jsonRoute(http.MethodPost, "/api/v2/discovery/sources/{id}/run", "Discovery", "runDiscoverySyncSource", "Run discovery sync source", "Runs one persisted discovery sync source immediately and returns imported/offlined counts.", envelopeSchema(jsonObjectSchema("Discovery sync run result"), false), nil, withCSRF()),
		jsonRoute(http.MethodGet, "/api/v2/discovery/assets", "Discovery", "listDiscoveryAssets", "List discovery assets", "Lists discovered assets with optional filters.", envelopeSchema(arraySchema(jsonObjectSchema("Discovered asset")), true), listParameters(
			queryStringParam("status", "Asset status filter"),
			queryStringParam("host", "Host filter"),
			queryStringParam("os", "Operating system filter"),
			queryStringParam("tag", "Tag filter"),
		)),
		jsonRoute(http.MethodGet, "/api/v2/discovery/assets/{id}", "Discovery", "getDiscoveryAsset", "Get discovery asset", "Returns one discovered asset by identifier.", envelopeSchema(jsonObjectSchema("Discovered asset"), false), nil),
		jsonRoute(http.MethodPut, "/api/v2/discovery/assets/{id}", "Discovery", "updateDiscoveryAsset", "Update discovery asset", "Updates labels or metadata for a discovered asset.", envelopeSchema(jsonObjectSchema("Updated discovery asset"), false), nil,
			withCSRF(),
			withRequestBody("Partial discovery asset update document", jsonObjectSchema("Fields to update"), map[string]interface{}{"name": "bastion-01"}),
		),
		jsonRoute(http.MethodDelete, "/api/v2/discovery/assets/{id}", "Discovery", "deleteDiscoveryAsset", "Delete discovery asset", "Deletes a discovered asset record.", messageEnvelope("Discovery asset deleted"), nil, withCSRF()),
		jsonRoute(http.MethodPost, "/api/v2/discovery/register", "Discovery", "registerDiscoveryAsset", "Register discovery asset", "Promotes a discovered asset into the managed server inventory.", envelopeSchema(refSchema("Server"), false), nil,
			withCSRF(),
			withRequestBody("Discovery asset registration request", objectSchema(map[string]*Schema{
				"asset_id": stringSchema("Discovery asset identifier"),
				"name":     stringSchema("Optional managed server name"),
				"group":    stringSchema("Optional server group"),
			}, "asset_id"), map[string]interface{}{"asset_id": "asset-1", "name": "prod-db"}),
		),
		jsonRoute(http.MethodGet, "/api/v2/discovery/config", "Discovery", "getDiscoveryConfig", "Get discovery config", "Returns the current discovery scanner configuration.", envelopeSchema(jsonObjectSchema("Discovery configuration"), false), nil),
		jsonRoute(http.MethodPut, "/api/v2/discovery/config", "Discovery", "updateDiscoveryConfig", "Update discovery config", "Updates the default discovery scanner configuration.", envelopeSchema(jsonObjectSchema("Discovery configuration"), false), nil,
			withCSRF(),
			withRequestBody("Discovery configuration update", jsonObjectSchema("Discovery configuration fields"), map[string]interface{}{"ports": []int{22, 2222}, "concurrency": 100}),
		),
		jsonRoute(http.MethodGet, "/api/v2/webhooks/deliveries", "Webhooks", "listWebhookDeliveries", "List failed webhook deliveries", "Lists webhook dead-letter queue entries for debugging and replay.", envelopeSchema(arraySchema(jsonObjectSchema("Webhook delivery")), true), listParameters()),
		jsonRoute(http.MethodPost, "/api/v2/webhooks/deliveries/retry", "Webhooks", "retryWebhookDeliveries", "Retry failed webhook deliveries", "Retries selected or all failed webhook deliveries and removes successful replays from the dead-letter queue.", envelopeSchema(jsonObjectSchema("Webhook retry result"), false), nil,
			withCSRF(),
			withRequestBody("Webhook retry payload", objectSchema(map[string]*Schema{
				"ids": arraySchema(stringSchema("Webhook delivery identifier")),
			}), map[string]interface{}{"ids": []string{"delivery-1"}}),
		),

		// Automation.
		jsonRoute(http.MethodGet, "/api/v2/automation/scripts", "Automation", "listAutomationScripts", "List automation scripts", "Lists the predefined automation script library used by scheduled jobs and CI-triggerable runs.", envelopeSchema(arraySchema(jsonObjectSchema("Automation script")), true), listParameters()),
		jsonRoute(http.MethodPost, "/api/v2/automation/scripts", "Automation", "createAutomationScript", "Create automation script", "Creates a reusable script entry that can be referenced by automation jobs.", envelopeSchema(jsonObjectSchema("Automation script"), false), nil,
			withStatus(http.StatusCreated),
			withCSRF(),
			withRequestBody("Automation script definition", objectSchema(map[string]*Schema{
				"name":        stringSchema("Display name"),
				"description": stringSchema("Optional description"),
				"shell":       stringSchema("Interpreter command such as /bin/sh or /bin/bash"),
				"body":        stringSchema("Script body pushed to the remote target over SSH stdin"),
			}, "name", "body"), map[string]interface{}{"name": "restart-nginx", "shell": "/bin/sh", "body": "sudo systemctl restart nginx\n"}),
		),
		jsonRoute(http.MethodGet, "/api/v2/automation/scripts/{id}", "Automation", "getAutomationScript", "Get automation script", "Returns one automation script by identifier.", envelopeSchema(jsonObjectSchema("Automation script"), false), nil),
		jsonRoute(http.MethodPut, "/api/v2/automation/scripts/{id}", "Automation", "updateAutomationScript", "Update automation script", "Replaces one automation script definition.", envelopeSchema(jsonObjectSchema("Automation script"), false), nil,
			withCSRF(),
			withRequestBody("Automation script definition", jsonObjectSchema("Automation script fields"), map[string]interface{}{"name": "restart-nginx", "shell": "/bin/bash", "body": "sudo systemctl restart nginx\n"}),
		),
		jsonRoute(http.MethodDelete, "/api/v2/automation/scripts/{id}", "Automation", "deleteAutomationScript", "Delete automation script", "Deletes an automation script when no job still references it.", messageEnvelope("Automation script deleted"), nil, withCSRF()),
		jsonRoute(http.MethodGet, "/api/v2/automation/jobs", "Automation", "listAutomationJobs", "List automation jobs", "Lists automation jobs with optional enabled/provider filters.", envelopeSchema(arraySchema(jsonObjectSchema("Automation job")), true), listParameters(
			queryStringParam("enabled", "Optional enabled=true/false filter"),
			queryStringParam("provider", "Optional CI/CD provider filter"),
		)),
		jsonRoute(http.MethodPost, "/api/v2/automation/jobs", "Automation", "createAutomationJob", "Create automation job", "Creates a scheduled or manually triggered SSH automation job that can target multiple managed servers.", envelopeSchema(jsonObjectSchema("Automation job"), false), nil,
			withStatus(http.StatusCreated),
			withCSRF(),
			withRequestBody("Automation job definition", objectSchema(map[string]*Schema{
				"name":                           stringSchema("Display name"),
				"description":                    stringSchema("Optional description"),
				"command":                        stringSchema("Inline remote command"),
				"script_id":                      stringSchema("Optional automation script identifier"),
				"schedule":                       stringSchema("Optional schedule duration such as 30m"),
				"timeout":                        stringSchema("Per-target timeout such as 45s"),
				"server_ids":                     arraySchema(stringSchema("Managed server identifier")),
				"username":                       stringSchema("SSH username"),
				"password":                       stringSchema("SSH password or ${env:...}/${file:...} secret reference"),
				"private_key":                    stringSchema("SSH private key PEM or ${file:...} reference"),
				"known_hosts_path":               stringSchema("known_hosts file path"),
				"insecure_skip_host_key_verify":  boolSchema("Skip host-key verification"),
				"trigger_providers":              arraySchema(stringSchema("Allowed CI providers")),
				"enabled":                        boolSchema("Whether the scheduled job is enabled"),
			}, "name"), map[string]interface{}{"name": "nightly-inventory", "command": "hostname && uptime", "server_ids": []string{"srv-1", "srv-2"}, "username": "ops", "password": "${env:OPS_SSH_PASSWORD}", "schedule": "24h", "known_hosts_path": "/etc/ssh/ssh_known_hosts", "trigger_providers": []string{"github-actions", "jenkins"}, "enabled": true}),
		),
		jsonRoute(http.MethodGet, "/api/v2/automation/jobs/{id}", "Automation", "getAutomationJob", "Get automation job", "Returns one automation job by identifier.", envelopeSchema(jsonObjectSchema("Automation job"), false), nil),
		jsonRoute(http.MethodPut, "/api/v2/automation/jobs/{id}", "Automation", "updateAutomationJob", "Update automation job", "Replaces one automation job definition.", envelopeSchema(jsonObjectSchema("Automation job"), false), nil,
			withCSRF(),
			withRequestBody("Automation job definition", jsonObjectSchema("Automation job fields"), map[string]interface{}{"name": "nightly-inventory", "schedule": "12h", "enabled": true}),
		),
		jsonRoute(http.MethodDelete, "/api/v2/automation/jobs/{id}", "Automation", "deleteAutomationJob", "Delete automation job", "Deletes an automation job definition.", messageEnvelope("Automation job deleted"), nil, withCSRF()),
		jsonRoute(http.MethodPost, "/api/v2/automation/jobs/{id}/run", "Automation", "runAutomationJob", "Run automation job", "Runs an automation job immediately and returns collected per-target execution results.", envelopeSchema(jsonObjectSchema("Automation run"), false), nil,
			withCSRF(),
			withRequestBody("Immediate automation run request", objectSchema(map[string]*Schema{
				"trigger":     stringSchema("Trigger label such as web-ui or manual"),
				"environment": jsonObjectSchema("Optional environment overrides"),
			}), map[string]interface{}{"trigger": "web-ui", "environment": map[string]interface{}{"DEPLOY_SHA": "abc123"}}),
		),
		jsonRoute(http.MethodPost, "/api/v2/automation/jobs/{id}/trigger", "Automation", "triggerAutomationJob", "Trigger automation job from CI", "Triggers an automation job from GitHub Actions, GitLab CI, Jenkins, or another allowed CI/CD provider.", envelopeSchema(jsonObjectSchema("Automation run"), false), nil,
			withCSRF(),
			withStatus(http.StatusAccepted),
			withRequestBody("CI/CD trigger payload", objectSchema(map[string]*Schema{
				"provider":    stringSchema("CI provider such as github-actions, gitlab-ci, or jenkins"),
				"workflow":    stringSchema("Workflow or pipeline name"),
				"ref":         stringSchema("Git ref or branch"),
				"pipeline_id": stringSchema("Pipeline or run identifier"),
				"environment": jsonObjectSchema("Optional environment overrides"),
			}, "provider"), map[string]interface{}{"provider": "github-actions", "workflow": "deploy.yml", "ref": "refs/heads/main", "pipeline_id": "12345"}),
		),
		jsonRoute(http.MethodGet, "/api/v2/automation/runs", "Automation", "listAutomationRuns", "List automation runs", "Lists collected automation run history with optional job/status filters.", envelopeSchema(arraySchema(jsonObjectSchema("Automation run")), true), listParameters(
			queryStringParam("job_id", "Optional job identifier filter"),
			queryStringParam("status", "Optional run status filter"),
		)),
		jsonRoute(http.MethodGet, "/api/v2/automation/runs/{id}", "Automation", "getAutomationRun", "Get automation run", "Returns one automation run including per-target stdout/stderr summaries.", envelopeSchema(jsonObjectSchema("Automation run"), false), nil),

		// Gateway.
		jsonRoute(http.MethodGet, "/api/v2/gateway/proxies", "Gateway", "listGatewayProxies", "List gateway proxies", "Lists active unified protocol proxies such as RDP, VNC, database, HTTP(S), Kubernetes API, X11, and SOCKS5 listeners.", envelopeSchema(arraySchema(jsonObjectSchema("Gateway proxy")), true), listParameters()),
		jsonRoute(http.MethodPost, "/api/v2/gateway/proxies", "Gateway", "createGatewayProxy", "Create gateway proxy", "Creates and starts an ephemeral local listener that tunnels traffic through SSH, with protocol presets for SOCKS5, RDP, VNC, MySQL, PostgreSQL, Redis, Kubernetes API, HTTP, HTTPS, X11, or a custom TCP port.", envelopeSchema(jsonObjectSchema("Gateway proxy"), false), nil,
			withStatus(http.StatusCreated),
			withCSRF(),
			withRequestBody("Gateway proxy definition", objectSchema(map[string]*Schema{
				"name":                           stringSchema("Optional display name"),
				"protocol":                       stringSchema("Preset such as socks5, rdp, vnc, mysql, postgresql, redis, kubernetes, http, https, x11, or tcp"),
				"bind_address":                   stringSchema("Local bind address, default 127.0.0.1"),
				"bind_port":                      integerSchema("Local bind port, default random"),
				"remote_host":                    stringSchema("Remote host reached from the SSH target, default 127.0.0.1 for fixed-port presets"),
				"remote_port":                    integerSchema("Remote port, default comes from the selected protocol preset"),
				"ssh_host":                       stringSchema("SSH gateway host"),
				"ssh_port":                       integerSchema("SSH gateway port, default 22"),
				"username":                       stringSchema("SSH username"),
				"password":                       stringSchema("SSH password or ${env:...}/${file:...} secret reference"),
				"private_key":                    stringSchema("SSH private key PEM or ${file:...} reference"),
				"passphrase":                     stringSchema("SSH private key passphrase"),
				"known_hosts_path":               stringSchema("known_hosts file path"),
				"insecure_skip_host_key_verify":  boolSchema("Skip host-key verification"),
				"jump_chain":                     arraySchema(jsonObjectSchema("Optional SSH jump hop list")),
			}, "protocol", "ssh_host", "username"), map[string]interface{}{"protocol": "rdp", "remote_host": "127.0.0.1", "ssh_host": "bastion.internal", "username": "ops", "password": "${env:OPS_SSH_PASSWORD}", "known_hosts_path": "/etc/ssh/ssh_known_hosts"}),
		),
		jsonRoute(http.MethodGet, "/api/v2/gateway/proxies/{id}", "Gateway", "getGatewayProxy", "Get gateway proxy", "Returns one active gateway proxy listener.", envelopeSchema(jsonObjectSchema("Gateway proxy"), false), nil),
		jsonRoute(http.MethodDelete, "/api/v2/gateway/proxies/{id}", "Gateway", "deleteGatewayProxy", "Delete gateway proxy", "Stops and removes an active gateway proxy listener.", messageEnvelope("Gateway proxy stopped"), nil, withCSRF()),

		// Insights.
		jsonRoute(http.MethodGet, "/api/v2/insights/command-intents", "Insights", "listCommandIntents", "List command intents", "Classifies audited command events into high-level intents such as discovery, service operations, destructive changes, or Kubernetes administration.", envelopeSchema(arraySchema(jsonObjectSchema("Command intent insight")), true), listParameters(
			queryStringParam("user", "Optional username filter"),
			queryStringParam("target_host", "Optional target host filter"),
		)),
		jsonRoute(http.MethodGet, "/api/v2/insights/anomalies", "Insights", "listInsightAnomalies", "List anomaly baselines", "Builds lightweight user behavior baselines from audit events and returns recent deviations such as rare targets, rare intents, off-hours activity, and high-risk commands.", envelopeSchema(arraySchema(jsonObjectSchema("User baseline profile")), true), []Parameter{
			queryStringParam("user", "Optional username filter"),
		}),
		jsonRoute(http.MethodGet, "/api/v2/insights/recommendations", "Insights", "listPrivilegeRecommendations", "List privilege recommendations", "Generates least-privilege role and operation recommendations from observed command behavior.", envelopeSchema(arraySchema(jsonObjectSchema("Privilege recommendation")), true), []Parameter{
			queryStringParam("user", "Optional username filter"),
		}),
		jsonRoute(http.MethodPost, "/api/v2/insights/policy-preview", "Insights", "previewNaturalLanguagePolicy", "Preview natural-language policy", "Parses a short natural-language access statement into a policy rule preview with inferred role, resources, operations, and conditions.", envelopeSchema(jsonObjectSchema("Natural-language policy preview"), false), nil,
			withCSRF(),
			withRequestBody("Natural-language policy prompt", objectSchema(map[string]*Schema{
				"text": stringSchema("Policy statement such as allow ops team to access production servers during business hours"),
			}, "text"), map[string]interface{}{"text": "允许运维团队在工作时间访问生产服务器"}),
		),
		jsonRoute(http.MethodGet, "/api/v2/insights/audit-summary", "Insights", "getAuditSummaryInsight", "Get audit summary insight", "Summarizes audit activity for a time range, including high-risk command counts, failed logins, top users, and top targets.", envelopeSchema(jsonObjectSchema("Audit summary insight"), false), []Parameter{
			queryStringParam("user", "Optional username filter"),
			queryStringParam("from", "Optional RFC3339 start time"),
			queryStringParam("to", "Optional RFC3339 end time"),
		}),

		// Command control.
		jsonRoute(http.MethodGet, "/api/v2/commands/rules", "Command Control", "listCommandRules", "List command rules", "Lists command control rules.", envelopeSchema(arraySchema(jsonObjectSchema("Command rule")), true), listParameters()),
		jsonRoute(http.MethodPost, "/api/v2/commands/rules", "Command Control", "createCommandRule", "Create command rule", "Creates a new command control rule.", envelopeSchema(jsonObjectSchema("Created command rule"), false), nil,
			withStatus(http.StatusCreated),
			withCSRF(),
			withRequestBody("Command rule definition", jsonObjectSchema("Command rule object"), map[string]interface{}{"id": "block-rm", "pattern": "rm -rf /", "action": "deny"}),
		),
		jsonRoute(http.MethodGet, "/api/v2/commands/rules/{id}", "Command Control", "getCommandRule", "Get command rule", "Returns a command control rule by identifier.", envelopeSchema(jsonObjectSchema("Command rule"), false), nil),
		jsonRoute(http.MethodPut, "/api/v2/commands/rules/{id}", "Command Control", "updateCommandRule", "Update command rule", "Updates an existing command control rule.", envelopeSchema(jsonObjectSchema("Updated command rule"), false), nil,
			withCSRF(),
			withRequestBody("Command rule update", jsonObjectSchema("Command rule fields"), map[string]interface{}{"action": "audit"}),
		),
		jsonRoute(http.MethodDelete, "/api/v2/commands/rules/{id}", "Command Control", "deleteCommandRule", "Delete command rule", "Deletes a command control rule.", envelopeSchema(stringSchema("Deletion result"), false), nil, withCSRF()),
		jsonRoute(http.MethodPost, "/api/v2/commands/evaluate", "Command Control", "evaluateCommand", "Evaluate command", "Evaluates a command against current policy.", envelopeSchema(jsonObjectSchema("Policy decision"), false), nil,
			withCSRF(),
			withRequestBody("Command evaluation payload", objectSchema(map[string]*Schema{
				"command":  stringSchema("Command line to evaluate"),
				"username": stringSchema("Username"),
				"role":     stringSchema("User role"),
				"target":   stringSchema("Target host"),
			}, "command"), map[string]interface{}{"command": "sudo su -", "username": "alice", "role": "admin", "target": "db.internal"}),
		),
		jsonRoute(http.MethodGet, "/api/v2/commands/approvals", "Command Control", "listCommandApprovals", "List command approvals", "Lists pending and completed command approval requests.", envelopeSchema(arraySchema(jsonObjectSchema("Approval request")), true), listParameters()),
		jsonRoute(http.MethodPost, "/api/v2/commands/approvals/{id}/approve", "Command Control", "approveCommand", "Approve command", "Approves a pending command execution request.", messageEnvelope("Command approved"), nil, withCSRF()),
		jsonRoute(http.MethodPost, "/api/v2/commands/approvals/{id}/deny", "Command Control", "denyCommand", "Deny command", "Denies a pending command execution request.", messageEnvelope("Command denied"), nil, withCSRF()),
		jsonRoute(http.MethodGet, "/api/v2/commands/stats", "Command Control", "getCommandControlStats", "Get command control stats", "Returns command control counters and aggregates.", envelopeSchema(jsonObjectSchema("Command control statistics"), false), nil),

		// Collaboration.
		jsonRoute(http.MethodPost, "/api/v2/collab/sessions", "Collaboration", "createCollabSession", "Create collaboration session", "Creates a shared collaboration session bound to an SSH session.", envelopeSchema(jsonObjectSchema("Created collaboration session"), false), nil,
			withStatus(http.StatusCreated),
			withCSRF(),
			withRequestBody("Collaboration session definition", objectSchema(map[string]*Schema{
				"session_id":         stringSchema("Underlying SSH session ID"),
				"target":             stringSchema("Target host"),
				"max_viewers":        integerSchema("Maximum viewer count"),
				"allow_control":      boolSchema("Whether participants may request control"),
				"four_eyes_required": boolSchema("Whether grant/revoke/end actions require a second participant approval"),
			}, "session_id"), map[string]interface{}{"session_id": "sess-1", "target": "db.internal", "max_viewers": 5, "allow_control": true, "four_eyes_required": true}),
		),
		jsonRoute(http.MethodGet, "/api/v2/collab/sessions", "Collaboration", "listCollabSessions", "List collaboration sessions", "Lists active shared sessions.", envelopeSchema(arraySchema(jsonObjectSchema("Shared collaboration session")), false), nil),
		jsonRoute(http.MethodGet, "/api/v2/collab/sessions/{id}", "Collaboration", "getCollabSession", "Get collaboration session", "Returns one shared session by identifier.", envelopeSchema(jsonObjectSchema("Shared collaboration session"), false), nil),
		jsonRoute(http.MethodPost, "/api/v2/collab/sessions/{id}/join", "Collaboration", "joinCollabSession", "Join collaboration session", "Joins a shared session as a viewer or controller.", messageEnvelope("Joined session"), nil,
			withCSRF(),
			withRequestBody("Join session payload", objectSchema(map[string]*Schema{
				"role": stringSchema("viewer or controller"),
			}), map[string]interface{}{"role": "viewer"}),
		),
		jsonRoute(http.MethodPost, "/api/v2/collab/sessions/{id}/leave", "Collaboration", "leaveCollabSession", "Leave collaboration session", "Leaves a shared session.", messageEnvelope("Left session"), nil, withCSRF()),
		jsonRoute(http.MethodPost, "/api/v2/collab/sessions/{id}/end", "Collaboration", "endCollabSession", "End collaboration session", "Ends a shared session owned by the current user. Returns 202 with a pending approval when four-eyes is enabled.", envelopeSchema(jsonObjectSchema("Collaboration action result"), false), nil, withCSRF()),
		jsonRoute(http.MethodPost, "/api/v2/collab/sessions/{id}/request-control", "Collaboration", "requestCollabControl", "Request control", "Requests terminal control in a shared session.", messageEnvelope("Control requested"), nil, withCSRF()),
		jsonRoute(http.MethodPost, "/api/v2/collab/sessions/{id}/grant-control", "Collaboration", "grantCollabControl", "Grant control", "Grants terminal control to a participant. Returns 202 with a pending approval when four-eyes is enabled.", envelopeSchema(jsonObjectSchema("Collaboration action result"), false), nil,
			withCSRF(),
			withRequestBody("Grant control payload", objectSchema(map[string]*Schema{
				"username": stringSchema("Participant username"),
			}, "username"), map[string]interface{}{"username": "bob"}),
		),
		jsonRoute(http.MethodPost, "/api/v2/collab/sessions/{id}/revoke-control", "Collaboration", "revokeCollabControl", "Revoke control", "Revokes terminal control from the current controller. Returns 202 with a pending approval when four-eyes is enabled.", envelopeSchema(jsonObjectSchema("Collaboration action result"), false), nil, withCSRF()),
		jsonRoute(http.MethodGet, "/api/v2/collab/sessions/{id}/approvals", "Collaboration", "listCollabApprovals", "List four-eyes approvals", "Lists four-eyes approval requests for a shared session.", envelopeSchema(arraySchema(jsonObjectSchema("Four-eyes approval request")), false), nil),
		jsonRoute(http.MethodPost, "/api/v2/collab/sessions/{id}/approvals/{approvalId}/approve", "Collaboration", "approveCollabApproval", "Approve four-eyes action", "Approves and executes a pending four-eyes collaboration action.", envelopeSchema(jsonObjectSchema("Approved four-eyes action"), false), nil, withCSRF()),
		jsonRoute(http.MethodPost, "/api/v2/collab/sessions/{id}/approvals/{approvalId}/deny", "Collaboration", "denyCollabApproval", "Deny four-eyes action", "Denies a pending four-eyes collaboration action.", envelopeSchema(jsonObjectSchema("Denied four-eyes action"), false), nil, withCSRF()),
		jsonRoute(http.MethodGet, "/api/v2/collab/sessions/{id}/chat", "Collaboration", "getCollabChat", "Get collaboration chat", "Returns the chat transcript for a shared session.", envelopeSchema(arraySchema(jsonObjectSchema("Chat message")), false), nil),
		jsonRoute(http.MethodPost, "/api/v2/collab/sessions/{id}/chat", "Collaboration", "sendCollabChat", "Send collaboration chat", "Posts a chat message into the shared session.", envelopeSchema(jsonObjectSchema("Chat message"), false), nil,
			withCSRF(),
			withRequestBody("Chat message payload", objectSchema(map[string]*Schema{
				"message": stringSchema("Chat message"),
			}, "message"), map[string]interface{}{"message": "Please watch the migration step"}),
		),
		jsonRoute(http.MethodGet, "/api/v2/collab/sessions/{id}/recording", "Collaboration", "getCollabRecording", "Get collaboration recording", "Returns collaboration session recording metadata.", envelopeSchema(jsonObjectSchema("Collaboration recording metadata"), false), nil),
	}
}

type routeOption func(*Route)

func jsonRoute(method, path, tag, operationID, summary, description string, successSchema *Schema, params []Parameter, opts ...routeOption) Route {
	r := Route{
		Method:             method,
		Path:               path,
		Tag:                tag,
		Summary:            summary,
		Description:        description,
		OperationID:        operationID,
		RequiresAuth:       true,
		QueryParameters:    params,
		SuccessStatus:      http.StatusOK,
		SuccessDescription: http.StatusText(http.StatusOK),
		SuccessSchema:      successSchema,
		AdditionalResponses: map[string]Response{
			"400": jsonErrorResponse("Validation or request decoding error"),
		},
	}
	if method == http.MethodGet {
		r.RequiresCSRF = false
	}
	for _, opt := range opts {
		opt(&r)
	}
	return r
}

func withStatus(code int) routeOption {
	return func(r *Route) {
		r.SuccessStatus = code
		r.SuccessDescription = http.StatusText(code)
	}
}

func withNoAuth() routeOption {
	return func(r *Route) {
		r.RequiresAuth = false
		r.RequiresCSRF = false
	}
}

func withCSRF() routeOption {
	return func(r *Route) {
		r.RequiresCSRF = true
	}
}

func withRequestBody(description string, schema *Schema, example interface{}) routeOption {
	return func(r *Route) {
		r.RequestBodyDesc = description
		r.RequestBodySchema = schema
		r.RequestBodyExample = example
	}
}

func withSuccessContentType(contentType string) routeOption {
	return func(r *Route) {
		r.SuccessContentType = contentType
	}
}

func queryStringParam(name, description string) Parameter {
	return Parameter{
		Name:        name,
		In:          "query",
		Description: description,
		Required:    false,
		Schema:      stringSchema(description),
	}
}

func jsonObjectSchema(description string) *Schema {
	return &Schema{
		Type:        "object",
		Description: description,
	}
}

func currentUserSchema() *Schema {
	return objectSchema(map[string]*Schema{
		"username": stringSchema("Authenticated username"),
		"role":     stringSchema("Effective role"),
	}, "username", "role")
}

func publicHealthSchema() *Schema {
	return objectSchema(map[string]*Schema{
		"control_plane": stringSchema("Control-plane health summary"),
		"data_plane":    refSchema("HealthStatus"),
	}, "control_plane")
}
