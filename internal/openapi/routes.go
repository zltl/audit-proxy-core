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
		jsonRoute(http.MethodGet, "/api/v2/threats/rules", "Threats", "listThreatRules", "List threat rules", "Returns the built-in threat rules and their current thresholds.", envelopeSchema(arraySchema(jsonObjectSchema("Threat rule")), true), nil),
		jsonRoute(http.MethodGet, "/api/v2/threats/risk", "Threats", "listThreatRiskAssessments", "List threat risk assessments", "Lists the latest multi-factor contextual risk assessments for each user/source tuple.", envelopeSchema(arraySchema(jsonObjectSchema("Threat risk assessment")), true), listParameters(
			queryStringParam("username", "Optional username filter"),
			queryStringParam("source_ip", "Optional source IP filter"),
			queryStringParam("level", "Optional risk level filter"),
		)),
		jsonRoute(http.MethodPut, "/api/v2/threats/rules/{id}", "Threats", "updateThreatRule", "Update threat rule", "Updates enablement or thresholds for a threat rule.", messageEnvelope("rule updated"), nil,
			withCSRF(),
			withRequestBody("Threat rule update payload", objectSchema(map[string]*Schema{
				"enabled":   boolSchema("Whether the rule is enabled"),
				"threshold": integerSchema("Threshold override"),
				"window":    stringSchema("Duration override such as 30m"),
				"pattern":   stringSchema("Pattern override for regex-based rules"),
			}), map[string]interface{}{"enabled": true, "threshold": 5, "window": "30m"}),
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
				"session_id":    stringSchema("Underlying SSH session ID"),
				"target":        stringSchema("Target host"),
				"max_viewers":   integerSchema("Maximum viewer count"),
				"allow_control": boolSchema("Whether participants may request control"),
			}, "session_id"), map[string]interface{}{"session_id": "sess-1", "target": "db.internal", "max_viewers": 5, "allow_control": true}),
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
		jsonRoute(http.MethodPost, "/api/v2/collab/sessions/{id}/end", "Collaboration", "endCollabSession", "End collaboration session", "Ends a shared session owned by the current user.", messageEnvelope("Ended session"), nil, withCSRF()),
		jsonRoute(http.MethodPost, "/api/v2/collab/sessions/{id}/request-control", "Collaboration", "requestCollabControl", "Request control", "Requests terminal control in a shared session.", messageEnvelope("Control requested"), nil, withCSRF()),
		jsonRoute(http.MethodPost, "/api/v2/collab/sessions/{id}/grant-control", "Collaboration", "grantCollabControl", "Grant control", "Grants terminal control to a participant.", messageEnvelope("Control granted"), nil,
			withCSRF(),
			withRequestBody("Grant control payload", objectSchema(map[string]*Schema{
				"username": stringSchema("Participant username"),
			}, "username"), map[string]interface{}{"username": "bob"}),
		),
		jsonRoute(http.MethodPost, "/api/v2/collab/sessions/{id}/revoke-control", "Collaboration", "revokeCollabControl", "Revoke control", "Revokes terminal control from the current controller.", messageEnvelope("Control revoked"), nil, withCSRF()),
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
