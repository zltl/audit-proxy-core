# SSH Proxy Core — REST API Reference

Base URLs:

- Canonical management API: `https://<host>:8443/api/v2`
- Version alias: `https://<host>:8443/api/v3`
- Compatibility endpoints: `https://<host>:8443/api/v1` (currently auth/health only)

Auto-generated API documentation is now available from the control plane:

- OpenAPI JSON: `/api/openapi.json`
- Swagger UI: `/api/docs`

Both endpoints require an authenticated web session. Swagger UI documents the
canonical v2 surface; the control plane also exposes the same management routes
under `/api/v3` via a transparent version alias. Browser sessions reuse the
`session` cookie and automatically send `X-CSRF-Token` for state-changing
requests.

All responses use the standard envelope:

```json
{
  "success": true,
  "data": {},
  "error": "",
  "total": 0,
  "page": 1,
  "per_page": 50
}
```

Pagination query parameters (`page`, `per_page`) apply to every list endpoint.
Maximum `per_page` is 200; default is 50.

Management API requests are audited as `api.request` events and are protected by
per-client rate limiting. Exceeded limits return `429 Too Many Requests` with a
JSON error body.

---

## Table of Contents

- [Authentication](#authentication)
- [Dashboard](#dashboard)
- [Sessions](#sessions)
- [Users](#users)
- [Servers](#servers)
- [Audit](#audit)
- [Configuration](#configuration)
- [Realtime WebSocket Endpoints](#realtime-websocket-endpoints)
- [System](#system)
- [SSH Certificate Authority](#ssh-certificate-authority)
- [JIT Access](#jit-access)
- [Cluster](#cluster)
- [Compliance](#compliance)
- [SIEM](#siem)
- [Threat Detection](#threat-detection)
- [Discovery](#discovery)
- [Command Control](#command-control)
- [Session Collaboration](#session-collaboration)
- [Automation](#automation)
- [Gateway](#gateway)
- [Insights](#insights)
- [SDKs and Schemas](#sdks-and-schemas)

---

## SDKs and Schemas

- Go SDK: `sdk/sshproxy`
- Python SDK: `sdk/python/sshproxy`
- gRPC proto definitions: `api/proto/sshproxy/v1/control_plane.proto`
- Webhook event schema: `docs/webhook-event-schema.json`

The SDKs wrap the standard API envelope and ship typed helpers for core
resources such as users, servers, sessions, configuration, and SSH CA signing.
The webhook schema documents the current data-plane webhook payload contract in
machine-readable JSON Schema form.
When the control-plane JSON config sets `grpc_listen_addr`, it also exposes an
internal gRPC bridge backed by the same runtime data-plane client used by the
HTTP API.

---

## Authentication

The control-plane uses cookie-based sessions for the web UI and accepts
`X-User` / `X-Role` headers (set by the auth middleware) for API calls.
A `Bearer` token can also be passed via the `Authorization` header.

### POST /login

Login and create a session cookie.

**Request**

```
POST /login
Content-Type: application/x-www-form-urlencoded

username=admin&password=secret
```

**Response**

`302 Found` redirect to `/dashboard` with a `Set-Cookie` session header.

### POST /logout

Destroy the current session.

**Response**

`302 Found` redirect to `/login`.

### GET /auth/saml/login

Start an SP-initiated SAML 2.0 login flow for the browser.

- Optional query string: `return_to=/relative/path`
- Response: `302 Found` redirect to the IdP SSO endpoint (or an auto-submitting
  HTML form when the IdP only exposes HTTP-POST binding)

### POST /auth/saml/acs

Assertion Consumer Service (ACS) endpoint for SAML 2.0.

- Accepts both SP-initiated responses and IdP-initiated POSTs
- Validates signed/encrypted assertions against IdP metadata, audience,
  recipient, and validity window
- Maps assertion attributes into the local control-plane role model using
  `saml_roles_attribute` / `saml_role_mappings`
- Response: `302 Found` redirect to the tracked page or sanitized `RelayState`

### GET /auth/saml/metadata

Return the generated SAML SP metadata XML used to register this control plane
with an enterprise IdP such as ADFS, Shibboleth, or OneLogin.

### GET /api/v1/auth/me

Return the currently authenticated user.

**Response**

```json
{
  "username": "admin",
  "role": "admin"
}
```

### GET /api/v1/health

Public health check (no authentication required).

**Response**

```json
{
  "control_plane": "healthy",
  "data_plane": { "status": "healthy" }
}
```

---

## Dashboard

### GET /api/v2/dashboard/stats

Aggregate statistics for the dashboard overview.

**Response**

```json
{
  "success": true,
  "data": {
    "active_sessions": 12,
    "total_users": 8,
    "total_servers": 5,
    "healthy_servers": 4,
    "recent_events": []
  }
}
```

| Error | Description |
|-------|-------------|
| 502   | Data-plane unreachable |

### GET /api/v2/dashboard/activity

Recent activity feed.

**Response**

```json
{
  "success": true,
  "data": [
    {
      "type": "session",
      "action": "active",
      "user": "admin",
      "source_ip": "10.0.0.5",
      "target": "web-01",
      "time": "2025-01-15T10:30:00Z",
      "detail": "SSH session started"
    }
  ]
}
```

---

## Sessions

### GET /api/v2/sessions

List live and persisted SSH session metadata.

The control-plane stores session metadata in `data_dir/sessions.db`, so closed or
terminated sessions remain queryable after they disappear from the data-plane
live view or after the control-plane restarts. When object-storage archival is
enabled, the same sync loop also discovers `recording_dir/session_<id>_*.cast`
files and keeps `/api/v2/sessions/{id}/recording/download` usable even after the
local file has been rotated away.

When the data-plane `[session_store]` shared file backend is enabled, active
session snapshots also carry an owner heartbeat. Surviving nodes refresh their
own heartbeat in the background and automatically drop stale remote records
after several missed sync intervals, so `/api/v2/sessions` recovers cleanly
after a node failure instead of showing orphaned active sessions forever.

**Query Parameters**

| Param    | Description              |
|----------|--------------------------|
| `status` | Filter by session status |
| `user`   | Filter by username       |
| `ip`     | Filter by source IP      |

**Response**

```json
{
  "success": true,
  "data": [
    {
      "id": "sess-abc123",
      "username": "admin",
      "source_ip": "10.0.0.5",
      "client_version": "OpenSSH_9.7p1 Ubuntu-7ubuntu4",
      "client_os": "Ubuntu/Linux",
      "device_fingerprint": "sshfp-4d2d9f6a1f0ef8e0",
      "target_host": "web-01",
      "target_port": 22,
      "status": "active",
      "start_time": "2025-01-15T10:30:00Z",
      "duration": "15m32s"
    }
  ],
  "total": 1,
  "page": 1,
  "per_page": 50
}
```

### GET /api/v2/sessions/{id}

Get details for a single session.

`client_version`, `client_os`, and `device_fingerprint` are best-effort values
derived from the SSH identification banner presented by the client during the
handshake.

When the session database is enabled (the default under `data_dir/sessions.db`),
this endpoint also returns closed or terminated sessions that are no longer
present in the live data-plane session list.

**Response**

```json
{
  "success": true,
  "data": {
    "id": "sess-abc123",
    "username": "admin",
    "source_ip": "10.0.0.5",
    "client_version": "OpenSSH_9.7p1 Ubuntu-7ubuntu4",
    "client_os": "Ubuntu/Linux",
    "device_fingerprint": "sshfp-4d2d9f6a1f0ef8e0",
    "target_host": "web-01",
    "target_port": 22,
    "status": "active",
    "start_time": "2025-01-15T10:30:00Z",
    "duration": "15m32s"
  }
}
```

| Error | Description |
|-------|-------------|
| 404   | Session not found |
| 502   | Data-plane unreachable |

### DELETE /api/v2/sessions/{id}

Terminate (kill) a session.

**Response**

```json
{ "success": true, "data": { "message": "session terminated" } }
```

| Error | Description |
|-------|-------------|
| 404   | Session not found |
| 502   | Data-plane error |

### POST /api/v2/sessions/bulk-kill

Terminate multiple sessions at once.

**Request**

```json
{ "ids": ["sess-abc123", "sess-def456"] }
```

**Response**

```json
{
  "success": true,
  "data": {
    "sess-abc123": "terminated",
    "sess-def456": "terminated"
  }
}
```

### GET /api/v2/sessions/{id}/recording

Get session recording metadata.

**Response**

```json
{
  "success": true,
  "data": {
    "session_id": "sess-abc123",
    "recording_file": "/var/lib/ssh-proxy/recordings/session_123.cast"
  }
}
```

| Error | Description |
|-------|-------------|
| 404   | Recording not found |

### GET /api/v2/sessions/{id}/recording/download

Download the session recording as an asciicast v2 file.

When `recording_object_storage_enabled=true`, the control-plane mirrors session
recordings from `recording_dir` into the configured S3/MinIO/OSS-compatible
bucket under `<prefix>/sessions/<session-id>.cast`. This download endpoint
streams the local file when present and automatically falls back to the archived
object when the on-disk recording is no longer available.

**Response**

Binary `application/x-asciicast` data or JSON error.

| Error | Description |
|-------|-------------|
| 404   | Recording not found |

### GET /api/v2/terminal/recordings/{id}/download

Download the synchronized Web Terminal audit recording as an asciicast v2 file.
Each `/ws/terminal` session writes the same output stream shown in the browser to
`recording_dir/web-terminal/*.cast`, and the terminal page exposes this endpoint
as a direct download link while the session is active.

**Response**

Binary `application/x-asciicast` data or HTML error.

| Error | Description |
|-------|-------------|
| 404   | Terminal recording not found |
| 400   | Invalid recording identifier |

---

## Users

### GET /api/v2/users

List all users.

**Response**

```json
{
  "success": true,
  "data": [
    {
      "username": "admin",
      "display_name": "Admin",
      "email": "admin@example.com",
      "role": "admin",
      "enabled": true,
      "created_at": "2025-01-01T00:00:00Z",
      "updated_at": "2025-01-15T10:00:00Z",
      "allowed_ips": [],
      "mfa_enabled": false
    }
  ],
  "total": 1,
  "page": 1,
  "per_page": 50
}
```

### POST /api/v2/users

Create a new user.

**Request**

```json
{
  "username": "alice",
  "display_name": "Alice",
  "email": "alice@example.com",
  "role": "user",
  "password": "secureP@ss123",
  "allowed_ips": ["10.0.0.0/8"]
}
```

**Response** `201 Created`

```json
{
  "success": true,
  "data": {
    "username": "alice",
    "display_name": "Alice",
    "email": "alice@example.com",
    "role": "user",
    "enabled": true,
    "created_at": "2025-01-15T11:00:00Z",
    "allowed_ips": ["10.0.0.0/8"],
    "mfa_enabled": false
  }
}
```

| Error | Description |
|-------|-------------|
| 400   | Password shorter than 8 characters; missing required fields |
| 409   | User already exists |

### GET /api/v2/users/{username}

Get a single user.

| Error | Description |
|-------|-------------|
| 404   | User not found |

### PUT /api/v2/users/{username}

Update user fields (partial update).

**Request**

```json
{
  "display_name": "Alice Smith",
  "email": "alice.smith@example.com",
  "role": "admin",
  "enabled": true,
  "allowed_ips": ["10.0.0.0/8"]
}
```

| Error | Description |
|-------|-------------|
| 404   | User not found |

### DELETE /api/v2/users/{username}

Delete a user.

| Error | Description |
|-------|-------------|
| 404   | User not found |

### PUT /api/v2/users/{username}/password

Change a user's password.

**Request**

```json
{ "new_password": "newSecureP@ss456" }
```

| Error | Description |
|-------|-------------|
| 400   | Password shorter than 8 characters |
| 404   | User not found |

### PUT /api/v2/users/{username}/mfa

Enable or disable MFA for a user.

**Request**

```json
{ "enabled": true }
```

**Response** (when enabling)

```json
{
  "success": true,
  "data": {
    "mfa_enabled": true,
    "secret": "JBSWY3DPEBLW64TMMQ======",
    "otpauth_uri": "otpauth://totp/SSHProxy:alice?secret=JBSWY3DPEBLW64TMMQ======&issuer=SSHProxy"
  }
}
```

### GET /api/v2/users/{username}/mfa/qrcode

Returns a PNG QR code image for MFA enrollment.

**Response**

`Content-Type: image/png`

| Error | Description |
|-------|-------------|
| 404   | User not found or MFA not configured |

---

## Servers

### GET /api/v2/servers

List all upstream servers.

**Response**

```json
{
  "success": true,
  "data": [
    {
      "id": "srv-abc123",
      "name": "web-01",
      "host": "10.0.1.10",
      "port": 22,
      "group": "production",
      "status": "online",
      "healthy": true,
      "maintenance": false,
      "weight": 1,
      "max_sessions": 0,
      "tags": { "env": "prod" },
      "checked_at": "2025-01-15T10:30:00Z"
    }
  ],
  "total": 1,
  "page": 1,
  "per_page": 50
}
```

### POST /api/v2/servers

Register a new upstream server.

**Request**

```json
{
  "name": "web-02",
  "host": "10.0.1.11",
  "port": 22,
  "group": "production",
  "weight": 1,
  "max_sessions": 50,
  "tags": { "env": "prod" }
}
```

**Response** `201 Created`

| Error | Description |
|-------|-------------|
| 400   | Missing required fields |

### GET /api/v2/servers/health

Aggregate server health summary.

**Response**

```json
{
  "success": true,
  "data": {
    "total": 5,
    "healthy": 4,
    "unhealthy": 0,
    "maintenance": 1
  }
}
```

### GET /api/v2/servers/{id}

Get a single server.

| Error | Description |
|-------|-------------|
| 404   | Server not found |

### PUT /api/v2/servers/{id}

Update server fields (partial update).

**Request**

```json
{
  "name": "web-02-updated",
  "weight": 2,
  "max_sessions": 100
}
```

### DELETE /api/v2/servers/{id}

Remove a server.

| Error | Description |
|-------|-------------|
| 404   | Server not found |

### PUT /api/v2/servers/{id}/maintenance

Toggle maintenance mode.

**Request**

```json
{ "maintenance": true }
```

---

## Audit

### GET /api/v2/audit/events

List audit events with optional filters. When `audit_store_backend` is set to a
SQL or Elasticsearch/OpenSearch index, the control-plane serves results from
that mirrored index. Otherwise, when file-backed audit archive object storage
is enabled, the control-plane reads local `.jsonl`/`.log` files first and
automatically supplements missing files from the archived objects.

**Query Parameters**

| Param  | Description                    |
|--------|--------------------------------|
| `type` | Event type filter              |
| `user` | Username filter                |
| `from` | Start time (RFC 3339)          |
| `to`   | End time (RFC 3339)            |

**Response**

```json
{
  "success": true,
  "data": [
    {
      "id": "evt-001",
      "type": "auth.login",
      "user": "admin",
      "source_ip": "10.0.0.5",
      "timestamp": "2025-01-15T10:30:00Z",
      "details": {}
    }
  ],
  "total": 100,
  "page": 1,
  "per_page": 50
}
```

### GET /api/v2/audit/events/{id}

Get a single audit event. Indexed audit backends are queried directly when
enabled; otherwise archived object-backed audit files are included in the
lookup when local files are no longer present.

| Error | Description |
|-------|-------------|
| 404   | Event not found |

### GET /api/v2/audit/search

Full-text search across audit events, including indexed audit backends and
archived file-backed audit logs when object storage archival is enabled.

**Query Parameters**

| Param | Description  |
|-------|--------------|
| `q`   | Search query |

### GET /api/v2/audit/export

Export audit events. Indexed audit backends are used automatically when
configured; otherwise archived file-backed audit logs are included when object
storage archival is enabled.

**Response**

File download with `Content-Disposition` header.

### GET /api/v2/audit/stats

Audit event statistics and aggregates.

**Response**

```json
{
  "success": true,
  "data": {
    "total_events": 1520,
    "by_type": { "auth.login": 300, "session.start": 450 },
    "by_user": { "admin": 200, "alice": 150 }
  }
}
```

---

## Configuration

### GET /api/v2/config

Get the current configuration.

**Response**

```json
{
  "success": true,
  "data": {
    "max_sessions": 100,
    "session_timeout": 3600,
    "auth_timeout": 60
  }
}
```

### GET /api/v2/config/store

Return the persisted centralized configuration snapshot together with metadata
about the last writer and a sanitized config document.

**Response**

```json
{
  "success": true,
  "data": {
    "version": "20260408-011500.123456789",
    "change_id": "cfg-1234",
    "requester": "admin",
    "source": "node-1",
    "updated_at": "2026-04-08T01:15:00Z",
    "config": {
      "max_sessions": 100,
      "session_timeout": 3600
    }
  }
}
```

### GET /api/v2/config/templates

List the built-in environment templates exposed by the settings page.

**Response**

```json
{
  "success": true,
  "data": [
    {
      "name": "production",
      "environment": "production",
      "description": "Higher session capacity with stricter defaults for audited production environments.",
      "config": {
        "log_level": "warn",
        "log_format": "json",
        "max_sessions": 500,
        "session_timeout": 7200
      }
    }
  ]
}
```

### GET /api/v2/config/templates/{name}

Return one built-in template together with `resolved_config`, which is the
current config with the template overlay applied and sensitive values redacted.
The web UI uses this response to preview a diff and then submits the resolved
document through the normal config apply / approval pipeline.

### GET /api/v2/config/export

Export the current configuration as `json`, `yaml`, or `ini`.

**Query Parameters**

| Param    | Description                                |
|----------|--------------------------------------------|
| `format` | Optional export format (`json`, `yaml`, `ini`) |

**Response**

```json
{
  "success": true,
  "data": {
    "format": "ini",
    "content": "[server]\nbind_addr = 0.0.0.0\nport = 2222\n"
  }
}
```

This endpoint returns a raw config backup and may include secrets. Handle the
response content as sensitive material.

### POST /api/v2/config/import

Parse JSON, YAML, or INI configuration content and return a canonical config
document plus a sanitized diff preview. The import is **not** persisted until
the caller later submits the returned `config` document through `PUT /api/v2/config`.

**Request**

```json
{
  "format": "ini",
  "content": "[server]\nbind_addr = 127.0.0.1\nport = 2022\n"
}
```

**Response**

```json
{
  "success": true,
  "data": {
    "format": "ini",
    "config": {
      "bind_addr": "127.0.0.1",
      "port": 2022
    },
    "sanitized_config": {
      "bind_addr": "127.0.0.1",
      "port": 2022
    },
    "changed": true,
    "diff": "--- current\n+++ imported\n@@ -1,4 +1,4 @@\n {\n-  \"port\": 2222,\n+  \"port\": 2022,\n }\n"
  }
}
```

### PUT /api/v2/config

Update configuration values. Creates a version snapshot automatically.

When the control-plane JSON config sets `config_approval_enabled=true`, this
endpoint no longer applies the change immediately. It returns `202 Accepted`
with a persisted pending change request that must later be approved through the
config approval endpoints below.

When clustering is enabled, config mutation requests must be sent to the
current leader. After a successful apply on the leader, the desired config
snapshot is distributed automatically to followers and retried on subsequent
cluster sync cycles until followers converge.

**Request**

```json
{
  "max_sessions": 200,
  "session_timeout": 7200
}
```

| Error | Description |
|-------|-------------|
| 400   | Invalid configuration |
| 502   | Data-plane reload failed |

### POST /api/v2/config/changes

Create a pending configuration change request explicitly.

**Request**

```json
{
  "max_sessions": 200,
  "session_timeout": 7200
}
```

**Response** `201 Created`

```json
{
  "success": true,
  "data": {
    "id": "9f0a1b2c3d4e5f60",
    "requester": "alice",
    "status": "pending",
    "base_version": "20260408-011500.123456789",
    "payload": {
      "max_sessions": 200,
      "session_timeout": 7200
    }
  }
}
```

### GET /api/v2/config/changes

List persisted configuration change requests.

**Query Parameters**

| Param       | Description                       |
|-------------|-----------------------------------|
| `status`    | Filter by request status          |
| `requester` | Filter by submitting user         |
| `approver`  | Filter by decision maker          |

### GET /api/v2/config/changes/{id}

Get a single configuration change request together with its sanitized diff
preview against the stored base version.

### POST /api/v2/config/changes/{id}/approve

Approve a pending configuration change (admin only). The control-plane writes
the stored config payload, reloads the data plane, and marks the request
`applied` on success. In clustered deployments the response also includes the
current per-node `sync_status` view.

| Error | Description |
|-------|-------------|
| 400   | Request not pending or already expired |
| 502   | Apply/reload failed; request marked `failed` and config rolled back |

### POST /api/v2/config/changes/{id}/deny

Deny a pending configuration change (admin only). An optional JSON body may
include `{ "reason": "..." }` for audit context.

### GET /api/v2/config/sync-status

Return the cluster-wide config sync status. This endpoint is available only
when clustering is enabled.

**Response**

```json
{
  "success": true,
  "data": {
    "version": "20260408-011500.123456789",
    "change_id": "cfg-1234",
    "requester": "admin",
    "nodes": [
      {
        "node_id": "node-1",
        "node_name": "node-1",
        "role": "leader",
        "version": "20260408-011500.123456789",
        "status": "applied"
      },
      {
        "node_id": "node-2",
        "node_name": "node-2",
        "role": "follower",
        "version": "20260408-011500.123456789",
        "status": "pending"
      }
    ]
  }
}
```

### GET /api/v2/config/versions

List config version history.

**Response**

```json
{
  "success": true,
  "data": [
    {
      "version": "20250115-103000",
      "size": 1024,
      "timestamp": "2025-01-15T10:30:00Z"
    }
  ]
}
```

### GET /api/v2/config/versions/{version}

Get a specific config version. Sensitive values are redacted.

| Error | Description |
|-------|-------------|
| 404   | Version not found |

### POST /api/v2/config/diff

Compare the current or versioned configuration against another version or a pending config document.

**Request**

```json
{
  "from_version": "20250115-103000",
  "to_version": "current"
}
```

Or preview unsaved changes:

```json
{
  "to_config": {
    "max_sessions": 200,
    "session_timeout": 7200
  }
}
```

**Response**

```json
{
  "success": true,
  "data": {
    "from_version": "current",
    "to_version": "pending",
    "changed": true,
    "diff": "--- current\n+++ pending\n@@ -1,4 +1,4 @@\n {\n-  \"max_sessions\": 100,\n+  \"max_sessions\": 200,\n   \"session_timeout\": 7200\n }\n"
  }
}
```

### POST /api/v2/config/rollback

Rollback to a previous config version. In clustered deployments the restored
snapshot is also republished so followers converge on the same version.

**Request**

```json
{ "version": "20250115-103000" }
```

| Error | Description |
|-------|-------------|
| 400   | Invalid version |
| 404   | Version not found |
| 502   | Data-plane reload failed |

### POST /api/v2/config/reload

Force-reload the data-plane configuration. In clustered deployments the leader
also republishes the current snapshot so followers reload the same config.

**Response**

```json
{ "success": true, "data": { "message": "configuration reloaded" } }
```

| Error | Description |
|-------|-------------|
| 502   | Data-plane reload failed |

---

## Realtime WebSocket Endpoints

The control plane also exposes authenticated WebSocket endpoints for realtime UI
updates. They reuse the browser `session` cookie just like the HTML pages.

### GET /ws/dashboard

Pushes `dashboard.snapshot` messages containing:

- `stats`: dashboard aggregate counters
- `sessions`: recent sessions
- `events`: recent audit events
- `servers`: current server health snapshot

### GET /ws/sessions

Pushes `sessions.snapshot` messages for the session table. Supports the same
query filters as the REST list endpoint for `status`, `user`, and `ip`.

### GET /ws/sessions/{id}/live

Streams `session.live.chunk` messages by tailing the session recording file, so
the session detail dialog can follow active terminal output in near realtime.

### GET /ws/terminal

Browser terminal WebSocket used by `/terminal`. The terminal now passes raw
binary data frames in both directions so browser-side ZMODEM can support
drag-and-drop uploads and downloads, and it simultaneously writes a synced
asciicast audit recording that can be downloaded from the terminal page. In practice:

- run `rz` on the remote host to receive files dropped into the browser terminal
- run `sz <file>` on the remote host to trigger a browser download

Control messages such as resize and connection status still use small JSON text
frames with `{"type":"control", ... }`. Successful connection messages may also
include `recording_id` and `download_url` so the browser can expose the synced
audit cast immediately. When browser-terminal DLP rules are configured, the
page also sends `transfer_check` control messages before `rz`/`sz` transfers:

- browser → server: `{"type":"control","action":"transfer_check","request_id":"...","direction":"upload|download","name":"...","path":"...","size":123}`
- server → browser: `{"type":"control","action":"transfer_decision","request_id":"...","allowed":true|false,"reason":"..."}`

These checks are driven by the control-plane JSON config fields
`dlp_file_allow_*` / `dlp_file_deny_*`, plus
`dlp_file_max_upload_bytes` / `dlp_file_max_download_bytes`. Successful
`connected` frames may also include `sensitive_patterns` and
`sensitive_max_scan_bytes` so the browser can inspect file contents for
configured credit-card / ID-card / API-key detectors before upload or save, as
well as `transfer_approval_enabled` when sensitive matches can be escalated into
persisted approval requests, and `clipboard_audit_enabled` when browser-terminal
paste events should be audited with the same detector set.

### POST /api/v2/terminal/clipboard-audit

Record a browser-terminal clipboard paste audit event. The browser sends only
metadata such as target, paste source, text length, and matched detector IDs; it
does not upload the raw clipboard contents.

### POST /api/v2/terminal/transfer-approvals

Create or reuse a transfer approval request for a sensitive browser-terminal
file. If an equivalent request is already approved and still valid, the control
plane returns that approved request so the client can proceed immediately on the
next retry.

### GET /api/v2/terminal/transfer-approvals

List transfer approval requests. Non-approvers only see their own requests.

### GET /api/v2/terminal/transfer-approvals/{id}

Get a single transfer approval request.

### POST /api/v2/terminal/transfer-approvals/{id}/approve

Approve a pending transfer approval request.

### POST /api/v2/terminal/transfer-approvals/{id}/deny

Deny a pending transfer approval request.

---

## System

### GET /api/v2/system/health

Detailed health status.

**Response**

```json
{
  "success": true,
  "data": {
    "status": "healthy",
    "data_plane": "healthy",
    "uptime_seconds": 3600,
    "timestamp": "2025-01-15T10:30:00Z"
  }
}
```

### GET /api/v2/system/info

System and runtime information.

**Response**

```json
{
  "success": true,
  "data": {
    "version": "2.0.0",
    "go_version": "go1.21",
    "os": "linux",
    "arch": "amd64",
    "hostname": "proxy-01",
    "num_goroutines": 42,
    "num_cpus": 8,
    "memory_alloc": 10485760,
    "memory_sys": 20971520,
    "uptime_seconds": 3600,
    "started_at": "2025-01-15T09:30:00Z"
  }
}
```

### GET /api/v2/system/upgrade

Returns the local rolling-upgrade state. The payload exposes whether drain mode is
enabled, how many active SSH sessions remain on the node, and whether it is safe
to restart the node without breaking cluster availability. When cluster nodes are
labeled with `region` / `zone` metadata, the payload also includes a topology
summary and marks the node unsafe to restart if it is the last healthy member of
its region or availability zone.

**Response**

```json
{
  "success": true,
  "data": {
    "status": "draining",
    "draining": true,
    "active_sessions": 0,
    "ready_for_restart": true,
    "cluster": {
      "enabled": true,
      "role": "follower",
      "leader": "cp-1",
      "other_healthy_nodes": 2,
      "topology": {
        "self_region": "ap-southeast-1",
        "self_zone": "ap-southeast-1/ap-southeast-1b",
        "healthy_regions": ["ap-southeast-1", "ap-southeast-2"],
        "healthy_zones": [
          "ap-southeast-1/ap-southeast-1a",
          "ap-southeast-1/ap-southeast-1b",
          "ap-southeast-2/ap-southeast-2a"
        ],
        "cross_region_redundant": true,
        "cross_zone_redundant": true,
        "last_healthy_in_region": false,
        "last_healthy_in_zone": false
      }
    },
    "timestamp": "2025-01-15T10:35:00Z"
  }
}
```

### PUT /api/v2/system/upgrade

Enables or disables local drain mode. When draining is enabled, the data-plane
health endpoint returns `503` with `status=draining`, new SSH sessions are
rejected, and existing sessions continue until they exit naturally. Cluster
leaders refuse to drain when they are the last healthy node, and topology-aware
clusters also refuse to drain the last healthy node in a region or availability
zone.

**Request**

```json
{
  "draining": true
}
```

**Response**

Returns the same payload as `GET /api/v2/system/upgrade`.

### GET /api/v2/system/metrics

Prometheus-format metrics.

**Response**

```
Content-Type: text/plain

# HELP ssh_proxy_active_sessions Current active sessions
ssh_proxy_active_sessions 12
...
```

---

## SSH Certificate Authority

### POST /api/v2/ca/sign-user

Sign a user SSH certificate.

**Request**

```json
{
  "public_key": "ssh-ed25519 AAAA...",
  "principals": ["alice", "deploy"],
  "ttl": "8h",
  "force_command": "",
  "source_addresses": ["10.0.0.0/8"]
}
```

**Response**

```json
{
  "success": true,
  "data": {
    "certificate": "ssh-ed25519-cert-v01@openssh.com AAAA...",
    "serial": 1001,
    "key_id": "alice-20250115",
    "expires_at": "2025-01-15T18:30:00Z"
  }
}
```

| Error | Description |
|-------|-------------|
| 400   | Invalid public key or parameters |
| 503   | Certificate authority not configured |

### POST /api/v2/ca/sign-host

Sign a host SSH certificate.

**Request**

```json
{
  "public_key": "ssh-ed25519 AAAA...",
  "hostname": "web-01.example.com",
  "ttl": "720h"
}
```

**Response**

Same structure as sign-user.

| Error | Description |
|-------|-------------|
| 400   | Invalid public key or missing hostname |
| 503   | Certificate authority not configured |

### GET /api/v2/ca/public-keys

Get CA public keys.

**Query Parameters**

| Param    | Description                      |
|----------|----------------------------------|
| `format` | `text` for plain text, otherwise JSON |

**Response (JSON)**

```json
{
  "success": true,
  "data": {
    "user_ca_public_key": "ssh-ed25519 AAAA...",
    "host_ca_public_key": "ssh-ed25519 AAAA..."
  }
}
```

### GET /api/v2/ca/certs

List all issued certificates (paginated).

**Response**

```json
{
  "success": true,
  "data": [
    {
      "serial": 1001,
      "key_id": "alice-20250115",
      "type": "user",
      "principals": ["alice"],
      "valid_after": "2025-01-15T10:30:00Z",
      "valid_before": "2025-01-15T18:30:00Z",
      "revoked": false
    }
  ],
  "total": 25,
  "page": 1,
  "per_page": 50
}
```

### GET /api/v2/ca/crl

Export the current certificate revocation list.

**Query Parameters**

| Param    | Description                               |
|----------|-------------------------------------------|
| `format` | `text` for newline-delimited serials, otherwise JSON |

**Response (JSON)**

```json
{
  "success": true,
  "data": {
    "revoked_serials": [1001, 1002],
    "count": 2
  }
}
```

### POST /api/v2/ca/revoke

Revoke a certificate by serial number.

**Request**

```json
{ "serial": 1001 }
```

Also accepts `?serial=1001` as a query parameter.

**Response**

```json
{ "success": true, "data": { "message": "certificate revoked" } }
```

| Error | Description |
|-------|-------------|
| 400   | Missing or invalid serial |
| 404   | Certificate not found |
| 503   | Certificate authority not configured |

---

## JIT Access

All JIT endpoints require the `X-User` header. Approve/deny actions require
an admin role (`X-Role: admin` or a role listed in the JIT policy's `approver_roles`).
When the control-plane JSON config includes `jit_notify_email_to`,
`jit_notify_slack_webhook_url`, `jit_notify_dingtalk_webhook_url`, or
`jit_notify_wecom_webhook_url`, or `jit_notify_teams_webhook_url`,
`jit_notify_pagerduty_routing_key`, or `jit_notify_opsgenie_api_key`, the
`notify_on_request` / `notify_on_approve` policy flags fan out JIT events to
those approver channels and alerting systems.

When `jit_chatops_slack_signing_secret` is configured, Slack slash commands can
also call `POST /api/v2/chatops/slack/commands` without a session cookie. The
control-plane verifies Slack's HMAC signature, maps `user_name` to a local user,
and reuses that user's role for ChatOps approvals.

`jit_notify_subject_template` / `jit_notify_body_template` can override the
default JIT event notification rendering, while
`jit_notify_message_subject_template` / `jit_notify_message_body_template`
customize generic message notifications sent through the same sink fan-out.

### POST /api/v2/jit/requests

Create a just-in-time access request. Set `break_glass=true` with an incident
`ticket` to activate the emergency-access fast path when the current JIT policy
allows it.

**Request**

```json
{
  "target": "db-01.prod",
  "role": "operator",
  "reason": "Investigate slow queries",
  "ticket": "INC-12345",
  "break_glass": false,
  "duration": "2h"
}
```

### POST /api/v2/chatops/slack/commands

Slack slash-command endpoint for JIT ChatOps. The request is standard
`application/x-www-form-urlencoded` Slack command payload plus
`X-Slack-Signature` and `X-Slack-Request-Timestamp` headers. Supported commands
are `jit show <request-id>`, `jit approve <request-id>`, and
`jit deny <request-id> [reason]`.

**Response** `201 Created`

```json
{
  "success": true,
  "data": {
    "id": "jit-abc123",
    "requester": "alice",
    "target": "db-01.prod",
    "role": "operator",
    "reason": "Investigate slow queries",
    "ticket": "INC-12345",
    "break_glass": false,
    "duration": "2h0m0s",
    "status": "pending",
    "created_at": "2025-01-15T10:30:00Z"
  }
}
```

| Error | Description |
|-------|-------------|
| 400   | Missing required fields or invalid duration |
| 401   | `X-User` header missing |
| 503   | JIT access not enabled |

### GET /api/v2/jit/requests

List JIT requests with optional filters.

**Query Parameters**

| Param       | Description                |
|-------------|----------------------------|
| `status`    | pending, approved, denied, expired, revoked |
| `requester` | Filter by requester        |
| `target`    | Filter by target           |
| `since`     | Start time (RFC 3339)      |
| `until`     | End time (RFC 3339)        |

### GET /api/v2/jit/requests/{id}

Get a single JIT request.

| Error | Description |
|-------|-------------|
| 404   | Request not found |

### POST /api/v2/jit/requests/{id}/approve

Approve the current stage of a pending JIT request. Requires a role allowed by
the request's current approval stage. In multi-stage workflows the request stays
`pending` until the final stage is approved.

**Response**

```json
{
  "success": true,
  "data": {
    "id": "jit-abc123",
    "status": "pending",
    "current_stage": 1,
    "current_approver_roles": ["admin"]
  }
}
```

| Error | Description |
|-------|-------------|
| 400   | Request not in pending state |
| 401   | Authentication required |
| 403   | Caller role is not allowed for the current approval stage |

### POST /api/v2/jit/requests/{id}/deny

Deny a pending JIT request at its current approval stage.

**Request**

```json
{ "reason": "Not authorized for production access" }
```

| Error | Description |
|-------|-------------|
| 400   | Request not in pending state |
| 403   | Caller role is not allowed for the current approval stage |

### POST /api/v2/jit/requests/{id}/revoke

Revoke a previously approved JIT request.

| Error | Description |
|-------|-------------|
| 400   | Request not in approved state |

### GET /api/v2/jit/grants

List all active access grants.

**Response**

```json
{
  "success": true,
  "data": [
    {
      "id": "grant-abc123",
      "request_id": "jit-abc123",
      "user": "alice",
      "target": "db-01.prod",
      "role": "operator",
      "granted_at": "2025-01-15T10:35:00Z",
      "expires_at": "2025-01-15T12:35:00Z"
    }
  ],
  "total": 1
}
```

### GET /api/v2/jit/check

Check if a user has active JIT access to a target.

**Query Parameters** (both required)

| Param    | Description         |
|----------|---------------------|
| `user`   | Username to check   |
| `target` | Target to check     |

**Response**

```json
{
  "success": true,
  "data": {
    "has_access": true,
    "user": "alice",
    "target": "db-01.prod",
    "grant": { ... }
  }
}
```

| Error | Description |
|-------|-------------|
| 400   | Missing user or target |

### GET /api/v2/jit/policy

Get the current JIT policy.

**Response**

```json
{
  "success": true,
  "data": {
    "max_duration": "24h0m0s",
    "auto_approve": false,
    "auto_approve_for": ["admin"],
    "auto_approve_rules": [
      {
        "name": "viewer-staging",
        "targets": ["staging-*"],
        "roles": ["viewer"],
        "max_duration": "30m0s"
      }
    ],
    "require_reason": true,
    "approver_roles": ["admin"],
    "approval_stages": [
      {
        "name": "security",
        "approver_roles": ["security"],
        "required_approvals": 1
      },
      {
        "name": "admin",
        "approver_roles": ["admin"],
        "required_approvals": 1
      }
    ],
    "break_glass_enabled": true,
    "break_glass_max_duration": "1h0m0s",
    "break_glass_roles": ["operator"],
    "break_glass_targets": ["prod-*"],
    "notify_on_request": true,
    "notify_on_approve": true
  }
}
```

### PUT /api/v2/jit/policy

Update the JIT policy. Requires admin role.

**Request**

```json
{
  "max_duration": "24h",
  "auto_approve": false,
  "auto_approve_for": ["admin"],
  "auto_approve_rules": [
    {
      "name": "viewer-staging",
      "targets": ["staging-*"],
      "roles": ["viewer"],
      "max_duration": "30m"
    }
  ],
  "require_reason": true,
  "approver_roles": ["admin"],
  "approval_stages": [
    {
      "name": "security",
      "approver_roles": ["security"],
      "required_approvals": 1
    },
    {
      "name": "admin",
      "approver_roles": ["admin"],
      "required_approvals": 1
    }
  ],
  "break_glass_enabled": true,
  "break_glass_max_duration": "1h",
  "break_glass_roles": ["operator"],
  "break_glass_targets": ["prod-*"],
  "notify_on_request": true,
  "notify_on_approve": true
}
```

| Error | Description |
|-------|-------------|
| 400   | Invalid max_duration |
| 403   | Admin role required |

---

## Cluster

### GET /api/v2/cluster/status

Cluster overview including node role, leader, member count, and cross-AZ /
cross-region topology spread when nodes publish region / zone metadata.

**Response**

```json
{
  "success": true,
  "data": {
    "node_id": "node-1",
    "role": "leader",
    "status": "active",
    "leader": "node-1",
    "term": 5,
    "node_count": 3,
    "nodes": [],
    "topology": {
      "self_region": "ap-southeast-1",
      "self_zone": "ap-southeast-1/ap-southeast-1a",
      "healthy_regions": ["ap-southeast-1", "ap-southeast-2"],
      "healthy_zones": [
        "ap-southeast-1/ap-southeast-1a",
        "ap-southeast-1/ap-southeast-1b",
        "ap-southeast-2/ap-southeast-2a"
      ],
      "cross_region_redundant": true,
      "cross_zone_redundant": true
    }
  }
}
```

| Error | Description |
|-------|-------------|
| 503   | Clustering not enabled |

### GET /api/v2/cluster/nodes

List all cluster members.

**Response**

```json
{
  "success": true,
  "data": [
    {
      "id": "node-1",
      "address": "10.0.0.1:8444",
      "api_addr": "https://cp-1.example.com",
      "role": "leader",
      "status": "healthy",
      "metadata": { "region": "ap-southeast-1", "zone": "ap-southeast-1a" }
    },
    {
      "id": "node-2",
      "address": "10.0.0.2:8444",
      "api_addr": "https://cp-2.example.com",
      "role": "follower",
      "status": "healthy",
      "metadata": { "region": "ap-southeast-1", "zone": "ap-southeast-1b" }
    }
  ],
  "total": 2
}
```

### POST /api/v2/cluster/join

Join the cluster using seed addresses or discovery URIs.

**Request**

```json
{
  "seeds": [
    "10.0.0.1:8444",
    "dns://ssh-proxy.internal:8444",
    "k8s://ssh-proxy.default:8444",
    "consul://consul.service.consul:8500/ssh-proxy?tag=prod"
  ]
}
```

`dns://` resolves A/AAAA records, `k8s://` expands Kubernetes service names such
as `service.namespace` to `service.namespace.svc.cluster.local`, and
`consul://` queries Consul's health API for healthy service instances.

| Error | Description |
|-------|-------------|
| 400   | No seed addresses provided |
| 502   | Failed to join cluster |

### POST /api/v2/cluster/leave

Gracefully leave the cluster.

| Error | Description |
|-------|-------------|
| 500   | Failed to leave cluster |

### GET /api/v2/cluster/leader

Get the current cluster leader.

**Response**

```json
{
  "success": true,
  "data": { "id": "node-1", "addr": "10.0.0.1:8444", "role": "leader" }
}
```

---

## Compliance

### GET /api/v2/compliance/frameworks

List supported compliance frameworks.

**Response**

```json
{
  "success": true,
  "data": [
    { "id": "soc2", "name": "SOC 2", "description": "Service Organization Control 2 - Trust Services Criteria" },
    { "id": "hipaa", "name": "HIPAA", "description": "Health Insurance Portability and Accountability Act" },
    { "id": "gdpr", "name": "GDPR", "description": "General Data Protection Regulation" },
    { "id": "pci-dss", "name": "PCI DSS", "description": "Payment Card Industry Data Security Standard" },
    { "id": "iso27001", "name": "ISO 27001", "description": "Information Security Management System" },
    { "id": "mlps-2.0", "name": "MLPS 2.0", "description": "Chinese Multi-Level Protection Scheme 2.0 baseline audit report" },
    { "id": "mlps-3.0", "name": "MLPS 3.0", "description": "Chinese Multi-Level Protection Scheme 3.0 enhanced audit report" }
  ],
  "total": 7
}
```

### POST /api/v2/compliance/reports

Generate a compliance report.

**Request**

```json
{
  "framework": "soc2",
  "start": "2025-01-01T00:00:00Z",
  "end": "2025-01-31T23:59:59Z"
}
```

**Response** `201 Created`

```json
{
  "success": true,
  "data": {
    "id": "rpt-abc123",
    "framework": "soc2",
    "generated_at": "2025-01-15T10:30:00Z",
    "generated_by": "admin",
    "score": 92.5,
    "pass_count": 37,
    "fail_count": 3,
    "total_count": 40,
    "findings": []
  }
}
```

| Error | Description |
|-------|-------------|
| 400   | Missing or unsupported framework |
| 503   | Compliance reporting not enabled |

### GET /api/v2/compliance/reports

List generated reports (paginated).

### GET /api/v2/compliance/reports/{id}

Get a single report.

| Error | Description |
|-------|-------------|
| 404   | Report not found |

### GET /api/v2/compliance/reports/{id}/export

Export a report as CSV or JSON file.

**Query Parameters**

| Param    | Description               |
|----------|---------------------------|
| `format` | `csv` or `json` (default) |

**Response**

File download with `Content-Disposition` header.

### POST /api/v2/compliance/gdpr/reports

Generate a GDPR subject access or deletion report for one user.

**Request**

```json
{
  "type": "deletion",
  "subject": "alice",
  "start": "2024-01-01T00:00:00Z",
  "end": "2026-12-31T23:59:59Z"
}
```

- `type` supports `access` (default) and `deletion`.
- `subject` is required.

**Response** `201 Created`

```json
{
  "success": true,
  "data": {
    "id": "gdpr-abc123",
    "kind": "deletion",
    "subject": "alice",
    "generated_at": "2026-04-09T08:00:00Z",
    "generated_by": "admin",
    "artifacts": [
      { "kind": "user_account", "count": 0 },
      { "kind": "session_metadata", "count": 3 },
      { "kind": "audit_events", "count": 12 }
    ],
    "deletion_checks": [
      { "scope": "user_account", "status": "removed", "detail": "No active control-plane user record was found" },
      { "scope": "session_metadata", "status": "retained", "detail": "3 historical session records remain for auditability" },
      { "scope": "audit_events", "status": "retained", "detail": "12 audit events remain under security retention requirements" }
    ]
  }
}
```

### GET /api/v2/compliance/gdpr/reports

List generated GDPR subject reports (paginated).

### GET /api/v2/compliance/gdpr/reports/{id}

Get a single GDPR subject report.

### GET /api/v2/compliance/gdpr/reports/{id}/export

Export a GDPR subject report as CSV or JSON file.

**Query Parameters**

| Param    | Description               |
|----------|---------------------------|
| `format` | `csv` or `json` (default) |

### GET /api/v2/compliance/templates

List saved custom SQL report templates.

### POST /api/v2/compliance/templates

Create a custom SQL report template.

**Request**

```json
{
  "name": "Sessions by user",
  "description": "Aggregate persisted session rows by username",
  "query": "SELECT username, COUNT(*) AS sessions FROM sessions GROUP BY username ORDER BY username",
  "default_format": "csv"
}
```

- Queries must be a single read-only `SELECT`/`WITH` statement.
- Available snapshot tables are `users`, `sessions`, `audit_events`, and `servers`.
- `default_format` supports `csv` and `pdf`.

### GET /api/v2/compliance/templates/{id}

Get one custom SQL report template.

### PUT /api/v2/compliance/templates/{id}

Update one custom SQL report template.

### DELETE /api/v2/compliance/templates/{id}

Delete one custom SQL report template.

### GET /api/v2/compliance/templates/{id}/export

Render and export a custom SQL report template.

**Query Parameters**

| Param    | Description               |
|----------|---------------------------|
| `format` | `csv` or `pdf`            |

### GET /api/v2/compliance/schedules

List saved scheduled report jobs.

### POST /api/v2/compliance/schedules

Create a scheduled report job.

**Request**

```json
{
  "name": "Nightly template export",
  "type": "template",
  "template_id": "tpl-abc123",
  "format": "pdf",
  "interval": "24h",
  "recipients": ["audit@example.com"]
}
```

- `type` supports `framework`, `gdpr`, and `template`.
- `interval` and optional `lookback` use Go duration syntax such as `1h`, `24h`, `7d`-style equivalents like `168h`.
- Scheduled emails reuse the configured SMTP relay from `jit_notify_smtp_*` and `jit_notify_email_from`.

### GET /api/v2/compliance/schedules/{id}

Get one scheduled report job.

### PUT /api/v2/compliance/schedules/{id}

Update one scheduled report job.

### DELETE /api/v2/compliance/schedules/{id}

Delete one scheduled report job.

### POST /api/v2/compliance/schedules/{id}/run

Run a scheduled report immediately and send the email attachment to its configured recipients.

### GET /api/v2/compliance/score

Get compliance scores across all frameworks.

**Response**

```json
{
  "success": true,
  "data": {
    "soc2":    { "score": 92.5, "pass_count": 37, "fail_count": 3, "total_count": 40 },
    "hipaa":   { "score": 88.0, "pass_count": 22, "fail_count": 3, "total_count": 25 },
    "gdpr":    { "score": 95.0, "pass_count": 19, "fail_count": 1, "total_count": 20 },
    "pci-dss": { "score": 90.0, "pass_count": 27, "fail_count": 3, "total_count": 30 },
    "iso27001":{ "score": 87.5, "pass_count": 35, "fail_count": 5, "total_count": 40 },
    "mlps-2.0":{ "score": 91.0, "pass_count": 10, "fail_count": 1, "total_count": 11 },
    "mlps-3.0":{ "score": 89.0, "pass_count": 8, "fail_count": 1, "total_count": 9 }
  }
}
```

---

## SIEM

### GET /api/v2/siem/config

Get the current SIEM integration configuration (token redacted).

**Response**

```json
{
  "success": true,
  "data": {
    "endpoint": "https://siem.example.com/api/events",
    "token": "***",
    "type": "splunk"
  }
}
```

| Error | Description |
|-------|-------------|
| 503   | SIEM integration not enabled |

### PUT /api/v2/siem/config

Update SIEM configuration. Replaces the active forwarder.

Supported `type` values: `splunk`, `datadog`, `elastic`, `logstash`, `sumo`, `syslog`, `qradar`, `wazuh`, `webhook`.

**Request**

```json
{
  "endpoint": "https://siem.example.com/api/events",
  "token": "your-api-token",
  "type": "splunk"
}
```

| Error | Description |
|-------|-------------|
| 400   | Missing endpoint |

### POST /api/v2/siem/test

Send a test event to the configured SIEM endpoint.

**Response**

```json
{ "success": true, "data": { "message": "test event sent successfully" } }
```

| Error | Description |
|-------|-------------|
| 500   | Failed to send or flush test event |

### GET /api/v2/siem/status

Get SIEM forwarder runtime status.

**Response**

```json
{
  "success": true,
  "data": {
    "type": "splunk",
    "endpoint": "https://siem.example.com/api/events",
    "running": true,
    "buffer_size": 42,
    "last_flush": "2025-01-15T10:29:00Z",
    "last_error": "",
    "events_sent": 15230
  }
}
```

---

## Threat Detection

When the control-plane JSON config sets `data_plane_config_file` and
`geoip_data_file`, the detector can accept signed SSH data-plane webhook events
from `POST /api/v2/threats/ingest`, resolve source IPs to locations, and attach
GeoIP-backed evidence to `impossible_travel` alerts instead of relying only on
the legacy IP-prefix heuristic.

It also maintains a multi-factor contextual `risk_assessment` for each
user/source tuple by combining GeoIP movement, device fingerprint, source
network type, recent auth failures, and rapid multi-target access.

### GET /api/v2/threats/alerts

List threat alerts with optional filters.

**Query Parameters**

| Param       | Description                          |
|-------------|--------------------------------------|
| `severity`  | low, medium, high, critical          |
| `status`    | new, acknowledged, resolved, false_positive |
| `username`  | Filter by username                   |
| `source_ip` | Filter by source IP                  |
| `rule_id`   | Filter by detection rule             |

**Response**

```json
{
  "success": true,
  "data": [
    {
      "id": "alert-001",
      "rule_id": "brute-force",
      "severity": "high",
      "status": "new",
      "username": "unknown",
      "source_ip": "203.0.113.50",
      "message": "Brute force detected",
      "created_at": "2025-01-15T10:30:00Z"
    }
  ],
  "total": 1,
  "page": 1,
  "per_page": 50
}
```

| Error | Description |
|-------|-------------|
| 503   | Threat detection not enabled |

### GET /api/v2/threats/alerts/{id}

Get a single threat alert.

| Error | Description |
|-------|-------------|
| 404   | Alert not found |

### POST /api/v2/threats/alerts/{id}/ack

Acknowledge a threat alert.

**Request**

```json
{ "user": "admin" }
```

| Error | Description |
|-------|-------------|
| 404   | Alert not found |

### POST /api/v2/threats/alerts/{id}/resolve

Resolve a threat alert.

**Request**

```json
{ "user": "admin" }
```

### POST /api/v2/threats/alerts/{id}/false-positive

Mark a threat alert as a false positive.

**Request**

```json
{ "user": "admin" }
```

### GET /api/v2/threats/rules

List all threat detection rules, including built-in rules and JSON DSL-based
custom rules.

**Response**

```json
{
  "success": true,
  "data": [
    {
      "id": "brute_force",
      "name": "Brute Force Attack",
      "builtin": true,
      "enabled": true,
      "conditions": {
        "threshold": 10,
        "window": 300000000000
      },
      "severity": "high"
    }
  ],
  "total": 11
}
```

### POST /api/v2/threats/rules

Create a custom threat rule. Custom rules support generic pattern / threshold
rules as well as a recursive JSON DSL (`type: "dsl"`).

**Request**

```json
{
  "name": "Kubectl Exec Detection",
  "type": "dsl",
  "severity": "high",
  "event_types": ["command"],
  "expression": {
    "operator": "and",
    "children": [
      { "operator": "contains", "field": "details.command", "value": "kubectl" },
      { "operator": "contains", "field": "details.command", "value": "exec" }
    ]
  }
}
```

### PUT /api/v2/threats/rules/{id}

Update a threat detection rule. Built-in rules support persisted overrides such
as `enabled`, `threshold`, `window`, and `pattern`; custom rules can also
update `name`, `description`, `severity`, and `expression`.

**Request**

```json
{
  "enabled": true,
  "threshold": 10,
  "window": "10m",
  "pattern": ".*",
  "severity": "medium"
}
```

| Error | Description |
|-------|-------------|
| 400   | Invalid window duration |
| 404   | Rule not found |

### DELETE /api/v2/threats/rules/{id}

Delete a custom threat rule. Built-in rules cannot be deleted.

### GET /api/v2/threats/risk

List the latest contextual risk assessments. Supports optional `username`,
`source_ip`, and `level` filters.

### GET /api/v2/threats/stats

Get threat detection statistics.

Besides alert counts, the response includes `dynamic_risk_score`,
`risk_assessment_count`, `by_risk_level`, and `top_risk_entities`.

**Response**

```json
{
  "success": true,
  "data": {
    "total_alerts": 150,
    "by_severity": { "critical": 5, "high": 30, "medium": 65, "low": 50 },
    "by_status": { "new": 10, "acknowledged": 20, "resolved": 115, "false_positive": 5 }
  }
}
```

### POST /api/v2/threats/simulate

Simulate a threat event for testing. Accepts a full `threat.Event` object and
returns both generated alerts and the resulting `risk_assessment`.

**Request**

```json
{
  "type": "auth.failure",
  "username": "test",
  "source_ip": "203.0.113.50",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

**Response**

```json
{
  "success": true,
  "data": {
    "alerts_generated": 1,
    "alerts": [ { "id": "alert-sim-001", "rule_id": "brute-force" } ]
  }
}
```

### POST /api/v2/threats/ingest

Accept a signed data-plane webhook event and feed it into the runtime threat
detector. This endpoint is intentionally public so the C data plane can call
it directly, but it verifies the configured `Authorization` header and/or
`X-SSH-Proxy-Signature: sha256=<hex>` HMAC taken from the data-plane webhook
config file.

Typical deployment flow:

1. Set control-plane `data_plane_config_file` to the managed `config.ini`.
2. Set control-plane `geoip_data_file` to a JSON CIDR-to-location database.
3. Point the data-plane `[webhook] url` at `/api/v2/threats/ingest`.
4. Configure `auth_header` and/or `hmac_secret` under `[webhook]`.

When the data-plane config also defines `[network_sources] office_cidrs` and
`vpn_cidrs`, ingest classifies each source as `office`, `vpn`, or `public`.
For `session.start` and `session.end`, it additionally enriches the event with
the matching session's `client_version`, `client_os`, and `device_fingerprint`
before evaluating contextual risk.

**Request**

```json
{
  "event": "auth.success",
  "timestamp": 1736937000,
  "username": "alice",
  "client_addr": "203.0.113.10",
  "detail": "ubuntu@db-01.prod:22"
}
```

**Response**

```json
{
  "success": true,
  "data": {
    "accepted": true,
    "event": "auth.success",
    "handled": true,
    "alerts_generated": 1,
    "alerts": [
      {
        "id": "alert-geo-001",
        "rule_id": "impossible_travel"
      }
    ]
  }
}
```

Events unrelated to threat rules (for example `upstream.healthy`) are accepted
and acknowledged with `"handled": false` so they do not accumulate in the
data-plane webhook dead-letter queue.

| Error | Description |
|-------|-------------|
| 400   | Invalid JSON payload |
| 401   | Missing or invalid webhook signature / authorization header |
| 403   | Event is not enabled in the data-plane webhook config |
| 503   | Data-plane webhook verification is not configured |

---

## Discovery

### POST /api/v2/discovery/scan

Trigger a network scan for SSH hosts.

**Request**

```json
{
  "targets": ["10.0.1.0/24", "10.0.2.0/24"],
  "ports": [22, 2222],
  "timeout": "5s",
  "concurrency": 50,
  "ssh_banner": true
}
```

**Response**

```json
{
  "success": true,
  "data": {
    "results": [
      { "host": "10.0.1.5", "port": 22, "banner": "SSH-2.0-OpenSSH_9.0" }
    ],
    "total": 15,
    "new_assets": 3
  }
}
```

| Error | Description |
|-------|-------------|
| 400   | Missing targets |
| 500   | Scan failed |

### POST /api/v2/discovery/cloud/import

Import provider-native cloud instance inventory JSON into the shared discovery
inventory.

**Request**

```json
{
  "provider": "aws",
  "content": {
    "Reservations": [{
      "Instances": [{
        "InstanceId": "i-1234567890",
        "PrivateIpAddress": "10.0.10.15",
        "Tags": [
          { "Key": "Name", "Value": "prod-bastion" },
          { "Key": "env", "Value": "prod" }
        ]
      }]
    }]
  },
  "tag_filters": { "env": "prod" },
  "auto_register": true
}
```

`provider` accepts `aws`, `azure`, `gcp`, `aliyun`, and `tencent`. Instead of
embedding `content`, you can provide `uri` pointing at `http://...` or
`https://...`; optional `headers` are forwarded for HTTP fetches.

**Response**

```json
{
  "success": true,
  "data": {
    "provider": "aws",
    "imported": 1,
    "new_assets": 1,
    "auto_register": true
  }
}
```

| Error | Description |
|-------|-------------|
| 400   | Missing provider / invalid payload / unsupported provider |
| 500   | Inventory persistence failed |

### POST /api/v2/discovery/cmdb/import

Import CMDB inventory JSON into the shared discovery inventory.

**Request**

```json
{
  "provider": "servicenow",
  "content": {
    "result": [{
      "sys_id": "cmdb-123",
      "name": "prod-app-01",
      "ip_address": "10.20.10.25",
      "os": "Ubuntu 22.04",
      "u_ssh_port": "2222",
      "environment": "prod"
    }]
  }
}
```

`provider` accepts `servicenow` and `custom-api`. `servicenow` has built-in
field defaults. `custom-api` uses explicit `items_path`, `host_field`,
`id_field`, `name_field`, `port_field`, `os_field`, `status_field`,
`tag_fields`, and `static_tags` mappings so arbitrary HTTP JSON payloads can be
projected into discovery assets.

**Response**

```json
{
  "success": true,
  "data": {
    "provider": "servicenow",
    "imported": 1,
    "new_assets": 1,
    "auto_register": false
  }
}
```

| Error | Description |
|-------|-------------|
| 400   | Missing provider / invalid mapping / unsupported provider |
| 500   | Inventory persistence failed |

### POST /api/v2/discovery/ansible/import

Import Ansible inventory into the shared discovery inventory.

**Request**

```json
{
  "format": "json",
  "content": {
    "_meta": {
      "hostvars": {
        "web-1": {
          "ansible_host": "10.50.0.10",
          "ansible_port": "2222",
          "env": "prod"
        }
      }
    },
    "web": {
      "hosts": ["web-1"]
    }
  }
}
```

`format` accepts `json`, `ini`, or can be omitted for auto-detect. JSON imports
match `ansible-inventory --list`; INI imports use `content_text` or an HTTP(S)
`uri` that serves the classic inventory syntax.

**Response**

```json
{
  "success": true,
  "data": {
    "format": "json",
    "imported": 1,
    "new_assets": 1,
    "auto_register": false
  }
}
```

| Error | Description |
|-------|-------------|
| 400   | Invalid Ansible payload |
| 500   | Inventory persistence failed |

### GET /api/v2/discovery/sources

List persisted discovery sync sources used for scheduled imports.

### POST /api/v2/discovery/sources

Create a persisted discovery sync source definition.

**Request**

```json
{
  "name": "aws-prod-sync",
  "kind": "cloud",
  "provider": "aws",
  "interval": "15m",
  "auto_register": true,
  "uri": "https://inventory.example.com/aws.json",
  "headers": {
    "Authorization": "Bearer <token>"
  }
}
```

`kind` accepts `cloud`, `cmdb`, and `ansible`. The source can use inline
`content` / `content_text` or an HTTP(S) `uri`. Background sync will run the
source on the requested `interval`, update existing assets in place, and mark
previously seen assets from that source `offline` when they are absent from a
later successful run.

**Response**

```json
{
  "success": true,
  "data": {
    "id": "discsrc-1234abcd",
    "name": "aws-prod-sync",
    "kind": "cloud",
    "provider": "aws",
    "interval": "15m",
    "enabled": true,
    "auto_register": true
  }
}
```

| Error | Description |
|-------|-------------|
| 400   | Invalid source definition |
| 500   | Source persistence failed |

### GET /api/v2/discovery/sources/{id}

Get one persisted discovery sync source.

| Error | Description |
|-------|-------------|
| 404   | Source not found |

### PUT /api/v2/discovery/sources/{id}

Replace one persisted discovery sync source definition.

### DELETE /api/v2/discovery/sources/{id}

Delete one persisted discovery sync source definition.

| Error | Description |
|-------|-------------|
| 404   | Source not found |

### POST /api/v2/discovery/sources/{id}/run

Run one persisted discovery sync source immediately.

**Response**

```json
{
  "success": true,
  "data": {
    "source": {
      "id": "discsrc-1234abcd",
      "name": "aws-prod-sync",
      "kind": "cloud",
      "provider": "aws"
    },
    "result": {
      "imported": 12,
      "new_assets": 2,
      "offlined": 1,
      "registered": 12
    }
  }
}
```

| Error | Description |
|-------|-------------|
| 400   | Invalid source configuration or payload |
| 404   | Source not found |
| 500   | Sync execution failed |

### GET /api/v2/discovery/assets

List discovered assets with optional filters.

**Query Parameters**

| Param    | Description            |
|----------|------------------------|
| `status` | Filter by status       |
| `host`   | Filter by hostname/IP  |
| `os`     | Filter by OS           |
| `tag`    | Filter by tag          |

### GET /api/v2/discovery/assets/{id}

Get a single discovered asset.

| Error | Description |
|-------|-------------|
| 404   | Asset not found |

### PUT /api/v2/discovery/assets/{id}

Update asset metadata (tags, status, etc.).

### DELETE /api/v2/discovery/assets/{id}

Remove a discovered asset.

| Error | Description |
|-------|-------------|
| 404   | Asset not found |

### POST /api/v2/discovery/register

Register discovered assets as upstream servers.

**Request**

```json
{ "ids": ["10.0.1.5:22", "10.0.1.6:22"] }
```

Send an empty `ids` array to auto-register all unregistered assets.

**Response**

```json
{ "success": true, "data": { "registered": 2 } }
```

### GET /api/v2/discovery/config

Get the default scan configuration.

**Response**

```json
{
  "success": true,
  "data": {
    "ports": [22, 2222],
    "timeout": "5s",
    "concurrency": 50,
    "ssh_banner": true
  }
}
```

### PUT /api/v2/discovery/config

Update the default scan configuration.

**Request**

```json
{
  "ports": [22, 2222, 8022],
  "timeout": "10s",
  "concurrency": 100,
  "ssh_banner": true
}
```

---

## Command Control

### GET /api/v2/commands/rules

List all command control rules (paginated).

**Response**

```json
{
  "success": true,
  "data": [
    {
      "id": "block_rm_rf",
      "name": "Block recursive delete of root paths",
      "pattern": "rm\\s+(-[rfRF]+\\s+)?/",
      "action": "deny",
      "severity": "critical",
      "message": "Recursive delete of root paths blocked",
      "roles": [],
      "targets": [],
      "enabled": true
    }
  ],
  "total": 10,
  "page": 1,
  "per_page": 50
}
```

| Error | Description |
|-------|-------------|
| 503   | Command control not enabled |

### POST /api/v2/commands/rules

Create a new command control rule.

**Request**

```json
{
  "id": "block_custom",
  "name": "Block custom command",
  "pattern": "dangerous-cmd.*",
  "action": "deny",
  "severity": "high",
  "message": "Custom command blocked",
  "roles": [],
  "targets": [],
  "enabled": true
}
```

**Response** `201 Created`

| Error | Description |
|-------|-------------|
| 400   | Missing ID/pattern or invalid regex |

### GET /api/v2/commands/rules/{id}

Get a single rule.

| Error | Description |
|-------|-------------|
| 404   | Rule not found |

### PUT /api/v2/commands/rules/{id}

Update an existing rule.

| Error | Description |
|-------|-------------|
| 400   | Invalid regex pattern |
| 404   | Rule not found |

### DELETE /api/v2/commands/rules/{id}

Delete a rule.

| Error | Description |
|-------|-------------|
| 404   | Rule not found |

### POST /api/v2/commands/evaluate

Evaluate a command against the policy engine.

**Request**

```json
{
  "command": "rm -rf /var/log",
  "username": "alice",
  "role": "user",
  "target": "web-01"
}
```

**Response**

```json
{
  "success": true,
  "data": {
    "action": "deny",
    "rule": {
      "id": "block_rm_rf",
      "name": "Block recursive delete of root paths"
    },
    "message": "Recursive delete of root paths blocked"
  }
}
```

Possible `action` values: `allow`, `deny`, `audit`, `approve`.

### GET /api/v2/commands/approvals

List pending command approval requests.

**Response**

```json
{
  "success": true,
  "data": [
    {
      "id": "apr-001",
      "session_id": "sess-abc",
      "username": "alice",
      "command": "reboot",
      "target": "web-01",
      "rule_id": "block_shutdown",
      "status": "pending",
      "created_at": "2025-01-15T10:30:00Z",
      "expires_at": "2025-01-15T10:35:00Z"
    }
  ],
  "total": 1
}
```

### POST /api/v2/commands/approvals/{id}/approve

Approve a pending command. Requires `X-User` header.

**Response**

```json
{ "success": true, "data": "command approved" }
```

| Error | Description |
|-------|-------------|
| 400   | Request not pending or already expired |
| 401   | Authentication required |

### POST /api/v2/commands/approvals/{id}/deny

Deny a pending command. Requires `X-User` header.

**Response**

```json
{ "success": true, "data": "command denied" }
```

### GET /api/v2/commands/stats

Command control statistics.

**Response**

```json
{
  "success": true,
  "data": {
    "total_evaluations": 5000,
    "allowed": 4500,
    "denied": 200,
    "audited": 250,
    "approval_required": 50,
    "rule_count": 10,
    "pending_approvals": 2
  }
}
```

---

## Session Collaboration

All collaboration endpoints require the `X-User` header for identifying the
requesting user.

### POST /api/v2/collab/sessions

Create a new collaborative session.

**Request**

```json
{
  "session_id": "sess-abc123",
  "target": "web-01",
  "max_viewers": 5,
  "allow_control": true,
  "four_eyes_required": true
}
```

**Response** `201 Created`

```json
{
  "success": true,
  "data": {
    "id": "collab-abc123",
    "session_id": "sess-abc123",
    "owner": "admin",
    "target": "web-01",
    "created_at": "2025-01-15T10:30:00Z",
    "participants": [
      { "username": "admin", "role": "owner", "joined_at": "2025-01-15T10:30:00Z" }
    ],
    "max_viewers": 5,
    "allow_control": true,
    "four_eyes_required": true,
    "status": "active"
  }
}
```

| Error | Description |
|-------|-------------|
| 400   | Missing session_id or duplicate |
| 401   | Authentication required |
| 503   | Collaboration not enabled |

### GET /api/v2/collab/sessions

List all active collaboration sessions.

### GET /api/v2/collab/sessions/{id}

Get a single collaboration session.

| Error | Description |
|-------|-------------|
| 404   | Session not found |

### POST /api/v2/collab/sessions/{id}/join

Join a collaboration session.

**Request**

```json
{ "role": "viewer" }
```

Accepted roles: `viewer`, `operator`. Defaults to `viewer` if omitted.

| Error | Description |
|-------|-------------|
| 400   | Session full or already joined |
| 401   | Authentication required |

### POST /api/v2/collab/sessions/{id}/leave

Leave a collaboration session.

### POST /api/v2/collab/sessions/{id}/end

End a collaboration session. Only the session owner can do this.

When the session was created with `four_eyes_required=true`, this endpoint does
not end immediately. Instead it returns `202 Accepted` with a pending approval,
and a second participant who is still present in the session must approve it.

| Error | Description |
|-------|-------------|
| 403   | Only the session owner can end the session |

### POST /api/v2/collab/sessions/{id}/request-control

Request control of the shared terminal.

### POST /api/v2/collab/sessions/{id}/grant-control

Grant control to another user. Only the owner can grant control.

When `four_eyes_required=true`, this endpoint returns `202 Accepted` and a
pending approval instead of granting control immediately.

**Request**

```json
{ "username": "alice" }
```

| Error | Description |
|-------|-------------|
| 400   | User not in session or control not allowed |

### POST /api/v2/collab/sessions/{id}/revoke-control

Revoke control from a user. Only the owner can revoke control.

When `four_eyes_required=true`, this endpoint returns `202 Accepted` and a
pending approval instead of revoking control immediately.

**Request**

```json
{ "username": "alice" }
```

### GET /api/v2/collab/sessions/{id}/approvals

List four-eyes approval requests for a collaboration session.

**Response**

```json
{
  "success": true,
  "data": [
    {
      "id": "approval-123",
      "session_id": "collab-abc123",
      "action": "grant_control",
      "requested_by": "admin",
      "target_username": "alice",
      "status": "pending",
      "requested_at": "2025-01-15T10:31:00Z",
      "expires_at": "2025-01-15T10:36:00Z"
    }
  ],
  "total": 1
}
```

### POST /api/v2/collab/sessions/{id}/approvals/{approvalId}/approve

Approve a pending four-eyes action. The approver must be a different
participant who is still present in the session.

### POST /api/v2/collab/sessions/{id}/approvals/{approvalId}/deny

Deny a pending four-eyes action. The approver must be a different participant
who is still present in the session.

### GET /api/v2/collab/sessions/{id}/chat

Get chat message history.

**Query Parameters**

| Param   | Description                     |
|---------|---------------------------------|
| `limit` | Max messages to return (default 50) |

**Response**

```json
{
  "success": true,
  "data": [
    {
      "id": "msg-001",
      "session_id": "collab-abc123",
      "username": "admin",
      "message": "Taking a look at the logs",
      "type": "user",
      "timestamp": "2025-01-15T10:31:00Z"
    }
  ],
  "total": 1
}
```

### POST /api/v2/collab/sessions/{id}/chat

Send a chat message.

**Request**

```json
{ "message": "Can you check /var/log/syslog?" }
```

**Response** `201 Created`

| Error | Description |
|-------|-------------|
| 400   | Empty message |
| 404   | Session not found |
| 401   | Authentication required |

### GET /api/v2/collab/sessions/{id}/recording

Get session recording events. Supports `Accept: application/x-ndjson` for
NDJSON streaming format; otherwise returns a JSON array.

**Response**

```json
{
  "success": true,
  "data": [
    {
      "type": "output",
      "data": "$ ls\nREADME.md\n",
      "user": "",
      "elapsed_ms": 1500,
      "timestamp": "2025-01-15T10:30:01Z"
    }
  ],
  "total": 50
}
```

---

## Automation

Automation endpoints provide a persisted script library, scheduled or on-demand
SSH jobs, per-target result collection, and CI/CD trigger hooks.

### POST /api/v2/automation/scripts

Create a reusable automation script.

**Request**

```json
{
  "name": "restart-nginx",
  "shell": "/bin/sh",
  "body": "sudo systemctl restart nginx\n"
}
```

**Response** `201 Created`

### GET /api/v2/automation/scripts

List saved automation scripts.

### POST /api/v2/automation/jobs

Create an automation job. Use `server_ids` to batch across managed servers, set
`schedule` to a Go duration such as `30m` or `24h`, and optionally restrict
`trigger_providers` to CI systems that are allowed to invoke the job.

**Request**

```json
{
  "name": "nightly-inventory",
  "command": "hostname && uptime",
  "server_ids": ["srv-1", "srv-2"],
  "username": "ops",
  "password": "${env:OPS_SSH_PASSWORD}",
  "known_hosts_path": "/etc/ssh/ssh_known_hosts",
  "schedule": "24h",
  "trigger_providers": ["github-actions", "jenkins"],
  "enabled": true
}
```

### GET /api/v2/automation/jobs

List automation jobs. Optional query parameters:

| Param | Description |
|-------|-------------|
| `enabled` | Filter by enabled state (`true` / `false`) |
| `provider` | Filter by allowed CI/CD provider |

### POST /api/v2/automation/jobs/{id}/run

Run a job immediately.

**Request**

```json
{
  "trigger": "web-ui",
  "environment": {
    "DEPLOY_SHA": "abc123"
  }
}
```

**Response**

```json
{
  "success": true,
  "data": {
    "id": "run-123",
    "job_id": "job-123",
    "job_name": "nightly-inventory",
    "trigger": "web-ui",
    "status": "completed",
    "summary": "2 target(s) succeeded, 0 target(s) failed",
    "results": [
      {
        "target_id": "srv-1",
        "target_name": "server1",
        "host": "10.0.1.1",
        "port": 22,
        "status": "completed",
        "stdout": "server1\n",
        "stderr": ""
      }
    ]
  }
}
```

### POST /api/v2/automation/jobs/{id}/trigger

Trigger a job from GitHub Actions, GitLab CI, Jenkins, or another allowed CI
provider.

**Request**

```json
{
  "provider": "github-actions",
  "workflow": "deploy.yml",
  "ref": "refs/heads/main",
  "pipeline_id": "run-42"
}
```

Returns `202 Accepted` with the collected run payload.

### GET /api/v2/automation/runs

List historical automation runs.

| Param | Description |
|-------|-------------|
| `job_id` | Filter by job identifier |
| `status` | Filter by run status (`completed`, `partial`, `failed`) |

### GET /api/v2/automation/runs/{id}

Return a single automation run including per-target stdout/stderr summaries.

---

## Gateway

Gateway endpoints start ephemeral local listeners that tunnel through SSH using
protocol presets. This covers:

| Protocol | Default remote port | Typical use |
|----------|---------------------|-------------|
| `socks5` | dynamic | Generic egress / browser / CLI network access |
| `rdp` | `3389` | Remote Desktop |
| `vnc` | `5900` | VNC viewers |
| `mysql` | `3306` | MySQL |
| `postgresql` | `5432` | PostgreSQL |
| `redis` | `6379` | Redis |
| `kubernetes` | `6443` | Kubernetes API |
| `http` | `80` | HTTP applications |
| `https` | `443` | HTTPS applications |
| `x11` | `6000` | X11 display traffic |
| `tcp` | custom | Any TCP service |

All gateway proxies also accept `jump_chain`, so the same API can be used for
multi-hop SSH access through one or more bastion hosts.

### POST /api/v2/gateway/proxies

Create and start a protocol proxy.

**Request**

```json
{
  "protocol": "rdp",
  "remote_host": "127.0.0.1",
  "ssh_host": "bastion.internal",
  "username": "ops",
  "password": "${env:OPS_SSH_PASSWORD}",
  "known_hosts_path": "/etc/ssh/ssh_known_hosts"
}
```

**Response** `201 Created`

```json
{
  "success": true,
  "data": {
    "id": "proxy-123",
    "name": "RDP 127.0.0.1:3389 via bastion.internal",
    "protocol": "rdp",
    "bind_address": "127.0.0.1",
    "bind_port": 41213,
    "local_address": "127.0.0.1:41213",
    "local_url": "rdp://127.0.0.1:41213",
    "remote_host": "127.0.0.1",
    "remote_port": 3389,
    "ssh_host": "bastion.internal",
    "ssh_port": 22,
    "username": "ops",
    "status": "running"
  }
}
```

### POST /api/v2/gateway/proxies for SOCKS5 / jump-chain

```json
{
  "protocol": "socks5",
  "ssh_host": "bastion.internal",
  "username": "ops",
  "password": "${env:OPS_SSH_PASSWORD}",
  "insecure_skip_host_key_verify": true,
  "jump_chain": [
    {
      "host": "jump-1.internal",
      "username": "jump",
      "password": "${env:JUMP_PASSWORD}"
    }
  ]
}
```

The response returns a `socks5://127.0.0.1:<port>` endpoint that can reach any
TCP destination through the SSH path.

### GET /api/v2/gateway/proxies

List active gateway proxy listeners.

### GET /api/v2/gateway/proxies/{id}

Return one active gateway proxy.

### DELETE /api/v2/gateway/proxies/{id}

Stop and remove a gateway proxy.

---

## Insights

Insights endpoints turn existing audit logs into higher-level operational
signals: command intent classification, anomaly baselines, least-privilege
recommendations, natural-language policy previews, and compact audit summaries.

### GET /api/v2/insights/command-intents

Classify audited command events into intents such as `discovery`,
`service-operation`, `database-admin`, `kubernetes-admin`, and
`destructive-change`.

| Param | Description |
|-------|-------------|
| `page` / `per_page` | Standard pagination |
| `user` | Filter by username |
| `target_host` | Filter by target host substring |

**Response**

```json
{
  "success": true,
  "data": [
    {
      "event_id": "audit-123",
      "username": "alice",
      "target_host": "prod-k8s-1",
      "command": "kubectl exec deploy/api -- bash",
      "intent": "kubernetes-admin",
      "risk": "high",
      "confidence": 0.96,
      "labels": ["kubernetes", "platform"],
      "timestamp": "2026-04-09T23:45:00Z"
    }
  ],
  "total": 1,
  "page": 1,
  "per_page": 50
}
```

### GET /api/v2/insights/anomalies

Build per-user command baselines and return recent deviations such as
`rare-target`, `rare-intent`, `off-pattern-hours`, and `high-risk-command`.

| Param | Description |
|-------|-------------|
| `user` | Optional username filter |

### GET /api/v2/insights/recommendations

Recommend a least-privilege role and operation set from observed command usage.
The current heuristic promotes users to `admin` when high-risk commands are
already present, downgrades read-only behavior to `viewer`, and can add
conditions such as `login_window=09:00-18:00`.

| Param | Description |
|-------|-------------|
| `user` | Optional username filter |

### POST /api/v2/insights/policy-preview

Preview a natural-language access request as a policy rule without persisting
it.

**Request**

```json
{
  "text": "允许运维团队在工作时间访问生产服务器"
}
```

**Response**

```json
{
  "success": true,
  "data": {
    "raw_text": "允许运维团队在工作时间访问生产服务器",
    "rule": {
      "name": "nl-preview",
      "action": "allow",
      "role": "operator",
      "resources": ["prod-*"],
      "operations": ["exec", "shell"],
      "conditions": {
        "login_days": "mon-fri",
        "login_window": "09:00-18:00"
      }
    },
    "notes": [
      "Mapped production servers to prod-* resource pattern.",
      "Expanded work-hours language to 09:00-18:00 on weekdays."
    ],
    "confidence": 0.95
  }
}
```

### GET /api/v2/insights/audit-summary

Generate a compact audit summary for the current or filtered time range.

| Param | Description |
|-------|-------------|
| `user` | Optional username filter |
| `from` | Optional RFC3339 start time |
| `to` | Optional RFC3339 end time |

**Response**

```json
{
  "success": true,
  "data": {
    "from": "2026-04-09T00:00:00Z",
    "to": "2026-04-10T00:00:00Z",
    "total_events": 6,
    "command_events": 5,
    "failed_logins": 1,
    "high_risk_commands": 2,
    "top_users": ["alice", "bob"],
    "top_targets": ["prod-app-1", "prod-k8s-1", "db-1"],
    "summary": "Observed 6 audit events, including 5 command events, 1 failed logins, and 2 high-risk commands. Top users: alice, bob. Top targets: prod-app-1, prod-k8s-1, db-1."
  }
}
```
