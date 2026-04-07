# SSH Proxy Core — REST API Reference

Base URL: `https://<host>:8443/api/v2`

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

---

## Table of Contents

- [Authentication](#authentication)
- [Dashboard](#dashboard)
- [Sessions](#sessions)
- [Users](#users)
- [Servers](#servers)
- [Audit](#audit)
- [Configuration](#configuration)
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

List active SSH sessions.

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
      "target": "web-01:22",
      "status": "active",
      "started_at": "2025-01-15T10:30:00Z"
    }
  ],
  "total": 1,
  "page": 1,
  "per_page": 50
}
```

### GET /api/v2/sessions/{id}

Get details for a single session.

**Response**

```json
{
  "success": true,
  "data": {
    "id": "sess-abc123",
    "username": "admin",
    "source_ip": "10.0.0.5",
    "target": "web-01:22",
    "status": "active",
    "started_at": "2025-01-15T10:30:00Z"
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

Download the session recording.

**Response**

Binary recording data or JSON error.

| Error | Description |
|-------|-------------|
| 404   | Recording not found |

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

List audit events with optional filters.

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

Get a single audit event.

| Error | Description |
|-------|-------------|
| 404   | Event not found |

### GET /api/v2/audit/search

Full-text search across audit events.

**Query Parameters**

| Param | Description  |
|-------|--------------|
| `q`   | Search query |

### GET /api/v2/audit/export

Export audit events. Supports `format=csv` or `format=json` query parameter.

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

### PUT /api/v2/config

Update configuration values. Creates a version snapshot automatically.

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

Get a specific config version.

| Error | Description |
|-------|-------------|
| 404   | Version not found |

### POST /api/v2/config/rollback

Rollback to a previous config version.

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

Force-reload the data-plane configuration.

**Response**

```json
{ "success": true, "data": { "message": "configuration reloaded" } }
```

| Error | Description |
|-------|-------------|
| 502   | Data-plane reload failed |

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

### POST /api/v2/jit/requests

Create a just-in-time access request.

**Request**

```json
{
  "target": "db-01.prod",
  "role": "operator",
  "reason": "Investigate slow queries",
  "duration": "2h"
}
```

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

Approve a pending JIT request. Requires approver role.

**Response**

```json
{ "success": true, "data": { "id": "jit-abc123", "status": "approved" } }
```

| Error | Description |
|-------|-------------|
| 400   | Request not in pending state |
| 401   | Authentication required |
| 403   | Admin role required |

### POST /api/v2/jit/requests/{id}/deny

Deny a pending JIT request.

**Request**

```json
{ "reason": "Not authorized for production access" }
```

| Error | Description |
|-------|-------------|
| 400   | Request not in pending state |
| 403   | Admin role required |

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
    "require_reason": true,
    "approver_roles": ["admin"],
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
  "require_reason": true,
  "approver_roles": ["admin"],
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

Cluster overview including node role, leader, and member count.

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
    "nodes": []
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
    { "id": "node-1", "addr": "10.0.0.1:8444", "role": "leader", "status": "active" },
    { "id": "node-2", "addr": "10.0.0.2:8444", "role": "follower", "status": "active" }
  ],
  "total": 2
}
```

### POST /api/v2/cluster/join

Join the cluster using seed addresses.

**Request**

```json
{ "seeds": ["10.0.0.1:8444", "10.0.0.2:8444"] }
```

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
    { "id": "iso27001", "name": "ISO 27001", "description": "Information Security Management System" }
  ],
  "total": 5
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
    "iso27001":{ "score": 87.5, "pass_count": 35, "fail_count": 5, "total_count": 40 }
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

List all threat detection rules.

**Response**

```json
{
  "success": true,
  "data": [
    {
      "id": "brute-force",
      "name": "Brute Force Detection",
      "enabled": true,
      "threshold": 5,
      "window": "5m",
      "severity": "high"
    }
  ],
  "total": 5
}
```

### PUT /api/v2/threats/rules/{id}

Update a threat detection rule.

**Request**

```json
{
  "enabled": true,
  "threshold": 10,
  "window": "10m",
  "pattern": ".*"
}
```

| Error | Description |
|-------|-------------|
| 400   | Invalid window duration |
| 404   | Rule not found |

### GET /api/v2/threats/stats

Get threat detection statistics.

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

Simulate a threat event for testing. Accepts a full `threat.Event` object.

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
  "allow_control": true
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

| Error | Description |
|-------|-------------|
| 403   | Only the session owner can end the session |

### POST /api/v2/collab/sessions/{id}/request-control

Request control of the shared terminal.

### POST /api/v2/collab/sessions/{id}/grant-control

Grant control to another user. Only the owner can grant control.

**Request**

```json
{ "username": "alice" }
```

| Error | Description |
|-------|-------------|
| 400   | User not in session or control not allowed |

### POST /api/v2/collab/sessions/{id}/revoke-control

Revoke control from a user. Only the owner can revoke control.

**Request**

```json
{ "username": "alice" }
```

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
