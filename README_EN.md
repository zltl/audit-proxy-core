# SSH Proxy Core

High-performance, extensible SSH protocol proxy platform. C data plane (libssh, ~14,700 LOC) + Go control plane (REST API / Web UI / Automation / Gateway / Insights).

[中文文档](README.md)

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Configuration Reference](#configuration-reference)
- [Feature Policy](#feature-policy)
- [Logging & Audit](#logging--audit)
- [Operations](#operations)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Build](#build)
- [Terraform Bridge](#terraform-bridge)
- [API Reference](#api-reference)
- [Development](#development)
- [Deployment](#deployment)
- [Documentation](#documentation)
- [License](#license)

## Features

### Core Proxy

- **Proxy Forwarding** — Transparent and explicit proxy with multi-backend routing
- **Session Management** — Complete SSH session lifecycle management with thread-safe tracking
- **Routing & Load Balancing** — Round-Robin, Least-Connections policies with upstream health checks
- **Upstream Connection Pool** — SSH connection pooling and keepalive for reduced latency *(v0.3.0)*
- **Upstream Connection Retry** — Exponential backoff retry on upstream connection failures *(v0.3.0)*

### Security & Access Control

- **Filter Chain** — Envoy-style ordered, extensible filter architecture
- **Authentication** — Password (crypt), public key, and SSH certificate authentication
- **LDAP Authentication** — Raw-socket LDAP simple bind backend with zero external dependencies *(v0.3.0)*
- **TOTP/MFA Two-Factor Authentication** — Self-contained SHA1/HMAC-SHA1 TOTP implementation *(v0.3.0)*
- **RBAC** — Role-based access control with glob-pattern matching
- **Feature Policies** — Fine-grained per-user, per-upstream feature control (shell, SCP, SFTP, git, port forwarding, etc.)
- **IP Whitelist/Blacklist** — CIDR-based IP access control with whitelist and blacklist modes *(v0.3.0)*
- **Rate Limiting** — Per-IP and global connection rate and concurrency limits
- **Per-User Session Limits** — Configurable maximum concurrent sessions per user *(v0.3.0)*

### Observability & Audit

- **Structured JSON Logging** — NDJSON (newline-delimited JSON) log output format *(v0.3.0)*
- **Session Audit** — JSON event logs for connections, authentication, and disconnections
- **Terminal Recording** — asciicast v2 format session recordings (compatible with asciinema)
- **Command Audit** — Records shell commands parsed from upstream data stream *(v0.3.0)*
- **File Transfer Logging** — Logs all SCP/SFTP/rsync file transfers with checksums
- **Port Forward Logging** — Records all port forwarding requests
- **Prometheus Metrics** — `/metrics` endpoint with atomic runtime counters

### Operations

- **Health Check HTTP Server** — `/health` and `/metrics` endpoints
- **Admin REST API** — Session management, upstream control, config reload via HTTP *(v0.3.0)*
- **Hot Reload** — SIGHUP-based configuration reload without downtime
- **Configuration Validation** — `--check` / `-t` flag for config validation (like `nginx -t`) *(v0.3.0)*
- **Login Banner/MOTD** — Pre-auth banner and post-auth MOTD with variable expansion *(v0.3.0)*
- **Webhook Notifications** — Async HTTP POST event notifications *(v0.3.0)*
- **Distributed Session Storage** — Local memory or file-based (NDJSON + flock) session backends *(v0.3.0)*

### Design Principles

- **Zero external dependencies** for new features — LDAP via raw socket BER encoding, TOTP via self-implemented SHA1/HMAC-SHA1, webhook via raw HTTP
- **C11** with `-Wall -Wextra -Wpedantic -Werror`
- **Thread-safe** — pthread mutexes throughout
- **~14,700 lines of C** — 20 source files, 19 headers, 11 test files
- **All new features backward compatible** — disabled by default

### Control Plane (Go)

| # | Module | Description |
|---|--------|-------------|
| 1 | Web UI | Dashboard, sessions, users, servers, audit viewer |
| 2 | REST API | Full CRUD with OpenAPI/Swagger at `/api/docs` |
| 3 | OIDC / SAML SSO | Enterprise single sign-on integration |
| 4 | SSH CA | Short-lived certificate issuance, auto-rotation |
| 5 | JIT Access | Just-in-time access requests with multi-level approvals |
| 6 | Cluster | Multi-node clustering with DNS / K8s / Consul discovery |
| 7 | Discovery | Auto-import hosts from AWS / Azure / GCP / CMDB / Ansible |
| 8 | Command Control | Real-time interception and approval of high-risk commands |
| 9 | Collaboration | Multi-user session sharing, control transfer, in-session chat |
| 10 | Compliance | Policy engine and compliance reporting |
| 11 | SIEM | Export to Splunk / Elasticsearch / Syslog |
| 12 | Threat Detection | Rule-based anomalous behaviour alerting |
| 13 | **Workflow Automation** | Script library, batch SSH jobs, cron scheduling, CI/CD triggers |
| 14 | **Protocol Gateway** | SOCKS5 / RDP / VNC / MySQL / PostgreSQL / Redis / K8s / HTTP(S) / X11 tunnels |
| 15 | **Intelligent Insights** | Command intent classification, anomaly detection, least-privilege recommendations, NL policy preview, audit summaries |

> See [API Reference](docs/api-reference.md) and [Architecture](docs/DESIGN.md) for details.

## Quick Start

### 1. Build

```bash
# Install dependencies
sudo apt update && sudo apt install -y build-essential libssh-dev

# Build (debug)
make

# Build (release)
make release

# Run tests
make test

# Generate host key (first run)
ssh-keygen -t rsa -f /tmp/ssh_proxy_host_key -N ""
```

### 2. Configuration

Create a configuration file (e.g., `config.ini`):

```ini
[server]
bind_addr = 0.0.0.0
port = 2222
host_key = /etc/ssh-proxy/host_key

[logging]
level = info
audit_dir = /var/log/ssh-proxy/audit

[limits]
max_sessions = 1000
session_timeout = 3600
auth_timeout = 60

# Users — generate password hash with: openssl passwd -6
[user:admin]
password_hash = $6$saltsalt$...
pubkey = ssh-rsa AAAA... user@host
enabled = true

# Routes — map proxy users to upstream servers
[route:admin]
upstream = prod.example.com
port = 22
user = root
privkey = /etc/ssh-proxy/keys/admin.key

# Wildcard routes
[route:dev-*]
upstream = dev.example.com
user = developer

# Default catch-all route
[route:*]
upstream = bastion.example.com
user = guest

# Feature policies
[policy:admin]
allow = all

[policy:dev-*]
allow = shell, exec, git, download, sftp_list
deny = upload, port_forward

[policy:readonly-*]
allow = shell, download, sftp_list
deny = upload, scp_upload, sftp_upload, rsync_upload, git_push, exec
```

### 3. Validate & Run

```bash
# Validate configuration (like nginx -t)
./build/bin/ssh-proxy-core -t -c config.ini

# Start with config file
./build/bin/ssh-proxy-core -c config.ini

# Debug mode
./build/bin/ssh-proxy-core -d -c config.ini

# Show version
./build/bin/ssh-proxy-core --version

# Show help
./build/bin/ssh-proxy-core --help
```

### 4. Connect

```bash
# Connect through the proxy
ssh -p 2222 admin@proxy-server

# Transparent proxy mode
ssh -p 2222 admin@target-server -o ProxyJump=proxy-server
```

## Configuration Reference

SSH Proxy Core uses INI-format configuration. All new feature sections are optional and disabled by default for backward compatibility.

### `[server]` — Server Settings

```ini
[server]
bind_addr = 0.0.0.0                     # Listen address
port = 2222                              # Listen port
host_key = /etc/ssh-proxy/host_key       # SSH host key path
banner = /etc/ssh-proxy/banner.txt       # Pre-auth banner file path (v0.3.0)
motd = Welcome {username} from {client_ip}!  # Post-auth message (v0.3.0)
```

**MOTD variable expansion** *(v0.3.0)*:

| Variable | Description |
|----------|-------------|
| `{username}` | Authenticated username |
| `{client_ip}` | Client IP address |
| `{datetime}` | Current date and time |
| `{hostname}` | Proxy server hostname |
| `{version}` | SSH Proxy Core version |

### `[logging]` — Logging Configuration

```ini
[logging]
level = info                             # Log level: debug, info, warn, error
audit_dir = /var/log/ssh-proxy/audit     # Audit log and recording directory
audit_encryption_key = 001122...eeff     # Optional: 64 hex chars for AES-256-GCM
format = text                            # Output format: text | json (v0.3.0)
```

When `format = json`, all log output uses NDJSON (one JSON object per line):

```json
{"timestamp":"2025-01-05T12:00:00Z","level":"INFO","message":"Server started","port":2222}
```

When `audit_encryption_key` or `audit_encryption_key_file` is configured, event and command audit
logs are wrapped per line with AES-256-GCM while keeping the existing rotation/archival behavior.

### `[limits]` — Connection Limits

```ini
[limits]
max_sessions = 1000                      # Maximum concurrent sessions
session_timeout = 3600                   # Session timeout in seconds
auth_timeout = 60                        # Authentication timeout in seconds
per_user_max_sessions = 10               # Max sessions per user (v0.3.0, 0 = unlimited)
```

### `[user:*]` — User Definitions

Each user section defines authentication credentials. Generate password hashes with `openssl passwd -6`.

```ini
[user:admin]
password_hash = $6$saltsalt$...          # crypt(3) password hash
pubkey = ssh-rsa AAAA... admin@host      # Inline public key
pubkey_file = /etc/ssh-proxy/authorized_keys/admin  # Authorized keys file
enabled = true                           # Enable/disable user
totp_secret = JBSWY3DPEHPK3PXP          # Base32 TOTP secret (v0.3.0)
mfa_enabled = true                       # Enable MFA for this user (v0.3.0)
```

Sensitive data in the current data-plane config supports three forms:

1. Plaintext for backward compatibility
2. `${env:NAME}` / `${file:/path/to/value}`
3. `enc:v1:<nonce_hex>:<ciphertext_hex>:<tag_hex>` protected by `[security].master_key` or `master_key_file`

The encrypted-value path currently covers `password_hash`, `[admin].auth_token`,
`[webhook].hmac_secret`, and `[logging].audit_encryption_key`.

To enable SSH certificate authentication, configure `trusted_user_ca_key` or
`trusted_user_ca_keys_file` in `[security]`. With a trusted user CA configured, users can
authenticate with short-lived CA-signed certificates; the proxy enforces the `source-address`
critical option and rejects unsupported critical options. To enforce revocations, export revoked
serials from `/api/v2/ca/crl` and configure `revoked_user_cert_serial` or
`revoked_user_cert_serials_file` in the data plane `[security]` section.

```ini
[security]
master_key = ${env:SSH_PROXY_MASTER_KEY}      # 64 hex chars (AES-256)
# master_key_file = /etc/ssh-proxy/master_key.hex
```

### `[route:*]` — User-to-Upstream Routing

Route sections map proxy users to upstream servers. Patterns support glob matching (`*`, `?`).

```ini
# Exact match
[route:admin]
upstream = prod.example.com              # Upstream hostname/IP
port = 22                                # Upstream port (default: 22)
user = root                              # Upstream username
privkey = /etc/ssh-proxy/keys/admin.key  # Private key for upstream auth
enabled = true                           # Enable/disable route

# Wildcard match
[route:dev-*]                            # Matches dev-alice, dev-bob, etc.
upstream = dev.example.com
user = developer

# Default catch-all
[route:*]
upstream = bastion.example.com
user = guest
```

### `[policy:*]` — Feature Policies

Policies control which SSH features a user can access. Format: `[policy:user_pattern]` or `[policy:user_pattern@upstream_pattern]`.

```ini
# Admin — all features
[policy:admin]
allow = all

# Developer — shell, exec, git, download; no upload or port forwarding
[policy:dev-*]
allow = shell, exec, git, download, sftp_list
deny = upload, port_forward

# Read-only — can view but not modify
[policy:readonly-*]
allow = shell, download, sftp_list
deny = upload, scp_upload, sftp_upload, rsync_upload, git_push, exec

# Git-only — restricted to git operations
[policy:git-*]
allow = git_pull, git_push
deny = shell, exec, scp, sftp, rsync, port_forward

# Restricted — shell only, no file transfers
[policy:restricted-*]
allow = shell
deny = scp, sftp, rsync, port_forward, git, exec

# Per-upstream policies (user@upstream pattern)
[policy:*@prod.example.com]
allow = shell, download, sftp_list
deny = upload, exec, git_push, sftp_delete

[policy:admin@prod.example.com]
allow = all
```

**Matching priority** (highest to lowest):
1. Exact user + exact upstream
2. Exact user + wildcard upstream
3. Exact user (no upstream restriction)
4. Wildcard user + exact upstream
5. Wildcard user + wildcard upstream
6. Wildcard user (no upstream restriction)

### `[rbac:*]` — Role-Based Access Control

```ini
[rbac:admin_role]
permissions = shell, exec, scp, sftp, port_forward
default_action = deny
```

### `[ip_acl]` — IP Whitelist/Blacklist *(v0.3.0)*

CIDR-based IP access control. Supports whitelist mode (only listed IPs allowed) and blacklist mode (listed IPs denied).

```ini
[ip_acl]
mode = blacklist                         # whitelist | blacklist
log_rejections = true                    # Log denied connections

# Rules: CIDR ranges with allow/deny actions
rules = deny 10.0.0.0/8, deny 172.16.0.0/12, allow 192.168.1.0/24
```

In **whitelist** mode, only IPs matching an `allow` rule are permitted. In **blacklist** mode, IPs matching a `deny` rule are rejected.

### `[auth]` — Authentication Backend *(v0.3.0)*

```ini
[auth]
backend = local                          # local | ldap

# LDAP settings (when backend = ldap)
ldap_uri = ldap://ldap-a.example.com:389,ldap://ldap-b.example.com:389  # LDAP server URIs
ldap_base_dn = dc=example,dc=com        # Base DN for user search
ldap_bind_dn = cn=proxy,dc=example,dc=com  # Optional bind DN for identity lookups
ldap_bind_pw = ${env:LDAP_BIND_PASSWORD}
ldap_user_filter = uid=%s                # User search filter (%s = username)
ldap_timeout = 5                         # Connection timeout in seconds
ldap_group_attr = memberOf               # Group membership attribute
ldap_email_attr = mail
ldap_department_attr = department
ldap_manager_attr = manager
```

The LDAP backend uses raw TCP socket BER encoding — no libldap dependency required. Multiple
`ldap_uri` values enable endpoint failover, and the most recently successful endpoint is tried
first on later binds. After a successful password bind, the filter also loads
`memberOf/mail/department/manager` from the user entry (attribute names are configurable) and
stores them in session metadata for downstream role-mapping or audit consumers.

### `[mfa]` — TOTP Two-Factor Authentication *(v0.3.0)*

```ini
[mfa]
enabled = true                           # Global MFA enable
issuer = SSH-Proxy                       # TOTP issuer name
time_step = 30                           # TOTP time step in seconds
digits = 6                               # TOTP code digit count
window = 1                               # Time window tolerance (±steps)
```

Per-user TOTP configuration is set in the corresponding `[user:*]` section (`totp_secret`, `mfa_enabled`). The TOTP implementation uses a self-contained SHA1/HMAC-SHA1 — no external crypto library required.

### `[webhook]` — Event Notifications *(v0.3.0)*

Asynchronous HTTP POST notifications for system events.

```ini
[webhook]
enabled = true
url = https://hooks.example.com/ssh-proxy  # Webhook endpoint URL
auth_header = Bearer your-webhook-token     # Authorization header value
events = auth.success, auth.failure, session.start, session.end  # Subscribed events
retry_max = 3                            # Max retry attempts
retry_delay_ms = 1000                    # Retry delay in milliseconds
timeout_ms = 5000                        # HTTP request timeout
```

**Available events:**

| Event | Description |
|-------|-------------|
| `auth.success` | Successful authentication |
| `auth.failure` | Failed authentication attempt |
| `session.start` | New session established |
| `session.end` | Session closed |
| `rate_limit.triggered` | Rate limit exceeded |
| `ip_acl.denied` | IP access denied by ACL |
| `upstream.unhealthy` | Upstream server became unhealthy |
| `upstream.healthy` | Upstream server recovered |
| `config.reloaded` | Configuration reloaded via SIGHUP or API |

### `[admin]` — Admin REST API *(v0.3.0)*

```ini
[admin]
enabled = true                           # Enable admin API endpoints
auth_token = your-secret-token           # Bearer token for API authentication (or enc:v1:...)
```

See [Admin REST API](#admin-rest-api) in the Operations section for endpoint details.

### `[router]` — Routing & Connection Settings *(v0.3.0)*

```ini
[router]
# Connection retry with exponential backoff
retry_max = 3                            # Maximum retry attempts
retry_initial_delay_ms = 100             # Initial retry delay
retry_max_delay_ms = 5000                # Maximum retry delay
retry_backoff_factor = 2.0               # Backoff multiplier

# Per-route circuit breaker
circuit_breaker_enabled = true           # Temporarily skip repeatedly failing routes
circuit_breaker_failure_threshold = 3
circuit_breaker_open_seconds = 30

# Connection pooling
pool_enabled = false                     # Enable connection pooling
pool_max_idle = 10                       # Max idle connections per upstream
pool_max_idle_time = 300                 # Max idle time in seconds
```

Retries use exponential backoff and re-run route selection each round. Routes
whose circuit breaker is still open are skipped, and once the cool-down window
expires only one half-open recovery probe is allowed through at a time.

### `[session_store]` — Session Storage Backend *(v0.3.0)*

When a shared backend is enabled, the admin session list merges local and remote
active sessions and exposes the owning `instance_id`. The `per_user_max_sessions`
limit also evaluates against the shared authenticated-session view, so cluster
nodes enforce the same concurrent-session ceiling.

```ini
[session_store]
type = local                             # local (in-memory) | file (NDJSON + flock)
path = /var/lib/ssh-proxy/sessions.ndjson  # File path (when type = file)
max_records = 10000                      # Maximum stored session records
```

The file backend uses NDJSON format with `flock(2)` for concurrent access safety.

### `[audit]` — Command Audit *(v0.3.0)*

```ini
[audit]
record_commands = true                   # Parse and log shell commands
```

When enabled, commands are written to `{audit_dir}/commands_YYYYMMDD.log`.

## Feature Policy

The feature policy system provides fine-grained control over which SSH capabilities each user can access.

### Feature Reference

| Feature | Description |
|---------|-------------|
| `shell` | Interactive shell |
| `exec` | Remote command execution |
| `scp` | SCP upload and download |
| `scp_upload` | SCP upload only |
| `scp_download` | SCP download only |
| `sftp` | All SFTP operations |
| `sftp_upload` | SFTP upload |
| `sftp_download` | SFTP download |
| `sftp_list` | SFTP directory listing |
| `sftp_delete` | SFTP delete/rename |
| `rsync` | rsync upload and download |
| `rsync_upload` | rsync upload |
| `rsync_download` | rsync download |
| `port_forward` | All port forwarding |
| `local-forward` | Local port forwarding (`-L`) |
| `remote-forward` | Remote port forwarding (`-R`) |
| `dynamic-forward` | Dynamic port forwarding (`-D`) |
| `x11` | X11 forwarding |
| `agent` | SSH agent forwarding |
| `git` | All Git operations |
| `git_push` | git push |
| `git_pull` | git pull/fetch/clone |
| `upload` | All uploads (SCP/SFTP/rsync) |
| `download` | All downloads (SCP/SFTP/rsync) |
| `all` | All features |
| `none` | Deny all |

## Logging & Audit

### Log Locations

| Type | Default Path | Description |
|------|-------------|-------------|
| Audit events | `{audit_dir}/audit_YYYYMMDD.log` | JSON connection/auth/disconnect events |
| Session recordings | `{audit_dir}/session_{id}_{datetime}.cast` | asciicast v2 terminal recordings |
| File transfer log | `{audit_dir}/transfers_YYYYMMDD.log` | SCP/SFTP/rsync transfer records |
| Port forward log | `{audit_dir}/port_forwards_YYYYMMDD.log` | Port forwarding request records |
| Command audit | `{audit_dir}/commands_YYYYMMDD.log` | Shell command records *(v0.3.0)* |
| Runtime log | stdout/stderr | Server runtime log |

Default `audit_dir` is `/tmp/ssh_proxy_audit`. Override it in the `[logging]` section.

### Structured JSON Logging *(v0.3.0)*

Set `format = json` in `[logging]` to enable NDJSON output. Each log line is a self-contained JSON object:

```json
{"timestamp":"2025-01-05T12:00:00Z","level":"INFO","message":"Server started on 0.0.0.0:2222"}
{"timestamp":"2025-01-05T12:00:01Z","level":"INFO","message":"Auth success","username":"admin","client_addr":"192.168.1.100"}
```

This is ideal for log aggregation pipelines (ELK, Loki, Splunk, etc.).

### Audit Event Log

Audit events are JSON-formatted, one event per line:

```json
{"timestamp":1704412800,"type":"AUTH_SUCCESS","session_id":12345,"username":"admin","client_addr":"192.168.1.100"}
{"timestamp":1704412801,"type":"SESSION_START","session_id":12345,"username":"admin","target":"prod.example.com"}
{"timestamp":1704413400,"type":"SESSION_END","session_id":12345,"username":"admin"}
```

### Command Audit Log *(v0.3.0)*

When `record_commands = true`, the audit filter parses upstream data to extract shell commands:

```json
{"timestamp":1704412900,"session_id":12345,"username":"admin","command":"ls -la /etc/"}
{"timestamp":1704412910,"session_id":12345,"username":"admin","command":"cat /etc/passwd"}
```

### File Transfer Log

Records all file transfers through the proxy:

```json
{"timestamp":1704412900,"session":12345,"user":"admin","event":"start","direction":"upload","protocol":"scp","path":"/home/user/file.txt","size":1024,"transferred":0}
{"timestamp":1704412901,"session":12345,"user":"admin","event":"complete","direction":"upload","protocol":"scp","path":"/home/user/file.txt","size":1024,"transferred":1024,"checksum":"a1b2c3..."}
{"timestamp":1704412950,"session":12346,"user":"dev","event":"denied","direction":"upload","protocol":"sftp","path":"/etc/passwd","size":0,"transferred":0}
```

| Field | Description |
|-------|-------------|
| `event` | `start` / `complete` / `failed` / `denied` |
| `direction` | `upload` / `download` |
| `protocol` | `scp` / `sftp` / `rsync` / `git` |
| `path` | Remote file path |
| `size` | File size in bytes |
| `transferred` | Bytes transferred |
| `checksum` | SHA-256 checksum (on completion) |

### Port Forward Log

```json
{"timestamp":1704413000,"session":12345,"user":"admin","type":"local","bind":"localhost:8080","target":"db.internal:3306","allowed":true}
{"timestamp":1704413010,"session":12346,"user":"guest","type":"remote","bind":"0.0.0.0:9000","target":"localhost:22","allowed":false}
```

### Viewing Session Recordings (.cast files)

Session recordings use the [asciicast v2](https://github.com/asciinema/asciinema/blob/develop/doc/asciicast-v2.md) format.

#### Method 1: asciinema CLI

```bash
# Install asciinema
sudo apt install asciinema
# or
pip install asciinema

# Play recording
asciinema play /tmp/ssh_proxy_audit/session_12345_20250105_120000.cast

# Play at 2x speed
asciinema play -s 2 /tmp/ssh_proxy_audit/session_12345_20250105_120000.cast

# Cap idle time to 2 seconds
asciinema play -i 2 /tmp/ssh_proxy_audit/session_12345_20250105_120000.cast
```

#### Method 2: asciinema-player (Web)

```bash
# Serve recordings over HTTP
cd /tmp/ssh_proxy_audit
python3 -m http.server 8000
```

Then embed the player in an HTML page:

```html
<html>
<head>
  <link rel="stylesheet" type="text/css" href="https://unpkg.com/asciinema-player@3.0.1/dist/bundle/asciinema-player.css" />
</head>
<body>
  <div id="player"></div>
  <script src="https://unpkg.com/asciinema-player@3.0.1/dist/bundle/asciinema-player.min.js"></script>
  <script>
    AsciinemaPlayer.create('http://localhost:8000/session_12345_20250105_120000.cast', document.getElementById('player'));
  </script>
</body>
</html>
```

#### Method 3: Raw Inspection

```bash
# View recording header
head -1 /tmp/ssh_proxy_audit/session_12345_20250105_120000.cast | jq

# View all frames
cat /tmp/ssh_proxy_audit/session_12345_20250105_120000.cast
```

`.cast` file format:
- Line 1: JSON header (version, terminal size, timestamp)
- Subsequent lines: `[time_offset, "o"|"i", "data"]` event frames
  - `"o"` = output (server → client)
  - `"i"` = input (client → server)

## Operations

### Health Check & Metrics

The built-in HTTP server listens on `127.0.0.1:9090` by default:

```bash
# Health status (JSON)
curl http://localhost:9090/health

# Prometheus metrics
curl http://localhost:9090/metrics
```

Health response example:
```json
{"bind_addr":"0.0.0.0","port":2222,"num_users":5,"num_routes":3}
```

### Admin REST API *(v0.3.0)*

The admin API extends the health check HTTP server. All admin endpoints require Bearer token authentication.

```bash
# List active sessions
curl -H "Authorization: Bearer <token>" http://localhost:9090/api/v1/sessions

# List upstream servers and status
curl -H "Authorization: Bearer <token>" http://localhost:9090/api/v1/upstreams

# Trigger configuration reload
curl -X POST -H "Authorization: Bearer <token>" http://localhost:9090/api/v1/reload

# View current configuration
curl -H "Authorization: Bearer <token>" http://localhost:9090/api/v1/config
```

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health status (no auth) |
| `/metrics` | GET | Prometheus metrics (no auth) |
| `/api/v1/sessions` | GET | List active sessions |
| `/api/v1/upstreams` | GET | List upstream servers |
| `/api/v1/reload` | POST | Reload configuration |
| `/api/v1/config` | GET | View running configuration |

### Configuration Validation *(v0.3.0)*

Validate configuration syntax and semantics without starting the server (like `nginx -t`):

```bash
./build/bin/ssh-proxy-core -t -c config.ini
# or
./build/bin/ssh-proxy-core --check -c config.ini
```

On success:
```
Configuration file config.ini is valid
```

On failure, reports the specific error and exits with a non-zero code.

### Hot Reload

Reload configuration without restarting the server:

```bash
# Via SIGHUP
kill -HUP $(pgrep ssh-proxy-core)

# Via Admin API (v0.3.0)
curl -X POST -H "Authorization: Bearer <token>" http://localhost:9090/api/v1/reload
```

Hot reload updates users, routes, policies, and ACL rules. Existing sessions are not interrupted.

### `sshproxy` Control-Plane CLI

`cmd/sshproxy` provides a control-plane CLI for OIDC login, short-lived SSH certificate issuance, session discovery, and proxied `ssh` / `scp` access:

```bash
go build ./cmd/sshproxy

# Initial control-plane configuration
./sshproxy config set server https://proxy.example.com
./sshproxy config set ssh_addr proxy.example.com:2222

# Browser-based OIDC login and automatic SSH certificate issuance
./sshproxy login

# Common commands
./sshproxy ls servers
./sshproxy ls sessions
./sshproxy ssh alice@db-prod
./sshproxy scp ./backup.tgz alice@db-prod:/tmp/
./sshproxy completion bash
```

`sshproxy login` stores the authenticated control-plane session in `~/.sshproxy/config.json`, generates or reuses `~/.sshproxy/id_ed25519`, and requests a short-lived user certificate from the built-in SSH CA. Later `sshproxy ssh` / `scp` commands automatically inject that identity file. To pin the control-plane HTTPS server key, set `pinned_server_pubkey_sha256` in that config file using the `sha256/<base64-spki-hash>` format.

### Web SSO (OIDC / SAML)

The control-plane login page supports both OIDC and SAML 2.0 Web SSO. The
SAML path is metadata-driven: configure `saml_root_url`,
`saml_idp_metadata_url` (or `saml_idp_metadata_file`), `saml_sp_cert`, and
`saml_sp_key`, then the server exposes `/auth/saml/login` (SP-initiated),
`/auth/saml/acs` (ACS / IdP-initiated), and `/auth/saml/metadata` (SP
metadata). Assertion attributes can be mapped into local `admin`,
`operator`, and `viewer` roles, and the flow is intended to interoperate with
enterprise IdPs such as ADFS, Shibboleth, and OneLogin.

### CLI Reference

| Flag | Description |
|------|-------------|
| `-h`, `--help` | Show help message |
| `-v`, `--version` | Show version information |
| `-d`, `--debug` | Enable debug logging |
| `-c`, `--config FILE` | Config file path (default: `/etc/ssh-proxy/config.ini`) |
| `-p`, `--port PORT` | Listen port (overrides config file) |
| `-k`, `--key FILE` | Host key file path |
| `-t`, `--check` | Validate configuration and exit *(v0.3.0)* |

## Architecture

```
┌─────────────┐     ┌───────────────────────────────────────────────┐     ┌──────────────┐
│             │     │              SSH Proxy Core                   │     │              │
│   Client    │────▶│  ┌─────────────────────────────────────────┐  │────▶│   Upstream   │
│             │     │  │           Filter Chain                  │  │     │              │
└─────────────┘     │  │ ┌────────┬────────┬───────┬──────────┐  │  │     └──────────────┘
                    │  │ │IP ACL  │  Auth  │  MFA  │Rate Limit│  │  │
                    │  │ ├────────┼────────┼───────┼──────────┤  │  │
                    │  │ │  RBAC  │ Policy │ Audit │  Custom  │  │  │
                    │  │ └────────┴────────┴───────┴──────────┘  │  │
                    │  └─────────────────────────────────────────┘  │
                    │                                               │
                    │  ┌────────────┐  ┌──────────────────────┐    │
                    │  │  Session   │  │   Router / Pool      │    │
                    │  │  Manager   │  │   (Load Balancer)    │    │
                    │  └────────────┘  └──────────────────────┘    │
                    │                                               │
                    │  ┌────────────┐  ┌──────────┐  ┌──────────┐  │
                    │  │  Webhook   │  │  Admin   │  │ Session  │  │
                    │  │  Notifier  │  │  API     │  │ Store    │  │
                    │  └────────────┘  └──────────┘  └──────────┘  │
                    │                                               │
                    │  ┌────────────┐  ┌──────────┐  ┌──────────┐  │
                    │  │  Health    │  │ Metrics  │  │  Logger  │  │
                    │  │  Check     │  │          │  │ (JSON)   │  │
                    │  └────────────┘  └──────────┘  └──────────┘  │
                    └───────────────────────────────────────────────┘
```

### Key Components

| Component | Description |
|-----------|-------------|
| `ssh_server` | libssh-based SSH listener with epoll + signalfd event loop |
| `session` | Thread-safe session lifecycle manager |
| `filter` | Ordered filter chain (connect → auth → route → data → close) |
| `auth_filter` | Password + public key authentication; LDAP backend support |
| `rbac_filter` | Role-based access control with glob-pattern matching |
| `audit_filter` | JSON event logs, asciicast recordings, command audit |
| `rate_limit_filter` | Per-IP and global rate/concurrency limits |
| `policy_filter` | Fine-grained per-user, per-upstream feature policy enforcement |
| `ip_acl_filter` | CIDR-based IP whitelist/blacklist filtering |
| `mfa_filter` | TOTP two-factor authentication (self-contained SHA1/HMAC-SHA1) |
| `router` | Multi-upstream routing with load balancing and connection pooling |
| `proxy_handler` | Per-connection SSH handshake, auth, and bidirectional forwarding |
| `health_check` | HTTP /health, /metrics, and admin API endpoints |
| `metrics` | Atomic runtime counters (connections, auth, bytes, errors) |
| `webhook` | Async HTTP POST event notifications with retry |
| `session_store` | Distributed session storage (local memory or file-based) |
| `logger` | Structured logging with text and JSON (NDJSON) output formats |
| `config` | INI config parser with hot reload and validation support |

## Project Structure

```
ssh-proxy-core/
├── src/                          # Source files (.c) — 20 files
│   ├── main.c                        # Entry point and CLI argument parsing
│   ├── ssh_server.c                  # SSH server (libssh, epoll, signalfd)
│   ├── session.c                     # Session lifecycle manager
│   ├── filter.c                      # Filter chain infrastructure
│   ├── config.c                      # INI config parser and validator
│   ├── router.c                      # Routing, load balancing, connection pool
│   ├── proxy_handler.c              # SSH handshake and bidirectional forwarding
│   ├── auth_filter.c                # Authentication filter (password/pubkey/LDAP)
│   ├── ldap_auth.c                  # Raw-socket LDAP simple bind (no libldap)
│   ├── rbac_filter.c               # Role-based access control filter
│   ├── policy_filter.c             # Feature policy enforcement filter
│   ├── audit_filter.c              # Audit logging, recording, command capture
│   ├── rate_limit_filter.c         # Rate and concurrency limiting filter
│   ├── ip_acl_filter.c             # IP whitelist/blacklist filter
│   ├── mfa_filter.c                # TOTP/MFA filter (self-contained SHA1)
│   ├── health_check.c              # HTTP server (health, metrics, admin API)
│   ├── metrics.c                    # Prometheus metrics collection
│   ├── logger.c                     # Structured logging (text/JSON)
│   ├── webhook.c                    # Async webhook event notifications
│   └── session_store.c             # Session storage (local/file backends)
├── include/                      # Header files (.h) — 19 files
│   ├── ssh_server.h, session.h, filter.h, config.h, router.h
│   ├── proxy_handler.h, auth_filter.h, rbac_filter.h, policy_filter.h
│   ├── audit_filter.h, rate_limit_filter.h, ip_acl_filter.h
│   ├── mfa_filter.h, health_check.h, metrics.h, logger.h
│   ├── webhook.h, session_store.h, version.h
├── tests/                        # Test files (.c) — 11 files
│   ├── test_config.c                 # Configuration parsing tests
│   ├── test_filter.c                 # Filter chain tests
│   ├── test_session.c               # Session management tests
│   ├── test_router.c                # Routing and connection pool tests
│   ├── test_ssh_server.c           # SSH server tests
│   ├── test_logger.c               # Logging tests
│   ├── test_ip_acl_filter.c        # IP ACL tests
│   ├── test_mfa_filter.c           # TOTP/MFA tests
│   ├── test_session_store.c        # Session store tests
│   ├── test_webhook.c              # Webhook tests
│   └── test_integration.c          # Integration tests
├── lib/                          # Third-party libraries
├── docs/                         # Documentation
│   ├── DESIGN.md                     # Architecture and design decisions
│   ├── DEPLOYMENT.md                # Production deployment guide
│   ├── TESTING.md                   # Test suite and manual testing
│   └── config.example.ini          # Example configuration file
├── scripts/                      # Build and utility scripts
├── deploy/                       # Deployment files
│   └── ssh-proxy.service            # systemd unit file
├── build/                        # Build output directory
├── Makefile                      # Build configuration
├── Dockerfile                    # Docker build file
├── config.ini                    # Default configuration
├── CHANGELOG.md                  # Version history
├── CONTRIBUTING.md               # Contribution guide
├── SECURITY.md                   # Security policy
├── LICENSE                       # GNU GPL v3.0
├── README.md                     # Chinese documentation
└── README_EN.md                  # English documentation (this file)
```

## Build

### Dependencies

- **GCC** (C11 support)
- **Make**
- **libssh** (>= 0.9.0) — SSH protocol library
- **pthread** — Thread support
- **crypt** — Password hashing
- *(Optional)* **clang-format** — Code formatting
- *(Optional)* **cppcheck** — Static analysis

### Install Dependencies (Ubuntu/Debian)

```bash
sudo apt update
sudo apt install -y build-essential libssh-dev
```

### Install libssh from Source

If the system package is unavailable or too old:

```bash
./scripts/install-libssh.sh
```

### Build Targets

| Target | Description |
|--------|-------------|
| `make` | Debug build (default) |
| `make debug` | Debug build with symbols |
| `make release` | Optimized release build |
| `make lib` | Build static library |
| `make test` | Build and run all tests |
| `make run` | Build and run with debug config |
| `make install` | Install to system (`PREFIX=/usr/local`) |
| `make clean` | Clean build artifacts |
| `make format` | Format source code (clang-format) |
| `make check` | Static analysis (cppcheck) |
| `make help` | Show all available targets |

## Terraform Bridge

The control plane ships with a lightweight Terraform bridge at
`cmd/terraform-provider`. It is designed for `external` data sources,
`local-exec`, or thin wrappers that want to reuse the current REST API without
requiring a full Terraform plugin runtime.

### Environment Variables

- `SSHPROXY_SERVER` — control-plane URL, for example `https://proxy.example.com:8443`
- `SSHPROXY_TOKEN` — API Bearer token

### Supported Actions

- Read: `read-users`, `read-user <username>`, `read-servers`, `read-server <id>`, `read-config`
- Mutate: `create-user`, `update-user`, `delete-user`, `create-server`, `update-server`, `delete-server`, `apply-config`

### Examples

```bash
# Read the current config
SSHPROXY_SERVER=https://proxy.example.com:8443 \
SSHPROXY_TOKEN=$TOKEN \
go run ./cmd/terraform-provider read-config

# "Import" an existing user / server by identifier for Terraform state alignment
go run ./cmd/terraform-provider read-user alice
go run ./cmd/terraform-provider read-server srv-1

# Create a user
printf '{"username":"alice","password":"Str0ngPass!","role":"operator"}' \
  | go run ./cmd/terraform-provider create-user
```

## API Reference

### Session Manager (`session.h`)

```c
session_manager_t *session_manager_create(const session_manager_config_t *config);
void session_manager_destroy(session_manager_t *manager);
session_t *session_manager_create_session(session_manager_t *manager, ssh_session client);
void session_manager_remove_session(session_manager_t *manager, session_t *session);
size_t session_manager_cleanup(session_manager_t *manager);
```

### Filter Chain (`filter.h`)

```c
filter_chain_t *filter_chain_create(void);
void filter_chain_destroy(filter_chain_t *chain);
int filter_chain_add(filter_chain_t *chain, filter_t *filter);
filter_status_t filter_chain_on_connect(filter_chain_t *chain, filter_context_t *ctx);
filter_status_t filter_chain_on_auth(filter_chain_t *chain, filter_context_t *ctx);
```

### Router (`router.h`)

```c
router_t *router_create(const router_config_t *config);
void router_destroy(router_t *router);
int router_add_upstream(router_t *router, const upstream_config_t *config);
int router_resolve(router_t *router, const char *username, const char *target,
                   route_result_t *result);
ssh_session router_connect(router_t *router, route_result_t *result, uint32_t timeout_ms);
```

### Connection Pool (`router.h`) *(v0.3.0)*

```c
int connection_pool_init(connection_pool_t *pool, size_t max_idle, uint32_t max_idle_time);
ssh_session connection_pool_get(connection_pool_t *pool, const char *host, uint16_t port);
int connection_pool_put(connection_pool_t *pool, const char *host, uint16_t port,
                        ssh_session session);
void connection_pool_cleanup(connection_pool_t *pool);
void connection_pool_destroy(connection_pool_t *pool);
```

### Session Store (`session_store.h`) *(v0.3.0)*

```c
session_store_t *session_store_create(const session_store_config_t *config);
void session_store_destroy(session_store_t *store);
int session_store_put(session_store_t *store, const session_store_record_t *record);
int session_store_get(session_store_t *store, uint64_t session_id,
                      session_store_record_t *record);
int session_store_remove(session_store_t *store, uint64_t session_id);
int session_store_list(session_store_t *store, session_store_record_t *records,
                       size_t max_records, size_t *count);
size_t session_store_count(session_store_t *store);
size_t session_store_count_user(session_store_t *store, const char *username);
int session_store_sync(session_store_t *store);
```

### Webhook (`webhook.h`) *(v0.3.0)*

```c
webhook_t *webhook_create(const webhook_config_t *config);
void webhook_destroy(webhook_t *webhook);
int webhook_notify(webhook_t *webhook, webhook_event_type_t event,
                   const char *payload_json);
```

### Config (`config.h`)

```c
proxy_config_t *config_load(const char *path);
void config_destroy(proxy_config_t *config);
int config_reload(proxy_config_t *config, const char *path);
config_user_t *config_find_user(proxy_config_t *config, const char *username);
config_route_t *config_find_route(proxy_config_t *config, const char *username);
```

## Development

### Adding a Custom Filter

```c
#include "filter.h"

// Define filter callbacks
static filter_status_t my_on_connect(filter_t *filter, filter_context_t *ctx) {
    LOG_INFO("Custom filter: new connection from %s", ctx->client_addr);
    return FILTER_CONTINUE;  // or FILTER_REJECT
}

static filter_status_t my_on_auth(filter_t *filter, filter_context_t *ctx) {
    LOG_INFO("Custom filter: auth for %s", ctx->username);
    return FILTER_CONTINUE;
}

static void my_on_close(filter_t *filter, filter_context_t *ctx) {
    LOG_INFO("Custom filter: connection closed");
}

// Create and register the filter
filter_callbacks_t callbacks = {
    .on_connect = my_on_connect,
    .on_auth = my_on_auth,
    .on_close = my_on_close
};
filter_t *my_filter = filter_create("my_filter", FILTER_TYPE_CUSTOM, &callbacks, config);
filter_chain_add(chain, my_filter);
```

### Embedded Usage

```c
#include "session.h"
#include "filter.h"
#include "router.h"

// Create session manager
session_manager_config_t sm_cfg = {
    .max_sessions = 1000,
    .session_timeout = 3600,
    .auth_timeout = 60
};
session_manager_t *session_mgr = session_manager_create(&sm_cfg);

// Create filter chain
filter_chain_t *filters = filter_chain_create();

// Add auth filter
auth_filter_config_t auth_cfg = {
    .backend = AUTH_BACKEND_CALLBACK,
    .allow_password = true,
    .password_cb = my_auth_callback,
    .cb_user_data = my_context
};
filter_chain_add(filters, auth_filter_create(&auth_cfg));

// Create router with connection pool
router_config_t router_cfg = {
    .lb_policy = LB_POLICY_ROUND_ROBIN,
    .connect_timeout_ms = 10000,
    .max_retries = 3,
    .retry_initial_delay_ms = 100,
    .retry_backoff_factor = 2.0,
    .pool_enabled = true,
    .pool_max_idle = 10
};
router_t *router = router_create(&router_cfg);

// Add upstream
upstream_config_t upstream = { .port = 22, .enabled = true };
strcpy(upstream.host, "backend.example.com");
router_add_upstream(router, &upstream);
```

### Debugging

```bash
# Debug build
make debug

# Run with GDB
gdb ./build/bin/ssh-proxy-core

# Run with debug logging
./build/bin/ssh-proxy-core -d -c config.ini
```

### Code Quality

```bash
# Format source code
make format

# Static analysis
make check
```

## Deployment

### systemd

```bash
sudo cp deploy/ssh-proxy.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ssh-proxy

# Check status
sudo systemctl status ssh-proxy

# View logs
sudo journalctl -u ssh-proxy -f

# Reload configuration
sudo systemctl reload ssh-proxy
```

### Docker

```bash
# Build image
docker build -t ssh-proxy-core .

# Run container
docker run -d -p 2222:2222 -p 9090:9090 \
  -v /path/to/config.ini:/etc/ssh-proxy/config.ini:ro \
  -v /path/to/host_key:/etc/ssh-proxy/host_key:ro \
  -v /var/log/ssh-proxy:/var/log/ssh-proxy \
  ssh-proxy-core
```

## Documentation

| Document | Description |
|----------|-------------|
| [Quick Start Guide](docs/quickstart.md) | From installation to first use |
| [API Reference](docs/api-reference.md) | All REST API endpoints with request/response examples |
| [Architecture & Design](docs/DESIGN.md) | Dual-plane architecture, module design, data flow |
| [Deployment Guide](docs/DEPLOYMENT.md) | Production deployment, systemd, Docker, Kubernetes |
| [Testing Guide](docs/TESTING.md) | C and Go test suites, coverage matrix |
| [Configuration Example](docs/config.example.ini) | Full configuration file template |
| [Contributing](CONTRIBUTING.md) | Development guidelines for C and Go components |
| [Security Policy](SECURITY.md) | Vulnerability reporting |
| [Changelog](CHANGELOG.md) | Version history |

## License

This project is licensed under the [GNU GPL v3.0 only](LICENSE). See the [LICENSE](LICENSE) file for details.
