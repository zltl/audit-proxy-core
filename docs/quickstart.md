# SSH Proxy Core — Quick Start Guide

Get up and running with SSH Proxy Core in minutes.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Building from Source](#2-building-from-source)
3. [Configuration](#3-configuration)
4. [Running the Control Plane](#4-running-the-control-plane)
5. [Accessing the Web UI](#5-accessing-the-web-ui)
6. [Basic API Usage](#6-basic-api-usage)

---

## 1. Prerequisites

| Dependency   | Minimum Version | Purpose                       |
|-------------|-----------------|-------------------------------|
| **Go**      | 1.21+           | Control-plane, CLI tools      |
| **GCC**     | 9+              | C data-plane compilation      |
| **libssh**  | 0.9+            | SSH protocol (data-plane)     |
| **pkg-config** | any          | Library discovery             |

### Install on Ubuntu / Debian

```bash
sudo apt-get update
sudo apt-get install -y golang gcc libssh-dev pkg-config make
```

### Install on Fedora / RHEL

```bash
sudo dnf install golang gcc libssh-devel pkgconf-pkg-config make
```

### Install on macOS (Homebrew)

```bash
brew install go gcc libssh pkg-config
```

Verify installations:

```bash
go version          # go1.21 or later
gcc --version       # GCC 9+
pkg-config --modversion libssh   # 0.9+
```

---

## 2. Building from Source

Clone the repository and build both the C data-plane and Go control-plane:

```bash
git clone https://github.com/ssh-proxy-core/ssh-proxy-core.git
cd ssh-proxy-core
```

### Build the C Data-Plane

```bash
make release        # optimised build (-O2)
# or
make debug          # debug build (-g, address sanitiser)
```

Build artefacts are written to `build/`.  Key targets:

| Target         | Description                     |
|----------------|---------------------------------|
| `make all`     | Default debug build             |
| `make release` | Optimised release build         |
| `make test`    | Compile and run C unit tests    |
| `make clean`   | Remove all build artefacts      |
| `make format`  | Format C source with clang-format |
| `make check`   | Run cppcheck static analysis    |

### Build the Go Control-Plane

```bash
go build -o build/control-plane ./cmd/control-plane
go build -o build/sshproxy      ./cmd/sshproxy
```

Or build everything at once:

```bash
go build ./...
```

### Build the Docker Image (optional)

```bash
docker build -t ssh-proxy-core .
```

---

## 3. Configuration

SSH Proxy Core uses a simple INI-format configuration file. A sample is
provided at `config.ini` in the repository root; a more complete example lives
at `docs/config.example.ini`.

### Minimal `config.ini`

```ini
[server]
bind_addr = 0.0.0.0
port = 2222
host_key = /etc/ssh-proxy/host_key

[logging]
level = info
audit_dir = /var/log/ssh-proxy

[limits]
max_sessions = 100
session_timeout = 3600

[user:admin]
password_hash = $6$rounds=5000$saltsalt$...
enabled = true

[route:admin]
upstream = 10.0.1.10
port = 22
user = ubuntu
# Optional Geo-routing metadata when multiple routes match the same user:
# country_code = US
# region = California
# city = San Francisco
# latitude = 37.7749
# longitude = -122.4194

[route:*]
upstream = 10.0.1.10
port = 22
user = ubuntu

[router]
retry_max = 3
retry_initial_delay_ms = 100
retry_max_delay_ms = 5000
retry_backoff_factor = 2.0
circuit_breaker_enabled = true
circuit_breaker_failure_threshold = 3
circuit_breaker_open_seconds = 30

[admin]
enabled = true
```

### Context-Aware Login Windows

Use `[policy:<user>]` or `[policy:<user>@<upstream>]` sections to restrict when a
user may log in. `login_window` accepts `HH:MM-HH:MM`, `login_days` accepts
comma-separated day names or ranges like `mon-fri`, and `login_timezone`
accepts `UTC` or fixed offsets such as `+08:00`.

```ini
[policy:admin@10.0.1.10]
allow = shell, exec
login_window = 09:00-18:00
login_days = mon-fri
login_timezone = +08:00
```

Overnight windows are supported too. For example, `22:00-02:00` with
`login_days = fri` allows Friday-night access until 02:00 on Saturday.

To differentiate office, VPN, and public Internet access, classify trusted
network ranges once and let policies reference those source types:

```ini
[network_sources]
office_cidrs = 10.0.0.0/8,192.168.0.0/16
vpn_cidrs = 100.64.0.0/10
geoip_data_file = /etc/ssh-proxy/geoip.json

[policy:admin@10.0.1.10]
allowed_source_types = office, vpn
denied_source_types = public
```

For Geo-routing, define multiple matching route sections and annotate each
candidate upstream with location metadata. When the client IP resolves through
`network_sources.geoip_data_file`, the data-plane prefers the best
country/region/city match and then the nearest configured coordinates; if no
GeoIP match is available it falls back to deterministic same-user affinity
across the matching routes instead of raw file order.

When a matched upstream keeps failing TCP connection attempts, the route-level
circuit breaker opens after the configured failure threshold. Open circuits are
skipped during selection, and after `circuit_breaker_open_seconds` only one
half-open recovery probe is allowed back through at a time.

```ini
[network_sources]
geoip_data_file = /etc/ssh-proxy/geoip.json

[route:admin]
upstream = sfo-bastion.example.com
country_code = US
region = California
city = San Francisco
latitude = 37.7749
longitude = -122.4194

[route:admin]
upstream = fra-bastion.example.com
country_code = DE
region = Hesse
city = Frankfurt
latitude = 50.1109
longitude = 8.6821
```

### Control-Plane JSON Config

The Go control-plane reads a separate JSON configuration. Key fields:

```json
{
  "listen_addr": ":8443",
  "session_secret": "change-me-to-a-random-32-byte-string",
  "admin_user": "admin",
  "admin_pass_hash": "$2a$10$...",
  "tls_self_signed": true,
  "tls_self_signed_hosts": "localhost,127.0.0.1",
  "hsts_enabled": true,
  "hsts_include_subdomains": false,
  "data_plane_addr": "http://127.0.0.1:9090",
  "data_plane_config_file": "/etc/ssh-proxy/config.ini",
  "grpc_listen_addr": "127.0.0.1:9445",
  "config_approval_enabled": true,
  "config_store_backend": "file",
  "user_store_backend": "file",
  "postgres_database_url": "postgres://sshproxy:change-me@db.example.com:5432/sshproxy?sslmode=require",
  "postgres_read_database_urls": "postgres://sshproxy:change-me@db-ro-1.example.com:5432/sshproxy?sslmode=require,postgres://sshproxy:change-me@db-ro-2.example.com:5432/sshproxy?sslmode=require",
  "database_max_open_conns": 24,
  "database_max_idle_conns": 12,
  "database_conn_max_lifetime": "30m",
  "database_conn_max_idle_time": "5m",
  "database_read_after_write_window": "2s",
  "audit_log_dir": "/var/log/ssh-proxy",
  "audit_store_backend": "file",
  "audit_store_database_url": "postgres://sshproxy:change-me@db.example.com:5432/sshproxy?sslmode=require",
  "audit_store_read_database_urls": "postgres://sshproxy:change-me@audit-ro.example.com:5432/sshproxy?sslmode=require",
  "recording_dir": "/var/lib/ssh-proxy/recordings",
  "recording_object_storage_enabled": true,
  "recording_object_storage_endpoint": "https://minio.example.com",
  "recording_object_storage_bucket": "ssh-proxy-recordings",
  "recording_object_storage_access_key": "minio-access-key",
  "recording_object_storage_secret_key": "minio-secret-key",
  "recording_object_storage_region": "us-east-1",
  "recording_object_storage_prefix": "recordings",
  "geoip_data_file": "/etc/ssh-proxy/geoip.json",
  "saml_enabled": true,
  "saml_root_url": "https://proxy.example.com",
  "saml_idp_metadata_url": "https://idp.example.com/metadata",
  "saml_sp_cert": "/etc/ssh-proxy/saml-sp.pem",
  "saml_sp_key": "/etc/ssh-proxy/saml-sp.key",
  "saml_username_attribute": "email",
  "saml_roles_attribute": "groups",
  "saml_role_mappings": {
    "Operators": "operator",
    "Admins": "admin"
  },
  "jit_notify_smtp_addr": "mail.example.com:587",
  "jit_notify_email_from": "proxy@example.com",
  "jit_notify_email_to": "approver@example.com,security@example.com",
  "jit_notify_slack_webhook_url": "https://hooks.slack.com/services/T000/B000/XXX",
  "jit_notify_dingtalk_webhook_url": "https://oapi.dingtalk.com/robot/send?access_token=abc",
  "jit_notify_wecom_webhook_url": "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=abc",
  "cluster_enabled": false
}
```

Set `grpc_listen_addr` when you want the control-plane to expose the internal
gRPC bridge generated from `api/proto/sshproxy/v1/control_plane.proto`. The
bridge proxies runtime data-plane operations such as health, session listing,
server inventory, and config reload over gRPC.

Set `config_approval_enabled=true` when configuration edits made through
`PUT /api/v2/config` should create persisted pending changes that require an
admin approval step before the data-plane config file is rewritten and reloaded.

TLS modes are mutually exclusive:

- Provide `tls_cert` + `tls_key` to use operator-managed PEM files.
- Set `tls_self_signed=true` to generate an in-memory self-signed certificate.
- Set `tls_lets_encrypt=true` with `tls_lets_encrypt_hosts` (and optionally
  `tls_lets_encrypt_cache_dir`) to enable automatic Let's Encrypt issuance and renewal.

When serving HTTPS, you can enable HSTS with `hsts_enabled=true`. Add
`hsts_include_subdomains=true` and `hsts_preload=true` only when your full
domain tree is ready for a long-lived HSTS policy.

For cluster-internal node communication, enable mTLS by setting
`cluster_tls_cert`, `cluster_tls_key`, and `cluster_tls_ca` together on every
node. The same certificate/key pair is used for both server and client auth,
so the certificate must be valid for both `serverAuth` and `clientAuth`.

When `cluster_enabled=true`, submit configuration changes to the current leader.
Successful config applies on the leader are distributed automatically to
followers, and you can inspect convergence with `GET /api/v2/config/sync-status`.
The control-plane also persists the latest centralized config snapshot under
`data_dir` and exposes it through `GET /api/v2/config/store`. Session metadata is
also persisted in `data_dir/sessions.db`, so `/api/v2/sessions` and
`/api/v2/sessions/{id}` continue to expose historical session records after the
live SSH session ends or the control-plane restarts.

When you want PostgreSQL to become the system of record for centralized config
snapshots/version history and/or `/api/v2/users`, set `config_store_backend` and
`user_store_backend` to `postgres` and provide `postgres_database_url`. The
control-plane will bootstrap an empty database from the existing `config.ini`,
`config_store.json`, `config_versions/`, and `users.json` state on first start,
but the data-plane still keeps using the local `data_plane_config_file` as its
materialized runtime config.

When you want the audit center to stop scanning raw files directly and instead
query a database-backed index, set `audit_store_backend` to `postgres` or
`timescaledb`. The control-plane keeps writing append-only local audit files
under `audit_log_dir`, then incrementally mirrors `.jsonl` and data-plane
`.log` audit records into the SQL store in the background. If
`audit_store_database_url` is empty, the audit index reuses
`postgres_database_url`.

When you have PostgreSQL replicas available, set
`postgres_read_database_urls` and/or `audit_store_read_database_urls` to a
comma-separated DSN list. Writes still go to the primary DSN, while read-only
queries are load-balanced across replicas. To reduce replica-lag surprises for
immediate admin workflows, the control-plane temporarily pins reads back to the
writer for `database_read_after_write_window` after each local SQL write.
Connection pool size and lifetime are controlled with
`database_max_open_conns`, `database_max_idle_conns`,
`database_conn_max_lifetime`, and `database_conn_max_idle_time`.

To run file-backed state migration explicitly before switching traffic, start
the control-plane in one-shot migration mode:

```bash
control-plane -config /etc/ssh-proxy/control-plane.json -migrate
control-plane -config /etc/ssh-proxy/control-plane.json -migrate -migrate-targets config,users,audit
```

The migration command applies SQL schema upgrades first, then imports
`config_store.json`, `config_versions/`, `users.json`, and/or `audit_log_dir`
into the configured SQL backends. It is safe to re-run: once rows already
exist, the import step becomes a no-op and the command only verifies schema
version state.

To create or restore a logical control-plane backup bundle, use:

```bash
control-plane -config /etc/ssh-proxy/control-plane.json -backup /var/backups/ssh-proxy/backup.json
control-plane -config /etc/ssh-proxy/control-plane.json -restore /var/backups/ssh-proxy/backup.json
control-plane -config /etc/ssh-proxy/control-plane.json -backup /var/backups/ssh-proxy/config-users.json -backup-targets config,users
```

The backup bundle is JSON and captures logical state rather than vendor-specific
database pages, so the same file can be restored into either file-backed or
PostgreSQL-backed config/user stores. By default it includes centralized config
current/version history, users, audit events, and session metadata, plus schema
version metadata for the SQL-backed stores. Restore is replace-oriented: it
rewrites managed config/user/version/session state and, for file-backed audit
restore, replaces the root `.jsonl`/`.log` set under `audit_log_dir` with a
single normalized restore file.

To archive SSH session recordings into S3/MinIO/OSS-compatible storage, set
`recording_object_storage_enabled=true` together with the endpoint, bucket, and
static credentials above. The control-plane keeps writing local asciicast files
to `recording_dir`, scans that directory every 5 seconds, and mirrors
`session_<id>_*.cast` files to `<recording_object_storage_prefix>/sessions/<id>.cast`.
`GET /api/v2/sessions/{id}/recording/download` serves the local file when it is
still present and automatically falls back to the archived object when the local
recording has been deleted or rotated away. The endpoint accepts either a full
`http(s)://` URL or a plain `host:port`, which makes the same config work for
AWS S3, MinIO, and OSS-compatible gateways.

If you also enable the data-plane `[session_store]` file backend for shared
cluster session state, each node now publishes a periodic owner heartbeat for
its active sessions. Healthy peers refresh their own lease in the background,
and stale remote records are removed automatically after several missed sync
intervals. That means `/api/v2/sessions` converges back to the surviving
cluster's real active-session set after a node crash instead of keeping orphaned
entries indefinitely.

`cluster_seeds` accepts either static `host:port` entries or discovery URIs.
For example:

```json
"cluster_enabled": true,
"cluster_node_id": "cp-1",
"cluster_region": "ap-southeast-1",
"cluster_zone": "ap-southeast-1a",
"cluster_bind_addr": "0.0.0.0:9444",
"cluster_heartbeat_interval": "8s",
"cluster_election_timeout": "30s",
"cluster_sync_interval": "12s",
"cluster_seeds": [
  "dns://ssh-proxy.internal:9444",
  "k8s://ssh-proxy.default:9444",
  "consul://consul.service.consul:8500/ssh-proxy?tag=prod"
]
```

Use `dns://` for generic DNS A/AAAA discovery, `k8s://` for Kubernetes Service
DNS names, and `consul://` for healthy Consul service instances.

For cross-AZ or cross-region deployments, label each node with
`cluster_region` and `cluster_zone`. The cluster API will then surface topology
spread, and rolling-upgrade drain checks will refuse to take down the last
healthy node in a region or availability zone. `cluster_heartbeat_interval`,
`cluster_election_timeout`, and `cluster_sync_interval` are optional overrides
for WAN deployments where the default 5s / 15s / 10s timings are too aggressive.

If you prefer a CRD-driven Kubernetes deployment flow instead of Helm, apply
the operator assets under `deploy/operator/` and create an
`SSHProxyCluster.proxy.sshproxy.io/v1alpha1` resource:

```bash
kubectl apply -f deploy/operator/crd.yaml
kubectl apply -f deploy/operator/rbac.yaml
kubectl apply -f deploy/operator/deployment.yaml
kubectl apply -f deploy/operator/example-sshproxycluster.yaml
```

The operator reconciles a namespaced `SSHProxyCluster` into a ServiceAccount,
ConfigMap, Secret, Services, Deployments, and optional PVC. The CR stores raw
`controlPlaneJSON` and `dataPlaneINI`. Values under `spec.secrets` are mounted
as `/etc/ssh-proxy/secrets/*` files for the data-plane and also projected into
the control-plane as `SSH_PROXY_CP_<KEY>` environment variables, so
`session_secret`, `admin_user`, `admin_pass_hash`, and similar control-plane
settings can stay out of the CR body.

For zero-downtime rolling upgrades, put one node into drain mode before
restarting it:

```bash
curl -k -b cookies.txt -H 'Content-Type: application/json' \
  -X PUT https://proxy.example.com/api/v2/system/upgrade \
  -d '{"draining":true}'

curl -k -b cookies.txt https://proxy.example.com/api/v2/system/upgrade
```

While drain mode is enabled, the C data-plane stops accepting new SSH sessions
and `/health` returns `503` with `status=draining`, which lets external load
balancers remove the node from rotation. Existing sessions continue running. The
control-plane reports `ready_for_restart=true` only after local sessions drain,
and in cluster mode the current leader will only report ready when at least one
other healthy peer remains. After the node comes back, disable drain mode with
`{"draining":false}` to accept new sessions again.

Set `data_plane_config_file` when the control plane needs to verify signed
data-plane webhooks or inspect the managed `config.ini` directly. The default
value follows the C data-plane default: `/etc/ssh-proxy/config.ini`.

Set `geoip_data_file` to enable file-backed GeoIP enrichment for threat
detection. The file is a JSON array (or `{ "entries": [...] }`) of CIDR records:

```json
[
  {
    "cidr": "203.0.113.0/24",
    "country_code": "US",
    "country": "United States",
    "region": "California",
    "city": "San Francisco",
    "latitude": 37.7749,
    "longitude": -122.4194
  },
  {
    "cidr": "198.51.100.0/24",
    "country_code": "DE",
    "country": "Germany",
    "region": "Hesse",
    "city": "Frankfurt",
    "latitude": 50.1109,
    "longitude": 8.6821
  }
]
```

To feed real SSH login events into the GeoIP-aware detector, point the data
plane webhook config back at the control plane:

```ini
[webhook]
enabled = true
url = https://proxy.example.com/api/v2/threats/ingest
hmac_secret = replace-with-a-shared-secret
events = auth.success,auth.failure,session.start,session.end

[network_sources]
office_cidrs = 10.0.0.0/8, 192.168.0.0/16
vpn_cidrs = 100.64.0.0/10
```

Audit/event logs and session recordings now force a durable disk sync on every
write, and a full data-plane webhook queue spills events into
`dead_letter_path` (default: `<audit_dir>/webhook-dlq.jsonl`) instead of
silently dropping them. For production deployments, keep `audit_dir`,
`recording_dir`, and the webhook dead-letter file on persistent storage.

The ingest/simulate path now also returns a contextual `risk_assessment`. It
combines GeoIP movement, device fingerprint, source network type, recent auth
failures, and rapid multi-target access into one explainable score, exposes the
latest results through `GET /api/v2/threats/risk`, and can raise the built-in
`high_risk_access` alert when multiple factors stack up.

The Settings page also exposes built-in configuration templates for
`development`, `testing`, and `production`. Selecting one loads a resolved
preview and then reuses the normal diff, approval, and apply flow instead of
introducing a separate template-specific write path.

The same page now supports config import/export in `json`, `yaml`, and `ini`.
Imports are preview-only until you confirm the resulting diff; exports are raw
backups and therefore may contain secrets.

Set `saml_enabled=true` to expose `/auth/saml/login`, `/auth/saml/acs`, and
`/auth/saml/metadata` for browser SSO. `/auth/saml/login` drives SP-initiated
SSO and the ACS endpoint also accepts IdP-initiated POSTs. Configure exactly one of
`saml_idp_metadata_url` or `saml_idp_metadata_file`, and provide
`saml_sp_cert` + `saml_sp_key` so the control plane can publish SP metadata and
sign authentication requests.

By default, SAML assertions fall back to common username/email/group attributes
and map IdP groups into local control-plane roles via `saml_role_mappings`.
Override `saml_username_attribute` or `saml_roles_attribute` when your IdP uses
custom attribute names. Assertions are signature-checked, audience/recipient/time
validated, and encrypted assertions can be decrypted with the same SP key pair.
The metadata-driven flow is intended to interoperate with ADFS, Shibboleth,
OneLogin, and similar enterprise IdPs.

JIT approval notifications can fan out to SMTP email plus Slack, DingTalk, and
WeCom robot webhooks. Configure one or more of the `jit_notify_*` endpoints in
the control-plane JSON config, then enable `notify_on_request` and/or
`notify_on_approve` in the JIT policy API so pending approvals and status
changes are pushed to your approver channels.

The same SMTP relay (`jit_notify_smtp_addr`, optional username/password, and
`jit_notify_email_from`) is also reused by scheduled compliance report delivery.
Custom SQL report templates live under `/api/v2/compliance/templates*`, and
scheduled framework/GDPR/template report jobs live under
`/api/v2/compliance/schedules*`.

Environment variables override every field. The naming convention is
`SSH_PROXY_CP_<UPPER_SNAKE_FIELD>`, for example:

```bash
export SSH_PROXY_CP_LISTEN_ADDR=":9443"
export SSH_PROXY_CP_SESSION_SECRET="my-secret"
```

---

## 4. Running the Control Plane

### Start the C Data-Plane

```bash
./build/ssh_proxy -c config.ini
```

The data-plane exposes an admin API on port 9090 by default.

### Start the Go Control-Plane

```bash
export SSH_PROXY_CP_SESSION_SECRET="change-me"
./build/control-plane -config cp-config.json -addr :8443
```

Or with environment overrides only (no JSON file):

```bash
export SSH_PROXY_CP_SESSION_SECRET="change-me"
export SSH_PROXY_CP_DATA_PLANE_ADDR="http://127.0.0.1:9090"
export SSH_PROXY_CP_ADMIN_USER="admin"
./build/control-plane -addr :8443
```

The control-plane logs to stdout:

```
2025/01/15 10:30:00 control-plane listening on :8443
```

To stop either process, press `Ctrl+C` or send `SIGTERM`.

---

## 5. Accessing the Web UI

Open your browser to:

```
http://localhost:8443
```

(or `https://` if TLS is configured)

When OIDC or SAML is enabled, the login page exposes a matching SSO button
alongside local username/password authentication.

You will see the login page. Sign in with the admin credentials configured in
step 3.

After login you are redirected to the **Dashboard**, which shows:

- Active sessions count
- Server health summary
- Recent audit events

Navigate the sidebar for:

| Page       | Path         | Description                  |
|------------|--------------|------------------------------|
| Dashboard  | `/dashboard` | Overview and statistics      |
| Sessions   | `/sessions`  | Active SSH session list      |
| Users      | `/users`     | User management              |
| Servers    | `/servers`   | Upstream server management   |
| Audit      | `/audit`     | Audit log viewer             |
| Settings   | `/settings`  | Configuration                |
| Terminal   | `/terminal`  | Web-based SSH terminal       |

The browser terminal also supports ZMODEM-based file transfer: drag files onto
the terminal page and then run `rz` remotely to upload, or run `sz <file>`
remotely to download the file into the browser. When `recording_dir` is
configured, the same terminal page also produces a synced `.cast` audit
recording and exposes a direct download link in the toolbar area.

---

## 6. Basic API Usage

All API v2 endpoints live under `/api/v2/`. Responses use a standard JSON
envelope. Below are common examples using `curl`.

### Health Check (no auth)

```bash
curl -s http://localhost:8443/api/v1/health | jq
```

### System Info

```bash
curl -s http://localhost:8443/api/v2/system/info \
  -H "Cookie: session=<your-session-cookie>" | jq
```

### List Users

```bash
curl -s http://localhost:8443/api/v2/users \
  -H "Cookie: session=<your-session-cookie>" | jq '.data'
```

### Create a User

```bash
curl -s -X POST http://localhost:8443/api/v2/users \
  -H "Content-Type: application/json" \
  -H "Cookie: session=<your-session-cookie>" \
  -d '{
    "username": "alice",
    "display_name": "Alice",
    "email": "alice@example.com",
    "role": "user",
    "password": "secureP@ss123"
  }' | jq
```

### List Active Sessions

```bash
curl -s http://localhost:8443/api/v2/sessions \
  -H "Cookie: session=<your-session-cookie>" | jq '.data'
```

### List Servers and Check Health

```bash
# List servers
curl -s http://localhost:8443/api/v2/servers \
  -H "Cookie: session=<your-session-cookie>" | jq '.data'

# Health summary
curl -s http://localhost:8443/api/v2/servers/health \
  -H "Cookie: session=<your-session-cookie>" | jq '.data'
```

### Evaluate a Command (Command Control)

```bash
curl -s -X POST http://localhost:8443/api/v2/commands/evaluate \
  -H "Content-Type: application/json" \
  -H "Cookie: session=<your-session-cookie>" \
  -d '{
    "command": "rm -rf /",
    "username": "alice",
    "role": "user",
    "target": "web-01"
  }' | jq '.data'
# → { "action": "deny", "message": "Recursive delete of root paths blocked" }
```

### Trigger a Discovery Scan

```bash
curl -s -X POST http://localhost:8443/api/v2/discovery/scan \
  -H "Content-Type: application/json" \
  -H "Cookie: session=<your-session-cookie>" \
  -d '{
    "targets": ["10.0.1.0/24"],
    "ports": [22],
    "timeout": "5s"
  }' | jq '.data'
```

---

## Next Steps

- Read the full [API Reference](api-reference.md) for every endpoint
- Review [DEPLOYMENT.md](DEPLOYMENT.md) for production deployment guidance
- See [DESIGN.md](DESIGN.md) for architecture details
- Check [TESTING.md](TESTING.md) for test conventions
