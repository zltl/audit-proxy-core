# SSH Proxy Core

High-performance, extensible SSH protocol proxy server core library, implemented in pure C.

[中文文档](README.md)

## Features

- **Proxy Forwarding**: Transparent and explicit proxy with multi-backend routing
- **Filter Chain**: Envoy-style extensible filter architecture
  - Auth Filter: User authentication (Password, PublicKey)
  - RBAC Filter: Role-based access control
  - Audit Filter: Session auditing and recording (asciicast format)
  - Rate Limit Filter: Connection rate and concurrency limits
- **Session Management**: Complete SSH session lifecycle management
- **Routing & Load Balancing**: Round-Robin, Random, Least-Connections, Hash policies
- **Health Check**: Automatic backend health detection, HTTP health/metrics endpoints
- **Hot Reload**: SIGHUP-based configuration reload without downtime
- **Observability**: Prometheus metrics endpoint, structured audit logs

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

### 3. Run

```bash
# Start with config file
./build/bin/ssh-proxy-core -c config.ini

# Debug mode
./build/bin/ssh-proxy-core -d -c config.ini

# Show version
./build/bin/ssh-proxy-core --version
```

### 4. Connect

```bash
ssh -p 2222 admin@proxy-server
```

## Operations

### Health Check & Metrics

The health check HTTP server listens on `127.0.0.1:9090` by default:

```bash
# Health status (JSON)
curl http://localhost:9090/health

# Prometheus metrics
curl http://localhost:9090/metrics
```

### Configuration Reload

Reload configuration without restarting:

```bash
kill -HUP $(pgrep ssh-proxy-core)
```

### Systemd Deployment

```bash
sudo cp deploy/ssh-proxy.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ssh-proxy
```

### Docker

```bash
docker build -t ssh-proxy-core .
docker run -d -p 2222:2222 -p 9090:9090 \
  -v /path/to/config.ini:/etc/ssh-proxy/config.ini:ro \
  ssh-proxy-core
```

## Architecture

```
Client ──► SSH Server ──► Filter Chain ──► Router ──► Upstream
              │              │
              │         ┌────┴────┐
              │         │ Filters │
              │         ├─────────┤
              │         │RateLimit│
              │         │  Auth   │
              │         │  RBAC   │
              │         │  Audit  │
              │         └─────────┘
              │
         Session Manager
```

### Key Components

| Component | Description |
|-----------|-------------|
| `ssh_server` | libssh-based listener with epoll + signalfd |
| `session` | Thread-safe session lifecycle manager |
| `filter` | Ordered filter chain (connect → auth → route → data → close) |
| `auth_filter` | Password + public key authentication |
| `rbac_filter` | Glob-pattern-based feature policy enforcement |
| `audit_filter` | JSON event logs + asciicast terminal recordings |
| `rate_limit_filter` | Per-IP and global rate/concurrency limits |
| `router` | Multi-upstream routing with load balancing |
| `proxy_handler` | Per-connection SSH handshake, auth, and bidirectional forwarding |
| `health_check` | HTTP /health and /metrics endpoints |
| `metrics` | Atomic runtime counters (connections, auth, bytes) |

## Build Targets

| Target | Description |
|--------|-------------|
| `make` | Debug build (default) |
| `make release` | Optimized release build |
| `make test` | Build and run all tests |
| `make lib` | Build static library |
| `make run` | Build and run with debug config |
| `make install` | Install to system (`PREFIX=/usr/local`) |
| `make format` | Format source code (clang-format) |
| `make check` | Static analysis (cppcheck) |

## Documentation

- [Design Document](docs/DESIGN.md) — Architecture and design decisions
- [Deployment Guide](docs/DEPLOYMENT.md) — Production deployment instructions
- [Testing Guide](docs/TESTING.md) — Test suite and manual testing
- [Contributing](CONTRIBUTING.md) — How to contribute
- [Security Policy](SECURITY.md) — Vulnerability reporting
- [Changelog](CHANGELOG.md) — Version history

## License

This project is licensed under the [GNU GPL v3.0 only](LICENSE).
