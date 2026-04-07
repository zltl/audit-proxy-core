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

[route:*]
upstream = 10.0.1.10
port = 22
user = ubuntu

[admin]
enabled = true
```

### Control-Plane JSON Config

The Go control-plane reads a separate JSON configuration. Key fields:

```json
{
  "listen_addr": ":8443",
  "session_secret": "change-me-to-a-random-32-byte-string",
  "admin_user": "admin",
  "admin_pass_hash": "$2a$10$...",
  "data_plane_addr": "http://127.0.0.1:9090",
  "audit_log_dir": "/var/log/ssh-proxy",
  "recording_dir": "/var/lib/ssh-proxy/recordings"
}
```

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
