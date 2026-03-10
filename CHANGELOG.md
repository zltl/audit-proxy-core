# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-03-09

### Added
- IP whitelist/blacklist filter (`ip_acl_filter`) with CIDR notation support and whitelist/blacklist modes
  - New files: `src/ip_acl_filter.c`, `include/ip_acl_filter.h`, `tests/test_ip_acl_filter.c` (18 tests)
- Per-user concurrent session limits in rate_limit_filter via `on_authenticated` callback
- Upstream connection retry with configurable exponential backoff (`router_connect_with_retry()`)
- Configuration validation mode (`--check` / `-t` flag, like nginx -t) with `config_validate()` API
- Command audit logging — keystroke buffering in `on_data_upstream`, command extraction on newline detection
  - Writes to `{audit_dir}/commands_YYYYMMDD.log`
- Structured JSON logging (NDJSON format) with `log_set_format()` API, configurable via `[logging] format = json`
- Login Banner/MOTD support with variable expansion ({username}, {client_ip}, {datetime}, {hostname}, {version})
- Admin REST API extending health check HTTP server
  - `GET /api/v1/sessions` — list active sessions
  - `DELETE /api/v1/sessions/{id}` — force disconnect session
  - `GET /api/v1/upstreams` — list upstream server status
  - `POST /api/v1/upstreams/{id}/enable|disable` — toggle upstream
  - `POST /api/v1/reload` — trigger configuration reload
  - `GET /api/v1/config` — get current configuration summary
  - Optional Bearer token authentication
- Webhook/event notification system with async HTTP POST delivery
  - Worker thread with ring buffer queue
  - Events: auth.success/failure, session.start/end, rate_limit.triggered, ip_acl.denied, upstream.unhealthy/healthy, config.reloaded
  - Configurable retry with backoff
  - New files: `src/webhook.c`, `include/webhook.h`, `tests/test_webhook.c` (11 tests)
- Upstream SSH connection pool with keepalive, idle timeout, and health checking
- LDAP authentication backend via raw TCP socket with BER encoding (zero external dependencies)
  - New file: `src/ldap_auth.c`
- TOTP/MFA two-factor authentication with self-contained SHA1/HMAC-SHA1/Base32 implementation
  - Passes RFC 2202 HMAC-SHA1 test vectors
  - New files: `src/mfa_filter.c`, `include/mfa_filter.h`, `tests/test_mfa_filter.c` (14 tests)
- Distributed session storage abstraction with local (memory) and file-based (NDJSON + flock) backends
  - New files: `src/session_store.c`, `include/session_store.h`, `tests/test_session_store.c` (10 tests)

### Changed
- Project grew from ~10,000 to ~14,700 lines of C code
- Source files: 16 → 20, header files: 15 → 19, test files: 7 → 11
- Test suite: 86+ unit tests across 10 test suites
- Rate limit filter extended with `on_authenticated` callback for per-user checks
- Router extended with retry logic and connection pooling
- Audit filter extended with command recording implementation
- Auth filter LDAP backend stub replaced with working implementation
- Health check HTTP server extended into admin REST API with method+path routing
- Logger extended with JSON format support
- Config parser extended with validation API and new config sections

### Technical Notes
- All new features maintain zero external dependency policy
- All features backward compatible — disabled by default, existing configs work unchanged
- Compiles cleanly with `-Wall -Wextra -Wpedantic -Werror`
- Thread-safe implementations using pthread mutexes throughout

## [0.2.0] - 2026-03-09

### Added
- GPL-3.0-only LICENSE file
- Semantic version management (`include/version.h`)
- GitHub Actions CI/CD pipeline (`.github/workflows/ci.yml`)
- Dockerfile for container-based deployment
- systemd service file (`deploy/ssh-proxy.service`)
- SECURITY.md security disclosure policy
- CONTRIBUTING.md contributor guidelines
- CHANGELOG.md (this file)
- Real public key authentication (replaces placeholder)
- Config file permission validation on startup
- SIGHUP-based configuration hot-reload
- HTTP health check endpoint (`/health`) on configurable port
- Prometheus-compatible metrics endpoint (`/metrics`)
- Improved graceful shutdown with connection draining
- Config validation on load (port ranges, required fields, file existence)
- English documentation (`README_EN.md`)

### Changed
- Pinned `json-gen-c` dependency to specific commit SHA for reproducible builds
- Updated `main.c` to use `version.h` constants
- Improved shutdown sequence: stop accepting, drain sessions, then exit
- Updated docs/TESTING.md and docs/DEPLOYMENT.md to match current code state

### Fixed
- Public key authentication was non-functional (placeholder only)
- Config files with world-readable permissions now emit warnings

## [0.1.0] - 2025-01-05

### Added
- Initial SSH proxy core with filter chain architecture
- Password authentication via crypt-based hashing
- RBAC filter for role-based access control
- Policy filter for SSH feature control (shell, exec, scp, sftp, git, port-forward)
- Audit filter with asciicast recording
- Rate limit filter for connection throttling
- Router with Round-Robin, Random, Least-Connections, Hash load balancing
- INI-based configuration with user/route/policy definitions
- Upstream health checks (TCP connect)
- epoll + signalfd based event loop
- json-gen-c integration for type-safe JSON serialization
