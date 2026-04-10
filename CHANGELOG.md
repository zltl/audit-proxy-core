# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-04-10

### Added — Go Control Plane

#### Workflow Automation (P7.3)
- Script library with CRUD operations and version tracking (`/api/v2/automation/scripts`)
- Batch SSH job orchestration with parallel target execution (`/api/v2/automation/jobs`)
- Job run history with per-target stdout/stderr capture (`/api/v2/automation/runs`)
- Cron-based job scheduler with automatic background execution
- CI/CD trigger integration for GitHub Actions, GitLab CI, and Jenkins
  (`POST /api/v2/automation/jobs/{id}/trigger`)
- SSH executor with multi-hop jump-chain support, password/key/env/file secret resolution
- Automation Web UI page with script editor, job builder, and run history table
  - New files: `internal/api/automation.go`, `internal/api/automation_ssh.go`,
    `internal/api/automation_test.go`, `web/templates/pages/automation.html`

#### Unified Protocol Gateway (P7.4 / P7.5)
- Ephemeral local-listener gateway supporting 11 protocol presets:
  SOCKS5, RDP, VNC, MySQL, PostgreSQL, Redis, Kubernetes API, HTTP, HTTPS, X11, TCP
- Full RFC 1928 SOCKS5 implementation (no-auth, CONNECT, IPv4/IPv6/domain)
- Multi-hop jump-chain tunnelling shared with the automation subsystem via
  reusable `sshClientConnector` (extracted to `internal/api/ssh_transport.go`)
- Lifecycle REST API: create / list / get / delete gateway proxies
  (`/api/v2/gateway/proxies`)
- SCP/SFTP feature detection validated in C data-plane test suite
  - New files: `internal/api/ssh_transport.go`, `internal/api/gateway.go`,
    `internal/api/gateway_test.go`

#### Intelligent Insights (P7.6)
- Command intent classification: maps audited commands to categories
  (`discovery`, `service-operation`, `database-admin`, `kubernetes-admin`,
  `destructive-change`) with risk scoring (`/api/v2/insights/command-intents`)
- Anomaly baseline & deviation detection: per-user behavioural baselines with
  alerts for rare targets, rare intents, off-pattern hours, and high-risk
  commands (`/api/v2/insights/anomalies`)
- Least-privilege recommendations: suggests role narrowing and time-based
  conditions from observed usage (`/api/v2/insights/recommendations`)
- Natural-language policy preview: converts free-text access requests into
  structured policy rules without persisting (`/api/v2/insights/policy-preview`)
- Audit summary generation: compact digest of audit activity for a given time
  range (`/api/v2/insights/audit-summary`)
  - New files: `internal/api/insights_api.go`, `internal/api/insights_api_test.go`

#### Infrastructure
- Shared SSH client connector with multi-hop jump-chain, key/password auth, env/file
  secret resolution, and known_hosts verification (`internal/api/ssh_transport.go`)
- OpenAPI route definitions for all new endpoints (`internal/openapi/routes.go`)
- Sidebar navigation link for Automation UI
- Integration of automation scheduler start and gateway Close into server lifecycle

### Changed
- `internal/api/api.go` — added `automation` and `gateway` state fields, initialised
  in `New()`, wired into `RegisterRoutes()` and `Close()`
- `internal/server/server.go` — started automation scheduler on boot; registered
  `/automation` page route
- `web/templates/partials/sidebar.html` — added Automation nav entry
- `docs/api-reference.md` — added Automation, Gateway, and Insights sections
- `docs/quickstart.md` — added usage examples for new APIs

### Technical Notes
- All gateway proxies are ephemeral in-memory listeners (not persisted to disk);
  they survive until explicitly stopped or process restart
- Insights API uses deterministic regex/heuristic classification, not ML/NLP,
  which is appropriate for the current operational stage
- Automation data persists as JSON files under `data_dir`:
  `automation_scripts.json`, `automation_jobs.json`, `automation_runs.json`
- Full Go test suite (466+ tests) and C test suite (188+ tests) pass

---

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
