# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-03-09

### Added
- Apache-2.0 LICENSE file
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
