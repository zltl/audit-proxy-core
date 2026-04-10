# Contributing to SSH Proxy Core

Thank you for your interest in contributing! This document provides guidelines
for contributing to the project.

## Getting Started

1. Fork the repository and clone your fork.
2. Install dependencies:
   ```bash
   # C data-plane
   sudo apt install build-essential libssh-dev pkg-config
   # Go control-plane
   # Install Go 1.21+ from https://go.dev/dl/
   ```
3. Build both planes:
   ```bash
   make              # C data-plane
   go build ./...    # Go control-plane
   ```
4. Run the tests:
   ```bash
   make test                 # C unit tests (188+)
   go test ./... -count=1    # Go unit tests (466+)
   ```

## Project Structure

```
src/  include/  tests/     # C data-plane
cmd/  internal/  web/      # Go control-plane
sdk/  api/proto/           # SDKs and proto definitions
deploy/  scripts/          # Deployment & tooling
docs/                      # Documentation
```

See [docs/DESIGN.md](docs/DESIGN.md) for the full architecture description.

## Development Workflow

1. Create a feature branch from `main`: `git checkout -b feat/my-feature`
2. Make your changes, ensuring tests pass.
3. Commit with a descriptive message (see below).
4. Push and open a pull request.

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

Types: `feat`, `fix`, `docs`, `chore`, `refactor`, `test`, `perf`, `ci`

Scopes for C data-plane: `auth`, `filter`, `router`, `audit`, `session`, `proxy`
Scopes for Go control-plane: `api`, `server`, `cluster`, `automation`, `gateway`, `insights`

Examples:
- `feat(auth): add LDAP authentication backend`
- `fix(router): handle upstream timeout correctly`
- `feat(gateway): add PostgreSQL protocol preset`
- `docs: update deployment guide for Docker`

---

## C Data-Plane Guidelines

### Code Style

- C11 standard (`-std=c11`)
- Use `clang-format` (config in `.clang-format`)
- Use safe string functions (`strncpy`, `snprintf`)
- All public APIs must have Doxygen-style comments in headers
- Run `make format` before committing

### Testing

- Add unit tests for new modules in `tests/test_<module>.c`
- Add integration test cases in `tests/test_integration.c`
- Use the test macros from `tests/test_utils.h`
- All tests must pass before merging: `make test`
- For TLS-related changes, also run: `make clean && make TLS_ENABLED=1 test`

### Adding a New Filter

1. Create `src/<name>_filter.c` and `include/<name>_filter.h`
2. Implement the `filter_callbacks_t` interface (8 callbacks)
3. Register the filter in `main.c`
4. Add tests in `tests/test_<name>_filter.c`
5. Document the filter in `README.md`

### Build Targets

| Target | Description |
|--------|-------------|
| `make all` | Default debug build |
| `make release` | Optimised build (`-O2`) |
| `make debug` | Debug build (`-g`, address sanitiser) |
| `make test` | Compile and run all C tests |
| `make format` | clang-format code formatting |
| `make check` | cppcheck static analysis |
| `make clean` | Remove build artefacts |

---

## Go Control-Plane Guidelines

### Code Style

- Follow standard Go conventions (`gofmt`, `go vet`)
- Use the existing helper functions: `writeJSON`, `readJSON`, `writeError`
- Get the current user from `r.Header.Get("X-User")`
- Use the `Set*/Register*Routes` pattern for optional features

### Adding a New API Module

1. Create `internal/api/<module>.go` with state struct and handlers
2. Add the state field to the `API` struct in `internal/api/api.go`
3. Initialise the state in `New()`
4. Call `api.register<Module>Routes(mux)` from `RegisterRoutes()`
5. If the module holds resources, add cleanup to `API.Close()`
6. Add OpenAPI route definitions in `internal/openapi/routes.go`
7. Add tests in `internal/api/<module>_test.go`
8. Document endpoints in `docs/api-reference.md`

### Testing

- Tests use Go's standard `testing` package
- Run: `go test ./... -count=1`
- Use `httptest.NewServer` for HTTP handler tests
- All tests must pass before merging

### Shared SSH Transport

If your feature needs SSH connectivity (e.g., automation, gateway), use the
shared `sshClientConnector` from `internal/api/ssh_transport.go`. It provides:

- Multi-hop jump chain support
- Password / private key authentication
- `${env:VAR}` / `${file:/path}` secret resolution
- `known_hosts` verification

---

## Documentation

- Update `docs/api-reference.md` for new API endpoints
- Update `docs/quickstart.md` for new user-facing features
- Update `CHANGELOG.md` for all notable changes
- Update `docs/DESIGN.md` if the architecture changes

## Security

If you discover a security vulnerability, please see [SECURITY.md](SECURITY.md)
for responsible disclosure instructions. **Do not open a public issue.**

## License

By contributing, you agree that your contributions will be licensed under
the GNU GPL v3.0 only (see [LICENSE](LICENSE)).
