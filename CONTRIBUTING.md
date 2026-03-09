# Contributing to SSH Proxy Core

Thank you for your interest in contributing! This document provides guidelines
for contributing to the project.

## Getting Started

1. Fork the repository and clone your fork.
2. Install dependencies: `sudo apt install build-essential libssh-dev`
3. Build the project: `make`
4. Run the tests: `make test`

## Development Workflow

1. Create a feature branch from `main`: `git checkout -b feat/my-feature`
2. Make your changes, ensuring tests pass: `make test`
3. Run static analysis: `make check`
4. Format your code: `make format`
5. Commit with a descriptive message (see below).
6. Push and open a pull request.

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

Types: `feat`, `fix`, `docs`, `chore`, `refactor`, `test`, `perf`, `ci`

Examples:
- `feat(auth): add LDAP authentication backend`
- `fix(router): handle upstream timeout correctly`
- `docs: update deployment guide for Docker`

## Code Style

- C11 standard (`-std=c11`)
- Use `clang-format` (config in `.clang-format`)
- Use safe string functions (`strncpy`, `snprintf`)
- All public APIs must have Doxygen-style comments in headers
- Run `make format` before committing

## Testing

- Add unit tests for new modules in `tests/test_<module>.c`
- Add integration test cases in `tests/test_integration.c`
- Use the test macros from `tests/test_utils.h`
- All tests must pass before merging: `make test`

## Adding a New Filter

1. Create `src/<name>_filter.c` and `include/<name>_filter.h`
2. Implement the `filter_callbacks_t` interface
3. Register the filter in `main.c`
4. Add tests in `tests/test_<name>_filter.c`
5. Document the filter in `README.md`

## Security

If you discover a security vulnerability, please see [SECURITY.md](SECURITY.md)
for responsible disclosure instructions. **Do not open a public issue.**

## License

By contributing, you agree that your contributions will be licensed under
the Apache License 2.0 (see [LICENSE](LICENSE)).
