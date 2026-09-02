# Legacy C data plane (deprecated)

This directory holds the original libssh-based C data plane (`src/`, `include/`, `tests/`).

**New deployments should use the Go data plane** (`cmd/dataplane`). The C path remains for reference and migration only. Known protocol limitations versus the Go dataplane include: only the first session channel per connection, no port forwarding, and no upstream host-key verification.

## Build

From the repository root:

```bash
make legacy-c      # build
make legacy-test   # unit tests
```

Or:

```bash
make -C legacy/c-dataplane release
```

Docker (from repo root):

```bash
docker build -f legacy/c-dataplane/Dockerfile -t ssh-proxy-core:legacy .
```

`config.ini` and `sshproxy migrate ini2db` remain supported for importing legacy configuration into the database-backed Go stack.
