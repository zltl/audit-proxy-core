# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | :white_check_mark: |
| < 0.2   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in SSH Proxy Core, please report it
responsibly. **Do not open a public GitHub issue for security vulnerabilities.**

### How to Report

1. Email your findings to the project maintainers (see CODEOWNERS or repository contacts).
2. Include a clear description of the vulnerability and steps to reproduce.
3. If possible, include a proof-of-concept or minimal test case.

### What to Expect

- **Acknowledgement**: We will acknowledge receipt of your report within 48 hours.
- **Assessment**: We will assess the severity and impact within 5 business days.
- **Fix Timeline**: Critical vulnerabilities will be patched within 7 days.
  High-severity issues within 14 days. Medium/low within 30 days.
- **Disclosure**: We will coordinate with you on public disclosure timing.
  We follow a 90-day disclosure policy.

### Scope

The following are in scope for security reports:

- Authentication bypass or weakness
- Authorization/RBAC bypass
- Session hijacking or fixation
- Audit log tampering or bypass
- Buffer overflows or memory corruption
- Denial of service vulnerabilities
- Information disclosure (credentials, session data)
- Upstream connection security issues
- Configuration injection or path traversal

### Out of Scope

- Social engineering attacks
- Denial of service via resource exhaustion (unless disproportionate)
- Issues in third-party dependencies (report upstream, but notify us)

## Security Best Practices for Deployment

1. **File Permissions**: Ensure config files are `0600` and owned by the service user.
2. **Host Keys**: Use at least RSA 4096-bit or Ed25519 keys.
3. **Network**: Run behind a firewall; expose only the SSH proxy port.
4. **Audit Logs**: Store audit logs on a separate, append-only filesystem.
5. **Updates**: Subscribe to release notifications and update promptly.
