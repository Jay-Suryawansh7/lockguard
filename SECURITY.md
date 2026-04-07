# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in LockGuard, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please send details to the maintainer via:

- GitHub Security Advisories (preferred): https://github.com/Jay-Suryawansh7/lockguard/security/advisories/new

Or email the maintainer directly.

Please include:

1. Description of the vulnerability
2. Steps to reproduce
3. Potential impact
4. Any suggested fixes (optional)

## Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 7 days
- **Fix timeline**: Depends on severity, typically within 30 days

## Security Best Practices for LockGuard Users

- Keep your `LOCKGUARD_GITHUB_TOKEN` secret — never commit it to version control
- Use a `.lockguardrc` file with appropriate permissions (`chmod 600`)
- Review hook detection results carefully — not all hooks are malicious
- Keep LockGuard updated: `npm install -g lockguard`
- Use the SARIF output with GitHub Security tab for continuous monitoring
