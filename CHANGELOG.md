# Changelog

All notable changes will be documented in this file.

## [0.1.0] — 2026-04-07

### Added
- Lockfile parser — reads `package-lock.json` v3 and builds full dependency tree
- CVE checker — queries GitHub Advisory Database API for vulnerabilities in your exact package versions
- Hook detector — flags `postinstall`, `prepare`, `prepublish`, and other lifecycle hooks with risk assessment
- Lockfile diff — compares current lockfile against a baseline to surface unexpected changes
- CLI with colored terminal output and exit codes (0=safe, 1=medium, 2=high/critical, 3=error)
- JSON output mode for CI integration
- HTML dashboard with color-coded risk indicators
- GitHub Action manifest at `action/action.yml`
- Library API — import `checkCVEs`, `detectHooks`, `reportText` for programmatic use
- MIT license

### Not yet implemented (deferred)
- VS Code extension
- Real-time npm registry monitoring
- Package signing / Sigstore integration
- Web-hosted dashboard
