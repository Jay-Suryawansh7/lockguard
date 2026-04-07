# LockGuard

[![npm version](https://img.shields.io/npm/v/lockguard?style=flat-square)](https://www.npmjs.com/package/lockguard)
[![npm downloads](https://img.shields.io/npm/dw/lockguard?style=flat-square)](https://www.npmjs.com/package/lockguard)
[![CI](https://img.shields.io/github/actions/workflow/status/Jay-Suryawansh7/lockguard/CI.yml?style=flat-square)](https://github.com/Jay-Suryawansh7/lockguard/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](https://opensource.org/licenses/MIT)

**npm supply-chain security scanner** — detect malicious postinstall hooks, CVE vulnerabilities, and unexpected lockfile changes before they ship.

```bash
npx lockguard
```

## Why LockGuard

npm supply-chain attacks are accelerating. In September 2025, 18 widely-used packages (chalk, debug, axios) were compromised in a single campaign — 2.6 billion weekly downloads affected. In March 2026, Axios itself was trojanized via a malicious postinstall hook.

`npm audit` misses novel attack patterns and suspicious install scripts. LockGuard catches what audit doesn't.

## Features

- **CVE detection** — queries the GitHub Advisory Database for vulnerabilities in your exact package versions
- **Lifecycle hook detection** — flags `postinstall`, `prepare`, `prepublish`, and other hooks with risk assessment
- **Lockfile diff** — compares against a baseline to surface unexpected package changes
- **Monorepo support** — auto-detects workspaces and scans all `package-lock.json` files
- **Multiple output formats** — text, JSON, HTML dashboard, SARIF
- **Config file** — save defaults in `.lockguardrc`
- **GitHub Action** — first-class CI integration with SARIF output for the Security tab

## Installation

```bash
npm install -g lockguard
```

Or run without installing:

```bash
npx lockguard
```

## Quick Start

```bash
# Scan your project
lockguard

# Scan and save HTML report
lockguard --output html > report.html

# Compare against a baseline lockfile
lockguard --baseline package-lock.json.backup

# Use SARIF output for GitHub Security tab
lockguard --output sarif > results.sarif
```

## Configuration

Create a `.lockguardrc` in your project root:

```json
{
  "token": "ghp_your_github_token",
  "skipCve": false,
  "skipHooks": false,
  "riskThreshold": "high",
  "output": "text",
  "baseline": "package-lock.json.backup"
}
```

Or use the init command:

```bash
lockguard --init
```

Environment variables:
- `LOCKGUARD_GITHUB_TOKEN` — GitHub API token (for higher rate limits)
- `CHAIN_GUARD_GITHUB_TOKEN` — legacy alias (deprecated, use `LOCKGUARD_GITHUB_TOKEN`)

## Monorepo Support

LockGuard auto-detects npm/yarn/pnpm workspaces:

```bash
# Scan all workspaces
lockguard --workspaces

# Verbose mode shows each workspace
lockguard --workspaces --verbose
```

## Output Formats

| Format | Flag | Use case |
|--------|------|----------|
| Text | `--output text` | Terminal, CI logs |
| JSON | `--output json` | Scripting, data pipelines |
| HTML | `--output html` | Reports, dashboards |
| SARIF | `--output sarif` | GitHub Security tab, security dashboards |

### SARIF Integration

SARIF output integrates with GitHub Security tab:

```bash
lockguard --output sarif > lockguard-results.sarif
```

Upload results to GitHub:

```yaml
- name: Run LockGuard
  run: lockguard --output sarif > results.sarif

- name: Upload to GitHub Security tab
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
    category: lockguard
```

## GitHub Action

```yaml
- uses: Jay-Suryawansh7/lockguard-action@v1
  with:
    lockfile-path: 'package-lock.json'
    output-format: 'text'
    token: ${{ secrets.GITHUB_TOKEN }}
```

Outputs:
- `risk-level` — `low`, `medium`, `high`, `critical`
- `risk-score` — numeric score 0-100
- `cve-count` — number of CVEs found
- `hook-count` — number of suspicious hooks found

## CLI Options

```
lockguard [options]

Options:
  -p, --path <path>          path to package-lock.json
  -o, --output <format>       output format: text, json, html, sarif (default: text)
  -b, --baseline <path>      baseline package-lock.json for diff
  -t, --token <token>        GitHub API token
  --no-cve                   skip CVE checks
  --no-hooks                 skip lifecycle hook detection
  --workspaces               scan all workspaces in a monorepo
  --threshold <level>        risk threshold: low, medium, high, critical (default: high)
  --init                     create a .lockguardrc config file
  -q, --quiet                quiet output
  -v, --verbose              verbose output
  -h, --help                 display help for command
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No issues found |
| 1 | Medium risk found |
| 2 | High or critical risk found |
| 3 | Error |

## Library API

```ts
import {
  checkCVEs,
  detectHooks,
  reportText,
  reportSARIF,
  loadConfig,
  detectWorkspaces,
} from 'lockguard';

const cveResults = await checkCVEs([
  { name: 'axios', version: '1.14.0' },
]);

const hookResults = await detectHooks([
  { name: 'lodash', version: '4.17.21' },
]);

const workspaces = detectWorkspaces(process.cwd());
console.log(reportText({ cveResults, hookResults, ... }));
```

## Architecture

```
src/
  cli.ts          # Commander.js CLI entry
  index.ts        # Library API exports
  lib/
    parser.ts    # package-lock.json parser
    cve.ts       # GitHub Advisory DB integration
    hooks.ts      # Lifecycle hook detector
    diff.ts       # Lockfile diff against baseline
    report.ts     # Text, JSON, HTML output
    sarif.ts      # SARIF output for GitHub Security tab
    config.ts     # Config file loading (.lockguardrc)
    workspaces.ts # Monorepo/workspace detection
```

## Development

```bash
git clone https://github.com/Jay-Suryawansh7/lockguard.git
cd lockguard
npm install
npm test
npm run build
```

## License

MIT
