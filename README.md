# LockGuard

**npm supply-chain security scanner** — detect malicious postinstall hooks, CVE vulnerabilities, and unexpected lockfile changes before they ship.

```
npx lockguard
```

## What it does

Chain Guard scans your `package-lock.json` and flags:

- **CVE vulnerabilities** via the GitHub Advisory Database
- **Malicious lifecycle hooks** (`postinstall`, `prepare`, `prepublish`, etc.) in your dependencies
- **Unexpected lockfile changes** compared against a baseline (git commit, saved snapshot)

## Why

npm supply-chain attacks are accelerating. In September 2025, 18 widely-used packages (chalk, debug, axios, and more) were compromised in a single campaign — 2.6 billion weekly downloads affected. In March 2026, Axios itself was trojanized via a malicious postinstall hook.

`npm audit` doesn't catch novel attacks or suspicious install scripts. LockGuard fills that gap.

## Installation

```bash
npm install -g lockguard
```

Or run without installing:

```bash
npx lockguard
```

## Usage

```bash
# Basic scan
chain-guard

# Scan a specific lockfile
lockguard --path ./package-lock.json
lockguard --baseline ./package-lock.json.old
lockguard --output html > report.html
lockguard --output json > result.json
lockguard --no-cve

# Set GitHub token for higher API rate limits
export CHAIN_GUARD_GITHUB_TOKEN=ghp_your_token
chain-guard
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | No issues found |
| 1 | Medium risk found |
| 2 | High or critical risk found |
| 3 | Error |

## GitHub Action

```yaml
- uses: Jay-Suryawansh7/lockguard-action@v1
  with:
    lockfile-path: 'package-lock.json'
    output-format: 'text'
```

Outputs: `risk-level`, `risk-score`, `cve-count`, `hook-count`

## Library API

```ts
import { checkCVEs, detectHooks, reportText } from 'lockguard';

const cveResults = await checkCVEs([
  { name: 'axios', version: '1.14.0' },
]);
const hookResults = await detectHooks([
  { name: 'lodash', version: '4.17.21' },
]);

console.log(reportText({ cveResults, hookResults, ... }));
```

## Architecture

```
src/
  cli.ts          # Commander.js CLI entry
  lib/
    parser.ts     # package-lock.json parser
    cve.ts        # GitHub Advisory DB integration
    hooks.ts      # Lifecycle hook detector
    diff.ts       # Lockfile diff against baseline
    report.ts     # Text, JSON, HTML output
  index.ts        # Library API
```

## Development

```bash
npm install
npm test
npm run build
```

## License

MIT
