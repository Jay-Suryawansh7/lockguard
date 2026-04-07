#!/usr/bin/env node

import { Command } from 'commander';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { parseLockfile, getAllPackages } from './lib/parser.js';
import { checkCVEs } from './lib/cve.js';
import { detectHooks } from './lib/hooks.js';
import { diffLockfiles } from './lib/diff.js';
import {
  type ScanResult,
  calcRiskScore,
  calcRiskLevel,
  reportText,
  reportJSON,
  reportHTML,
} from './lib/report.js';

const pkg = JSON.parse(readFileSync(resolve(import.meta.dirname, '../package.json'), 'utf-8'));

const program = new Command();

program
  .name('lockguard')
  .description('npm supply-chain security scanner')
  .version(pkg.version)
  .option('-p, --path <path>', 'path to package-lock.json', 'package-lock.json')
  .option('-o, --output <format>', 'output format: text, json, html', 'text')
  .option('-b, --baseline <path>', 'baseline package-lock.json for diff')
  .option('-t, --token <token>', 'GitHub API token for CVE lookups', process.env.CHAIN_GUARD_GITHUB_TOKEN)
  .option('-w, --workspace <path>', 'workspace root (scans all package-lock.json files)', process.cwd())
  .option('--no-cve', 'skip CVE checks')
  .option('--no-hooks', 'skip lifecycle hook detection')
  .parse(process.argv);

const opts = program.opts();

async function scan(path: string): Promise<ScanResult> {
  const lockfileRaw = readFileSync(resolve(path), 'utf-8');
  const lockfile = parseLockfile(lockfileRaw);
  const packages = getAllPackages(lockfile);

  const pkgList = packages.map(({ path: p, pkg }) => {
    const name = p.replace(/^node_modules\/?/, '').replace(/^@[^/]+\//, '').split('node_modules').pop() || '';
    return {
      name,
      version: pkg.version || 'unknown',
      resolved: pkg.resolved,
    };
  }).filter(p => p.name);

  const [cveResults, hookResults] = await Promise.all([
    opts.cve !== false ? checkCVEs(pkgList, opts.token) : Promise.resolve([]),
    opts.hooks !== false ? detectHooks(pkgList) : Promise.resolve([]),
  ]);

    const diff = opts.baseline ? diffLockfiles(path, opts.baseline) : undefined;

  const totalCVEs = cveResults.reduce((acc, r) => acc + r.advisories.length, 0);
  const totalSuspiciousHooks = hookResults.filter(h => h.risk === 'high').length;
  const riskScore = calcRiskScore(cveResults, hookResults, diff);
  const riskLevel = calcRiskLevel(riskScore);

  return {
    scannedAt: new Date().toISOString(),
    packageCount: packages.length,
    cveResults,
    hookResults,
    diff,
    riskScore,
    riskLevel,
    totalCVEs,
    totalSuspiciousHooks,
  };
}

async function main() {
  try {
    const result = await scan(opts.path);
    let output: string;

    switch (opts.output) {
      case 'json':
        output = reportJSON(result);
        break;
      case 'html':
        output = reportHTML(result);
        process.stdout.write(output);
        return;
      default:
        output = reportText(result);
    }

    process.stdout.write(output);

    if (result.riskLevel === 'critical' || result.riskLevel === 'high') {
      process.exit(2);
    } else if (result.riskLevel === 'medium') {
      process.exit(1);
    } else {
      process.exit(0);
    }
  } catch (err) {
    console.error(`Error: ${err instanceof Error ? err.message : err}`);
    process.exit(3);
  }
}

main();
