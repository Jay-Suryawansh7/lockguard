#!/usr/bin/env node

import { Command } from 'commander';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
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
import { reportSARIF } from './lib/sarif.js';
import { loadConfig } from './lib/config.js';
import { detectWorkspaces } from './lib/workspaces.js';

const pkg = JSON.parse(readFileSync(resolve(import.meta.dirname, '../package.json'), 'utf-8'));

const program = new Command();

program
  .name('lockguard')
  .description('npm supply-chain security scanner')
  .version(pkg.version)
  .option('-p, --path <path>', 'path to package-lock.json')
  .option('-o, --output <format>', 'output format: text, json, html, sarif')
  .option('-b, --baseline <path>', 'baseline package-lock.json for diff')
  .option('-t, --token <token>', 'GitHub API token for CVE lookups')
  .option('--no-cve', 'skip CVE checks')
  .option('--no-hooks', 'skip lifecycle hook detection')
  .option('--workspaces', 'scan all workspaces in a monorepo')
  .option('--threshold <level>', 'risk threshold: low, medium, high, critical', 'high')
  .option('--init', 'create a .lockguardrc config file')
  .option('-q, --quiet', 'only output results, no progress info')
  .option('-v, --verbose', 'verbose output')
  .hook('preAction', (thisCmd, actionCmd) => {
    if (actionCmd.opts().init) {
      initConfig();
      process.exit(0);
    }
  })
  .parse(process.argv);

const opts = program.opts();
const config = loadConfig();

function initConfig(): void {
  if (existsSync('.lockguardrc')) {
    console.error('.lockguardrc already exists. Delete it first to recreate.');
    process.exit(1);
  }
  const defaultConfig = {
    token: process.env.LOCKGUARD_GITHUB_TOKEN || '',
    skipCve: false,
    skipHooks: false,
    riskThreshold: 'high',
    output: 'text',
  };
  console.log('Creating .lockguardrc with defaults. Edit it to configure.');
  writeFileSync('.lockguardrc', JSON.stringify(defaultConfig, null, 2));
}

async function scan(path: string, baseline?: string, quiet = false): Promise<ScanResult> {
  if (!quiet) {
    console.error(`Scanning ${path}...`);
  }
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

  const token = opts.token || config.token || process.env.LOCKGUARD_GITHUB_TOKEN;

  const [cveResults, hookResults] = await Promise.all([
    (opts.cve !== false && !config.skipCve) ? checkCVEs(pkgList, token) : Promise.resolve([]),
    (opts.hooks !== false && !config.skipHooks) ? detectHooks(pkgList) : Promise.resolve([]),
  ]);

  const diff = baseline || config.baseline ? diffLockfiles(path, baseline || config.baseline!) : undefined;

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

function getThresholdExitCode(level: ScanResult['riskLevel']): number {
  switch (level) {
    case 'critical': return 2;
    case 'high': return 2;
    case 'medium': return 1;
    default: return 0;
  }
}

async function main() {
  try {
    const outputFormat = opts.output || config.output || 'text';
    const baseline = opts.baseline || config.baseline;
    const threshold = opts.threshold || config.riskThreshold || 'high';

    if (opts.workspaces || opts.verbose) {
      const workspaces = detectWorkspaces(process.cwd());
      if (workspaces.length === 0) {
        console.error('No workspaces found.');
        process.exit(0);
      }
      console.error(`Found ${workspaces.length} workspace(s).\n`);

      const results: ScanResult[] = [];
      for (const ws of workspaces) {
        const result = await scan(ws.lockfile, baseline, opts.quiet);
        results.push(result);
      }

      const totalCVEs = results.reduce((acc, r) => acc + r.totalCVEs, 0);
      const totalHooks = results.reduce((acc, r) => acc + r.totalSuspiciousHooks, 0);
      const maxScore = Math.max(...results.map(r => r.riskScore));
      const maxLevel = calcRiskLevel(maxScore);

      const aggregate: ScanResult = {
        scannedAt: new Date().toISOString(),
        packageCount: results.reduce((acc, r) => acc + r.packageCount, 0),
        cveResults: results.flatMap(r => r.cveResults),
        hookResults: results.flatMap(r => r.hookResults),
        riskScore: maxScore,
        riskLevel: maxLevel,
        totalCVEs,
        totalSuspiciousHooks: totalHooks,
      };

      let output: string;
      switch (outputFormat) {
        case 'json':
          output = reportJSON(aggregate);
          break;
        case 'html':
          output = reportHTML(aggregate);
          break;
        case 'sarif':
          output = reportSARIF(aggregate);
          break;
        default:
          output = reportText(aggregate);
      }

      if (outputFormat === 'html') {
        process.stdout.write(output);
      } else {
        process.stdout.write(output + '\n');
      }

      if (aggregate.riskScore >= thresholdScore(threshold)) {
        process.exit(2);
      }
      process.exit(0);
      return;
    }

    const path = opts.path || 'package-lock.json';
    const result = await scan(path, baseline, opts.quiet);
    let output: string;

    switch (outputFormat) {
      case 'json':
        output = reportJSON(result);
        break;
      case 'html':
        output = reportHTML(result);
        process.stdout.write(output);
        return;
      case 'sarif':
        output = reportSARIF(result);
        break;
      default:
        output = reportText(result);
    }

    process.stdout.write(output + '\n');

    if (result.riskScore >= thresholdScore(threshold)) {
      process.exit(2);
    }
    process.exit(0);
  } catch (err) {
    console.error(`Error: ${err instanceof Error ? err.message : err}`);
    process.exit(3);
  }
}

function thresholdScore(t: string): number {
  switch (t) {
    case 'critical': return 70;
    case 'high': return 40;
    case 'medium': return 20;
    case 'low': return 0;
    default: return 40;
  }
}

main();
