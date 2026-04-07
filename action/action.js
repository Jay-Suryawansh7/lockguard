import * as core from '@actions/core';
import { readFileSync } from 'node:fs';
import { parseLockfile, getAllPackages } from './lib/parser.js';
import { checkCVEs } from './lib/cve.js';
import { detectHooks } from './lib/hooks.js';
import { reportText, calcRiskScore, calcRiskLevel } from './lib/report.js';

async function run() {
  const lockfilePath = core.getInput('lockfile-path') || 'package-lock.json';
  const baselinePath = core.getInput('baseline-path');
  const outputFormat = core.getInput('output-format') || 'text';
  const token = core.getInput('token');
  const skipCVE = core.getInput('skip-cve') === 'true';
  const skipHooks = core.getInput('skip-hooks') === 'true';

  const lockfileRaw = readFileSync(lockfilePath, 'utf-8');
  const lockfile = parseLockfile(lockfileRaw);
  const packages = getAllPackages(lockfile);

  const pkgList = packages.map(({ path, pkg }) => ({
    name: path.replace(/^node_modules\/?/, '').replace(/^@[^/]+\//, '').split('node_modules').pop() || '',
    version: pkg.version || 'unknown',
  })).filter(p => p.name);

  const [cveResults, hookResults] = await Promise.all([
    skipCVE ? Promise.resolve([]) : checkCVEs(pkgList, token || undefined),
    skipHooks ? Promise.resolve([]) : detectHooks(pkgList),
  ]);

  const totalCVEs = cveResults.reduce((acc, r) => acc + r.advisories.length, 0);
  const totalHooks = hookResults.filter(h => h.risk === 'high').length;
  const riskScore = calcRiskScore(cveResults, hookResults, undefined);
  const riskLevel = calcRiskLevel(riskScore);

  const result = {
    scannedAt: new Date().toISOString(),
    packageCount: packages.length,
    cveResults,
    hookResults,
    riskScore,
    riskLevel,
    totalCVEs,
    totalSuspiciousHooks: totalHooks,
  };

  const output = reportText(result);
  core.info(output);

  core.setOutput('risk-level', riskLevel);
  core.setOutput('risk-score', riskScore.toString());
  core.setOutput('cve-count', totalCVEs.toString());
  core.setOutput('hook-count', totalHooks.toString());

  if (riskLevel === 'critical' || riskLevel === 'high') {
    core.setFailed(`Chain Guard found ${totalCVEs} CVE(s) and ${totalHooks} suspicious hook(s). Risk level: ${riskLevel}`);
  }
}

run().catch(err => {
  core.error(`Chain Guard action failed: ${err}`);
  core.setFailed(err.message);
});
