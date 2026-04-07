import type { CVEResult, Advisory } from './cve.js';
import type { HookInfo } from './hooks.js';
import type { LockfileDiff } from './diff.js';

export type OutputFormat = 'text' | 'json' | 'html';

export interface ScanResult {
  scannedAt: string;
  packageCount: number;
  cveResults: CVEResult[];
  hookResults: HookInfo[];
  diff?: LockfileDiff;
  riskScore: number;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  totalCVEs: number;
  totalSuspiciousHooks: number;
}

export function calcRiskLevel(score: number): ScanResult['riskLevel'] {
  if (score >= 70) return 'critical';
  if (score >= 40) return 'high';
  if (score >= 20) return 'medium';
  return 'low';
}

export function calcRiskScore(
  cveResults: CVEResult[],
  hookResults: HookInfo[],
  diff?: LockfileDiff
): number {
  let score = 0;

  for (const r of cveResults) {
    for (const adv of r.advisories) {
      switch (adv.severity) {
        case 'critical': score += 25; break;
        case 'high': score += 15; break;
        case 'moderate': score += 5; break;
        case 'low': score += 1; break;
      }
    }
  }

  for (const h of hookResults) {
    if (h.risk === 'high') score += 15;
    else if (h.risk === 'medium') score += 5;
    else score += 1;
  }

  if (diff) {
    score += diff.totalAdded * 2;
    score += diff.totalChanged;
  }

  return Math.min(score, 100);
}

export function reportText(result: ScanResult): string {
  const lines: string[] = [];
  const riskIcon = result.riskLevel === 'critical' ? '🔴' :
    result.riskLevel === 'high' ? '🟠' :
    result.riskLevel === 'medium' ? '🟡' : '🟢';

  lines.push(`\n${riskIcon} Chain Guard Scan — ${result.scannedAt}`);
  lines.push(`Risk Level: ${result.riskLevel.toUpperCase()} (score: ${result.riskScore})`);
  lines.push(`Packages scanned: ${result.packageCount}`);
  lines.push(`CVEs found: ${result.totalCVEs}`);
  lines.push(`Suspicious hooks: ${result.totalSuspiciousHooks}\n`);

  if (result.cveResults.some(r => r.advisories.length > 0)) {
    lines.push('─── CVE Vulnerabilities ───');
    for (const r of result.cveResults) {
      if (r.advisories.length === 0) continue;
      lines.push(`\n  ${r.packageName}@${r.version}`);
      for (const adv of r.advisories) {
        lines.push(`    [${adv.severity.toUpperCase()}] ${adv.ghsaId}${adv.cveId ? ` / ${adv.cveId}` : ''}`);
        lines.push(`    ${adv.summary}`);
        if (adv.firstPatchedVersion) {
          lines.push(`    Patched in: ${adv.firstPatchedVersion}`);
        }
      }
    }
  }

  if (result.hookResults.length > 0) {
    lines.push('\n─── Suspicious Lifecycle Hooks ───');
    for (const h of result.hookResults) {
      const icon = h.risk === 'high' ? '⚠️' : h.risk === 'medium' ? '⚡' : 'ℹ️';
      lines.push(`\n  ${icon} ${h.packageName}@${h.packageVersion} — ${h.risk.toUpperCase()}`);
      lines.push(`     Hooks: ${h.hooks.join(', ')}`);
      lines.push(`     Reason: ${h.reason}`);
    }
  }

  if (result.diff) {
    const d = result.diff;
    lines.push('\n─── Lockfile Changes ───');
    if (d.totalAdded > 0) lines.push(`  Added: ${d.totalAdded}`);
    if (d.totalChanged > 0) lines.push(`  Changed: ${d.totalChanged}`);
    if (d.totalRemoved > 0) lines.push(`  Removed: ${d.totalRemoved}`);
  }

  lines.push('');
  return lines.join('\n');
}

export function reportJSON(result: ScanResult): string {
  return JSON.stringify(result, null, 2);
}

export function reportHTML(result: ScanResult): string {
  const riskColors: Record<string, string> = {
    critical: '#dc2626',
    high: '#ea580c',
    medium: '#ca8a04',
    low: '#16a34a',
  };
  const riskColor = riskColors[result.riskLevel] || '#6b7280';

  const cveRows = result.cveResults
    .filter(r => r.advisories.length > 0)
    .map(r => `
      <div class="pkg-block">
        <div class="pkg-name">${escapeHtml(r.packageName)} <span class="version">@${escapeHtml(r.version)}</span></div>
        ${r.advisories.map(a => `
          <div class="advisory advisory--${a.severity}">
            <span class="badge badge--${a.severity}">${a.severity}</span>
            <span class="advisory-id">${escapeHtml(a.ghsaId)}${a.cveId ? ` / ${escapeHtml(a.cveId)}` : ''}</span>
            <div class="advisory-summary">${escapeHtml(a.summary)}</div>
            ${a.firstPatchedVersion ? `<div class="patched">Patched: ${escapeHtml(a.firstPatchedVersion)}</div>` : ''}
          </div>
        `).join('')}
      </div>
    `).join('');

  const hookRows = result.hookResults.map(h => `
    <div class="hook-block hook--${h.risk}">
      <div class="pkg-name">${escapeHtml(h.packageName)} <span class="version">@${escapeHtml(h.packageVersion)}</span> <span class="badge badge--risk-${h.risk}">${h.risk}</span></div>
      <div class="hook-reason">${escapeHtml(h.reason)}</div>
      <div class="hook-list">Hooks: ${h.hooks.map(hook => `<code>${escapeHtml(hook)}</code>`).join(', ')}</div>
    </div>
  `).join('');

  const diffRows = result.diff ? `
    <div class="diff-summary">
      <div class="diff-stat diff-added">+${result.diff.totalAdded} added</div>
      <div class="diff-stat diff-changed">~${result.diff.totalChanged} changed</div>
      <div class="diff-stat diff-removed">-${result.diff.totalRemoved} removed</div>
    </div>
  ` : '';

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Chain Guard Report</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; padding: 2rem; }
  .container { max-width: 900px; margin: 0 auto; }
  h1 { font-size: 1.5rem; font-weight: 700; color: #f8fafc; margin-bottom: 0.25rem; }
  .subtitle { color: #64748b; font-size: 0.875rem; margin-bottom: 2rem; }
  .risk-header { background: #1e293b; border-radius: 12px; padding: 1.5rem; margin-bottom: 2rem; border: 1px solid #334155; }
  .risk-score { font-size: 3rem; font-weight: 800; color: ${riskColor}; }
  .risk-label { font-size: 0.875rem; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; }
  .stats { display: flex; gap: 1.5rem; margin-top: 1rem; flex-wrap: wrap; }
  .stat { }
  .stat-num { font-size: 1.25rem; font-weight: 700; color: #f8fafc; }
  .stat-label { font-size: 0.75rem; color: #64748b; }
  .section { background: #1e293b; border-radius: 12px; padding: 1.5rem; margin-bottom: 1.5rem; border: 1px solid #334155; }
  .section-title { font-size: 0.875rem; font-weight: 600; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 1rem; }
  .pkg-block { margin-bottom: 1.25rem; padding-bottom: 1.25rem; border-bottom: 1px solid #334155; }
  .pkg-block:last-child { border-bottom: none; margin-bottom: 0; padding-bottom: 0; }
  .pkg-name { font-weight: 600; color: #f8fafc; font-size: 1rem; }
  .version { color: #64748b; font-weight: 400; }
  .advisory { padding: 0.75rem; border-radius: 8px; margin-top: 0.5rem; }
  .advisory--critical { background: rgba(220,38,38,0.1); border: 1px solid rgba(220,38,38,0.3); }
  .advisory--high { background: rgba(234,88,12,0.1); border: 1px solid rgba(234,88,12,0.3); }
  .advisory--moderate { background: rgba(202,138,4,0.1); border: 1px solid rgba(202,138,4,0.3); }
  .advisory--low { background: rgba(22,163,74,0.1); border: 1px solid rgba(22,163,74,0.3); }
  .badge { display: inline-block; padding: 0.125rem 0.5rem; border-radius: 9999px; font-size: 0.7rem; font-weight: 700; text-transform: uppercase; margin-right: 0.5rem; }
  .badge--critical { background: #dc2626; color: white; }
  .badge--high { background: #ea580c; color: white; }
  .badge--moderate { background: #ca8a04; color: white; }
  .badge--low { background: #16a34a; color: white; }
  .badge--risk-high { background: #dc2626; color: white; }
  .badge--risk-medium { background: #ca8a04; color: white; }
  .badge--risk-low { background: #16a34a; color: white; }
  .advisory-id { font-family: monospace; font-size: 0.8rem; color: #94a3b8; }
  .advisory-summary { margin-top: 0.25rem; font-size: 0.875rem; color: #cbd5e1; }
  .patched { margin-top: 0.25rem; font-size: 0.75rem; color: #16a34a; }
  .hook-block { padding: 0.75rem; border-radius: 8px; margin-top: 0.5rem; }
  .hook--high { background: rgba(220,38,38,0.1); border: 1px solid rgba(220,38,38,0.3); }
  .hook--medium { background: rgba(202,138,4,0.1); border: 1px solid rgba(202,138,4,0.3); }
  .hook--low { background: rgba(22,163,74,0.1); border: 1px solid rgba(22,163,74,0.3); }
  .hook-reason { margin-top: 0.25rem; font-size: 0.875rem; color: #cbd5e1; }
  .hook-list { margin-top: 0.25rem; font-size: 0.75rem; color: #64748b; }
  code { background: #334155; padding: 0.125rem 0.375rem; border-radius: 4px; font-family: monospace; font-size: 0.8rem; }
  .diff-summary { display: flex; gap: 1rem; }
  .diff-stat { padding: 0.5rem 1rem; border-radius: 8px; font-weight: 700; font-size: 0.875rem; }
  .diff-added { background: rgba(22,163,74,0.15); color: #4ade80; }
  .diff-changed { background: rgba(202,138,4,0.15); color: #fbbf24; }
  .diff-removed { background: rgba(220,38,38,0.15); color: #f87171; }
  .empty { color: #64748b; font-style: italic; }
  .footer { text-align: center; color: #475569; font-size: 0.75rem; margin-top: 2rem; }
</style>
</head>
<body>
<div class="container">
  <h1>Chain Guard</h1>
  <div class="subtitle">Supply-chain security scan — ${escapeHtml(result.scannedAt)}</div>

  <div class="risk-header">
    <div class="risk-label">Overall Risk Score</div>
    <div class="risk-score">${result.riskScore}</div>
    <div class="stats">
      <div class="stat"><div class="stat-num">${result.packageCount}</div><div class="stat-label">Packages scanned</div></div>
      <div class="stat"><div class="stat-num">${result.totalCVEs}</div><div class="stat-label">CVEs found</div></div>
      <div class="stat"><div class="stat-num">${result.totalSuspiciousHooks}</div><div class="stat-label">Suspicious hooks</div></div>
    </div>
  </div>

  ${cveRows ? `<div class="section"><div class="section-title">CVE Vulnerabilities</div>${cveRows || '<div class="empty">No known CVE vulnerabilities found.</div>'}</div>` : ''}

  ${hookRows ? `<div class="section"><div class="section-title">Suspicious Lifecycle Hooks</div>${hookRows}</div>` : ''}

  ${result.diff ? `<div class="section"><div class="section-title">Lockfile Changes</div>${diffRows}</div>` : ''}

  <div class="footer">Generated by Chain Guard</div>
</div>
</body>
</html>`;
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
