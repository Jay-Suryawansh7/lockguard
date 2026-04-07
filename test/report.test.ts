import { severityScore, clearCache } from '../src/lib/cve.js';
import { calcRiskScore, calcRiskLevel } from '../src/lib/report.js';
import type { CVEResult, Advisory } from '../src/lib/cve.js';
import type { LockfileDiff } from '../src/lib/diff.js';

describe('cve', () => {
  test('severityScore returns correct values', () => {
    expect(severityScore('critical')).toBe(10);
    expect(severityScore('high')).toBe(7);
    expect(severityScore('moderate')).toBe(4);
    expect(severityScore('low')).toBe(1);
  });
});

describe('report', () => {
  test('calcRiskLevel returns correct levels', () => {
    expect(calcRiskLevel(0)).toBe('low');
    expect(calcRiskLevel(15)).toBe('low');
    expect(calcRiskLevel(20)).toBe('medium');
    expect(calcRiskLevel(35)).toBe('medium');
    expect(calcRiskLevel(40)).toBe('high');
    expect(calcRiskLevel(65)).toBe('high');
    expect(calcRiskLevel(70)).toBe('critical');
    expect(calcRiskLevel(100)).toBe('critical');
  });

  test('calcRiskScore accumulates from CVEs', () => {
    const cveResults: CVEResult[] = [
      {
        packageName: 'axios',
        version: '1.0.0',
        advisories: [
          {
            ghsaId: 'GHSA-xxxx',
            cveId: 'CVE-2025-0001',
            summary: 'Remote code execution',
            description: 'RCE via malicious postinstall',
            severity: 'critical',
            vulnerableVersionRange: '>=1.0.0',
          },
        ],
      },
    ];

    const score = calcRiskScore(cveResults, [], undefined);
    expect(score).toBeGreaterThanOrEqual(25);
  });

  test('calcRiskScore accumulates from hooks', () => {
    const hookResults = [
      {
        packageName: 'suspicious-lib',
        packageVersion: '1.0.0',
        hooks: ['postinstall'],
        risk: 'high' as const,
        reason: 'Contains eval()',
      },
    ];

    const score = calcRiskScore([], hookResults, undefined);
    expect(score).toBeGreaterThanOrEqual(15);
  });

  test('calcRiskScore caps at 100', () => {
    const manyCVEs: CVEResult[] = Array.from({ length: 10 }, (_, i) => ({
      packageName: `pkg-${i}`,
      version: '1.0.0',
      advisories: Array.from({ length: 5 }, (_, j) => ({
        ghsaId: `GHSA-${i}-${j}`,
        summary: 'Critical vuln',
        description: '',
        severity: 'critical' as const,
        vulnerableVersionRange: '>=0',
      })),
    }));

    const score = calcRiskScore(manyCVEs, [], undefined);
    expect(score).toBeLessThanOrEqual(100);
  });
});
