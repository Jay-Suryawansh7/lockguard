import type { CVEResult } from './cve.js';
import type { HookInfo } from './hooks.js';
import type { LockfileDiff } from './diff.js';
import type { ScanResult } from './report.js';

export interface SarifReport {
  version: '2.1.0';
  $schema: string;
  runs: SarifRun[];
}

export interface SarifRun {
  tool: {
    driver: {
      name: string;
      version: string;
      informationUri: string;
      rules: SarifRule[];
    };
  };
  results: SarifResult[];
  properties?: Record<string, unknown>;
}

export interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  help: { text: string; markdown: string };
  properties: {
    tags: string[];
    'security-severity': string;
    'precision'?: string;
  };
}

export interface SarifResult {
  ruleId: string;
  ruleIndex: number;
  level: 'error' | 'warning' | 'note';
  message: { text: string };
  locations: SarifLocation[];
  properties?: Record<string, unknown>;
}

export interface SarifLocation {
  physicalLocation: {
    artifactLocation: { uri: string };
    region?: { startLine: number; startColumn: number };
  };
}

export function reportSARIF(result: ScanResult): string {
  const rules: SarifRule[] = [];
  const results: SarifResult[] = [];

  for (const r of result.cveResults) {
    for (const adv of r.advisories) {
      const ruleId = `CVE-${adv.cveId || adv.ghsaId}`;
      const severity = adv.severity === 'critical' ? 'error' : adv.severity === 'high' ? 'error' : 'warning';
      const sevNum = adv.severity === 'critical' ? '9.0' : adv.severity === 'high' ? '7.0' : adv.severity === 'moderate' ? '4.0' : '2.0';

      const ruleIdx = rules.length;
      rules.push({
        id: ruleId,
        name: `CVE-${adv.cveId || adv.ghsaId}`,
        shortDescription: { text: adv.summary },
        fullDescription: { text: adv.description },
        help: {
          text: `Patch: ${adv.firstPatchedVersion || 'Unknown'}`,
          markdown: `## ${adv.summary}\n\n${adv.description}\n\n**Vulnerable range:** ${adv.vulnerableVersionRange}\n**Patch:** ${adv.firstPatchedVersion || 'No patch available'}`,
        },
        properties: {
          tags: ['security', 'cve', adv.severity],
          'security-severity': sevNum,
          'precision': 'high',
        },
      });

      results.push({
        ruleId,
        ruleIndex: ruleIdx,
        level: severity as 'error' | 'warning' | 'note',
        message: {
          text: `${r.packageName}@${r.version}: ${adv.summary}`,
        },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: 'package-lock.json' },
          },
        }],
        properties: {
          packageName: r.packageName,
          packageVersion: r.version,
          ghsaId: adv.ghsaId,
          cveId: adv.cveId,
        },
      });
    }
  }

  for (const h of result.hookResults) {
    const ruleId = `HOOK-${h.packageName}`;
    const level = h.risk === 'high' ? 'error' : 'warning';
    const sevNum = h.risk === 'high' ? '8.0' : '5.0';

    const ruleIdx = rules.length;
    rules.push({
      id: ruleId,
      name: `SuspiciousHook-${h.packageName}`,
      shortDescription: { text: `Suspicious lifecycle hook in ${h.packageName}` },
      fullDescription: { text: h.reason },
      help: {
        text: `Hooks: ${h.hooks.join(', ')}`,
        markdown: `## Suspicious Lifecycle Hook\n\n**Package:** ${h.packageName}@${h.packageVersion}\n**Hooks:** ${h.hooks.join(', ')}\n\n${h.reason}`,
      },
      properties: {
        tags: ['security', 'lifecycle-hook', h.risk],
        'security-severity': sevNum,
      },
    });

    results.push({
      ruleId,
      ruleIndex: ruleIdx,
      level: level as 'error' | 'warning' | 'note',
      message: {
        text: `${h.packageName}: ${h.reason}`,
      },
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: 'package-lock.json' },
        },
      }],
      properties: {
        packageName: h.packageName,
        packageVersion: h.packageVersion,
        hooks: h.hooks,
        risk: h.risk,
      },
    });
  }

  const sarif: SarifReport = {
    version: '2.1.0',
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    runs: [{
      tool: {
        driver: {
          name: 'LockGuard',
          version: '1.0.1',
          informationUri: 'https://github.com/Jay-Suryawansh7/lockguard',
          rules,
        },
      },
      results,
      properties: {
        metric: {
          'security-severity': result.riskScore / 10,
        },
      },
    }],
  };

  return JSON.stringify(sarif, null, 2);
}
