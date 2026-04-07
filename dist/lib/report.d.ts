import type { CVEResult } from './cve.js';
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
export declare function calcRiskLevel(score: number): ScanResult['riskLevel'];
export declare function calcRiskScore(cveResults: CVEResult[], hookResults: HookInfo[], diff?: LockfileDiff): number;
export declare function reportText(result: ScanResult): string;
export declare function reportJSON(result: ScanResult): string;
export declare function reportHTML(result: ScanResult): string;
//# sourceMappingURL=report.d.ts.map