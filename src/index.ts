export { parseLockfile, buildDependencyTree, flattenTree, getAllPackages } from './lib/parser.js';
export type { LockfilePackage, ParsedLockfile, DependencyNode } from './lib/parser.js';

export { checkCVEs, clearCache, severityScore } from './lib/cve.js';
export type { Advisory, CVEResult } from './lib/cve.js';

export { detectHooks, clearHookCache, SUSPICIOUS_HOOKS } from './lib/hooks.js';
export type { HookInfo, PackageMetadata } from './lib/hooks.js';

export { diffLockfiles, computeDiff, getRiskScore, isSuspiciousDiff } from './lib/diff.js';
export type { DiffEntry, LockfileDiff } from './lib/diff.js';

export {
  calcRiskScore,
  calcRiskLevel,
  reportText,
  reportJSON,
  reportHTML,
} from './lib/report.js';
export type { ScanResult, OutputFormat } from './lib/report.js';

export { reportSARIF } from './lib/sarif.js';
export type { SarifReport, SarifResult } from './lib/sarif.js';

export { loadConfig, getConfigPath } from './lib/config.js';
export type { LockGuardConfig } from './lib/config.js';

export { detectWorkspaces } from './lib/workspaces.js';
export type { WorkspaceInfo } from './lib/workspaces.js';
