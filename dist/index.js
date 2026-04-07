export { parseLockfile, buildDependencyTree, flattenTree, getAllPackages } from './lib/parser.js';
export { checkCVEs, clearCache, severityScore } from './lib/cve.js';
export { detectHooks, clearHookCache, SUSPICIOUS_HOOKS } from './lib/hooks.js';
export { diffLockfiles, computeDiff, getRiskScore, isSuspiciousDiff } from './lib/diff.js';
export { calcRiskScore, calcRiskLevel, reportText, reportJSON, reportHTML, } from './lib/report.js';
//# sourceMappingURL=index.js.map