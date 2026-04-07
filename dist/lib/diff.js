import { readFileSync } from 'node:fs';
import { parseLockfile } from './parser.js';
export function diffLockfiles(currentPath, baselinePath) {
    const currentRaw = readFileSync(currentPath, 'utf-8');
    const baselineRaw = readFileSync(baselinePath, 'utf-8');
    const current = parseLockfile(currentRaw);
    const baseline = parseLockfile(baselineRaw);
    return computeDiff(current, baseline);
}
export function computeDiff(current, baseline) {
    const added = [];
    const removed = [];
    const changed = [];
    for (const [path, pkg] of current.packages) {
        const name = pathToPackageName(path);
        if (!name)
            continue;
        const baselinePkg = baseline.packages.get(path);
        if (!baselinePkg) {
            added.push({
                name,
                version: pkg.version || 'unknown',
                resolved: pkg.resolved,
                action: 'added',
                newVersion: pkg.version,
                dev: !!pkg.dev,
                optional: !!pkg.optional,
            });
        }
        else if (pkg.version !== baselinePkg.version) {
            changed.push({
                name,
                version: pkg.version || 'unknown',
                resolved: pkg.resolved,
                action: 'changed',
                oldVersion: baselinePkg.version,
                newVersion: pkg.version,
                dev: !!pkg.dev,
                optional: !!pkg.optional,
            });
        }
    }
    for (const [path, pkg] of baseline.packages) {
        const name = pathToPackageName(path);
        if (!name)
            continue;
        if (!current.packages.has(path)) {
            removed.push({
                name,
                version: pkg.version || 'unknown',
                resolved: pkg.resolved,
                action: 'removed',
                oldVersion: pkg.version,
                dev: !!pkg.dev,
                optional: !!pkg.optional,
            });
        }
    }
    return {
        added,
        removed,
        changed,
        totalAdded: added.length,
        totalRemoved: removed.length,
        totalChanged: changed.length,
    };
}
export function pathToPackageName(path) {
    const match = path.match(/^node_modules\/(?:@[^/]+\/)?([^/]+)/);
    return match ? match[1] : null;
}
export function isSuspiciousDiff(diff) {
    const suspicious = diff.added.filter(e => e.name === 'postinstall-js' ||
        e.name === 'preinstall-js' ||
        e.name === 'prepare-js' ||
        e.name.includes('eval') ||
        e.name.includes('curl') ||
        e.name.includes('wget') ||
        e.name.includes('setup') ||
        e.name.includes('init'));
    return suspicious.length > 0;
}
export function getRiskScore(diff) {
    let score = 0;
    score += diff.totalAdded * 2;
    score += diff.totalChanged;
    if (isSuspiciousDiff(diff))
        score += 50;
    if (diff.added.some(e => e.dev === false && e.optional === false))
        score += 10;
    return Math.min(score, 100);
}
//# sourceMappingURL=diff.js.map