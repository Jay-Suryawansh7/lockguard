import { type ParsedLockfile } from './parser.js';
export interface DiffEntry {
    name: string;
    version: string;
    resolved?: string;
    action: 'added' | 'removed' | 'changed';
    oldVersion?: string;
    newVersion?: string;
    dev: boolean;
    optional: boolean;
}
export interface LockfileDiff {
    added: DiffEntry[];
    removed: DiffEntry[];
    changed: DiffEntry[];
    totalAdded: number;
    totalRemoved: number;
    totalChanged: number;
}
export declare function diffLockfiles(currentPath: string, baselinePath: string): LockfileDiff;
export declare function computeDiff(current: ParsedLockfile, baseline: ParsedLockfile): LockfileDiff;
export declare function pathToPackageName(path: string): string | null;
export declare function isSuspiciousDiff(diff: LockfileDiff): boolean;
export declare function getRiskScore(diff: LockfileDiff): number;
//# sourceMappingURL=diff.d.ts.map