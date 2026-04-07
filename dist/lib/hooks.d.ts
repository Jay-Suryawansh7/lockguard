export interface HookInfo {
    packageName: string;
    packageVersion: string;
    resolved?: string;
    hooks: string[];
    risk: 'low' | 'medium' | 'high';
    reason: string;
}
export declare const SUSPICIOUS_HOOKS: string[];
export declare const RISKY_HOOK_PATTERNS: RegExp[];
export interface PackageMetadata {
    name: string;
    version: string;
    scripts?: Record<string, string>;
    readme?: string;
}
export declare function detectHooks(packages: Array<{
    name: string;
    version: string;
    resolved?: string;
}>): Promise<HookInfo[]>;
export declare function clearHookCache(): void;
//# sourceMappingURL=hooks.d.ts.map