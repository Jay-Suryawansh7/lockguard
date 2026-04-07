export interface LockfilePackage {
    version: string;
    resolved?: string;
    integrity?: string;
    dev?: boolean;
    optional?: boolean;
    engines?: Record<string, string>;
    dependencies?: Record<string, string>;
    optionalDependencies?: Record<string, string>;
}
export interface ParsedLockfile {
    name?: string;
    version?: string;
    packages: Map<string, LockfilePackage>;
    dependencies: Map<string, string>;
}
export interface DependencyNode {
    name: string;
    version: string;
    resolved?: string;
    integrity?: string;
    dev: boolean;
    optional: boolean;
    path: string;
    children: DependencyNode[];
}
export declare function parseLockfile(content: string): ParsedLockfile;
export declare function buildDependencyTree(lockfile: ParsedLockfile, rootName: string, rootVersion: string): DependencyNode;
export declare function flattenTree(node: DependencyNode): DependencyNode[];
export declare function getAllPackages(lockfile: ParsedLockfile): Array<{
    path: string;
    pkg: LockfilePackage;
}>;
//# sourceMappingURL=parser.d.ts.map