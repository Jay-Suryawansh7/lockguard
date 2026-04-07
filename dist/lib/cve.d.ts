export interface Advisory {
    ghsaId: string;
    cveId?: string;
    summary: string;
    description: string;
    severity: 'low' | 'moderate' | 'high' | 'critical';
    vulnerableVersionRange: string;
    firstPatchedVersion?: string;
}
export interface CVEResult {
    packageName: string;
    version: string;
    advisories: Advisory[];
}
export declare function checkCVEs(packages: Array<{
    name: string;
    version: string;
}>, token?: string): Promise<CVEResult[]>;
export declare function clearCache(): void;
export declare function severityScore(severity: Advisory['severity']): number;
//# sourceMappingURL=cve.d.ts.map