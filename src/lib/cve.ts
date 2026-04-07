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

interface GitHubAdvisoryNode {
  advisory: {
    ghsaId: string;
    cveId?: string;
    summary: string;
    description: string;
    severity: string;
    vulnerabilities: Array<{
      vulnerableVersionRange: string;
      firstPatchedVersion?: { identifier: string };
    }>;
  };
}

const GITHUB_API = 'https://api.github.com/graphql';
const CACHE_TTL_MS = 60 * 60 * 1000;

const cache = new Map<string, { data: CVEResult[]; expiry: number }>();

export async function checkCVEs(
  packages: Array<{ name: string; version: string }>,
  token?: string
): Promise<CVEResult[]> {
  const results: CVEResult[] = [];
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  for (const { name, version } of packages) {
    const cached = getCached(name, version);
    if (cached) {
      results.push(...cached);
      continue;
    }

    try {
      const advisories = await queryAdvisory(name, version, headers);
      const result: CVEResult = { packageName: name, version, advisories };
      results.push(result);
      setCached(name, version, [result]);
    } catch (err) {
      console.error(`Failed to check CVEs for ${name}@${version}: ${err}`);
    }
  }

  return results;
}

async function queryAdvisory(
  packageName: string,
  packageVersion: string,
  headers: Record<string, string>
): Promise<Advisory[]> {
  const query = `
    query {
      securityVulnerabilities(first: 10, package: "${packageName}", ecosystem: NPM) {
        nodes {
          advisory {
            ghsaId
            cveId
            summary
            description
            severity
            vulnerabilities(first: 5) {
              nodes {
                vulnerableVersionRange
                firstPatchedVersion {
                  identifier
                }
              }
            }
          }
        }
      }
    }
  `;

  const res = await fetch(GITHUB_API, {
    method: 'POST',
    headers,
    body: JSON.stringify({ query }),
  });

  if (!res.ok) {
    if (res.status === 403) {
      throw new Error('GitHub API rate limit exceeded. Set CHAIN_GUARD_GITHUB_TOKEN to avoid this.');
    }
    throw new Error(`GitHub API error: ${res.status}`);
  }

  const json = (await res.json()) as {
    errors?: Array<{ message: string }>;
    data?: { securityVulnerabilities: { nodes: GitHubAdvisoryNode[] } };
  };

  if (json.errors?.length) {
    throw new Error(json.errors[0].message);
  }

  if (!json.data) {
    return [];
  }

  return json.data.securityVulnerabilities.nodes.map((node) => ({
    ghsaId: node.advisory.ghsaId,
    cveId: node.advisory.cveId,
    summary: node.advisory.summary,
    description: node.advisory.description,
    severity: node.advisory.severity as Advisory['severity'],
    vulnerableVersionRange: node.advisory.vulnerabilities[0]?.vulnerableVersionRange || 'unknown',
    firstPatchedVersion: node.advisory.vulnerabilities[0]?.firstPatchedVersion?.identifier,
  }));
}

function getCached(name: string, version: string): CVEResult[] | null {
  const key = `${name}@${version}`;
  const entry = cache.get(key);
  if (!entry) return null;
  if (Date.now() > entry.expiry) {
    cache.delete(key);
    return null;
  }
  return entry.data;
}

function setCached(name: string, version: string, data: CVEResult[]): void {
  const key = `${name}@${version}`;
  cache.set(key, { data, expiry: Date.now() + CACHE_TTL_MS });
}

export function clearCache(): void {
  cache.clear();
}

export function severityScore(severity: Advisory['severity']): number {
  switch (severity) {
    case 'critical': return 10;
    case 'high': return 7;
    case 'moderate': return 4;
    case 'low': return 1;
    default: return 0;
  }
}
