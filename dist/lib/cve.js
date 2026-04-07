const GITHUB_API = 'https://api.github.com/graphql';
const CACHE_TTL_MS = 60 * 60 * 1000;
const cache = new Map();
export async function checkCVEs(packages, token) {
    const results = [];
    const headers = {
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
            const result = { packageName: name, version, advisories };
            results.push(result);
            setCached(name, version, [result]);
        }
        catch (err) {
            console.error(`Failed to check CVEs for ${name}@${version}: ${err}`);
        }
    }
    return results;
}
async function queryAdvisory(packageName, packageVersion, headers) {
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
    const json = (await res.json());
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
        severity: node.advisory.severity,
        vulnerableVersionRange: node.advisory.vulnerabilities[0]?.vulnerableVersionRange || 'unknown',
        firstPatchedVersion: node.advisory.vulnerabilities[0]?.firstPatchedVersion?.identifier,
    }));
}
function getCached(name, version) {
    const key = `${name}@${version}`;
    const entry = cache.get(key);
    if (!entry)
        return null;
    if (Date.now() > entry.expiry) {
        cache.delete(key);
        return null;
    }
    return entry.data;
}
function setCached(name, version, data) {
    const key = `${name}@${version}`;
    cache.set(key, { data, expiry: Date.now() + CACHE_TTL_MS });
}
export function clearCache() {
    cache.clear();
}
export function severityScore(severity) {
    switch (severity) {
        case 'critical': return 10;
        case 'high': return 7;
        case 'moderate': return 4;
        case 'low': return 1;
        default: return 0;
    }
}
//# sourceMappingURL=cve.js.map