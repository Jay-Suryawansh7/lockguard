export const SUSPICIOUS_HOOKS = [
    'postinstall',
    'preinstall',
    'prepare',
    'prepublish',
    'prepack',
    'postpack',
    'publish',
    'postpublish',
];
export const RISKY_HOOK_PATTERNS = [
    /\beval\s*\(/,
    /\bchild_process\b/,
    /\bprocess\.env\b/,
    /\bfetch\s*\(/,
    /\brequire\s*\(\s*['"`]http/,
    /\brequire\s*\(\s*['"`]https/,
    /\bBuffer\.from/,
    /\batob\s*\(/,
    /\bbtoa\s*\(/,
    /\bexec\s*\(/,
    /\bspawn\s*\(/,
    /\bfs\.(read|write)FileSync/,
    /\bcurl\s+/,
    /\bwget\s+/,
];
const NPM_REGISTRY = 'https://registry.npmjs.org';
const HOOK_CACHE_TTL_MS = 30 * 60 * 1000;
const hookCache = new Map();
export async function detectHooks(packages) {
    const results = [];
    for (const pkg of packages) {
        const cached = getCached(pkg.name);
        if (cached) {
            results.push(...cached);
            continue;
        }
        try {
            const hooks = await fetchPackageHooks(pkg.name, pkg.version);
            results.push(...hooks);
            setCached(pkg.name, hooks);
        }
        catch (err) {
            console.error(`Failed to check hooks for ${pkg.name}: ${err}`);
        }
    }
    return results;
}
async function fetchPackageHooks(name, version) {
    const url = `${NPM_REGISTRY}/${encodeURIComponent(name)}/${version}`;
    const res = await fetch(url);
    if (!res.ok) {
        throw new Error(`npm registry error: ${res.status}`);
    }
    const data = (await res.json());
    const scripts = data.scripts || {};
    const foundHooks = [];
    for (const hook of SUSPICIOUS_HOOKS) {
        if (scripts[hook]) {
            foundHooks.push(hook);
        }
    }
    if (foundHooks.length === 0) {
        return [];
    }
    const risk = assessRisk(foundHooks, scripts);
    const reason = buildReason(foundHooks, scripts);
    return [{
            packageName: name,
            packageVersion: version,
            resolved: data.name ? `${NPM_REGISTRY}/${name}` : undefined,
            hooks: foundHooks,
            risk,
            reason,
        }];
}
function assessRisk(hooks, scripts) {
    if (hooks.some(h => ['postinstall', 'preinstall', 'prepare'].includes(h))) {
        const hookScript = scripts[hooks[0]] || '';
        if (RISKY_HOOK_PATTERNS.some(p => p.test(hookScript))) {
            return 'high';
        }
        return 'high';
    }
    if (hooks.length > 2)
        return 'medium';
    return 'low';
}
function buildReason(hooks, scripts) {
    const hookScript = scripts[hooks[0]] || '';
    const hasEval = /\beval\s*\(/.test(hookScript);
    const hasNet = /\b(fetch|require\s*\(['"]http)/.test(hookScript);
    const hasChild = /\bchild_process\b|\bexec\b|\bspawn\b/.test(hookScript);
    if (hasEval)
        return 'Script contains eval() — potential code injection';
    if (hasNet)
        return 'Script makes network request — could exfiltrate data';
    if (hasChild)
        return 'Script spawns processes — could execute arbitrary commands';
    return `Has lifecycle hook(s): ${hooks.join(', ')}`;
}
function getCached(name) {
    const entry = hookCache.get(name);
    if (!entry)
        return null;
    if (Date.now() > entry.expiry) {
        hookCache.delete(name);
        return null;
    }
    return entry.data;
}
function setCached(name, data) {
    hookCache.set(name, { data, expiry: Date.now() + HOOK_CACHE_TTL_MS });
}
export function clearHookCache() {
    hookCache.clear();
}
//# sourceMappingURL=hooks.js.map