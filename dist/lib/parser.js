export function parseLockfile(content) {
    const data = JSON.parse(content);
    const packages = new Map();
    const dependencies = new Map();
    if (data.packages && typeof data.packages === 'object') {
        const pkgs = data.packages;
        for (const [path, pkg] of Object.entries(pkgs)) {
            if (path === '')
                continue;
            packages.set(path, pkg === '' ? {} : pkg);
        }
    }
    if (data.dependencies && typeof data.dependencies === 'object') {
        const deps = data.dependencies;
        for (const [name, info] of Object.entries(deps)) {
            dependencies.set(name, info.version);
        }
    }
    return {
        name: data.name,
        version: data.version,
        packages,
        dependencies,
    };
}
export function buildDependencyTree(lockfile, rootName, rootVersion) {
    const root = {
        name: rootName,
        version: rootVersion,
        dev: false,
        optional: false,
        path: '',
        children: [],
    };
    const visited = new Set();
    function traverse(node, dev, optional) {
        const key = `${node.path}:${node.name}@${node.version}`;
        if (visited.has(key))
            return;
        visited.add(key);
        const pkgKey = `node_modules/${node.name}`;
        const pkg = lockfile.packages.get(pkgKey);
        if (pkg) {
            node.dev = dev || !!pkg.dev;
            node.optional = optional || !!pkg.optional;
            node.integrity = pkg.integrity;
            node.resolved = pkg.resolved;
            const deps = pkg.dependencies || {};
            for (const [depName, depVersion] of Object.entries(deps)) {
                const depKey = `node_modules/${depName}`;
                const depPkg = lockfile.packages.get(depKey);
                if (!depPkg)
                    continue;
                const depNode = {
                    name: depName,
                    version: depVersion.replace(/^[\^~>=<]+/, ''),
                    dev: !!depPkg.dev,
                    optional: !!depPkg.optional,
                    path: `${node.path}/node_modules/${depName}`,
                    children: [],
                };
                node.children.push(depNode);
                traverse(depNode, node.dev, node.optional);
            }
        }
    }
    traverse(root, false, false);
    return root;
}
export function flattenTree(node) {
    const result = [];
    function walk(n) {
        result.push(n);
        for (const child of n.children) {
            walk(child);
        }
    }
    walk(node);
    return result;
}
export function getAllPackages(lockfile) {
    return Array.from(lockfile.packages.entries()).map(([path, pkg]) => ({
        path,
        pkg,
    }));
}
//# sourceMappingURL=parser.js.map