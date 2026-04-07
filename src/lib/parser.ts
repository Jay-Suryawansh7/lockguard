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

export function parseLockfile(content: string): ParsedLockfile {
  const data = JSON.parse(content) as Record<string, unknown>;

  const packages = new Map<string, LockfilePackage>();
  const dependencies = new Map<string, string>();

  if (data.packages && typeof data.packages === 'object') {
    const pkgs = data.packages as Record<string, LockfilePackage | ''>;
    for (const [path, pkg] of Object.entries(pkgs)) {
      if (path === '') continue;
      packages.set(path, pkg === '' ? {} as LockfilePackage : pkg);
    }
  }

  if (data.dependencies && typeof data.dependencies === 'object') {
    const deps = data.dependencies as Record<string, { version: string }>;
    for (const [name, info] of Object.entries(deps)) {
      dependencies.set(name, info.version);
    }
  }

  return {
    name: data.name as string | undefined,
    version: data.version as string | undefined,
    packages,
    dependencies,
  };
}

export function buildDependencyTree(
  lockfile: ParsedLockfile,
  rootName: string,
  rootVersion: string
): DependencyNode {
  const root: DependencyNode = {
    name: rootName,
    version: rootVersion,
    dev: false,
    optional: false,
    path: '',
    children: [],
  };

  const visited = new Set<string>();

  function traverse(node: DependencyNode, dev: boolean, optional: boolean): void {
    const key = `${node.path}:${node.name}@${node.version}`;
    if (visited.has(key)) return;
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
        if (!depPkg) continue;

        const depNode: DependencyNode = {
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

export function flattenTree(node: DependencyNode): DependencyNode[] {
  const result: DependencyNode[] = [];
  function walk(n: DependencyNode): void {
    result.push(n);
    for (const child of n.children) {
      walk(child);
    }
  }
  walk(node);
  return result;
}

export function getAllPackages(lockfile: ParsedLockfile): Array<{ path: string; pkg: LockfilePackage }> {
  return Array.from(lockfile.packages.entries()).map(([path, pkg]) => ({
    path,
    pkg,
  }));
}
