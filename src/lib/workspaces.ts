import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';

export interface WorkspaceInfo {
  path: string;
  name: string;
  lockfile: string;
}

export interface WorkspaceConfig {
  packages: string[];
}

export function detectWorkspaces(cwd: string): WorkspaceInfo[] {
  const workspaces: WorkspaceInfo[] = [];

  const pkgJsonPath = resolve(cwd, 'package.json');
  if (!existsSync(pkgJsonPath)) {
    return workspaces;
  }

  try {
    const pkgJson = JSON.parse(readFileSync(pkgJsonPath, 'utf-8'));

    if (pkgJson.workspaces) {
      const wsPaths: string[] = [];

      if (Array.isArray(pkgJson.workspaces)) {
        wsPaths.push(...pkgJson.workspaces);
      } else if (pkgJson.workspaces.packages) {
        wsPaths.push(...pkgJson.workspaces.packages);
      }

      for (const wsPath of wsPaths) {
        const fullPath = resolve(cwd, wsPath);
        const lockfilePath = resolve(fullPath, 'package-lock.json');
        if (existsSync(lockfilePath)) {
          const name = resolveWorkspaceName(fullPath) || wsPath;
          workspaces.push({
            path: fullPath,
            name,
            lockfile: lockfilePath,
          });
        }

        const subDirs = getSubDirs(fullPath);
        for (const subDir of subDirs) {
          const subLockfile = resolve(subDir, 'package-lock.json');
          if (existsSync(subLockfile)) {
            const name = resolveWorkspaceName(subDir) || subDir;
            workspaces.push({
              path: subDir,
              name,
              lockfile: subLockfile,
            });
          }
        }
      }
    }
  } catch {
    // ignore
  }

  const rootLockfile = resolve(cwd, 'package-lock.json');
  if (existsSync(rootLockfile)) {
    workspaces.unshift({
      path: cwd,
      name: 'root',
      lockfile: rootLockfile,
    });
  }

  return workspaces;
}

function resolveWorkspaceName(workspacePath: string): string | null {
  const pkgPath = resolve(workspacePath, 'package.json');
  if (!existsSync(pkgPath)) return null;
  try {
    const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8'));
    return pkg.name || null;
  } catch {
    return null;
  }
}

function getSubDirs(dir: string): string[] {
  try {
    return readdirSync(dir, { withFileTypes: true })
      .filter((d: { isDirectory: () => boolean }) => d.isDirectory())
      .map((d: { name: string }) => join(dir, d.name));
  } catch {
    return [];
  }
}
