import { readFileSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

export interface LockGuardConfig {
  token?: string;
  baseline?: string;
  skipCve?: boolean;
  skipHooks?: boolean;
  riskThreshold?: 'low' | 'medium' | 'high' | 'critical';
  output?: 'text' | 'json' | 'html' | 'sarif';
  workspaces?: string[];
}

const CONFIG_FILES = [
  '.lockguardrc',
  '.lockguardrc.json',
  'lockguard.config.json',
];

export function loadConfig(cwd: string = process.cwd()): LockGuardConfig {
  for (const name of CONFIG_FILES) {
    const path = resolve(cwd, name);
    if (existsSync(path)) {
      try {
        const content = readFileSync(path, 'utf-8');
        return JSON.parse(content) as LockGuardConfig;
      } catch {
        return {};
      }
    }
  }
  return {};
}

export function getConfigPath(cwd: string = process.cwd()): string | null {
  for (const name of CONFIG_FILES) {
    const path = resolve(cwd, name);
    if (existsSync(path)) {
      return path;
    }
  }
  return null;
}
